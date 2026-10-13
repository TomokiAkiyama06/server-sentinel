"""Transactional local authorization state; WebAuthn verification lives in ``webauthn.py``."""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import sqlite3
from typing import Callable, ContextManager, Iterable
from uuid import UUID, uuid4

from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.audit.store import AuditStorageError, AuditStore
from app.storage.database import Database
from .boot_clock import BootInstant, invitation_clock_valid, read_boot_instant, step_up_fresh
from .invitation_code import INVITATION_LIFETIME, MAX_INVITATION_LIFETIME, valid_invitation_lifetime
from .model import (
    AccessValidationError, Credential, CredentialStatus, Permission, Principal, PrincipalRole, PrincipalStatus,
    utc_time,
)
from .session_binding import SessionBindingKey, canonical_identity


class AccessStorageError(RuntimeError):
    """Storage failure without paths, identities, tokens, or credential material."""


class UnauditedAccessWriteError(RuntimeError):
    """An Owner-only access mutation was attempted outside the audited boundary."""


class StepUpRequired(AccessValidationError):
    """An authenticated Owner session must re-verify before an AUTH-008 operation.

    Returned only to a currently valid Owner session; every other caller gets
    the generic denial and learns nothing about owner routes.
    """

    def __init__(self) -> None:
        super().__init__("step_up_required")


class OwnerAlreadyConfigured(AccessValidationError):
    """Local bootstrap refused: an Owner principal already exists."""

    def __init__(self) -> None:
        super().__init__("owner is already configured")


class OwnerNotConfigured(AccessValidationError):
    """Local recovery refused: no Owner principal exists yet."""

    def __init__(self) -> None:
        super().__init__("owner is not configured")


class InvitationClockUnavailable(AccessValidationError):
    """Issuance refused: the boot id or ``CLOCK_BOOTTIME`` cannot be read.

    Every invitation records both (``app.auth.boot_clock``); without them its
    lifetime could not be checked against a wall-clock rollback, so none is
    issued (fail closed).
    """

    def __init__(self) -> None:
        super().__init__("invitation clock is unavailable")


class AccessLimitReached(AccessValidationError):
    """An Owner invitation refused by a deployment bound (Owner decision S4-8).

    At most ``MAX_PRINCIPALS`` principals that are not revoked, and at most
    ``MAX_PENDING_INVITATIONS`` unused invitation code per principal. The
    human surface answers it with the generic denial; it carries no count.
    """

    def __init__(self) -> None:
        super().__init__("access limit reached")


class DeviceBoundCredentialRequired(AccessValidationError):
    """A verified backup-eligible registration refused by deployment policy.

    Raised by ``enroll_credential`` only inside the redemption transaction,
    after the invitation the presented code names proved valid and is the one
    the consumed challenge was bound to, so only the holder of a valid
    invitation who completed a verified ceremony sees it and the Web client
    may show an actionable message. Nothing is written: the invitation stays
    unredeemed.
    """

    def __init__(self) -> None:
        super().__init__("device_bound_credential_required")


# ADR-0003 accepted parameters (Owner approval recorded 2026-09-21).
IDLE_LIFETIME = timedelta(minutes=30)
ABSOLUTE_LIFETIME = timedelta(hours=12)
OWNER_STEP_UP_FRESHNESS = timedelta(minutes=5)
# Ceremony bounds chosen for Issue #10 (implementation limits, not ADR parameters).
MAX_CHALLENGE_LIFETIME = timedelta(minutes=10)
MAX_PENDING_CHALLENGES = 1024
MAX_REDEMPTION_ATTEMPTS = 5
# Owner decision 2026-09-30 (PR #107): a proxy-identity binding mismatch is
# audited at most once per session per window; later mismatches in the same
# window only increment the session's counter, so a replayed stolen cookie
# cannot flood the audit log.
BINDING_MISMATCH_AUDIT_INTERVAL = timedelta(minutes=10)
# Owner decision S4-8 (2026-10-13): administration bounds.
MAX_PRINCIPALS = 64
MAX_PENDING_INVITATIONS = 1


@dataclass(frozen=True)
class RegistrationSubject:
    invitation_id: UUID
    principal_id: UUID
    display_name: str
    excluded_credential_ids: tuple[bytes, ...]


class Requirement(Enum):
    """What a human route requires of its caller (Issue #10 phase 2, S1).

    ``PRE_CREDENTIAL`` marks the sign-in ceremony routes, which run before a
    session exists and gate themselves inside ``PasskeyCeremonies``; it is
    never satisfied by ``authorize_request``. Every other requirement needs a
    currently valid, credential-backed session:

    - ``SESSION``: nothing more (session self-description, sign-out);
    - ``LIVE`` / ``RECORDINGS``: the Owner, or a person holding ``live:view``
      / ``recordings:view``; each is checked on its own, so one never
      implies the other (historical timeline/events belong to
      ``RECORDINGS``);
    - ``OWNER_READ``: the Owner, without step-up freshness;
    - ``OWNER_OP``: the Owner with a user verification fresher than the
      step-up window (ADR-0003, AUTH-008). Only this requirement can end in
      ``StepUpRequired``, and only for an otherwise valid Owner session.
    """

    PRE_CREDENTIAL = "pre_credential"
    SESSION = "session"
    LIVE = "live"
    RECORDINGS = "recordings"
    OWNER_READ = "owner_read"
    OWNER_OP = "owner_op"


@dataclass(frozen=True)
class SessionView:
    """A currently valid session as one authorization saw it.

    ``credential_id`` is opaque WebAuthn material and is left out of
    ``repr``; ``role``, ``authorization_revision`` and ``permissions`` are
    set by ``authorize_request`` (the Owner holds every permission) and are
    ``None``/empty from the read-only ``current_session`` lookup.
    """

    session_id: UUID
    principal_id: UUID
    credential_id: bytes = field(repr=False)
    role: PrincipalRole | None = None
    authorization_revision: int | None = None
    permissions: frozenset = frozenset()


@dataclass(frozen=True)
class ConsumedChallenge:
    invitation_id: UUID | None
    session_id: UUID | None


def _us(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    value = utc_time(value)
    delta = value - epoch
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _time(value: int) -> datetime:
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)


def _duration_us(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _digest(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or not 16 <= len(secret) <= 4096:
        raise AccessValidationError("secret is invalid")
    return hashlib.sha256(secret).digest()


_LOOKUP_DOMAIN = b"serversentinel/invitation-lookup/v1\x00"
_MAX_INVITATION_LIFETIME_US = MAX_INVITATION_LIFETIME // timedelta(microseconds=1)


def _lookup_key(secret: bytes) -> bytes:
    """The non-secret row locator of an invitation secret (PR #234 review).

    A domain-separated SHA-256 of the secret truncated to 128 bits, unrelated
    to ``secret_digest``: SQLite's (not constant-time) index comparison only
    ever sees this value, and the stored ``secret_digest`` is then compared
    with ``hmac.compare_digest`` (AUTH-013). Learning a lookup key through
    timing reveals neither the secret nor its verification digest.
    """
    if not isinstance(secret, bytes) or not 16 <= len(secret) <= 4096:
        raise AccessValidationError("secret is invalid")
    return hashlib.sha256(_LOOKUP_DOMAIN + secret).digest()[:16]


def _identity(value: object) -> str:
    """Validate a supplied trusted-proxy identity.

    A present, well-formed identity is required on every ceremony and session
    check (ADR-0003 rejects a missing human identity), but it is never
    compared with a principal: every holder of the shared Tailscale account
    presents the same value, so it cannot say who is asking.
    """
    canonical = canonical_identity(value)
    if canonical is None:
        raise AccessValidationError("external identity is invalid")
    return canonical


def _handle(value: object) -> str:
    """A credential handle in its canonical form (a lower-case UUID string), else denial."""
    try:
        if isinstance(value, str) and len(value) == 36 and str(UUID(value)) == value:
            return value
    except ValueError:
        pass
    raise AccessValidationError("credential is unavailable")


def _display(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(char) < 32 for char in value):
        raise AccessValidationError("display name is invalid")
    return value


class AccessStore:
    """Authoritative grants and opaque session state.

    Callers must verify WebAuthn assertion/registration cryptography before
    ``enroll_credential`` or ``establish_session``.  This module deliberately
    treats credential IDs/public keys as opaque bytes and creates no route,
    cookie, trusted-header adapter, or browser ceremony.

    Owner-only mutations (invitation, grant change, principal or credential
    revocation) are reached through ``app.audit.integration.AccessAdministration``,
    which authorizes the Owner and commits the ``*_on`` mutation together with
    its security audit record in one SQLite transaction. The plain wrappers
    refuse with ``UnauditedAccessWriteError`` unless this store was explicitly
    constructed with ``unaudited_writes=True`` for non-runtime fixtures.
    Invitation redemption is not an Owner operation; it appends its own audit
    record in the same transaction and therefore requires ``audit``.

    Per-person authorization rests on the invitation and on the passkey
    credential bound to the principal (ADR-0004). The trusted-proxy identity
    is supplementary: it is required to be present, recorded on the principal
    as the value last observed at authentication, and bound into each session
    as ``HMAC(session_binding, identity)``. A later request whose identity
    does not reproduce that binding is refused; the binding never grants
    anything, and no principal is ever selected or authorized by it. Without
    ``session_binding`` no session can be established or used.
    """

    def __init__(self, database: Database, *, clock: Callable[[], datetime] | None = None,
                 audit: AuditStore | None = None, unaudited_writes: bool = False,
                 session_binding: SessionBindingKey | None = None,
                 invitation_lifetime: timedelta = INVITATION_LIFETIME,
                 boot_clock: Callable[[], BootInstant | None] = read_boot_instant):
        if type(unaudited_writes) is not bool:
            raise AccessValidationError("unaudited write mode is invalid")
        # The deployment's invitation lifetime (Owner decision 2026-10-11:
        # default 24 hours, at most 7 days); no invitation is issued for longer.
        if not valid_invitation_lifetime(invitation_lifetime) or not callable(boot_clock):
            raise AccessValidationError("invitation configuration is invalid")
        if session_binding is not None and not isinstance(session_binding, SessionBindingKey):
            raise AccessValidationError("session binding key is invalid")
        if audit is not None and (not isinstance(audit, AuditStore) or audit.database != database):
            # The audit row must share the mutation's SQLite database/transaction.
            raise AccessValidationError("audit store is invalid")
        self.database = database
        self.audit = audit
        self.unaudited_writes = unaudited_writes
        self._session_binding = session_binding
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.invitation_lifetime = invitation_lifetime
        self._boot_clock = boot_clock
        # Bounded health only: a matched invitation redemption whose audit
        # append or commit failed is counted here instead of being appended
        # separately, so unauthenticated attempts cannot grow the audit table.
        self.audit_delivery_failed = False
        self.undelivered_audit_records = 0

    @property
    def session_binding_configured(self) -> bool:
        return self._session_binding is not None

    def _mark_undelivered(self) -> None:
        self.audit_delivery_failed = True
        self.undelivered_audit_records += 1

    def _require_unaudited_writes(self) -> None:
        if not self.unaudited_writes:
            raise UnauditedAccessWriteError("owner access mutation requires the audited boundary")

    def now(self) -> datetime:
        return utc_time(self._clock())

    def invitation_expiry(self, at: datetime) -> datetime:
        """The expiry of an invitation issued at ``at`` under this deployment's lifetime."""
        return utc_time(at) + self.invitation_lifetime

    def _boot_instant(self) -> BootInstant | None:
        try:
            instant = self._boot_clock()
        except Exception:
            return None
        return instant if isinstance(instant, BootInstant) else None

    @staticmethod
    def _invitation_row_on(connection, secret: bytes, columns: str):
        """The invitation row whose secret this is, compared in constant time.

        Located by the non-secret ``lookup_key``; the stored ``secret_digest``
        is then compared with ``hmac.compare_digest`` (AUTH-013). Rows issued
        before the lookup key existed have none and are never found.
        """
        row = connection.execute(
            f"SELECT {columns} FROM access_invitations i JOIN access_principals p ON p.id=i.principal_id "
            "WHERE i.lookup_key=?", (_lookup_key(secret),)).fetchone()
        if row is None or not hmac.compare_digest(bytes(row["secret_digest"]), _digest(secret)):
            return None
        return row

    @staticmethod
    def _redeemable(row, generation: int, at: datetime, now: BootInstant | None) -> bool:
        """Every validity condition of an invitation row, on both clocks."""
        return (row is not None and row["redeemed_at_us"] is None and row["revoked_at_us"] is None
                and row["status"] != PrincipalStatus.REVOKED.value
                and row["principal_revision"] == row["authorization_revision"]
                and row["deployment_generation"] == generation
                and invitation_clock_valid(
                    issued_us=row["issued_at_us"], expires_us=row["expires_at_us"],
                    issued_boot_id=row["issued_boot_id"], issued_boottime_us=row["issued_boottime_us"],
                    now_us=_us(at), now=now, max_lifetime_us=_MAX_INVITATION_LIFETIME_US))

    @contextmanager
    def _transaction(self, write: bool = False):
        """One SQLite transaction; a write is admitted like an audit write.

        A write with an audit store holds that store's storage reservation
        (the Main storage policy once bound) through commit, so challenge
        rows, session touches and expiry sweeps cannot spend the hard
        filesystem reserve or grow the rollback journal at
        ``STORAGE_HARD_STOP``. A refused admission is an
        ``AccessStorageError`` and nothing is written. Reads never reserve,
        and therefore never create: a read opens the existing database file
        ``mode=ro`` (``Database.connect_read_only``), so a request that reaches
        a read after the verified filesystem disappeared cannot create a
        fallback database at the path; the read fails (a denial) instead.
        """
        with ExitStack() as admission:
            reservation = self.audit.reservation if write and self.audit is not None else None
            if reservation is not None:
                try:
                    admission.enter_context(reservation())
                except Exception:
                    raise AccessStorageError("access state operation failed") from None
            connection = None
            try:
                try:
                    connection = self.database.connect() if write else self.database.connect_read_only()
                except ValueError:
                    raise AccessStorageError("access state operation failed") from None
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield connection
                connection.execute("COMMIT")
            except sqlite3.Error:
                if connection is not None and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise AccessStorageError("access state operation failed") from None
            except BaseException:
                if connection is not None and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                if connection is not None:
                    connection.close()

    @contextmanager
    def _audited_transaction(self):
        """Write transaction admitted through the audit store's storage reservation."""
        if self.audit is None:
            raise AccessStorageError("access audit is unavailable")
        try:
            with self.audit.transaction(write=True) as connection:
                yield connection
        except AuditStorageError:
            raise AccessStorageError("access state operation failed") from None

    @staticmethod
    def _principal(row) -> Principal:
        return Principal(UUID(row["principal_id"] if "principal_id" in row.keys() else row["id"]), row["external_identity"], row["display_name"],
                         PrincipalRole(row["role"]), PrincipalStatus(row["status"]),
                         row["authorization_revision"], _time(row["created_at_us"]),
                         _time(row["revoked_at_us"]) if row["revoked_at_us"] is not None else None)

    @staticmethod
    def _credential(row) -> Credential:
        def optional(name):
            return _time(row[name]) if row[name] is not None else None

        return Credential(bytes(row["credential_id"]), UUID(row["principal_id"]), bytes(row["public_key"]),
                          row["algorithm"], row["sign_count"], _time(row["enrolled_at_us"]),
                          optional("revoked_at_us"), backup_eligible=bool(row["backup_eligible"]),
                          backup_state=bool(row["backup_state"]), inconsistent_at=optional("inconsistent_at_us"),
                          label=row["label"], last_used_at=optional("last_used_at_us"))

    def bootstrap_owner(self, display_name: str, *, now: datetime | None = None) -> Principal:
        name = _display(display_name)
        at = utc_time(self._clock() if now is None else now)
        owner = Principal(uuid4(), None, name, PrincipalRole.OWNER, PrincipalStatus.ACTIVE, 0, at)
        with self._transaction(write=True) as connection:
            if connection.execute("SELECT 1 FROM access_principals WHERE role='owner'").fetchone() is not None:
                raise AccessValidationError("owner is already configured")
            connection.execute("INSERT INTO access_principals VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                               (str(owner.id), owner.external_identity, owner.display_name, owner.role.value,
                                owner.status.value, owner.authorization_revision, _us(owner.created_at)))
        return owner

    @staticmethod
    def owner_configured_on(connection) -> bool:
        """Whether an Owner principal row exists (whatever its status)."""
        return connection.execute("SELECT 1 FROM access_principals WHERE role='owner'").fetchone() is not None

    def bootstrap_owner_on(self, connection, principal_id: UUID, display_name: str, secret: bytes,
                           expires_at: datetime, *, at: datetime) -> UUID:
        """Create the single Owner with one enrollment authorization (ADR-0003 steps 3-4).

        Local bootstrap only (``app.auth.bootstrap_cli``), on a caller-owned
        write transaction that also carries its audit records. The Owner is
        created ``invited`` with no credential; redeeming the authorization
        through the ordinary redemption route registers its first credential
        and makes it ``active``. Refused with ``OwnerAlreadyConfigured`` when
        any Owner row exists (the ``access_one_owner`` index refuses a
        concurrent second one as well). Returns the invitation id.
        """
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        name = _display(display_name)
        at = utc_time(at)
        if self.owner_configured_on(connection):
            raise OwnerAlreadyConfigured()
        connection.execute("INSERT INTO access_principals VALUES (?, NULL, ?, ?, ?, 0, ?, NULL)",
                           (str(principal_id), name, PrincipalRole.OWNER.value,
                            PrincipalStatus.INVITED.value, _us(at)))
        return self.issue_enrollment_on(connection, principal_id, secret, expires_at, at=at)

    def recover_owner_on(self, connection, secret: bytes, expires_at: datetime, *, at: datetime,
                         display_name: str | None = None) -> tuple[UUID, UUID, int]:
        """Local Owner recovery on a caller-owned write transaction (ADR-0003).

        In one transaction: advance the deployment authorization generation,
        which ends every human session, deletes every pending challenge and
        voids every outstanding enrollment authorization (the Owner's and
        every invitee's; a pending invitation must be issued again,
        ``invalidate_all_sessions_on``); revoke every credential of the Owner
        principal (credential-scoped: a synced passkey stops on every device
        it exists on) and its pending invitations; clear its last observed
        proxy identity; advance its authorization revision; set it
        ``invited`` (optionally renamed); and issue exactly one new
        enrollment authorization under the new generation. The Owner keeps
        its logical UUID (the ``access_one_owner`` index allows one Owner
        row); recordings, grants of other principals and capture nodes are
        untouched. Returns ``(owner id, invitation id, credentials revoked)``.
        Refused with ``OwnerNotConfigured`` when no Owner exists.
        """
        at = utc_time(at)
        name = None if display_name is None else _display(display_name)
        row = connection.execute("SELECT id FROM access_principals WHERE role='owner'").fetchone()
        if row is None:
            raise OwnerNotConfigured()
        owner = UUID(row["id"])
        self.invalidate_all_sessions_on(connection, at=at)
        revoked = connection.execute(
            "UPDATE access_credentials SET revoked_at_us=? WHERE principal_id=? AND revoked_at_us IS NULL",
            (_us(at), str(owner))).rowcount
        connection.execute("UPDATE access_invitations SET revoked_at_us=? WHERE principal_id=? "
                           "AND redeemed_at_us IS NULL AND revoked_at_us IS NULL", (_us(at), str(owner)))
        connection.execute("UPDATE access_principals SET status=?, revoked_at_us=NULL, external_identity=NULL, "
                           "display_name=COALESCE(?, display_name), "
                           "authorization_revision=authorization_revision+1 WHERE id=?",
                           (PrincipalStatus.INVITED.value, name, str(owner)))
        invitation = self.issue_enrollment_on(connection, owner, secret, expires_at, at=at)
        return owner, invitation, revoked

    def invite(self, display_name: str, permissions: Iterable[Permission], *, now: datetime | None = None) -> Principal:
        self._require_unaudited_writes()
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            return self.invite_on(connection, uuid4(), display_name, permissions, at=at)

    def invite_on(self, connection, principal_id: UUID, display_name: str,
                  permissions: Iterable[Permission], *, at: datetime) -> Principal:
        """Create an invited principal with its grants on a caller-owned transaction.

        The principal is identified by its id and later by its own passkey,
        never by a Tailscale/proxy login: several invited people may share one.
        """
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        name = _display(display_name)
        grants = self._permissions(permissions)
        at = utc_time(at)
        principal = Principal(principal_id, None, name, PrincipalRole.INVITED_USER, PrincipalStatus.INVITED, 0, at)
        connection.execute("INSERT INTO access_principals VALUES (?, NULL, ?, ?, ?, ?, ?, NULL)",
                           (str(principal.id), name, principal.role.value, principal.status.value, 0, _us(at)))
        connection.executemany("INSERT INTO access_principal_permissions VALUES (?, ?)",
                               ((str(principal.id), grant.value) for grant in grants))
        return principal

    def issue_enrollment(self, principal_id: UUID, secret: bytes, expires_at: datetime, *, now: datetime | None = None) -> UUID:
        self._require_unaudited_writes()
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            return self.issue_enrollment_on(connection, principal_id, secret, expires_at, at=at)

    def issue_enrollment_on(self, connection, principal_id: UUID, secret: bytes, expires_at: datetime,
                            *, at: datetime) -> UUID:
        """Persist a single-use invitation digest on a caller-owned transaction.

        The expiry must lie within this deployment's invitation lifetime
        (``invitation_lifetime``, at most 7 days). The row also records the
        non-secret lookup key and the boot id plus ``CLOCK_BOOTTIME`` read
        now (``app.auth.boot_clock``); when they cannot be read nothing is
        issued (``InvitationClockUnavailable``). Applies to every invitation:
        the local bootstrap/recovery command's and an Owner-issued one.

        At most ``MAX_PENDING_INVITATIONS`` (one) pending code per principal
        (Owner decision S4-8): while one is pending
        (``_pending_invitations_on``) another is refused with
        ``AccessLimitReached``. Re-issuing revokes the pending one first in
        the same transaction (``reissue_invitation_on``).
        """
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        digest = _digest(secret)
        lookup = _lookup_key(secret)
        at, expiry = utc_time(at), utc_time(expires_at)
        if expiry <= at or expiry - at > self.invitation_lifetime:
            raise AccessValidationError("enrollment expiry is invalid")
        instant = self._boot_instant()
        if instant is None:
            raise InvitationClockUnavailable()
        invitation_id = uuid4()
        principal = connection.execute("SELECT * FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
        if principal is None or principal["status"] == PrincipalStatus.REVOKED.value:
            raise AccessValidationError("principal is unavailable")
        if self._pending_invitations_on(connection, principal_id, at) >= MAX_PENDING_INVITATIONS:
            raise AccessLimitReached()
        generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
        connection.execute("INSERT INTO access_invitations (id, secret_digest, principal_id, principal_revision, deployment_generation, issued_at_us, expires_at_us, redeemed_at_us, revoked_at_us, lookup_key, issued_boot_id, issued_boottime_us) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)",
                           (str(invitation_id), digest, str(principal_id), principal["authorization_revision"], generation, _us(at), _us(expiry),
                            lookup, instant.boot_id, instant.boottime_us))
        return invitation_id

    @staticmethod
    def _pending_invitations_on(connection, principal_id: UUID, at: datetime) -> int:
        """Unused codes of a principal that could still be redeemed at ``at``.

        Unredeemed, unrevoked, unexpired, of the current deployment
        generation and the principal's current authorization revision (the
        stored conditions of ``_redeemable``; the boot-clock check is left to
        redemption). A code made unusable by a recovery or an expiry does not
        count, so it never blocks a new one.
        """
        return connection.execute(
            "SELECT count(*) FROM access_invitations i JOIN access_principals p ON p.id=i.principal_id "
            "WHERE i.principal_id=? AND i.redeemed_at_us IS NULL AND i.revoked_at_us IS NULL "
            "AND i.expires_at_us > ? AND i.principal_revision = p.authorization_revision "
            "AND i.deployment_generation = (SELECT authorization_generation FROM access_deployment_state WHERE singleton=1)",
            (str(principal_id), _us(utc_time(at)))).fetchone()[0]

    @staticmethod
    def _administered_on(connection, principal_id: UUID):
        """The principal row an Owner administration targets, never the Owner.

        Owner decision S4-3: grant changes, revocations and re-issued codes
        refuse the Owner principal; only the local ``recover`` command changes
        the Owner's credentials. A missing or revoked principal is refused as
        well. Every refusal is the same ``AccessValidationError``.
        """
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        row = connection.execute("SELECT id, role, status, authorization_revision FROM access_principals WHERE id=?",
                                 (str(principal_id),)).fetchone()
        if (row is None or row["role"] != PrincipalRole.INVITED_USER.value
                or row["status"] == PrincipalStatus.REVOKED.value):
            raise AccessValidationError("principal is unavailable")
        return row

    def invite_with_invitation_on(self, connection, principal_id: UUID, display_name: str,
                                  permissions: Iterable[Permission], secret: bytes, *,
                                  at: datetime) -> datetime:
        """Invite one person and issue their single code in one transaction.

        On a caller-owned (audited) write transaction: the principal, its
        grants and its one invitation commit together or not at all, so no
        principal is left without the code the Owner was shown. ``at`` must
        be the time read inside that transaction; the expiry is ``at`` plus
        this deployment's ``invitation_lifetime`` (PR #234 rule) and is
        returned. Refused with ``AccessLimitReached`` when ``MAX_PRINCIPALS``
        principals (the Owner included) are not revoked (Owner decision S4-8).
        """
        at = utc_time(at)
        alive = connection.execute("SELECT count(*) FROM access_principals WHERE status<>?",
                                   (PrincipalStatus.REVOKED.value,)).fetchone()[0]
        if alive >= MAX_PRINCIPALS:
            raise AccessLimitReached()
        self.invite_on(connection, principal_id, display_name, permissions, at=at)
        expires_at = self.invitation_expiry(at)
        self.issue_enrollment_on(connection, principal_id, secret, expires_at, at=at)
        return expires_at

    def reissue_invitation_on(self, connection, principal_id: UUID, secret: bytes, *,
                              at: datetime) -> datetime:
        """Revoke a principal's unused codes and issue its one new code (Owner decision S4-4).

        Allowed for an invited and for an active principal (an active one
        redeems it to register another credential); refused for a revoked
        principal and for the Owner (S4-3). ``at`` is read inside the caller's
        transaction and the expiry, ``at`` plus ``invitation_lifetime``, is
        returned.
        """
        self._administered_on(connection, principal_id)
        at = utc_time(at)
        connection.execute("UPDATE access_invitations SET revoked_at_us=? WHERE principal_id=? "
                           "AND redeemed_at_us IS NULL AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
        expires_at = self.invitation_expiry(at)
        self.issue_enrollment_on(connection, principal_id, secret, expires_at, at=at)
        return expires_at

    def enroll_credential(self, enrollment_secret: bytes, proxy_identity: str, credential_id: bytes,
                          public_key: bytes, algorithm: int, sign_count: int, *, now: datetime | None = None,
                          backup_eligible: bool = False, backup_state: bool = False,
                          label: str | None = None, invitation_id: UUID | None = None,
                          require_device_bound: bool = False) -> Credential:
        """Redeem an invitation and record its audit row in the same transaction.

        Callers must have verified the WebAuthn registration first
        (``app.auth.passkeys.PasskeyCeremonies``). When ``invitation_id`` is
        given, the redeemed invitation must be exactly the one the verified
        registration challenge was bound to. ``proxy_identity`` must be a
        present, well-formed trusted-proxy identity but selects nothing: the
        enrollment secret alone names the invitation and so the person.

        With ``require_device_bound`` a backup-eligible credential raises
        ``DeviceBoundCredentialRequired``, decided here only after the
        invitation proved valid (and the one the challenge was bound to);
        nothing is written. Validity includes the boot-clock check
        (``app.auth.boot_clock``): the wall-clock and boot-clock readings it
        compares are taken as one pair inside the redemption transaction,
        after every gate, storage-admission and lock wait, so a slow commit
        path is never mistaken for a wall clock stepped back (PR #234
        review). ``now`` pins the wall reading for deterministic tests only;
        a ceremony passes none.

        A rejected redemption writes nothing, so an unauthenticated caller
        presenting unknown or stale codes cannot grow the audit table. When a
        matched redemption's audit append or commit fails, the rolled-back
        outcome is counted in ``audit_delivery_failed`` /
        ``undelivered_audit_records`` instead of being appended separately.
        """
        _digest(enrollment_secret)
        _identity(proxy_identity)
        if invitation_id is not None and not isinstance(invitation_id, UUID):
            raise AccessValidationError("enrollment is unavailable")
        if type(require_device_bound) is not bool:
            raise AccessValidationError("enrollment is unavailable")
        pinned = None if now is None else utc_time(now)
        # Validate the credential fields before any transaction; the stored
        # row is rebuilt with the principal and the in-transaction time.
        Credential(credential_id, UUID(int=0), public_key, algorithm, sign_count,
                   pinned if pinned is not None else utc_time(self._clock()),
                   backup_eligible=backup_eligible, backup_state=backup_state, label=label)
        # Only a matched, valid invitation reaches the append; ordinary
        # unmatched or stale attempts never touch audit health.
        audit_attempted = False
        try:
            with self._audited_transaction() as connection:
                row = self._invitation_row_on(connection, enrollment_secret,
                                              "i.*, p.role, p.status, p.authorization_revision")
                state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
                # One pair, sampled together here where the decision is made
                # (PR #234 review): a wait before this point moves both.
                at = pinned if pinned is not None else utc_time(self._clock())
                instant = self._boot_instant()
                if (not self._redeemable(row, state, at, instant)
                        or (invitation_id is not None and row["id"] != str(invitation_id))):
                    raise AccessValidationError("enrollment is unavailable")
                if require_device_bound and backup_eligible:
                    raise DeviceBoundCredentialRequired()
                principal_id = UUID(row["principal_id"])
                credential = Credential(credential_id, principal_id, public_key, algorithm, sign_count, at,
                                        backup_eligible=backup_eligible, backup_state=backup_state, label=label)
                # ``handle`` (migration 24) is the credential's random,
                # non-secret administration name: the Owner's inventory and
                # revocation use it, so the WebAuthn credential id never
                # reaches a URL, log or audit record.
                connection.execute("INSERT INTO access_credentials (credential_id, principal_id, public_key, algorithm, sign_count, enrolled_at_us, revoked_at_us, backup_eligible, backup_state, label, handle) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                                   (credential.credential_id, str(principal_id), credential.public_key, credential.algorithm, credential.sign_count, _us(at),
                                    int(credential.backup_eligible), int(credential.backup_state), credential.label, str(uuid4())))
                connection.execute("UPDATE access_invitations SET redeemed_at_us=? WHERE id=?", (_us(at), row["id"]))
                connection.execute("UPDATE access_principals SET status=? WHERE id=? AND status=?", (PrincipalStatus.ACTIVE.value, str(principal_id), PrincipalStatus.INVITED.value))
                # Same transaction: an audit write failure rolls the redemption back.
                # Only the principal's logical UUID is recorded, never the secret,
                # external identity, credential identifier or public key.
                actor = ActorCategory.OWNER if row["role"] == PrincipalRole.OWNER.value else ActorCategory.INVITED_USER
                audit_attempted = True
                self.audit.append_on(connection, actor_category=actor,
                                     action=AuditAction.REDEEM_PRINCIPAL_INVITATION,
                                     target_kind=TargetKind.PRINCIPAL, target_logical_id=principal_id,
                                     outcome=AuditOutcome.SUCCEEDED)
        except Exception:
            if audit_attempted:
                # The append or its commit failed and rolled the redemption
                # back. Surface the lost outcome in bounded health only.
                self._mark_undelivered()
            raise
        return credential

    def establish_session(self, principal_id: UUID, credential_id: bytes, token: bytes, *, proxy_identity: str,
                          now: datetime | None = None,
                          idle_lifetime: timedelta = IDLE_LIFETIME, absolute_lifetime: timedelta = ABSOLUTE_LIFETIME) -> UUID:
        """Persist a session for an already verified assertion.

        This low-level entry records no user-verification time, so a session
        created here is never fresh for an owner operation. The WebAuthn
        ceremony establishes sessions through ``accept_assertion`` instead.
        """
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            return self.establish_session_on(connection, principal_id, credential_id, token,
                                             proxy_identity=proxy_identity, at=at,
                                             idle_lifetime=idle_lifetime, absolute_lifetime=absolute_lifetime)

    def _binding(self, proxy_identity: object) -> bytes:
        """Keyed binding of a verified proxy identity; generic denial when unusable."""
        binding = None if self._session_binding is None else self._session_binding.bind(proxy_identity)
        if binding is None:
            raise AccessValidationError("access is unavailable")
        return binding

    @staticmethod
    def _end_expired_sessions_on(connection, at: datetime) -> int:
        """Invalidate sessions whose idle or absolute lifetime has ended and drop their binding.

        AUTH-012: expiry clears the keyed binding and invalidates the
        server-side record. This runs inside every authorization transaction
        that commits, in a separate transaction after a denial, when a session
        is established, and from ``end_expired_sessions`` for a periodic sweep,
        so an expired row does not keep its binding merely because nobody
        signs in again. Returns the number of rows changed.
        """
        return connection.execute(
            "UPDATE access_sessions SET invalidated_at_us=COALESCE(invalidated_at_us, ?), external_identity_binding=NULL "
            "WHERE (invalidated_at_us IS NULL OR external_identity_binding IS NOT NULL) AND (idle_expires_at_us <= ? OR absolute_expires_at_us <= ?)",
            (_us(at), _us(at), _us(at))).rowcount

    def end_expired_sessions(self, *, now: datetime | None = None) -> int:
        """Bounded maintenance sweep of expired sessions (see ``_end_expired_sessions_on``)."""
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            return self._end_expired_sessions_on(connection, at)

    def _end_expired_sessions_after_denial(self, at: datetime) -> None:
        """Commit the expiry sweep that a denied request's rolled-back transaction lost.

        Never turns the denial into anything else: a storage failure here only
        leaves the rows for the next sweep.
        """
        try:
            self.end_expired_sessions(now=at)
        except AccessStorageError:
            pass

    def establish_session_on(self, connection, principal_id: UUID, credential_id: bytes, token: bytes, *,
                             proxy_identity: str, at: datetime, verified_at: datetime | None = None,
                             verified_boot: BootInstant | None = None,
                             idle_lifetime: timedelta = IDLE_LIFETIME,
                             absolute_lifetime: timedelta = ABSOLUTE_LIFETIME) -> UUID:
        """Create an opaque session bound to one principal and one credential.

        Lifetimes default to the ADR-0003 accepted values (30 minutes idle,
        12 hours absolute). Only the token digest is stored, and of the
        proxy identity only its keyed binding (never the raw value).
        ``verified_boot`` is the boot pair read with ``verified_at`` (Owner
        step-up freshness, ``app.auth.boot_clock.step_up_fresh``); without it
        the session is never fresh for an Owner operation.
        """
        if not isinstance(principal_id, UUID) or not isinstance(credential_id, bytes):
            raise AccessValidationError("session subject is invalid")
        token_digest = _digest(token)
        binding = self._binding(proxy_identity)
        if not isinstance(idle_lifetime, timedelta) or not isinstance(absolute_lifetime, timedelta) or not timedelta(0) < idle_lifetime <= absolute_lifetime:
            raise AccessValidationError("session lifetime is invalid")
        at, session_id = utc_time(at), uuid4()
        verified = None if verified_at is None else _us(utc_time(verified_at))
        if verified is not None and verified != _us(at):
            raise AccessValidationError("session verification time is invalid")
        if verified_boot is not None and (verified is None or not isinstance(verified_boot, BootInstant)):
            raise AccessValidationError("session verification time is invalid")
        boot_id = None if verified_boot is None else verified_boot.boot_id
        boottime = None if verified_boot is None else verified_boot.boottime_us
        row = connection.execute("SELECT p.status, p.authorization_revision, c.revoked_at_us, c.inconsistent_at_us FROM access_principals p JOIN access_credentials c ON c.principal_id=p.id WHERE p.id=? AND c.credential_id=?", (str(principal_id), credential_id)).fetchone()
        if (row is None or row["status"] != PrincipalStatus.ACTIVE.value or row["revoked_at_us"] is not None
                or row["inconsistent_at_us"] is not None):
            raise AccessValidationError("session subject is unavailable")
        generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
        self._end_expired_sessions_on(connection, at)
        connection.execute("INSERT INTO access_sessions (id, token_digest, principal_id, credential_id, principal_revision, deployment_generation, established_at_us, last_seen_at_us, idle_lifetime_us, idle_expires_at_us, absolute_expires_at_us, invalidated_at_us, last_user_verification_at_us, external_identity_binding, last_user_verification_boot_id, last_user_verification_boottime_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                           (str(session_id), token_digest, str(principal_id), credential_id, row["authorization_revision"], generation,
                            _us(at), _us(at), _duration_us(idle_lifetime), _us(at + idle_lifetime), _us(at + absolute_lifetime), verified,
                            binding, boot_id, boottime))
        return session_id

    @staticmethod
    def _request_digest(token: object) -> bytes:
        """Digest a presented session token without a distinguishable failure.

        A malformed token takes the same lookup path as a well-formed unknown
        one: it is replaced by a value that cannot match any stored digest, so
        callers see only the single generic denial.
        """
        try:
            return _digest(token)
        except AccessValidationError:
            return b"\x00" * 32

    def _current_session_on(self, connection, token: object, proxy_identity: object, at: datetime,
                            mismatch: list | None = None):
        """Return the joined session row when it is currently valid, else ``None``.

        The session is found by its token digest alone. The proxy identity
        only has to reproduce the session's keyed binding (constant-time); it
        is never compared with the principal, so a shared login neither
        selects nor excludes a person. When the session is otherwise current
        and only the binding fails, ``(session_id, principal_id)`` is appended
        to ``mismatch`` so the caller can audit it after its own transaction.
        """
        digest = self._request_digest(token)
        row = connection.execute("SELECT s.*, p.id principal_id, p.external_identity, p.display_name, p.role, p.status, p.authorization_revision, p.created_at_us, p.revoked_at_us, c.revoked_at_us credential_revoked, c.inconsistent_at_us credential_inconsistent FROM access_sessions s JOIN access_principals p ON p.id=s.principal_id JOIN access_credentials c ON c.credential_id=s.credential_id WHERE s.token_digest=?", (digest,)).fetchone()
        state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
        bound = (row is not None and self._session_binding is not None
                 and self._session_binding.matches(row["external_identity_binding"], proxy_identity))
        current = (row is not None and row["invalidated_at_us"] is None
                   and row["status"] == PrincipalStatus.ACTIVE.value and row["credential_revoked"] is None
                   and row["credential_inconsistent"] is None
                   and row["principal_revision"] == row["authorization_revision"] and row["deployment_generation"] == state
                   and row["established_at_us"] <= _us(at) and row["last_seen_at_us"] <= _us(at)
                   and _us(at) < row["idle_expires_at_us"] and _us(at) < row["absolute_expires_at_us"])
        if current and not bound and mismatch is not None and self._session_binding is not None:
            mismatch.append((row["id"], UUID(row["principal_id"])))
        return row if current and bound else None

    def _record_binding_mismatch(self, mismatch: list, at: datetime) -> None:
        """Audit a binding mismatch of an otherwise current session, coalesced.

        The request is denied whatever happens here. At most one
        ``detect_session_proxy_identity_mismatch`` record (actor ``system``,
        outcome ``denied``, target the principal's logical UUID) is written per
        session per ``BINDING_MISMATCH_AUDIT_INTERVAL``; further mismatches in
        that window, including any at an earlier clock reading, only increment
        ``access_sessions.binding_mismatch_suppressed``. No identity, binding,
        token or session secret reaches the audit log. The session is neither
        revoked nor sent to step-up. A failed append, or a write refused
        before the coalescing decision (for example by the storage
        reservation), is counted in ``audit_delivery_failed`` /
        ``undelivered_audit_records``.
        """
        if not mismatch:
            return
        session_id, principal_id = mismatch[0]
        at_us = _us(utc_time(at))
        window = _duration_us(BINDING_MISMATCH_AUDIT_INTERVAL)

        decided = [False]

        def write(connection, mark):
            row = connection.execute("SELECT binding_mismatch_audited_at_us FROM access_sessions WHERE id=? AND invalidated_at_us IS NULL",
                                     (session_id,)).fetchone()
            if row is None:
                decided[0] = True
                return
            last = row[0]
            if last is not None and at_us < last + window:
                decided[0] = True
                connection.execute("UPDATE access_sessions SET binding_mismatch_suppressed=binding_mismatch_suppressed+1 WHERE id=?", (session_id,))
                return
            connection.execute("UPDATE access_sessions SET binding_mismatch_audited_at_us=? WHERE id=?", (at_us, session_id))
            decided[0] = True
            mark()
            self.audit.append_on(connection, actor_category=ActorCategory.SYSTEM,
                                 action=AuditAction.DETECT_SESSION_PROXY_IDENTITY_MISMATCH,
                                 target_kind=TargetKind.PRINCIPAL, target_logical_id=principal_id,
                                 outcome=AuditOutcome.DENIED)

        try:
            self._audited_write(write)
        except Exception:
            # Never turns the denial into anything else. A lost record is
            # counted by ``_audited_write`` once the append was attempted; a
            # failure before the coalescing decision -- including a storage
            # reservation that refuses admission -- is counted here, because
            # this mismatch may have been due a record.
            if not decided[0]:
                self._mark_undelivered()

    @staticmethod
    def _touch_session_on(connection, row, at: datetime) -> None:
        next_idle = min(_us(at) + row["idle_lifetime_us"], row["absolute_expires_at_us"])
        connection.execute("UPDATE access_sessions SET last_seen_at_us=?, idle_expires_at_us=? WHERE id=?", (_us(at), next_idle, row["id"]))

    def _authorize_gated(self, token: object, proxy_identity: object, decide, *,
                         now: datetime | None, admit: Callable[[], ContextManager] | None):
        """Run ``decide(connection, row, at)`` on a currently valid session.

        Lock order: the session gate (``admit()``, when given) -> the storage
        admission -> the SQLite write lock, all held through the commit. The
        request time is read after all three were entered, so concurrent
        requests of one session commit their idle touch in order and none is
        refused for preceding another's ``last_seen`` (Claude review, PR
        #219). A refusal by the gate (``HumanAccessClosed``) propagates before
        anything is read or written. Every other refusal is the generic
        ``AccessValidationError``; its rolled-back expiry sweep and any
        binding-mismatch audit run after the gate has been released (Codex
        PR #219), so denial bookkeeping never holds the gate.
        """
        at = None
        mismatch: list = []
        try:
            with ExitStack() as gate:
                if admit is not None:
                    gate.enter_context(admit())
                connection = gate.enter_context(self._transaction(write=True))
                at = utc_time(self._clock() if now is None else now)
                self._end_expired_sessions_on(connection, at)
                row = self._current_session_on(connection, token, proxy_identity, at, mismatch)
                if row is None:
                    raise AccessValidationError("access is unavailable")
                return decide(connection, row, at)
        except AccessValidationError:
            if at is None:
                at = utc_time(self._clock() if now is None else now)
            self._end_expired_sessions_after_denial(at)
            self._record_binding_mismatch(mismatch, at)
            raise

    def _verification_stale(self, row, at: datetime, freshness: timedelta) -> bool:
        """Whether a session's last user verification is too old for an Owner operation.

        Stale unless the verification lies between the session's
        establishment and now and is fresher than ``freshness`` on both the
        wall clock and ``CLOCK_BOOTTIME`` of the same boot, with no detected
        wall-clock step back (``app.auth.boot_clock.step_up_fresh``). The
        boot pair is read here, inside the caller's transaction, right after
        ``at``. A session without a recorded pair (established before
        migration 23, or while the boot clock was unreadable) is stale.
        """
        verified = row["last_user_verification_at_us"]
        if verified is None or not row["established_at_us"] <= verified:
            return True
        return not step_up_fresh(
            verified_us=verified, verified_boot_id=row["last_user_verification_boot_id"],
            verified_boottime_us=row["last_user_verification_boottime_us"],
            now_us=_us(at), now=self._boot_instant(), freshness_us=_duration_us(freshness))

    @staticmethod
    def _granted_on(connection, row) -> frozenset:
        """The principal's current permissions; the Owner holds every one."""
        if row["role"] == PrincipalRole.OWNER.value:
            return frozenset(Permission)
        known = {item.value: item for item in Permission}
        return frozenset(
            known[value] for (value,) in connection.execute(
                "SELECT permission FROM access_principal_permissions WHERE principal_id=?",
                (row["principal_id"],)).fetchall()
            if value in known)

    def authorize(self, token: bytes, proxy_identity: str, permission: Permission, *,
                  now: datetime | None = None,
                  admit: Callable[[], ContextManager] | None = None) -> Principal:
        """Authorize one request; every refusal is the same generic denial.

        A proxy identity that does not reproduce the session binding is
        refused for this request only; the session itself is left as it is
        (see the auth README for this Owner-reviewable choice).

        ``admit``, when given, is the reservation session gate
        (``admit(epoch)``) held around the whole authorization transaction
        (see ``_authorize_gated``). Human routes never call this: they go
        through ``authorize_request``, whose gate is mandatory. Without
        ``admit`` the authorization can commit after a reservation check
        closed access, so the bare form is for fixtures only.
        """
        if not isinstance(permission, Permission):
            raise AccessValidationError("permission is invalid")

        def decide(connection, row, at):
            granted = connection.execute("SELECT 1 FROM access_principal_permissions WHERE principal_id=? AND permission=?", (row["principal_id"], permission.value)).fetchone() is not None
            principal = self._principal(row)
            if principal.role is not PrincipalRole.OWNER and not granted:
                raise AccessValidationError("access is unavailable")
            self._touch_session_on(connection, row, at)
            return principal

        return self._authorize_gated(token, proxy_identity, decide, now=now, admit=admit)

    def authorize_request(self, token: object, proxy_identity: object, requirement: Requirement, *,
                          admit: Callable[[], ContextManager],
                          freshness: timedelta = OWNER_STEP_UP_FRESHNESS,
                          csrf: object = None,
                          touch: bool = True,
                          now: datetime | None = None) -> SessionView:
        """Authorize one human request against ``requirement`` inside the gate.

        ``admit`` is mandatory: the reservation session gate
        (``admit(epoch)``, epoch taken before this call) is held around the
        whole transaction, so the authorization and its idle touch commit
        only while human access stayed open since the request's epoch (Issue
        #144); a close in between refuses before anything is read or
        written. The session checks are exactly those of ``authorize``
        (current, unrevoked principal and credential, authorization revision
        and deployment generation, idle and absolute lifetimes, keyed
        proxy-identity binding).

        ``csrf``, when not ``None``, must equal the session's CSRF token
        (constant time, Owner decision D2). It is checked inside the same
        transaction before the idle touch, so a refused mutation does not
        extend the session.

        ``touch=False`` runs the very same checks (idle and absolute expiry
        included, at the in-gate request time) but commits no idle touch: the
        session's ``last_seen`` and idle expiry stay as they are. The Owner
        step-up routes use it (PR #236 review): only a successful step-up
        moves the idle expiry, inside ``accept_assertion``'s transaction under
        the same ``admit(epoch)``, so repeated failed or abandoned step-ups
        cannot keep an unattended Owner session alive (AGENTS.md: sessions
        end at both an idle and an absolute limit; a failed step-up changes
        nothing).

        Returns a ``SessionView`` with the role, the authorization revision
        and the permissions read in the same transaction. Every refusal is
        the same generic ``AccessValidationError``, except that an otherwise
        valid Owner session whose last user verification is not fresh gets
        ``StepUpRequired`` for ``OWNER_OP`` only (Owner decision D3). Fresh
        means newer than ``freshness`` (ADR-0003: five minutes, so stale at
        exactly five minutes) on both the wall clock and ``CLOCK_BOOTTIME``
        of the same boot, with no detected wall-clock step back, and not
        before the session's establishment (``_verification_stale``). That
        outcome is decided under the gate with the epoch unchanged and
        commits no idle touch (Owner decision S4-2, #238 item 1): an Owner
        operation refused for a stale verification is not served, so it does
        not keep the session alive; the expiry sweep still commits.
        """
        if not isinstance(requirement, Requirement) or requirement is Requirement.PRE_CREDENTIAL:
            raise AccessValidationError("access is unavailable")
        if not callable(admit):
            raise AccessValidationError("access is unavailable")
        if not isinstance(freshness, timedelta) or freshness <= timedelta(0):
            raise AccessValidationError("freshness window is invalid")
        if not isinstance(touch, bool):
            raise AccessValidationError("access is unavailable")
        binding = self._session_binding

        def decide(connection, row, at):
            owner = row["role"] == PrincipalRole.OWNER.value
            granted = self._granted_on(connection, row)
            if requirement is Requirement.LIVE and Permission.LIVE_VIEW not in granted:
                raise AccessValidationError("access is unavailable")
            if requirement is Requirement.RECORDINGS and Permission.RECORDINGS_VIEW not in granted:
                raise AccessValidationError("access is unavailable")
            if requirement in (Requirement.OWNER_READ, Requirement.OWNER_OP) and not owner:
                raise AccessValidationError("access is unavailable")
            if csrf is not None and (binding is None or not binding.csrf_matches(UUID(row["id"]), csrf)):
                raise AccessValidationError("access is unavailable")
            stale = requirement is Requirement.OWNER_OP and self._verification_stale(row, at, freshness)
            # Owner decision S4-2 (#238 item 1): a step_up_required answer
            # does not extend the session; the touch commits only when the
            # request is actually served.
            if touch and not stale:
                self._touch_session_on(connection, row, at)
            view = SessionView(UUID(row["id"]), UUID(row["principal_id"]), bytes(row["credential_id"]),
                               role=PrincipalRole(row["role"]),
                               authorization_revision=row["authorization_revision"],
                               permissions=granted)
            return view, stale

        view, stale = self._authorize_gated(token, proxy_identity, decide, now=now, admit=admit)
        if stale:
            raise StepUpRequired()
        return view

    def csrf_token(self, session_id: UUID) -> str:
        """The session's CSRF token (Owner decision D2); never stored or logged.

        ``HMAC-SHA-256`` under a subkey derived from the session-binding key
        with its own domain label (``SessionBindingKey.csrf_token``). Without
        the binding key there is no session and no token.
        """
        if self._session_binding is None or not isinstance(session_id, UUID):
            raise AccessValidationError("access is unavailable")
        return self._session_binding.csrf_token(session_id)

    @staticmethod
    def end_session_on(connection, session_id: UUID, at: datetime) -> int:
        """Invalidate one session and clear its binding on a caller-owned transaction.

        Returns the number of rows changed: ``1`` when the session was still
        valid, ``0`` when it was already invalidated or never existed.
        """
        if not isinstance(session_id, UUID):
            raise AccessValidationError("session identity is invalid")
        return connection.execute(
            "UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL "
            "WHERE id=? AND invalidated_at_us IS NULL",
            (_us(utc_time(at)), str(session_id))).rowcount

    def sign_out(self, session: SessionView, *, admit: Callable[[], ContextManager],
                 now: datetime | None = None) -> None:
        """End the caller's own session with its audit record (Owner decision D7).

        ``session`` must come from ``authorize_request`` in the same request,
        and ``admit`` must be that request's ``admit(epoch)``: the
        invalidation and its ``sign_out_principal`` record (actor ``owner`` or
        ``invited_user``, target the principal's logical UUID only, never a
        token, session id, credential id or identity) commit together inside
        the gate (lock order gate -> storage admission -> SQLite). While human
        access is closed the sign-out is refused like every other request and
        changes nothing (accepted, D7); an emergency revocation uses the local
        command over SSH (D6). A session that is no longer valid at the commit
        is the generic denial and records nothing. A failed append rolls the
        sign-out back and is counted in ``audit_delivery_failed``.
        """
        if (not isinstance(session, SessionView) or not isinstance(session.role, PrincipalRole)
                or not callable(admit)):
            raise AccessValidationError("access is unavailable")
        actor = ActorCategory.OWNER if session.role is PrincipalRole.OWNER else ActorCategory.INVITED_USER

        def write(connection, mark):
            at = utc_time(self._clock() if now is None else now)
            row = connection.execute("SELECT principal_id FROM access_sessions WHERE id=? AND invalidated_at_us IS NULL",
                                     (str(session.session_id),)).fetchone()
            if row is None or row["principal_id"] != str(session.principal_id):
                raise AccessValidationError("access is unavailable")
            if self.end_session_on(connection, session.session_id, at) != 1:
                raise AccessValidationError("access is unavailable")
            mark()
            self.audit.append_on(connection, actor_category=actor, action=AuditAction.SIGN_OUT_PRINCIPAL,
                                 target_kind=TargetKind.PRINCIPAL, target_logical_id=session.principal_id,
                                 outcome=AuditOutcome.SUCCEEDED)

        with admit():
            self._audited_write(write)

    def session_may_be_current(self, token: object, *, now: datetime | None = None) -> bool:
        """Read-only pre-check of a presented session token.

        It takes no session gate lock and no SQLite write lock; the deferred
        read still takes SQLite's SHARED lock (rollback journal) while it
        runs, so it can contend with writers for at most the SQLite timeout,
        and a failure there is a denial (fail-closed). It opens the existing
        database ``mode=ro`` and never creates one: with the verified
        filesystem gone and the mount-point directory left behind, a
        well-formed cookie gets a denial, not a fallback ``state.sqlite3``.

        ``True`` only when a session row with this token digest exists, is not
        invalidated and has not passed its idle or absolute expiry; it grants
        nothing and says nothing about the principal, credential, generation
        or proxy-identity binding, which ``authorize_session`` still checks.
        ``False`` (also for a malformed token or a storage failure) means the
        full check would deny anyway without a binding-mismatch audit, so the
        human surface refuses such a request before taking the session gate or
        any SQLite write lock: a flood of forged, well-formed cookies costs one
        deferred read transaction each and never writes (Issue #181 item 4).
        An expired row it skips is left to the periodic expiry sweep.
        """
        try:
            at = utc_time(self._clock() if now is None else now)
            digest = _digest(token)
        except Exception:
            return False
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    "SELECT 1 FROM access_sessions WHERE token_digest=? AND invalidated_at_us IS NULL "
                    "AND idle_expires_at_us > ? AND absolute_expires_at_us > ?",
                    (digest, _us(at), _us(at))).fetchone()
        except Exception:
            return False
        return row is not None

    def authorize_session(self, token: bytes, proxy_identity: str, *,
                          now: datetime | None = None,
                          admit: Callable[[], ContextManager] | None = None
                          ) -> tuple[Principal, frozenset]:
        """Authorize a request that needs a current session but no permission.

        Exactly the session checks of ``authorize`` (current, unrevoked
        principal and credential, generation, lifetimes, keyed proxy-identity
        binding, idle touch), returning the principal with its current
        permissions read in the same transaction. The Owner holds every
        permission. Every refusal is the same generic denial. The human
        surface uses ``authorize_request(..., Requirement.SESSION)``, whose
        gate is mandatory; this form remains for embedders and tests.

        ``admit``, when given, returns the reservation session gate
        (``HostnameReservationCheck.admit(epoch)``). It is entered before the
        write transaction (lock order: gate -> storage admission -> SQLite
        write lock) and held through its commit, so the authorization and
        its idle touch commit only while access stayed open since the
        request's epoch; a refusal by the gate (``HumanAccessClosed``)
        propagates before anything is read or written. The denial
        bookkeeping (expiry sweep, binding-mismatch audit) runs after the
        gate is released (Codex PR #219).

        The request time is read after the gate, the storage admission and
        the write transaction have been entered. Concurrent reads of the same
        session commit their idle touch in this order, so a request that
        waited for an earlier one is never refused because its time precedes
        that request's ``last_seen`` (Claude review, PR #219).
        """
        def decide(connection, row, at):
            granted = self._granted_on(connection, row)
            self._touch_session_on(connection, row, at)
            return self._principal(row), granted

        return self._authorize_gated(token, proxy_identity, decide, now=now, admit=admit)

    def authorize_owner(self, token: bytes, proxy_identity: str, *, now: datetime | None = None,
                        freshness: timedelta = OWNER_STEP_UP_FRESHNESS,
                        admit: Callable[[], ContextManager] | None = None) -> Principal:
        """Authorize an AUTH-008 owner operation with fresh user verification.

        Anything that is not a currently valid Owner session receives the
        generic denial. Only an authenticated Owner session whose last user
        verification is not fresh (``_verification_stale``: older than
        ``freshness``, ADR-0003 five minutes, on the wall clock or on
        ``CLOCK_BOOTTIME``, another boot, a detected wall-clock step back, or
        not between the session's establishment and now) receives the
        distinct ``StepUpRequired``. A stale session never performs the
        operation, and its idle expiry is left as it was (Owner decision
        S4-2).

        ``admit`` is the reservation session gate (Issue #228 item 5): the
        same gated pattern as ``authorize_request`` (gate -> storage
        admission -> SQLite, request time read inside), so the decision,
        ``StepUpRequired`` included, is made while access stayed open since
        the request's epoch. ``PasskeyCeremonies.authorize_owner_operation``
        always passes it.
        """
        if not isinstance(freshness, timedelta) or freshness <= timedelta(0):
            raise AccessValidationError("freshness window is invalid")

        def decide(connection, row, at):
            if row["role"] != PrincipalRole.OWNER.value:
                raise AccessValidationError("access is unavailable")
            stale = self._verification_stale(row, at, freshness)
            if not stale:  # Owner decision S4-2: no idle touch on StepUpRequired.
                self._touch_session_on(connection, row, at)
            return self._principal(row), stale

        principal, stale = self._authorize_gated(token, proxy_identity, decide, now=now, admit=admit)
        if stale:
            raise StepUpRequired()
        return principal

    def set_permissions(self, principal_id: UUID, permissions: Iterable[Permission]) -> None:
        self._require_unaudited_writes()
        at = utc_time(self._clock())
        with self._transaction(write=True) as connection:
            self.set_permissions_on(connection, principal_id, permissions, at=at)

    def set_permissions_on(self, connection, principal_id: UUID, permissions: Iterable[Permission],
                           *, at: datetime) -> bool:
        """Set a principal's grants on a caller-owned transaction; ``True`` when they changed.

        Read-modify-write in the caller's transaction (Owner decision S4-5):
        when the grant set is already the requested one nothing is written,
        the authorization revision stays and no session ends. A real change
        replaces the grants, advances the revision and ends that principal's
        sessions, while its pending invitation code stays valid
        (``_advance_principal``). Refused for the Owner, a revoked or a
        missing principal (S4-3).
        """
        self._administered_on(connection, principal_id)
        grants = frozenset(self._permissions(permissions))
        current = frozenset(Permission(value) for (value,) in connection.execute(
            "SELECT permission FROM access_principal_permissions WHERE principal_id=?", (str(principal_id),)))
        if grants == current:
            return False
        at = utc_time(at)
        connection.execute("DELETE FROM access_principal_permissions WHERE principal_id=?", (str(principal_id),))
        connection.executemany("INSERT INTO access_principal_permissions VALUES (?, ?)",
                               ((str(principal_id), value.value) for value in sorted(grants, key=lambda item: item.value)))
        self._advance_principal(connection, principal_id, at)
        return True

    def change_permission_on(self, connection, principal_id: UUID, permission: Permission,
                             granted: bool, *, at: datetime) -> bool:
        """Grant or withdraw one permission as a delta; ``True`` when the grants changed.

        ``live:view`` and ``recordings:view`` are independent: changing one
        never touches the other. Read and written in the caller's single
        transaction, so two concurrent changes of different permissions both
        apply. No-op and change semantics are those of ``set_permissions_on``.
        """
        if not isinstance(permission, Permission) or type(granted) is not bool:
            raise AccessValidationError("permissions are invalid")
        self._administered_on(connection, principal_id)
        current = {Permission(value) for (value,) in connection.execute(
            "SELECT permission FROM access_principal_permissions WHERE principal_id=?", (str(principal_id),))}
        wanted = current | {permission} if granted else current - {permission}
        return self.set_permissions_on(connection, principal_id, wanted, at=at)

    def revoke_principal(self, principal_id: UUID, *, now: datetime | None = None) -> None:
        self._require_unaudited_writes()
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            self.revoke_principal_on(connection, principal_id, at=at)

    def revoke_principal_on(self, connection, principal_id: UUID, *, at: datetime) -> None:
        """Revoke a principal with its credentials, invitations and sessions together.

        Refused for the Owner (S4-3: the Owner is replaced only by the local
        ``recover`` command), for a principal already revoked and for a
        missing one.
        """
        self._administered_on(connection, principal_id)
        at = utc_time(at)
        # The last observed proxy identity is cleared with the principal (§11.4).
        connection.execute("UPDATE access_principals SET status=?, revoked_at_us=?, external_identity=NULL, authorization_revision=authorization_revision+1 WHERE id=?", (PrincipalStatus.REVOKED.value, _us(at), str(principal_id)))
        connection.execute("UPDATE access_credentials SET revoked_at_us=? WHERE principal_id=? AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
        connection.execute("UPDATE access_invitations SET revoked_at_us=? WHERE principal_id=? AND redeemed_at_us IS NULL AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE principal_id=? AND invalidated_at_us IS NULL", (_us(at), str(principal_id)))

    def revoke_credential_on(self, connection, principal_id: UUID, handle: str, *, at: datetime) -> None:
        """Revoke one credential of a principal, named by its handle, and end its sessions.

        ``handle`` is the credential's random administration name (migration
        24, ``admin_inventory``); the WebAuthn credential id is looked up here
        and never leaves the store. Revocation is credential-scoped, not
        device-scoped: a synced passkey may exist on several devices and is
        revoked on all of them. Refused for the Owner's credentials (S4-3),
        for a revoked principal, and for an unknown, foreign or already
        revoked handle. The audited caller records only the principal's
        logical UUID.
        """
        self._administered_on(connection, principal_id)
        handle = _handle(handle)
        at = utc_time(at)
        row = connection.execute(
            "SELECT credential_id FROM access_credentials WHERE handle=? AND principal_id=? AND revoked_at_us IS NULL",
            (handle, str(principal_id))).fetchone()
        if row is None:
            raise AccessValidationError("credential is unavailable")
        credential_id = bytes(row["credential_id"])
        connection.execute("UPDATE access_credentials SET revoked_at_us=? WHERE credential_id=? AND principal_id=?",
                           (_us(at), credential_id, str(principal_id)))
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE credential_id=? AND invalidated_at_us IS NULL", (_us(at), credential_id))

    def require_owner_session_on(self, connection, view: "SessionView", at: datetime, *,
                                 freshness: timedelta = OWNER_STEP_UP_FRESHNESS) -> None:
        """Re-check, inside an Owner operation's own transaction, that its session still holds.

        ``view`` is the ``SessionView`` the request's ``OWNER_OP``
        authorization returned. The gate (``admit(epoch)``) already refuses a
        reservation close, reopen or ``stop()`` since that authorization, but
        the local ``recover`` / revocation commands commit outside the gate
        (D6), so the operation's transaction reads the session again after
        ``BEGIN IMMEDIATE``: not invalidated, of the same principal and
        credential, the principal still the active Owner at the
        authorization revision the view saw (and the session's own revision
        and the deployment generation unchanged), the credential neither
        revoked nor inconsistent, the idle and absolute lifetimes not passed
        at ``at``, and the user verification still fresh
        (``_verification_stale``). The proxy-identity binding was checked by
        the authorization under the same epoch. A stale verification raises
        ``StepUpRequired``; anything else the generic ``AccessValidationError``.
        Nothing is written, so the session's idle expiry does not move.
        """
        if (not isinstance(view, SessionView) or view.role is not PrincipalRole.OWNER
                or type(view.authorization_revision) is not int or not isinstance(view.credential_id, bytes)):
            raise AccessValidationError("access is unavailable")
        at = utc_time(at)
        row = connection.execute(
            "SELECT s.*, p.role, p.status, p.authorization_revision, c.revoked_at_us credential_revoked, "
            "c.inconsistent_at_us credential_inconsistent FROM access_sessions s "
            "JOIN access_principals p ON p.id=s.principal_id JOIN access_credentials c ON c.credential_id=s.credential_id "
            "WHERE s.id=?", (str(view.session_id),)).fetchone()
        generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
        now = _us(at)
        current = (row is not None and row["principal_id"] == str(view.principal_id)
                   and hmac.compare_digest(bytes(row["credential_id"]), view.credential_id)
                   and row["invalidated_at_us"] is None
                   and row["role"] == PrincipalRole.OWNER.value and row["status"] == PrincipalStatus.ACTIVE.value
                   and row["credential_revoked"] is None and row["credential_inconsistent"] is None
                   and row["principal_revision"] == row["authorization_revision"] == view.authorization_revision
                   and row["deployment_generation"] == generation
                   and row["established_at_us"] <= now and row["last_seen_at_us"] <= now
                   and now < row["idle_expires_at_us"] and now < row["absolute_expires_at_us"])
        if not current:
            raise AccessValidationError("access is unavailable")
        if self._verification_stale(row, at, freshness):
            raise StepUpRequired()

    def admin_inventory(self) -> tuple[dict, ...]:
        """The Owner's read-only view of every principal (Issue #10 phase 2 S4).

        One read transaction (``mode=ro``, nothing written). Per principal,
        ordered by creation: ``id``, ``display_name``, ``role``, ``status``,
        ``created_at``, ``revoked_at``, ``permissions`` (sorted values; the
        Owner holds every one), ``invitation`` (``pending``: an unused code
        that could still be redeemed, with its ``expires_at``) and
        ``credentials``: per credential ``handle``, ``label``, ``status``
        (``active``/``revoked``/``inconsistent``), ``inconsistency_reason``,
        ``backup_eligible``, ``backup_state``, ``created_at``,
        ``last_used_at`` and ``revoked_at``. Times are ISO 8601 UTC strings.

        Deliberately absent: the last observed proxy identity (Owner decision
        D14: a shared account does not tell people apart), WebAuthn credential
        ids, public keys, signature counters, invitation digests and lookup
        keys, and all session data.
        """
        def iso(value):
            return None if value is None else _time(value).isoformat()

        with self._transaction() as connection:
            at = _us(self.now())
            principals = connection.execute(
                "SELECT id, display_name, role, status, created_at_us, revoked_at_us FROM access_principals "
                "ORDER BY created_at_us, id").fetchall()
            grants: dict[str, list] = {}
            for principal_id, value in connection.execute(
                    "SELECT principal_id, permission FROM access_principal_permissions ORDER BY permission"):
                grants.setdefault(principal_id, []).append(value)
            pending = {row[0]: row[1] for row in connection.execute(
                "SELECT i.principal_id, max(i.expires_at_us) FROM access_invitations i "
                "JOIN access_principals p ON p.id=i.principal_id "
                "WHERE i.redeemed_at_us IS NULL AND i.revoked_at_us IS NULL AND i.expires_at_us > ? "
                "AND i.principal_revision = p.authorization_revision AND p.status <> 'revoked' "
                "AND i.deployment_generation = (SELECT authorization_generation FROM access_deployment_state WHERE singleton=1) "
                "GROUP BY i.principal_id", (at,))}
            credentials: dict[str, list] = {}
            for row in connection.execute(
                    "SELECT principal_id, handle, label, revoked_at_us, inconsistent_at_us, inconsistency_reason, "
                    "backup_eligible, backup_state, enrolled_at_us, last_used_at_us FROM access_credentials "
                    "ORDER BY enrolled_at_us, handle"):
                status = (CredentialStatus.REVOKED if row["revoked_at_us"] is not None
                          else CredentialStatus.INCONSISTENT if row["inconsistent_at_us"] is not None
                          else CredentialStatus.ACTIVE)
                credentials.setdefault(row["principal_id"], []).append({
                    "handle": row["handle"],
                    "label": row["label"],
                    "status": status.value,
                    "inconsistency_reason": row["inconsistency_reason"],
                    "backup_eligible": bool(row["backup_eligible"]),
                    "backup_state": bool(row["backup_state"]),
                    "created_at": iso(row["enrolled_at_us"]),
                    "last_used_at": iso(row["last_used_at_us"]),
                    "revoked_at": iso(row["revoked_at_us"]),
                })
        result = []
        for row in principals:
            owner = row["role"] == PrincipalRole.OWNER.value
            result.append({
                "id": row["id"],
                "display_name": row["display_name"],
                "role": row["role"],
                "status": row["status"],
                "created_at": iso(row["created_at_us"]),
                "revoked_at": iso(row["revoked_at_us"]),
                "permissions": sorted(item.value for item in Permission) if owner else grants.get(row["id"], []),
                "invitation": {"pending": row["id"] in pending, "expires_at": iso(pending.get(row["id"]))},
                "credentials": credentials.get(row["id"], []),
            })
        return tuple(result)

    def invalidate_all_sessions_on(self, connection, *, at: datetime) -> None:
        """Advance the deployment authorization generation and end every human session.

        Runs on a caller-owned (audited) transaction. Every session, the
        Owner's included, stops being accepted, as does every enrollment
        authorization issued under the previous generation. Principals, grants
        and credentials are unchanged: each person signs in again with their
        own credential, and a pending invitation must be issued again.

        Every pending WebAuthn challenge is deleted as well (PR #174 review):
        an assertion signed over a challenge issued before the revocation, for
        example one a listener answering during an exposure received, cannot
        establish a session afterwards. A ceremony in progress starts again.
        """
        at = utc_time(at)
        connection.execute("UPDATE access_deployment_state SET authorization_generation=authorization_generation+1 WHERE singleton=1")
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE invalidated_at_us IS NULL", (_us(at),))
        connection.execute("DELETE FROM access_webauthn_challenges")

    # --- WebAuthn ceremony state (Issue #10). Verification lives in app.auth.webauthn;
    # these methods persist only digests, flags and the accepted counter. ---

    def _audited_write(self, write):
        """Run ``write(connection)`` in an audited transaction; count a lost audit."""
        audit_attempted = [False]

        def mark():
            audit_attempted[0] = True

        try:
            with self._audited_transaction() as connection:
                return write(connection, mark)
        except Exception:
            if audit_attempted[0]:
                self._mark_undelivered()
            raise

    def _insert_challenge_on(self, connection, digest: bytes, ceremony: str, at: datetime, lifetime: timedelta,
                             *, invitation_id: str | None = None, session_id: str | None = None) -> None:
        """Insert a challenge digest; reached only from the three ``begin`` steps below.

        Their only runtime caller, ``PasskeyCeremonies``, runs each of them
        inside the reservation session gate (``admit(epoch)``, epoch taken at
        the start of the request), so a challenge either commits before a
        close, and ``invalidate_all_sessions_on`` deletes it with every other
        pending challenge, or is never stored (Issue #144, PR #174 review).
        The row carries no authorization generation: under that gate any
        revocation either precedes the request (the challenge is fresh) or
        follows the insert (it deletes the row), so a generation column would
        add nothing, and the table has no column to hold one without a
        migration.
        """
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise AccessValidationError("access is unavailable")
        if not isinstance(lifetime, timedelta) or not timedelta(0) < lifetime <= MAX_CHALLENGE_LIFETIME:
            raise AccessValidationError("challenge lifetime is invalid")
        connection.execute("DELETE FROM access_webauthn_challenges WHERE expires_at_us <= ?", (_us(at),))
        pending = connection.execute("SELECT count(*) FROM access_webauthn_challenges").fetchone()[0]
        if pending >= MAX_PENDING_CHALLENGES:
            raise AccessValidationError("access is unavailable")
        connection.execute("INSERT INTO access_webauthn_challenges (challenge_digest, ceremony, invitation_id, session_id, issued_at_us, expires_at_us) VALUES (?, ?, ?, ?, ?, ?)",
                           (digest, ceremony, invitation_id, session_id, _us(at), _us(at + lifetime)))

    def _in_transaction_time(self, pinned: datetime | None) -> datetime:
        """The decision time of a ceremony step, read inside its transaction.

        Called only after the storage admission and ``BEGIN IMMEDIATE`` were
        entered, so nothing is decided with a time read before a wait for
        either (PR #234 review). ``pinned`` is for deterministic tests and
        direct callers only; ``PasskeyCeremonies`` passes none.
        """
        return pinned if pinned is not None else utc_time(self._clock())

    def issue_authentication_challenge(self, digest: bytes, *, at: datetime | None = None,
                                       lifetime: timedelta) -> None:
        """Store the digest of an unbound sign-in challenge (discoverable credentials).

        Its issue and expiry times are read inside the transaction (see
        ``_in_transaction_time``); ``at`` pins them for tests only.
        """
        pinned = None if at is None else utc_time(at)
        with self._transaction(write=True) as connection:
            self._insert_challenge_on(connection, digest, "authentication",
                                      self._in_transaction_time(pinned), lifetime)

    def begin_registration(self, enrollment_secret: object, proxy_identity: object, digest: bytes, *,
                           at: datetime | None = None, lifetime: timedelta) -> RegistrationSubject:
        """Bind a registration challenge to one valid invitation and count the attempt.

        The invitation is not redeemed here. An absent, unknown, expired,
        redeemed, revoked, generation-stale or attempt-exhausted code receives
        the generic denial and writes nothing. The enrollment secret alone
        selects the invitation; the proxy identity must be present and
        well-formed but is not compared with anything.

        Validity includes the boot-clock check (``app.auth.boot_clock``): the
        wall-clock and boot-clock readings are taken as one pair inside the
        transaction, after the storage-admission and lock waits and right
        before the decision (PR #234 review, as in ``enroll_credential``), so
        an invitation that expired, or a wall clock stepped back, during such
        a wait is refused and nothing is written. The challenge's issue and
        expiry times are that same reading. ``at`` pins the wall reading for
        deterministic tests only; a ceremony passes none.
        """
        pinned = None if at is None else utc_time(at)
        try:
            _digest(enrollment_secret)
            _identity(proxy_identity)
        except AccessValidationError:
            raise AccessValidationError("access is unavailable") from None
        with self._transaction(write=True) as connection:
            row = self._invitation_row_on(connection, enrollment_secret,
                                          "i.*, p.display_name, p.status, p.authorization_revision")
            state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
            # One pair, sampled together here where the decision is made.
            at = self._in_transaction_time(pinned)
            instant = self._boot_instant()
            if not self._redeemable(row, state, at, instant):
                raise AccessValidationError("access is unavailable")
            counted = connection.execute("UPDATE access_invitations SET attempt_count=attempt_count+1 WHERE id=? AND attempt_count < ? AND redeemed_at_us IS NULL",
                                         (row["id"], MAX_REDEMPTION_ATTEMPTS)).rowcount
            if counted != 1:
                raise AccessValidationError("access is unavailable")
            self._insert_challenge_on(connection, digest, "registration", at, lifetime, invitation_id=row["id"])
            # Only usable credentials (PR #234 review): after a recovery the
            # Owner's revoked passkey may still sit in a synced keychain under
            # the same user handle, and excluding it would make that
            # authenticator refuse the replacement registration.
            excluded = tuple(bytes(item[0]) for item in connection.execute(
                "SELECT credential_id FROM access_credentials WHERE principal_id=? AND revoked_at_us IS NULL "
                "AND inconsistent_at_us IS NULL ORDER BY enrolled_at_us", (row["principal_id"],)))
            return RegistrationSubject(UUID(row["id"]), UUID(row["principal_id"]), row["display_name"], excluded)

    def consume_challenge(self, digest: bytes, ceremony: str, *, at: datetime | None = None) -> ConsumedChallenge:
        """Delete a pending challenge exactly once and return its binding.

        The challenge is removed whether or not the ceremony later verifies, so
        a failed attempt cannot be retried with it. A challenge used outside
        its issue-to-expiry window, or for another ceremony, is refused. The
        window is checked at a time read inside the transaction (see
        ``_in_transaction_time``), so a challenge that expired during a lock
        or admission wait is refused; ``at`` pins it for tests only.
        """
        pinned = None if at is None else utc_time(at)
        if not isinstance(digest, bytes) or len(digest) != 32 or ceremony not in ("registration", "authentication", "step_up"):
            raise AccessValidationError("access is unavailable")
        with self._transaction(write=True) as connection:
            at = self._in_transaction_time(pinned)
            row = connection.execute("DELETE FROM access_webauthn_challenges WHERE challenge_digest=? AND ceremony=? RETURNING invitation_id, session_id, issued_at_us, expires_at_us",
                                     (digest, ceremony)).fetchone()
            row = None if row is None else dict(row)
        if row is None or not row["issued_at_us"] <= _us(at) < row["expires_at_us"]:
            raise AccessValidationError("access is unavailable")
        return ConsumedChallenge(None if row["invitation_id"] is None else UUID(row["invitation_id"]),
                                 None if row["session_id"] is None else UUID(row["session_id"]))

    def begin_step_up(self, token: object, proxy_identity: object, digest: bytes, *,
                      at: datetime | None = None, lifetime: timedelta) -> bytes:
        """Bind a step-up challenge to a current Owner session and return its credential id.

        The returned id is the only entry of the challenge's allowed-credential
        list; ``accept_assertion`` refuses an assertion from any other credential.
        A pending step-up challenge of the same session is replaced, so each
        session holds at most one.
        The session is judged current at a time read inside the transaction
        (see ``_in_transaction_time``); ``at`` pins it for tests only.
        """
        pinned = None if at is None else utc_time(at)
        at = None
        mismatch: list = []
        try:
            with self._transaction(write=True) as connection:
                at = self._in_transaction_time(pinned)
                self._end_expired_sessions_on(connection, at)
                row = self._current_session_on(connection, token, proxy_identity, at, mismatch)
                if row is None or row["role"] != PrincipalRole.OWNER.value:
                    raise AccessValidationError("access is unavailable")
                # One outstanding step-up challenge per session: a new begin
                # replaces the previous one, so a session cannot fill the
                # bounded challenge table that sign-in also uses.
                connection.execute("DELETE FROM access_webauthn_challenges WHERE ceremony='step_up' AND session_id=?",
                                   (row["id"],))
                self._insert_challenge_on(connection, digest, "step_up", at, lifetime, session_id=row["id"])
                return bytes(row["credential_id"])
        except AccessValidationError:
            if at is None:
                at = self._in_transaction_time(pinned)
            self._end_expired_sessions_after_denial(at)
            self._record_binding_mismatch(mismatch, at)
            raise

    def pending_step_up_challenge(self, digest: bytes, *, at: datetime | None = None) -> UUID | None:
        """The session a pending, unexpired step-up challenge is bound to; read only.

        Nothing is deleted: ``accept_assertion`` deletes the challenge in the
        transaction that refreshes the session (PR #236 review), a credential
        finding spends it in the transaction that records the finding
        (``record_step_up_finding``), and any other refused step-up spends it
        through ``consume_challenge``. The window is checked
        at a time read inside the transaction; ``at`` pins it for tests only.
        """
        pinned = None if at is None else utc_time(at)
        if not isinstance(digest, bytes) or len(digest) != 32:
            return None
        with self._transaction() as connection:
            now = self._in_transaction_time(pinned)
            row = connection.execute("SELECT session_id, issued_at_us, expires_at_us FROM access_webauthn_challenges WHERE challenge_digest=? AND ceremony='step_up'",
                                     (digest,)).fetchone()
        if row is None or row["session_id"] is None or not row["issued_at_us"] <= _us(now) < row["expires_at_us"]:
            return None
        return UUID(row["session_id"])

    def current_session(self, token: object, proxy_identity: object, *, at: datetime) -> SessionView | None:
        """Lookup of a currently valid session; records no activity.

        Only a binding mismatch of an otherwise current session writes, and
        then only the coalesced audit record of ``_record_binding_mismatch``.
        """
        at = utc_time(at)
        mismatch: list = []
        with self._transaction() as connection:
            row = self._current_session_on(connection, token, proxy_identity, at, mismatch)
        if row is None:
            self._record_binding_mismatch(mismatch, at)
            return None
        return SessionView(UUID(row["id"]), UUID(row["principal_id"]), bytes(row["credential_id"]))

    def assertion_subject(self, credential_id: bytes) -> tuple[Principal, Credential] | None:
        """Read the stored credential and its principal for signature verification."""
        if not isinstance(credential_id, bytes):
            return None
        with self._transaction() as connection:
            row = connection.execute("SELECT c.*, p.id principal_row_id, p.external_identity, p.display_name, p.role, p.status, p.authorization_revision, p.created_at_us, p.revoked_at_us principal_revoked_at_us FROM access_credentials c JOIN access_principals p ON p.id=c.principal_id WHERE c.credential_id=?", (credential_id,)).fetchone()
        if row is None:
            return None
        principal = Principal(UUID(row["principal_row_id"]), row["external_identity"], row["display_name"],
                              PrincipalRole(row["role"]), PrincipalStatus(row["status"]), row["authorization_revision"],
                              _time(row["created_at_us"]),
                              _time(row["principal_revoked_at_us"]) if row["principal_revoked_at_us"] is not None else None)
        return principal, self._credential(row)

    def credentials_for(self, principal_id: UUID) -> tuple[Credential, ...]:
        """Credential rows of a principal, WebAuthn material included (internal and tests).

        Not an Owner view: the Owner's inventory is ``admin_inventory``, which
        names credentials by handle only.
        """
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        with self._transaction() as connection:
            rows = connection.execute("SELECT * FROM access_credentials WHERE principal_id=? ORDER BY enrolled_at_us, credential_id", (str(principal_id),)).fetchall()
        return tuple(self._credential(row) for row in rows)

    def accept_assertion(self, credential_id: bytes, principal_id: UUID, proxy_identity: str, *,
                         expected_sign_count: int, sign_count: int, backup_state: bool,
                         at: datetime | None = None,
                         token: bytes | None = None, step_up_session_id: UUID | None = None,
                         step_up_challenge: bytes | None = None) -> UUID:
        """Commit a verified assertion: counter, backup state, last use and its session effect.

        With ``token`` a new session is established (sign-in); with
        ``step_up_session_id`` that session's user-verification time is
        refreshed, but only when the session is an Owner's, was created by
        this very credential, and the boot clock can be read (a step-up that
        could never make the session fresh is refused rather than reported
        as done). A step-up also requires ``step_up_challenge``, the digest of
        that session's pending, unexpired step-up challenge, which is deleted
        in this same transaction: a refused commit rolls the deletion back,
        and a challenge is never spent by a refresh that did not happen
        (PR #236 review). The verification time is recorded with the boot id and
        ``CLOCK_BOOTTIME`` read in the same transaction. The counter update
        is conditional on the value the signature was checked against, so
        two racing assertions cannot both advance it. The audit record commits in the same transaction.

        The credential selected the principal; the proxy identity is only
        recorded as the principal's last observed value and, for a new
        session, bound into it. A step-up must present the identity its
        session is bound to.

        The commit time (last use, the new session's start and verification
        time, the step-up verification time and the step-up session's expiry
        checks) is read inside the transaction (see ``_in_transaction_time``),
        so a session that expired during a lock or admission wait is refused,
        not refreshed; ``at`` pins it for tests only.
        """
        if (token is None) == (step_up_session_id is None):
            raise AccessValidationError("access is unavailable")
        if (step_up_challenge is not None) != (step_up_session_id is not None) or (
                step_up_challenge is not None
                and (not isinstance(step_up_challenge, bytes) or len(step_up_challenge) != 32)):
            raise AccessValidationError("access is unavailable")
        pinned = None if at is None else utc_time(at)
        identity = _identity(proxy_identity)

        def write(connection, mark):
            at = self._in_transaction_time(pinned)
            # Read as one pair with ``at``: the verification time of a new
            # session or a step-up is fresh only on both clocks.
            instant = self._boot_instant()
            row = connection.execute("SELECT c.sign_count, c.revoked_at_us, c.inconsistent_at_us, c.backup_eligible, p.role, p.status FROM access_credentials c JOIN access_principals p ON p.id=c.principal_id WHERE c.credential_id=? AND c.principal_id=?",
                                     (credential_id, str(principal_id))).fetchone()
            if (row is None or row["status"] != PrincipalStatus.ACTIVE.value or row["revoked_at_us"] is not None
                    or row["inconsistent_at_us"] is not None
                    or row["sign_count"] != expected_sign_count or (backup_state and not row["backup_eligible"])):
                raise AccessValidationError("access is unavailable")
            changed = connection.execute("UPDATE access_credentials SET sign_count=?, backup_state=?, last_used_at_us=? WHERE credential_id=? AND sign_count=? AND revoked_at_us IS NULL AND inconsistent_at_us IS NULL",
                                         (sign_count, int(backup_state), _us(at), credential_id, expected_sign_count)).rowcount
            if changed != 1:
                raise AccessValidationError("access is unavailable")
            actor = ActorCategory.OWNER if row["role"] == PrincipalRole.OWNER.value else ActorCategory.INVITED_USER
            if token is not None:
                session_id = self.establish_session_on(connection, principal_id, credential_id, token,
                                                       proxy_identity=identity, at=at, verified_at=at,
                                                       verified_boot=instant)
                action = AuditAction.AUTHENTICATE_PRINCIPAL
            else:
                session = connection.execute("SELECT s.*, p.authorization_revision FROM access_sessions s JOIN access_principals p ON p.id=s.principal_id WHERE s.id=?",
                                             (str(step_up_session_id),)).fetchone()
                state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
                if (instant is None or row["role"] != PrincipalRole.OWNER.value
                        or session is None or session["principal_id"] != str(principal_id)
                        or bytes(session["credential_id"]) != credential_id or session["invalidated_at_us"] is not None
                        or session["principal_revision"] != session["authorization_revision"]
                        or session["deployment_generation"] != state
                        or not session["established_at_us"] <= _us(at) or not session["last_seen_at_us"] <= _us(at)
                        or _us(at) >= session["idle_expires_at_us"] or _us(at) >= session["absolute_expires_at_us"]
                        or self._session_binding is None
                        or not self._session_binding.matches(session["external_identity_binding"], identity)):
                    raise AccessValidationError("access is unavailable")
                # Spent only by this commit: a refusal below rolls it back.
                challenge = connection.execute("DELETE FROM access_webauthn_challenges WHERE challenge_digest=? AND ceremony='step_up' AND session_id=? RETURNING issued_at_us, expires_at_us",
                                               (step_up_challenge, session["id"])).fetchone()
                if challenge is None or not challenge["issued_at_us"] <= _us(at) < challenge["expires_at_us"]:
                    raise AccessValidationError("access is unavailable")
                connection.execute("UPDATE access_sessions SET last_user_verification_at_us=?, last_user_verification_boot_id=?, "
                                   "last_user_verification_boottime_us=? WHERE id=?",
                                   (_us(at), instant.boot_id, instant.boottime_us, session["id"]))
                self._touch_session_on(connection, session, at)
                session_id = step_up_session_id
                action = AuditAction.VERIFY_PRINCIPAL_STEP_UP
            # Stored, never returned or shown (Owner decision D14), overwritten
            # each authentication, never an input.
            connection.execute("UPDATE access_principals SET external_identity=? WHERE id=?", (identity, str(principal_id)))
            mark()
            self.audit.append_on(connection, actor_category=actor, action=action,
                                 target_kind=TargetKind.PRINCIPAL, target_logical_id=principal_id,
                                 outcome=AuditOutcome.SUCCEEDED)
            return session_id

        return self._audited_write(write)

    def mark_credential_inconsistent(self, credential_id: bytes, principal_id: UUID, *, at: datetime) -> None:
        """Atomically mark a credential whose backup eligibility changed and end its sessions.

        The credential stays unusable until the Owner revokes/replaces it; the
        audit record carries only the principal's logical UUID.
        """
        at = utc_time(at)
        self._audited_write(lambda connection, mark: self._mark_credential_inconsistent_on(
            connection, mark, credential_id, principal_id, at))

    def _mark_credential_inconsistent_on(self, connection, mark, credential_id: bytes, principal_id: UUID,
                                         at: datetime) -> None:
        changed = connection.execute("UPDATE access_credentials SET inconsistency_reason='backup_eligibility_changed', inconsistent_at_us=? WHERE credential_id=? AND principal_id=? AND inconsistent_at_us IS NULL AND revoked_at_us IS NULL",
                                     (_us(at), credential_id, str(principal_id))).rowcount
        if changed != 1:
            return
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE credential_id=? AND invalidated_at_us IS NULL", (_us(at), credential_id))
        mark()
        self.audit.append_on(connection, actor_category=ActorCategory.SYSTEM,
                             action=AuditAction.MARK_PRINCIPAL_CREDENTIAL_INCONSISTENT,
                             target_kind=TargetKind.PRINCIPAL, target_logical_id=principal_id,
                             outcome=AuditOutcome.SUCCEEDED)

    def record_sign_count_regression(self, principal_id: UUID) -> None:
        """Record a refused assertion whose signature counter regressed."""
        self._audited_write(lambda connection, mark: self._record_sign_count_regression_on(
            connection, mark, principal_id))

    def _record_sign_count_regression_on(self, connection, mark, principal_id: UUID) -> None:
        mark()
        self.audit.append_on(connection, actor_category=ActorCategory.SYSTEM,
                             action=AuditAction.DETECT_PRINCIPAL_CREDENTIAL_SIGN_COUNT_REGRESSION,
                             target_kind=TargetKind.PRINCIPAL, target_logical_id=principal_id,
                             outcome=AuditOutcome.FAILED)

    def record_step_up_finding(self, digest: bytes, session_id: UUID, *, backup_eligibility_changed: bool,
                               credential_id: bytes, principal_id: UUID,
                               at: datetime | None = None) -> bool:
        """Spend a step-up challenge and record its credential finding in one transaction.

        The finding of a refused step-up (a changed backup eligibility, or a
        counter that did not advance) is recorded only by the attempt that
        actually deletes this session's pending, unexpired step-up challenge
        (``challenge_digest``, ceremony ``step_up`` and ``session_id`` all
        match): the DELETE runs first, and the finding's writes — the
        credential mark with its session invalidation, or the regression
        record, each with its audit record — follow in the same SQLite
        transaction (PR #236 review). Returns ``True`` only then.

        When the DELETE removes nothing (a concurrent finish of the same
        assertion already spent the challenge, and its ``accept_assertion``
        may have advanced the counter this attempt compared against), or the
        removed challenge is outside its issue-to-expiry window, nothing else
        is written and ``False`` is returned: no finding, no audit record, no
        notification. A failure rolls back the DELETE together with the
        finding; the caller then spends the challenge on its own, so it stays
        single use while the unchanged stored credential lets the next
        assertion detect the finding again. ``at`` pins the commit time for
        tests only.
        """
        pinned = None if at is None else utc_time(at)
        if (not isinstance(digest, bytes) or len(digest) != 32 or not isinstance(session_id, UUID)
                or not isinstance(credential_id, bytes) or not isinstance(principal_id, UUID)):
            raise AccessValidationError("access is unavailable")

        def write(connection, mark):
            now = self._in_transaction_time(pinned)
            row = connection.execute("DELETE FROM access_webauthn_challenges WHERE challenge_digest=? AND ceremony='step_up' AND session_id=? RETURNING issued_at_us, expires_at_us",
                                     (digest, str(session_id))).fetchone()
            if row is None or not row["issued_at_us"] <= _us(now) < row["expires_at_us"]:
                return False
            if backup_eligibility_changed:
                self._mark_credential_inconsistent_on(connection, mark, credential_id, principal_id, now)
            else:
                self._record_sign_count_regression_on(connection, mark, principal_id)
            return True

        return self._audited_write(write)

    @staticmethod
    def _permissions(values: Iterable[Permission]) -> tuple[Permission, ...]:
        try:
            result = tuple(values)
        except TypeError:
            raise AccessValidationError("permissions are invalid") from None
        if len(set(result)) != len(result) or any(not isinstance(value, Permission) for value in result):
            raise AccessValidationError("permissions are invalid")
        return result

    @staticmethod
    def _advance_principal(connection, principal_id: UUID, at: datetime) -> None:
        # All statements are within the caller's BEGIN IMMEDIATE transaction:
        # a commit publishes the revision and every invalidation together, while
        # a failure rolls both back. A real invalidation timestamp avoids a
        # sentinel value that could be misread as a valid Unix epoch session.
        # A grant change keeps the principal's pending code valid (Owner
        # decision S4-5): an invitation still at the current revision moves
        # with it, while one already stale (or redeemed/revoked) stays as is.
        connection.execute("UPDATE access_invitations SET principal_revision=principal_revision+1 WHERE principal_id=? "
                           "AND redeemed_at_us IS NULL AND revoked_at_us IS NULL AND principal_revision="
                           "(SELECT authorization_revision FROM access_principals WHERE id=?)",
                           (str(principal_id), str(principal_id)))
        connection.execute("UPDATE access_principals SET authorization_revision=authorization_revision+1 WHERE id=?", (str(principal_id),))
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE principal_id=? AND invalidated_at_us IS NULL", (_us(at), str(principal_id)))
