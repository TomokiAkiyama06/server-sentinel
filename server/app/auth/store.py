"""Transactional local authorization state; WebAuthn verification lives in ``webauthn.py``."""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
from typing import Callable, Iterable
from uuid import UUID, uuid4

from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.audit.store import AuditStorageError, AuditStore
from app.storage.database import Database
from .model import AccessValidationError, Credential, Permission, Principal, PrincipalRole, PrincipalStatus, utc_time
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


@dataclass(frozen=True)
class RegistrationSubject:
    invitation_id: UUID
    principal_id: UUID
    display_name: str
    excluded_credential_ids: tuple[bytes, ...]


@dataclass(frozen=True)
class SessionView:
    session_id: UUID
    principal_id: UUID
    credential_id: bytes


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
                 session_binding: SessionBindingKey | None = None):
        if type(unaudited_writes) is not bool:
            raise AccessValidationError("unaudited write mode is invalid")
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

    @contextmanager
    def _transaction(self, write: bool = False):
        connection = None
        try:
            connection = self.database.connect()
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
        """Persist a single-use invitation digest on a caller-owned transaction."""
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        digest = _digest(secret)
        at, expiry = utc_time(at), utc_time(expires_at)
        if expiry <= at:
            raise AccessValidationError("enrollment expiry is invalid")
        invitation_id = uuid4()
        principal = connection.execute("SELECT * FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
        if principal is None or principal["status"] == PrincipalStatus.REVOKED.value:
            raise AccessValidationError("principal is unavailable")
        generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
        connection.execute("INSERT INTO access_invitations (id, secret_digest, principal_id, principal_revision, deployment_generation, issued_at_us, expires_at_us, redeemed_at_us, revoked_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                           (str(invitation_id), digest, str(principal_id), principal["authorization_revision"], generation, _us(at), _us(expiry)))
        return invitation_id

    def enroll_credential(self, enrollment_secret: bytes, proxy_identity: str, credential_id: bytes,
                          public_key: bytes, algorithm: int, sign_count: int, *, now: datetime | None = None,
                          backup_eligible: bool = False, backup_state: bool = False,
                          label: str | None = None, invitation_id: UUID | None = None) -> Credential:
        """Redeem an invitation and record its audit row in the same transaction.

        Callers must have verified the WebAuthn registration first
        (``app.auth.passkeys.PasskeyCeremonies``). When ``invitation_id`` is
        given, the redeemed invitation must be exactly the one the verified
        registration challenge was bound to. ``proxy_identity`` must be a
        present, well-formed trusted-proxy identity but selects nothing: the
        enrollment secret alone names the invitation and so the person.

        A rejected redemption writes nothing, so an unauthenticated caller
        presenting unknown or stale codes cannot grow the audit table. When a
        matched redemption's audit append or commit fails, the rolled-back
        outcome is counted in ``audit_delivery_failed`` /
        ``undelivered_audit_records`` instead of being appended separately.
        """
        digest = _digest(enrollment_secret)
        _identity(proxy_identity)
        if invitation_id is not None and not isinstance(invitation_id, UUID):
            raise AccessValidationError("enrollment is unavailable")
        credential = Credential(credential_id, UUID(int=0), public_key, algorithm, sign_count,
                                utc_time(self._clock() if now is None else now),
                                backup_eligible=backup_eligible, backup_state=backup_state, label=label)
        at = credential.enrolled_at
        # Only a matched, valid invitation reaches the append; ordinary
        # unmatched or stale attempts never touch audit health.
        audit_attempted = False
        try:
            with self._audited_transaction() as connection:
                row = connection.execute("SELECT i.*, p.role, p.status, p.authorization_revision FROM access_invitations i JOIN access_principals p ON p.id=i.principal_id WHERE i.secret_digest=?", (digest,)).fetchone()
                state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
                if (row is None or row["redeemed_at_us"] is not None or row["revoked_at_us"] is not None
                        or row["status"] == PrincipalStatus.REVOKED.value
                        or row["principal_revision"] != row["authorization_revision"]
                        or row["deployment_generation"] != state or not row["issued_at_us"] <= _us(at) < row["expires_at_us"]
                        or (invitation_id is not None and row["id"] != str(invitation_id))):
                    raise AccessValidationError("enrollment is unavailable")
                principal_id = UUID(row["principal_id"])
                credential = Credential(credential_id, principal_id, public_key, algorithm, sign_count, at,
                                        backup_eligible=backup_eligible, backup_state=backup_state, label=label)
                connection.execute("INSERT INTO access_credentials (credential_id, principal_id, public_key, algorithm, sign_count, enrolled_at_us, revoked_at_us, backup_eligible, backup_state, label) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                                   (credential.credential_id, str(principal_id), credential.public_key, credential.algorithm, credential.sign_count, _us(at),
                                    int(credential.backup_eligible), int(credential.backup_state), credential.label))
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
                             idle_lifetime: timedelta = IDLE_LIFETIME,
                             absolute_lifetime: timedelta = ABSOLUTE_LIFETIME) -> UUID:
        """Create an opaque session bound to one principal and one credential.

        Lifetimes default to the ADR-0003 accepted values (30 minutes idle,
        12 hours absolute). Only the token digest is stored, and of the
        proxy identity only its keyed binding (never the raw value).
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
        row = connection.execute("SELECT p.status, p.authorization_revision, c.revoked_at_us, c.inconsistent_at_us FROM access_principals p JOIN access_credentials c ON c.principal_id=p.id WHERE p.id=? AND c.credential_id=?", (str(principal_id), credential_id)).fetchone()
        if (row is None or row["status"] != PrincipalStatus.ACTIVE.value or row["revoked_at_us"] is not None
                or row["inconsistent_at_us"] is not None):
            raise AccessValidationError("session subject is unavailable")
        generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
        self._end_expired_sessions_on(connection, at)
        connection.execute("INSERT INTO access_sessions (id, token_digest, principal_id, credential_id, principal_revision, deployment_generation, established_at_us, last_seen_at_us, idle_lifetime_us, idle_expires_at_us, absolute_expires_at_us, invalidated_at_us, last_user_verification_at_us, external_identity_binding) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                           (str(session_id), token_digest, str(principal_id), credential_id, row["authorization_revision"], generation,
                            _us(at), _us(at), _duration_us(idle_lifetime), _us(at + idle_lifetime), _us(at + absolute_lifetime), verified,
                            binding))
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

    def authorize(self, token: bytes, proxy_identity: str, permission: Permission, *, now: datetime | None = None) -> Principal:
        """Authorize one request; every refusal is the same generic denial.

        A proxy identity that does not reproduce the session binding is
        refused for this request only; the session itself is left as it is
        (see the auth README for this Owner-reviewable choice).
        """
        if not isinstance(permission, Permission):
            raise AccessValidationError("permission is invalid")
        at = utc_time(self._clock() if now is None else now)
        mismatch: list = []
        try:
            return self._authorize(token, proxy_identity, permission, at, mismatch)
        except AccessValidationError:
            self._end_expired_sessions_after_denial(at)
            self._record_binding_mismatch(mismatch, at)
            raise

    def _authorize(self, token, proxy_identity, permission, at, mismatch) -> Principal:
        with self._transaction(write=True) as connection:
            self._end_expired_sessions_on(connection, at)
            row = self._current_session_on(connection, token, proxy_identity, at, mismatch)
            if row is None:
                raise AccessValidationError("access is unavailable")
            granted = connection.execute("SELECT 1 FROM access_principal_permissions WHERE principal_id=? AND permission=?", (row["principal_id"], permission.value)).fetchone() is not None
            principal = self._principal(row)
            if principal.role is not PrincipalRole.OWNER and not granted:
                raise AccessValidationError("access is unavailable")
            self._touch_session_on(connection, row, at)
            return principal

    def authorize_owner(self, token: bytes, proxy_identity: str, *, now: datetime | None = None,
                        freshness: timedelta = OWNER_STEP_UP_FRESHNESS) -> Principal:
        """Authorize an AUTH-008 owner operation with fresh user verification.

        Anything that is not a currently valid Owner session receives the
        generic denial. Only an authenticated Owner session whose last user
        verification is older than ``freshness`` (ADR-0003: five minutes), or
        not between the session's establishment and now, receives the distinct
        ``StepUpRequired``. A stale session never performs the operation.
        """
        if not isinstance(freshness, timedelta) or freshness <= timedelta(0):
            raise AccessValidationError("freshness window is invalid")
        at = utc_time(self._clock() if now is None else now)
        mismatch: list = []
        try:
            with self._transaction(write=True) as connection:
                self._end_expired_sessions_on(connection, at)
                row = self._current_session_on(connection, token, proxy_identity, at, mismatch)
                if row is None or row["role"] != PrincipalRole.OWNER.value:
                    raise AccessValidationError("access is unavailable")
                self._touch_session_on(connection, row, at)
                principal = self._principal(row)
                verified = row["last_user_verification_at_us"]
        except AccessValidationError:
            self._end_expired_sessions_after_denial(at)
            self._record_binding_mismatch(mismatch, at)
            raise
        if (verified is None or not row["established_at_us"] <= verified <= _us(at)
                or _us(at) - verified >= _duration_us(freshness)):
            raise StepUpRequired()
        return principal

    def set_permissions(self, principal_id: UUID, permissions: Iterable[Permission]) -> None:
        self._require_unaudited_writes()
        at = utc_time(self._clock())
        with self._transaction(write=True) as connection:
            self.set_permissions_on(connection, principal_id, permissions, at=at)

    def set_permissions_on(self, connection, principal_id: UUID, permissions: Iterable[Permission],
                           *, at: datetime) -> None:
        """Replace grants and invalidate existing sessions on a caller-owned transaction."""
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        grants = self._permissions(permissions)
        at = utc_time(at)
        row = connection.execute("SELECT status FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
        if row is None or row["status"] == PrincipalStatus.REVOKED.value:
            raise AccessValidationError("principal is unavailable")
        connection.execute("DELETE FROM access_principal_permissions WHERE principal_id=?", (str(principal_id),))
        connection.executemany("INSERT INTO access_principal_permissions VALUES (?, ?)", ((str(principal_id), value.value) for value in grants))
        self._advance_principal(connection, principal_id, at)

    def revoke_principal(self, principal_id: UUID, *, now: datetime | None = None) -> None:
        self._require_unaudited_writes()
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            self.revoke_principal_on(connection, principal_id, at=at)

    def revoke_principal_on(self, connection, principal_id: UUID, *, at: datetime) -> None:
        """Revoke a principal with its credentials, invitations and sessions together."""
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        at = utc_time(at)
        row = connection.execute("SELECT status FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
        if row is None:
            raise AccessValidationError("principal is unavailable")
        # The last observed proxy identity is cleared with the principal (§11.4).
        connection.execute("UPDATE access_principals SET status=?, revoked_at_us=?, external_identity=NULL, authorization_revision=authorization_revision+1 WHERE id=?", (PrincipalStatus.REVOKED.value, _us(at), str(principal_id)))
        connection.execute("UPDATE access_credentials SET revoked_at_us=? WHERE principal_id=? AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
        connection.execute("UPDATE access_invitations SET revoked_at_us=? WHERE principal_id=? AND redeemed_at_us IS NULL AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE principal_id=? AND invalidated_at_us IS NULL", (_us(at), str(principal_id)))

    def revoke_credential_on(self, connection, principal_id: UUID, credential_id: bytes, *, at: datetime) -> None:
        """Revoke one credential of a principal and end the sessions it created.

        Revocation is credential-scoped, not device-scoped: a synced passkey may
        exist on several devices. The credential identifier is opaque WebAuthn
        material; the audited caller records only the principal's logical UUID.
        """
        if not isinstance(principal_id, UUID) or not isinstance(credential_id, bytes):
            raise AccessValidationError("credential subject is invalid")
        at = utc_time(at)
        changed = connection.execute(
            "UPDATE access_credentials SET revoked_at_us=? WHERE credential_id=? AND principal_id=? AND revoked_at_us IS NULL",
            (_us(at), credential_id, str(principal_id))).rowcount
        if changed != 1:
            raise AccessValidationError("credential is unavailable")
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE credential_id=? AND invalidated_at_us IS NULL", (_us(at), credential_id))

    def invalidate_all_sessions_on(self, connection, *, at: datetime) -> None:
        """Advance the deployment authorization generation and end every human session.

        Runs on a caller-owned (audited) transaction. Every session, the
        Owner's included, stops being accepted, as does every enrollment
        authorization issued under the previous generation. Principals, grants
        and credentials are unchanged: each person signs in again with their
        own credential, and a pending invitation must be issued again.
        """
        at = utc_time(at)
        connection.execute("UPDATE access_deployment_state SET authorization_generation=authorization_generation+1 WHERE singleton=1")
        connection.execute("UPDATE access_sessions SET invalidated_at_us=? WHERE invalidated_at_us IS NULL", (_us(at),))

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

    def issue_authentication_challenge(self, digest: bytes, *, at: datetime, lifetime: timedelta) -> None:
        """Store the digest of an unbound sign-in challenge (discoverable credentials)."""
        at = utc_time(at)
        with self._transaction(write=True) as connection:
            self._insert_challenge_on(connection, digest, "authentication", at, lifetime)

    def begin_registration(self, enrollment_secret: object, proxy_identity: object, digest: bytes, *,
                           at: datetime, lifetime: timedelta) -> RegistrationSubject:
        """Bind a registration challenge to one valid invitation and count the attempt.

        The invitation is not redeemed here. An absent, unknown, expired,
        redeemed, revoked, generation-stale or attempt-exhausted code receives
        the generic denial and writes nothing. The enrollment secret alone
        selects the invitation; the proxy identity must be present and
        well-formed but is not compared with anything.
        """
        at = utc_time(at)
        try:
            secret_digest = _digest(enrollment_secret)
            _identity(proxy_identity)
        except AccessValidationError:
            raise AccessValidationError("access is unavailable") from None
        with self._transaction(write=True) as connection:
            row = connection.execute("SELECT i.*, p.display_name, p.status, p.authorization_revision FROM access_invitations i JOIN access_principals p ON p.id=i.principal_id WHERE i.secret_digest=?", (secret_digest,)).fetchone()
            state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
            if (row is None or row["redeemed_at_us"] is not None or row["revoked_at_us"] is not None
                    or row["status"] == PrincipalStatus.REVOKED.value
                    or row["principal_revision"] != row["authorization_revision"]
                    or row["deployment_generation"] != state or not row["issued_at_us"] <= _us(at) < row["expires_at_us"]):
                raise AccessValidationError("access is unavailable")
            counted = connection.execute("UPDATE access_invitations SET attempt_count=attempt_count+1 WHERE id=? AND attempt_count < ? AND redeemed_at_us IS NULL",
                                         (row["id"], MAX_REDEMPTION_ATTEMPTS)).rowcount
            if counted != 1:
                raise AccessValidationError("access is unavailable")
            self._insert_challenge_on(connection, digest, "registration", at, lifetime, invitation_id=row["id"])
            excluded = tuple(bytes(item[0]) for item in connection.execute(
                "SELECT credential_id FROM access_credentials WHERE principal_id=? ORDER BY enrolled_at_us", (row["principal_id"],)))
            return RegistrationSubject(UUID(row["id"]), UUID(row["principal_id"]), row["display_name"], excluded)

    def consume_challenge(self, digest: bytes, ceremony: str, *, at: datetime) -> ConsumedChallenge:
        """Delete a pending challenge exactly once and return its binding.

        The challenge is removed whether or not the ceremony later verifies, so
        a failed attempt cannot be retried with it. A challenge used outside
        its issue-to-expiry window, or for another ceremony, is refused.
        """
        at = utc_time(at)
        if not isinstance(digest, bytes) or len(digest) != 32 or ceremony not in ("registration", "authentication", "step_up"):
            raise AccessValidationError("access is unavailable")
        with self._transaction(write=True) as connection:
            row = connection.execute("DELETE FROM access_webauthn_challenges WHERE challenge_digest=? AND ceremony=? RETURNING invitation_id, session_id, issued_at_us, expires_at_us",
                                     (digest, ceremony)).fetchone()
            row = None if row is None else dict(row)
        if row is None or not row["issued_at_us"] <= _us(at) < row["expires_at_us"]:
            raise AccessValidationError("access is unavailable")
        return ConsumedChallenge(None if row["invitation_id"] is None else UUID(row["invitation_id"]),
                                 None if row["session_id"] is None else UUID(row["session_id"]))

    def begin_step_up(self, token: object, proxy_identity: object, digest: bytes, *,
                      at: datetime, lifetime: timedelta) -> bytes:
        """Bind a step-up challenge to a current Owner session and return its credential id.

        The returned id is the only entry of the challenge's allowed-credential
        list; ``accept_assertion`` refuses an assertion from any other credential.
        """
        at = utc_time(at)
        mismatch: list = []
        try:
            with self._transaction(write=True) as connection:
                self._end_expired_sessions_on(connection, at)
                row = self._current_session_on(connection, token, proxy_identity, at, mismatch)
                if row is None or row["role"] != PrincipalRole.OWNER.value:
                    raise AccessValidationError("access is unavailable")
                self._insert_challenge_on(connection, digest, "step_up", at, lifetime, session_id=row["id"])
                return bytes(row["credential_id"])
        except AccessValidationError:
            self._end_expired_sessions_after_denial(at)
            self._record_binding_mismatch(mismatch, at)
            raise

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
        """Owner-visible credential inventory; revocation is credential-scoped."""
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        with self._transaction() as connection:
            rows = connection.execute("SELECT * FROM access_credentials WHERE principal_id=? ORDER BY enrolled_at_us, credential_id", (str(principal_id),)).fetchall()
        return tuple(self._credential(row) for row in rows)

    def accept_assertion(self, credential_id: bytes, principal_id: UUID, proxy_identity: str, *,
                         expected_sign_count: int, sign_count: int, backup_state: bool, at: datetime,
                         token: bytes | None = None, step_up_session_id: UUID | None = None) -> UUID:
        """Commit a verified assertion: counter, backup state, last use and its session effect.

        With ``token`` a new session is established (sign-in); with
        ``step_up_session_id`` that session's user-verification time is
        refreshed, but only when the session was created by this very
        credential. The counter update is conditional on the value the
        signature was checked against, so two racing assertions cannot both
        advance it. The audit record commits in the same transaction.

        The credential selected the principal; the proxy identity is only
        recorded as the principal's last observed value and, for a new
        session, bound into it. A step-up must present the identity its
        session is bound to.
        """
        if (token is None) == (step_up_session_id is None):
            raise AccessValidationError("access is unavailable")
        at = utc_time(at)
        identity = _identity(proxy_identity)

        def write(connection, mark):
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
                                                       proxy_identity=identity, at=at, verified_at=at)
                action = AuditAction.AUTHENTICATE_PRINCIPAL
            else:
                session = connection.execute("SELECT s.*, p.authorization_revision FROM access_sessions s JOIN access_principals p ON p.id=s.principal_id WHERE s.id=?",
                                             (str(step_up_session_id),)).fetchone()
                state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
                if (session is None or session["principal_id"] != str(principal_id)
                        or bytes(session["credential_id"]) != credential_id or session["invalidated_at_us"] is not None
                        or session["principal_revision"] != session["authorization_revision"]
                        or session["deployment_generation"] != state
                        or not session["established_at_us"] <= _us(at) or not session["last_seen_at_us"] <= _us(at)
                        or _us(at) >= session["idle_expires_at_us"] or _us(at) >= session["absolute_expires_at_us"]
                        or self._session_binding is None
                        or not self._session_binding.matches(session["external_identity_binding"], identity)):
                    raise AccessValidationError("access is unavailable")
                connection.execute("UPDATE access_sessions SET last_user_verification_at_us=? WHERE id=?", (_us(at), session["id"]))
                self._touch_session_on(connection, session, at)
                session_id = step_up_session_id
                action = AuditAction.VERIFY_PRINCIPAL_STEP_UP
            # Owner-visible, overwritten each authentication, never an input.
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

        def write(connection, mark):
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

        self._audited_write(write)

    def record_sign_count_regression(self, principal_id: UUID) -> None:
        """Record a refused assertion whose signature counter regressed."""

        def write(connection, mark):
            mark()
            self.audit.append_on(connection, actor_category=ActorCategory.SYSTEM,
                                 action=AuditAction.DETECT_PRINCIPAL_CREDENTIAL_SIGN_COUNT_REGRESSION,
                                 target_kind=TargetKind.PRINCIPAL, target_logical_id=principal_id,
                                 outcome=AuditOutcome.FAILED)

        self._audited_write(write)

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
        # Both statements are within the caller's BEGIN IMMEDIATE transaction:
        # a commit publishes the revision and every invalidation together, while
        # a failure rolls both back. A real invalidation timestamp avoids a
        # sentinel value that could be misread as a valid Unix epoch session.
        connection.execute("UPDATE access_principals SET authorization_revision=authorization_revision+1 WHERE id=?", (str(principal_id),))
        connection.execute("UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE principal_id=? AND invalidated_at_us IS NULL", (_us(at), str(principal_id)))
