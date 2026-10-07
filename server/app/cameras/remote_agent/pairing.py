"""Fail-closed pairing ledger; this module has no CLI, TLS, or network listener.

The caller supplies a cryptographic verifier and Owner authorization boundary.  The
ledger only stores HMAC digests and public-key *digests*, never a pairing code,
private key, CSR, endpoint, or raw public key. The one certificate it keeps is
the public PEM of a staged renewal (Issue #123), bound to the staged digest and
deleted with its staged row, so a same-key retry can be answered with the
certificate first issued for it.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
import base64
import hashlib
import hmac
import secrets
import ssl
import time
from typing import Callable, Protocol
from uuid import UUID, uuid4

from app.audit.model import ActorCategory, AuditAction, AuditOutcome, TargetKind
from app.audit.service import OwnerAuthorizationError
from app.audit.store import AuditStorageError, AuditStore
from app.storage.database import Database

_CODE_BYTES = 16
_CODE_LIFETIME_SECONDS = 5 * 60
_DIGEST_LENGTH = 64
_MAX_EXPIRY_ROWS = 256
# Permanent key bindings one node may accumulate. Every staged renewal binds
# its key for good, so this bounds ledger growth from repeated renewal
# attempts; the Agent retries at most ~40 times per 30-day renewal window, so
# a legitimate node stays far below it for decades. Beyond it renewal is
# refused (Owner-visible warning) and the node must re-pair.
_MAX_KEY_BINDINGS_PER_NODE = 1024
# Upper bound for a staged renewal certificate PEM (a P-256 leaf is ~1 KiB).
_MAX_CERTIFICATE_PEM_BYTES = 16 * 1024


class PairingError(RuntimeError):
    """A bounded pairing failure that contains no caller-supplied value."""


class PairingAuthorizationError(PairingError):
    """The current actor is not allowed to administer capture-node pairing."""


class PairingValidationError(PairingError):
    """A pairing request or trusted adapter result is invalid."""


class PairingStorageError(PairingError):
    """The durable pairing state cannot safely be read or changed."""


class OwnerAuthorizer(Protocol):
    def require_owner(self, actor_context: object) -> None:
        ...


class CodeVerifier(Protocol):
    def digest(self, code: str) -> str:
        ...


class HmacCodeVerifier:
    """Keyed, constant-time verifier owned by the deployment secret boundary.

    The key is injected by a future protected deployment adapter and is never
    persisted, logged, accepted through this API as text, or returned.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) < 32:
            raise PairingValidationError("invalid pairing verifier")
        self._key = key

    def digest(self, code: str) -> str:
        if not isinstance(code, str) or len(code) != 26 or not code.isascii():
            raise PairingValidationError("invalid pairing code")
        return hmac.new(self._key, code.encode("ascii"), hashlib.sha256).hexdigest()

    @staticmethod
    def matches(expected: str, actual: str) -> bool:
        return (isinstance(expected, str) and isinstance(actual, str)
                and hmac.compare_digest(expected, actual))


@dataclass(frozen=True)
class PairingCode:
    """Ephemeral output for a non-echoing local CLI; never serialize or log it."""

    value: str

    def __post_init__(self):
        if not isinstance(self.value, str) or len(self.value) != 26 or not self.value.isascii():
            raise PairingValidationError("invalid pairing code")

    def __repr__(self) -> str:
        return "PairingCode(<redacted>)"


@dataclass(frozen=True)
class EnrollmentApproval:
    enrollment_id: UUID
    node_id: UUID
    public_key_digest: str
    expires_at_monotonic: float


@dataclass(frozen=True)
class CredentialExpiry:
    """Expiry of a node's active credential (UTC epoch seconds); no key material."""

    node_id: UUID
    not_after: float
    renewal_staged: bool


@dataclass(frozen=True)
class StagedRenewal:
    """The renewal staged for a node: its public certificate and digests only.

    ``stage_renewal`` returns the row actually staged. For a same-key retry
    that is the certificate first issued for that key, not the caller's new
    one, so every response for one pending key carries the same certificate.
    """

    public_key_digest: str
    credential_serial_digest: str
    not_after: float
    certificate_pem: bytes = dataclass_field(repr=False)


@dataclass(frozen=True)
class PairingSummary:
    """Listing row for the local Owner CLI; contains no key material or digest."""

    node_id: UUID
    enrollment_state: str | None
    credential_state: str | None
    not_after: float | None


@dataclass(frozen=True)
class EnrollmentClaim:
    """A consumed enrollment awaiting a separately implemented signer."""

    enrollment_id: UUID
    node_id: UUID
    public_key_digest: str


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != _DIGEST_LENGTH:
        raise PairingValidationError(f"invalid {field}")
    try:
        int(value, 16)
    except ValueError:
        raise PairingValidationError(f"invalid {field}") from None
    if value != value.lower():
        raise PairingValidationError(f"invalid {field}")
    return value


def _expiry(value: object, *, optional: bool) -> float | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise PairingValidationError("invalid credential expiry")
    return float(value)


def _identity(value: object, field: str) -> UUID:
    if not isinstance(value, UUID):
        raise PairingValidationError(f"invalid {field}")
    return value


def _certificate_pem(value: object, serial: str) -> str:
    """Return ``value`` as PEM text if it is one certificate whose DER digest is ``serial``.

    The ledger stays free of an X.509 dependency: it checks only the PEM
    armor and that SHA-256 of the DER is the staged credential digest, which
    binds the stored bytes to exactly the certificate that will be admitted.
    """
    if not isinstance(value, bytes) or not 0 < len(value) <= _MAX_CERTIFICATE_PEM_BYTES:
        raise PairingValidationError("invalid renewal certificate")
    try:
        text = value.decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(text)
    except (UnicodeError, ValueError):
        raise PairingValidationError("invalid renewal certificate") from None
    if text.count("BEGIN CERTIFICATE") != 1 or not hmac.compare_digest(
            hashlib.sha256(der).hexdigest(), serial):
        raise PairingValidationError("invalid renewal certificate")
    return text


def _refuse_foreign_key(connection, node: UUID, key: str) -> bool:
    """Refuse ``key`` if another node holds it or it was ever revoked; return whether bound.

    Owner decision 2026-09-30: a node public key is unique across all nodes
    and all credential states, and a revoked key is never reused. Runs inside
    the caller's write transaction.
    """
    row = connection.execute(
        "SELECT node_id, revoked FROM pairing_key_bindings WHERE public_key_digest = ?", (key,)
    ).fetchone()
    staged = connection.execute(
        "SELECT 1 FROM pairing_node_renewals WHERE public_key_digest = ? AND node_id != ?",
        (key, str(node)),
    ).fetchone()
    if staged or (row is not None and (row["node_id"] != str(node) or row["revoked"])):
        raise PairingError("public key is bound to another capture node identity")
    return row is not None


def _bind_key(connection, node: UUID, key: str) -> None:
    """Permanently bind ``key`` to ``node``; re-binding the same live node is a no-op."""
    if not _refuse_foreign_key(connection, node, key):
        connection.execute(
            "INSERT INTO pairing_key_bindings (public_key_digest, node_id, revoked) "
            "VALUES (?, ?, 0)", (key, str(node)))


def _new_code() -> PairingCode:
    # 128 bits encode to exactly 26 unpadded Base32 characters.
    return PairingCode(base64.b32encode(secrets.token_bytes(_CODE_BYTES)).decode("ascii").rstrip("="))


class PairingLedger:
    """SQLite ledger with process-epoch expiry and single-use redemption.

    A fresh process epoch is generated at construction. Pending approvals from
    a previous process are rejected rather than interpreting a monotonic clock
    across restart. All admission decisions read durable revocation/activation
    state; a certificate alone can never authorize a node.

    Every state change commits in the same SQLite transaction as its bounded
    security audit record, admitted through the injected ``AuditStore``'s
    storage reservation, so an audit write failure rolls the change back. Only
    the capture node's application logical UUID is recorded; a pairing code,
    its digest, the enrollment identity and key/serial digests never are. An
    Owner-only call refused by the authorizer runs nothing and records a
    ``denied`` outcome. Redemption attempts that match no pending enrollment
    (unknown identity, wrong code or wrong key) record nothing, so an
    unauthenticated caller cannot grow the audit table. When a matched
    redemption's audit append or commit fails, the rolled-back outcome is
    counted in the bounded ledger health instead of being appended separately,
    so repeated attempts still cannot grow the table.
    """

    def __init__(self, database: Database, verifier: CodeVerifier, *,
                 audit: AuditStore,
                 clock: Callable[[], float] = time.monotonic,
                 process_epoch: UUID | None = None):
        if not isinstance(database, Database) or not callable(getattr(verifier, "digest", None)):
            raise PairingValidationError("invalid pairing ledger dependency")
        if not isinstance(audit, AuditStore) or audit.database != database:
            raise PairingValidationError("invalid pairing ledger dependency")
        if not callable(clock):
            raise PairingValidationError("invalid pairing clock")
        self.database = database
        self.verifier = verifier
        self.audit = audit
        self.clock = clock
        self.process_epoch = process_epoch or uuid4()
        if not isinstance(self.process_epoch, UUID):
            raise PairingValidationError("invalid pairing process epoch")
        # Bounded health only: an outcome that could not be recorded outside a
        # committed mutation stays visible instead of being silently dropped.
        self.audit_delivery_failed = False
        self.undelivered_audit_records = 0

    @contextmanager
    def _transaction(self, *, write: bool):
        # The audit store owns connection lifetime, rollback and the storage
        # admission for writes; a refused admission propagates unchanged.
        try:
            with self.audit.transaction(write=write) as connection:
                yield connection
        except AuditStorageError:
            raise PairingStorageError("pairing ledger operation failed") from None

    def _record(self, actor: ActorCategory, action: AuditAction, node: UUID,
                outcome: AuditOutcome) -> None:
        """Append an outcome in its own admitted transaction; never raise."""
        try:
            self.audit.append(actor_category=actor, action=action,
                              target_kind=TargetKind.CAPTURE_NODE,
                              target_logical_id=node, outcome=outcome)
        except Exception:
            self._mark_undelivered()

    def _mark_undelivered(self) -> None:
        self.audit_delivery_failed = True
        self.undelivered_audit_records += 1

    def _append_on(self, connection, actor: ActorCategory, action: AuditAction, node: UUID,
                   outcome: AuditOutcome) -> None:
        self.audit.append_on(connection, actor_category=actor, action=action,
                        target_kind=TargetKind.CAPTURE_NODE,
                        target_logical_id=node, outcome=outcome)

    def _authorize(self, authorizer: OwnerAuthorizer, actor_context: object,
                   action: AuditAction, node: UUID) -> None:
        gate = getattr(authorizer, "require_owner", None)
        try:
            if not callable(gate):
                raise PermissionError
            gate(actor_context)
        except PermissionError as error:
            # Never read an injected authorizer's message or attributes other
            # than the bounded category of this subsystem's own denial type.
            category = (error.actor_category if isinstance(error, OwnerAuthorizationError)
                        else ActorCategory.UNAUTHENTICATED)
            self._record(category, action, node, AuditOutcome.DENIED)
            raise PairingAuthorizationError("owner authorization denied") from None

    def approve(self, authorizer: OwnerAuthorizer, actor_context: object, *,
                node_id: UUID, public_key_digest: str) -> tuple[EnrollmentApproval, PairingCode]:
        """Create a fresh Owner-approved enrollment and return its ephemeral code."""
        node = _identity(node_id, "node identity")
        action = AuditAction.APPROVE_CAPTURE_NODE_ENROLLMENT
        self._authorize(authorizer, actor_context, action, node)
        try:
            key_digest = _digest(public_key_digest, "public key digest")
            code = _new_code()
            code_digest = _digest(self.verifier.digest(code.value), "pairing verifier result")
            now = self.clock()
            if not isinstance(now, (float, int)):
                raise PairingValidationError("invalid pairing clock")
            expires = float(now) + _CODE_LIFETIME_SECONDS
            approval = EnrollmentApproval(uuid4(), node, key_digest, expires)
            with self._transaction(write=True) as connection:
                _bind_key(connection, node, key_digest)
                connection.execute(
                    "INSERT INTO pairing_enrollments "
                    "(id, node_id, public_key_digest, code_digest, process_epoch, expires_at, state) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'pending')",
                    (str(approval.enrollment_id), str(node), key_digest, code_digest,
                     str(self.process_epoch), expires),
                )
                self._append_on(connection, ActorCategory.OWNER, action, node,
                                AuditOutcome.SUCCEEDED)
        except Exception:
            self._record(ActorCategory.OWNER, action, node, AuditOutcome.FAILED)
            raise
        return approval, code

    def redeem(self, *, enrollment_id: UUID, public_key_digest: str,
               code: str) -> EnrollmentClaim:
        """Atomically consume an approval after its trusted transport verified Main."""
        enrollment = _identity(enrollment_id, "enrollment identity")
        key_digest = _digest(public_key_digest, "public key digest")
        candidate = _digest(self.verifier.digest(code), "pairing verifier result")
        now = self.clock()
        if not isinstance(now, (float, int)):
            raise PairingValidationError("invalid pairing clock")
        action = AuditAction.REDEEM_CAPTURE_NODE_ENROLLMENT
        expired = False
        claim = None
        # Only a matched enrollment (expiry or consumption) produces an audit
        # outcome; ordinary unmatched denials never reach an append.
        audit_attempted = False
        try:
            with self._transaction(write=True) as connection:
                row = connection.execute(
                    "SELECT node_id, public_key_digest, code_digest, process_epoch, expires_at, state "
                    "FROM pairing_enrollments WHERE id = ?", (str(enrollment),)
                ).fetchone()
                if row is None or row["state"] != "pending":
                    raise PairingError("pairing enrollment is unavailable")
                node = UUID(row["node_id"])
                if row["process_epoch"] != str(self.process_epoch) or float(now) >= row["expires_at"]:
                    # A pending enrollment expires at most once, so this record is
                    # bounded by Owner approvals rather than by redemption attempts.
                    connection.execute("UPDATE pairing_enrollments SET state = 'expired' WHERE id = ?", (str(enrollment),))
                    audit_attempted = True
                    self._append_on(connection, ActorCategory.CAPTURE_NODE, action, node,
                                    AuditOutcome.FAILED)
                    expired = True
                elif not HmacCodeVerifier.matches(row["code_digest"], candidate):
                    raise PairingError("pairing enrollment is unavailable")
                elif not hmac.compare_digest(row["public_key_digest"], key_digest):
                    raise PairingError("pairing enrollment is unavailable")
                else:
                    changed = connection.execute(
                        "UPDATE pairing_enrollments SET state = 'consumed' "
                        "WHERE id = ? AND state = 'pending'", (str(enrollment),)
                    ).rowcount
                    if changed != 1:
                        raise PairingError("pairing enrollment is unavailable")
                    audit_attempted = True
                    self._append_on(connection, ActorCategory.CAPTURE_NODE, action, node,
                                    AuditOutcome.SUCCEEDED)
                    claim = EnrollmentClaim(enrollment, node, key_digest)
        except Exception:
            if audit_attempted:
                # The append or its commit failed and rolled the change back.
                # Surface the lost outcome in bounded health only: a separate
                # append would let repeated attempts grow the audit table.
                self._mark_undelivered()
            raise
        if expired:
            raise PairingError("pairing enrollment is unavailable")
        if claim is None:
            raise PairingStorageError("pairing enrollment state is unavailable")
        return claim

    def activate(self, claim: EnrollmentClaim, *, credential_serial_digest: str,
                 not_after: float | None = None) -> None:
        """Activate a signer-produced credential reference after successful issuance.

        The signer/certificate bytes are intentionally outside this dependency-free
        domain core. A later adapter must validate its output before calling this.
        """
        if not isinstance(claim, EnrollmentClaim):
            raise PairingValidationError("invalid enrollment claim")
        node = _identity(claim.node_id, "node identity")
        action = AuditAction.ACTIVATE_CAPTURE_NODE_CREDENTIAL
        try:
            serial = _digest(credential_serial_digest, "credential serial digest")
            expiry = _expiry(not_after, optional=True)
            with self._transaction(write=True) as connection:
                row = connection.execute(
                    "SELECT node_id, public_key_digest, state FROM pairing_enrollments WHERE id = ?",
                    (str(claim.enrollment_id),),
                ).fetchone()
                if (row is None or row["state"] != "consumed" or row["node_id"] != str(node)
                        or not hmac.compare_digest(row["public_key_digest"], claim.public_key_digest)):
                    raise PairingError("pairing enrollment cannot be activated")
                _bind_key(connection, node, claim.public_key_digest)
                connection.execute(
                    "INSERT INTO pairing_node_credentials "
                    "(node_id, public_key_digest, credential_serial_digest, state, not_after) "
                    "VALUES (?, ?, ?, 'active', ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET public_key_digest = excluded.public_key_digest, "
                    "credential_serial_digest = excluded.credential_serial_digest, state = 'active', "
                    "not_after = excluded.not_after",
                    (str(node), claim.public_key_digest, serial, expiry),
                )
                # A fresh pairing discards any renewal staged for an older identity.
                connection.execute("DELETE FROM pairing_node_renewals WHERE node_id = ?", (str(node),))
                connection.execute("UPDATE pairing_enrollments SET state = 'activated' WHERE id = ?", (str(claim.enrollment_id),))
                self._append_on(connection, ActorCategory.SYSTEM, action, node,
                                AuditOutcome.SUCCEEDED)
        except Exception:
            self._record(ActorCategory.SYSTEM, action, node, AuditOutcome.FAILED)
            raise

    def revoke(self, authorizer: OwnerAuthorizer, actor_context: object, *, node_id: UUID) -> None:
        node = _identity(node_id, "node identity")
        action = AuditAction.REVOKE_CAPTURE_NODE_PAIRING
        self._authorize(authorizer, actor_context, action, node)
        try:
            with self._transaction(write=True) as connection:
                credentials = connection.execute(
                    "UPDATE pairing_node_credentials SET state = 'revoked' WHERE node_id = ? AND state = 'active'",
                    (str(node),),
                ).rowcount
                enrollments = connection.execute(
                    "UPDATE pairing_enrollments SET state = 'revoked' "
                    "WHERE node_id = ? AND state IN ('pending', 'consumed')", (str(node),),
                ).rowcount
                # A revoked node can never promote a renewal it staged earlier.
                connection.execute("DELETE FROM pairing_node_renewals WHERE node_id = ?", (str(node),))
                if credentials + enrollments == 0:
                    raise PairingError("capture node is unavailable")
                # No key this node ever held can be bound again, by any node.
                connection.execute("UPDATE pairing_key_bindings SET revoked = 1 WHERE node_id = ?",
                                   (str(node),))
                self._append_on(connection, ActorCategory.OWNER, action, node,
                                AuditOutcome.SUCCEEDED)
        except Exception:
            self._record(ActorCategory.OWNER, action, node, AuditOutcome.FAILED)
            raise

    def admits(self, *, node_id: UUID, public_key_digest: str,
               credential_serial_digest: str) -> bool:
        """Return true only for the current active capture-node credential.

        A credential staged by ``stage_renewal`` is admitted exactly by being
        promoted: in one write transaction it replaces the active credential
        (superseding the old certificate) and records an activation audit
        entry. Promotion re-checks that the node is still active, so a
        revocation committed before it wins. A connection that loses a
        concurrent promotion of the same staged renewal is admitted when its
        key and certificate are, by then, the active credential (Issue #121).
        """
        node = _identity(node_id, "node identity")
        key = _digest(public_key_digest, "public key digest")
        serial = _digest(credential_serial_digest, "credential serial digest")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT public_key_digest, credential_serial_digest, state "
                "FROM pairing_node_credentials WHERE node_id = ?", (str(node),)
            ).fetchone()
            staged = connection.execute(
                "SELECT public_key_digest, credential_serial_digest FROM pairing_node_renewals "
                "WHERE node_id = ?", (str(node),)
            ).fetchone()
        if not row or row["state"] != "active":
            return False
        if (hmac.compare_digest(row["public_key_digest"], key)
                and hmac.compare_digest(row["credential_serial_digest"], serial)):
            return True
        if not (staged and hmac.compare_digest(staged["public_key_digest"], key)
                and hmac.compare_digest(staged["credential_serial_digest"], serial)):
            return False
        return self._promote_renewal(node, key, serial)

    def _promote_renewal(self, node: UUID, key: str, serial: str) -> bool:
        try:
            return self._promote_renewal_once(node, key, serial)
        except PairingError:
            raise
        except Exception:
            # The promotion and its audit record rolled back together; deny.
            raise PairingStorageError("pairing ledger operation failed") from None

    def _promote_renewal_once(self, node: UUID, key: str, serial: str) -> bool:
        action = AuditAction.ACTIVATE_CAPTURE_NODE_CREDENTIAL
        with self._transaction(write=True) as connection:
            staged = connection.execute(
                "SELECT r.public_key_digest, r.credential_serial_digest, r.not_after "
                "FROM pairing_node_renewals r JOIN pairing_node_credentials c "
                "ON c.node_id = r.node_id WHERE r.node_id = ? AND c.state = 'active'",
                (str(node),),
            ).fetchone()
            if not (staged and hmac.compare_digest(staged["public_key_digest"], key)
                    and hmac.compare_digest(staged["credential_serial_digest"], serial)):
                # A concurrent connection may have promoted this same staged
                # renewal after our read (Issue #121): re-read the active
                # credential in this write transaction and admit only that
                # exact key and certificate. The winner already wrote the
                # activation audit record, so nothing is written here.
                active = connection.execute(
                    "SELECT public_key_digest, credential_serial_digest FROM "
                    "pairing_node_credentials WHERE node_id = ? AND state = 'active'",
                    (str(node),),
                ).fetchone()
                return bool(active and hmac.compare_digest(active["public_key_digest"], key)
                            and hmac.compare_digest(active["credential_serial_digest"], serial))
            _bind_key(connection, node, key)
            connection.execute(
                "UPDATE pairing_node_credentials SET public_key_digest = ?, "
                "credential_serial_digest = ?, not_after = ? WHERE node_id = ? AND state = 'active'",
                (key, serial, staged["not_after"], str(node)),
            )
            connection.execute("DELETE FROM pairing_node_renewals WHERE node_id = ?", (str(node),))
            self._append_on(connection, ActorCategory.SYSTEM, action, node, AuditOutcome.SUCCEEDED)
        return True

    def stage_renewal(self, *, node_id: UUID, current_public_key_digest: str,
                      current_credential_digest: str, public_key_digest: str,
                      credential_serial_digest: str, not_after: float,
                      certificate_pem: bytes) -> StagedRenewal:
        """Stage a renewed credential for a node whose presented credential is current.

        The caller has authenticated the node over mTLS with the credential
        named by the ``current_*`` digests; this re-checks, in the same write
        transaction, that it is still the node's active credential. The new key
        must differ from the current one and must not be bound to another node
        by a credential, staged renewal or enrollment, nor be a revoked key.
        At most one renewal is staged per node (a retry replaces it). The
        staged key is bound to the node permanently before the row is written,
        so neither a retry with a fresh key nor revocation frees it; bindings
        per node are capped so repeated attempts cannot grow the ledger without
        bound. A key already bound to this node is accepted only as a retry of
        the currently staged key, never a superseded or earlier staged one.
        Staging writes no audit record for the same reason; promotion does.

        ``certificate_pem`` is the issued certificate whose DER digest is
        ``credential_serial_digest``; it is stored with the staged row. A retry
        of the currently staged key is certificate-idempotent (Issue #123): it
        keeps the staged row unchanged and returns the certificate first
        issued for that key, so a delayed first response and the retry's
        response name the same staged credential. Only a row staged before
        certificates were kept is replaced by the retry's certificate. The
        returned ``StagedRenewal`` is what the caller must send to the node.
        """
        node = _identity(node_id, "node identity")
        current_key = _digest(current_public_key_digest, "public key digest")
        current_serial = _digest(current_credential_digest, "credential serial digest")
        key = _digest(public_key_digest, "public key digest")
        serial = _digest(credential_serial_digest, "credential serial digest")
        expiry = _expiry(not_after, optional=False)
        certificate = _certificate_pem(certificate_pem, serial)
        if hmac.compare_digest(key, current_key):
            raise PairingValidationError("renewal requires a fresh key")
        with self._transaction(write=True) as connection:
            row = connection.execute(
                "SELECT public_key_digest, credential_serial_digest, state "
                "FROM pairing_node_credentials WHERE node_id = ?", (str(node),)
            ).fetchone()
            if not (row and row["state"] == "active"
                    and hmac.compare_digest(row["public_key_digest"], current_key)
                    and hmac.compare_digest(row["credential_serial_digest"], current_serial)):
                raise PairingError("capture node is not eligible for renewal")
            # An enrollment (any state) already binds its key to its node, even
            # before that node activates a credential.
            reused = connection.execute(
                "SELECT 1 FROM pairing_node_credentials WHERE public_key_digest = ? "
                "UNION ALL SELECT 1 FROM pairing_node_renewals WHERE public_key_digest = ? "
                "AND node_id != ? "
                "UNION ALL SELECT 1 FROM pairing_enrollments WHERE public_key_digest = ? "
                "AND node_id != ?", (key, key, str(node), key, str(node)),
            ).fetchone()
            if reused:
                raise PairingError("capture node is not eligible for renewal")
            # Main issues the certificate before staging, so the key is bound
            # to this node for good now: replacing this staged row with a retry,
            # or revoking the node, must not free it for another node.
            if _refuse_foreign_key(connection, node, key):
                # A key already bound to this node is accepted only as a retry
                # of the currently staged renewal: a superseded key is never
                # re-staged, and an earlier staged key cannot replace a newer one.
                current = connection.execute(
                    "SELECT public_key_digest, credential_serial_digest, not_after, "
                    "certificate_pem FROM pairing_node_renewals WHERE node_id = ?",
                    (str(node),)).fetchone()
                if not (current and hmac.compare_digest(current["public_key_digest"], key)):
                    raise PairingError("capture node is not eligible for renewal")
                if current["certificate_pem"] is not None:
                    # Certificate-idempotent retry: keep and resend the first
                    # certificate; the caller's new one is never staged.
                    try:
                        kept = _certificate_pem(current["certificate_pem"].encode("ascii"),
                                                current["credential_serial_digest"])
                    except (AttributeError, UnicodeError, PairingValidationError):
                        raise PairingStorageError("staged renewal is unavailable") from None
                    return StagedRenewal(key, current["credential_serial_digest"],
                                         float(current["not_after"]), kept.encode("ascii"))
            else:
                held = connection.execute(
                    "SELECT COUNT(*) FROM pairing_key_bindings WHERE node_id = ?", (str(node),)
                ).fetchone()[0]
                if held >= _MAX_KEY_BINDINGS_PER_NODE:
                    raise PairingError("capture node is not eligible for renewal")
                _bind_key(connection, node, key)
            connection.execute(
                "INSERT INTO pairing_node_renewals "
                "(node_id, public_key_digest, credential_serial_digest, not_after, certificate_pem) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET public_key_digest = excluded.public_key_digest, "
                "credential_serial_digest = excluded.credential_serial_digest, "
                "not_after = excluded.not_after, certificate_pem = excluded.certificate_pem",
                (str(node), key, serial, expiry, certificate),
            )
        return StagedRenewal(key, serial, expiry, certificate.encode("ascii"))

    def staged_renewal(self, *, node_id: UUID, current_public_key_digest: str,
                       current_credential_digest: str,
                       public_key_digest: str) -> StagedRenewal | None:
        """The certificate already staged for ``public_key_digest``, or ``None``.

        Read-only lookup that lets a same-key renewal retry be answered with
        the staged certificate before anything is signed (Issue #148, #123).
        A row is returned only while the presented credential (the
        ``current_*`` digests) is still the node's active one, the staged key
        is exactly ``public_key_digest`` and the staged row kept its
        certificate. Anything else returns ``None`` and the caller falls back
        to issuing and ``stage_renewal``, which re-checks eligibility in its
        own write transaction.
        """
        node = _identity(node_id, "node identity")
        current_key = _digest(current_public_key_digest, "public key digest")
        current_serial = _digest(current_credential_digest, "credential serial digest")
        key = _digest(public_key_digest, "public key digest")
        if hmac.compare_digest(key, current_key):
            return None
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT public_key_digest, credential_serial_digest, state "
                "FROM pairing_node_credentials WHERE node_id = ?", (str(node),)
            ).fetchone()
            if not (row and row["state"] == "active"
                    and hmac.compare_digest(row["public_key_digest"], current_key)
                    and hmac.compare_digest(row["credential_serial_digest"], current_serial)):
                return None
            staged = connection.execute(
                "SELECT r.public_key_digest, r.credential_serial_digest, r.not_after, "
                "r.certificate_pem FROM pairing_node_renewals r "
                "JOIN pairing_key_bindings b ON b.public_key_digest = r.public_key_digest "
                "WHERE r.node_id = ? AND b.node_id = r.node_id AND b.revoked = 0",
                (str(node),)).fetchone()
        if not (staged and staged["certificate_pem"] is not None
                and hmac.compare_digest(staged["public_key_digest"], key)):
            return None
        try:
            kept = _certificate_pem(staged["certificate_pem"].encode("ascii"),
                                    staged["credential_serial_digest"])
        except (AttributeError, UnicodeError, PairingValidationError):
            raise PairingStorageError("staged renewal is unavailable") from None
        return StagedRenewal(key, staged["credential_serial_digest"],
                             float(staged["not_after"]), kept.encode("ascii"))

    def bound_node(self, public_key_digest: str) -> UUID | None:
        """The node a live (never revoked) key binding names, or ``None``.

        Lets a retried Owner approval reuse the node the key is already bound
        to (for good, see ``_refuse_foreign_key``) after an interrupted or
        expired enrollment. A revoked key reports ``None``; approval still
        refuses it.
        """
        key = _digest(public_key_digest, "public key digest")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT node_id FROM pairing_key_bindings "
                "WHERE public_key_digest = ? AND revoked = 0", (key,)).fetchone()
        return None if row is None else UUID(row["node_id"])

    def key_revoked(self, public_key_digest: str) -> bool:
        """Whether ``public_key_digest`` was ever held by a revoked node.

        Lets the local approval CLI refuse a revoked key before it prompts the
        Owner or opens the enrollment listener (#116: a revoked node re-pairs
        only with a new key and a new node). ``approve`` refuses such a key
        independently inside its write transaction.
        """
        key = _digest(public_key_digest, "public key digest")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT 1 FROM pairing_key_bindings WHERE public_key_digest = ? AND revoked != 0",
                (key,)).fetchone()
        return row is not None

    def pairing_summaries(self) -> tuple[PairingSummary, ...]:
        """Per-node enrollment/credential states for the local Owner CLI listing.

        Only generated node UUIDs, fixed state words and credential expiry;
        no code, key, serial or certificate digest.
        """
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT n.node_id, "
                "(SELECT e.state FROM pairing_enrollments e WHERE e.node_id = n.node_id "
                " ORDER BY e.rowid DESC LIMIT 1) AS enrollment_state, "
                "c.state AS credential_state, c.not_after "
                "FROM (SELECT node_id FROM pairing_enrollments UNION "
                "      SELECT node_id FROM pairing_node_credentials) n "
                "LEFT JOIN pairing_node_credentials c ON c.node_id = n.node_id "
                "ORDER BY n.node_id LIMIT ?", (_MAX_EXPIRY_ROWS,),
            ).fetchall()
        return tuple(PairingSummary(
            node_id=UUID(row["node_id"]), enrollment_state=row["enrollment_state"],
            credential_state=row["credential_state"],
            not_after=None if row["not_after"] is None else float(row["not_after"]))
            for row in rows)

    def credential_expiries(self) -> tuple[CredentialExpiry, ...]:
        """Active credentials with a recorded expiry, for Owner-visible monitoring."""
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT c.node_id, c.not_after, r.node_id IS NOT NULL AS staged "
                "FROM pairing_node_credentials c LEFT JOIN pairing_node_renewals r "
                "ON r.node_id = c.node_id WHERE c.state = 'active' AND c.not_after IS NOT NULL "
                "ORDER BY c.not_after LIMIT ?", (_MAX_EXPIRY_ROWS,),
            ).fetchall()
        return tuple(CredentialExpiry(UUID(row["node_id"]), float(row["not_after"]),
                                      bool(row["staged"])) for row in rows)
