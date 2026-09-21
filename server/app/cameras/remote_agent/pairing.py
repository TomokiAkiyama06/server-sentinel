"""Fail-closed pairing ledger; this module has no CLI, TLS, or network listener.

The caller supplies a cryptographic verifier and Owner authorization boundary.  The
ledger only stores HMAC digests and public-key *digests*, never a pairing code,
private key, CSR, certificate, endpoint, or raw public key.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import hashlib
import hmac
import secrets
import sqlite3
import time
from typing import Callable, Protocol
from uuid import UUID, uuid4

from app.storage.database import Database

_CODE_BYTES = 16
_CODE_LIFETIME_SECONDS = 5 * 60
_DIGEST_LENGTH = 64


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


def _identity(value: object, field: str) -> UUID:
    if not isinstance(value, UUID):
        raise PairingValidationError(f"invalid {field}")
    return value


def _new_code() -> PairingCode:
    # 128 bits encode to exactly 26 unpadded Base32 characters.
    return PairingCode(base64.b32encode(secrets.token_bytes(_CODE_BYTES)).decode("ascii").rstrip("="))


class PairingLedger:
    """SQLite ledger with process-epoch expiry and single-use redemption.

    A fresh process epoch is generated at construction. Pending approvals from
    a previous process are rejected rather than interpreting a monotonic clock
    across restart. All admission decisions read durable revocation/activation
    state; a certificate alone can never authorize a node.
    """

    def __init__(self, database: Database, verifier: CodeVerifier, *,
                 clock: Callable[[], float] = time.monotonic,
                 process_epoch: UUID | None = None):
        if not isinstance(database, Database) or not callable(getattr(verifier, "digest", None)):
            raise PairingValidationError("invalid pairing ledger dependency")
        if not callable(clock):
            raise PairingValidationError("invalid pairing clock")
        self.database = database
        self.verifier = verifier
        self.clock = clock
        self.process_epoch = process_epoch or uuid4()
        if not isinstance(self.process_epoch, UUID):
            raise PairingValidationError("invalid pairing process epoch")

    @contextmanager
    def _transaction(self, *, write: bool):
        connection = None
        try:
            connection = self.database.connect()
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.execute("COMMIT")
        except sqlite3.Error:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise PairingStorageError("pairing ledger operation failed") from None
        except BaseException:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _authorize(authorizer: OwnerAuthorizer, actor_context: object) -> None:
        if not callable(getattr(authorizer, "require_owner", None)):
            raise PairingAuthorizationError("owner authorization is unavailable")
        try:
            authorizer.require_owner(actor_context)
        except PermissionError:
            raise PairingAuthorizationError("owner authorization denied") from None

    def approve(self, authorizer: OwnerAuthorizer, actor_context: object, *,
                node_id: UUID, public_key_digest: str) -> tuple[EnrollmentApproval, PairingCode]:
        """Create a fresh Owner-approved enrollment and return its ephemeral code."""
        self._authorize(authorizer, actor_context)
        node = _identity(node_id, "node identity")
        key_digest = _digest(public_key_digest, "public key digest")
        code = _new_code()
        code_digest = _digest(self.verifier.digest(code.value), "pairing verifier result")
        now = self.clock()
        if not isinstance(now, (float, int)):
            raise PairingValidationError("invalid pairing clock")
        expires = float(now) + _CODE_LIFETIME_SECONDS
        approval = EnrollmentApproval(uuid4(), node, key_digest, expires)
        with self._transaction(write=True) as connection:
            connection.execute(
                "INSERT INTO pairing_enrollments "
                "(id, node_id, public_key_digest, code_digest, process_epoch, expires_at, state) "
                "VALUES (?, ?, ?, ?, ?, ?, 'pending')",
                (str(approval.enrollment_id), str(node), key_digest, code_digest,
                 str(self.process_epoch), expires),
            )
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
        with self._transaction(write=True) as connection:
            row = connection.execute(
                "SELECT node_id, public_key_digest, code_digest, process_epoch, expires_at, state "
                "FROM pairing_enrollments WHERE id = ?", (str(enrollment),)
            ).fetchone()
            if row is None or row["state"] != "pending":
                raise PairingError("pairing enrollment is unavailable")
            if row["process_epoch"] != str(self.process_epoch) or float(now) >= row["expires_at"]:
                connection.execute("UPDATE pairing_enrollments SET state = 'expired' WHERE id = ?", (str(enrollment),))
                raise PairingError("pairing enrollment is unavailable")
            if not HmacCodeVerifier.matches(row["code_digest"], candidate):
                raise PairingError("pairing enrollment is unavailable")
            if not hmac.compare_digest(row["public_key_digest"], key_digest):
                raise PairingError("pairing enrollment is unavailable")
            changed = connection.execute(
                "UPDATE pairing_enrollments SET state = 'consumed' "
                "WHERE id = ? AND state = 'pending'", (str(enrollment),)
            ).rowcount
            if changed != 1:
                raise PairingError("pairing enrollment is unavailable")
            return EnrollmentClaim(enrollment, UUID(row["node_id"]), key_digest)

    def activate(self, claim: EnrollmentClaim, *, credential_serial_digest: str) -> None:
        """Activate a signer-produced credential reference after successful issuance.

        The signer/certificate bytes are intentionally outside this dependency-free
        domain core. A later adapter must validate its output before calling this.
        """
        if not isinstance(claim, EnrollmentClaim):
            raise PairingValidationError("invalid enrollment claim")
        serial = _digest(credential_serial_digest, "credential serial digest")
        with self._transaction(write=True) as connection:
            row = connection.execute(
                "SELECT node_id, public_key_digest, state FROM pairing_enrollments WHERE id = ?",
                (str(claim.enrollment_id),),
            ).fetchone()
            if (row is None or row["state"] != "consumed" or row["node_id"] != str(claim.node_id)
                    or not hmac.compare_digest(row["public_key_digest"], claim.public_key_digest)):
                raise PairingError("pairing enrollment cannot be activated")
            connection.execute(
                "INSERT INTO pairing_node_credentials "
                "(node_id, public_key_digest, credential_serial_digest, state) VALUES (?, ?, ?, 'active') "
                "ON CONFLICT(node_id) DO UPDATE SET public_key_digest = excluded.public_key_digest, "
                "credential_serial_digest = excluded.credential_serial_digest, state = 'active'",
                (str(claim.node_id), claim.public_key_digest, serial),
            )
            connection.execute("UPDATE pairing_enrollments SET state = 'activated' WHERE id = ?", (str(claim.enrollment_id),))

    def revoke(self, authorizer: OwnerAuthorizer, actor_context: object, *, node_id: UUID) -> None:
        self._authorize(authorizer, actor_context)
        node = _identity(node_id, "node identity")
        with self._transaction(write=True) as connection:
            changed = connection.execute(
                "UPDATE pairing_node_credentials SET state = 'revoked' WHERE node_id = ? AND state = 'active'",
                (str(node),),
            ).rowcount
            if changed != 1:
                raise PairingError("capture node is unavailable")

    def admits(self, *, node_id: UUID, public_key_digest: str,
               credential_serial_digest: str) -> bool:
        """Return true only for the current active capture-node credential."""
        node = _identity(node_id, "node identity")
        key = _digest(public_key_digest, "public key digest")
        serial = _digest(credential_serial_digest, "credential serial digest")
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT public_key_digest, credential_serial_digest, state "
                "FROM pairing_node_credentials WHERE node_id = ?", (str(node),)
            ).fetchone()
        return bool(row and row["state"] == "active"
                    and hmac.compare_digest(row["public_key_digest"], key)
                    and hmac.compare_digest(row["credential_serial_digest"], serial))
