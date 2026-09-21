"""Transactional local authorization state; WebAuthn ceremony remains outside this module."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
from typing import Callable, Iterable
from uuid import UUID, uuid4

from app.storage.database import Database
from .model import AccessValidationError, Credential, Permission, Principal, PrincipalRole, PrincipalStatus, utc_time


class AccessStorageError(RuntimeError):
    """Storage failure without paths, identities, tokens, or credential material."""


IDLE_LIFETIME = timedelta(minutes=30)
ABSOLUTE_LIFETIME = timedelta(hours=12)


def _us(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    value = utc_time(value)
    delta = value - epoch
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _time(value: int) -> datetime:
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)


def _digest(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or not 16 <= len(secret) <= 4096:
        raise AccessValidationError("secret is invalid")
    return hashlib.sha256(secret).digest()


def _identity(value: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or not value.isascii() or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise AccessValidationError("external identity is invalid")
    return value


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
    """

    def __init__(self, database: Database, *, clock: Callable[[], datetime] | None = None):
        self.database = database
        self._clock = clock or (lambda: datetime.now(timezone.utc))

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

    @staticmethod
    def _principal(row) -> Principal:
        return Principal(UUID(row["principal_id"] if "principal_id" in row.keys() else row["id"]), row["external_identity"], row["display_name"],
                         PrincipalRole(row["role"]), PrincipalStatus(row["status"]),
                         row["authorization_revision"], _time(row["created_at_us"]),
                         _time(row["revoked_at_us"]) if row["revoked_at_us"] is not None else None)

    @staticmethod
    def _credential(row) -> Credential:
        return Credential(bytes(row["credential_id"]), UUID(row["principal_id"]), bytes(row["public_key"]),
                          row["algorithm"], row["sign_count"], _time(row["enrolled_at_us"]),
                          _time(row["revoked_at_us"]) if row["revoked_at_us"] is not None else None)

    def bootstrap_owner(self, external_identity: str, display_name: str, *, now: datetime | None = None) -> Principal:
        identity, name = _identity(external_identity), _display(display_name)
        at = utc_time(self._clock() if now is None else now)
        owner = Principal(uuid4(), identity, name, PrincipalRole.OWNER, PrincipalStatus.ACTIVE, 0, at)
        with self._transaction(write=True) as connection:
            if connection.execute("SELECT 1 FROM access_principals WHERE role='owner'").fetchone() is not None:
                raise AccessValidationError("owner is already configured")
            connection.execute("INSERT INTO access_principals VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                               (str(owner.id), owner.external_identity, owner.display_name, owner.role.value,
                                owner.status.value, owner.authorization_revision, _us(owner.created_at)))
        return owner

    def invite(self, external_identity: str, display_name: str, permissions: Iterable[Permission], *, now: datetime | None = None) -> Principal:
        identity, name = _identity(external_identity), _display(display_name)
        grants = self._permissions(permissions)
        at = utc_time(self._clock() if now is None else now)
        principal = Principal(uuid4(), identity, name, PrincipalRole.INVITED_USER, PrincipalStatus.INVITED, 0, at)
        with self._transaction(write=True) as connection:
            connection.execute("INSERT INTO access_principals VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                               (str(principal.id), identity, name, principal.role.value, principal.status.value, 0, _us(at)))
            connection.executemany("INSERT INTO access_principal_permissions VALUES (?, ?)",
                                   ((str(principal.id), grant.value) for grant in grants))
        return principal

    def issue_enrollment(self, principal_id: UUID, secret: bytes, expires_at: datetime, *, now: datetime | None = None) -> UUID:
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        digest = _digest(secret)
        at, expiry = utc_time(self._clock() if now is None else now), utc_time(expires_at)
        if expiry <= at:
            raise AccessValidationError("enrollment expiry is invalid")
        invitation_id = uuid4()
        with self._transaction(write=True) as connection:
            principal = connection.execute("SELECT * FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
            if principal is None or principal["status"] == PrincipalStatus.REVOKED.value:
                raise AccessValidationError("principal is unavailable")
            generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
            connection.execute("INSERT INTO access_invitations VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                               (str(invitation_id), digest, str(principal_id), principal["authorization_revision"], generation, _us(at), _us(expiry)))
        return invitation_id

    def enroll_credential(self, enrollment_secret: bytes, external_identity: str, credential_id: bytes,
                          public_key: bytes, algorithm: int, sign_count: int, *, now: datetime | None = None) -> Credential:
        digest, identity = _digest(enrollment_secret), _identity(external_identity)
        credential = Credential(credential_id, UUID(int=0), public_key, algorithm, sign_count,
                                utc_time(self._clock() if now is None else now))
        at = credential.enrolled_at
        with self._transaction(write=True) as connection:
            row = connection.execute("SELECT i.*, p.external_identity, p.status, p.authorization_revision FROM access_invitations i JOIN access_principals p ON p.id=i.principal_id WHERE i.secret_digest=?", (digest,)).fetchone()
            state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
            if (row is None or row["redeemed_at_us"] is not None or row["revoked_at_us"] is not None
                    or row["status"] == PrincipalStatus.REVOKED.value or row["external_identity"] != identity
                    or row["principal_revision"] != row["authorization_revision"]
                    or row["deployment_generation"] != state or not row["issued_at_us"] <= _us(at) <= row["expires_at_us"]):
                raise AccessValidationError("enrollment is unavailable")
            principal_id = UUID(row["principal_id"])
            credential = Credential(credential_id, principal_id, public_key, algorithm, sign_count, at)
            connection.execute("INSERT INTO access_credentials VALUES (?, ?, ?, ?, ?, ?, NULL)",
                               (credential.credential_id, str(principal_id), credential.public_key, credential.algorithm, credential.sign_count, _us(at)))
            connection.execute("UPDATE access_invitations SET redeemed_at_us=? WHERE id=?", (_us(at), row["id"]))
            connection.execute("UPDATE access_principals SET status=? WHERE id=? AND status=?", (PrincipalStatus.ACTIVE.value, str(principal_id), PrincipalStatus.INVITED.value))
        return credential

    def establish_session(self, principal_id: UUID, credential_id: bytes, token: bytes, *, now: datetime | None = None,
                          idle_lifetime: timedelta = IDLE_LIFETIME, absolute_lifetime: timedelta = ABSOLUTE_LIFETIME) -> UUID:
        if not isinstance(principal_id, UUID) or not isinstance(credential_id, bytes):
            raise AccessValidationError("session subject is invalid")
        token_digest = _digest(token)
        if not isinstance(idle_lifetime, timedelta) or not isinstance(absolute_lifetime, timedelta) or not timedelta(0) < idle_lifetime <= absolute_lifetime:
            raise AccessValidationError("session lifetime is invalid")
        at, session_id = utc_time(self._clock() if now is None else now), uuid4()
        with self._transaction(write=True) as connection:
            row = connection.execute("SELECT p.status, p.authorization_revision, c.revoked_at_us FROM access_principals p JOIN access_credentials c ON c.principal_id=p.id WHERE p.id=? AND c.credential_id=?", (str(principal_id), credential_id)).fetchone()
            if row is None or row["status"] != PrincipalStatus.ACTIVE.value or row["revoked_at_us"] is not None:
                raise AccessValidationError("session subject is unavailable")
            generation = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
            connection.execute("INSERT INTO access_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                               (str(session_id), token_digest, str(principal_id), credential_id, row["authorization_revision"], generation,
                                _us(at), _us(at), _us(at + idle_lifetime), _us(at + absolute_lifetime)))
        return session_id

    def authorize(self, token: bytes, external_identity: str, permission: Permission, *, now: datetime | None = None) -> Principal:
        digest, identity = _digest(token), _identity(external_identity)
        if not isinstance(permission, Permission):
            raise AccessValidationError("permission is invalid")
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            row = connection.execute("SELECT s.*, p.id principal_id, p.external_identity, p.display_name, p.role, p.status, p.authorization_revision, p.created_at_us, p.revoked_at_us, c.revoked_at_us credential_revoked FROM access_sessions s JOIN access_principals p ON p.id=s.principal_id JOIN access_credentials c ON c.credential_id=s.credential_id WHERE s.token_digest=?", (digest,)).fetchone()
            state = connection.execute("SELECT authorization_generation FROM access_deployment_state WHERE singleton=1").fetchone()[0]
            valid = row is not None and row["invalidated_at_us"] is None and row["external_identity"] == identity and row["status"] == PrincipalStatus.ACTIVE.value and row["credential_revoked"] is None and row["principal_revision"] == row["authorization_revision"] and row["deployment_generation"] == state and _us(at) < row["idle_expires_at_us"] and _us(at) < row["absolute_expires_at_us"]
            if not valid:
                raise AccessValidationError("access is unavailable")
            granted = connection.execute("SELECT 1 FROM access_principal_permissions WHERE principal_id=? AND permission=?", (row["principal_id"], permission.value)).fetchone() is not None
            principal = self._principal(row)
            if principal.role is not PrincipalRole.OWNER and not granted:
                raise AccessValidationError("access is unavailable")
            next_idle = min(_us(at + IDLE_LIFETIME), row["absolute_expires_at_us"])
            connection.execute("UPDATE access_sessions SET last_seen_at_us=?, idle_expires_at_us=? WHERE id=?", (_us(at), next_idle, row["id"]))
            return principal

    def set_permissions(self, principal_id: UUID, permissions: Iterable[Permission]) -> None:
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        grants = self._permissions(permissions)
        at = utc_time(self._clock())
        with self._transaction(write=True) as connection:
            row = connection.execute("SELECT status FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
            if row is None or row["status"] == PrincipalStatus.REVOKED.value:
                raise AccessValidationError("principal is unavailable")
            connection.execute("DELETE FROM access_principal_permissions WHERE principal_id=?", (str(principal_id),))
            connection.executemany("INSERT INTO access_principal_permissions VALUES (?, ?)", ((str(principal_id), value.value) for value in grants))
            self._advance_principal(connection, principal_id, at)

    def revoke_principal(self, principal_id: UUID, *, now: datetime | None = None) -> None:
        if not isinstance(principal_id, UUID):
            raise AccessValidationError("principal identity is invalid")
        at = utc_time(self._clock() if now is None else now)
        with self._transaction(write=True) as connection:
            row = connection.execute("SELECT status FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()
            if row is None:
                raise AccessValidationError("principal is unavailable")
            connection.execute("UPDATE access_principals SET status=?, revoked_at_us=?, authorization_revision=authorization_revision+1 WHERE id=?", (PrincipalStatus.REVOKED.value, _us(at), str(principal_id)))
            connection.execute("UPDATE access_credentials SET revoked_at_us=? WHERE principal_id=? AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
            connection.execute("UPDATE access_invitations SET revoked_at_us=? WHERE principal_id=? AND redeemed_at_us IS NULL AND revoked_at_us IS NULL", (_us(at), str(principal_id)))
            connection.execute("UPDATE access_sessions SET invalidated_at_us=? WHERE principal_id=? AND invalidated_at_us IS NULL", (_us(at), str(principal_id)))

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
        connection.execute("UPDATE access_sessions SET invalidated_at_us=? WHERE principal_id=? AND invalidated_at_us IS NULL", (_us(at), str(principal_id)))
