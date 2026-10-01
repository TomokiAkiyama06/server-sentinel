"""Server-side ``live:view`` validator for authorization-bound live sessions.

A future human route resolves the caller with ``authorize_live_access`` (which
runs ``AccessStore.authorize`` with ``Permission.LIVE_VIEW``) and receives a
``BoundLiveAccess`` tied to that caller's human access session.  This validator
is what ``LiveViewerSessions`` re-runs on every open and every media read, so a
grant change, principal revocation, credential revocation (credential-scoped:
a synced passkey is revoked wherever it exists, not on one device),
session invalidation or expiry, or copied session identifier cannot keep a live
stream open: the bound human access session must still be current, the
principal must still be active at the exact authorization revision the session
was bound to, and must still hold ``live:view`` (the Owner implicitly holds
it).  ``recordings:view`` alone never satisfies it, and a ``LiveAccess`` that is
not bound to a human access session is refused.  Any storage error denies.
"""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from uuid import UUID

from app.media.live.sessions import LiveAccess
from app.storage.database import Database, PinnedDatabase
from .model import AccessValidationError, Permission, PrincipalRole, PrincipalStatus, utc_time
from .store import AccessStore, _digest, _us


@dataclass(frozen=True)
class BoundLiveAccess(LiveAccess):
    """``LiveAccess`` bound to the human access session that authorized it."""

    access_session_id: UUID

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.access_session_id, UUID):
            raise ValueError("access_session_id must be a UUID")


def authorize_live_access(access_store: AccessStore, token: bytes, external_identity: str,
                          *, now: datetime | None = None) -> BoundLiveAccess:
    """Authorize ``live:view`` for a human request and bind it to its session."""
    principal = access_store.authorize(token, external_identity, Permission.LIVE_VIEW, now=now)
    with closing(access_store.database.connect()) as connection:
        row = connection.execute(
            "SELECT id FROM access_sessions WHERE token_digest=? AND principal_id=?",
            (_digest(token), str(principal.id)),
        ).fetchone()
    if row is None:
        raise AccessValidationError("access is unavailable")
    return BoundLiveAccess(principal.id, principal.authorization_revision, UUID(row["id"]))


def live_view_validator(database: Database, *,
                        source_allowed: Callable[[UUID], bool] | None = None,
                        clock: Callable[[], datetime] | None = None):
    """Return a ``LiveAccessValidator`` that reads current grants from SQLite."""
    # A route may pass the admission-pinned database so validation never
    # opens or creates a database on a lost/replaced filesystem.
    if not isinstance(database, (Database, PinnedDatabase)):
        raise ValueError("access database is required")
    if source_allowed is not None and not callable(source_allowed):
        raise ValueError("source filter must be callable")
    if clock is not None and not callable(clock):
        raise ValueError("clock must be callable")
    current = clock or (lambda: datetime.now(timezone.utc))

    def validate(access, source_id) -> bool:
        if (not isinstance(access, BoundLiveAccess)
                or type(access.authorization_revision) is not int
                or not isinstance(source_id, UUID)):
            return False
        if source_allowed is not None and source_allowed(source_id) is not True:
            return False
        try:
            at = _us(utc_time(current()))
            with closing(database.connect()) as connection:
                connection.execute("BEGIN")
                row = connection.execute(
                    "SELECT p.role, p.status, p.authorization_revision, s.principal_revision,"
                    " s.deployment_generation, s.invalidated_at_us, s.established_at_us,"
                    " s.last_seen_at_us, s.idle_expires_at_us, s.absolute_expires_at_us,"
                    " c.revoked_at_us credential_revoked, c.inconsistent_at_us credential_inconsistent"
                    " FROM access_sessions s JOIN access_principals p ON p.id=s.principal_id"
                    " JOIN access_credentials c ON c.credential_id=s.credential_id"
                    " WHERE s.id=? AND s.principal_id=?",
                    (str(access.access_session_id), str(access.principal_id)),
                ).fetchone()
                generation = connection.execute(
                    "SELECT authorization_generation FROM access_deployment_state WHERE singleton=1"
                ).fetchone()
                granted = connection.execute(
                    "SELECT 1 FROM access_principal_permissions WHERE principal_id=? AND permission=?",
                    (str(access.principal_id), Permission.LIVE_VIEW.value),
                ).fetchone() is not None
                connection.execute("COMMIT")
        except Exception:
            return False
        if (row is None or generation is None
                or row["status"] != PrincipalStatus.ACTIVE.value
                or row["authorization_revision"] != access.authorization_revision
                or row["principal_revision"] != access.authorization_revision
                or row["deployment_generation"] != generation[0]
                or row["invalidated_at_us"] is not None
                or row["credential_revoked"] is not None
                or row["credential_inconsistent"] is not None
                or not row["established_at_us"] <= at < row["idle_expires_at_us"]
                # A clock that moved before the last accepted activity fails
                # closed exactly like ``AccessStore.authorize`` (AUTH-009), so a
                # regression can never extend an open preview's lifetime.
                or not row["last_seen_at_us"] <= at
                or at >= row["absolute_expires_at_us"]):
            return False
        return row["role"] == PrincipalRole.OWNER.value or granted

    return validate
