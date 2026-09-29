"""Server-side ``live:view`` validator for authorization-bound live sessions.

A future human route resolves the caller through ``AccessStore.authorize`` with
``Permission.LIVE_VIEW`` and only then constructs ``LiveAccess``.  This
validator is what ``LiveViewerSessions`` re-runs on every open and every media
read, so a grant change, principal revocation or copied session identifier
cannot keep a live stream open: the principal must still be active, still at
the exact authorization revision the session was bound to, and still hold
``live:view`` (the Owner implicitly holds it).  ``recordings:view`` alone never
satisfies it.  Any storage error denies.
"""

from contextlib import closing
from typing import Callable
from uuid import UUID

from app.storage.database import Database
from .model import Permission, PrincipalRole, PrincipalStatus


def live_view_validator(database: Database, *,
                        source_allowed: Callable[[UUID], bool] | None = None):
    """Return a ``LiveAccessValidator`` that reads current grants from SQLite."""
    if not isinstance(database, Database):
        raise ValueError("access database is required")
    if source_allowed is not None and not callable(source_allowed):
        raise ValueError("source filter must be callable")

    def validate(access, source_id) -> bool:
        principal_id = getattr(access, "principal_id", None)
        revision = getattr(access, "authorization_revision", None)
        if (not isinstance(principal_id, UUID) or type(revision) is not int
                or not isinstance(source_id, UUID)):
            return False
        if source_allowed is not None and source_allowed(source_id) is not True:
            return False
        try:
            with closing(database.connect()) as connection:
                connection.execute("BEGIN")
                row = connection.execute(
                    "SELECT role, status, authorization_revision FROM access_principals WHERE id=?",
                    (str(principal_id),),
                ).fetchone()
                granted = connection.execute(
                    "SELECT 1 FROM access_principal_permissions WHERE principal_id=? AND permission=?",
                    (str(principal_id), Permission.LIVE_VIEW.value),
                ).fetchone() is not None
                connection.execute("COMMIT")
        except Exception:
            return False
        if (row is None or row["status"] != PrincipalStatus.ACTIVE.value
                or row["authorization_revision"] != revision):
            return False
        return row["role"] == PrincipalRole.OWNER.value or granted

    return validate
