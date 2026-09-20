"""Real SQLite smoke through closed, synthetic-only permission/action ports."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from uuid import UUID

from app.presence.access import AccessDenied
from app.presence.delivery import ActionResult
from app.presence.models import Kind, Observation, PresenceState, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


def run_presence(root, scenario):
    database = Database(root / "synthetic-presence.sqlite3")
    with closing(database.connect()) as db:
        migrate(db, APPLICATION_MIGRATIONS)

    class SyntheticAccess:
        def require_owner(self, context):
            if context != "synthetic-owner":
                raise AccessDenied()
            return UUID(int=4)

        def require_recordings(self, context):
            if context != "synthetic-recordings":
                raise AccessDenied()

    notifications = []
    def evidence(item, complete):
        if scenario == "error":
            raise OSError("synthetic action failure")
        return ActionResult.DELIVERED

    def notify(item, complete):
        notifications.append(item.identifier)
        return ActionResult.DELIVERED

    core = PresenceService(database, access=SyntheticAccess(), evidence=evidence,
                           notifications=notify, write_guard=lambda: None,
                           detection=lambda: True)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    core.override("synthetic-owner", PresenceState.PRESENT, now=now, clock_trusted=True)
    event = Observation(Kind.SERVER_MOVEMENT, now, now, source_id=UUID(int=1), confidence=0.9,
                        quality=Quality.SUFFICIENT, confirmed=True, clock_trusted=True)
    core.process_critical(lambda: event)
    assert not notifications  # Ingestion never invokes potentially slow ports.
    core.dispatch_pending()
    assert notifications == [event.identifier]
    status = core.snapshot(now=now, clock_trusted=True)
    assert status["pending_critical_actions"] == (scenario == "error")
    assert [status[key] for key in ("critical_detection", "critical_persistence",
                                    "critical_evidence", "critical_notifications")] == ["armed"] * 4
    assert not status["critical_paths_degraded"] and not status["override_expiry_pending"]
    window = dict(received_from=now - timedelta(seconds=1), received_to=now + timedelta(seconds=1))
    assert len(core.history("synthetic-recordings", **window)["items"]) == 2
    try:
        core.history("synthetic-live-only", **window)
    except AccessDenied:
        pass
    else:
        raise AssertionError("historical permission boundary failed")
