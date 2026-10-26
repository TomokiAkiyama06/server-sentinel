"""Durable local fault/notification state, independent of optional Slack."""

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from uuid import UUID

from app.media.health.service import HealthResult, HealthState, Stage
from app.notifications.service import NotificationEvent, NotificationKind
from app.notifications.slack import DeliveryResult
from app.storage.migrations import Migration


def monitoring_migration(version: int) -> Migration:
    return Migration(version, "monitoring_runtime", (
        "CREATE TABLE notification_events (event_id TEXT PRIMARY KEY, kind TEXT NOT NULL, "
        "at TEXT NOT NULL, confirmed INTEGER NOT NULL CHECK(confirmed IN (0,1)), "
        "delivery TEXT NOT NULL CHECK(delivery IN ('disabled','sent','failed','suppressed','pending')))",
        "CREATE INDEX notification_events_time ON notification_events(at)",
        "CREATE TABLE recording_health_status (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "at TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('OK','FAILED','UNAVAILABLE')), "
        "stages TEXT NOT NULL)",
    ))


def notification_acceptance_migration(version: int) -> Migration:
    """When the service last took each notification row (Issue #287).

    ``accepted_at`` is the wall-clock time of a row's latest local write: the
    notification service accepting the notification, or a later write of the
    same row (its delivery result, a refused write retried). It is never
    earlier than the acceptance, so the restart recovery of the hourly access
    and finding budgets (``MonitoringRuntime._notification_window``) counts a
    row at least as long as the process that sent it did. ``at`` stays the
    event's own time, which a retry keeps. Existing rows keep ``NULL``, read
    as ``at`` (the recovery before this column). ``ADD COLUMN`` rewrites no
    row and deletes nothing.
    """
    return Migration(version, "notification_acceptance_time", (
        "ALTER TABLE notification_events ADD COLUMN accepted_at TEXT",
    ))


def run_marker_migration(version: int) -> Migration:
    """The running marker of the monitoring runtime (Issue #351, #347).

    One row while a process runs with storage admitted: a random per-process
    token (no host, path, device or time value), written when the runtime
    reaches `running` and deleted by its graceful stop. A row found at the
    next start therefore means the previous process exited without that stop
    (crash, kill, OOM, power loss), so a refusal it kept only in memory may
    have been lost. The table lives in the Main database on the verified
    recording filesystem (`admit_state_file`); creating it deletes nothing.
    """
    return Migration(version, "monitoring_run_marker", (
        "CREATE TABLE monitoring_run_marker (singleton INTEGER PRIMARY KEY "
        "CHECK(singleton=1), token TEXT NOT NULL)",
    ))


def _utc(at: datetime) -> str:
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("AWARE_TIME_REQUIRED")
    return at.astimezone(timezone.utc).isoformat()


class _Autocommit:
    def __init__(self, connection: sqlite3.Connection, reservation):
        if connection.isolation_level is not None or not callable(reservation):
            raise ValueError("MONITORING_STORE_UNAVAILABLE")
        self.db = connection
        self._reservation = reservation

    def _write(self, statement: str, values: tuple) -> int:
        if self.db.in_transaction:
            raise RuntimeError("MONITORING_DATABASE_BUSY")
        with self._reservation():
            return self.db.execute(statement, values).rowcount


class NotificationEventStore(_Autocommit):
    """`NotificationService` local sink: durable upsert keyed by event ID.

    A pending event and its later sent/failed result share one row. Only fixed
    kind/time/delivery values are stored; no message text, media or identity.
    """

    def upsert(self, event: NotificationEvent, *, accepted_at: datetime) -> None:
        """Write ``event``; ``accepted_at`` is now (the time of this write).

        Every write of the row moves ``accepted_at`` to its own time, so a
        retry accepted hours after the event's ``at`` is counted from the
        retry (Issue #287); kind, time and confirmed flag never change.
        """
        if not isinstance(event, NotificationEvent):
            raise ValueError("invalid notification event")
        self._write(
            "INSERT INTO notification_events(event_id,kind,at,confirmed,delivery,accepted_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET "
            "delivery=excluded.delivery,accepted_at=excluded.accepted_at",
            (str(event.event_id), event.kind.value, _utc(event.at), int(event.confirmed),
             event.delivery.value, _utc(accepted_at)),
        )

    def get(self, event_id: UUID) -> dict | None:
        row = self.db.execute(
            "SELECT event_id,kind,at,confirmed,delivery FROM notification_events WHERE event_id=?",
            (str(event_id),),
        ).fetchone()
        if row is None:
            return None
        return {"event_id": UUID(row[0]), "kind": NotificationKind(row[1]),
                "at": datetime.fromisoformat(row[2]), "confirmed": bool(row[3]),
                "delivery": DeliveryResult(row[4])}

    def count_since(self, since: datetime, kinds: tuple[NotificationKind, ...]) -> int:
        marks = ",".join("?" for _ in kinds)
        return self.db.execute(
            f"SELECT COUNT(*) FROM notification_events WHERE at>=? AND kind IN ({marks})",
            (_utc(since), *(kind.value for kind in kinds)),
        ).fetchone()[0]

    def expire(self, now: datetime, retention: timedelta, *, limit: int = 1000) -> int:
        """Remove fault history older than the shared audit-retention period."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid notification retention batch")
        return max(self._write(
            "DELETE FROM notification_events WHERE event_id IN (SELECT event_id FROM "
            "notification_events WHERE at<? ORDER BY at,event_id LIMIT ?)",
            (_utc(now - retention), limit),
        ), 0)


class RecordingHealthStatusStore(_Autocommit):
    """Latest recording-health verdict as fixed state/stage codes for the UI."""

    def record(self, result: HealthResult, at: datetime) -> None:
        if (not isinstance(result, HealthResult) or not isinstance(result.state, HealthState)
                or any(not isinstance(stage, Stage) for stage in result.stages)):
            raise ValueError("invalid recording health result")
        self._write(
            "INSERT INTO recording_health_status VALUES (1,?,?,?) ON CONFLICT(singleton) DO UPDATE "
            "SET at=excluded.at,state=excluded.state,stages=excluded.stages",
            (_utc(at), result.state.value,
             json.dumps([stage.value for stage in result.stages], separators=(",", ":"))),
        )

    def latest(self) -> dict | None:
        row = self.db.execute(
            "SELECT at,state,stages FROM recording_health_status WHERE singleton=1"
        ).fetchone()
        if row is None:
            return None
        return {"at": datetime.fromisoformat(row[0]), "state": HealthState(row[1]),
                "stages": tuple(Stage(stage) for stage in json.loads(row[2]))}


class RunMarkerStore(_Autocommit):
    """The singleton running marker (`run_marker_migration`).

    Every write is admitted by the storage policy like any other metadata
    write, so the marker is never written outside the verified filesystem.
    """

    def read(self) -> str | None:
        row = self.db.execute(
            "SELECT token FROM monitoring_run_marker WHERE singleton=1").fetchone()
        return None if row is None else str(row[0])

    def mark(self, token: str) -> None:
        self._write(
            "INSERT INTO monitoring_run_marker VALUES (1,?) ON CONFLICT(singleton) DO UPDATE "
            "SET token=excluded.token", (str(token),))

    def clear(self, token: str) -> None:
        """Delete the marker only when it is still ``token`` (this process's)."""
        self._write("DELETE FROM monitoring_run_marker WHERE singleton=1 AND token=?",
                    (str(token),))
