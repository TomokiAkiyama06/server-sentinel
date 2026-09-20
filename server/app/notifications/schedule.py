"""Persisted, once-per-local-date summary dispatch; no implicit retries/floods."""

from datetime import datetime
from zoneinfo import ZoneInfo
import sqlite3

from app.notifications.service import DailySummary, NotificationService, aware
from app.notifications.slack import DeliveryResult
from app.storage.migrations import Migration


def notification_migration(version: int) -> Migration:
    return Migration(version, "notification_schedule", (
        "CREATE TABLE notification_schedule (schedule_id TEXT PRIMARY KEY, "
        "local_date TEXT NOT NULL, result TEXT NOT NULL)",
    ))


class DailySummaryScheduler:
    """Call tick from the owning worker's timer; the default is 23:00 local.

    During a forward clock/DST jump, the first tick after the scheduled wall
    time sends that day's summary. A backward jump/fold never sends it twice.
    A durable claim is made before delivery; a crash leaves 'pending', explicitly
    indicating uncertain delivery. No automatic retry risks duplicate messages.
    The integration supplies the same metadata write guard as the storage worker.
    """

    def __init__(self, connection: sqlite3.Connection, zone: ZoneInfo,
                 service: NotificationService, reservation, *, hour: int = 23,
                 minute: int = 0):
        if (not isinstance(zone, ZoneInfo) or type(hour) is not int or not 0 <= hour <= 23
                or type(minute) is not int or not 0 <= minute <= 59):
            raise ValueError("invalid daily schedule")
        self.db, self.zone, self.service = connection, zone, service
        self.hour, self.minute, self._reservation = hour, minute, reservation
        self._key = f"daily:{zone.key}:{hour:02}:{minute:02}"

    def status(self) -> dict | None:
        row = self.db.execute("SELECT local_date,result FROM notification_schedule WHERE schedule_id=?",
                              (self._key,)).fetchone()
        return {"local_date": row[0], "result": row[1]} if row else None

    def tick(self, now: datetime, summary: DailySummary) -> DeliveryResult:
        aware(now)
        if not isinstance(summary, DailySummary):
            raise ValueError("invalid daily summary")
        local = now.astimezone(self.zone)
        if (local.hour, local.minute) < (self.hour, self.minute):
            return DeliveryResult.SUPPRESSED
        date = local.date().isoformat()
        if self.db.in_transaction:
            raise RuntimeError("notification schedule unavailable")
        with self._reservation():
            try:
                self.db.execute("BEGIN IMMEDIATE")
                prior = self.db.execute("SELECT local_date FROM notification_schedule WHERE schedule_id=?",
                                        (self._key,)).fetchone()
                if prior and prior[0] >= date:
                    self.db.rollback()
                    return DeliveryResult.SUPPRESSED
                self.db.execute("INSERT INTO notification_schedule VALUES (?,?,'pending') "
                                "ON CONFLICT(schedule_id) DO UPDATE SET local_date=excluded.local_date,result='pending'",
                                (self._key, date))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        result = self.service.daily(summary, at=now)
        with self._reservation():
            self.db.execute("UPDATE notification_schedule SET result=? WHERE schedule_id=? AND local_date=?",
                            (result.value, self._key, date))
        return result
