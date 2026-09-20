"""Main recording/audit retention, disjoint from Agent incident lifecycles."""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable
from uuid import UUID
import sqlite3

from app.media.recording.model import RecordingError
from app.storage.migrations import Migration
from app.storage.policy import StorageTransition


DAY_MS = 86_400_000


@dataclass(frozen=True)
class RetentionPeriods:
    recording_days: int = 20
    audit_days: int = 90

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in vars(self).values()):
            raise ValueError("invalid retention period")


class RetentionService:
    def __init__(self, store, periods: RetentionPeriods = RetentionPeriods()):
        self.store = store
        self.periods = periods

    def expired(self, now_ms: int, limit: int) -> int:
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError("invalid retention clock")
        cutoff = now_ms - self.periods.recording_days * DAY_MS
        return self._delete(cutoff, limit) if cutoff >= 0 else 0

    def oldest(self, limit: int) -> int:
        return self._delete(None, limit)

    def _delete(self, before_ms: int | None, limit: int) -> int:
        rows = self.store.retention_candidates(before_ms=before_ms, limit=limit)
        for row in rows:
            self.store.delete_recording(UUID(row["id"]), owner_requested=False)
        # Number of removed manifests, not reclaimed bytes: shared pre-roll or
        # evidence links may retain all segment bytes after a manifest removal.
        return len(rows)


class Action(StrEnum):
    READ = "recordings:view"
    OWNER = "owner"


def deny_action(_: Action) -> None:
    raise RecordingError("RECORDING_ACCESS_DENIED")


def deny_write() -> None:
    raise RecordingError("STORAGE_HARD_STOP")


@contextmanager
def deny_reservation():
    raise RecordingError("STORAGE_HARD_STOP")
    yield


class RecordingBrowser:
    """Domain-only facade; #10 supplies the actual authorized request adapter.

    No subject/session parsing, human route or download function is provided.
    Caller authorization is checked before any metadata read or mutation.
    """

    def __init__(self, store, authorize: Callable[[Action], None] = deny_action,
                 write_guard: Callable[[], None] = deny_write):
        self.store, self._authorize = store, authorize
        self._write_guard = write_guard

    def list(self, *, limit: int = 50, offset: int = 0):
        self._authorize(Action.READ)
        return self.store.list_recordings(limit=limit, offset=offset)

    def manifest(self, recording_id: UUID):
        self._authorize(Action.READ)
        # The store holds a control reservation for integrity persistence and
        # returns a truthful read-only snapshot if that write is unsafe.
        return self.store.manifest(recording_id)

    def star(self, recording_id: UUID, starred: bool) -> None:
        self._authorize(Action.OWNER)
        self._write_guard()
        self.store.set_starred(recording_id, starred)

    def delete(self, recording_id: UUID) -> int:
        self._authorize(Action.OWNER)
        self._write_guard()
        return self.store.delete_recording(recording_id, owner_requested=True)


def storage_audit_migration(version: int) -> Migration:
    return Migration(version, "storage_audit", (
        "CREATE TABLE storage_state_audit (id INTEGER PRIMARY KEY, at_ms INTEGER NOT NULL, "
        "previous_state TEXT NOT NULL, current_state TEXT NOT NULL)",
        "CREATE INDEX storage_audit_time ON storage_state_audit(at_ms)",
    ))


class StorageAudit:
    """Durable local transitions, with a separate default 90-day cleanup."""

    def __init__(self, connection: sqlite3.Connection,
                 periods: RetentionPeriods = RetentionPeriods(),
                 reservation=deny_reservation):
        if connection.isolation_level is not None:
            raise RecordingError("STORAGE_AUDIT_UNAVAILABLE")
        self.db, self.periods = connection, periods
        self._reservation = reservation

    def append(self, event: StorageTransition) -> None:
        if self.db.in_transaction or not isinstance(event, StorageTransition):
            raise RecordingError("STORAGE_AUDIT_UNAVAILABLE")
        with self._reservation():
            self.db.execute("INSERT INTO storage_state_audit(at_ms,previous_state,current_state) "
                            "VALUES (?,?,?)", (event.at_ms, event.previous.value, event.current.value))

    def expire(self, now_ms: int) -> int:
        if self.db.in_transaction or type(now_ms) is not int or now_ms < 0:
            raise RecordingError("STORAGE_AUDIT_UNAVAILABLE")
        with self._reservation():
            cursor = self.db.execute("DELETE FROM storage_state_audit WHERE at_ms < ?",
                                     (now_ms - self.periods.audit_days * DAY_MS,))
        return cursor.rowcount
