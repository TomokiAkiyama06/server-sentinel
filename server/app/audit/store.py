"""SQLite security/admin audit persistence and bounded retention cleanup."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Callable
from uuid import UUID, uuid4

from app.storage.database import Database
from .model import (
    ActorCategory, AuditAction, AuditOutcome, AuditRecord, AuditValidationError,
    TargetKind, utc_timestamp,
)


DEFAULT_RETENTION = timedelta(days=90)
MAX_PAGE_SIZE = 1000


class AuditStorageError(RuntimeError):
    """Audit persistence failed without disclosing database paths or values."""


def _microseconds(value: datetime) -> int:
    value = utc_timestamp(value)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (delta.days * 86_400_000_000
            + delta.seconds * 1_000_000 + delta.microseconds)


def _datetime(value: int) -> datetime:
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)


class AuditStore:
    """Low-level local store; authorization is enforced by the service boundary."""

    def __init__(self, database: Database, *, clock: Callable[[], datetime] | None = None,
                 retention: timedelta = DEFAULT_RETENTION):
        if not isinstance(retention, timedelta) or retention <= timedelta(0):
            raise AuditValidationError("invalid audit retention")
        self.database = database
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.retention = retention

    @contextmanager
    def transaction(self, *, write=False):
        connection = None
        try:
            connection = self.database.connect()
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except sqlite3.Error:
            if connection is not None:
                connection.rollback()
            raise AuditStorageError("audit storage operation failed") from None
        except BaseException:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

    def append_on(self, connection: sqlite3.Connection, *,
                  actor_category: ActorCategory, action: AuditAction,
                  target_kind: TargetKind, target_logical_id: UUID,
                  outcome: AuditOutcome) -> AuditRecord:
        """Append on a caller-owned transaction for atomic domain mutations."""
        if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
            raise AuditStorageError("audit transaction is unavailable")
        record = AuditRecord(
            uuid4(), actor_category, action, target_kind, target_logical_id,
            utc_timestamp(self._clock()), outcome,
        )
        try:
            connection.execute(
                "INSERT INTO security_admin_audit_records VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(record.id), record.actor_category.value, record.action.value,
                 record.target_kind.value, str(record.target_logical_id),
                 _microseconds(record.occurred_at), record.outcome.value),
            )
        except sqlite3.Error:
            raise AuditStorageError("audit storage operation failed") from None
        return record

    def append(self, *, actor_category: ActorCategory, action: AuditAction,
               target_kind: TargetKind, target_logical_id: UUID,
               outcome: AuditOutcome) -> AuditRecord:
        with self.transaction(write=True) as connection:
            return self.append_on(
                connection, actor_category=actor_category, action=action,
                target_kind=target_kind, target_logical_id=target_logical_id,
                outcome=outcome,
            )

    @staticmethod
    def _record(row) -> AuditRecord:
        return AuditRecord(
            UUID(row["id"]), ActorCategory(row["actor_category"]),
            AuditAction(row["action"]), TargetKind(row["target_kind"]),
            UUID(row["target_logical_id"]), _datetime(row["occurred_at_us"]),
            AuditOutcome(row["outcome"]),
        )

    def list_records(self, *, limit: int = 100,
                     before: datetime | None = None) -> tuple[AuditRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise AuditValidationError("invalid audit page size")
        cutoff = _microseconds(before) if before is not None else None
        with self.transaction() as connection:
            if cutoff is None:
                rows = connection.execute(
                    "SELECT * FROM security_admin_audit_records "
                    "ORDER BY occurred_at_us DESC, id DESC LIMIT ?", (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM security_admin_audit_records WHERE occurred_at_us < ? "
                    "ORDER BY occurred_at_us DESC, id DESC LIMIT ?", (cutoff, limit),
                ).fetchall()
        return tuple(self._record(row) for row in rows)

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        """Delete only audit rows strictly older than this store's retention."""
        reference = utc_timestamp(self._clock() if now is None else now)
        cutoff = _microseconds(reference - self.retention)
        with self.transaction(write=True) as connection:
            cursor = connection.execute(
                "DELETE FROM security_admin_audit_records WHERE occurred_at_us < ?", (cutoff,),
            )
            return cursor.rowcount
