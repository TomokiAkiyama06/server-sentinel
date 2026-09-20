"""Baseline and sanitized fault outbox in the deployment-local database."""

from dataclasses import asdict
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID
import json
import sqlite3
import threading

from app.storage.migrations import Migration
from .model import Component, Finding, Inventory, Kind, State


def integrity_migration(version: int) -> Migration:
    """The application schema aggregator assigns the next unused version."""
    return Migration(version, "hardware_integrity", (
        "CREATE TABLE integrity_baseline (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "revision INTEGER NOT NULL, inventory TEXT NOT NULL)",
        "CREATE TABLE integrity_audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, "
        "actor TEXT NOT NULL, revision INTEGER NOT NULL)",
        "CREATE TABLE integrity_status (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "at TEXT NOT NULL, findings TEXT NOT NULL, delivery_blocked INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE integrity_outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, "
        "immediate INTEGER NOT NULL, findings TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE integrity_overflow (kind TEXT NOT NULL CHECK(kind IN ('CPU','MEMORY','STORAGE','GPU')), "
        "state TEXT NOT NULL CHECK(state IN ('CHANGED','MISSING','NEW_DEVICE','UNVERIFIABLE')), "
        "at TEXT NOT NULL, PRIMARY KEY(kind,state))",
    ))


class OwnerApproval(Protocol):
    def require_owner(self) -> UUID:
        """Trusted application authorization, not a caller-controlled boolean."""


class DenyApproval:
    def require_owner(self) -> UUID:
        raise PermissionError("OWNER_APPROVAL_REQUIRED")


def timestamp(at: datetime) -> str:
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("AWARE_TIME_REQUIRED")
    return at.astimezone(timezone.utc).isoformat()


class IntegrityStore:
    def __init__(self, connection: sqlite3.Connection, approval: OwnerApproval | None = None, *,
                 reservation, max_pending_events: int):
        if (type(max_pending_events) is not int or not 1 <= max_pending_events <= 10000
                or not callable(reservation)):
            raise ValueError("INVALID_INTEGRITY_STORAGE_POLICY")
        self.db = connection
        self.db.row_factory = sqlite3.Row
        self.approval = approval or DenyApproval()
        self._owner = threading.get_ident()
        self._reservation = reservation
        self._max_pending = max_pending_events
        self._check()
        if self.db.in_transaction:
            raise RuntimeError("INTEGRITY_DATABASE_BUSY")

    def _check(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError("INTEGRITY_WORKER_UNAVAILABLE")
        mode = getattr(self.db, "autocommit", None)
        if mode is False or (self.db.isolation_level is not None and mode is not True):
            raise ValueError("INTEGRITY_AUTOCOMMIT_REQUIRED")

    @contextmanager
    def _transaction(self):
        self._check()
        if self.db.in_transaction:
            raise RuntimeError("INTEGRITY_DATABASE_BUSY")
        with self._reservation():
            try:
                self.db.execute("BEGIN IMMEDIATE")
                yield
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def baseline(self) -> tuple[int, Inventory | None]:
        self._check()
        row = self.db.execute("SELECT revision,inventory FROM integrity_baseline WHERE singleton=1").fetchone()
        if row is None:
            return 0, None
        data = json.loads(row["inventory"])
        components = tuple(Component(Kind(item["kind"]), item["location"],
                                     tuple(tuple(pair) for pair in item["properties"]),
                                     tuple(tuple(pair) for pair in item["identity"]), item.get("complete", True))
                           for item in data["components"])
        return row["revision"], Inventory(components, frozenset(Kind(kind) for kind in data["unavailable"]))

    def approve(self, inventory: Inventory, *, expected_revision: int, at: datetime) -> int:
        self._check()
        actor = str(UUID(str(self.approval.require_owner())))
        when = timestamp(at)
        payload = json.dumps({"components": [asdict(item) for item in inventory.components],
                              "unavailable": sorted(inventory.unavailable)}, separators=(",", ":"))
        with self._transaction():
            actual, _ = self.baseline()
            if actual != expected_revision:
                raise ValueError("BASELINE_REVISION_CHANGED")
            revision = actual + 1
            self.db.execute("INSERT INTO integrity_baseline VALUES(1,?,?) "
                            "ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,inventory=excluded.inventory",
                            (revision, payload))
            self.db.execute("INSERT INTO integrity_audit(at,actor,revision) VALUES(?,?,?)", (when, actor, revision))
            return revision

    def record(self, findings: tuple[Finding, ...], at: datetime) -> None:
        when = timestamp(at)
        payload = json.dumps([asdict(item) for item in findings], separators=(",", ":"))
        warning = any(item.state != "OK" for item in findings)
        blocked = False
        with self._transaction():
            pending = self.db.execute("SELECT COUNT(*) FROM integrity_outbox WHERE delivered=0").fetchone()[0]
            blocked = warning and pending >= self._max_pending
            if blocked:
                # Sixteen fixed category/state slots coalesce repeated faults
                # durably even if healthy status later replaces the observation.
                self.db.executemany("INSERT INTO integrity_overflow(kind,state,at) VALUES(?,?,?) "
                                    "ON CONFLICT(kind,state) DO NOTHING",
                                    ((item.kind, item.state, when) for item in findings if item.state != State.OK))
            overflow = bool(self.db.execute("SELECT 1 FROM integrity_overflow LIMIT 1").fetchone())
            self.db.execute("INSERT INTO integrity_status VALUES(1,?,?,?) "
                            "ON CONFLICT(singleton) DO UPDATE SET at=excluded.at,findings=excluded.findings,"
                            "delivery_blocked=excluded.delivery_blocked", (when, payload, int(overflow)))
            if warning and not blocked:
                self.db.execute("INSERT INTO integrity_outbox(at,immediate,findings) VALUES(?,?,?)",
                                (when, int(any(item.immediate for item in findings)), payload))
        if blocked:
            raise RuntimeError("INTEGRITY_OUTBOX_FULL")

    def _promote_overflow(self):
        """Run inside the reserved acknowledgement transaction, without loss."""
        pending = self.db.execute("SELECT COUNT(*) FROM integrity_outbox WHERE delivered=0").fetchone()[0]
        rows = self.db.execute("SELECT kind,state,at FROM integrity_overflow ORDER BY at,kind,state LIMIT ?",
                               (max(0, self._max_pending - pending),)).fetchall()
        for row in rows:
            finding = Finding(Kind(row["kind"]), State(row["state"]), "COALESCED_PENDING_WARNING")
            payload = json.dumps([asdict(finding)], separators=(",", ":"))
            self.db.execute("INSERT INTO integrity_outbox(at,immediate,findings) VALUES(?,?,?)",
                            (row["at"], int(finding.immediate), payload))
            self.db.execute("DELETE FROM integrity_overflow WHERE kind=? AND state=?", (finding.kind, finding.state))
        remaining = bool(self.db.execute("SELECT 1 FROM integrity_overflow LIMIT 1").fetchone())
        self.db.execute("UPDATE integrity_status SET delivery_blocked=? WHERE singleton=1", (int(remaining),))

    def deliver(self, sink) -> bool:
        """At-least-once fixed-data events. Slack failure cannot erase local faults.

        The injected #21 bridge handles immediate alerts and visible warnings;
        it must not treat an unconfigured optional Slack destination as failure.
        """
        self._check()
        rows = self.db.execute("SELECT id,at,immediate,findings FROM integrity_outbox WHERE delivered=0 ORDER BY id LIMIT 100").fetchall()
        for row in rows:
            try:
                sink(row["id"], datetime.fromisoformat(row["at"]), bool(row["immediate"]), json.loads(row["findings"]))
            except Exception:
                return False
            # Successful sink acceptance transfers history ownership to the
            # durable #21 sink. Keep only pending transport rows in this outbox.
            with self._transaction():
                self.db.execute("DELETE FROM integrity_outbox WHERE id=?", (row["id"],))
                self._promote_overflow()
        return True
