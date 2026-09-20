"""Baseline and sanitized fault outbox in the deployment-local database."""

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID
import json
import sqlite3

from app.storage.migrations import Migration
from .model import Component, Finding, Inventory, Kind


def integrity_migration(version: int) -> Migration:
    """The application schema aggregator assigns the next unused version."""
    return Migration(version, "hardware_integrity", (
        "CREATE TABLE integrity_baseline (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "revision INTEGER NOT NULL, inventory TEXT NOT NULL)",
        "CREATE TABLE integrity_audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, "
        "actor TEXT NOT NULL, revision INTEGER NOT NULL)",
        "CREATE TABLE integrity_status (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "at TEXT NOT NULL, findings TEXT NOT NULL)",
        "CREATE TABLE integrity_outbox (id INTEGER PRIMARY KEY, at TEXT NOT NULL, "
        "immediate INTEGER NOT NULL, findings TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)",
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
    def __init__(self, connection: sqlite3.Connection, approval: OwnerApproval | None = None):
        self.db = connection
        self.db.row_factory = sqlite3.Row
        self.approval = approval or DenyApproval()

    def baseline(self) -> tuple[int, Inventory | None]:
        row = self.db.execute("SELECT revision,inventory FROM integrity_baseline WHERE singleton=1").fetchone()
        if row is None:
            return 0, None
        data = json.loads(row["inventory"])
        components = tuple(Component(Kind(item["kind"]), item["location"],
                                     tuple(tuple(pair) for pair in item["properties"]),
                                     tuple(tuple(pair) for pair in item["identity"])) for item in data["components"])
        return row["revision"], Inventory(components, frozenset(Kind(kind) for kind in data["unavailable"]))

    def approve(self, inventory: Inventory, *, expected_revision: int, at: datetime) -> int:
        actor = str(UUID(str(self.approval.require_owner())))
        when = timestamp(at)
        payload = json.dumps({"components": [asdict(item) for item in inventory.components],
                              "unavailable": sorted(inventory.unavailable)}, separators=(",", ":"))
        if self.db.in_transaction:
            raise RuntimeError("INTEGRITY_DATABASE_BUSY")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            actual, _ = self.baseline()
            if actual != expected_revision:
                raise ValueError("BASELINE_REVISION_CHANGED")
            revision = actual + 1
            self.db.execute("INSERT INTO integrity_baseline VALUES(1,?,?) "
                            "ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,inventory=excluded.inventory",
                            (revision, payload))
            self.db.execute("INSERT INTO integrity_audit(at,actor,revision) VALUES(?,?,?)", (when, actor, revision))
            self.db.commit()
            return revision
        except BaseException:
            self.db.rollback()
            raise

    def record(self, findings: tuple[Finding, ...], at: datetime) -> None:
        when = timestamp(at)
        payload = json.dumps([asdict(item) for item in findings], separators=(",", ":"))
        warning = any(item.state != "OK" for item in findings)
        if self.db.in_transaction:
            raise RuntimeError("INTEGRITY_DATABASE_BUSY")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("INSERT INTO integrity_status VALUES(1,?,?) "
                            "ON CONFLICT(singleton) DO UPDATE SET at=excluded.at,findings=excluded.findings", (when, payload))
            if warning:
                self.db.execute("INSERT INTO integrity_outbox(at,immediate,findings) VALUES(?,?,?)",
                                (when, int(any(item.immediate for item in findings)), payload))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def deliver(self, sink) -> bool:
        """At-least-once fixed-data events. Slack failure cannot erase local faults.

        The injected #21 bridge handles immediate alerts and visible warnings;
        it must not treat an unconfigured optional Slack destination as failure.
        """
        rows = self.db.execute("SELECT id,at,immediate,findings FROM integrity_outbox WHERE delivered=0 ORDER BY id LIMIT 100").fetchall()
        for row in rows:
            try:
                sink(row["id"], datetime.fromisoformat(row["at"]), bool(row["immediate"]), json.loads(row["findings"]))
            except Exception:
                return False
            self.db.execute("UPDATE integrity_outbox SET delivered=1 WHERE id=?", (row["id"],))
        return True
