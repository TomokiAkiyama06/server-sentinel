"""Private approved device evidence and durable ambiguity latch in SQLite."""

from dataclasses import asdict, dataclass, field
import json
import sqlite3

from .identity import DeviceEvidence


# Included by the append-only application migration after the registry schema.
SCHEMA = (
    "CREATE TABLE uvc_approvals (source_id TEXT PRIMARY KEY "
    "REFERENCES camera_sources(id), evidence TEXT NOT NULL, "
    "requires_approval INTEGER NOT NULL CHECK (requires_approval IN (0, 1)))"
)


class ApprovalStorageError(RuntimeError):
    """A fixed safe error, without physical identifiers or database contents."""


@dataclass(frozen=True)
class ApprovalState:
    approved: DeviceEvidence = field(repr=False)
    requires_approval: bool


class ApprovalStore:
    """Uses the deployment's private Database connection factory.

    A new controller restores the latch, never a live capture binding. Storage
    errors abort the operation; they must never be replaced by an empty store.
    """

    def __init__(self, database):
        self.database = database

    def load(self, source_id):
        connection = None
        try:
            connection = self.database.connect()
            row = connection.execute(
                "SELECT evidence, requires_approval FROM uvc_approvals WHERE source_id = ?",
                (str(source_id),),
            ).fetchone()
            if row is None:
                return None
            evidence = json.loads(row[0])
            evidence["by_id"] = tuple(evidence["by_id"])
            evidence["formats"] = tuple(evidence["formats"])
            if evidence.get("instance_token") is not None:
                evidence["instance_token"] = tuple(evidence["instance_token"])
            return ApprovalState(DeviceEvidence(**evidence), bool(row[1]))
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            raise ApprovalStorageError("UVC approval state is unavailable") from None
        finally:
            if connection is not None:
                connection.close()

    def save(self, source_id, approved, requires_approval):
        evidence = json.dumps(asdict(approved), allow_nan=False, separators=(",", ":"))
        connection = None
        try:
            connection = self.database.connect()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO uvc_approvals VALUES (?, ?, ?) ON CONFLICT(source_id) "
                "DO UPDATE SET evidence = excluded.evidence, requires_approval = excluded.requires_approval",
                (str(source_id), evidence, int(requires_approval)),
            )
            connection.commit()
        except sqlite3.Error:
            if connection is not None:
                connection.rollback()
            raise ApprovalStorageError("UVC approval state could not be saved") from None
        finally:
            if connection is not None:
                connection.close()
