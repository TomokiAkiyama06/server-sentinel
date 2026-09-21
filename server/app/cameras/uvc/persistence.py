"""Private approved device evidence and durable ambiguity latch in SQLite."""

from dataclasses import asdict, dataclass, field
import json
import sqlite3
from uuid import uuid4

from .identity import DeviceEvidence


# Included by the append-only application migration after the registry schema.
SCHEMA = (
    "CREATE TABLE uvc_approvals (source_id TEXT PRIMARY KEY "
    "REFERENCES camera_sources(id), evidence TEXT NOT NULL, "
    "requires_approval INTEGER NOT NULL CHECK (requires_approval IN (0, 1)), "
    "session_token TEXT, serial_ambiguous INTEGER NOT NULL CHECK (serial_ambiguous IN (0, 1)))"
)

# A live explicit binding is in-memory only: it proves which physical device an
# Owner selected during one session. This column keeps that invariant visible
# and enforced in the schema, so every durable row is written and read as 0 and
# a restart can never restore a binding from storage.
EXPLICIT_BINDING_SCHEMA = (
    "ALTER TABLE uvc_approvals ADD COLUMN explicit_binding INTEGER NOT NULL DEFAULT 0 "
    "CHECK (explicit_binding IN (0, 1))"
)


class ApprovalStorageError(RuntimeError):
    """A fixed safe error, without physical identifiers or database contents."""


@dataclass(frozen=True)
class ApprovalState:
    approved: DeviceEvidence = field(repr=False)
    requires_approval: bool
    session_token: str | None = field(default=None, repr=False)
    serial_ambiguous: bool = False
    explicit_binding: bool = False


class ApprovalStore:
    """Uses the deployment's private Database connection factory.

    A new controller restores the latch, never a live capture binding. Storage
    errors abort the operation; they must never be replaced by an empty store.
    """

    def __init__(self, database):
        self.database = database

    @staticmethod
    def _state(row):
        if row is None:
            return None
        evidence = json.loads(row[0])
        evidence["by_id"] = tuple(evidence["by_id"])
        evidence["formats"] = tuple(evidence["formats"])
        if evidence.get("instance_token") is not None:
            evidence["instance_token"] = tuple(evidence["instance_token"])
        return ApprovalState(
            DeviceEvidence(**evidence), bool(row[1]), row[2], bool(row[3]), bool(row[4]),
        )

    def load(self, source_id):
        connection = None
        try:
            connection = self.database.connect()
            row = connection.execute(
                "SELECT evidence, requires_approval, session_token, serial_ambiguous, "
                "explicit_binding "
                "FROM uvc_approvals WHERE source_id = ?",
                (str(source_id),),
            ).fetchone()
            return self._state(row)
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            raise ApprovalStorageError("UVC approval state is unavailable") from None
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def approve_on(connection, source_id, approved, *, serial_ambiguous):
        """Persist Owner selection inside a caller-owned audit transaction."""
        if not connection.in_transaction:
            raise ApprovalStorageError("UVC approval transaction is unavailable")
        try:
            evidence = json.dumps(asdict(approved), allow_nan=False, separators=(",", ":"))
            row = connection.execute(
                "SELECT evidence, requires_approval, session_token, serial_ambiguous, "
                "explicit_binding FROM uvc_approvals WHERE source_id=?", (str(source_id),)
            ).fetchone()
            prior = ApprovalStore._state(row)
            preserve_latch = (prior is not None and prior.serial_ambiguous
                              and prior.approved.strong_key == approved.strong_key)
            connection.execute(
                "INSERT INTO uvc_approvals "
                "(source_id,evidence,requires_approval,session_token,serial_ambiguous,explicit_binding) "
                "VALUES (?, ?, 0, NULL, ?, 0) "
                "ON CONFLICT(source_id) DO UPDATE SET evidence=excluded.evidence, "
                "requires_approval=0, session_token=NULL, "
                "serial_ambiguous=excluded.serial_ambiguous, explicit_binding=0",
                (str(source_id), evidence, int(serial_ambiguous or preserve_latch)),
            )
        except (sqlite3.Error, ValueError, TypeError):
            raise ApprovalStorageError("UVC approval state could not be saved") from None

    def start_session(self, source_id, initial_approved):
        """Arm recovery before any discovery/reconciliation decision is trusted.

        If a later ambiguity write cannot persist, the already durable active
        marker makes the next controller require approval. A new session also
        fences old controllers from clearing its state with a stale shutdown.
        """
        connection = None
        try:
            connection = self.database.connect()
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT evidence, requires_approval, session_token, serial_ambiguous, "
                "explicit_binding "
                "FROM uvc_approvals WHERE source_id = ?",
                (str(source_id),),
            ).fetchone()
            prior = self._state(row)
            approved = initial_approved if prior is None else prior.approved
            # Initial evidence is merely an Owner selection candidate. Only a
            # successful approve() write may clear its approval-required flag.
            required = True if prior is None else prior.requires_approval or prior.session_token is not None
            ambiguous = False if prior is None else prior.serial_ambiguous
            token = str(uuid4())
            connection.execute(
                "INSERT INTO uvc_approvals "
                "(source_id,evidence,requires_approval,session_token,serial_ambiguous,explicit_binding) "
                "VALUES (?, ?, ?, ?, ?, 0) ON CONFLICT(source_id) "
                "DO UPDATE SET evidence = excluded.evidence, requires_approval = excluded.requires_approval, "
                "session_token = excluded.session_token, serial_ambiguous = excluded.serial_ambiguous, "
                "explicit_binding = 0",
                (str(source_id), json.dumps(asdict(approved), allow_nan=False), int(required), token, int(ambiguous)),
            )
            connection.commit()
            return ApprovalState(approved, required, token, ambiguous, False)
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            if connection is not None:
                connection.rollback()
            raise ApprovalStorageError("UVC approval session could not start") from None
        finally:
            if connection is not None:
                connection.close()

    def save(self, source_id, approved, requires_approval, *, session_token, serial_ambiguous, release=False):
        if session_token is None:
            raise ApprovalStorageError("UVC approval session is not active")
        evidence = json.dumps(asdict(approved), allow_nan=False, separators=(",", ":"))
        connection = None
        try:
            connection = self.database.connect()
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE uvc_approvals SET evidence = ?, requires_approval = ?, session_token = ?, serial_ambiguous = ? "
                "WHERE source_id = ? AND session_token = ?",
                (evidence, int(requires_approval), None if release else session_token,
                 int(serial_ambiguous), str(source_id), session_token),
            )
            if changed.rowcount != 1:
                connection.rollback()
                raise ApprovalStorageError("UVC approval session was superseded")
            connection.commit()
        except sqlite3.Error:
            if connection is not None:
                connection.rollback()
            raise ApprovalStorageError("UVC approval state could not be saved") from None
        finally:
            if connection is not None:
                connection.close()
