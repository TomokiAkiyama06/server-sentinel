"""Private approved device evidence and durable ambiguity latch in SQLite."""

from contextlib import nullcontext
from dataclasses import asdict, dataclass, field
import json
import sqlite3
from uuid import uuid4

from .identity import DeviceEvidence, same_physical_camera


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


class ApprovalConflictError(ValueError):
    """The camera is approved for another enabled source; fixed safe message."""


# Active Owner approvals of other enabled local UVC sources. A row that
# requires approval (manual latch or never approved) holds no camera.
_HELD_APPROVALS = (
    "SELECT a.evidence, a.serial_ambiguous FROM uvc_approvals AS a "
    "JOIN camera_sources AS s ON s.id = a.source_id "
    "WHERE a.requires_approval = 0 AND s.enabled = 1 "
    "AND s.source_type = 'local_uvc' AND a.source_id != ?"
)


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

    ``reservation`` is the deployment storage admission: the session marker
    writes this store commits itself are admitted by the Main storage policy
    through commit. A refused admission raises the policy's bounded error and
    nothing is written; the already durable marker then conservatively
    requires Owner reapproval. The Owner approval itself is written on the
    audited transaction, which holds its own admission.
    """

    def __init__(self, database, *, reservation=None):
        if reservation is not None and not callable(reservation):
            raise ApprovalStorageError("UVC approval storage admission is invalid")
        self.database = database
        self.reservation = reservation

    def _admission(self):
        return self.reservation() if self.reservation is not None else nullcontext()

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

    @staticmethod
    def _held_on(connection, source_id):
        rows = connection.execute(_HELD_APPROVALS, (str(source_id),)).fetchall()
        return tuple(ApprovalStore._state((row[0], 0, None, row[1], 0)) for row in rows)

    @staticmethod
    def _conflicts(evidence, serial_ambiguous, held):
        """True when either side's own comparison names the same camera.

        Each source checks for conflicts with its own recorded comparison
        mode, so a holder approved before a same-serial twin appeared still
        compares by serial. Checking both directions keeps the approval-time
        refusal consistent with what every holder's runtime check reports.
        """
        return any(
            same_physical_camera(evidence, other.approved, serial_ambiguous=serial_ambiguous)
            or same_physical_camera(other.approved, evidence,
                                    serial_ambiguous=other.serial_ambiguous)
            for other in held
        )

    def approved_elsewhere(self, source_id, evidence, *, serial_ambiguous=False):
        """True when another enabled source holds an active approval for this camera.

        ``serial_ambiguous`` compares exact live-instance evidence, for a
        camera whose serial is shared by another concurrently connected one.
        """
        connection = None
        try:
            connection = self.database.connect()
            return self._conflicts(evidence, serial_ambiguous,
                                   self._held_on(connection, source_id))
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            raise ApprovalStorageError("UVC approval state is unavailable") from None
        finally:
            if connection is not None:
                connection.close()

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
            held = ApprovalStore._held_on(connection, source_id)
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            raise ApprovalStorageError("UVC approval state could not be saved") from None
        # Checked again inside the write transaction, so two concurrent
        # approvals can never both bind one physical camera.
        if ApprovalStore._conflicts(approved, serial_ambiguous, held):
            raise ApprovalConflictError("camera approval is unavailable")
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
        with self._admission():
            return self._start_session(source_id, initial_approved)

    def _start_session(self, source_id, initial_approved):
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
        with self._admission():
            self._save(source_id, approved, requires_approval, session_token=session_token,
                       serial_ambiguous=serial_ambiguous, release=release)

    def _save(self, source_id, approved, requires_approval, *, session_token, serial_ambiguous,
              release):
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
