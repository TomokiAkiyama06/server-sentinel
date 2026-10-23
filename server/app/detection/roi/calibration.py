"""Private calibration history and a default-denied Owner operation facade.

The history stores no decoded monitoring media and nothing derived from it
(Owner decision 2026-10-22, Issue #205): a calibration reference frame stays in
process memory only, and the history keeps non-frame provenance (identities,
version, time, polygon, policy, reference geometry and the luma reader). No
digest, histogram, thumbnail or statistic of the frame is persisted. Detection
resumes only by binding the in-memory ``Calibration`` that produced a stored
record (``CalibrationRecord.bind``); a stored record alone cannot reproduce or
re-admit a reference.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import json
import sqlite3
from typing import Callable
from uuid import UUID

from app.cameras.registry.models import SourceType, timestamp
from app.detection.foundation.contracts import positive_integer
from .contracts import Calibration, Policy, valid_reader
from .detector import SceneDetector
from .geometry import validate_polygon


COLUMNS = ("source_id", "profile_id", "version", "identifier", "metadata")


def calibration_metadata(calibration):
    reference = calibration.reference
    reader = {} if calibration.reader is None else {"reader": calibration.reader}
    return {
        **reader,
        "identifier": str(calibration.identifier), "source_id": str(calibration.source_id),
        "source_type": calibration.source_type.value, "profile_id": str(calibration.profile_id),
        "version": calibration.version, "created_at": calibration.created_at.isoformat(),
        "polygon": calibration.polygon, "policy": asdict(calibration.policy),
        "reference": {"stream_id": str(reference.stream_id), "sequence": reference.sequence,
                      "width": reference.width, "height": reference.height},
    }


@dataclass(frozen=True)
class CalibrationRecord:
    """Persistable calibration provenance that cannot reconstruct a scene.

    It intentionally has no pixel field and no value computed from pixels
    (no digest, histogram or statistic): restored history never becomes a
    retention-free still-image store of a monitored room or of whoever was
    visible while the Owner calibrated it, nor a fingerprint of that scene.
    A record written before #205 may carry a ``reference.sha256``; it is
    ignored when read and removed by ``scrub_legacy_reference_digests`` at
    the next start.
    """

    identifier: UUID
    source_id: UUID
    source_type: SourceType
    profile_id: UUID
    version: int
    created_at: datetime
    polygon: tuple[tuple[int, int], ...]
    reference_stream_id: UUID
    reference_sequence: int
    reference_width: int
    reference_height: int
    policy: Policy
    # The luma reader of the reference (``contracts.READER``); ``None`` in a
    # record written before readers were recorded.
    reader: str | None = None

    def __post_init__(self):
        identities = (self.identifier, self.source_id, self.profile_id, self.reference_stream_id)
        if any(not isinstance(value, UUID) for value in identities):
            raise ValueError("calibration identities must be UUIDs")
        if not valid_reader(self.reader):
            raise ValueError("invalid calibration reader")
        if not isinstance(self.source_type, SourceType) or not isinstance(self.policy, Policy):
            raise ValueError("invalid source type or calibration policy")
        positive_integer(self.version, "calibration version")
        positive_integer(self.reference_width, "reference width")
        positive_integer(self.reference_height, "reference height")
        if type(self.reference_sequence) is not int or self.reference_sequence < 0:
            raise ValueError("reference sequence must be a nonnegative integer")
        timestamp(self.created_at)
        if self.reference_width * self.reference_height > self.policy.maximum_pixels:
            raise ValueError("calibration exceeds pixel budget")
        if type(self.polygon) is not tuple or not 3 <= len(self.polygon) <= 32:
            raise ValueError("invalid polygon vertex count")
        for point in self.polygon:
            if (type(point) is not tuple or len(point) != 2 or any(type(v) is not int for v in point)
                    or not 0 <= point[0] < self.reference_width
                    or not 0 <= point[1] < self.reference_height):
                raise ValueError("polygon lies outside reference")
        validate_polygon(self.polygon)

    def bind(self, calibration: Calibration) -> Calibration:
        """Bind the in-memory calibration that produced this stored record.

        The archive cannot return a reference image and keeps nothing derived
        from one, so the integrity binding between the stored version and its
        reference lives in process memory: only a ``Calibration`` object whose
        whole non-frame provenance (identity, source, profile, version, time,
        polygon, policy, reader, reference stream, sample and geometry) is this
        record is accepted. A bare frame, or a calibration of another version
        or identity, is refused instead of silently recalibrating; a frame
        read from the camera becomes a reference only through a new, audited
        calibration version.
        """
        if not isinstance(calibration, Calibration):
            raise ValueError("calibration reference must be an in-memory calibration")
        if provenance(calibration) != self:
            raise ValueError("calibration reference integrity failed")
        SceneDetector(calibration)
        return calibration


def provenance(calibration: Calibration) -> CalibrationRecord:
    """The persistable, frame-free provenance of an in-memory calibration."""
    reference = calibration.reference
    return CalibrationRecord(calibration.identifier, calibration.source_id,
                             calibration.source_type, calibration.profile_id,
                             calibration.version, calibration.created_at,
                             calibration.polygon, reference.stream_id, reference.sequence,
                             reference.width, reference.height, calibration.policy,
                             calibration.reader)


def _decode(metadata) -> CalibrationRecord:
    value = json.loads(metadata)
    policy = dict(value["policy"])
    policy["global_quarter_turns"] = tuple(policy["global_quarter_turns"])
    policy["roi_quarter_turns"] = tuple(policy["roi_quarter_turns"])
    # A pre-#205 record's ``reference.sha256`` is ignored, never re-used.
    reference = value["reference"]
    return CalibrationRecord(UUID(value["identifier"]), UUID(value["source_id"]),
                             SourceType(value["source_type"]), UUID(value["profile_id"]),
                             value["version"], datetime.fromisoformat(value["created_at"]),
                             tuple(tuple(point) for point in value["polygon"]),
                             UUID(reference["stream_id"]), reference["sequence"],
                             reference["width"], reference["height"],
                             Policy(**policy), value.get("reader"))


def scrub_legacy_reference_digests(connection: sqlite3.Connection) -> int:
    """Remove ``reference.sha256`` from every stored version (#205, Codex P1).

    A version written before the Owner decision 2026-10-22 may carry the
    SHA-256 of its reference frame, image-derived data that must not stay on
    disk. Runs inside the caller's write transaction (storage admission and
    commit are the caller's). When a row carries the key, the whole table is
    rebuilt with ``secure_delete`` on, so the old cells, the freed pages and
    any stale copy a legacy write left in this table's free space are
    zeroed inside the database file. This is not a forensic erasure: copies
    outside the file (rollback-journal blocks the filesystem freed, SSD
    remapping, snapshots, backups) and a page of this table an earlier build
    freed to another table are beyond it. Each scrubbed
    row is re-serialized exactly as ``calibration_metadata()`` writes a new
    one, so its frame-free provenance, and the lifecycle inventory's keyed
    digest of it (``app.lifecycle_inventory.sources``), stay identical.
    A row that is not a JSON object with a ``reference`` object is left for
    the history and inventory checks to report. Returns the number of rows
    scrubbed; idempotent.
    """
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        raise ValueError("calibration history requires an open transaction")
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                          "AND name='roi_calibration_history'").fetchone() is None:
        return 0
    rows = connection.execute(
        "SELECT source_id, profile_id, version, identifier, metadata FROM roi_calibration_history "
        "ORDER BY source_id, profile_id, version").fetchall()
    rewritten = [(*row[:4], without_reference_digest(row[4]) or row[4]) for row in rows]
    scrubbed = sum(1 for old, new in zip(rows, rewritten) if old[4] != new[4])
    if not scrubbed:
        return 0
    # Rebuild the whole table, not only the scrubbed rows: a legacy build
    # may have written with `secure_delete` off, leaving stale copies of a
    # digest in the free space of this table's pages, which rewriting a row
    # does not reach. With `secure_delete` on, deleting every row zeroes
    # the cells and the freed pages before the rows are inserted again.
    connection.execute("PRAGMA secure_delete = ON")
    connection.execute("DELETE FROM roi_calibration_history")
    connection.executemany("INSERT INTO roi_calibration_history VALUES (?,?,?,?,?)", rewritten)
    return scrubbed


def without_reference_digest(metadata) -> str | None:
    """`metadata` re-serialized without ``reference.sha256``, or None.

    None when it is not a JSON object whose ``reference`` is an object (a
    corrupt row the history checks report as such). A row without the key
    comes back as ``calibration_metadata()`` would serialize it.
    """
    try:
        value = json.loads(metadata)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("reference"), dict):
        return None
    value["reference"].pop("sha256", None)
    return json.dumps(value, sort_keys=True)


def decode_history_row(row) -> CalibrationRecord:
    """Read one stored ``COLUMNS`` row back exactly as ``load()`` does.

    The lifecycle inventory (#132) checks every stored version through this
    same function, so a row it accepts is one ``load()`` can return.
    """
    try:
        record = _decode(row[4])
    except Exception:
        # A stored record that cannot be decoded is corrupt history, not an
        # unavailable database. Reporting it as unavailable would hide an
        # integrity problem behind a transient-looking failure; the stored
        # content stays out of the message either way.
        raise ValueError("calibration history record is unreadable") from None
    # The decoded provenance must be the row that was looked up. Logical
    # corruption or a manual recovery can leave another calibration's
    # metadata under these keys, and the embedded identities would then
    # validate against themselves, binding a detector to a source or
    # profile the caller never asked for.
    if (str(record.source_id), str(record.profile_id), record.version,
            str(record.identifier)) != tuple(row[:4]):
        raise ValueError("calibration history record does not match its key")
    return record


def _insert(connection, calibration: Calibration) -> None:
    latest = connection.execute(
        "SELECT version, identifier FROM roi_calibration_history WHERE source_id=? AND profile_id=? ORDER BY version DESC LIMIT 1",
        (str(calibration.source_id), str(calibration.profile_id)),
    ).fetchone()
    expected = latest[0] + 1 if latest else 1
    if calibration.version != expected or latest and latest[1] != str(calibration.identifier):
        raise ValueError("calibration version or identity conflicts with history")
    connection.execute("INSERT INTO roi_calibration_history VALUES (?,?,?,?,?)", (
        str(calibration.source_id), str(calibration.profile_id), calibration.version,
        str(calibration.identifier), json.dumps(calibration_metadata(calibration), sort_keys=True),
    ))


def append_on(connection: sqlite3.Connection, calibration: Calibration) -> CalibrationRecord:
    """Append one version inside a caller-owned write transaction.

    For an audited mutation (Issue #205): the calibration's provenance and its
    audit record commit or roll back together. The caller owns ``BEGIN
    IMMEDIATE``, the storage admission and the commit; the same version and
    identity rules as ``CalibrationArchive.append`` apply, and nothing but
    provenance is written (no pixel, crop, frame or value derived from one).
    """
    if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
        raise ValueError("calibration history requires an open transaction")
    SceneDetector(calibration)
    try:
        cursor = connection.execute("SELECT * FROM roi_calibration_history LIMIT 0")
    except sqlite3.Error:
        raise RuntimeError("calibration archive unavailable") from None
    if tuple(column[0] for column in cursor.description) != COLUMNS:
        raise RuntimeError("calibration archive unavailable")
    try:
        _insert(connection, calibration)
    except sqlite3.Error:
        raise RuntimeError("calibration archive unavailable") from None
    return provenance(calibration)


class CalibrationArchive:
    """Append-only versions in a caller-owned private deployment SQLite database.

    The caller supplies an already-open connection from the deployment's private
    database boundary. This does not choose paths, create directories or expose
    references through any API. It persists calibration provenance only: no
    frame bytes, crop, other decoded media or value computed from a frame
    (digest, histogram, statistic) enters this table, so the history
    cannot outlive recording retention as hidden image storage. Schema is local
    to this independently testable archive; Main runtime onboarding must
    register its migration explicitly.
    """

    def __init__(self, connection: sqlite3.Connection):
        if connection.in_transaction:
            raise ValueError("archive requires an idle database connection")
        self.connection = connection
        try:
            cursor = connection.execute("SELECT * FROM roi_calibration_history LIMIT 0")
        except sqlite3.Error:
            raise RuntimeError("calibration archive unavailable") from None
        if tuple(column[0] for column in cursor.description) != COLUMNS:
            raise RuntimeError("calibration archive unavailable")

    def append(self, calibration: Calibration):
        SceneDetector(calibration)
        connection = self.connection
        if connection.in_transaction:
            raise ValueError("archive requires an idle database connection")
        try:
            connection.execute("BEGIN IMMEDIATE")
            _insert(connection, calibration)
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise RuntimeError("calibration archive unavailable") from None
        except Exception:
            connection.rollback()
            raise
        return provenance(calibration)

    def load(self, source_id: UUID, profile_id: UUID, version: int | None = None):
        """Return stored provenance only; a reference image is never returned."""
        query = ("SELECT source_id, profile_id, version, identifier, metadata "
                 "FROM roi_calibration_history WHERE source_id=? AND profile_id=?")
        parameters = [str(source_id), str(profile_id)]
        if version is not None:
            query += " AND version=?"
            parameters.append(version)
        query += " ORDER BY version DESC LIMIT 1"
        try:
            row = self.connection.execute(query, parameters).fetchone()
        except sqlite3.Error:
            raise RuntimeError("calibration archive unavailable") from None
        if row is None:
            return None
        return decode_history_row(row)


class OwnerCalibrationOperations:
    """No HTTP/authentication policy: injected trusted Owner authorization only."""

    def __init__(self, archive: CalibrationArchive, *, owner_authorized: Callable[[], bool] | None = None):
        self.archive, self.owner_authorized = archive, owner_authorized

    def save(self, calibration: Calibration):
        try:
            allowed = self.owner_authorized is not None and self.owner_authorized() is True
        except Exception:
            allowed = False
        if not allowed:
            raise PermissionError("operation unavailable")
        return self.archive.append(calibration)
