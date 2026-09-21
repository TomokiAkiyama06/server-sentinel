"""Private calibration history and a default-denied Owner operation facade.

The history stores no decoded monitoring media. A calibration reference frame
stays transient: only its irreversible digest, geometry and policy are
persisted, and an Owner-supplied frame must be re-bound through
``CalibrationRecord.rehydrate`` before detection can resume.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
import json
import re
import sqlite3
from typing import Callable
from uuid import UUID

from app.cameras.registry.models import SourceType, timestamp
from app.detection.foundation import GrayFrame
from app.detection.foundation.contracts import positive_integer
from .contracts import Calibration, Policy
from .detector import SceneDetector
from .geometry import validate_polygon


DIGEST = re.compile(r"[0-9a-f]{64}")
COLUMNS = ("source_id", "profile_id", "version", "identifier", "metadata")


def calibration_metadata(calibration):
    reference = calibration.reference
    return {
        "identifier": str(calibration.identifier), "source_id": str(calibration.source_id),
        "source_type": calibration.source_type.value, "profile_id": str(calibration.profile_id),
        "version": calibration.version, "created_at": calibration.created_at.isoformat(),
        "polygon": calibration.polygon, "policy": asdict(calibration.policy),
        "reference": {"stream_id": str(reference.stream_id), "sequence": reference.sequence,
                      "width": reference.width, "height": reference.height,
                      "sha256": calibration.reference_sha256},
    }


@dataclass(frozen=True)
class CalibrationRecord:
    """Persistable calibration provenance that cannot reconstruct a scene.

    It intentionally has no pixel field: the archive keeps the reference
    digest, not the reference image, so restored history never becomes a
    retention-free still-image store of a monitored room or of whoever was
    visible while the Owner calibrated it.
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
    reference_sha256: str
    policy: Policy

    def __post_init__(self):
        identities = (self.identifier, self.source_id, self.profile_id, self.reference_stream_id)
        if any(not isinstance(value, UUID) for value in identities):
            raise ValueError("calibration identities must be UUIDs")
        if not isinstance(self.source_type, SourceType) or not isinstance(self.policy, Policy):
            raise ValueError("invalid source type or calibration policy")
        positive_integer(self.version, "calibration version")
        positive_integer(self.reference_width, "reference width")
        positive_integer(self.reference_height, "reference height")
        if type(self.reference_sequence) is not int or self.reference_sequence < 0:
            raise ValueError("reference sequence must be a nonnegative integer")
        timestamp(self.created_at)
        if type(self.reference_sha256) is not str or not DIGEST.fullmatch(self.reference_sha256):
            raise ValueError("calibration reference digest is malformed")
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

    def rehydrate(self, reference: GrayFrame) -> Calibration:
        """Bind a transient Owner-supplied frame to this stored provenance.

        The archive cannot return a reference image, so the caller supplies the
        frame again from the deployment's own Owner-controlled media boundary.
        A frame from another source, stream, sample or geometry, or one whose
        digest differs, is refused instead of silently recalibrating.
        """
        if not isinstance(reference, GrayFrame) or reference.channels != 1:
            raise ValueError("calibration requires a grayscale reference")
        if (reference.source_id != self.source_id
                or reference.stream_id != self.reference_stream_id
                or reference.sequence != self.reference_sequence
                or (reference.width, reference.height) != (self.reference_width, self.reference_height)):
            raise ValueError("reference frame does not match calibration history")
        calibration = Calibration(self.identifier, self.source_id, self.source_type,
                                  self.profile_id, self.version, self.created_at,
                                  self.polygon, reference, self.policy)
        if calibration.reference_sha256 != self.reference_sha256:
            raise ValueError("calibration reference integrity failed")
        SceneDetector(calibration)
        return calibration


def _record(calibration: Calibration) -> CalibrationRecord:
    reference = calibration.reference
    return CalibrationRecord(calibration.identifier, calibration.source_id,
                             calibration.source_type, calibration.profile_id,
                             calibration.version, calibration.created_at,
                             calibration.polygon, reference.stream_id, reference.sequence,
                             reference.width, reference.height,
                             calibration.reference_sha256, calibration.policy)


def _decode(metadata) -> CalibrationRecord:
    value = json.loads(metadata)
    policy = dict(value["policy"])
    policy["global_quarter_turns"] = tuple(policy["global_quarter_turns"])
    policy["roi_quarter_turns"] = tuple(policy["roi_quarter_turns"])
    reference = value["reference"]
    return CalibrationRecord(UUID(value["identifier"]), UUID(value["source_id"]),
                             SourceType(value["source_type"]), UUID(value["profile_id"]),
                             value["version"], datetime.fromisoformat(value["created_at"]),
                             tuple(tuple(point) for point in value["polygon"]),
                             UUID(reference["stream_id"]), reference["sequence"],
                             reference["width"], reference["height"],
                             reference["sha256"], Policy(**policy))


class CalibrationArchive:
    """Append-only versions in a caller-owned private deployment SQLite database.

    The caller supplies an already-open connection from the deployment's private
    database boundary. This does not choose paths, create directories or expose
    references through any API. It persists calibration provenance only: no
    frame bytes, crop or other decoded media enters this table, so the history
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
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise RuntimeError("calibration archive unavailable") from None
        except Exception:
            connection.rollback()
            raise
        return _record(calibration)

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
