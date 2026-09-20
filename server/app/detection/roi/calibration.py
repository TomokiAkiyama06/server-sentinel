"""Private calibration history and a default-denied Owner operation facade."""

from dataclasses import asdict
from datetime import datetime
import json
import sqlite3
from typing import Callable
from uuid import UUID

from app.cameras.registry.models import SourceType
from app.detection.foundation import GrayFrame
from .contracts import Calibration, Policy
from .detector import SceneDetector


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


def _decode(metadata, pixels):
    value = json.loads(metadata)
    policy = value["policy"]
    policy["global_quarter_turns"] = tuple(policy["global_quarter_turns"])
    policy["roi_quarter_turns"] = tuple(policy["roi_quarter_turns"])
    source_id = UUID(value["source_id"])
    reference = value["reference"]
    frame = GrayFrame(source_id, UUID(reference["stream_id"]), reference["sequence"],
                      reference["width"], reference["height"], pixels)
    calibration = Calibration(UUID(value["identifier"]), source_id, SourceType(value["source_type"]),
                              UUID(value["profile_id"]), value["version"], datetime.fromisoformat(value["created_at"]),
                              tuple(tuple(point) for point in value["polygon"]), frame, Policy(**policy))
    if calibration.reference_sha256 != reference["sha256"]:
        raise ValueError("calibration reference integrity failed")
    SceneDetector(calibration)
    return calibration


class CalibrationArchive:
    """Append-only versions in a caller-owned private deployment SQLite database.

    The caller supplies an already-open connection from the deployment's private
    database boundary. This does not choose paths, create directories or expose
    references through any API. Schema is local to this independently testable
    archive; Main runtime onboarding must register its migration explicitly.
    """

    def __init__(self, connection: sqlite3.Connection):
        if connection.in_transaction:
            raise ValueError("archive requires an idle database connection")
        self.connection = connection
        try:
            connection.execute("SELECT 1 FROM roi_calibration_history LIMIT 1")
        except sqlite3.Error:
            raise RuntimeError("calibration archive unavailable") from None

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
            connection.execute("INSERT INTO roi_calibration_history VALUES (?,?,?,?,?,?)", (
                str(calibration.source_id), str(calibration.profile_id), calibration.version,
                str(calibration.identifier), json.dumps(calibration_metadata(calibration), sort_keys=True),
                calibration.reference.pixels,
            ))
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise RuntimeError("calibration archive unavailable") from None
        except Exception:
            connection.rollback()
            raise

    def load(self, source_id: UUID, profile_id: UUID, version: int | None = None):
        query = "SELECT metadata,reference FROM roi_calibration_history WHERE source_id=? AND profile_id=?"
        parameters = [str(source_id), str(profile_id)]
        if version is not None:
            query += " AND version=?"
            parameters.append(version)
        query += " ORDER BY version DESC LIMIT 1"
        try:
            row = self.connection.execute(query, parameters).fetchone()
            return _decode(*row) if row is not None else None
        except Exception:
            raise RuntimeError("calibration archive unavailable") from None


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
        self.archive.append(calibration)
