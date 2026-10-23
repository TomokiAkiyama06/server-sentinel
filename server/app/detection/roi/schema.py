"""ROI calibration DDL; the application aggregator assigns its final slot.

The history is metadata only. Decoded monitoring frames are never persisted
here, nor any value computed from them (since #205 no reference digest
either): only identities, reference geometry, polygon, policy and reader of a
calibration. A pre-#205 row may still carry a reference digest: it is ignored
and removed at the next start (``calibration.scrub_legacy_reference_digests``).
"""

from app.storage.migrations import Migration


ROI_CALIBRATION_STATEMENTS = (
    "CREATE TABLE roi_calibration_history ("
    "source_id TEXT NOT NULL, profile_id TEXT NOT NULL, "
    "version INTEGER NOT NULL CHECK (version > 0), identifier TEXT NOT NULL, "
    "metadata TEXT NOT NULL, "
    "PRIMARY KEY (source_id, profile_id, version))",
)


def roi_calibration_migration(version: int) -> Migration:
    return Migration(version, "roi_calibration_history", ROI_CALIBRATION_STATEMENTS)
