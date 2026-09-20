"""Append-only application migration for private ROI calibration history."""

from app.storage.migrations import Migration


ROI_CALIBRATION_MIGRATION = Migration(3, "roi_calibration_history", (
    "CREATE TABLE roi_calibration_history ("
    "source_id TEXT NOT NULL, profile_id TEXT NOT NULL, "
    "version INTEGER NOT NULL CHECK (version > 0), identifier TEXT NOT NULL, "
    "metadata TEXT NOT NULL, reference BLOB NOT NULL, "
    "PRIMARY KEY (source_id, profile_id, version))",
))
