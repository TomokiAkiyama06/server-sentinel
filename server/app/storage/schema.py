"""Ordered application schema; feature modules never import this catalog."""

from app.cameras.registry.schema import REGISTRY_MIGRATION
from app.cameras.uvc.schema import UVC_MIGRATION
from app.detection.roi.schema import roi_calibration_migration
from app.media.recording.schema import recording_migration
from app.storage.migrations import BUILTIN_MIGRATIONS


APPLICATION_MIGRATIONS = (
    *BUILTIN_MIGRATIONS, REGISTRY_MIGRATION, UVC_MIGRATION, recording_migration(4),
    roi_calibration_migration(5),
)
