"""Ordered application schema; feature modules never import this catalog."""

from app.audit.schema import audit_migration
from app.cameras.registry.schema import REGISTRY_MIGRATION
from app.cameras.uvc.schema import UVC_MIGRATION, uvc_explicit_binding_migration
from app.cameras.remote_agent.schema import PAIRING_MIGRATION
from app.detection.roi.schema import roi_calibration_migration
from app.integrity.store import integrity_migration
from app.media.health.artifacts import recording_health_migration
from app.media.recording.schema import recording_migration
from app.presence.schema import presence_migration
from app.storage.migrations import BUILTIN_MIGRATIONS


APPLICATION_MIGRATIONS = (
    *BUILTIN_MIGRATIONS,
    REGISTRY_MIGRATION,
    UVC_MIGRATION,
    recording_migration(4),
    recording_health_migration(5),
    integrity_migration(6),
    roi_calibration_migration(7),
    # Version 8 is already published by the presence timeline on main.
    presence_migration(8),
    audit_migration(9),
    uvc_explicit_binding_migration(10),
    PAIRING_MIGRATION,
)
