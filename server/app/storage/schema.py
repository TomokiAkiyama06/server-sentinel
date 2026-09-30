"""Ordered application schema; feature modules never import this catalog."""

from app.audit.schema import audit_migration
from app.auth.schema import access_migration
from app.cameras.remote_agent.schema import PAIRING_MIGRATION, pairing_renewal_migration
from app.cameras.registry.schema import REGISTRY_MIGRATION
from app.cameras.uvc.schema import UVC_MIGRATION, uvc_explicit_binding_migration
from app.detection.roi.schema import roi_calibration_migration
from app.integrity.store import integrity_migration
from app.media.health.artifacts import recording_health_migration
from app.media.recording.schema import recording_migration
from app.monitoring.store import monitoring_migration
from app.notifications.schedule import notification_migration
from app.presence.schema import presence_migration
from app.storage.migrations import BUILTIN_MIGRATIONS
from app.setup_wizard.schema import wizard_state_migration
from app.storage.retention import storage_audit_migration

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
    access_migration(12),
    wizard_state_migration(13),
    # Issues #21/#23 runtime wiring: the storage state-transition audit, the
    # persisted daily-summary claim and the durable local fault/notification
    # state that the monitoring runtime owns.
    storage_audit_migration(14),
    notification_migration(15),
    monitoring_migration(16),
    # Issue #13 capture-node certificate renewal. PR #97 (and PR #83) also
    # claim 17; whichever merges later renumbers, since the runner requires a
    # contiguous sequence.
    pairing_renewal_migration(17),
)
