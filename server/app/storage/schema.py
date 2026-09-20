"""Ordered application schema; feature modules never import this catalog."""

from app.cameras.registry.schema import REGISTRY_MIGRATION
from app.cameras.uvc.schema import UVC_MIGRATION
from app.integrity.store import integrity_migration
from app.media.health.artifacts import recording_health_migration
from app.media.recording.schema import recording_migration
from app.storage.migrations import BUILTIN_MIGRATIONS


APPLICATION_MIGRATIONS = (
    *BUILTIN_MIGRATIONS,
    REGISTRY_MIGRATION,
    UVC_MIGRATION,
    recording_migration(4),
    recording_health_migration(5),
    integrity_migration(6),
)
