"""Ordered application schema; feature modules never import this catalog."""

from app.cameras.registry.schema import REGISTRY_MIGRATION
from app.detection.roi.schema import ROI_CALIBRATION_MIGRATION
from app.storage.migrations import BUILTIN_MIGRATIONS


APPLICATION_MIGRATIONS = (*BUILTIN_MIGRATIONS, REGISTRY_MIGRATION, ROI_CALIBRATION_MIGRATION)
