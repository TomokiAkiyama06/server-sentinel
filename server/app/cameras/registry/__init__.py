"""Public in-process Camera Source registry contract; no HTTP routes."""

from .models import (
    CameraSource, CaptureNode, CaptureProfile, DetectionBinding, DetectionKind,
    HealthState, SourceType, ValidationError,
)
from .repository import (
    ActiveSourceLimitError, CameraRegistry, NotFoundError, RegistryError,
)

__all__ = [
    "ActiveSourceLimitError", "CameraRegistry", "CameraSource", "CaptureNode",
    "CaptureProfile", "DetectionBinding", "DetectionKind", "HealthState",
    "NotFoundError", "RegistryError", "SourceType", "ValidationError",
]
