"""Public in-process Camera Source registry contract; no HTTP routes."""

from .models import (
    CameraSource, CaptureNode, CaptureProfile, DetectionBinding, DetectionKind,
    NodeHealthState, SourceHealthState, SourceType, ValidationError,
)
from .repository import (
    ActiveSourceLimitError, CameraRegistry, NotFoundError, RegistryError,
    UnauditedWriteError,
)

__all__ = [
    "ActiveSourceLimitError", "CameraRegistry", "CameraSource", "CaptureNode",
    "CaptureProfile", "DetectionBinding", "DetectionKind", "NodeHealthState", "SourceHealthState",
    "NotFoundError", "RegistryError", "SourceType", "UnauditedWriteError",
    "ValidationError",
]
