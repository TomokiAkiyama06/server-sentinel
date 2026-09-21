"""Camera registry records; no device access, human routes, or auth claims."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import json
import math
from uuid import UUID


class ValidationError(ValueError):
    """Invalid camera configuration; messages never include submitted values."""


class SourceType(StrEnum):
    LOCAL_UVC = "local_uvc"
    REMOTE_AGENT = "remote_agent"


class SourceHealthState(StrEnum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"


class NodeHealthState(StrEnum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    REVOKED = "revoked"


class DetectionKind(StrEnum):
    MOTION = "motion"
    PERSON = "person"
    SERVER_ROI = "server_roi"
    CAMERA_TAMPER = "camera_tamper"
    ENTRANCE_CROSSING = "entrance_crossing"
    OWNER_VERIFICATION = "owner_verification"
    IMAGE_QUALITY = "image_quality"


def text_value(value: str, field_name: str, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 for char in value)):
        raise ValidationError(f"invalid {field_name}")
    return value


def positive_integer(value: int, field_name: str) -> int:
    if type(value) is not int or not 1 <= value <= 2**31 - 1:
        raise ValidationError(f"invalid {field_name}")
    return value


def finite_number(value, field_name: str) -> None:
    try:
        valid = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise ValidationError(f"invalid {field_name}")


def timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def json_object(value: dict) -> dict:
    """Validate and detach a bounded JSON object, including nested keys."""
    visited = 0

    def check(item, depth=0):
        nonlocal visited
        visited += 1
        if depth > 32 or visited > 8192:
            raise ValidationError("configuration exceeds structural limit")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValidationError("configuration keys must be strings")
            for child in item.values():
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif item is not None and type(item) not in (str, bool, int, float):
            raise ValidationError("configuration must contain JSON values")

    if not isinstance(value, dict):
        raise ValidationError("configuration must be an object")
    try:
        check(value)
        encoded = json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode()) > 65536:
            raise ValidationError("configuration exceeds size limit")
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError):
        raise ValidationError("invalid JSON configuration") from None


@dataclass(frozen=True)
class CaptureProfile:
    """Video-only request/result; unset fields have no invented hardware default."""

    width: int | None = None
    height: int | None = None
    fps: float | None = None
    pixel_format: str | None = None
    codec: str | None = None
    bitrate_bps: int | None = None

    def __post_init__(self):
        for name in ("width", "height", "bitrate_bps"):
            value = getattr(self, name)
            if value is not None:
                positive_integer(value, name)
        if self.fps is not None:
            finite_number(self.fps, "fps")
            if self.fps <= 0:
                raise ValidationError("invalid fps")
        for name in ("pixel_format", "codec"):
            value = getattr(self, name)
            if value is not None:
                text_value(value, name, 64)


@dataclass(frozen=True)
class DetectionBinding:
    """Multiple named bindings, including multiple regions for a detector."""

    binding_id: UUID
    kind: DetectionKind
    version: int
    enabled: bool
    thresholds: dict[str, float] = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.binding_id, UUID):
            raise ValidationError("invalid binding identity")
        if not isinstance(self.kind, DetectionKind):
            raise ValidationError("invalid detection kind")
        positive_integer(self.version, "binding version")
        if type(self.enabled) is not bool:
            raise ValidationError("invalid binding enabled state")
        thresholds = json_object(self.thresholds)
        for key, value in thresholds.items():
            text_value(key, "threshold name")
            finite_number(value, "detection threshold")
        object.__setattr__(self, "thresholds", thresholds)
        object.__setattr__(self, "config", json_object(self.config))


@dataclass(frozen=True)
class CaptureNode:
    id: UUID
    name: str
    health_state: NodeHealthState
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class CameraSource:
    id: UUID
    capture_node_id: UUID | None
    source_type: SourceType
    name: str
    role_label: str | None
    enabled: bool
    capabilities: dict
    desired_capture_profile: CaptureProfile | None
    negotiated_capture_profile: CaptureProfile | None
    health_state: SourceHealthState
    image_quality_state: str
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
    detection_bindings: tuple[DetectionBinding, ...]
