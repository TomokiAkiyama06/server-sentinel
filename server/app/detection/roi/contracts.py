"""Neutral calibrated scene observations, independent of presence decisions."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import hashlib
import math
from uuid import UUID

from app.cameras.registry.models import SourceType, timestamp
from app.detection.foundation import GrayFrame, Observation, Quality
from app.detection.foundation.contracts import positive_integer


class CriticalKind(StrEnum):
    SERVER_MOVEMENT = "server_movement"
    CAMERA_TAMPER = "camera_tamper"


@dataclass(frozen=True)
class Transform:
    dx: int = 0
    dy: int = 0
    quarter_turns: int = 0

    @property
    def rotated(self) -> int:
        return min(self.quarter_turns % 4, (-self.quarter_turns) % 4)


@dataclass(frozen=True)
class Policy:
    global_search_pixels: int
    roi_search_pixels: int
    global_quarter_turns: tuple[int, ...]
    roi_quarter_turns: tuple[int, ...]
    maximum_match_error: float
    minimum_match_margin: float
    minimum_coverage: float
    minimum_background_variance: float
    minimum_roi_variance: float
    movement_pixels: int
    camera_shift_pixels: int
    dark_pixel_ceiling: int
    camera_dark_fraction: float
    confirmation_frames: int
    confirmation_ns: int
    maximum_gap_ns: int
    loss_correlation_ns: int
    maximum_pixels: int
    maximum_comparisons: int

    def __post_init__(self):
        for name in ("movement_pixels", "camera_shift_pixels", "confirmation_frames",
                     "confirmation_ns", "maximum_gap_ns", "loss_correlation_ns",
                     "maximum_pixels", "maximum_comparisons"):
            positive_integer(getattr(self, name), name)
        if self.confirmation_frames < 2:
            raise ValueError("temporal confirmation requires multiple frames")
        for name in ("global_search_pixels", "roi_search_pixels"):
            if type(getattr(self, name)) is not int or not 0 <= getattr(self, name) <= 32:
                raise ValueError("invalid bounded transform search")
        for angles in (self.global_quarter_turns, self.roi_quarter_turns):
            if (type(angles) is not tuple or not angles or len(set(angles)) != len(angles)
                    or 0 not in angles or any(type(v) is not int or v not in (0, 1, 2, 3) for v in angles)):
                raise ValueError("quarter-turn candidates must be unique and include identity")
        for name in ("maximum_match_error", "minimum_match_margin", "minimum_coverage",
                     "minimum_background_variance", "minimum_roi_variance", "camera_dark_fraction"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 1:
                raise ValueError("invalid finite policy fraction")
        if type(self.dark_pixel_ceiling) is not int or not 0 <= self.dark_pixel_ceiling < 255:
            raise ValueError("invalid dark-pixel threshold")


@dataclass(frozen=True)
class Calibration:
    identifier: UUID
    source_id: UUID
    source_type: SourceType
    profile_id: UUID
    version: int
    created_at: datetime
    polygon: tuple[tuple[int, int], ...]
    reference: GrayFrame = field(repr=False)
    policy: Policy

    def __post_init__(self):
        if any(not isinstance(v, UUID) for v in (self.identifier, self.source_id, self.profile_id)):
            raise ValueError("calibration identities must be UUIDs")
        if not isinstance(self.source_type, SourceType) or not isinstance(self.policy, Policy):
            raise ValueError("invalid source type or calibration policy")
        positive_integer(self.version, "calibration version")
        timestamp(self.created_at)
        if not isinstance(self.reference, GrayFrame) or self.reference.channels != 1:
            raise ValueError("calibration requires a grayscale reference")
        if self.reference.source_id != self.source_id:
            raise ValueError("reference source does not match calibration")
        if self.reference.width * self.reference.height > self.policy.maximum_pixels:
            raise ValueError("calibration exceeds pixel budget")
        if type(self.polygon) is not tuple or not 3 <= len(self.polygon) <= 32:
            raise ValueError("invalid polygon vertex count")
        for point in self.polygon:
            if (type(point) is not tuple or len(point) != 2 or any(type(v) is not int for v in point)
                    or not 0 <= point[0] < self.reference.width or not 0 <= point[1] < self.reference.height):
                raise ValueError("polygon lies outside reference")
        # Geometry validation, support and budget checks are done by SceneDetector.

    @property
    def reference_sha256(self):
        return hashlib.sha256(self.reference.pixels).hexdigest()


@dataclass(frozen=True)
class CriticalObservation:
    identifier: UUID
    kind: CriticalKind
    source_id: UUID
    source_type: SourceType
    stream_id: UUID
    sequence: int | None
    observed_at: datetime
    monotonic_ns: int
    calibration_id: UUID
    calibration_version: int
    calibration_created_at: datetime
    reference_sha256: str
    confidence: float
    quality: Quality
    reason: str
    confirmed: bool = True


@dataclass(frozen=True)
class SceneObservation:
    source_id: UUID
    stream_id: UUID
    sequence: int | None
    observed_at: datetime
    monotonic_ns: int
    calibration_id: UUID
    calibration_version: int
    calibration_created_at: datetime
    reference_sha256: str
    movement: Observation
    movement_quality: Quality
    tamper: Observation
    tamper_quality: Quality
    movement_reason: str
    tamper_reason: str
    movement_confidence: float | None
    tamper_confidence: float | None
    global_transform: Transform | None
    relative_transform: Transform | None
    critical: tuple[CriticalObservation, ...] = ()
