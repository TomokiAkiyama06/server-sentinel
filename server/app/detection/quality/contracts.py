"""Explicit per-detector calibration and frame-bound quality evidence."""

from dataclasses import dataclass
from enum import Enum
import math
from uuid import UUID

from app.detection.foundation import GrayFrame, Quality


class Metric(str, Enum):
    LUMINANCE = "mean_luminance"
    SHARPNESS = "gradient_energy"
    SATURATION = "clipped_fraction"
    WIDTH = "width"
    HEIGHT = "height"
    TARGET_WIDTH = "target_width"
    TARGET_HEIGHT = "target_height"
    OCCLUSION = "occlusion_fraction"
    CONFIDENCE = "detector_confidence"


class Execution(str, Enum):
    READY = "ready"
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"
    STOPPED = "stopped"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class QualityReason(str, Enum):
    BELOW_SUFFICIENT = "below_sufficient"
    ABOVE_SUFFICIENT = "above_sufficient"
    BELOW_USABLE = "below_usable"
    ABOVE_USABLE = "above_usable"
    METRIC_UNAVAILABLE = "metric_unavailable"
    MEASUREMENT_FAILED = "quality_measurement_failed"
    CONTEXT_MISMATCH = "context_mismatch"
    SOURCE_MISMATCH = "source_mismatch"
    RESOURCE_LIMIT = "quality_resource_limit"
    EXECUTION_UNAVAILABLE = "detector_execution_unavailable"
    DISCONTINUITY = "frame_discontinuity"
    RECOVERING = "quality_recovery_pending"


def finite(value) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


@dataclass(frozen=True)
class MetricRule:
    metric: Metric
    minimum_usable: float
    minimum_sufficient: float
    maximum_sufficient: float
    maximum_usable: float

    def __post_init__(self):
        values = (self.minimum_usable, self.minimum_sufficient,
                  self.maximum_sufficient, self.maximum_usable)
        if (not isinstance(self.metric, Metric) or not all(finite(item) for item in values)
                or not all(left <= right for left, right in zip(values, values[1:]))):
            raise ValueError("invalid calibrated metric range")
        lower, upper = ((0, 1) if self.metric in (
            Metric.LUMINANCE, Metric.SHARPNESS, Metric.SATURATION, Metric.OCCLUSION, Metric.CONFIDENCE,
        ) else (0, 2**31 - 1))
        if not lower <= self.minimum_usable <= self.maximum_usable <= upper:
            raise ValueError("metric range exceeds its measurement domain")


@dataclass(frozen=True)
class DetectorQualityPolicy:
    """Every rule is a prerequisite for both positive and negative conclusions.

    No production thresholds, target-size assumptions or recovery count are
    supplied by this module. Policies are separate for each detector/profile.
    """

    detector: str
    version: int
    rules: tuple[MetricRule, ...]
    recovery_frames: int
    maximum_pixels: int

    def __post_init__(self):
        if self.detector not in (
            "motion", "person", "server_roi", "camera_tamper", "entrance_crossing",
            "owner_verification", "image_quality", "presence",
        ):
            raise ValueError("unknown detector quality policy")
        if type(self.version) is not int or self.version <= 0:
            raise ValueError("quality policy requires a positive version")
        if type(self.recovery_frames) is not int or not 2 <= self.recovery_frames <= 2**31 - 1:
            raise ValueError("quality recovery requires at least two consecutive frames")
        if type(self.maximum_pixels) is not int or not 1 <= self.maximum_pixels <= 2**31 - 1:
            raise ValueError("quality pixel budget must be a bounded positive integer")
        if (type(self.rules) is not tuple or not self.rules or len(self.rules) > len(Metric)
                or any(not isinstance(rule, MetricRule) for rule in self.rules)
                or len({rule.metric for rule in self.rules}) != len(self.rules)):
            raise ValueError("quality policy requires distinct calibrated metric rules")


@dataclass(frozen=True)
class FrameIdentity:
    source_id: UUID
    stream_id: UUID
    sequence: int

    def __post_init__(self):
        if (not isinstance(self.source_id, UUID) or not isinstance(self.stream_id, UUID)
                or type(self.sequence) is not int or self.sequence < 0):
            raise ValueError("invalid quality frame identity")

    @classmethod
    def from_frame(cls, frame: GrayFrame):
        return cls(frame.source_id, frame.stream_id, frame.sequence)


@dataclass(frozen=True)
class QualityContext:
    """Trusted adapter observations/calibration, attributed to this exact frame.

    Target size for a person-negative prerequisite is the calibrated smallest
    relevant target, never a box synthesized from an empty detection result.
    None means unavailable evidence, never zero occlusion or adequate size.
    """

    frame: FrameIdentity
    target_width: float | None = None
    target_height: float | None = None
    occlusion_fraction: float | None = None
    detector_confidence: float | None = None

    def __post_init__(self):
        if not isinstance(self.frame, FrameIdentity):
            raise ValueError("quality context requires frame identity")
        for value in (self.target_width, self.target_height):
            if value is not None and (not finite(value) or not 0 < value <= 2**31 - 1):
                raise ValueError("invalid target size")
        for value in (self.occlusion_fraction, self.detector_confidence):
            if value is not None and (not finite(value) or not 0 <= value <= 1):
                raise ValueError("invalid quality context fraction")


@dataclass(frozen=True)
class QualityFinding:
    reason: QualityReason
    metric: Metric | None = None


@dataclass(frozen=True)
class QualityDecision:
    frame: FrameIdentity
    detector: str
    policy_version: int
    quality: Quality
    metrics: tuple[tuple[Metric, float | int | None], ...]
    findings: tuple[QualityFinding, ...]
    recovery_count: int

    @property
    def allows_conclusion(self) -> bool:
        return self.quality is Quality.SUFFICIENT

    def metric_values(self) -> dict[str, float | int | None]:
        """Detached, displayable numbers only; never pixels or detector secrets."""
        return {metric.value: value for metric, value in self.metrics}
