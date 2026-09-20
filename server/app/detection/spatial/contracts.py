"""Bounded, local spatial-observation contracts for separately calibrated sources.

The analyzers retain one reference frame in process memory.  They do not
capture frames, persist calibration, publish events, identify people, or make
human-access decisions.  A caller supplies detector-quality and occlusion
evidence for the exact input frame; missing evidence fails to UNKNOWN.
"""

from dataclasses import dataclass
from enum import StrEnum
import math
from uuid import UUID

from app.detection.foundation import GrayFrame, Quality


class SpatialKind(StrEnum):
    SERVER_ROI = "server_roi"
    CAMERA_TAMPER = "camera_tamper"


class SpatialState(StrEnum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"


class SpatialReason(StrEnum):
    EVALUATED = "evaluated"
    WARMUP = "warmup"
    QUALITY_UNAVAILABLE = "quality_unavailable"
    OCCLUDED = "occluded"
    DISCONTINUITY = "stream_discontinuity"
    CONTEXT_MISMATCH = "context_mismatch"
    INSUFFICIENT_COVERAGE = "insufficient_reference_coverage"


def _finite_fraction(value, name: str, *, positive: bool = False) -> None:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be a finite fraction")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")


def _positive_int(value, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class RoiCalibration:
    """Normalized polygon plus an explicit version for exactly one source."""

    source_id: UUID
    version: int
    polygon: tuple[tuple[float, float], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, UUID):
            raise ValueError("calibration source must be a UUID")
        _positive_int(self.version, "calibration version")
        if type(self.polygon) is not tuple or len(self.polygon) < 3:
            raise ValueError("ROI needs at least three normalized vertices")
        points = []
        for point in self.polygon:
            if type(point) is not tuple or len(point) != 2:
                raise ValueError("ROI vertex is invalid")
            x, y = point
            _finite_fraction(x, "ROI coordinate")
            _finite_fraction(y, "ROI coordinate")
            points.append((x, y))
        if len(set(points)) != len(points):
            raise ValueError("ROI vertices must be distinct")
        area = abs(sum(
            points[index][0] * points[(index + 1) % len(points)][1]
            - points[(index + 1) % len(points)][0] * points[index][1]
            for index in range(len(points))
        )) / 2
        if area <= 0:
            raise ValueError("ROI polygon must enclose an area")


@dataclass(frozen=True)
class RoiMovementPolicy:
    """Explicit synthetic/deployment calibration; this module exports no defaults."""

    pixel_delta: int
    changed_fraction: float
    confirmation_frames: int
    maximum_pixels: int
    maximum_occlusion_fraction: float
    minimum_reference_coverage: float
    maximum_translation_pixels: int

    def __post_init__(self) -> None:
        _positive_int(self.pixel_delta, "pixel_delta")
        if self.pixel_delta > 255:
            raise ValueError("pixel_delta must fit an eight-bit channel")
        _finite_fraction(self.changed_fraction, "changed_fraction", positive=True)
        _positive_int(self.confirmation_frames, "confirmation_frames")
        if self.confirmation_frames < 2:
            raise ValueError("movement requires temporal confirmation")
        _positive_int(self.maximum_pixels, "maximum_pixels")
        _finite_fraction(self.maximum_occlusion_fraction, "maximum_occlusion_fraction")
        _finite_fraction(self.minimum_reference_coverage, "minimum_reference_coverage", positive=True)
        _positive_int(self.maximum_translation_pixels, "maximum_translation_pixels")


@dataclass(frozen=True)
class CameraTamperPolicy:
    """Explicit persistent scene-change/occlusion thresholds for one source."""

    pixel_delta: int
    changed_fraction: float
    confirmation_frames: int
    maximum_pixels: int
    occlusion_fraction: float

    def __post_init__(self) -> None:
        _positive_int(self.pixel_delta, "pixel_delta")
        if self.pixel_delta > 255:
            raise ValueError("pixel_delta must fit an eight-bit channel")
        _finite_fraction(self.changed_fraction, "changed_fraction", positive=True)
        _positive_int(self.confirmation_frames, "confirmation_frames")
        if self.confirmation_frames < 2:
            raise ValueError("tamper requires temporal confirmation")
        _positive_int(self.maximum_pixels, "maximum_pixels")
        _finite_fraction(self.occlusion_fraction, "occlusion_fraction", positive=True)


@dataclass(frozen=True)
class SpatialContext:
    """Trusted, frame-bound quality and scene-transform evidence.

    translation describes current-frame displacement relative to the reference.
    It is optional because a source may not provide a global-transform estimate;
    the analyzer never fabricates one.  Occlusion is required for a trustworthy
    server-ROI conclusion, while tamper can use it as a direct signal.
    """

    source_id: UUID
    stream_id: UUID
    sequence: int
    quality: Quality
    occlusion_fraction: float | None
    translation_x: int | None = None
    translation_y: int | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.source_id, UUID) or not isinstance(self.stream_id, UUID)
                or type(self.sequence) is not int or self.sequence < 0
                or not isinstance(self.quality, Quality)):
            raise ValueError("invalid spatial frame context")
        if self.occlusion_fraction is not None:
            _finite_fraction(self.occlusion_fraction, "occlusion_fraction")
        translation = (self.translation_x, self.translation_y)
        if any(value is not None and type(value) is not int for value in translation):
            raise ValueError("translation must use integer pixels")
        if (self.translation_x is None) != (self.translation_y is None):
            raise ValueError("translation axes must be supplied together")


@dataclass(frozen=True)
class SpatialDecision:
    kind: SpatialKind
    source_id: UUID
    stream_id: UUID
    sequence: int
    calibration_version: int
    state: SpatialState
    reason: SpatialReason
    changed_fraction: float | None
    confirmation_count: int

    def __post_init__(self) -> None:
        if (not isinstance(self.kind, SpatialKind) or not isinstance(self.source_id, UUID)
                or not isinstance(self.stream_id, UUID) or type(self.sequence) is not int
                or self.sequence < 0 or type(self.calibration_version) is not int
                or self.calibration_version <= 0 or not isinstance(self.state, SpatialState)
                or not isinstance(self.reason, SpatialReason)
                or type(self.confirmation_count) is not int or self.confirmation_count < 0):
            raise ValueError("invalid spatial decision")
        if self.changed_fraction is not None:
            _finite_fraction(self.changed_fraction, "changed_fraction")


def _inside_polygon(x: float, y: float, polygon: tuple[tuple[float, float], ...]) -> bool:
    inside = False
    previous = polygon[-1]
    for current in polygon:
        x1, y1 = previous
        x2, y2 = current
        if (y1 > y) != (y2 > y):
            boundary_x = (x2 - x1) * (y - y1) / (y2 - y1) + x1
            if x < boundary_x:
                inside = not inside
        previous = current
    return inside


class _BaseAnalyzer:
    def __init__(self, kind: SpatialKind, calibration: RoiCalibration,
                 reference: GrayFrame, policy) -> None:
        if not isinstance(calibration, RoiCalibration) or not isinstance(reference, GrayFrame):
            raise ValueError("invalid spatial calibration reference")
        if reference.source_id != calibration.source_id:
            raise ValueError("reference must belong to calibration source")
        if reference.width * reference.height > policy.maximum_pixels:
            raise ValueError("reference exceeds configured pixel budget")
        self.kind = kind
        self.calibration = calibration
        self._reference = reference
        self._policy = policy
        self._stream_id: UUID | None = None
        self._sequence = -1
        self._confirmations = 0

    def reset(self) -> None:
        self._stream_id = None
        self._sequence = -1
        self._confirmations = 0

    def _decision(self, frame: GrayFrame, state: SpatialState, reason: SpatialReason,
                  changed: float | None = None) -> SpatialDecision:
        return SpatialDecision(self.kind, frame.source_id, frame.stream_id, frame.sequence,
                               self.calibration.version, state, reason, changed,
                               self._confirmations)

    def _validate(self, frame: GrayFrame, context: SpatialContext) -> SpatialDecision | None:
        if (frame.source_id != self.calibration.source_id or frame.channels != 1
                or frame.width * frame.height > self._policy.maximum_pixels
                or (frame.source_id, frame.stream_id, frame.sequence) != (
                    context.source_id, context.stream_id, context.sequence)):
            self.reset()
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.CONTEXT_MISMATCH)
        if (frame.width, frame.height) != (self._reference.width, self._reference.height):
            self.reset()
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.DISCONTINUITY)
        if context.quality is not Quality.SUFFICIENT:
            self._confirmations = 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.QUALITY_UNAVAILABLE)
        if self._stream_id != frame.stream_id:
            self._stream_id, self._sequence, self._confirmations = frame.stream_id, frame.sequence, 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.WARMUP)
        if frame.sequence != self._sequence + 1:
            self._sequence, self._confirmations = frame.sequence, 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.DISCONTINUITY)
        self._sequence = frame.sequence
        return None


class RoiMovementAnalyzer(_BaseAnalyzer):
    """Compare one source's explicit ROI to its reference after optional translation.

    A temporary/missing occlusion estimate never becomes either a movement or a
    no-movement conclusion.  Translation compensation is caller supplied and
    bounded; it does not claim to estimate camera pose from arbitrary pixels.
    """

    def __init__(self, calibration: RoiCalibration, reference: GrayFrame,
                 policy: RoiMovementPolicy) -> None:
        if not isinstance(policy, RoiMovementPolicy):
            raise ValueError("invalid ROI movement policy")
        super().__init__(SpatialKind.SERVER_ROI, calibration, reference, policy)
        self._roi = tuple(
            (x, y) for y in range(reference.height) for x in range(reference.width)
            if _inside_polygon((x + .5) / reference.width, (y + .5) / reference.height,
                               calibration.polygon)
        )
        if not self._roi:
            raise ValueError("ROI does not cover a reference pixel")

    def assess(self, frame: GrayFrame, context: SpatialContext) -> SpatialDecision:
        invalid = self._validate(frame, context)
        if invalid is not None:
            return invalid
        if context.occlusion_fraction is None:
            self._confirmations = 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.QUALITY_UNAVAILABLE)
        if context.occlusion_fraction > self._policy.maximum_occlusion_fraction:
            self._confirmations = 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.OCCLUDED)
        translation_x = context.translation_x or 0
        translation_y = context.translation_y or 0
        if (abs(translation_x) > self._policy.maximum_translation_pixels
                or abs(translation_y) > self._policy.maximum_translation_pixels):
            self._confirmations = 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.INSUFFICIENT_COVERAGE)
        samples = [
            (reference_y * frame.width + reference_x,
             (reference_y + translation_y) * frame.width + reference_x + translation_x)
            for reference_x, reference_y in self._roi
            if 0 <= reference_x + translation_x < frame.width
            and 0 <= reference_y + translation_y < frame.height
        ]
        if len(samples) / len(self._roi) < self._policy.minimum_reference_coverage:
            self._confirmations = 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.INSUFFICIENT_COVERAGE)
        changed = sum(abs(self._reference.pixels[before] - frame.pixels[after])
                      >= self._policy.pixel_delta for before, after in samples) / len(samples)
        if changed < self._policy.changed_fraction:
            self._confirmations = 0
            return self._decision(frame, SpatialState.NOT_DETECTED, SpatialReason.EVALUATED, changed)
        self._confirmations += 1
        if self._confirmations < self._policy.confirmation_frames:
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.WARMUP, changed)
        return self._decision(frame, SpatialState.DETECTED, SpatialReason.EVALUATED, changed)


class CameraTamperAnalyzer(_BaseAnalyzer):
    """Detect persistent full-scene change or persistent trusted lens occlusion."""

    def __init__(self, calibration: RoiCalibration, reference: GrayFrame,
                 policy: CameraTamperPolicy) -> None:
        if not isinstance(policy, CameraTamperPolicy):
            raise ValueError("invalid camera tamper policy")
        super().__init__(SpatialKind.CAMERA_TAMPER, calibration, reference, policy)

    def assess(self, frame: GrayFrame, context: SpatialContext) -> SpatialDecision:
        invalid = self._validate(frame, context)
        if invalid is not None:
            return invalid
        if context.occlusion_fraction is None:
            self._confirmations = 0
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.QUALITY_UNAVAILABLE)
        changed = sum(abs(before - after) >= self._policy.pixel_delta
                      for before, after in zip(self._reference.pixels, frame.pixels)) / len(frame.pixels)
        candidate = (changed >= self._policy.changed_fraction
                     or context.occlusion_fraction >= self._policy.occlusion_fraction)
        if not candidate:
            self._confirmations = 0
            return self._decision(frame, SpatialState.NOT_DETECTED, SpatialReason.EVALUATED, changed)
        self._confirmations += 1
        if self._confirmations < self._policy.confirmation_frames:
            return self._decision(frame, SpatialState.UNKNOWN, SpatialReason.WARMUP, changed)
        return self._decision(frame, SpatialState.DETECTED, SpatialReason.EVALUATED, changed)
