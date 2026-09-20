"""Detector-neutral contracts; pixels are transient and excluded from repr."""

from dataclasses import dataclass, field
from enum import Enum
import math
from typing import ClassVar, Protocol
from uuid import UUID


class DetectorKind(str, Enum):
    MOTION = "motion"
    PERSON = "person"


class Observation(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class Health(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class Quality(str, Enum):
    SUFFICIENT = "sufficient"
    DEGRADED = "degraded"
    INSUFFICIENT = "insufficient"
    UNKNOWN = "unknown"


class Reason(str, Enum):
    EVALUATED = "evaluated"
    WARMUP = "warmup"
    QUALITY = "quality_unavailable"
    MODEL_UNAVAILABLE = "model_unavailable"
    DROPPED = "inference_dropped"
    STALE = "inference_stale"
    OVER_BUDGET = "inference_over_budget"
    FAILURE = "detector_failure"
    DISCONTINUITY = "stream_discontinuity"
    RESOURCE_LIMIT = "frame_resource_limit"
    CLOCK = "local_clock_regression"
    NOT_STARTED = "not_started"


def positive_integer(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class GrayFrame:
    source_id: UUID
    stream_id: UUID
    sequence: int
    width: int
    height: int
    pixels: bytes = field(repr=False)
    channels: ClassVar[int] = 1

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, UUID) or not isinstance(self.stream_id, UUID):
            raise ValueError("source and stream identifiers must be UUIDs")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("sequence must be a nonnegative integer")
        positive_integer(self.width, "width")
        positive_integer(self.height, "height")
        if type(self.pixels) is not bytes or len(self.pixels) != self.width * self.height * self.channels:
            raise ValueError("frame must contain exactly the immutable bytes required by its channels")


@dataclass(frozen=True)
class RgbFrame(GrayFrame):
    channels: ClassVar[int] = 3


@dataclass(frozen=True)
class Detection:
    observation: Observation
    reason: Reason
    # Detector-specific measurement, never a probability or proof of guilt.
    measurement: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.observation, Observation) or not isinstance(self.reason, Reason):
            raise ValueError("invalid detector result")
        if self.observation is Observation.UNKNOWN and self.reason is Reason.EVALUATED:
            raise ValueError("unknown must carry an unavailable reason")
        if self.observation is not Observation.UNKNOWN and self.reason is not Reason.EVALUATED:
            raise ValueError("conclusions require an evaluated result")
        if self.measurement is not None:
            if isinstance(self.measurement, bool) or not isinstance(self.measurement, (int, float)):
                raise ValueError("measurement must be a finite fraction")
            if not math.isfinite(self.measurement) or not 0 <= self.measurement <= 1:
                raise ValueError("measurement must be a finite fraction")


class Detector(Protocol):
    """One local instance per source; the worker owns reset/evaluate calls.

    Implementations require separate code/weights/dependency review before
    registration. This Python interface is not a sandbox for untrusted plugins.
    """

    kind: DetectorKind
    implementation: str
    version: str

    def reset(self) -> None:
        ...

    def evaluate(self, frame: GrayFrame) -> Detection:
        ...
