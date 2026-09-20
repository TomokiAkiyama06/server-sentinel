"""CPU-only frame differencing; no model, dependency, download or identity."""

import math

from .contracts import (Detection, DetectorKind, GrayFrame, Observation,
                        Reason, positive_integer)


class MotionBaseline:
    """General image change only; not person detection or server movement.

    The two thresholds are explicitly supplied evaluation parameters, not
    deployment defaults. Stores only the previous sampled gray frame.
    """

    kind = DetectorKind.MOTION
    implementation = "server-sentinel-gray-difference"
    version = "1"

    def __init__(self, *, pixel_delta: int, changed_fraction: float) -> None:
        positive_integer(pixel_delta, "pixel_delta")
        if pixel_delta > 255:
            raise ValueError("pixel_delta must fit an eight-bit channel")
        if isinstance(changed_fraction, bool) or not isinstance(changed_fraction, (int, float)):
            raise ValueError("changed_fraction must be a finite fraction")
        if not math.isfinite(changed_fraction) or not 0 < changed_fraction <= 1:
            raise ValueError("changed_fraction must be in (0, 1]")
        self.pixel_delta = pixel_delta
        self.changed_fraction = changed_fraction
        self._previous: GrayFrame | None = None

    def reset(self) -> None:
        self._previous = None

    def evaluate(self, frame: GrayFrame) -> Detection:
        if frame.channels != 1:
            self.reset()
            return Detection(Observation.UNKNOWN, Reason.QUALITY)
        previous, self._previous = self._previous, frame
        if previous is None:
            return Detection(Observation.UNKNOWN, Reason.WARMUP)
        if (previous.source_id, previous.stream_id, previous.width, previous.height) != (
                frame.source_id, frame.stream_id, frame.width, frame.height):
            return Detection(Observation.UNKNOWN, Reason.DISCONTINUITY)
        if frame.sequence <= previous.sequence:
            self._previous = None
            return Detection(Observation.UNKNOWN, Reason.DISCONTINUITY)
        changed = sum(abs(a - b) >= self.pixel_delta
                      for a, b in zip(previous.pixels, frame.pixels))
        fraction = changed / len(frame.pixels)
        outcome = Observation.PRESENT if fraction >= self.changed_fraction else Observation.ABSENT
        return Detection(outcome, Reason.EVALUATED, fraction)


class UnavailablePersonDetector:
    """Honest placeholder while no separately approved weights are installed."""

    kind = DetectorKind.PERSON
    implementation = "unavailable-person-detector"
    version = "1"

    def reset(self) -> None:
        pass

    def evaluate(self, frame: GrayFrame) -> Detection:
        return Detection(Observation.UNKNOWN, Reason.MODEL_UNAVAILABLE)
