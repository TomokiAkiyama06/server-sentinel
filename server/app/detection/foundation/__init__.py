"""Local, transient inference primitives; never start capture or network I/O."""

from .contracts import (Detection, Detector, DetectorKind, GrayFrame, Health,
                        Observation, Quality, Reason, RgbFrame)
from .motion import MotionBaseline, UnavailablePersonDetector
from .scheduler import InferenceScheduler, SourcePolicy, SourceSnapshot

__all__ = [
    "Detection", "Detector", "DetectorKind", "GrayFrame", "Health", "Observation",
    "Quality", "Reason", "RgbFrame", "MotionBaseline", "UnavailablePersonDetector",
    "InferenceScheduler", "SourcePolicy", "SourceSnapshot",
]
