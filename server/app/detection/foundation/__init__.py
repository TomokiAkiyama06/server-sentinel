"""Local, transient inference primitives; never start capture or network I/O."""

from .contracts import (Detection, Detector, DetectorKind, GrayFrame, Health,
                        Observation, Quality, Reason, RgbFrame)
from .motion import MotionBaseline, UnavailablePersonDetector
from .scheduler import InferenceScheduler, SourcePolicy, SourceSnapshot
from .isolation import (DetectorWorkerFailure, IsolatedDetector, WorkerLimits,
                        WorkerSpec, WorkerStatus)
from .feed import FeedResult, FeedStatus, InferenceFeed

__all__ = [
    "Detection", "Detector", "DetectorKind", "GrayFrame", "Health", "Observation",
    "Quality", "Reason", "RgbFrame", "MotionBaseline", "UnavailablePersonDetector",
    "InferenceScheduler", "SourcePolicy", "SourceSnapshot",
    "DetectorWorkerFailure", "IsolatedDetector", "WorkerLimits", "WorkerSpec",
    "WorkerStatus", "FeedResult", "FeedStatus", "InferenceFeed",
]
