"""Local, calibration-bound server movement and camera-tamper primitives."""

from .contracts import (
    CameraTamperAnalyzer,
    CameraTamperPolicy,
    RoiCalibration,
    RoiMovementAnalyzer,
    RoiMovementPolicy,
    SpatialContext,
    SpatialDecision,
    SpatialKind,
    SpatialReason,
    SpatialState,
)

__all__ = [
    "CameraTamperAnalyzer", "CameraTamperPolicy", "RoiCalibration",
    "RoiMovementAnalyzer", "RoiMovementPolicy", "SpatialContext",
    "SpatialDecision", "SpatialKind", "SpatialReason", "SpatialState",
]
