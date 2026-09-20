"""Detector-specific local quality measurements and fail-unknown decisions."""

from .contracts import (
    DetectorQualityPolicy, Execution, FrameIdentity, Metric, MetricRule,
    QualityContext, QualityDecision, QualityFinding, QualityReason, ResultSink,
    unavailable_reason,
)
from .gate import QualityGate
from .metrics import MeasurementUnavailable, measure, obstruction_fraction

__all__ = [
    "DetectorQualityPolicy", "Execution", "FrameIdentity", "Metric", "MetricRule",
    "QualityContext", "QualityDecision", "QualityFinding", "QualityReason", "QualityGate",
    "ResultSink", "unavailable_reason", "MeasurementUnavailable", "measure",
    "obstruction_fraction",
]
