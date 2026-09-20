"""Detector-specific local quality measurements and fail-unknown decisions."""

from .contracts import (
    DetectorQualityPolicy, Execution, FrameIdentity, Metric, MetricRule,
    QualityContext, QualityDecision, QualityFinding, QualityReason,
)
from .gate import QualityGate
from .metrics import MeasurementUnavailable, measure, obstruction_fraction

__all__ = [
    "DetectorQualityPolicy", "Execution", "FrameIdentity", "Metric", "MetricRule",
    "QualityContext", "QualityDecision", "QualityFinding", "QualityReason", "QualityGate",
    "MeasurementUnavailable", "measure", "obstruction_fraction",
]
