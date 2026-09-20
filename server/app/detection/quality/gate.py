"""Per-source/profile quality recovery; no capture, recording or I/O control."""

import threading
from uuid import UUID

from app.detection.foundation import Detection, GrayFrame, Observation, Quality, Reason
from .contracts import (
    DetectorQualityPolicy, Execution, FrameIdentity, QualityContext, QualityDecision,
    QualityFinding, QualityReason,
)
from .metrics import MeasurementUnavailable, measure


class QualityGate:
    """One gate per source and detector/profile, evaluated on an inference worker.

    Poor/missing evidence takes effect immediately. Only consecutive, in-order
    good frames in the same stream and geometry can recover a gate. Decisions
    contain measurements/identities, and retain no frame or pixel buffer.
    """

    def __init__(self, source_id: UUID, policy: DetectorQualityPolicy):
        if not isinstance(source_id, UUID) or not isinstance(policy, DetectorQualityPolicy):
            raise ValueError("invalid quality gate registration")
        self._source_id = source_id
        self._policy = policy
        self._stream = None
        self._sequence = -1
        self._shape = None
        self._good = 0
        self._lock = threading.Lock()
        self._latest = None

    @property
    def source_id(self) -> UUID:
        return self._source_id

    @property
    def policy(self) -> DetectorQualityPolicy:
        return self._policy

    def _decision(self, frame, quality, findings=(), metrics=()):
        return QualityDecision(FrameIdentity.from_frame(frame), self.policy.detector,
                               self.policy.version, quality, metrics, tuple(findings), self._good)

    def assess(self, frame: GrayFrame, *, execution: Execution,
               context: QualityContext | None = None) -> QualityDecision:
        if (not isinstance(frame, GrayFrame) or not isinstance(execution, Execution)
                or (context is not None and not isinstance(context, QualityContext))):
            raise ValueError("invalid quality assessment input")
        with self._lock:
            self._latest = self._assess(frame, execution, context)
            return self._latest

    def _assess(self, frame, execution, context):
        if frame.source_id != self.source_id:
            self._good = 0
            return self._decision(frame, Quality.UNKNOWN, [QualityFinding(QualityReason.SOURCE_MISMATCH)])
        identity = FrameIdentity.from_frame(frame)
        if context is not None and context.frame != identity:
            self._good = 0
            return self._decision(frame, Quality.UNKNOWN, [QualityFinding(QualityReason.CONTEXT_MISMATCH)])
        if self._stream != frame.stream_id:
            self._stream, self._sequence, self._good = frame.stream_id, -1, 0
        if frame.sequence <= self._sequence:
            self._good = 0
            return self._decision(frame, Quality.UNKNOWN, [QualityFinding(QualityReason.DISCONTINUITY)])
        shape = (frame.width, frame.height, frame.channels)
        if frame.sequence != self._sequence + 1 or shape != self._shape:
            self._good = 0
        self._shape, self._sequence = shape, frame.sequence
        if execution not in (Execution.READY, Execution.SUCCEEDED):
            self._good = 0
            return self._decision(frame, Quality.UNKNOWN, [QualityFinding(QualityReason.EXECUTION_UNAVAILABLE)])
        try:
            metrics = measure(frame, maximum_pixels=self.policy.maximum_pixels, context=context)
        except MeasurementUnavailable as exc:
            self._good = 0
            return self._decision(frame, Quality.UNKNOWN, [QualityFinding(exc.reason)])
        except Exception:
            self._good = 0
            return self._decision(frame, Quality.UNKNOWN, [QualityFinding(QualityReason.MEASUREMENT_FAILED)])
        values = dict(metrics)
        findings = []
        quality = Quality.SUFFICIENT
        for rule in self.policy.rules:
            value = values[rule.metric]
            if value is None:
                quality = Quality.UNKNOWN
                findings.append(QualityFinding(QualityReason.METRIC_UNAVAILABLE, rule.metric))
            elif value < rule.minimum_usable or value > rule.maximum_usable:
                if quality is not Quality.UNKNOWN:
                    quality = Quality.INSUFFICIENT
                reason = (QualityReason.BELOW_USABLE if value < rule.minimum_usable
                          else QualityReason.ABOVE_USABLE)
                findings.append(QualityFinding(reason, rule.metric))
            elif value < rule.minimum_sufficient or value > rule.maximum_sufficient:
                if quality is Quality.SUFFICIENT:
                    quality = Quality.DEGRADED
                reason = (QualityReason.BELOW_SUFFICIENT if value < rule.minimum_sufficient
                          else QualityReason.ABOVE_SUFFICIENT)
                findings.append(QualityFinding(reason, rule.metric))
        if quality is Quality.SUFFICIENT:
            self._good = min(self._good + 1, self.policy.recovery_frames)
            if self._good < self.policy.recovery_frames:
                quality = Quality.DEGRADED
                findings.append(QualityFinding(QualityReason.RECOVERING))
        else:
            self._good = 0
        return self._decision(frame, quality, findings, metrics)

    def invalidate(self, *, execution: Execution) -> None:
        """Invalidate on worker stop/failure even when no new frame arrives."""
        if not isinstance(execution, Execution) or execution in (Execution.READY, Execution.SUCCEEDED):
            raise ValueError("quality invalidation requires unavailable execution")
        with self._lock:
            self._good = 0
            self._latest = None

    def guard_result(self, decision: QualityDecision, result: Detection | None, *, execution: Execution,
                     frame: FrameIdentity) -> Detection:
        """Only the latest assessment may authorize this detector's conclusion."""
        with self._lock:
            if decision is not self._latest:
                return Detection(Observation.UNKNOWN, Reason.STALE)
            return _guard_result(decision, result, execution=execution, frame=frame)


def _guard_result(decision: QualityDecision, result: Detection | None, *, execution: Execution,
                 frame: FrameIdentity) -> Detection:
    """Preserve a positive/negative only after quality and execution succeeded.

    Use the exact frame identity of the result: stale or mismatched decisions
    never authorize conclusions. Dependent owner/entrance/presence logic must
    propagate UNKNOWN, and must not turn skipped/failed inference into absence.
    """
    if (not isinstance(decision, QualityDecision) or not isinstance(execution, Execution)
            or not isinstance(frame, FrameIdentity)):
        raise ValueError("invalid quality result guard")
    if decision.frame != frame or not decision.allows_conclusion:
        return Detection(Observation.UNKNOWN, Reason.QUALITY)
    if execution is not Execution.SUCCEEDED:
        return Detection(Observation.UNKNOWN, Reason.FAILURE if execution is Execution.FAILED else Reason.NOT_STARTED)
    if not isinstance(result, Detection):
        return Detection(Observation.UNKNOWN, Reason.FAILURE)
    return result
