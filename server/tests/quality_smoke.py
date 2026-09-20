"""Small generated quality scenario under the enclosing smoke audit hook."""

from uuid import UUID

from app.detection.foundation import Detection, GrayFrame, Observation, Reason
from app.detection.quality import (
    DetectorQualityPolicy, Execution, FrameIdentity, Metric, MetricRule, QualityGate,
)


def run_quality_smoke(scenario):
    source, stream = UUID(int=101), UUID(int=102)
    policy = DetectorQualityPolicy("motion", 1, (
        MetricRule(Metric.LUMINANCE, .1, .2, .8, .9),
        MetricRule(Metric.SHARPNESS, .001, .01, 1, 1),
        MetricRule(Metric.SATURATION, 0, 0, .1, .4),
    ), 2, 64)
    gate = QualityGate(source, policy)
    good = bytes(64 if (x + y) % 2 else 192 for y in range(8) for x in range(8))
    for sequence in range(2):
        sample = GrayFrame(source, stream, sequence, 8, 8, good)
        decision = gate.assess(sample, execution=Execution.READY)
    assert decision.allows_conclusion
    if scenario == "error":
        sample = GrayFrame(source, stream, 2, 8, 8, bytes(64))
        decision = gate.assess(sample, execution=Execution.READY)
        assert not decision.allows_conclusion
    for observation in (Observation.PRESENT, Observation.ABSENT):
        guarded = gate.guard_result(decision, Detection(observation, Reason.EVALUATED),
                                    execution=Execution.SUCCEEDED, frame=FrameIdentity.from_frame(sample))
        assert guarded.observation is (Observation.UNKNOWN if scenario == "error" else observation)
