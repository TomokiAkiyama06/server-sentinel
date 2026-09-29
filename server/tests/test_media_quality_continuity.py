"""Live/recording continue through SourcePipeline while person quality is unusable.

Composes the real SourcePipeline, InferenceSampler, QualityGate and
InferenceScheduler on one synthetic scheduler thread. Packets and decoded frames
are generated in memory (geometric shapes, fixed byte payloads); no real-person
media, camera, codec or network is used. The decoded frame is a stand-in for the
decoder/resizer adapter output at the sampler-selected dimensions.
"""

from fractions import Fraction
import socket
import unittest
from unittest.mock import patch
from uuid import UUID

from app.detection.foundation import (
    Detection, DetectorKind, Health, InferenceScheduler, Observation, Quality,
    Reason, SourcePolicy,
)
from app.detection.quality import Execution, Metric, QualityGate, QualityReason
from app.media.profiles import CaptureProfile, RecordingProfile, SourceProfiles, ViewerProfile
from tests.test_detector_quality import calibrated_policy, context, synthetic_person
from tests.test_media_profiles import (
    SOURCE, STREAM, SyntheticFactory, inference_profile, packet, pipeline, video_format,
)

VIEWER = UUID(int=30)
FRAME_SIDE = 16


class SyntheticPersonDetector:
    """Generated stand-in; reports ABSENT unless told to fail. No model/weights."""

    kind = DetectorKind.PERSON
    implementation = "synthetic-continuity"
    version = "1"

    def __init__(self):
        self.calls = 0
        self.fail = False

    def reset(self):
        pass

    def evaluate(self, frame):
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic detector failure text must not escape")
        return Detection(Observation.ABSENT, Reason.EVALUATED)


def continuity_profiles():
    # Inference cadence equals capture cadence so every decoded frame is sampled
    # and the gate sees consecutive sequences (recovery hysteresis is testable).
    format_ = video_format()
    return SourceProfiles(
        CaptureProfile(format_, Fraction(2)), RecordingProfile(format_),
        inference_profile(width=FRAME_SIDE, height=FRAME_SIDE, fps=format_.fps),
        ViewerProfile(format_))


class Harness:
    def __init__(self):
        self.now = 0
        self.recording = SyntheticFactory()
        self.viewer = SyntheticFactory()
        self.pipeline = pipeline(recording=self.recording, viewer=self.viewer,
                                 profiles=continuity_profiles())
        self.pipeline.add_viewer(VIEWER)
        self.scheduler = InferenceScheduler(clock_ns=lambda: self.now)
        self.detector = SyntheticPersonDetector()
        self.scheduler.register(SOURCE, self.detector,
                                SourcePolicy(1, 8, 10**6, 10**6, 10**6, 4096))
        self.gate = QualityGate(SOURCE, calibrated_policy(), results=self.scheduler)
        self.sequence = 0
        self.offers = []
        self.decisions = []
        self.results = []

    def step(self, condition="clear", *, execution=Execution.READY, quality_context="default"):
        sequence = self.sequence
        self.sequence += 1
        self.now += 1
        item = packet(sequence, keyframe=sequence == 0)
        # Capture -> recording/live fanout never waits on inference.
        self.offers.append(self.pipeline.offer(item))
        self.pipeline.pump(8)
        sample = self.pipeline.inference.select(item.stream_id, item.pts, item.time_base)
        if not sample.emit:
            raise AssertionError("continuity fixture expects every frame sampled")
        frame = synthetic_person(sequence, condition=condition, stream=STREAM,
                                 width=sample.width, height=sample.height)
        values = {} if quality_context == "default" else quality_context
        ctx = None if values is None else context(frame, **values)
        decision = self.gate.assess(frame, execution=execution, context=ctx)
        self.decisions.append(decision)
        if execution in (Execution.READY, Execution.SUCCEEDED):
            self.scheduler.offer(frame, quality=decision.quality)
            self.scheduler.run_one()
        result = self.scheduler.snapshot(SOURCE).result
        self.results.append(result)
        return decision, result

    def recorded(self):
        return [item.sequence for item in self.recording.adapters[0].packets]

    def viewed(self):
        return [item.sequence for item in self.viewer.adapters[0].packets]

    def assert_media_continuous(self, case):
        expected = list(range(self.sequence))
        case.assertEqual(expected, self.recorded())
        case.assertEqual(expected, self.viewed())
        case.assertTrue(all(offer.recording_queued and offer.viewer_queued
                            and offer.reason == "accepted" for offer in self.offers))
        status = self.pipeline.status
        case.assertEqual("healthy", status.state)
        case.assertEqual((), status.reasons)
        case.assertEqual(0, status.capture_discontinuities)
        case.assertTrue(status.recording.healthy)
        case.assertTrue(status.viewer.healthy)


class PipelineQualityContinuityTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(socket.socket, "connect",
                             side_effect=AssertionError("unexpected network"))
        guard.start()
        self.addCleanup(guard.stop)

    def test_unusable_quality_keeps_live_and_recording_and_person_stays_unknown(self):
        cases = {
            "dark": ("dark", "default", Quality.INSUFFICIENT, Metric.LUMINANCE),
            "blurred": ("blurred", "default", Quality.INSUFFICIENT, Metric.SHARPNESS),
            "saturated": ("saturated", "default", Quality.INSUFFICIENT, Metric.SATURATION),
            "occluded": ("clear", {"occlusion_fraction": .5}, Quality.INSUFFICIENT,
                         Metric.OCCLUSION),
            "small_target": ("clear", {"target_width": 2, "target_height": 2},
                             Quality.INSUFFICIENT, Metric.TARGET_WIDTH),
            "context_missing": ("clear", None, Quality.UNKNOWN, Metric.TARGET_WIDTH),
        }
        for name, (condition, values, quality, metric) in cases.items():
            with self.subTest(case=name):
                harness = Harness()
                for _ in range(12):
                    decision, result = harness.step(condition, quality_context=values)
                    self.assertEqual(quality, decision.quality)
                    self.assertIn(metric, {finding.metric for finding in decision.findings})
                    self.assertEqual(Detection(Observation.UNKNOWN, Reason.QUALITY), result)
                harness.assert_media_continuous(self)
                self.assertEqual(0, harness.detector.calls)
                self.assertNotIn(Observation.ABSENT,
                                 {result.observation for result in harness.results})
                self.assertEqual(Health.UNAVAILABLE, harness.scheduler.snapshot(SOURCE).health)

    def test_quality_drop_revokes_published_absence_without_touching_media(self):
        harness = Harness()
        harness.step()  # recovery pending: first good frame is degraded.
        _, result = harness.step()
        self.assertEqual(Observation.ABSENT, result.observation)
        for _ in range(5):
            decision, result = harness.step("dark")
            self.assertFalse(decision.allows_conclusion)
            self.assertEqual(Detection(Observation.UNKNOWN, Reason.QUALITY), result)
        decision, result = harness.step()
        self.assertEqual(QualityReason.RECOVERING, decision.findings[-1].reason)
        self.assertEqual(Observation.UNKNOWN, result.observation)
        decision, result = harness.step()
        self.assertTrue(decision.allows_conclusion)
        self.assertEqual(Observation.ABSENT, result.observation)
        self.assertEqual(2, harness.detector.calls)
        harness.assert_media_continuous(self)

    def test_detector_failure_and_stop_do_not_interrupt_live_or_recording(self):
        harness = Harness()

        def publish_absence():
            # Every case starts from a published negative, so the assertions
            # show revocation of `absent`, not an already-unknown leftover.
            harness.step()  # recovery pending
            _, result = harness.step()
            self.assertEqual(Detection(Observation.ABSENT, Reason.EVALUATED), result)

        publish_absence()
        harness.detector.fail = True
        _, result = harness.step()
        self.assertEqual(Detection(Observation.UNKNOWN, Reason.FAILURE), result)
        self.assertNotIn("synthetic detector failure", repr(harness.scheduler.snapshot(SOURCE)))
        harness.detector.fail = False

        publish_absence()
        stopped = harness.gate.invalidate(execution=Execution.STOPPED)
        self.assertEqual(Detection(Observation.UNKNOWN, Reason.NOT_STARTED), stopped)
        self.assertEqual(stopped, harness.scheduler.snapshot(SOURCE).result)

        for execution in (Execution.STOPPED, Execution.FAILED, Execution.UNAVAILABLE,
                          Execution.SKIPPED):
            with self.subTest(execution=execution):
                publish_absence()
                calls = harness.detector.calls
                decision, result = harness.step(execution=execution)
                self.assertEqual(Quality.UNKNOWN, decision.quality)
                self.assertFalse(decision.allows_conclusion)
                # The gate alone revokes: no frame is offered to the scheduler.
                self.assertEqual(Observation.UNKNOWN, result.observation)
                self.assertEqual(calls, harness.detector.calls)
        harness.assert_media_continuous(self)

    def test_live_viewer_leaving_does_not_stop_recording_while_person_is_unknown(self):
        harness = Harness()
        for _ in range(3):
            harness.step("dark")
        self.assertTrue(harness.pipeline.remove_viewer(VIEWER))
        for _ in range(3):
            _, result = harness.step("dark")
            self.assertEqual(Observation.UNKNOWN, result.observation)
        self.assertEqual(list(range(6)), harness.recorded())
        self.assertEqual([0, 1, 2], harness.viewed())
        self.assertTrue(harness.viewer.adapters[0].closed)
        self.assertEqual("healthy", harness.pipeline.status.state)
        self.assertEqual(0, harness.detector.calls)


if __name__ == "__main__":
    unittest.main()
