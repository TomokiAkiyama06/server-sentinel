"""Generated pixels only: bounded inference and honest unavailable conclusions."""

from dataclasses import replace
import socket
import threading
import unittest
from unittest.mock import patch
from uuid import UUID

from app.detection.foundation import (Detection, DetectorKind, GrayFrame, Health,
                                     InferenceScheduler, MotionBaseline,
                                     Observation, Quality, Reason,
                                     SourcePolicy, UnavailablePersonDetector)

SOURCE = UUID(int=1)
STREAM = UUID(int=10)
POLICY = SourcePolicy(cadence_ns=10, maximum_cadence_ns=80,
                      maximum_queue_age_ns=100, maximum_evaluation_ns=20,
                      maximum_observation_age_ns=100, maximum_pixels=16)


def frame(sequence=0, *, value=0, source=SOURCE, stream=STREAM, width=4, height=4):
    return GrayFrame(source, stream, sequence, width, height, bytes([value]) * (width * height))


class Clock:
    value = 0

    def __call__(self):
        return self.value


class StubDetector:
    kind = DetectorKind.PERSON
    implementation = "synthetic-test-double"
    version = "1"

    def __init__(self, callback=None):
        self.callback = callback
        self.calls = 0
        self.resets = 0

    def reset(self):
        self.resets += 1

    def evaluate(self, sample):
        self.calls += 1
        if self.callback:
            return self.callback(sample)
        return Detection(Observation.ABSENT, Reason.EVALUATED)


class DetectorFoundationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.scheduler = InferenceScheduler(clock_ns=self.clock)

    def register(self, detector=None, source=SOURCE, policy=POLICY):
        detector = detector or StubDetector()
        self.scheduler.register(source, detector, policy)
        return detector

    def offer(self, sample, quality=Quality.SUFFICIENT):
        return self.scheduler.offer(sample, quality=quality)

    def test_motion_reports_only_measured_temporal_change(self):
        motion = MotionBaseline(pixel_delta=20, changed_fraction=0.25)
        self.assertEqual(motion.evaluate(frame()).reason, Reason.WARMUP)
        stable = motion.evaluate(frame(1, value=19))
        self.assertEqual(stable.observation, Observation.ABSENT)
        changed = motion.evaluate(frame(2, value=100))
        self.assertEqual(changed.observation, Observation.PRESENT)
        self.assertEqual(changed.measurement, 1)
        self.assertEqual(motion.kind, DetectorKind.MOTION)
        motion.reset()
        self.assertEqual(motion.evaluate(frame(3)).reason, Reason.WARMUP)

    def test_motion_resets_on_stream_shape_and_sequence_discontinuities(self):
        for changed in (frame(1, stream=UUID(int=11)), frame(1, width=2, height=8), frame(0)):
            motion = MotionBaseline(pixel_delta=20, changed_fraction=0.25)
            motion.evaluate(frame())
            self.assertEqual(motion.evaluate(changed).reason, Reason.DISCONTINUITY)

    def test_frames_are_immutable_and_do_not_expose_pixels_in_repr(self):
        sample = frame(value=33)
        self.assertNotIn("pixels", repr(sample))
        with self.assertRaises(ValueError):
            GrayFrame(SOURCE, STREAM, 0, 1, 1, bytearray([0]))
        with self.assertRaises(ValueError):
            GrayFrame(SOURCE, STREAM, 0, 4, 4, b"short")

    def test_invalid_limits_measurements_and_thresholds_are_rejected(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                replace(POLICY, maximum_pixels=value)
        for value in (0, 1.5, float("nan"), True):
            with self.assertRaises(ValueError):
                MotionBaseline(pixel_delta=20, changed_fraction=value)
        with self.assertRaises(ValueError):
            Detection(Observation.ABSENT, Reason.FAILURE)
        with self.assertRaises(ValueError):
            Detection(Observation.ABSENT, Reason.EVALUATED, float("nan"))

    def test_unavailable_person_never_becomes_absent(self):
        self.register(UnavailablePersonDetector())
        self.offer(frame())
        result = self.scheduler.run_one()
        self.assertEqual(result.kind, DetectorKind.PERSON)
        self.assertEqual(result.result.observation, Observation.UNKNOWN)
        self.assertEqual(result.result.reason, Reason.MODEL_UNAVAILABLE)

    def test_capture_offer_does_not_invoke_plugin(self):
        detector = self.register()
        self.offer(frame())
        self.assertEqual(detector.calls, 0)
        self.assertTrue(self.scheduler.snapshot(SOURCE).pending)
        self.scheduler.run_one()
        self.assertEqual(detector.calls, 1)

    def test_capture_cadence_does_not_cause_false_overload(self):
        detector = self.register()
        self.offer(frame())
        self.scheduler.run_one()
        for sequence in range(1, 10):
            self.clock.value = sequence
            self.assertFalse(self.offer(frame(sequence)))
            self.assertIsNone(self.scheduler.run_one())
        self.clock.value = 10
        self.assertTrue(self.offer(frame(10)))
        result = self.scheduler.run_one()
        self.assertEqual(detector.calls, 2)
        self.assertEqual(result.sampled_out, 9)
        self.assertEqual(result.dropped, 0)
        self.assertEqual(result.cadence_ns, 10)

    def test_low_quality_immediately_invalidates_previous_negative(self):
        for quality in (Quality.UNKNOWN, Quality.INSUFFICIENT, Quality.DEGRADED):
            with self.subTest(quality=quality):
                scheduler = InferenceScheduler(clock_ns=self.clock)
                detector = StubDetector()
                scheduler.register(SOURCE, detector, POLICY)
                scheduler.offer(frame(), quality=Quality.SUFFICIENT)
                scheduler.run_one()
                scheduler.offer(frame(1), quality=quality)
                self.assertEqual(scheduler.snapshot(SOURCE).result.reason, Reason.QUALITY)
                self.assertEqual(detector.calls, 1)

    def test_mailbox_drop_throttles_and_reports_unknown(self):
        self.register()
        self.offer(frame())
        self.clock.value = 10
        self.offer(frame(1))
        state = self.scheduler.snapshot(SOURCE)
        self.assertEqual(state.dropped, 1)
        self.assertEqual(state.result.reason, Reason.DROPPED)
        self.assertEqual(state.cadence_ns, 20)
        processed = self.scheduler.run_one()
        self.assertEqual(processed.sequence, 1)
        self.assertEqual(processed.cadence_ns, 20)
        self.assertEqual(processed.health, Health.DEGRADED)
        self.scheduler.restore_cadence(SOURCE)
        self.assertEqual(self.scheduler.snapshot(SOURCE).cadence_ns, 10)
        self.assertEqual(self.scheduler.snapshot(SOURCE).health, Health.DEGRADED)
        self.scheduler.acknowledge_recovery(SOURCE)
        self.assertEqual(self.scheduler.snapshot(SOURCE).health, Health.HEALTHY)

    def test_stale_queue_is_not_evaluated(self):
        detector = self.register()
        self.offer(frame())
        self.clock.value = 101
        result = self.scheduler.run_one()
        self.assertEqual(result.result.reason, Reason.STALE)
        self.assertEqual(detector.calls, 0)

    def test_stopped_feed_expires_last_negative(self):
        self.register()
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 101
        self.assertEqual(self.scheduler.snapshot(SOURCE).result.reason, Reason.STALE)

    def test_observation_lifetime_includes_queue_wait_and_evaluation(self):
        def evaluated_late(_sample):
            self.clock.value += 15
            return Detection(Observation.ABSENT, Reason.EVALUATED)
        self.register(StubDetector(evaluated_late))
        self.offer(frame())
        self.clock.value = 90
        self.assertEqual(self.scheduler.run_one().result.reason, Reason.STALE)

    def test_receipt_and_evaluation_provenance_are_main_monotonic(self):
        def evaluate(_sample):
            self.clock.value = 7
            return Detection(Observation.ABSENT, Reason.EVALUATED)
        self.register(StubDetector(evaluate))
        self.clock.value = 3
        self.offer(frame())
        result = self.scheduler.run_one()
        self.assertEqual((result.stream_id, result.sequence), (STREAM, 0))
        self.assertEqual((result.received_at_ns, result.evaluated_at_ns), (3, 7))

    def test_oversize_does_not_enter_pending_queue(self):
        self.register()
        self.assertFalse(self.offer(frame(width=5)))
        result = self.scheduler.snapshot(SOURCE)
        self.assertFalse(result.pending)
        self.assertEqual(result.result.reason, Reason.RESOURCE_LIMIT)

    def test_oversize_frame_advances_stream_and_sequence_watermarks(self):
        self.register()
        self.assertTrue(self.offer(frame(0)))
        self.scheduler.run_one()
        replacement = UUID(int=99)
        self.clock.value = 10
        self.assertFalse(self.offer(frame(10, stream=replacement, width=5)))
        self.assertEqual(replacement, self.scheduler.snapshot(SOURCE).stream_id)
        self.assertFalse(self.offer(frame(9, stream=replacement)))
        self.assertFalse(self.offer(frame(1)))

    def test_bounded_retired_stream_history_rejects_older_generation(self):
        self.register()
        stream_b, stream_c = UUID(int=11), UUID(int=12)
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 10
        self.offer(frame(0, stream=stream_b))
        self.scheduler.run_one()
        self.clock.value = 20
        self.offer(frame(0, stream=stream_c))
        self.scheduler.run_one()
        self.clock.value = 30
        self.assertFalse(self.offer(frame(1)))
        result = self.scheduler.snapshot(SOURCE)
        self.assertEqual((result.stream_id, result.sequence), (stream_c, 0))
        self.assertEqual(result.result.reason, Reason.EVALUATED)

    def test_retired_stream_rejection_preserves_current_pending_and_inflight(self):
        replacement = UUID(int=11)
        self.register()
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 10
        self.assertTrue(self.offer(frame(0, stream=replacement)))
        self.assertFalse(self.offer(frame(1)))
        self.assertTrue(self.scheduler.snapshot(SOURCE).pending)
        self.assertEqual(self.scheduler.run_one().stream_id, replacement)

        started, release = threading.Event(), threading.Event()

        def blocking(sample):
            if sample.sequence == 1:
                started.set()
                if not release.wait(2):
                    raise RuntimeError("test worker deadline")
            return Detection(Observation.ABSENT, Reason.EVALUATED)

        scheduler = InferenceScheduler(clock_ns=self.clock)
        scheduler.register(SOURCE, StubDetector(blocking), POLICY)
        scheduler.offer(frame(), quality=Quality.SUFFICIENT)
        scheduler.run_one()
        self.clock.value = 20
        scheduler.offer(frame(0, stream=replacement), quality=Quality.SUFFICIENT)
        scheduler.run_one()
        self.clock.value = 30
        scheduler.offer(frame(1, stream=replacement), quality=Quality.SUFFICIENT)
        results = []
        worker = threading.Thread(target=lambda: results.append(scheduler.run_one()))
        worker.start()
        try:
            self.assertTrue(started.wait(2))
            self.assertFalse(scheduler.offer(frame(1), quality=Quality.SUFFICIENT))
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual((results[0].stream_id, results[0].sequence), (replacement, 1))

    def test_backward_sequence_rejection_preserves_pending_and_inflight(self):
        self.register()
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 10
        self.assertTrue(self.offer(frame(1)))
        self.assertFalse(self.offer(frame()))
        self.assertTrue(self.scheduler.snapshot(SOURCE).pending)
        self.assertEqual(self.scheduler.run_one().sequence, 1)

        started, release = threading.Event(), threading.Event()

        def blocking(sample):
            if sample.sequence == 2:
                started.set()
                if not release.wait(2):
                    raise RuntimeError("test worker deadline")
            return Detection(Observation.ABSENT, Reason.EVALUATED)

        scheduler = InferenceScheduler(clock_ns=self.clock)
        scheduler.register(SOURCE, StubDetector(blocking), POLICY)
        scheduler.offer(frame(), quality=Quality.SUFFICIENT)
        scheduler.run_one()
        self.clock.value = 20
        scheduler.offer(frame(2), quality=Quality.SUFFICIENT)
        results = []
        worker = threading.Thread(target=lambda: results.append(scheduler.run_one()))
        worker.start()
        try:
            self.assertTrue(started.wait(2))
            self.assertFalse(scheduler.offer(frame(1), quality=Quality.SUFFICIENT))
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0].sequence, 2)

    def test_late_result_becomes_unknown_and_throttles(self):
        def slow(_sample):
            self.clock.value += 21
            return Detection(Observation.ABSENT, Reason.EVALUATED)
        self.register(StubDetector(slow))
        self.offer(frame())
        result = self.scheduler.run_one()
        self.assertEqual(result.result.reason, Reason.OVER_BUDGET)
        self.assertEqual(result.cadence_ns, 20)

    def test_plugin_failure_is_redacted_and_resets(self):
        def failure(_sample):
            raise RuntimeError("do not expose any implementation details")
        detector = self.register(StubDetector(failure))
        self.offer(frame())
        result = self.scheduler.run_one()
        self.assertEqual(result.result.reason, Reason.FAILURE)
        self.assertNotIn("implementation details", repr(result))
        self.clock.value = 10
        self.offer(frame(1))
        self.scheduler.run_one()
        self.assertEqual(detector.resets, 2)

    def test_malformed_plugin_result_is_unknown(self):
        self.register(StubDetector(lambda _: False))
        self.offer(frame())
        self.assertEqual(self.scheduler.run_one().result.reason, Reason.FAILURE)

    def test_sources_are_independent_fair_and_limit_is_explicit(self):
        sources = [UUID(int=index) for index in range(1, 5)]
        for source in sources:
            self.register(source=source)
            self.offer(frame(source=source))
        with self.assertRaises(ValueError):
            self.register(source=UUID(int=5))
        self.assertEqual([self.scheduler.run_one().source_id for _ in sources], sources)
        self.scheduler.unregister(sources[0])
        self.register(source=UUID(int=5))

    def test_one_detector_instance_cannot_mix_sources(self):
        detector = self.register()
        with self.assertRaises(ValueError):
            self.register(detector, source=UUID(int=2))

    def test_stream_restart_invalidates_pending_and_warms_up(self):
        self.register(MotionBaseline(pixel_delta=20, changed_fraction=0.25))
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 10
        self.offer(frame(1))
        self.assertEqual(self.scheduler.run_one().result.observation, Observation.ABSENT)
        self.clock.value = 20
        self.offer(frame(stream=UUID(int=11)))
        self.assertEqual(self.scheduler.run_one().result.reason, Reason.WARMUP)

    def test_clock_regression_invalidates_results(self):
        self.clock.value = 100
        self.register()
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 1
        self.assertEqual(self.scheduler.snapshot(SOURCE).result.reason, Reason.CLOCK)

    def test_slow_worker_does_not_hold_capture_or_health_lock(self):
        started, release = threading.Event(), threading.Event()
        def blocking(_sample):
            started.set()
            if not release.wait(2):
                raise RuntimeError("test worker deadline")
            return Detection(Observation.ABSENT, Reason.EVALUATED)
        self.register(StubDetector(blocking))
        self.offer(frame())
        results = []
        worker = threading.Thread(target=lambda: results.append(self.scheduler.run_one()))
        worker.start()
        try:
            self.assertTrue(started.wait(2))
            self.clock.value = 10
            self.offer(frame(1))
            self.clock.value = 20
            self.offer(frame(2))
            self.assertEqual(self.scheduler.snapshot(SOURCE).result.reason, Reason.DROPPED)
            self.assertIsNone(self.scheduler.run_one())
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0].result.reason, Reason.DROPPED)

    def test_expired_published_result_does_not_cancel_fresh_inflight_evaluation(self):
        started, release = threading.Event(), threading.Event()
        def evaluate(sample):
            if sample.sequence == 1:
                started.set()
                if not release.wait(2):
                    raise RuntimeError("test worker deadline")
            return Detection(Observation.ABSENT, Reason.EVALUATED)
        self.register(StubDetector(evaluate))
        self.offer(frame())
        self.scheduler.run_one()
        self.clock.value = 90
        self.offer(frame(1))
        results = []
        worker = threading.Thread(target=lambda: results.append(self.scheduler.run_one()))
        worker.start()
        try:
            self.assertTrue(started.wait(2))
            self.clock.value = 101
            self.assertEqual(self.scheduler.snapshot(SOURCE).result.reason, Reason.STALE)
            self.clock.value = 105
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0].result.observation, Observation.ABSENT)
        self.assertEqual((results[0].received_at_ns, results[0].evaluated_at_ns), (90, 105))
        self.assertEqual(self.scheduler.snapshot(SOURCE).result.observation, Observation.ABSENT)

    def test_baseline_and_failure_make_no_network_attempts(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network attempted")) as network:
            self.register(MotionBaseline(pixel_delta=20, changed_fraction=0.25))
            self.offer(frame())
            self.scheduler.run_one()
            self.clock.value = 10
            self.offer(frame(1, value=255))
            self.assertEqual(self.scheduler.run_one().result.observation, Observation.PRESENT)
            self.clock.value = 20
            self.offer(frame(2), quality=Quality.INSUFFICIENT)
            self.assertEqual(self.scheduler.snapshot(SOURCE).result.observation, Observation.UNKNOWN)
            network.assert_not_called()
