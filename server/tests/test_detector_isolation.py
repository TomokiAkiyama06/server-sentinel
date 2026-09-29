"""Generated pixels only: isolated detector workers fail closed to unknown."""

import os
import time
import unittest
from uuid import UUID

from app.detection.foundation import (Detection, DetectorKind, DetectorWorkerFailure,
                                     GrayFrame, Health, InferenceScheduler,
                                     IsolatedDetector, Observation, Quality, Reason,
                                     RgbFrame, SourcePolicy, WorkerLimits, WorkerSpec)
from app.detection.foundation.isolation import _parse_detection

try:
    from . import detector_worker_fakes as fakes
except ImportError:  # discovered as a top-level module
    import detector_worker_fakes as fakes

SOURCE = UUID(int=1)
STREAM = UUID(int=10)
SECONDS = 1_000_000_000


def limits(**changes):
    # Test-only values, not deployment defaults.
    value = dict(evaluation_timeout_ns=SECONDS // 2, start_timeout_ns=20 * SECONDS,
                 restart_backoff_ns=100, maximum_consecutive_failures=3,
                 address_space_bytes=1 << 30, open_files=64, maximum_frame_bytes=64)
    value.update(changes)
    return WorkerLimits(**value)


def spec(behaviour="absent", argument=None, *, factory=None):
    arguments = {} if factory is not None else {"behaviour": behaviour, "argument": argument}
    return WorkerSpec(DetectorKind.PERSON, "synthetic-worker-double", "1",
                      factory or fakes.fake, arguments)


def frame(sequence=0, value=51):
    return GrayFrame(SOURCE, STREAM, sequence, 4, 4, bytes([value]) * 16)


class Clock:
    value = 0

    def __call__(self):
        return self.value


class IsolatedDetectorTests(unittest.TestCase):
    def detector(self, worker_spec, **changes):
        self.clock = Clock()
        detector = IsolatedDetector(worker_spec, limits(**changes), clock_ns=self.clock)
        self.addCleanup(detector.close)
        return detector

    def assertUnknown(self, result, reason):
        self.assertEqual(Detection(Observation.UNKNOWN, reason), result)

    def test_evaluation_runs_in_child_and_returns_validated_result(self):
        detector = self.detector(spec())
        self.assertEqual("running", detector.maintain().state)
        result = detector.evaluate(frame(value=51))
        self.assertEqual(Detection(Observation.ABSENT, Reason.EVALUATED, 0.2), result)
        rgb = RgbFrame(SOURCE, STREAM, 1, 2, 2, bytes([255]) * 12)
        self.assertEqual(1.0, detector.evaluate(rgb).measurement)
        self.assertEqual(1, detector.status().starts)
        detector.reset()
        self.assertEqual("running", detector.status().state)

    def test_evaluate_never_spawns_and_is_unknown_without_worker(self):
        detector = self.detector(spec())
        self.assertUnknown(detector.evaluate(frame()), Reason.WORKER_UNAVAILABLE)
        self.assertEqual("stopped", detector.status().state)
        detector.reset()  # A fresh worker has no state to reset.

    def test_hanging_plugin_is_killed_and_reported_unknown(self):
        detector = self.detector(spec("hang"))
        detector.maintain()
        pid = detector._process.pid
        started = time.monotonic()
        self.assertUnknown(detector.evaluate(frame()), Reason.WORKER_TIMEOUT)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIsNone(detector._process)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)  # killed and reaped, not left running
        status = detector.status()
        self.assertEqual(("backoff", 1, 1), (status.state, status.timeouts,
                                             status.consecutive_failures))
        self.assertIs(Reason.WORKER_TIMEOUT, status.last_failure)
        # A later frame is still unknown, never absent, until a restart.
        self.assertUnknown(detector.evaluate(frame(1)), Reason.WORKER_UNAVAILABLE)

    def test_crashing_plugin_is_reported_unknown_and_restarted_after_backoff(self):
        detector = self.detector(spec("crash_after", 1))
        detector.maintain()
        self.assertEqual(Observation.ABSENT, detector.evaluate(frame()).observation)
        self.assertUnknown(detector.evaluate(frame(1)), Reason.WORKER_CRASHED)
        self.assertEqual((1, "backoff"), (detector.status().crashes, detector.status().state))
        self.assertEqual("backoff", detector.maintain().state)  # backoff not yet elapsed
        self.clock.value += 100
        self.assertEqual("running", detector.maintain().state)
        self.assertEqual(2, detector.status().starts)
        self.assertEqual(Observation.ABSENT, detector.evaluate(frame(2)).observation)
        self.assertEqual(0, detector.status().consecutive_failures)

    def test_idle_crash_is_detected_by_maintain(self):
        detector = self.detector(spec())
        detector.maintain()
        detector._process.kill()
        detector._process.join(5)
        status = detector.maintain()
        self.assertEqual((1, "backoff"), (status.crashes, status.state))
        self.assertUnknown(detector.evaluate(frame()), Reason.WORKER_UNAVAILABLE)

    def test_idle_crash_is_never_replaced_in_the_same_maintain_call(self):
        detector = self.detector(spec(), restart_backoff_ns=1)
        detector.maintain()
        detector._process.kill()
        detector._process.join(5)
        # Even when the backoff has already elapsed, the caller observes the
        # dead worker before any replacement is started.
        self.clock.value += 10
        status = detector.maintain()
        self.assertEqual(("backoff", 1, 1), (status.state, status.crashes, status.starts))
        self.clock.value += 10
        self.assertEqual("running", detector.maintain().state)
        self.assertEqual(2, detector.status().starts)

    def test_plugin_exception_is_unknown_without_leaking_text(self):
        detector = self.detector(spec("raise"))
        detector.maintain()
        self.assertUnknown(detector.evaluate(frame()), Reason.FAILURE)
        self.assertEqual("running", detector.status().state)
        self.assertNotIn("/private/model", repr(detector.status()))

    def test_address_space_limit_turns_allocation_into_unknown(self):
        detector = self.detector(spec("allocate", 2 << 30), address_space_bytes=512 << 20)
        self.assertEqual("running", detector.maintain().state)
        self.assertEqual(Observation.UNKNOWN, detector.evaluate(frame()).observation)

    def test_failed_hanging_and_impostor_starts_are_unavailable(self):
        for factory, reason in ((fakes.failing_start, Reason.WORKER_UNAVAILABLE),
                                (fakes.hanging_start, Reason.WORKER_TIMEOUT),
                                (fakes.impostor, Reason.WORKER_UNAVAILABLE)):
            with self.subTest(factory=factory.__name__):
                detector = self.detector(spec(factory=factory), start_timeout_ns=3 * SECONDS)
                status = detector.maintain()
                self.assertEqual(("backoff", 1, 0), (status.state, status.start_failures,
                                                     status.starts))
                self.assertIs(reason, status.last_failure)
                self.assertIsNone(detector._process)
                self.assertUnknown(detector.evaluate(frame()), Reason.WORKER_UNAVAILABLE)

    def test_repeated_failures_latch_until_explicit_recovery(self):
        detector = self.detector(spec(factory=fakes.failing_start),
                                 maximum_consecutive_failures=2)
        detector.maintain()
        self.clock.value += 100
        self.assertEqual("latched", detector.maintain().state)
        self.clock.value += 10_000
        status = detector.maintain()
        self.assertEqual(("latched", 2), (status.state, status.start_failures))
        detector.recover()
        self.assertEqual(3, detector.maintain().start_failures)

    def test_reset_hang_and_failure_raise_fixed_failure_and_stop_worker(self):
        for behaviour in ("hang_reset", "fail_reset"):
            with self.subTest(behaviour=behaviour):
                detector = self.detector(spec(behaviour))
                detector.maintain()
                with self.assertRaises(DetectorWorkerFailure) as caught:
                    detector.reset()
                self.assertNotIn("/private", str(caught.exception))
                self.assertIsNone(detector._process)
                self.assertEqual("backoff", detector.status().state)

    def test_oversized_and_invalid_frames_do_not_reach_worker(self):
        detector = self.detector(spec(), maximum_frame_bytes=8)
        detector.maintain()
        self.assertUnknown(detector.evaluate(frame()), Reason.RESOURCE_LIMIT)
        self.assertUnknown(detector.evaluate(object()), Reason.QUALITY)
        self.assertEqual("running", detector.status().state)

    def test_close_is_idempotent_and_prevents_restart(self):
        detector = self.detector(spec())
        detector.maintain()
        self.assertTrue(detector.close())
        self.assertTrue(detector.close())
        self.assertEqual("closed", detector.maintain().state)
        self.assertUnknown(detector.evaluate(frame()), Reason.WORKER_UNAVAILABLE)
        with self.assertRaises(RuntimeError):
            detector.recover()

    def test_unrepresentable_limits_are_rejected_before_any_spawn(self):
        from app.detection.foundation.isolation import MAXIMUM_RLIMIT, MAXIMUM_WATCHDOG_NS
        for field_name in ("evaluation_timeout_ns", "start_timeout_ns"):
            for value in (MAXIMUM_WATCHDOG_NS + 1, 10 ** 400):
                with self.subTest(field=field_name, value=value):
                    with self.assertRaises(ValueError):
                        limits(**{field_name: value})
        # 2**64 - 1 is RLIM_INFINITY: it would silently disable the limit.
        for field_name in ("address_space_bytes", "open_files"):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError):
                    limits(**{field_name: MAXIMUM_RLIMIT + 1})
        limits(evaluation_timeout_ns=MAXIMUM_WATCHDOG_NS)

    def test_unarmable_watchdog_is_a_start_failure_not_an_exception(self):
        detector = self.detector(spec())
        # Defence in depth behind WorkerLimits validation.
        object.__setattr__(detector._limits, "start_timeout_ns", 10 ** 400)
        status = detector.maintain()
        self.assertEqual(("backoff", 0, 1), (status.state, status.starts,
                                              status.start_failures))
        self.assertEqual(Reason.WORKER_UNAVAILABLE, status.last_failure)
        self.assertIsNone(detector._process)
        self.assertUnknown(detector.evaluate(frame()), Reason.WORKER_UNAVAILABLE)

    def test_reply_parser_rejects_malformed_documents(self):
        good = b'{"id": 7, "o": "absent", "r": "evaluated", "m": 0.5}'
        self.assertEqual(Detection(Observation.ABSENT, Reason.EVALUATED, 0.5),
                         _parse_detection(good, 7))
        for payload, request in (
                (good, 8), (b'{"id": 7, "o": "absent", "r": "evaluated", "m": NaN}', 7),
                (b'{"id": 7, "o": "absent", "r": "evaluated", "m": 2}', 7),
                (b'{"id": 7, "o": "unknown", "r": "evaluated", "m": null}', 7),
                (b'{"id": 7, "o": "absent", "r": "warmup", "m": null}', 7),
                (b'{"id": 7, "o": "nobody", "r": "evaluated", "m": null}', 7),
                (b'{"id": 7, "o": "absent", "r": "evaluated", "m": true}', 7),
                (b'{"id": 7, "o": "absent", "r": "evaluated", "m": null, "x": 1}', 7),
                (b'{"id": 7, "o": "absent", "r": "evaluated", "m": 1' + b'0' * 400 + b'}', 7),
                (b'[1]', 7), (b'\xff', 7)):
            with self.subTest(payload=payload):
                self.assertIsNone(_parse_detection(payload, request))

    def test_spec_rejects_non_importable_or_non_primitive_factories(self):
        with self.assertRaises(ValueError):
            WorkerSpec(DetectorKind.PERSON, "x", "1", lambda: None)
        with self.assertRaises(ValueError):
            WorkerSpec(DetectorKind.PERSON, "x", "1", fakes.fake, {"behaviour": object()})
        with self.assertRaises(ValueError):
            limits(open_files=4)
        self.assertNotIn("behaviour", repr(spec()))


class SchedulerIsolationTests(unittest.TestCase):
    POLICY = SourcePolicy(cadence_ns=10, maximum_cadence_ns=80, maximum_queue_age_ns=100,
                          maximum_evaluation_ns=100, maximum_observation_age_ns=1000,
                          maximum_pixels=16)

    def run_source(self, behaviour):
        clock = Clock()
        scheduler = InferenceScheduler(clock_ns=clock)
        detector = IsolatedDetector(spec(behaviour), limits(), clock_ns=clock)
        self.addCleanup(detector.close)
        scheduler.register(SOURCE, detector, self.POLICY)
        detector.maintain()
        self.assertTrue(scheduler.offer(frame(), quality=Quality.SUFFICIENT))
        return scheduler.run_one()

    def test_hung_or_crashed_worker_publishes_unavailable_never_absent(self):
        for behaviour, reason in (("hang", Reason.WORKER_TIMEOUT),
                                  ("crash", Reason.WORKER_CRASHED)):
            with self.subTest(behaviour=behaviour):
                snapshot = self.run_source(behaviour)
                self.assertEqual(Detection(Observation.UNKNOWN, reason), snapshot.result)
                self.assertIs(Health.UNAVAILABLE, snapshot.health)
                self.assertEqual(1, snapshot.processed)

    def test_healthy_worker_publishes_its_evaluated_result(self):
        snapshot = self.run_source("absent")
        self.assertIs(Health.HEALTHY, snapshot.health)
        self.assertEqual(Observation.ABSENT, snapshot.result.observation)
        self.assertEqual("synthetic-worker-double", snapshot.implementation)


if __name__ == "__main__":
    unittest.main()
