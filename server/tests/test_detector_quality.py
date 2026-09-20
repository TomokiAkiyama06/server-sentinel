"""Quality signals and fail-unknown propagation from generated shapes only."""

from dataclasses import replace
import socket
import unittest
from unittest.mock import patch
from uuid import UUID

from app.detection.foundation import (
    Detection, DetectorKind, GrayFrame, Health, InferenceScheduler, Observation,
    Quality, Reason, RgbFrame, SourcePolicy,
)
from app.detection.quality import (
    DetectorQualityPolicy, Execution, FrameIdentity, MeasurementUnavailable,
    Metric, MetricRule, QualityContext, QualityGate, QualityReason, measure,
    obstruction_fraction, unavailable_reason,
)

SOURCE, OTHER, STREAM = UUID(int=1), UUID(int=2), UUID(int=10)


def synthetic_person(sequence=0, *, condition="clear", stream=STREAM, width=16, height=16):
    # Geometric head/torso/legs on a checkerboard; no real-person input/image file.
    pixels = []
    for y in range(height):
        for x in range(width):
            head = 6 <= x <= 9 and 2 <= y <= 5
            torso = 4 <= x <= 11 and 6 <= y <= 11
            legs = (4 <= x <= 6 or 9 <= x <= 11) and y >= 12
            pixels.append(210 if head or torso or legs else (64 if (x + y) % 2 else 192))
    if condition == "dark":
        pixels = [value // 64 for value in pixels]
    elif condition == "blurred":
        # Extreme full-image box blur removes every distinguishing edge.
        pixels = [sum(pixels) // len(pixels)] * len(pixels)
    elif condition == "saturated":
        pixels = [255] * len(pixels)
    elif condition == "obstructed":
        pixels = [value if index % width >= width // 2 else 0 for index, value in enumerate(pixels)]
    return GrayFrame(SOURCE, stream, sequence, width, height, bytes(pixels))


def calibrated_policy(detector="person", *, recovery_frames=2):
    # Synthetic test calibration only. No production defaults are exported.
    return DetectorQualityPolicy(detector, 1, (
        MetricRule(Metric.LUMINANCE, .1, .2, .8, .95),
        MetricRule(Metric.SHARPNESS, .001, .01, 1, 1),
        MetricRule(Metric.SATURATION, 0, 0, .1, .4),
        MetricRule(Metric.WIDTH, 8, 8, 64, 64),
        MetricRule(Metric.HEIGHT, 8, 8, 64, 64),
        MetricRule(Metric.TARGET_WIDTH, 4, 6, 64, 64),
        MetricRule(Metric.TARGET_HEIGHT, 4, 6, 64, 64),
        MetricRule(Metric.OCCLUSION, 0, 0, .1, .4),
    ), recovery_frames, 4096)


def context(sample, **values):
    settings = dict(target_width=min(10, sample.width), target_height=min(10, sample.height),
                    occlusion_fraction=0.0)
    settings.update(values)
    return QualityContext(FrameIdentity.from_frame(sample), **settings)


def assess(gate, sample, **values):
    return gate.assess(sample, execution=Execution.READY, context=context(sample, **values))


class SyntheticNegative:
    """Generated stand-in detector; it never reads a real person or media file."""

    kind = DetectorKind.PERSON
    implementation = "synthetic-negative"
    version = "1"
    calls = 0

    def reset(self):
        pass

    def evaluate(self, sample):
        self.calls += 1
        return Detection(Observation.ABSENT, Reason.EVALUATED)


def published_negative(now, *, recovery_frames=2):
    """Scheduler publishing one synthetic ABSENT, with the gate that allowed it."""
    scheduler = InferenceScheduler(clock_ns=lambda: now[0])
    scheduler.register(SOURCE, SyntheticNegative(), SourcePolicy(1, 8, 10**6, 10**6, 10**6, 4096))
    gate = QualityGate(SOURCE, calibrated_policy(recovery_frames=recovery_frames), results=scheduler)
    for sequence in range(recovery_frames + 1):
        now[0] = sequence + 1
        sample = synthetic_person(sequence)
        decision = assess(gate, sample)
        scheduler.offer(sample, quality=decision.quality)
        scheduler.run_one()
    return scheduler, gate, decision


def ready_gate(detector="person"):
    gate = QualityGate(SOURCE, calibrated_policy(detector))
    assess(gate, synthetic_person(0))
    decision = assess(gate, synthetic_person(1))
    return gate, decision


class QualityMetricTests(unittest.TestCase):
    def test_luminance_sharpness_and_saturation_measure_pixels(self):
        clear = dict(measure(synthetic_person(), maximum_pixels=4096))
        dark = dict(measure(synthetic_person(condition="dark"), maximum_pixels=4096))
        blur = dict(measure(synthetic_person(condition="blurred"), maximum_pixels=4096))
        saturated = dict(measure(synthetic_person(condition="saturated"), maximum_pixels=4096))
        self.assertGreater(clear[Metric.LUMINANCE], dark[Metric.LUMINANCE])
        self.assertGreater(clear[Metric.SHARPNESS], blur[Metric.SHARPNESS])
        self.assertEqual(0, blur[Metric.SHARPNESS])
        self.assertEqual(0, clear[Metric.SATURATION])
        self.assertEqual(1, saturated[Metric.SATURATION])
        self.assertEqual(16, clear[Metric.WIDTH])
        self.assertIsNone(clear[Metric.TARGET_WIDTH])
        self.assertIsNone(clear[Metric.OCCLUSION])

    def test_rgb_luminance_and_clipped_channel_measurements(self):
        sample = RgbFrame(SOURCE, STREAM, 0, 2, 1, bytes([255, 0, 0, 0, 255, 0]))
        metrics = dict(measure(sample, maximum_pixels=2))
        self.assertAlmostEqual((.2126 + .7152) / 2, metrics[Metric.LUMINANCE])
        self.assertEqual(1, metrics[Metric.SATURATION])
        self.assertGreater(metrics[Metric.SHARPNESS], 0)

    def test_obstruction_mask_never_defaults_missing_observations_to_clear(self):
        self.assertEqual(.5, obstruction_fraction(bytes([0, 1, 0, 1]), maximum_pixels=4))
        for mask in (b"", b"\x00\x02", b"\x00" * 5, bytearray([0])):
            with self.assertRaises(ValueError):
                obstruction_fraction(mask, maximum_pixels=4)

    def test_one_pixel_has_unknown_sharpness(self):
        sample = GrayFrame(SOURCE, STREAM, 0, 1, 1, bytes([128]))
        self.assertIsNone(dict(measure(sample, maximum_pixels=1))[Metric.SHARPNESS])

    def test_explicit_pixel_budget_rejects_before_measurement(self):
        with self.assertRaises(MeasurementUnavailable):
            measure(synthetic_person(), maximum_pixels=255)
        gate = QualityGate(SOURCE, replace(calibrated_policy(), maximum_pixels=255))
        decision = assess(gate, synthetic_person())
        self.assertEqual(Quality.UNKNOWN, decision.quality)
        self.assertEqual(QualityReason.RESOURCE_LIMIT, decision.findings[0].reason)
        self.assertFalse(decision.metrics)

    def test_missing_oversized_and_mismatched_target_context_is_unknown(self):
        for kwargs in ({"target_width": None}, {"target_height": None},
                       {"occlusion_fraction": None}, {"target_width": 17}):
            with self.subTest(kwargs=kwargs):
                gate = QualityGate(SOURCE, calibrated_policy())
                decision = assess(gate, synthetic_person(), **kwargs)
                self.assertEqual(Quality.UNKNOWN, decision.quality)
        sample = synthetic_person()
        wrong = replace(context(sample), frame=FrameIdentity(SOURCE, STREAM, 99))
        gate = QualityGate(SOURCE, calibrated_policy())
        decision = gate.assess(sample, execution=Execution.READY, context=wrong)
        self.assertEqual(QualityReason.CONTEXT_MISMATCH, decision.findings[0].reason)
        with self.assertRaises(MeasurementUnavailable):
            measure(sample, maximum_pixels=4096, context=wrong)

    def test_reason_and_metrics_are_displayable_without_retaining_pixels(self):
        gate = QualityGate(SOURCE, calibrated_policy())
        decision = assess(gate, synthetic_person(condition="dark"))
        values = decision.metric_values()
        self.assertLess(values["mean_luminance"], .1)
        self.assertIn(Metric.LUMINANCE, [finding.metric for finding in decision.findings])
        self.assertNotIn("pixels", repr(decision))
        values["width"] = 123
        self.assertEqual(16, decision.metric_values()["width"])
        self.assertFalse(any(isinstance(value, GrayFrame) for value in vars(gate).values()))

    def test_policy_and_context_require_finite_explicit_calibration(self):
        policy = calibrated_policy()
        for changes in ({"recovery_frames": 1}, {"recovery_frames": True}, {"maximum_pixels": 0},
                        {"version": 0}, {"rules": ()}, {"rules": policy.rules + (policy.rules[0],)},
                        {"rules": list(policy.rules)}, {"detector": "unknown"}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                replace(policy, **changes)
        for values in ((0, .5, .4, 1), (0, .1, 1, float("inf")), (0, True, 1, 1),
                       (0, .1, 1, 10**1000), (0, 0, 2, 2)):
            with self.assertRaises(ValueError):
                MetricRule(Metric.LUMINANCE, *values)
        for changes in ({"target_width": 0}, {"target_height": True},
                        {"occlusion_fraction": float("nan")}, {"detector_confidence": 1.01}):
            with self.assertRaises(ValueError):
                context(synthetic_person(), **changes)


class QualityGateTests(unittest.TestCase):
    def test_dark_blurred_saturated_and_obstructed_inputs_fail_both_conclusions(self):
        for detector in ("person", "owner_verification", "entrance_crossing", "presence"):
            for condition in ("dark", "blurred", "saturated", "obstructed"):
                with self.subTest(detector=detector, condition=condition):
                    gate, _ = ready_gate(detector)
                    sample = synthetic_person(2, condition=condition)
                    occlusion = obstruction_fraction(bytes([1, 0]) * 128, maximum_pixels=256) if condition == "obstructed" else 0
                    decision = assess(gate, sample, occlusion_fraction=occlusion)
                    self.assertEqual(Quality.INSUFFICIENT, decision.quality)
                    for observation in (Observation.PRESENT, Observation.ABSENT):
                        result = gate.guard_result(decision, Detection(observation, Reason.EVALUATED),
                                                   execution=Execution.SUCCEEDED, frame=FrameIdentity.from_frame(sample))
                        self.assertEqual(Observation.UNKNOWN, result.observation)

    def test_small_target_and_resolution_block_positive_and_negative(self):
        for sample, extra in ((synthetic_person(2), {"target_width": 2}),
                              (synthetic_person(2), {"target_height": 2}),
                              (synthetic_person(2, width=4, height=4), {})):
            gate, _ = ready_gate()
            decision = assess(gate, sample, **extra)
            self.assertEqual(Quality.INSUFFICIENT, decision.quality)
            for observation in (Observation.PRESENT, Observation.ABSENT):
                self.assertEqual(Observation.UNKNOWN, gate.guard_result(
                    decision, Detection(observation, Reason.EVALUATED), execution=Execution.SUCCEEDED,
                    frame=FrameIdentity.from_frame(sample),
                ).observation)

    def test_clipped_pixels_block_results_even_when_mean_luminance_and_sharpness_are_good(self):
        gate, _ = ready_gate()
        sample = GrayFrame(SOURCE, STREAM, 2, 16, 16, bytes([0, 255]) * 128)
        decision = assess(gate, sample)
        self.assertEqual(Quality.INSUFFICIENT, decision.quality)
        self.assertEqual((Metric.SATURATION,), tuple(finding.metric for finding in decision.findings))
        for observation in (Observation.PRESENT, Observation.ABSENT):
            result = gate.guard_result(decision, Detection(observation, Reason.EVALUATED),
                                       execution=Execution.SUCCEEDED, frame=decision.frame)
            self.assertEqual(Observation.UNKNOWN, result.observation)

    def test_obstruction_context_alone_is_a_required_prerequisite(self):
        gate, _ = ready_gate()
        decision = assess(gate, synthetic_person(2), occlusion_fraction=.5)
        self.assertEqual(Quality.INSUFFICIENT, decision.quality)
        self.assertEqual((Metric.OCCLUSION,), tuple(finding.metric for finding in decision.findings))

    def test_source_and_policy_replacement_require_a_fresh_gate(self):
        gate, _ = ready_gate()
        with self.assertRaises(AttributeError):
            gate.policy = replace(gate.policy, version=2)
        with self.assertRaises(AttributeError):
            gate.source_id = OTHER
        replacement = QualityGate(SOURCE, replace(gate.policy, version=2))
        decision = assess(replacement, synthetic_person(2))
        self.assertEqual(2, decision.policy_version)
        self.assertFalse(decision.allows_conclusion)

    def test_degraded_band_requires_unknown_for_both_result_directions(self):
        gate, _ = ready_gate()
        decision = assess(gate, synthetic_person(2), target_width=5)
        self.assertEqual(Quality.DEGRADED, decision.quality)
        self.assertFalse(decision.allows_conclusion)
        self.assertIn(QualityReason.BELOW_SUFFICIENT, [finding.reason for finding in decision.findings])

    def test_recovery_needs_consecutive_good_frames_and_bad_frame_resets_it(self):
        gate = QualityGate(SOURCE, calibrated_policy(recovery_frames=3))
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(0)).quality)
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(1)).quality)
        self.assertEqual(Quality.INSUFFICIENT, assess(gate, synthetic_person(2, condition="dark")).quality)
        for sequence in (3, 4):
            decision = assess(gate, synthetic_person(sequence))
            self.assertEqual(Quality.DEGRADED, decision.quality)
            self.assertEqual(QualityReason.RECOVERING, decision.findings[0].reason)
        self.assertEqual(Quality.SUFFICIENT, assess(gate, synthetic_person(5)).quality)
        self.assertEqual(Quality.SUFFICIENT, assess(gate, synthetic_person(6)).quality)

    def test_stream_gap_regression_duplicate_and_geometry_changes_reset_recovery(self):
        for changed in (synthetic_person(2, stream=UUID(int=11)), synthetic_person(10),
                        synthetic_person(2, width=20), synthetic_person(0), synthetic_person(1)):
            with self.subTest(sequence=changed.sequence, stream=changed.stream_id, width=changed.width):
                gate, _ = ready_gate()
                self.assertFalse(assess(gate, changed).allows_conclusion)
        gate, _ = ready_gate()
        self.assertEqual(Quality.UNKNOWN, assess(gate, synthetic_person(0)).quality)
        self.assertEqual(Quality.UNKNOWN, assess(gate, synthetic_person(1)).quality)
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(2)).quality)
        self.assertEqual(Quality.SUFFICIENT, assess(gate, synthetic_person(3)).quality)

    def test_different_source_or_detector_cannot_reuse_quality_recovery(self):
        gate, decision = ready_gate()
        wrong = replace(synthetic_person(2), source_id=OTHER)
        self.assertEqual(Quality.UNKNOWN, gate.assess(wrong, execution=Execution.READY).quality)
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(2)).quality)
        other = QualityGate(SOURCE, calibrated_policy("owner_verification"))
        result = other.guard_result(decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                                    execution=Execution.SUCCEEDED, frame=decision.frame)
        self.assertEqual(Observation.UNKNOWN, result.observation)

    def test_stopped_failed_skipped_or_unknown_detector_invalidates_quality(self):
        for execution in (Execution.STOPPED, Execution.FAILED, Execution.SKIPPED, Execution.UNAVAILABLE):
            gate, _ = ready_gate()
            sample = synthetic_person(2)
            decision = gate.assess(sample, context=context(sample), execution=execution)
            self.assertEqual(Quality.UNKNOWN, decision.quality)
            self.assertEqual(QualityReason.EXECUTION_UNAVAILABLE, decision.findings[0].reason)
            self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(3)).quality)

    def test_inference_must_actually_complete_and_result_remains_unknown_on_failure(self):
        for execution in Execution:
            if execution is Execution.SUCCEEDED:
                continue
            gate, decision = ready_gate()
            result = gate.guard_result(decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                                       execution=execution, frame=decision.frame)
            self.assertEqual(Observation.UNKNOWN, result.observation)
            if execution is not Execution.READY:
                # An unavailable batch also drops the assessment it never completed.
                self.assertEqual(Reason.STALE, gate.guard_result(
                    decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                    execution=Execution.SUCCEEDED, frame=decision.frame,
                ).reason)
        gate, decision = ready_gate()
        for result in (None, Detection(Observation.UNKNOWN, Reason.MODEL_UNAVAILABLE)):
            guarded = gate.guard_result(decision, result, execution=Execution.SUCCEEDED, frame=decision.frame)
            self.assertEqual(Observation.UNKNOWN, guarded.observation)
        for observed in (Observation.ABSENT, Observation.PRESENT):
            result = Detection(observed, Reason.EVALUATED)
            self.assertEqual(result, gate.guard_result(decision, result, execution=Execution.SUCCEEDED,
                                                       frame=decision.frame))

    def test_worker_stop_without_new_frame_invalidates_pending_conclusion(self):
        gate, decision = ready_gate()
        self.assertEqual(Detection(Observation.UNKNOWN, Reason.NOT_STARTED),
                         gate.invalidate(execution=Execution.STOPPED))
        result = gate.guard_result(decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                                   execution=Execution.SUCCEEDED, frame=decision.frame)
        self.assertEqual(Observation.UNKNOWN, result.observation)
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(2)).quality)
        self.assertEqual(Quality.SUFFICIENT, assess(gate, synthetic_person(3)).quality)
        with self.assertRaises(ValueError):
            gate.invalidate(execution=Execution.READY)

    def test_old_quality_decision_cannot_authorize_late_result(self):
        gate, old = ready_gate()
        assess(gate, synthetic_person(2, condition="dark"))
        result = gate.guard_result(old, Detection(Observation.ABSENT, Reason.EVALUATED),
                                   execution=Execution.SUCCEEDED, frame=old.frame)
        self.assertEqual(Reason.STALE, result.reason)
        gate, decision = ready_gate()
        result = gate.guard_result(decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                                   execution=Execution.SUCCEEDED, frame=FrameIdentity(SOURCE, STREAM, 3))
        self.assertEqual(Observation.UNKNOWN, result.observation)

    def test_measurement_failure_is_unknown_without_exception_or_pixel_disclosure(self):
        gate, old = ready_gate()
        with patch('app.detection.quality.gate.measure', side_effect=RuntimeError("SYNTHETIC_PRIVATE_VALUE")):
            decision = assess(gate, synthetic_person(2))
        self.assertEqual(Quality.UNKNOWN, decision.quality)
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", repr(decision))
        self.assertEqual(QualityReason.MEASUREMENT_FAILED, decision.findings[0].reason)
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(3)).quality)
        self.assertEqual(Observation.UNKNOWN, gate.guard_result(
            old, Detection(Observation.PRESENT, Reason.EVALUATED),
            execution=Execution.SUCCEEDED, frame=old.frame,
        ).observation)

    def test_detector_specific_thresholds_do_not_globally_disable_critical_observations(self):
        person = QualityGate(SOURCE, calibrated_policy())
        critical_policy = DetectorQualityPolicy("camera_tamper", 1, (
            MetricRule(Metric.WIDTH, 8, 8, 64, 64), MetricRule(Metric.HEIGHT, 8, 8, 64, 64),
        ), 2, 4096)
        critical = QualityGate(SOURCE, critical_policy)
        live_frames, recording_frames = [], []
        for sequence in range(3):
            sample = synthetic_person(sequence, condition="dark")
            live_frames.append(sample)
            recording_frames.append(sample)
            self.assertFalse(assess(person, sample).allows_conclusion)
            critical_decision = critical.assess(sample, execution=Execution.READY)
        self.assertTrue(critical_decision.allows_conclusion)
        self.assertEqual(3, len(live_frames))
        self.assertEqual(3, len(recording_frames))
        self.assertTrue(all(live is recorded for live, recorded in zip(live_frames, recording_frames)))

    def test_optional_confidence_is_a_detector_specific_prerequisite_when_configured(self):
        policy = calibrated_policy("owner_verification")
        policy = replace(policy, rules=policy.rules + (MetricRule(Metric.CONFIDENCE, .5, .8, 1, 1),))
        gate = QualityGate(SOURCE, policy)
        self.assertEqual(Quality.UNKNOWN, assess(gate, synthetic_person(0)).quality)
        self.assertEqual(Quality.INSUFFICIENT, assess(gate, synthetic_person(1), detector_confidence=.4).quality)
        self.assertEqual(Quality.DEGRADED, assess(gate, synthetic_person(2), detector_confidence=.7).quality)
        self.assertFalse(assess(gate, synthetic_person(3), detector_confidence=.9).allows_conclusion)
        self.assertTrue(assess(gate, synthetic_person(4), detector_confidence=.9).allows_conclusion)


class QualitySchedulerIntegrationTests(unittest.TestCase):
    def test_skipped_quality_does_not_turn_person_owner_or_dependents_into_absence(self):
        now = [0]
        scheduler = InferenceScheduler(clock_ns=lambda: now[0])
        detector = SyntheticNegative()
        scheduler.register(SOURCE, detector, SourcePolicy(1, 8, 100, 100, 100, 4096))
        gate = QualityGate(SOURCE, calibrated_policy())
        live, recordings = [], []
        with patch.object(socket.socket, 'connect', side_effect=AssertionError("unexpected network")):
            for sequence in range(4):
                sample = synthetic_person(sequence, condition="clear" if sequence < 2 else "dark")
                live.append(sample)
                recordings.append(sample)
                now[0] = sequence
                decision = assess(gate, sample)
                scheduler.offer(sample, quality=decision.quality)
                scheduler.run_one()
        self.assertEqual(1, detector.calls)
        self.assertEqual(4, len(live))
        self.assertEqual(4, len(recordings))
        snapshot = scheduler.snapshot(SOURCE)
        self.assertEqual(Observation.UNKNOWN, snapshot.result.observation)
        self.assertEqual(Reason.QUALITY, snapshot.result.reason)
        for dependent in ("owner_verification", "presence", "entrance_crossing"):
            dependent_gate, decision = ready_gate(dependent)
            guarded = dependent_gate.guard_result(decision, snapshot.result,
                                                  execution=Execution.SUCCEEDED, frame=decision.frame)
            self.assertEqual(Observation.UNKNOWN, guarded.observation)


class QualityLifecycleInvalidationTests(unittest.TestCase):
    """A published conclusion never outlives the quality that authorized it."""

    def setUp(self):
        self.now = [0]
        self.scheduler, self.gate, self.decision = published_negative(self.now)
        self.assertEqual(Observation.ABSENT, self.scheduler.snapshot(SOURCE).result.observation)

    def published(self):
        self.now[0] += 1
        return self.scheduler.snapshot(SOURCE).result

    def test_worker_stop_or_failure_invalidates_the_published_negative(self):
        for execution in (Execution.STOPPED, Execution.FAILED, Execution.SKIPPED,
                          Execution.UNAVAILABLE):
            with self.subTest(execution=execution):
                self.setUp()
                reason = unavailable_reason(execution)
                self.assertEqual(Detection(Observation.UNKNOWN, reason),
                                 self.gate.invalidate(execution=execution))
                published = self.published()
                self.assertEqual(Observation.UNKNOWN, published.observation)
                self.assertEqual(reason, published.reason)
                self.assertEqual(Health.UNAVAILABLE, self.scheduler.snapshot(SOURCE).health)
                self.assertEqual(Observation.UNKNOWN, self.gate.guard_result(
                    self.decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                    execution=Execution.SUCCEEDED, frame=self.decision.frame,
                ).observation)

    def test_incomplete_batch_invalidates_the_published_negative(self):
        for execution in (Execution.FAILED, Execution.STOPPED, Execution.SKIPPED,
                          Execution.UNAVAILABLE):
            with self.subTest(execution=execution):
                self.setUp()
                guarded = self.gate.guard_result(
                    self.decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                    execution=execution, frame=self.decision.frame)
                self.assertEqual(Observation.UNKNOWN, guarded.observation)
                published = self.published()
                self.assertEqual(Observation.UNKNOWN, published.observation)
                self.assertEqual(unavailable_reason(execution), published.reason)
                self.assertEqual(Reason.STALE, self.gate.guard_result(
                    self.decision, Detection(Observation.ABSENT, Reason.EVALUATED),
                    execution=Execution.SUCCEEDED, frame=self.decision.frame,
                ).reason)

    def test_recovery_after_a_stop_never_republishes_the_old_conclusion(self):
        self.gate.invalidate(execution=Execution.STOPPED)
        self.assertEqual(Observation.UNKNOWN, self.published().observation)
        recovering = assess(self.gate, synthetic_person(3))
        self.assertEqual(QualityReason.RECOVERING, recovering.findings[0].reason)
        published = self.published()
        self.assertEqual(Observation.UNKNOWN, published.observation)
        self.assertEqual(Reason.QUALITY, published.reason)
        self.assertEqual(Observation.UNKNOWN, self.gate.guard_result(
            self.decision, Detection(Observation.ABSENT, Reason.EVALUATED),
            execution=Execution.SUCCEEDED, frame=self.decision.frame,
        ).observation)
        self.assertTrue(assess(self.gate, synthetic_person(4)).allows_conclusion)
        self.assertEqual(Observation.UNKNOWN, self.published().observation)

    def test_unusable_frame_invalidates_the_published_negative_on_its_own(self):
        # Fail-unknown does not depend on the caller remembering to offer it.
        self.assertEqual(Quality.INSUFFICIENT,
                         assess(self.gate, synthetic_person(3, condition="dark")).quality)
        published = self.published()
        self.assertEqual(Observation.UNKNOWN, published.observation)
        self.assertEqual(Reason.QUALITY, published.reason)

    def test_invalidation_drops_the_pending_frame_as_well(self):
        self.now[0] += 8
        self.assertTrue(self.scheduler.offer(synthetic_person(3), quality=Quality.SUFFICIENT))
        self.assertTrue(self.scheduler.snapshot(SOURCE).pending)
        self.gate.invalidate(execution=Execution.STOPPED)
        snapshot = self.scheduler.snapshot(SOURCE)
        self.assertFalse(snapshot.pending)
        self.assertEqual(Observation.UNKNOWN, snapshot.result.observation)

    def test_result_sink_and_invalidation_reason_are_explicit(self):
        for sink in (object(), self.scheduler.snapshot, 0, "scheduler"):
            with self.assertRaises(ValueError):
                QualityGate(SOURCE, calibrated_policy(), results=sink)
        for reason in (Reason.EVALUATED, Reason.WARMUP, "inference_stale", None):
            with self.assertRaises(ValueError):
                self.scheduler.invalidate(SOURCE, reason=reason)
        with self.assertRaises(ValueError):
            self.scheduler.invalidate(str(SOURCE), reason=Reason.NOT_STARTED)
        self.assertEqual(Observation.ABSENT, self.scheduler.snapshot(SOURCE).result.observation)
        # An unregistered source publishes no snapshot, so it revokes nothing.
        self.assertIsNone(self.scheduler.invalidate(OTHER, reason=Reason.NOT_STARTED))
        for execution in (Execution.READY, Execution.SUCCEEDED, "stopped", None):
            with self.assertRaises(ValueError):
                unavailable_reason(execution)


if __name__ == '__main__':
    unittest.main()
