"""Generated-frame contracts for calibration-bound spatial observations."""

import unittest
from uuid import UUID

from app.detection.foundation import GrayFrame, Quality
from app.detection.spatial import (
    CameraTamperAnalyzer, CameraTamperPolicy, RoiCalibration, RoiMovementAnalyzer,
    RoiMovementPolicy, SpatialContext, SpatialReason, SpatialState,
)


SOURCE, OTHER_SOURCE, STREAM = UUID(int=1), UUID(int=2), UUID(int=3)


def reference(sequence=0, *, source=SOURCE, stream=STREAM):
    # Generated gradient only; it represents neither a room nor a person.
    return GrayFrame(source, stream, sequence, 8, 8,
                     bytes((x * 20 + y * 3) for y in range(8) for x in range(8)))


def changed(sample, *, x_range=range(2, 6), y_range=range(2, 6), value=255):
    pixels = bytearray(sample.pixels)
    for y in y_range:
        for x in x_range:
            pixels[y * sample.width + x] = value
    return GrayFrame(sample.source_id, sample.stream_id, sample.sequence,
                     sample.width, sample.height, bytes(pixels))


def translated_right(sample, sequence):
    pixels = bytearray(sample.width * sample.height)
    for y in range(sample.height):
        for x in range(1, sample.width):
            pixels[y * sample.width + x] = sample.pixels[y * sample.width + x - 1]
    return GrayFrame(sample.source_id, sample.stream_id, sequence,
                     sample.width, sample.height, bytes(pixels))


def context(sample, **changes):
    values = dict(source_id=sample.source_id, stream_id=sample.stream_id,
                  sequence=sample.sequence, quality=Quality.SUFFICIENT,
                  occlusion_fraction=0.0)
    values.update(changes)
    return SpatialContext(**values)


def calibration(source=SOURCE):
    return RoiCalibration(source, 4, ((.25, .25), (.75, .25), (.75, .75), (.25, .75)))


def movement_policy(**changes):
    values = dict(pixel_delta=20, changed_fraction=.5, confirmation_frames=2,
                  maximum_pixels=64, maximum_occlusion_fraction=.4,
                  minimum_reference_coverage=.5, maximum_translation_pixels=2)
    values.update(changes)
    return RoiMovementPolicy(**values)


def tamper_policy(**changes):
    values = dict(pixel_delta=20, changed_fraction=.8, confirmation_frames=2,
                  maximum_pixels=64, occlusion_fraction=.7)
    values.update(changes)
    return CameraTamperPolicy(**values)


class RoiMovementTests(unittest.TestCase):
    def setUp(self):
        self.reference = reference()
        self.analyzer = RoiMovementAnalyzer(calibration(), self.reference, movement_policy())

    def assess(self, sample, **changes):
        return self.analyzer.assess(sample, context(sample, **changes))

    def test_displacement_requires_consecutive_unoccluded_frames(self):
        self.assertEqual(SpatialState.UNKNOWN, self.assess(reference(0)).state)
        self.assertEqual(SpatialState.NOT_DETECTED, self.assess(reference(1)).state)
        first = self.assess(changed(reference(2)))
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.WARMUP),
                         (first.state, first.reason))
        confirmed = self.assess(changed(reference(3)))
        self.assertEqual((SpatialState.DETECTED, SpatialReason.EVALUATED),
                         (confirmed.state, confirmed.reason))
        self.assertEqual(2, confirmed.confirmation_count)

    def test_occlusion_never_becomes_movement_or_no_movement(self):
        self.assess(reference(0))
        self.assess(changed(reference(1)))
        occluded = self.assess(changed(reference(2)), occlusion_fraction=.5)
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.OCCLUDED),
                         (occluded.state, occluded.reason))
        recovered = self.assess(reference(3))
        self.assertEqual(SpatialState.NOT_DETECTED, recovered.state)
        missing = self.assess(reference(4), occlusion_fraction=None)
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.QUALITY_UNAVAILABLE),
                         (missing.state, missing.reason))

    def test_explicit_global_translation_compensates_camera_motion(self):
        self.assess(reference(0))
        shifted = translated_right(reference(), 1)
        compensated = self.assess(shifted, translation_x=1, translation_y=0)
        self.assertEqual(SpatialState.NOT_DETECTED, compensated.state)

        self.analyzer.reset()
        self.assess(reference(0))
        uncompensated = self.assess(shifted)
        self.assertEqual(SpatialState.UNKNOWN, uncompensated.state)
        self.assertEqual(SpatialReason.WARMUP, uncompensated.reason)

    def test_quality_context_and_stream_loss_fail_unknown(self):
        self.assess(reference(0))
        insufficient = self.assess(reference(1), quality=Quality.INSUFFICIENT)
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.QUALITY_UNAVAILABLE),
                         (insufficient.state, insufficient.reason))
        gap = self.assess(reference(3))
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.DISCONTINUITY),
                         (gap.state, gap.reason))
        wrong_context = context(reference(4), source_id=OTHER_SOURCE)
        decision = self.analyzer.assess(reference(4), wrong_context)
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.CONTEXT_MISMATCH),
                         (decision.state, decision.reason))

    def test_translation_and_reference_coverage_are_bounded(self):
        self.assess(reference(0))
        too_far = self.assess(reference(1), translation_x=3, translation_y=0)
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.INSUFFICIENT_COVERAGE),
                         (too_far.state, too_far.reason))
        self.analyzer = RoiMovementAnalyzer(calibration(), self.reference,
                                            movement_policy(minimum_reference_coverage=.9,
                                                            maximum_translation_pixels=3))
        self.assess(reference(0))
        insufficient = self.assess(reference(1), translation_x=3, translation_y=0)
        self.assertEqual(SpatialReason.INSUFFICIENT_COVERAGE, insufficient.reason)


class CameraTamperTests(unittest.TestCase):
    def make(self):
        sample = reference()
        return CameraTamperAnalyzer(calibration(), sample, tamper_policy())

    def test_scene_change_requires_temporal_confirmation(self):
        analyzer = self.make()
        self.assertEqual(SpatialState.UNKNOWN, analyzer.assess(reference(0), context(reference(0))).state)
        first = analyzer.assess(changed(reference(1), x_range=range(8), y_range=range(8)),
                                context(reference(1)))
        self.assertEqual((SpatialState.UNKNOWN, SpatialReason.WARMUP), (first.state, first.reason))
        confirmed = analyzer.assess(changed(reference(2), x_range=range(8), y_range=range(8)),
                                    context(reference(2)))
        self.assertEqual((SpatialState.DETECTED, SpatialReason.EVALUATED),
                         (confirmed.state, confirmed.reason))

    def test_persistent_trusted_lens_occlusion_is_a_tamper_signal(self):
        analyzer = self.make()
        analyzer.assess(reference(0), context(reference(0)))
        first = analyzer.assess(reference(1), context(reference(1), occlusion_fraction=.8))
        confirmed = analyzer.assess(reference(2), context(reference(2), occlusion_fraction=.8))
        self.assertEqual(SpatialState.UNKNOWN, first.state)
        self.assertEqual(SpatialState.DETECTED, confirmed.state)

    def test_missing_occlusion_evidence_and_bad_quality_do_not_claim_safe_scene(self):
        analyzer = self.make()
        analyzer.assess(reference(0), context(reference(0)))
        missing = analyzer.assess(reference(1), context(reference(1), occlusion_fraction=None))
        poor = analyzer.assess(reference(2), context(reference(2), quality=Quality.DEGRADED))
        self.assertEqual(SpatialState.UNKNOWN, missing.state)
        self.assertEqual(SpatialState.UNKNOWN, poor.state)


class SpatialValidationTests(unittest.TestCase):
    def test_calibration_policies_and_context_reject_implicit_or_unsafe_values(self):
        for polygon in ((), ((0, 0), (1, 0)), ((0, 0), (1, 0), (1, 0)),
                        ((0, 0), (1, 0), (.5, 0))):
            with self.subTest(polygon=polygon), self.assertRaises(ValueError):
                RoiCalibration(SOURCE, 1, polygon)
        for changes in ({"confirmation_frames": 1}, {"maximum_pixels": True},
                        {"changed_fraction": 0}, {"pixel_delta": 256}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                movement_policy(**changes)
        with self.assertRaises(ValueError):
            SpatialContext(SOURCE, STREAM, 0, Quality.SUFFICIENT, 0, translation_x=1)

    def test_reference_source_and_pixel_budget_cannot_be_reused(self):
        with self.assertRaises(ValueError):
            RoiMovementAnalyzer(calibration(), reference(source=OTHER_SOURCE), movement_policy())
        with self.assertRaises(ValueError):
            CameraTamperAnalyzer(calibration(), reference(), tamper_policy(maximum_pixels=1))


if __name__ == "__main__":
    unittest.main()
