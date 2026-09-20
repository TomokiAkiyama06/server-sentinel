"""Generated grayscale scenes for calibrated ROI movement and camera tamper."""

import base64
from dataclasses import replace
from datetime import datetime, timezone
import inspect
import sqlite3
import unittest
from uuid import UUID

from app.cameras.registry.models import SourceType
from app.detection.foundation import GrayFrame, Observation, Quality
from app.detection.roi import (
    MAXIMUM_BATCH, Calibration, CalibrationArchive, CalibrationRecord,
    CriticalDelivery, CriticalKind, OwnerCalibrationOperations, Policy,
    SceneDetector,
)
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


SOURCE = UUID(int=301)
PROFILE = UUID(int=302)
STREAM = UUID(int=303)
NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
WIDTH = HEIGHT = 12
POLYGON = ((4, 4), (7, 4), (7, 7), (4, 7))


def pixels():
    """Non-symmetric generated texture; no real scene or person fixture."""
    return bytes((x * 29 + y * 47 + x * y * 11) % 251 + 2
                 for y in range(HEIGHT) for x in range(WIDTH))


def transformed(source, transform, *, region=None, fill=0):
    output = bytearray(source)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            if region is None or region[0] <= x <= region[2] and region[1] <= y <= region[3]:
                previous_x, previous_y = x - transform[0], y - transform[1]
                output[y * WIDTH + x] = (source[previous_y * WIDTH + previous_x]
                                         if 0 <= previous_x < WIDTH and 0 <= previous_y < HEIGHT else fill)
    return bytes(output)


def frame(sequence, data=None, *, source=SOURCE, stream=STREAM):
    return GrayFrame(source, stream, sequence, WIDTH, HEIGHT, pixels() if data is None else data)


def policy(**changes):
    values = dict(
        global_search_pixels=2, roi_search_pixels=2,
        global_quarter_turns=(0,), roi_quarter_turns=(0,),
        maximum_match_error=.01, minimum_match_margin=.001, minimum_coverage=.8,
        minimum_background_variance=.002, minimum_roi_variance=.002,
        movement_pixels=1, camera_shift_pixels=1,
        dark_pixel_ceiling=5, camera_dark_fraction=.9,
        confirmation_frames=2, confirmation_ns=10,
        maximum_gap_ns=100, loss_correlation_ns=30,
        maximum_pixels=256, maximum_comparisons=100_000,
    )
    values.update(changes)
    return Policy(**values)


def covered():
    """Generated bright, textured non-dark scene that does not register."""
    return bytes((x * 3 + y * 5) % 37 + 210 for y in range(HEIGHT) for x in range(WIDTH))


def near_dark():
    """Generated scene already at the obscured threshold, yet still textured."""
    return bytes(255 if index % 16 == 0 else 0 for index in range(WIDTH * HEIGHT))


def repetitive(shift=0):
    """Generated period-two stripes: several bounded transforms match equally."""
    return bytes(40 if (x - shift) % 2 == 0 else 200
                 for y in range(HEIGHT) for x in range(WIDTH))


def calibration(source_type=SourceType.LOCAL_UVC, *, version=1, rules=None, reference=None,
                shape=POLYGON):
    return Calibration(UUID(int=400 + version), SOURCE, source_type, PROFILE, version, NOW,
                       shape, frame(0, reference), rules or policy())


def detector(source_type=SourceType.LOCAL_UVC, *, rules=None, reference=None, shape=POLYGON):
    return SceneDetector(calibration(source_type, rules=rules, reference=reference, shape=shape))


def inspect_scene(instance, sample, monotonic_ns, *, movement=Quality.SUFFICIENT,
                  tamper=Quality.SUFFICIENT, occluded=None):
    return instance.inspect(sample, monotonic_ns=monotonic_ns, observed_at=NOW,
                            movement_quality=movement, tamper_quality=tamper,
                            roi_occluded=occluded)


class SceneDetectorTests(unittest.TestCase):
    def test_local_and_remote_calibrations_confirm_controlled_roi_displacement(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        for source_type in SourceType:
            with self.subTest(source_type=source_type):
                instance = detector(source_type)
                inspect_scene(instance, frame(0), 0)
                candidate = inspect_scene(instance, frame(1, moved), 10)
                confirmed = inspect_scene(instance, frame(2, moved), 20)
                self.assertEqual(Observation.UNKNOWN, candidate.movement)
                self.assertEqual(Observation.PRESENT, confirmed.movement)
                self.assertEqual("server_geometry_changed", confirmed.movement_reason)
                self.assertEqual((CriticalKind.SERVER_MOVEMENT,), tuple(item.kind for item in confirmed.critical))
                self.assertEqual(source_type, confirmed.critical[0].source_type)
                self.assertIsNotNone(confirmed.relative_transform)

    def test_global_camera_shift_is_tamper_not_server_movement(self):
        shifted = transformed(pixels(), (1, 0))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        first = inspect_scene(instance, frame(1, shifted), 10)
        confirmed = inspect_scene(instance, frame(2, shifted), 20)
        self.assertEqual(Observation.ABSENT, first.movement)
        self.assertEqual(Observation.ABSENT, confirmed.movement)
        self.assertEqual(Observation.PRESENT, confirmed.tamper)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in confirmed.critical))
        self.assertEqual((1, 0), (confirmed.global_transform.dx, confirmed.global_transform.dy))
        self.assertEqual((0, 0), (confirmed.relative_transform.dx, confirmed.relative_transform.dy))

    def test_temporary_roi_occlusion_never_confirms_movement(self):
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        hidden = inspect_scene(instance, frame(1), 10, occluded=True)
        restored = inspect_scene(instance, frame(2), 20)
        self.assertEqual(Observation.UNKNOWN, hidden.movement)
        self.assertEqual("roi_occluded", hidden.movement_reason)
        self.assertFalse(hidden.critical)
        self.assertEqual(Observation.ABSENT, restored.movement)
        self.assertFalse(restored.critical)

    def test_dark_scene_requires_persistence_then_confirms_tamper(self):
        instance = detector()
        dark = bytes(WIDTH * HEIGHT)
        inspect_scene(instance, frame(0), 0)
        first = inspect_scene(instance, frame(1, dark), 10)
        confirmed = inspect_scene(instance, frame(2, dark), 20)
        self.assertEqual(Observation.UNKNOWN, first.tamper)
        self.assertEqual(Observation.PRESENT, confirmed.tamper)
        self.assertEqual("scene_obscured_or_changed", confirmed.tamper_reason)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in confirmed.critical))

    def test_persistent_unmatched_scene_confirms_camera_tamper(self):
        instance = detector()
        obstruction = covered()
        inspect_scene(instance, frame(0), 0)
        first = inspect_scene(instance, frame(1, obstruction), 10)
        confirmed = inspect_scene(instance, frame(2, obstruction), 20)
        self.assertEqual(Observation.UNKNOWN, first.tamper)
        self.assertFalse(first.critical)
        self.assertEqual(Observation.PRESENT, confirmed.tamper)
        self.assertEqual("scene_unmatched_persistently", confirmed.tamper_reason)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in confirmed.critical))
        self.assertEqual(Observation.UNKNOWN, confirmed.movement)
        self.assertEqual("global_alignment_unavailable", confirmed.movement_reason)

    def test_ambiguous_registration_is_never_tamper_or_trustworthy_no_tamper(self):
        instance = detector(rules=policy(minimum_match_margin=.9))
        inspect_scene(instance, frame(0), 0)
        samples = [inspect_scene(instance, frame(index), index * 10) for index in range(1, 5)]
        for sample in samples:
            self.assertEqual(Observation.UNKNOWN, sample.tamper)
            self.assertEqual("global_alignment_unavailable", sample.tamper_reason)
            self.assertIsNone(sample.tamper_confidence)
            self.assertEqual(Observation.UNKNOWN, sample.movement)
            self.assertFalse(sample.critical)

    def test_source_loss_is_critical_only_when_trusted_and_correlated(self):
        shifted = transformed(pixels(), (1, 0))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, shifted), 10)
        untrusted = instance.source_lost(monotonic_ns=20, observed_at=NOW, health_signal_trusted=False)
        self.assertEqual(Observation.UNKNOWN, untrusted.tamper)
        self.assertFalse(untrusted.critical)

        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, shifted), 10)
        correlated = instance.source_lost(monotonic_ns=20, observed_at=NOW, health_signal_trusted=True)
        self.assertEqual(Observation.PRESENT, correlated.tamper)
        self.assertEqual("source_loss_after_scene_shift", correlated.tamper_reason)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in correlated.critical))
        expired = instance.source_lost(monotonic_ns=100, observed_at=NOW, health_signal_trusted=True)
        self.assertFalse(expired.critical)

    def test_detector_specific_quality_is_fail_unknown_without_cross_suppression(self):
        instance = detector()
        dark = bytes(WIDTH * HEIGHT)
        inspect_scene(instance, frame(0), 0)
        first = inspect_scene(instance, frame(1, dark), 10, movement=Quality.INSUFFICIENT)
        confirmed = inspect_scene(instance, frame(2, dark), 20, movement=Quality.INSUFFICIENT)
        self.assertEqual(Observation.UNKNOWN, first.movement)
        self.assertEqual(Observation.UNKNOWN, confirmed.movement)
        self.assertEqual(Observation.PRESENT, confirmed.tamper)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in confirmed.critical))

    def test_tamper_quality_failure_does_not_suppress_confirmed_roi_movement(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10, tamper=Quality.INSUFFICIENT)
        confirmed = inspect_scene(instance, frame(2, moved), 20, tamper=Quality.INSUFFICIENT)
        self.assertEqual(Observation.PRESENT, confirmed.movement)
        self.assertEqual(Observation.UNKNOWN, confirmed.tamper)
        self.assertEqual((CriticalKind.SERVER_MOVEMENT,), tuple(item.kind for item in confirmed.critical))

    def test_discontinuity_resets_confirmation_and_unknown_is_not_no_movement(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10)
        gap = inspect_scene(instance, frame(2, moved), 200)
        after_gap = inspect_scene(instance, frame(3, moved), 210)
        self.assertEqual(Observation.UNKNOWN, gap.movement)
        self.assertEqual("stream_or_sampling_discontinuity", gap.movement_reason)
        self.assertEqual(Observation.UNKNOWN, after_gap.movement)
        self.assertFalse(after_gap.critical)

    def test_calibration_without_a_usable_threshold_transform_is_refused(self):
        with self.assertRaises(ValueError):
            detector(rules=policy(minimum_coverage=1))

    def test_a_usable_rotation_does_not_satisfy_a_translation_threshold(self):
        rules = policy(minimum_coverage=1, global_quarter_turns=(0, 2))
        with self.assertRaises(ValueError):
            detector(rules=rules)

    def test_low_margin_match_stays_indeterminate_instead_of_confirming_tamper(self):
        rules = policy(camera_shift_pixels=2, minimum_coverage=.5)
        instance = detector(rules=rules, reference=repetitive())
        jittered = repetitive(1)
        inspect_scene(instance, frame(0, repetitive()), 0)
        samples = [inspect_scene(instance, frame(index, jittered), index * 10)
                   for index in range(1, 5)]
        for sample in samples:
            self.assertEqual(Observation.UNKNOWN, sample.tamper)
            self.assertEqual("global_alignment_unavailable", sample.tamper_reason)
            self.assertIsNone(sample.tamper_confidence)
            self.assertEqual(Observation.UNKNOWN, sample.movement)
            self.assertFalse(sample.critical)

    def test_frame_from_another_source_ends_temporal_confirmation(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10)
        with self.assertRaises(ValueError):
            inspect_scene(instance, frame(2, moved, source=UUID(int=399)), 20)
        after = inspect_scene(instance, frame(3, moved), 30)
        self.assertEqual(Observation.UNKNOWN, after.movement)
        self.assertEqual("awaiting_confirmation", after.movement_reason)
        self.assertFalse(after.critical)

    def test_incompatible_geometry_advances_the_observed_frame_progression(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10)
        wider = GrayFrame(SOURCE, STREAM, 2, WIDTH + 1, HEIGHT, bytes((WIDTH + 1) * HEIGHT))
        mismatch = inspect_scene(instance, wider, 20)
        self.assertEqual("reference_shape_mismatch", mismatch.movement_reason)
        buffered = inspect_scene(instance, frame(2, moved), 30)
        self.assertEqual("clock_or_sequence_regression", buffered.movement_reason)
        self.assertEqual(Observation.UNKNOWN, buffered.movement)
        self.assertFalse(buffered.critical)

    def test_comparison_budget_covers_the_unmatched_scene_path(self):
        small = ((4, 4), (5, 4), (4, 5))
        rules = dict(roi_search_pixels=1, maximum_comparisons=100_000)
        generous = detector(rules=policy(**rules), shape=small)
        roi_work = len(generous.roi_points) * len(generous.roi_candidates)
        background = len(generous.background)
        self.assertLess(roi_work, background)
        registered_only = background * len(generous.global_candidates) + roi_work + WIDTH * HEIGHT
        with self.assertRaises(ValueError):
            detector(rules=policy(**dict(rules, maximum_comparisons=registered_only)), shape=small)
        detector(rules=policy(**dict(rules, maximum_comparisons=registered_only - roi_work + background)),
                 shape=small)

    def test_reference_already_at_the_dark_threshold_is_refused(self):
        reference = near_dark()
        rules = policy()
        dark = sum(value <= rules.dark_pixel_ceiling for value in reference) / len(reference)
        self.assertGreaterEqual(dark, rules.camera_dark_fraction)
        with self.assertRaises(ValueError):
            detector(reference=reference)

    def test_rejected_source_loss_observation_ends_temporal_confirmation(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10)
        with self.assertRaises(ValueError):
            instance.source_lost(monotonic_ns=-1, observed_at=NOW, health_signal_trusted=True)
        after = inspect_scene(instance, frame(2, moved), 20)
        self.assertEqual(Observation.UNKNOWN, after.movement)
        self.assertEqual("awaiting_confirmation", after.movement_reason)
        self.assertFalse(after.critical)

    def test_search_window_must_reach_its_own_displacement_thresholds(self):
        with self.assertRaises(ValueError):
            policy(roi_search_pixels=1, movement_pixels=2)
        with self.assertRaises(ValueError):
            policy(global_search_pixels=1, camera_shift_pixels=2)
        policy(roi_search_pixels=2, movement_pixels=2, global_search_pixels=2, camera_shift_pixels=2)

    def test_frames_from_a_retired_stream_never_confirm(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        replacement = UUID(int=305)
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10)
        inspect_scene(instance, frame(0, moved, stream=replacement), 20)
        inspect_scene(instance, frame(1, moved, stream=replacement), 30)
        stale = [inspect_scene(instance, frame(2 + index, moved), 40 + index * 10)
                 for index in range(3)]
        for sample in stale:
            self.assertEqual("retired_stream", sample.movement_reason)
            self.assertEqual("retired_stream", sample.tamper_reason)
            self.assertEqual(Observation.UNKNOWN, sample.movement)
            self.assertEqual(Observation.UNKNOWN, sample.tamper)
            self.assertEqual(STREAM, sample.stream_id)
            self.assertFalse(sample.critical)
        resumed = inspect_scene(instance, frame(2, moved, stream=replacement), 80)
        self.assertEqual("awaiting_confirmation", resumed.movement_reason)
        self.assertEqual(replacement, resumed.stream_id)
        self.assertFalse(resumed.critical)

    def test_confirmation_after_an_interruption_reports_new_critical_evidence(self):
        moved = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, moved), 10)
        first = inspect_scene(instance, frame(2, moved), 20)
        self.assertEqual((CriticalKind.SERVER_MOVEMENT,), tuple(item.kind for item in first.critical))
        inspect_scene(instance, frame(3, moved), 30, movement=Quality.INSUFFICIENT)
        inspect_scene(instance, frame(4, moved), 40)
        again = inspect_scene(instance, frame(5, moved), 50)
        self.assertEqual(Observation.PRESENT, again.movement)
        self.assertEqual((CriticalKind.SERVER_MOVEMENT,), tuple(item.kind for item in again.critical))
        self.assertNotEqual(first.critical[0].identifier, again.critical[0].identifier)

    def test_tamper_after_a_stream_restart_is_not_silently_deduplicated(self):
        instance = detector()
        dark = bytes(WIDTH * HEIGHT)
        restarted = UUID(int=304)
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, dark), 10)
        first = inspect_scene(instance, frame(2, dark), 20)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in first.critical))
        inspect_scene(instance, frame(0, dark, stream=restarted), 30)
        inspect_scene(instance, frame(1, dark, stream=restarted), 40)
        again = inspect_scene(instance, frame(2, dark, stream=restarted), 50)
        self.assertEqual(Observation.PRESENT, again.tamper)
        self.assertEqual((CriticalKind.CAMERA_TAMPER,), tuple(item.kind for item in again.critical))
        self.assertNotEqual(first.critical[0].identifier, again.critical[0].identifier)

    def test_person_presence_is_not_an_input_to_movement_proof(self):
        parameters = inspect.signature(SceneDetector.inspect).parameters
        self.assertNotIn("person", parameters)
        self.assertNotIn("presence", parameters)


class CalibrationAndDeliveryTests(unittest.TestCase):
    def test_calibration_history_is_versioned_private_and_default_denied(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        with self.assertRaises(RuntimeError):
            CalibrationArchive(connection)
        migrate(connection, APPLICATION_MIGRATIONS)
        archive = CalibrationArchive(connection)
        first = calibration(SourceType.REMOTE_AGENT)
        owner = OwnerCalibrationOperations(archive)
        with self.assertRaises(PermissionError):
            owner.save(first)
        owner = OwnerCalibrationOperations(archive, owner_authorized=lambda: True)
        record = owner.save(first)
        second = replace(first, version=2)
        owner.save(second)
        self.assertEqual(2, archive.load(SOURCE, PROFILE).version)
        self.assertEqual(record, archive.load(SOURCE, PROFILE, 1))
        self.assertEqual(first, record.rehydrate(first.reference))
        with self.assertRaises(ValueError):
            owner.save(replace(second, identifier=UUID(int=499), version=3))

    def test_calibration_history_never_persists_decoded_reference_media(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        migrate(connection, APPLICATION_MIGRATIONS)
        archive = CalibrationArchive(connection)
        stored = calibration()
        OwnerCalibrationOperations(archive, owner_authorized=lambda: True).save(stored)
        columns = connection.execute("PRAGMA table_info(roi_calibration_history)").fetchall()
        self.assertEqual(["source_id", "profile_id", "version", "identifier", "metadata"],
                         [column[1] for column in columns])
        self.assertNotIn("BLOB", [column[2].upper() for column in columns])
        media = stored.reference.pixels
        for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            for row in connection.execute(f'SELECT * FROM "{table}"'):
                for value in row:
                    self.assertNotIsInstance(value, (bytes, bytearray))
                    text = str(value)
                    self.assertNotIn(media.hex(), text)
                    self.assertNotIn(base64.b64encode(media).decode(), text)
                    self.assertNotIn(media.decode("latin-1"), text)
        record = archive.load(SOURCE, PROFILE)
        self.assertIsInstance(record, CalibrationRecord)
        self.assertEqual(stored.reference_sha256, record.reference_sha256)
        self.assertFalse([name for name, value in vars(record).items()
                          if isinstance(value, (bytes, bytearray, GrayFrame))])
        self.assertEqual(stored, record.rehydrate(stored.reference))
        for rejected in (frame(0, covered()), frame(1), frame(0, source=UUID(int=399))):
            with self.assertRaises(ValueError):
                record.rehydrate(rejected)

    def test_archive_refuses_history_table_carrying_a_media_column(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.execute(
            "CREATE TABLE roi_calibration_history ("
            "source_id TEXT, profile_id TEXT, version INTEGER, identifier TEXT, "
            "metadata TEXT, reference BLOB)"
        )
        with self.assertRaises(RuntimeError):
            CalibrationArchive(connection)

    def test_delivery_staging_admits_a_whole_detector_batch(self):
        shifted = transformed(pixels(), (1, 0))
        both = transformed(shifted, (1, 0), region=(5, 4, 9, 8))
        instance = detector()
        inspect_scene(instance, frame(0), 0)
        inspect_scene(instance, frame(1, both), 10)
        batch = inspect_scene(instance, frame(2, both), 20).critical
        self.assertEqual({CriticalKind.SERVER_MOVEMENT, CriticalKind.CAMERA_TAMPER},
                         {item.kind for item in batch})
        self.assertEqual(MAXIMUM_BATCH, len(batch))
        with self.assertRaises(ValueError):
            CriticalDelivery(capacity=MAXIMUM_BATCH - 1)
        recorded = []
        delivery = CriticalDelivery(capacity=MAXIMUM_BATCH, recorder=recorded.append)
        state = delivery.submit(batch)
        self.assertTrue(state.available)
        self.assertEqual({item.identifier for item in batch}, set(state.accepted))
        self.assertEqual({item.identifier for item in batch},
                         {item.identifier for item in recorded})

    def test_critical_delivery_requires_confirmed_events_and_never_discards_failure(self):
        instance = detector()
        dark = bytes(WIDTH * HEIGHT)
        inspect_scene(instance, frame(0), 0)
        event = inspect_scene(instance, frame(1, dark), 10).critical
        event = inspect_scene(instance, frame(2, dark), 20).critical[0]
        calls = []

        def failing_once(item):
            calls.append(item.identifier)
            if len(calls) == 1:
                raise RuntimeError("synthetic outage")

        delivery = CriticalDelivery(capacity=MAXIMUM_BATCH, recorder=failing_once)
        state = delivery.submit((event,))
        self.assertFalse(state.available)
        self.assertEqual((event.identifier,), state.pending)
        self.assertEqual((event.identifier,), delivery.retry().accepted)
        self.assertTrue(delivery.retry().available)
        with self.assertRaises(ValueError):
            delivery.submit((replace(event, confirmed=False),))
