"""Main-runtime scene detection wiring (#205) with generated synthetic frames.

Every pixel is generated in memory; no camera, real scene or person is used.
"""

import asyncio
from contextlib import closing
from dataclasses import replace
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path
from uuid import UUID, uuid4

from app.cameras.registry import CameraRegistry
from app.cameras.registry.models import CaptureProfile, SourceHealthState, SourceType
from app.cameras.uvc.capture import NegotiatedVideo, VideoFrame
from app.cameras.uvc.config import LocalUvcConfiguration
from app.cameras.uvc.identity import CameraState, DeviceEvidence, HealthEvent
from app.cameras.uvc.runtime import LocalUvcDependencies
from app.audit import AuditStore, OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.detection.foundation import Observation
from app.detection.quality import DetectorQualityPolicy, Metric, MetricRule
from app.detection.roi import Calibration, CalibrationArchive, CriticalKind
from app.detection.roi.runtime import (
    CALIBRATION_RETRY_NS, ArchiveCalibrationProvider, CalibrationUnavailable, PackedLumaLayout,
    SceneMonitoringConfiguration, SceneMonitoringDependencies, SceneMonitoringRuntime,
    SceneRuntimeState, SceneSourceBinding, SceneSourceState, _CriticalPump,
)
from app.main import create_app
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_detector_roi import (
    HEIGHT, NOW, POLYGON, PROFILE, SOURCE, WIDTH, pixels, policy, reference_frame,
    transformed,
)
from tests.test_uvc_runtime import FAST, Discovery, PermitOwner, wait_for


INTERVAL = 10
OTHER = UUID(int=901)
THIRD = UUID(int=902)


def quality(detector, **rule):
    values = dict(minimum_usable=0.0, minimum_sufficient=0.05,
                  maximum_sufficient=0.95, maximum_usable=1.0)
    values.update(rule)
    return DetectorQualityPolicy(detector, 1, (MetricRule(Metric.LUMINANCE, **values),),
                                 2, 4096)


def unattainable(detector):
    """A sharpness prerequisite no generated frame meets: always unusable."""
    return DetectorQualityPolicy(detector, 1, (MetricRule(Metric.SHARPNESS, 1.0, 1.0, 1.0, 1.0),),
                                 2, 4096)


LAYOUT = PackedLumaLayout(WIDTH * 2, HEIGHT * 2, "YUYV")


def binding(source=SOURCE, source_type=SourceType.LOCAL_UVC, **changes):
    values = dict(movement_quality=quality("server_roi"), tamper_quality=quality("camera_tamper"),
                  layout=LAYOUT if source_type is SourceType.LOCAL_UVC else None,
                  sample_interval_ns=INTERVAL)
    values.update(changes)
    return SceneSourceBinding(source, source_type, PROFILE, **values)


def calibration_for(item, *, rules=None, version=1, profile=None):
    reference = replace(reference_frame(), source_id=item.source_id)
    return Calibration(UUID(int=500 + version), item.source_id, item.source_type,
                       profile or item.profile_id, version, NOW, POLYGON, reference,
                       rules or policy())


def yuyv(luma):
    """Pack a WIDTH x HEIGHT luma image as a 2x upscaled YUYV capture frame."""
    output = bytearray()
    for y in range(HEIGHT * 2):
        for x in range(WIDTH * 2):
            output += bytes((luma[(y // 2) * WIDTH + x // 2], 128))
    return bytes(output)


class Clock:
    def __init__(self):
        self.value = 1_000

    def __call__(self):
        return self.value


class Recorder:
    def __init__(self):
        self.items = []
        self.fail = False
        self.lock = threading.Lock()

    def __call__(self, observation):
        if self.fail:
            raise RuntimeError("synthetic presence write failure")
        with self.lock:
            self.items.append(observation)

    def kinds(self):
        with self.lock:
            return [item.kind for item in self.items]


class BlockingRecorder(Recorder):
    """Synthetic recorder whose first call blocks, like stalled storage."""

    def __init__(self):
        super().__init__()
        self.entered, self.release = threading.Event(), threading.Event()
        self.calls = 0

    def __call__(self, observation):
        with self.lock:
            self.calls += 1
        self.entered.set()
        self.release.wait(10)
        super().__call__(observation)


class Harness:
    def __init__(self, *bindings, recorder=True, calibrations="default", capacity=None,
                 threaded=False, stall_ns=None):
        self.clock = Clock()
        if recorder is True:
            recorder = Recorder()
        self.recorder = recorder or None
        if calibrations == "default":
            calibrations = calibration_for
        options = {} if capacity is None else {"critical_capacity": capacity}
        self.configuration = SceneMonitoringConfiguration(tuple(bindings or (binding(),)), **options)
        stall = {} if stall_ns is None else {"recorder_stall_ns": stall_ns}
        self.runtime = SceneMonitoringRuntime(
            self.configuration,
            SceneMonitoringDependencies(recorder=self.recorder, calibrations=calibrations,
                                        monotonic_ns=self.clock, utcnow=lambda: NOW,
                                        tick_seconds=0.01, **stall),
            threaded=threaded)
        self.threaded = threaded
        self.sequence = {}

    def frame(self, luma=None, source=SOURCE, advance=INTERVAL):
        self.clock.value += advance
        number = self.sequence.get(source, 0) + 1
        self.sequence[source] = number
        before = self._handled(source)
        self.runtime.on_uvc_frame(source, VideoFrame(yuyv(luma or pixels()), number, 0.0))
        if self.threaded:
            # The worker consumed this sample once one of its outcomes counted.
            assert wait_for(lambda: self._handled(source) > before)
        else:
            self.runtime.step()
        return self.source(source)

    def _handled(self, source):
        item = self.source(source)
        return item.evaluated + item.unusable + item.backpressured + item.failures

    def source(self, source=SOURCE):
        return next(item for item in self.runtime.status().sources if item.source_id == source)


MOVED = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
SHIFTED = transformed(pixels(), (1, 0))


class SceneRuntimeFailClosedTests(unittest.TestCase):
    def test_without_durable_recorder_no_detector_runs(self):
        harness = Harness(recorder=False)
        status = harness.runtime.start()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
        # The caller logs the returned UNAVAILABLE; status() does not repeat it.
        with self.assertNoLogs("app.detection.roi.runtime", level="ERROR"):
            for _ in range(4):
                source = harness.frame(MOVED)
        self.assertEqual(0, source.accepted)
        self.assertEqual("critical_recorder_unavailable", source.reason)
        self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN), (source.movement, source.tamper))

    def test_without_calibration_provider_source_stays_inactive_unknown(self):
        harness = Harness(calibrations=None)
        harness.runtime.start()
        for luma in (None, MOVED, MOVED, MOVED):
            source = harness.frame(luma)
        self.assertIs(SceneSourceState.INACTIVE, source.state)
        self.assertEqual("calibration_provider_unconfigured", source.reason)
        self.assertEqual(Observation.UNKNOWN, source.movement)
        self.assertEqual(Observation.UNKNOWN, source.tamper)
        self.assertEqual(0, source.evaluated)
        self.assertEqual([], harness.recorder.items)

    def test_archive_without_reference_never_fabricates_a_baseline(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "main.sqlite3"

        def connect():
            import sqlite3
            return sqlite3.connect(path)

        with closing(connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        item = binding()
        provider = ArchiveCalibrationProvider(connect)
        with self.assertRaises(CalibrationUnavailable) as missing:
            provider(item)
        self.assertEqual("calibration_missing", missing.exception.reason)
        stored = calibration_for(item)
        with closing(connect()) as connection:
            CalibrationArchive(connection).append(stored)
        with self.assertRaises(CalibrationUnavailable) as unreferenced:
            provider(item)
        self.assertEqual("calibration_reference_unavailable", unreferenced.exception.reason)
        # A live frame offered as the reference does not match the digest.
        live = ArchiveCalibrationProvider(connect, references=lambda record: replace(
            stored.reference, pixels=MOVED))
        with self.assertRaises(CalibrationUnavailable) as forged:
            live(item)
        self.assertEqual("calibration_integrity_failed", forged.exception.reason)
        harness = Harness(item, calibrations=provider)
        harness.runtime.start()
        for luma in (None, MOVED, MOVED, MOVED):
            source = harness.frame(luma)
        self.assertEqual("calibration_reference_unavailable", source.reason)
        self.assertEqual(Observation.UNKNOWN, source.movement)
        trusted = ArchiveCalibrationProvider(connect, references=lambda record: stored.reference)
        self.assertEqual(stored.reference_sha256, trusted(item).reference_sha256)

    def test_calibration_and_binding_mismatch_is_refused(self):
        cases = (
            (lambda item: calibration_for(item, profile=uuid4()), {}, "calibration_mismatch"),
            (calibration_for, {"sample_interval_ns": 100}, "sampling_exceeds_gap"),
            (calibration_for, {"layout": PackedLumaLayout(WIDTH * 2 + 1, HEIGHT, "GREY")},
             "capture_layout_incompatible"),
        )
        for provider, changes, reason in cases:
            with self.subTest(reason=reason):
                harness = Harness(binding(**changes), calibrations=provider)
                harness.runtime.start()
                source = harness.frame()
                self.assertIs(SceneSourceState.INACTIVE, source.state)
                self.assertEqual(reason, source.reason)

    def test_compressed_capture_format_has_no_luma_reader(self):
        with self.assertRaises(ValueError):
            PackedLumaLayout(640, 480, "MJPG")
        with self.assertRaises(ValueError):
            binding(layout=None)
        with self.assertRaises(ValueError):
            SceneMonitoringConfiguration(tuple(binding(UUID(int=index)) for index in range(5)))


class SceneRuntimeDetectionTests(unittest.TestCase):
    def test_local_uvc_frames_confirm_server_movement_into_recorder(self):
        harness = Harness()
        harness.runtime.start()
        first = harness.frame()        # new runtime stream: discontinuity
        baseline = harness.frame()     # quality recovered: evaluated
        self.assertEqual(Observation.UNKNOWN, first.movement)
        self.assertEqual(Observation.ABSENT, baseline.movement)
        self.assertEqual("reference_geometry_matches", baseline.movement_reason)
        candidate = harness.frame(MOVED)
        self.assertEqual(Observation.UNKNOWN, candidate.movement)
        confirmed = harness.frame(MOVED)
        self.assertEqual(Observation.PRESENT, confirmed.movement)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())
        recorded = harness.recorder.items[0]
        self.assertEqual("server_geometry_changed", recorded.reason)
        self.assertEqual(SourceType.LOCAL_UVC, recorded.source_type)
        harness.frame(MOVED)
        self.assertEqual(1, len(harness.recorder.items))
        self.assertEqual(0, harness.runtime.status().critical_pending)

    def test_unusable_movement_quality_is_unknown_while_tamper_continues(self):
        harness = Harness(binding(movement_quality=unattainable("server_roi")))
        harness.runtime.start()
        for luma in (None, None, MOVED, MOVED, MOVED):
            source = harness.frame(luma)
            # A failed prerequisite is never "no movement".
            self.assertNotEqual(Observation.ABSENT, source.movement)
        self.assertEqual(Observation.UNKNOWN, source.movement)
        self.assertEqual("quality_unavailable", source.movement_reason)
        self.assertEqual(Observation.ABSENT, source.tamper)
        self.assertEqual([], harness.recorder.items)

    def test_capture_rate_is_sampled_and_pending_sample_bounded(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        for index in range(5):
            harness.clock.value += 1
            harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), 100 + index, 0.0))
        source = harness.source()
        self.assertEqual(5, source.sampled_out)
        self.assertEqual(1, source.accepted)
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), 200, 0.0))
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), 201, 0.0))
        self.assertEqual(1, harness.source().replaced)

    def test_trusted_camera_loss_after_scene_shift_is_camera_tamper(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.frame()
        shifted = harness.frame(SHIFTED)
        self.assertEqual("global_scene_shift", shifted.tamper_reason)
        harness.clock.value += 5
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.OFFLINE, "synthetic_unplug"))
        harness.runtime.step()
        self.assertEqual([CriticalKind.CAMERA_TAMPER], harness.recorder.kinds())
        self.assertEqual("source_loss_after_scene_shift", harness.recorder.items[0].reason)

    def test_untrusted_degraded_state_only_ends_confirmation(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.frame()
        harness.frame(MOVED)
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.DEGRADED, "synthetic_stall"))
        # The loss ended the episode and the next sample is a new stream.
        after = harness.frame(MOVED)
        self.assertEqual("stream_or_sampling_discontinuity", after.movement_reason)
        harness.frame(MOVED)
        self.assertEqual([], harness.recorder.items)

    def test_stale_conclusion_becomes_unknown(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        self.assertEqual(Observation.ABSENT, harness.frame().movement)
        harness.clock.value += policy().maximum_gap_ns + 1
        source = harness.source()
        self.assertEqual(Observation.UNKNOWN, source.movement)
        self.assertEqual("observation_stale", source.movement_reason)

    def test_remote_agent_decoded_samples_use_the_same_pipeline(self):
        remote = binding(OTHER, SourceType.REMOTE_AGENT)
        harness = Harness(remote)
        harness.runtime.start()
        stream = uuid4()

        def offer(luma):
            harness.clock.value += INTERVAL
            harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH, height=HEIGHT,
                                       pixels=luma)
            harness.runtime.step()
            return harness.source(OTHER)

        # Raw capture frames are not accepted for a decoded-sample source.
        harness.runtime.on_uvc_frame(OTHER, VideoFrame(yuyv(pixels()), 1, 0.0))
        self.assertEqual(0, harness.source(OTHER).accepted)
        for luma in (pixels(), pixels(), MOVED, MOVED):
            source = offer(luma)
        self.assertEqual(Observation.PRESENT, source.movement)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())
        self.assertEqual(SourceType.REMOTE_AGENT, harness.recorder.items[0].source_type)


class SceneRuntimeIsolationTests(unittest.TestCase):
    def test_unusable_frame_on_one_source_leaves_another_running(self):
        harness = Harness(binding(), binding(OTHER))
        harness.runtime.start()
        for luma in (None, None, MOVED):
            harness.frame(luma, OTHER, advance=0)
            harness.frame(luma)
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(OTHER, VideoFrame(b"truncated", 99, 0.0))
        harness.frame(MOVED)
        broken = harness.source(OTHER)
        self.assertEqual("frame_unusable", broken.reason)
        self.assertEqual(Observation.UNKNOWN, broken.movement)
        self.assertEqual(1, broken.unusable)
        self.assertEqual(Observation.PRESENT, harness.source().movement)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())
        self.assertEqual({SOURCE}, {item.source_id for item in harness.recorder.items})

    def test_evaluation_fault_is_isolated_and_rebinds(self):
        harness = Harness(binding(), binding(OTHER))
        harness.runtime.start()
        harness.frame(source=OTHER, advance=0)
        harness.frame()
        context = harness.runtime._contexts[OTHER]

        def broken(*args, **kwargs):
            raise RuntimeError("synthetic detector fault")

        context.detector.inspect = broken
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.frame(source=OTHER, advance=0)
            healthy = harness.frame()
        self.assertTrue(any("scene_source_failed" in line for line in logs.output))
        failed = harness.source(OTHER)
        self.assertEqual("scene_evaluation_failed", failed.reason)
        self.assertEqual(1, failed.failures)
        self.assertEqual(Observation.UNKNOWN, failed.movement)
        self.assertEqual(Observation.ABSENT, healthy.movement)
        self.assertEqual("scene_evaluation_failed", harness.frame(source=OTHER).reason)
        harness.clock.value += CALIBRATION_RETRY_NS
        rebound = harness.frame(source=OTHER)
        self.assertIs(SceneSourceState.ACTIVE, rebound.state)
        self.assertEqual(1, rebound.failures)

    def test_failed_recorder_keeps_evidence_staged_and_backpressures(self):
        harness = Harness(capacity=2)
        harness.runtime.start()
        harness.recorder.fail = True
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        status = harness.runtime.status()
        self.assertEqual(1, status.critical_pending)
        self.assertIs(SceneRuntimeState.DEGRADED, status.state)
        blocked = harness.frame(MOVED)
        self.assertEqual("critical_backpressure", blocked.reason)
        self.assertEqual(Observation.UNKNOWN, blocked.movement)
        self.assertEqual(1, blocked.backpressured)
        harness.recorder.fail = False
        harness.frame(MOVED)
        status = harness.runtime.status()
        self.assertEqual(0, status.critical_pending)
        self.assertEqual(1, status.critical_accepted)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())

    def test_observations_accepted_on_submit_are_counted(self):
        # Codex P2 (#213): CriticalDelivery.submit() delivers immediately when
        # the recorder accepts; those identifiers must be counted.
        harness = Harness()
        harness.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        status = harness.runtime.status()
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())
        self.assertEqual(0, status.critical_pending)
        self.assertEqual(1, status.critical_accepted)

    def _loss_backpressure_harness(self):
        """Three sources, staging nearly full of undelivered movement evidence,
        and two scene shifts awaiting a correlated trusted loss."""
        harness = Harness(binding(), binding(OTHER), binding(THIRD), capacity=3)
        harness.runtime.start()
        harness.recorder.fail = True
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        for luma, moved in ((None, None), (None, MOVED), (SHIFTED, MOVED)):
            harness.frame(luma, OTHER, advance=0)
            harness.frame(luma, THIRD, advance=0)
            # The second confirmed movement leaves room for one item only.
            harness.frame(moved)
        self.assertEqual("global_scene_shift", harness.source(OTHER).tamper_reason)
        self.assertEqual("global_scene_shift", harness.source(THIRD).tamper_reason)
        self.assertEqual(2, harness.runtime.status().critical_pending)
        harness.clock.value += 5
        for source in (OTHER, THIRD):
            harness.runtime.on_uvc_health(HealthEvent(source, CameraState.OFFLINE, "synthetic_unplug"))
        harness.runtime.step()
        return harness

    def test_correlated_loss_waits_for_staging_instead_of_failing(self):
        harness = self._loss_backpressure_harness()
        status = harness.runtime.status()
        self.assertEqual(3, status.critical_pending)
        waiting = harness.source(THIRD)
        self.assertEqual(0, waiting.failures)
        self.assertIs(SceneSourceState.DEGRADED, waiting.state)
        self.assertEqual("critical_backpressure", waiting.reason)
        self.assertEqual(Observation.UNKNOWN, waiting.tamper)
        # A sample after the loss is not evaluated ahead of the held loss.
        harness.frame(None, THIRD)
        self.assertEqual("critical_backpressure", harness.source(THIRD).reason)
        self.assertEqual(0, harness.source(THIRD).evaluated - 3)
        # A calibration refresh would discard the shift state; it waits.
        harness.runtime.request_calibration_refresh(THIRD)
        harness.runtime.step()
        self.assertEqual("critical_backpressure", harness.source(THIRD).reason)
        harness.recorder.fail = False
        harness.runtime.step()
        harness.runtime.step()
        tampers = [item for item in harness.recorder.items
                   if item.kind is CriticalKind.CAMERA_TAMPER]
        self.assertEqual({OTHER, THIRD}, {item.source_id for item in tampers})
        self.assertTrue(all(item.reason == "source_loss_after_scene_shift" for item in tampers))
        status = harness.runtime.status()
        self.assertEqual(0, status.critical_pending)
        # Two movements and two tampers, including one accepted on submit.
        self.assertEqual(4, status.critical_accepted)
        self.assertEqual(0, harness.source(THIRD).failures)

    def test_held_correlated_loss_is_drained_at_stop(self):
        harness = self._loss_backpressure_harness()
        harness.recorder.fail = False
        status = harness.runtime.stop()
        self.assertEqual(0, status.critical_pending)
        tampers = [item.source_id for item in harness.recorder.items
                   if item.kind is CriticalKind.CAMERA_TAMPER]
        self.assertEqual(sorted((OTHER, THIRD)), sorted(tampers))
        self.assertEqual(Observation.UNKNOWN, harness.source(THIRD).tamper)

    def test_loss_queued_just_before_stop_is_processed(self):
        # Codex P1 (#213): a trusted loss still in its capture slot at stop()
        # (not yet moved into the worker's held loss) must reach the detector.
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.frame()
        self.assertEqual("global_scene_shift", harness.frame(SHIFTED).tamper_reason)
        harness.clock.value += 5
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.OFFLINE, "synthetic_unplug"))
        status = harness.runtime.stop()
        self.assertEqual([CriticalKind.CAMERA_TAMPER], harness.recorder.kinds())
        self.assertEqual("source_loss_after_scene_shift", harness.recorder.items[0].reason)
        self.assertEqual(0, status.critical_pending)
        self.assertEqual(0, status.losses_held)
        self.assertEqual(1, status.critical_accepted)

    def test_loss_queued_at_stop_without_room_is_counted_and_logged(self):
        harness = Harness(binding(), binding(OTHER), binding(THIRD), capacity=3)
        harness.runtime.start()
        harness.recorder.fail = True
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        for luma, moved in ((None, None), (None, MOVED), (SHIFTED, MOVED)):
            harness.frame(luma, OTHER, advance=0)
            harness.frame(luma, THIRD, advance=0)
            harness.frame(moved)
        harness.clock.value += 5
        for source in (OTHER, THIRD):
            harness.runtime.on_uvc_health(HealthEvent(source, CameraState.OFFLINE, "synthetic_unplug"))
        # Both losses are still queued in their slots; the recorder is down.
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            status = harness.runtime.stop()
        self.assertTrue(any("scene_critical_undelivered" in line for line in logs.output))
        # One loss fit the last staging slot; the other is held, not dropped.
        self.assertEqual(3, status.critical_pending)
        self.assertEqual(1, status.losses_held)
        self.assertEqual([], harness.recorder.kinds())
        self.assertEqual(0, sum(item.failures for item in status.sources))

    def test_sample_before_queued_loss_is_evaluated_at_stop(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.frame()
        self.assertEqual("global_scene_shift", harness.frame(SHIFTED).tamper_reason)
        # A sample showing the reference scene again is queued before the
        # loss; it ends the shift, so the loss must not confirm a tamper.
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), 4, 0.0))
        harness.clock.value += 5
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.OFFLINE, "synthetic_unplug"))
        harness.runtime.stop()
        self.assertEqual([], harness.recorder.kinds())

    def test_held_loss_keeps_the_first_trusted_loss(self):
        harness = self._loss_backpressure_harness()
        self.assertEqual(1, harness.runtime.status().losses_held)
        # Replug and unplug again, outside the shift correlation window. The
        # later loss must not replace the held one, or the tamper is lost.
        harness.runtime.on_uvc_health(HealthEvent(THIRD, CameraState.ONLINE, "synthetic_replug"))
        harness.clock.value += 100
        harness.runtime.on_uvc_health(HealthEvent(THIRD, CameraState.OFFLINE, "synthetic_unplug"))
        harness.runtime.step()
        self.assertEqual(1, harness.runtime.status().losses_held)
        harness.recorder.fail = False
        harness.runtime.step()
        harness.runtime.step()
        tampers = [item.source_id for item in harness.recorder.items
                   if item.kind is CriticalKind.CAMERA_TAMPER]
        self.assertEqual(sorted((OTHER, THIRD)), sorted(tampers))
        self.assertEqual(0, harness.runtime.status().losses_held)

    def test_threaded_worker_reprocesses_held_loss_on_tick(self):
        harness = Harness(binding(), binding(OTHER), binding(THIRD), capacity=3, threaded=True)
        harness.runtime.start()
        self.addCleanup(harness.runtime.stop)
        harness.recorder.fail = True
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        for luma, moved in ((None, None), (None, MOVED), (SHIFTED, MOVED)):
            harness.frame(luma, OTHER, advance=0)
            harness.frame(luma, THIRD, advance=0)
            harness.frame(moved)
        self.assertEqual("global_scene_shift", harness.source(THIRD).tamper_reason)
        harness.clock.value += 5
        for source in (OTHER, THIRD):
            harness.runtime.on_uvc_health(HealthEvent(source, CameraState.OFFLINE, "synthetic_unplug"))
        self.assertTrue(wait_for(lambda: harness.runtime.status().losses_held == 1))
        # No further frame arrives: only the worker's idle tick retries.
        harness.recorder.fail = False
        self.assertTrue(wait_for(lambda: sorted(
            item.source_id for item in harness.recorder.items
            if item.kind is CriticalKind.CAMERA_TAMPER) == sorted((OTHER, THIRD))))
        self.assertTrue(wait_for(lambda: harness.runtime.status().losses_held == 0))
        self.assertEqual(0, harness.runtime.status().critical_pending)

    def test_stop_withdraws_conclusions_and_reports_undelivered(self):
        harness = Harness()
        harness.runtime.start()
        harness.recorder.fail = True
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            status = harness.runtime.stop()
        self.assertTrue(any("scene_critical_undelivered" in line for line in logs.output))
        self.assertIs(SceneRuntimeState.STOPPED, status.state)
        self.assertEqual(1, status.critical_pending)
        self.assertEqual(Observation.UNKNOWN, status.sources[0].movement)
        harness.frame(MOVED)
        self.assertEqual(0, harness.source().accepted - 4)


class SceneRuntimeReviewRegressionTests(unittest.TestCase):
    """Regressions for the #213 review findings on ae2fc01."""

    def test_stalled_recorder_never_blocks_detection_and_stop_is_bounded(self):
        # Codex P1 (#213): a blocking durable recorder must not wedge the
        # sole scene worker; the in-flight stall is DEGRADED and shutdown is
        # bounded and explicit about the call still in flight.
        recorder = BlockingRecorder()
        self.addCleanup(recorder.release.set)
        harness = Harness(binding(), binding(OTHER), recorder=recorder, threaded=True,
                          stall_ns=1_000)
        harness.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        self.assertTrue(recorder.entered.wait(5))
        # Detection on every source continues while the call is in flight.
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma, OTHER)
        self.assertEqual(Observation.PRESENT, harness.source(OTHER).movement)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.clock.value += 1_000
            self.assertTrue(wait_for(lambda: harness.runtime.status().recorder_stalled))
            status = harness.runtime.status()
            self.assertIs(SceneRuntimeState.DEGRADED, status.state)
            self.assertTrue(status.critical_in_flight)
            self.assertTrue(status.worker_running)
            self.assertEqual(2, status.critical_pending)
            self.assertTrue(wait_for(lambda: any(
                "scene_critical_recorder_stalled" in line for line in logs.output)))
            started = time.monotonic()
            stopped = harness.runtime.stop(timeout=0.2)
            self.assertLess(time.monotonic() - started, 2.0)
        self.assertIs(SceneRuntimeState.STOP_FAILED, stopped.state)
        self.assertTrue(stopped.critical_in_flight)
        self.assertFalse(stopped.worker_running)
        self.assertEqual(2, stopped.critical_pending)
        for event in ("scene_monitoring_stop_failed", "scene_critical_undelivered"):
            self.assertTrue(any(event in line for line in logs.output), event)
        # Once released, the in-flight call completes but no further call
        # starts after the stop deadline (storage may be torn down).
        recorder.release.set()
        self.assertTrue(wait_for(lambda: not harness.runtime.status().delivery_running))
        self.assertEqual(1, recorder.calls)
        self.assertEqual(1, harness.runtime.status().critical_pending)

    def test_replaced_producer_stream_is_refused_as_stale(self):
        # Codex P2 (#213): A, then replacement B, then delayed A frames.
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT))
        harness.runtime.start()
        first, second = uuid4(), uuid4()

        def offer(stream, luma):
            harness.clock.value += INTERVAL
            offered = harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                                 height=HEIGHT, pixels=luma)
            harness.runtime.step()
            return offered

        for stream in (first, first, second, second):
            self.assertTrue(offer(stream, pixels()))
        for _ in range(4):
            self.assertFalse(offer(first, MOVED))
        source = harness.source(OTHER)
        self.assertEqual(4, source.stale_rejected)
        self.assertEqual([], harness.recorder.items)
        self.assertEqual(Observation.ABSENT, source.movement)
        # The live replacement stream keeps working.
        self.assertTrue(offer(second, MOVED))
        self.assertTrue(offer(second, MOVED))
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())

    def test_full_retired_stream_history_refuses_new_streams(self):
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT))
        harness.runtime.start()
        streams = [uuid4() for _ in range(4)]

        def offer(stream):
            harness.clock.value += INTERVAL
            return harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                              height=HEIGHT, pixels=pixels())

        with mock.patch("app.detection.roi.runtime.RETIRED_PRODUCER_LIMIT", 2):
            for stream in streams[:3]:
                self.assertTrue(offer(stream))
                harness.runtime.step()
            # A fourth stream would mean forgetting a retired one: refused,
            # and the current stream is then refused too (until restart).
            self.assertFalse(offer(streams[3]))
            self.assertFalse(offer(streams[2]))
        status = harness.runtime.status()
        self.assertIs(SceneSourceState.DEGRADED, status.sources[0].state)
        self.assertEqual("stream_history_exhausted", status.sources[0].reason)
        self.assertIs(SceneRuntimeState.DEGRADED, status.state)

    def test_camera_loss_degrades_source_and_runtime_until_a_sample(self):
        # Codex P2 (#213): an unplugged source is never presented as healthy.
        for state in (CameraState.OFFLINE, CameraState.MANUAL,
                      CameraState.DEGRADED):
            with self.subTest(state=state):
                harness = Harness()
                harness.runtime.start()
                harness.frame()
                self.assertIs(SceneSourceState.ACTIVE, harness.frame().state)
                self.assertIs(SceneRuntimeState.RUNNING, harness.runtime.status().state)
                harness.clock.value += 5
                harness.runtime.on_uvc_health(HealthEvent(SOURCE, state, "synthetic_loss"))
                harness.runtime.step()
                lost = harness.source()
                self.assertIs(SceneSourceState.DEGRADED, lost.state)
                self.assertEqual("source_unavailable", lost.reason)
                self.assertEqual(Observation.UNKNOWN, lost.movement)
                self.assertIs(SceneRuntimeState.DEGRADED, harness.runtime.status().state)
                # A camera-state recovery alone is not a recovery of the scene.
                harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.ONLINE, "replug"))
                harness.runtime.step()
                self.assertIs(SceneRuntimeState.DEGRADED, harness.runtime.status().state)
                self.assertIs(SceneSourceState.ACTIVE, harness.frame().state)
                self.assertIs(SceneRuntimeState.RUNNING, harness.runtime.status().state)

    def test_worker_failure_final_pass_keeps_evidence_and_withdraws(self):
        # Claude (#213): the final pass after a worker failure still delivers
        # the queued loss's evidence but republishes nothing as current.
        harness = Harness(threaded=True)
        harness.runtime.start()
        self.addCleanup(harness.runtime.stop)
        harness.frame()
        harness.frame()
        self.assertEqual("global_scene_shift", harness.frame(SHIFTED).tamper_reason)
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def broken():
            entered.set()
            release.wait(5)
            raise RuntimeError("synthetic worker failure")

        with self.assertLogs("app.detection.roi.runtime", level="ERROR"):
            harness.runtime._cycle = broken
            harness.runtime.request_calibration_refresh()
            self.assertTrue(entered.wait(5))
            harness.clock.value += 5
            harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.OFFLINE,
                                                      "synthetic_unplug"))
            release.set()
            self.assertTrue(wait_for(lambda: not harness.runtime.status().worker_running))
        self.assertTrue(wait_for(lambda: harness.recorder.kinds() == [CriticalKind.CAMERA_TAMPER]))
        status = harness.runtime.status()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
        source = status.sources[0]
        self.assertIs(SceneSourceState.INACTIVE, source.state)
        self.assertEqual("worker_failed", source.reason)
        self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN), (source.movement, source.tamper))
        self.assertTrue(wait_for(lambda: harness.runtime.status().critical_pending == 0))

    def test_sample_after_queued_loss_is_dropped_at_stop(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.frame()
        self.assertEqual("global_scene_shift", harness.frame(SHIFTED).tamper_reason)
        evaluated = harness.source().evaluated
        harness.clock.value += 5
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.OFFLINE, "synthetic_unplug"))
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.ONLINE, "synthetic_replug"))
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), 9, 0.0))
        slot = harness.runtime._slots[SOURCE]
        self.assertIsNotNone(slot.sample)
        status = harness.runtime.stop()
        self.assertEqual([CriticalKind.CAMERA_TAMPER], harness.recorder.kinds())
        self.assertEqual(evaluated, status.sources[0].evaluated)
        self.assertIsNone(slot.sample)

    def _shift_then_queue_loss(self, harness, source=SOURCE):
        harness.frame(None, source)
        harness.frame(None, source)
        self.assertEqual("global_scene_shift", harness.frame(SHIFTED, source).tamper_reason)
        harness.clock.value += 5
        harness.runtime.on_uvc_health(HealthEvent(source, CameraState.OFFLINE, "synthetic_unplug"))

    @staticmethod
    def _break_source_lost(harness, source):
        def broken(**kwargs):
            raise RuntimeError("synthetic detector fault")

        harness.runtime._contexts[source].detector.source_lost = broken

    def test_queued_loss_lost_to_a_fault_at_stop_is_counted(self):
        # Claude (#213): counted in status, not only logged.
        harness = Harness()
        harness.runtime.start()
        self._shift_then_queue_loss(harness)
        self._break_source_lost(harness, SOURCE)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            status = harness.runtime.stop()
        self.assertEqual(1, status.losses_failed)
        self.assertEqual(0, status.losses_held)
        for event in ("scene_source_failed", "scene_critical_undelivered"):
            self.assertTrue(any(event in line for line in logs.output), event)

    def test_held_loss_lost_to_a_fault_at_stop_is_counted(self):
        harness = SceneRuntimeIsolationTests._loss_backpressure_harness(self)
        self.assertEqual(1, harness.runtime.status().losses_held)
        harness.recorder.fail = False
        self._break_source_lost(harness, THIRD)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            status = harness.runtime.stop()
        self.assertEqual(1, status.losses_failed)
        self.assertEqual(0, status.losses_held)
        self.assertTrue(any("scene_critical_undelivered" in line for line in logs.output))

    def test_loss_lost_to_a_running_fault_is_counted(self):
        harness = Harness()
        harness.runtime.start()
        self._shift_then_queue_loss(harness)
        self._break_source_lost(harness, SOURCE)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR"):
            harness.runtime.step()
        status = harness.runtime.status()
        self.assertEqual(1, status.losses_failed)
        self.assertIs(SceneRuntimeState.DEGRADED, status.state)

    def test_tick_and_intervals_are_validated(self):
        for tick in (0, 0.0, -1, 0.001, float("nan"), float("inf"), True, "1", 61):
            with self.subTest(tick=tick), self.assertRaises(ValueError):
                SceneMonitoringDependencies(tick_seconds=tick)
        for field in ("calibration_retry_ns", "recorder_stall_ns"):
            for value in (0, -1, 1.5, True):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    SceneMonitoringDependencies(**{field: value})
        self.assertEqual(0.01, SceneMonitoringDependencies(tick_seconds=0.01).tick_seconds)


class SteppingClock(Clock):
    """Synthetic clock that can advance on every read once `step` is set."""

    def __init__(self):
        super().__init__()
        self.step = 0

    def __call__(self):
        self.value += self.step
        return self.value


class GatedRecorder(Recorder):
    """Synthetic recorder whose every call blocks until released."""

    def __init__(self):
        super().__init__()
        self.entered = threading.Semaphore(0)
        self.gates = [threading.Event() for _ in range(8)]
        self.calls = 0

    def __call__(self, observation):
        with self.lock:
            index = self.calls
            self.calls += 1
        self.entered.release()
        self.gates[index].wait(10)
        super().__call__(observation)

    def release_all(self):
        for gate in self.gates:
            gate.set()


class SceneRuntimeFollowUpRegressionTests(unittest.TestCase):
    """Regressions for the #213 review findings on ff4b36c."""

    def test_stale_source_lowers_source_and_runtime_until_a_fresh_sample(self):
        # Codex P2 (#213): without a frame evaluated within maximum_gap_ns
        # the source is lowered (not only its conclusions) and the runtime
        # is DEGRADED, until a fresh sample recovers it.
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        self.assertIs(SceneSourceState.ACTIVE, harness.frame().state)
        self.assertIs(SceneRuntimeState.RUNNING, harness.runtime.status().state)
        harness.clock.value += policy().maximum_gap_ns + 1
        stale = harness.source()
        self.assertIs(SceneSourceState.DEGRADED, stale.state)
        self.assertEqual("observation_stale", stale.reason)
        self.assertEqual(Observation.UNKNOWN, stale.movement)
        self.assertIs(SceneRuntimeState.DEGRADED, harness.runtime.status().state)
        recovered = harness.frame()
        self.assertIs(SceneSourceState.ACTIVE, recovered.state)
        self.assertIs(SceneRuntimeState.RUNNING, harness.runtime.status().state)

    def test_bound_source_that_never_receives_a_sample_is_lowered(self):
        harness = Harness()
        harness.runtime.start()
        harness.runtime.step()
        self.assertEqual("awaiting_sample", harness.source().reason)
        self.assertIs(SceneRuntimeState.RUNNING, harness.runtime.status().state)
        harness.clock.value += policy().maximum_gap_ns + 1
        self.assertIs(SceneSourceState.DEGRADED, harness.source().state)
        self.assertEqual("observation_stale", harness.source().reason)
        self.assertIs(SceneRuntimeState.DEGRADED, harness.runtime.status().state)

    def test_replacement_first_frame_inside_interval_still_retires_old_stream(self):
        # Codex P2 (#213): B's first frame is sampled out, yet A is retired,
        # so delayed A frames are refused instead of accepted as continuous.
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT))
        harness.runtime.start()
        first, second = uuid4(), uuid4()

        def offer(stream, advance, luma=None):
            harness.clock.value += advance
            offered = harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                                 height=HEIGHT, pixels=luma or pixels())
            harness.runtime.step()
            return offered

        self.assertTrue(offer(first, INTERVAL))
        self.assertTrue(offer(first, INTERVAL))
        self.assertFalse(offer(second, 1))
        self.assertEqual(1, harness.source(OTHER).sampled_out)
        for _ in range(3):
            self.assertFalse(offer(first, INTERVAL, MOVED))
        source = harness.source(OTHER)
        self.assertEqual(3, source.stale_rejected)
        self.assertEqual(2, source.accepted)
        self.assertEqual([], harness.recorder.items)
        self.assertTrue(offer(second, INTERVAL))
        self.assertTrue(offer(second, INTERVAL, MOVED))
        self.assertTrue(offer(second, INTERVAL, MOVED))
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())

    def test_dead_delivery_thread_makes_runtime_unavailable(self):
        # Claude (#213): the runtime itself reports UNAVAILABLE when its
        # delivery thread is gone, not only the application watcher.
        harness = Harness(threaded=True)
        harness.runtime.start()
        self.addCleanup(harness.runtime.stop, 1.0)
        self.assertIs(SceneRuntimeState.RUNNING, harness.runtime.status().state)

        def broken():
            raise RuntimeError("synthetic delivery failure")

        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.runtime._pump.deliver = broken
            for luma in (None, None, MOVED, MOVED):
                harness.frame(luma)
            self.assertTrue(wait_for(lambda: not harness.runtime.status().delivery_running))
        self.assertTrue(any("scene_critical_undelivered" in line for line in logs.output))
        status = harness.runtime.status()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
        self.assertTrue(status.worker_running)
        self.assertEqual(1, status.critical_pending)

    def test_pump_starts_no_recorder_call_after_close_with_two_staged(self):
        # Claude (#213): both observations are staged before the first call
        # blocks; after close the second is never offered to the recorder.
        source = Harness(binding(), binding(OTHER))
        source.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            source.frame(luma)
            source.frame(luma, OTHER)
        observations = list(source.recorder.items)
        self.assertEqual(2, len(observations))
        recorder = BlockingRecorder()
        self.addCleanup(recorder.release.set)
        pump = _CriticalPump(capacity=8, recorder=recorder, clock=Clock(), tick_seconds=0.01,
                             threaded=True)
        self.assertTrue(pump.submit(observations))
        pump.start()
        self.assertTrue(recorder.entered.wait(5))
        self.assertIsNotNone(pump.close(0.1))
        recorder.release.set()
        self.assertTrue(wait_for(lambda: not pump.snapshot().running))
        self.assertEqual(1, recorder.calls)
        self.assertEqual(1, pump.snapshot().pending)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR"):
            self.assertFalse(pump.submit(observations[1:]))
        self.assertEqual(1, pump.snapshot().refused)
        self.assertEqual(1, recorder.calls)

    def test_worker_outliving_stop_cannot_stage_or_republish(self):
        # Claude (#213): after a worker join timeout (STOP_FAILED) the late
        # confirmation is refused and counted, and nothing is republished.
        harness = Harness(threaded=True)
        harness.runtime.start()
        for luma in (None, None, MOVED):
            harness.frame(luma)
        detector = harness.runtime._contexts[SOURCE].detector
        inspect = detector.inspect
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def blocked(*args, **kwargs):
            entered.set()
            release.wait(10)
            return inspect(*args, **kwargs)

        detector.inspect = blocked
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(MOVED), 50, 0.0))
        self.assertTrue(entered.wait(5))
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            stopped = harness.runtime.stop(timeout=0.1)
            self.assertIs(SceneRuntimeState.STOP_FAILED, stopped.state)
            self.assertTrue(stopped.worker_running)
            release.set()
            self.assertTrue(wait_for(lambda: not harness.runtime.status().worker_running))
        self.assertTrue(any("scene_critical_undelivered" in line for line in logs.output))
        status = harness.runtime.status()
        self.assertIs(SceneRuntimeState.STOP_FAILED, status.state)
        self.assertEqual(1, status.critical_refused)
        self.assertEqual(0, status.critical_pending)
        self.assertEqual([], harness.recorder.items)
        source = status.sources[0]
        self.assertIs(SceneSourceState.INACTIVE, source.state)
        self.assertEqual("stopped", source.reason)
        self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN), (source.movement, source.tamper))

    def test_every_distinct_stalled_call_is_logged(self):
        # Claude (#213): a second stalled call is reported even when no
        # non-stalled moment was observed in between.
        recorder = GatedRecorder()
        self.addCleanup(recorder.release_all)
        harness = Harness(binding(), binding(OTHER), recorder=recorder, threaded=True,
                          stall_ns=1_000)
        harness.clock = SteppingClock()
        harness.clock.value = 1_000
        harness.runtime._deps = replace(harness.runtime._deps, monotonic_ns=harness.clock)
        harness.runtime._pump.clock = harness.clock
        harness.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        self.assertTrue(recorder.entered.acquire(timeout=5))
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma, OTHER)

        def stalls(logs):
            return sum("scene_critical_recorder_stalled" in line for line in logs.output)

        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.clock.step = 1_000
            self.assertTrue(wait_for(lambda: stalls(logs) == 1))
            recorder.gates[0].set()
            self.assertTrue(recorder.entered.acquire(timeout=5))
            self.assertTrue(wait_for(lambda: stalls(logs) == 2))
            harness.runtime.stop(timeout=0.1)
        # The call still in flight at stop had exceeded the stall bound.
        self.assertEqual(3, stalls(logs))
        self.assertFalse(any("scene_critical_in_flight_at_stop" in line for line in logs.output))

    def test_call_in_flight_at_stop_is_not_reported_as_stalled(self):
        # Claude (#213): a call merely in flight at stop (not past the stall
        # bound) is reported with its own event, not as a stall.
        recorder = BlockingRecorder()
        self.addCleanup(recorder.release.set)
        harness = Harness(recorder=recorder, threaded=True)
        harness.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        self.assertTrue(recorder.entered.wait(5))
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            stopped = harness.runtime.stop(timeout=0.1)
        self.assertIs(SceneRuntimeState.STOP_FAILED, stopped.state)
        self.assertTrue(stopped.critical_in_flight)
        self.assertFalse(stopped.recorder_stalled)
        self.assertTrue(any("scene_critical_in_flight_at_stop" in line for line in logs.output))
        self.assertFalse(any("scene_critical_recorder_stalled" in line for line in logs.output))


class SceneRuntimeThirdReviewRegressionTests(unittest.TestCase):
    """Regressions for the #213 review findings on 36da242."""

    def test_history_exhaustion_refuses_the_previous_stream_too(self):
        # Codex P2 (#213): after the refused replacement, frames of the
        # previous producer stream are stale as well and never confirm.
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT))
        harness.runtime.start()
        streams = [uuid4() for _ in range(4)]

        def offer(stream, luma=None, step=True):
            harness.clock.value += INTERVAL
            offered = harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                                 height=HEIGHT, pixels=luma or pixels())
            if step:
                harness.runtime.step()
            return offered

        with mock.patch("app.detection.roi.runtime.RETIRED_PRODUCER_LIMIT", 2):
            for stream in streams[:3]:
                self.assertTrue(offer(stream))
            self.assertTrue(offer(streams[2]))
            self.assertEqual(Observation.ABSENT, harness.source(OTHER).movement)
            evaluated = harness.source(OTHER).evaluated
            # A sample of the current stream pending when the replacement
            # arrives is dropped (and counted), not evaluated.
            self.assertTrue(offer(streams[2], MOVED, step=False))
            self.assertFalse(offer(streams[3]))
            accepted = harness.source(OTHER).accepted
            for _ in range(4):
                self.assertFalse(offer(streams[2], MOVED))
        self.assertEqual([], harness.recorder.items)
        source = harness.source(OTHER)
        self.assertEqual(accepted, source.accepted)
        self.assertEqual(evaluated, source.evaluated)
        # The refused replacement, the dropped pending sample and four frames.
        self.assertEqual(6, source.stale_rejected)
        self.assertIs(SceneSourceState.DEGRADED, source.state)
        self.assertEqual("stream_history_exhausted", source.reason)
        self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN), (source.movement, source.tamper))
        self.assertEqual("stream_history_exhausted", source.movement_reason)
        self.assertIs(SceneRuntimeState.DEGRADED, harness.runtime.status().state)

    def test_calibration_refresh_waits_for_a_loss_taken_from_the_slot(self):
        # Codex P2 (#213): a refresh racing with a queued loss must not replace
        # the detector before the loss is correlated with the scene shift.
        calls = []

        def calibrations(item):
            calls.append(item.source_id)
            return calibration_for(item)

        harness = Harness(calibrations=calibrations)
        harness.runtime.start()
        harness.frame()
        harness.frame()
        self.assertEqual("global_scene_shift", harness.frame(SHIFTED).tamper_reason)
        self.assertEqual(1, len(calls))
        harness.clock.value += 5
        harness.runtime.on_uvc_health(HealthEvent(SOURCE, CameraState.OFFLINE, "synthetic_unplug"))
        harness.runtime.request_calibration_refresh()
        harness.runtime.step()
        self.assertEqual([CriticalKind.CAMERA_TAMPER], harness.recorder.kinds())
        self.assertEqual("source_loss_after_scene_shift", harness.recorder.items[0].reason)
        self.assertEqual(1, len(calls))
        # The deferred refresh runs on the next pass.
        harness.runtime.step()
        self.assertEqual(2, len(calls))
        self.assertEqual("awaiting_sample", harness.source().reason)

    def test_worker_start_failure_rolls_back_the_delivery_thread(self):
        # Codex P2 (#213): a worker thread that cannot be started leaves no
        # delivery thread running and no unstarted thread for stop() to join.
        harness = Harness(threaded=True)
        original = threading.Thread.start

        def start(thread):
            if thread.name == "scene-monitoring":
                raise RuntimeError("synthetic thread exhaustion")
            return original(thread)

        with mock.patch.object(threading.Thread, "start", start):
            with self.assertRaises(RuntimeError):
                harness.runtime.start()
        # The caller reports the startup failure; status() does not log it.
        with self.assertNoLogs("app.detection.roi.runtime", level="ERROR"):
            status = harness.runtime.status()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
        self.assertFalse(status.worker_running)
        self.assertFalse(status.delivery_running)
        self.assertEqual("worker_start_failed", status.sources[0].reason)
        self.assertIsNone(harness.runtime._thread)
        self.assertFalse(harness.runtime._pump._thread.is_alive())
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(pixels()), 1, 0.0))
        self.assertEqual(0, harness.source().accepted)
        stopped = harness.runtime.stop(timeout=1.0)
        self.assertIs(SceneRuntimeState.UNAVAILABLE, stopped.state)
        self.assertFalse(stopped.delivery_running)

    def test_delivery_thread_start_failure_retains_no_thread(self):
        harness = Harness(threaded=True)
        original = threading.Thread.start

        def start(thread):
            if thread.name == "scene-critical-delivery":
                raise RuntimeError("synthetic thread exhaustion")
            return original(thread)

        with mock.patch.object(threading.Thread, "start", start):
            with self.assertRaises(RuntimeError):
                harness.runtime.start()
        self.assertIsNone(harness.runtime._pump._thread)
        self.assertIsNone(harness.runtime._thread)
        self.assertIs(SceneRuntimeState.UNAVAILABLE, harness.runtime.stop(timeout=1.0).state)

    def test_dead_delivery_thread_masks_every_published_conclusion(self):
        # Claude (#213): a runtime-derived UNAVAILABLE presents no conclusion
        # as current, without changing the stored results; logged once.
        harness = Harness(binding(), binding(OTHER), threaded=True)
        harness.runtime.start()
        self.addCleanup(harness.runtime.stop, 1.0)
        harness.frame()
        self.assertEqual(Observation.ABSENT, harness.frame().movement)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.runtime._pump.close(1.0)
            first = harness.runtime.status()
            second = harness.runtime.status()
        self.assertEqual(1, sum("scene_monitoring_unavailable" in line for line in logs.output))
        for status in (first, second):
            self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
            for source in status.sources:
                self.assertIs(SceneSourceState.INACTIVE, source.state)
                self.assertEqual("delivery_unavailable", source.reason)
                self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN),
                                 (source.movement, source.tamper))
                self.assertEqual("delivery_unavailable", source.movement_reason)
        self.assertEqual(Observation.ABSENT, harness.runtime._published[SOURCE].movement)

    def test_dead_worker_thread_masks_every_published_conclusion(self):
        harness = Harness(threaded=True)
        harness.runtime.start()
        self.addCleanup(harness.runtime.stop, 1.0)
        harness.frame()
        self.assertEqual(Observation.ABSENT, harness.frame().movement)

        def exits():
            # Leaves the worker without the failure path (not an Exception).
            raise SystemExit

        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.runtime._cycle = exits
            harness.runtime.request_calibration_refresh()
            self.assertTrue(wait_for(lambda: not harness.runtime.status().worker_running))
        self.assertEqual(1, sum("scene_monitoring_unavailable" in line for line in logs.output))
        status = harness.runtime.status()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
        source = status.sources[0]
        self.assertEqual("worker_unavailable", source.reason)
        self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN), (source.movement, source.tamper))

    def test_stopping_window_is_not_reported_unavailable(self):
        # Claude (#213): between the worker ending and the delivery thread
        # closing, stop() in progress is not a lost thread.
        recorder = BlockingRecorder()
        self.addCleanup(recorder.release.set)
        harness = Harness(recorder=recorder, threaded=True)
        harness.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            harness.frame(luma)
        self.assertTrue(recorder.entered.wait(5))
        result = {}
        stopper = threading.Thread(target=lambda: result.update(
            status=harness.runtime.stop(timeout=5.0)))
        stopper.start()
        self.addCleanup(stopper.join, 10)
        self.assertTrue(wait_for(lambda: not harness.runtime.status().worker_running))
        self.assertTrue(stopper.is_alive())
        during = harness.runtime.status()
        self.assertIsNot(SceneRuntimeState.UNAVAILABLE, during.state)
        self.assertTrue(during.delivery_running)
        recorder.release.set()
        stopper.join(10)
        self.assertIs(SceneRuntimeState.STOPPED, result["status"].state)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], recorder.kinds())

    def test_worker_failing_after_outliving_stop_keeps_stop_failed(self):
        # Claude (#213): a worker that outlived its stop bound and then
        # raises neither becomes UNAVAILABLE nor rewrites the stop reasons.
        harness = Harness(threaded=True)
        harness.runtime.start()
        harness.frame()
        harness.frame()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def broken():
            entered.set()
            release.wait(10)
            raise RuntimeError("synthetic late worker failure")

        harness.runtime._cycle = broken
        harness.runtime.request_calibration_refresh()
        self.assertTrue(entered.wait(5))
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            stopped = harness.runtime.stop(timeout=0.1)
            self.assertIs(SceneRuntimeState.STOP_FAILED, stopped.state)
            release.set()
            self.assertTrue(wait_for(lambda: not harness.runtime.status().worker_running))
            status = harness.runtime.status()
        # The late failure is a source failure, not a lifecycle transition.
        self.assertFalse(any("scene_monitoring_unavailable" in line for line in logs.output))
        self.assertTrue(any("scene_source_failed" in line for line in logs.output))
        self.assertIs(SceneRuntimeState.STOP_FAILED, status.state)
        source = status.sources[0]
        self.assertIs(SceneSourceState.INACTIVE, source.state)
        self.assertEqual("stopped", source.reason)
        self.assertEqual("stopped", source.movement_reason)

    def test_late_final_pass_after_stop_rewrites_nothing(self):
        # Claude (#213): a final worker pass that runs after stop() withdrew
        # every source does not republish `worker_failed` over `stopped`.
        harness = Harness(recorder=False)
        self.assertIs(SceneRuntimeState.UNAVAILABLE, harness.runtime.start().state)
        stopped = harness.runtime.stop()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, stopped.state)
        harness.runtime._finish()
        source = harness.runtime.status().sources[0]
        self.assertEqual("stopped", source.reason)
        self.assertEqual("stopped", source.movement_reason)

    def test_refused_late_observation_is_reported_by_stop(self):
        # Claude (#213): an observation refused after staging closed is part
        # of stop's undelivered report even when nothing else is undelivered.
        source = Harness()
        source.runtime.start()
        for luma in (None, None, MOVED, MOVED):
            source.frame(luma)
        observation = source.recorder.items[0]
        harness = Harness()
        harness.runtime.start()
        harness.runtime._pump.close(0)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR"):
            self.assertFalse(harness.runtime._pump.submit([observation]))
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            status = harness.runtime.stop()
        self.assertEqual(1, status.critical_refused)
        self.assertEqual((0, 0, 0), (status.critical_pending, status.losses_held,
                                     status.losses_failed))
        self.assertTrue(any("scene_critical_undelivered" in line for line in logs.output))


class SceneRuntimeFourthReviewRegressionTests(unittest.TestCase):
    """Regressions for the #213 review findings on 9a069a9."""

    def _exhausted_after_shift(self, *, loss_before_exhaustion, loss_delay_ns=5):
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT))
        harness.runtime.start()
        current, replacement = uuid4(), uuid4()

        def offer(stream, luma=None):
            harness.clock.value += INTERVAL
            return harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                              height=HEIGHT, pixels=luma or pixels())

        for luma in (None, None, SHIFTED):
            self.assertTrue(offer(current, luma))
            harness.runtime.step()
        self.assertEqual("global_scene_shift", harness.source(OTHER).tamper_reason)
        if loss_before_exhaustion:
            harness.clock.value += 1
            harness.runtime.source_unavailable(OTHER, trusted=True)
        with mock.patch("app.detection.roi.runtime.RETIRED_PRODUCER_LIMIT", 0):
            # The replacement is refused: the detector never sees the restart.
            self.assertFalse(offer(replacement))
        self.assertTrue(harness.runtime._slots[OTHER].history_exhausted)
        harness.clock.value += loss_delay_ns
        harness.runtime.source_unavailable(OTHER, trusted=True)
        harness.runtime.step()
        return harness

    def test_trusted_loss_after_history_exhaustion_never_confirms_tamper(self):
        # Claude (#213) / Owner decision 2026-10-11: a loss after exhaustion
        # is handed to the detector as untrusted.
        harness = self._exhausted_after_shift(loss_before_exhaustion=False)
        self.assertEqual([], harness.recorder.items)
        source = harness.source(OTHER)
        self.assertEqual(Observation.UNKNOWN, source.tamper)
        self.assertEqual("stream_history_exhausted", source.tamper_reason)

    def test_loss_at_the_exhaustion_instant_is_untrusted(self):
        # #224 item 1: the boundary `now >= exhausted_ns` is inclusive. A loss
        # with the very monotonic timestamp of the exhaustion is already after
        # it (the detector never saw the refused restart), so it never
        # confirms tamper; a `>` comparison would let it correlate.
        harness = self._exhausted_after_shift(loss_before_exhaustion=False, loss_delay_ns=0)
        self.assertEqual(harness.runtime._slots[OTHER].exhausted_ns, harness.clock.value)
        self.assertEqual([], harness.recorder.items)
        source = harness.source(OTHER)
        self.assertEqual(Observation.UNKNOWN, source.tamper)
        self.assertEqual("stream_history_exhausted", source.tamper_reason)

    def test_loss_timestamped_before_history_exhaustion_still_correlates(self):
        harness = self._exhausted_after_shift(loss_before_exhaustion=True)
        self.assertEqual([CriticalKind.CAMERA_TAMPER], harness.recorder.kinds())
        self.assertEqual("source_loss_after_scene_shift", harness.recorder.items[0].reason)

    def test_pending_sample_of_a_retired_producer_is_discarded(self):
        # Codex P2 (#213): B replaces A inside the sampling interval while an
        # A sample is pending; the A sample never completes a confirmation.
        harness = Harness(binding(OTHER, SourceType.REMOTE_AGENT))
        harness.runtime.start()
        first, second = uuid4(), uuid4()

        def offer(stream, luma, advance=INTERVAL):
            harness.clock.value += advance
            return harness.runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                              height=HEIGHT, pixels=luma)

        for luma in (pixels(), pixels(), MOVED):
            self.assertTrue(offer(first, luma))
            harness.runtime.step()
        evaluated = harness.source(OTHER).evaluated
        self.assertTrue(offer(first, MOVED))
        # Inside the interval: sampled out, but it retires A.
        self.assertFalse(offer(second, pixels(), advance=1))
        harness.runtime.step()
        source = harness.source(OTHER)
        self.assertEqual([], harness.recorder.items)
        self.assertEqual(evaluated, source.evaluated)
        self.assertEqual(1, source.stale_rejected)
        self.assertEqual(1, source.sampled_out)
        self.assertIsNone(harness.runtime._slots[OTHER].sample)

    def test_sample_pending_before_a_calibration_refresh_is_discarded(self):
        # Codex P2 (#213): a frame captured before the refresh request never
        # becomes a temporal-confirmation sample of the refreshed detector.
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.frame()
        harness.frame(MOVED)
        harness.clock.value += INTERVAL
        harness.runtime.on_uvc_frame(SOURCE, VideoFrame(yuyv(MOVED), 99, 0.0))
        harness.runtime.request_calibration_refresh()
        self.assertTrue(harness.source().refresh_pending)
        harness.runtime.step()
        source = harness.source()
        self.assertFalse(source.refresh_pending)
        self.assertEqual(1, source.refresh_discarded)
        self.assertEqual("awaiting_sample", source.reason)
        harness.frame(MOVED)
        self.assertEqual([], harness.recorder.items)
        # Frames after the refresh still confirm against the new calibration
        # (the discarded sample left a sequence gap: quality recovers first).
        for _ in range(4):
            harness.frame(MOVED)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())

    def test_refresh_deferred_by_sustained_losses_is_reported_pending(self):
        harness = Harness()
        harness.runtime.start()
        harness.frame()
        harness.runtime.request_calibration_refresh()
        for _ in range(3):
            harness.clock.value += 1
            harness.runtime.source_unavailable(SOURCE, trusted=False)
            harness.runtime.step()
            self.assertTrue(harness.source().refresh_pending)
        harness.runtime.step()
        self.assertFalse(harness.source().refresh_pending)
        self.assertEqual("awaiting_sample", harness.source().reason)


class SyntheticYuyvCapture:
    """Synthetic capture producing generated YUYV frames for one device."""

    def __init__(self, discovery):
        self.discovery = discovery
        self.instances = []
        self.luma = pixels()

    def __call__(self, candidate, profile, *, verify_identity):
        factory = self

        class Capture:
            def __init__(self):
                self.closed, self.sequence = False, 0

            def open(self):
                if not verify_identity(candidate):
                    raise RuntimeError("synthetic identity changed")
                return NegotiatedVideo(profile, WIDTH * 4, WIDTH * HEIGHT * 8)

            def read_frame(self, timeout):
                time.sleep(0.01)
                self.sequence += 1
                return VideoFrame(yuyv(factory.luma), self.sequence, time.monotonic())

            def close(self):
                self.closed = True

        capture = Capture()
        self.instances.append(capture)
        return capture


class SceneApplicationWiringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.settings = Settings(Path(temporary.name))

    async def test_unconfigured_scene_monitoring_is_explicit(self):
        from tests.test_uvc_runtime import synthetic_admission
        application = create_app(self.settings, storage_reservation=synthetic_admission)
        with self.assertLogs("app.main", level="WARNING") as logs:
            async with asyncio.timeout(20), application.router.lifespan_context(application):
                self.assertIs(SceneRuntimeState.UNCONFIGURED,
                              application.state.scene_monitoring_state)
                self.assertIsNone(application.state.scene_monitoring)
        self.assertTrue(any("scene_monitoring_unconfigured" in line for line in logs.output))

    async def _until(self, predicate, timeout=5.0):
        # The application watcher is an asyncio task: yield to the loop.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.01)
        return predicate()

    def _scene_application(self, recorder, gap_ns=10_000_000_000):
        from tests.test_uvc_runtime import synthetic_admission
        remote = binding(OTHER, SourceType.REMOTE_AGENT, sample_interval_ns=1)
        rules = policy(maximum_gap_ns=gap_ns, confirmation_ns=1)
        return create_app(
            self.settings, storage_reservation=synthetic_admission,
            scene_monitoring=SceneMonitoringConfiguration((remote,), critical_capacity=2),
            scene_monitoring_dependencies=SceneMonitoringDependencies(
                recorder=recorder, calibrations=lambda value: calibration_for(value, rules=rules),
                tick_seconds=0.01),
        )

    async def test_application_scene_state_follows_backpressure_and_recovery(self):
        # Codex P2 (#213): the application snapshot must not stay RUNNING
        # while critical staging is backpressured.
        recorder = Recorder()
        recorder.fail = True
        application = self._scene_application(recorder)
        stream = uuid4()
        # Bounded: a shutdown that waits on the watcher fails, never hangs.
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            self.assertIs(SceneRuntimeState.RUNNING, application.state.scene_monitoring_state)
            for luma in (pixels(), pixels(), MOVED, MOVED):
                evaluated = runtime.status().sources[0].evaluated
                await asyncio.sleep(0.002)
                self.assertTrue(runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                                   height=HEIGHT, pixels=luma))
                self.assertTrue(await self._until(
                    lambda: runtime.status().sources[0].evaluated > evaluated))
            self.assertEqual(1, runtime.status().critical_pending)
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.DEGRADED))
            recorder.fail = False
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.RUNNING))
        self.assertIs(SceneRuntimeState.STOPPED, application.state.scene_monitoring_state)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], recorder.kinds())

    async def _offer(self, runtime, stream, luma):
        evaluated = runtime.status().sources[0].evaluated
        await asyncio.sleep(0.002)
        self.assertTrue(runtime.offer_luma(OTHER, stream_id=stream, width=WIDTH,
                                           height=HEIGHT, pixels=luma))
        self.assertTrue(await self._until(
            lambda: runtime.status().sources[0].evaluated > evaluated))

    async def test_application_scene_state_degrades_on_source_loss(self):
        # Codex P2 (#213): the watched application state is not RUNNING
        # while a source is lost, until a new sample establishes recovery.
        application = self._scene_application(Recorder())
        stream = uuid4()
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            await self._offer(runtime, stream, pixels())
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.RUNNING))
            runtime.source_unavailable(OTHER, trusted=True)
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.DEGRADED))
            await self._offer(runtime, stream, pixels())
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.RUNNING))
        self.assertIs(SceneRuntimeState.STOPPED, application.state.scene_monitoring_state)

    async def test_application_scene_state_reports_dead_worker(self):
        application = self._scene_application(Recorder())
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            real = runtime.status
            with self.assertLogs("app.main", level="ERROR") as logs:
                # A worker that exited without reporting a failure.
                runtime.status = lambda: replace(real(), worker_running=False)
                self.assertTrue(await self._until(
                    lambda: application.state.scene_monitoring_state
                    is SceneRuntimeState.UNAVAILABLE))
            del runtime.status
        self.assertTrue(any("scene_monitoring_unavailable" in line for line in logs.output))

    async def test_application_scene_state_reports_dead_delivery_thread(self):
        # Claude (#213): a delivery thread that is gone delivers nothing.
        application = self._scene_application(Recorder())
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            real = runtime.status
            with self.assertLogs("app.main", level="ERROR") as logs:
                runtime.status = lambda: replace(real(), delivery_running=False)
                self.assertTrue(await self._until(
                    lambda: application.state.scene_monitoring_state
                    is SceneRuntimeState.UNAVAILABLE))
            del runtime.status
        self.assertTrue(any("scene_monitoring_unavailable" in line for line in logs.output))

    async def test_application_scene_state_degrades_when_samples_stop(self):
        # Codex P2 (#213): no sample within the calibrated gap is DEGRADED
        # at the application level too, until a fresh sample recovers it.
        application = self._scene_application(Recorder(), gap_ns=1_000_000_000)
        stream = uuid4()
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            await self._offer(runtime, stream, pixels())
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.RUNNING))
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.DEGRADED))
            self.assertEqual("observation_stale", runtime.status().sources[0].reason)
            await self._offer(runtime, stream, pixels())
            self.assertTrue(await self._until(
                lambda: application.state.scene_monitoring_state is SceneRuntimeState.RUNNING))
        self.assertIs(SceneRuntimeState.STOPPED, application.state.scene_monitoring_state)

    async def test_application_scene_state_reports_unreadable_status(self):
        application = self._scene_application(Recorder())
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring

            def unreadable():
                raise RuntimeError("synthetic status failure")

            with self.assertLogs("app.main", level="ERROR") as logs:
                runtime.status = unreadable
                self.assertTrue(await self._until(
                    lambda: application.state.scene_monitoring_state
                    is SceneRuntimeState.UNAVAILABLE))
            del runtime.status
        self.assertTrue(any("scene_monitoring_unavailable" in line for line in logs.output))

    async def test_application_scene_state_reports_worker_failure(self):
        application = self._scene_application(Recorder())
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            self.assertIs(SceneRuntimeState.RUNNING, application.state.scene_monitoring_state)

            def broken():
                raise RuntimeError("synthetic worker failure")

            with self.assertLogs("app.detection.roi.runtime", level="ERROR"):
                runtime._cycle = broken
                runtime.request_calibration_refresh()
                self.assertTrue(await self._until(
                    lambda: application.state.scene_monitoring_state
                    is SceneRuntimeState.UNAVAILABLE))
        self.assertIs(SceneRuntimeState.UNAVAILABLE, application.state.scene_monitoring_state)

    async def test_runtime_reported_unavailability_is_logged_once(self):
        # Claude (#213): the runtime already logs its own unavailability; the
        # application watcher does not log it a second time.
        for case in ("worker_failure", "dead_delivery"):
            with self.subTest(case=case):
                application = self._scene_application(Recorder())
                async with asyncio.timeout(20), application.router.lifespan_context(application):
                    runtime = application.state.scene_monitoring

                    def broken():
                        raise RuntimeError("synthetic worker failure")

                    with self.assertLogs("app", level="ERROR") as logs:
                        if case == "worker_failure":
                            runtime._cycle = broken
                            runtime.request_calibration_refresh()
                        else:
                            runtime._pump.close(1.0)
                        self.assertTrue(await self._until(
                            lambda: application.state.scene_monitoring_state
                            is SceneRuntimeState.UNAVAILABLE))
                        for _ in range(5):
                            runtime.status()
                            await asyncio.sleep(0.02)
                self.assertEqual(1, sum("scene_monitoring_unavailable" in line
                                        for line in logs.output), logs.output)

    async def test_local_uvc_frames_reach_scene_detector_and_stop_cleanly(self):
        from tests.test_uvc_runtime import synthetic_admission
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial-a")
        discovery = Discovery([camera])
        capture = SyntheticYuyvCapture(discovery)
        source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=CaptureProfile(WIDTH * 2, HEIGHT * 2, 10, "YUYV"),
        )
        item = binding(source.id, sample_interval_ns=20_000_000)
        recorder = Recorder()
        rules = policy(maximum_gap_ns=10_000_000_000, confirmation_ns=1)
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=LocalUvcDependencies(discovery=discovery,
                                                        capture_factory=capture),
            scene_monitoring=SceneMonitoringConfiguration((item,)),
            scene_monitoring_dependencies=SceneMonitoringDependencies(
                recorder=recorder, calibrations=lambda value: calibration_for(value, rules=rules),
                tick_seconds=0.05),
        )
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(database), PermitOwner()), CameraRegistry(database),
        )
        registry = CameraRegistry(database)
        async with asyncio.timeout(20), application.router.lifespan_context(application):
            runtime = application.state.scene_monitoring
            self.assertIs(SceneRuntimeState.RUNNING, application.state.scene_monitoring_state)
            application.state.local_uvc.reapprove(admin, "synthetic-owner", source.id, camera)
            self.assertTrue(wait_for(lambda: registry.get_source(source.id).health_state
                                     is SourceHealthState.ONLINE))
            self.assertTrue(wait_for(lambda: runtime.status().sources[0].movement
                                     is Observation.ABSENT))
            capture.luma = MOVED
            self.assertTrue(wait_for(lambda: recorder.kinds() == [CriticalKind.SERVER_MOVEMENT]))
        status = runtime.status()
        self.assertIs(SceneRuntimeState.STOPPED, status.state)
        self.assertFalse(status.worker_running)
        self.assertEqual(Observation.UNKNOWN, status.sources[0].movement)
        self.assertGreater(status.sources[0].sampled_out, 0)


if __name__ == "__main__":
    unittest.main()
