"""Main-runtime scene detection wiring (#205) with generated synthetic frames.

Every pixel is generated in memory; no camera, real scene or person is used.
"""

from contextlib import closing
from dataclasses import replace
import tempfile
import threading
import time
import unittest
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
    SceneRuntimeState, SceneSourceBinding, SceneSourceState,
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


class Harness:
    def __init__(self, *bindings, recorder=True, calibrations="default", capacity=None):
        self.clock = Clock()
        self.recorder = Recorder() if recorder else None
        if calibrations == "default":
            calibrations = calibration_for
        options = {} if capacity is None else {"critical_capacity": capacity}
        self.configuration = SceneMonitoringConfiguration(tuple(bindings or (binding(),)), **options)
        self.runtime = SceneMonitoringRuntime(
            self.configuration,
            SceneMonitoringDependencies(recorder=self.recorder, calibrations=calibrations,
                                        monotonic_ns=self.clock, utcnow=lambda: NOW),
            threaded=False)
        self.sequence = {}

    def frame(self, luma=None, source=SOURCE, advance=INTERVAL):
        self.clock.value += advance
        number = self.sequence.get(source, 0) + 1
        self.sequence[source] = number
        self.runtime.on_uvc_frame(source, VideoFrame(yuyv(luma or pixels()), number, 0.0))
        self.runtime.step()
        return self.source(source)

    def source(self, source=SOURCE):
        return next(item for item in self.runtime.status().sources if item.source_id == source)


MOVED = transformed(pixels(), (1, 0), region=(4, 4, 8, 7))
SHIFTED = transformed(pixels(), (1, 0))


class SceneRuntimeFailClosedTests(unittest.TestCase):
    def test_without_durable_recorder_no_detector_runs(self):
        harness = Harness(recorder=False)
        status = harness.runtime.start()
        self.assertIs(SceneRuntimeState.UNAVAILABLE, status.state)
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
            async with application.router.lifespan_context(application):
                self.assertIs(SceneRuntimeState.UNCONFIGURED,
                              application.state.scene_monitoring_state)
                self.assertIsNone(application.state.scene_monitoring)
        self.assertTrue(any("scene_monitoring_unconfigured" in line for line in logs.output))

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
        async with application.router.lifespan_context(application):
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
