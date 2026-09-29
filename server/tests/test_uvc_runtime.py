"""Synthetic lifecycle tests for the backend local UVC runtime (Issue #11).

No physical camera, V4L2 node or real frame is used: discovery and capture are
in-memory stand-ins and every frame payload is a fixed synthetic byte string.
"""

import asyncio
from contextlib import closing, contextmanager
from dataclasses import replace
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from app.audit import AuditAction, AuditOutcome, AuditStore, OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, CaptureProfile, SourceHealthState, SourceType
from app.cameras.uvc.capture import CaptureError, NegotiatedVideo, VideoFrame
from app.cameras.uvc.discovery import DiscoveryResult
from app.cameras.uvc.identity import CameraState, DeviceEvidence
from app.cameras.uvc.persistence import ApprovalStore
from app.cameras.uvc.config import LocalUvcConfiguration, parse_local_uvc
from app.cameras.uvc.runtime import (
    LocalUvcDependencies, LocalUvcRuntime, LocalUvcRuntimeState, SourceRuntimeState,
)
from app.deployment import Deployment
from app.main import create_app
from app.settings import ConfigurationError, Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.asgi import request


PROFILE = CaptureProfile(640, 480, 10, "MJPG")
FAST = dict(poll_timeout_seconds=0.05, retry_delay_seconds=0.05, join_timeout_seconds=2.0)


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class Discovery:
    """Thread-safe synthetic V4L2 discovery."""

    def __init__(self, devices=()):
        self._lock = threading.Lock()
        self._devices = list(devices)
        self.scans = 0

    @property
    def devices(self):
        with self._lock:
            return list(self._devices)

    @devices.setter
    def devices(self, value):
        with self._lock:
            self._devices = list(value)

    def scan(self):
        with self._lock:
            self.scans += 1
            return DiscoveryResult(tuple(self._devices), 0)


class CaptureFactory:
    """Synthetic capture that follows the discovery: an absent device fails."""

    def __init__(self, discovery):
        self.discovery = discovery
        self.instances = []
        self.block = None
        self.lock = threading.Lock()

    def __call__(self, candidate, profile, *, verify_identity):
        factory = self

        class Capture:
            def __init__(self):
                self.candidate, self.profile = candidate, profile
                self.verify = verify_identity
                self.closed = False
                self.sequence = 0

            def open(self):
                if not self.verify(self.candidate):
                    raise CaptureError("synthetic identity changed")
                return NegotiatedVideo(self.profile, 0, 1024)

            def read_frame(self, timeout):
                block = factory.block
                if block is not None:
                    block.wait(10)
                time.sleep(0.005)
                if self.candidate not in factory.discovery.devices:
                    raise CaptureError("synthetic unplug")
                self.sequence += 1
                return VideoFrame(b"synthetic-frame", self.sequence, 1.0)

            def close(self):
                self.closed = True

        capture = Capture()
        with self.lock:
            self.instances.append(capture)
        return capture


class PermitOwner:
    def require_owner(self, actor_context):
        if actor_context != "synthetic-owner":
            raise PermissionError("denied")


class RuntimeFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.database = Database(self.directory / "synthetic.sqlite")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.fixture_registry = CameraRegistry(self.database, unaudited_writes=True)
        self.registry = CameraRegistry(self.database)
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial-a")
        self.discovery = Discovery([self.camera])
        self.captures = CaptureFactory(self.discovery)
        self.frames = []
        self.frame_lock = threading.Lock()
        self.admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )

    def source(self, name="Synthetic source", **values):
        return self.fixture_registry.create_source(
            source_type=values.pop("source_type", SourceType.LOCAL_UVC), name=name,
            enabled=values.pop("enabled", True),
            desired_capture_profile=values.pop("desired_capture_profile", PROFILE), **values,
        )

    def on_frame(self, source_id, frame):
        with self.frame_lock:
            self.frames.append((source_id, frame.data))

    def frame_count(self, source_id):
        with self.frame_lock:
            return sum(1 for item in self.frames if item[0] == source_id)

    def runtime(self, *source_ids, health_sink=None, **kwargs):
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration(tuple(source_ids), **FAST), self.registry,
            on_frame=self.on_frame, health_sink=health_sink,
            discovery=self.discovery, capture_factory=self.captures, **kwargs,
        )
        self.addCleanup(runtime.stop)
        return runtime

    def health(self, source_id):
        return self.registry.get_source(source_id).health_state

    def wait_health(self, source_id, state, timeout=5.0):
        return wait_for(lambda: self.health(source_id) is state, timeout)


class RuntimeLifecycleTests(RuntimeFixture):
    def test_unapproved_source_never_acquires_a_device(self):
        source = self.source()
        runtime = self.runtime(source.id)
        self.assertIs(runtime.start().state, LocalUvcRuntimeState.RUNNING)
        self.assertTrue(runtime.status().sources[0].worker_running)
        writes = []
        original = self.registry.update_source_health

        def counted(*args, **kwargs):
            writes.append(args)
            return original(*args, **kwargs)

        with patch.object(self.registry, "update_source_health", side_effect=counted):
            time.sleep(0.3)
        # Retried polls of an unapproved, already-offline source write nothing.
        self.assertEqual([], writes)
        self.assertEqual(0, self.discovery.scans)
        self.assertEqual([], self.captures.instances)
        self.assertEqual(0, self.frame_count(source.id))
        self.assertIs(self.health(source.id), SourceHealthState.OFFLINE)

    def test_start_reapprove_stream_and_stop(self):
        source = self.source()
        runtime = self.runtime(source.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.assertTrue(wait_for(lambda: self.frame_count(source.id) > 0))
        registry_source = self.registry.get_source(source.id)
        self.assertEqual("MJPG", registry_source.negotiated_capture_profile.pixel_format)
        self.assertIsNotNone(registry_source.last_seen_at)
        records = [record for record in AuditStore(self.database).list_records()
                   if record.action is AuditAction.APPROVE_CAMERA]
        self.assertEqual([AuditOutcome.SUCCEEDED], [record.outcome for record in records])

        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOPPED)
        self.assertEqual([SourceRuntimeState.STOPPED], [item.state for item in status.sources])
        self.assertFalse(status.sources[0].worker_running)
        self.assertTrue(all(capture.closed for capture in self.captures.instances))
        self.assertIs(self.health(source.id), SourceHealthState.OFFLINE)
        # Clean shutdown releases the active-session marker.
        self.assertIsNone(ApprovalStore(self.database).load(source.id).session_token)
        count = self.frame_count(source.id)
        time.sleep(0.1)
        self.assertEqual(count, self.frame_count(source.id))

    def test_start_and_stop_are_idempotent_and_single_use(self):
        source = self.source()
        runtime = self.runtime(source.id)
        runtime.start()
        self.assertIs(runtime.start().state, LocalUvcRuntimeState.RUNNING)
        self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOPPED)
        self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOPPED)
        with self.assertRaises(RuntimeError):
            runtime.start()
        never = self.runtime(source.id)
        self.assertIs(never.stop().state, LocalUvcRuntimeState.STOPPED)

    def test_unplug_is_camera_offline_while_service_keeps_running(self):
        source = self.source()
        events = []
        runtime = self.runtime(source.id, health_sink=events.append)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

        self.discovery.devices = []
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        status = runtime.status()
        # Camera offline is distinct from capture service health.
        self.assertIs(status.state, LocalUvcRuntimeState.RUNNING)
        self.assertTrue(status.sources[0].worker_running)
        self.assertIn(CameraState.OFFLINE, [event.state for event in events])
        self.assertTrue(all(event.source_id == source.id for event in events))

        # A uniquely serial-identified camera on a new video node reconnects.
        self.discovery.devices = [replace(self.camera, device_path="/dev/video7")]
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.assertEqual(source.id, self.registry.get_source(source.id).id)

    def test_identical_non_serial_reconnect_requires_manual_intervention(self):
        source = self.source()
        weak = DeviceEvidence("/dev/video0", "synthetic", "model", None,
                              topology="1-1", instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        runtime = self.runtime(source.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, weak)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

        self.discovery.devices = []
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        # Same port, same /dev/videoN and same model: still not proof.
        returned = replace(weak, instance_token=(1, 2, 4))
        twin = replace(weak, device_path="/dev/video1", topology="1-2",
                       instance_token=(1, 2, 5))
        self.discovery.devices = [returned, twin]
        self.assertTrue(self.wait_health(
            source.id, SourceHealthState.MANUAL_INTERVENTION_REQUIRED))
        frames = self.frame_count(source.id)
        time.sleep(0.2)
        self.assertEqual(frames, self.frame_count(source.id))
        self.assertIs(self.health(source.id), SourceHealthState.MANUAL_INTERVENTION_REQUIRED)
        self.assertIs(runtime.status().state, LocalUvcRuntimeState.RUNNING)

        # Only an explicit, audited Owner selection restores capture.
        runtime.reapprove(self.admin, "synthetic-owner", source.id, returned)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

    def test_single_indistinguishable_reattach_is_not_bound_automatically(self):
        source = self.source()
        weak = DeviceEvidence("/dev/video0", "synthetic", "model", None,
                              instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        runtime = self.runtime(source.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, weak)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.discovery.devices = []
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        self.discovery.devices = [replace(weak, instance_token=(1, 2, 9))]
        self.assertTrue(self.wait_health(
            source.id, SourceHealthState.MANUAL_INTERVENTION_REQUIRED))

    def test_duplicate_serial_reconnect_requires_manual_intervention(self):
        source = self.source()
        runtime = self.runtime(source.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.discovery.devices = []
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        self.discovery.devices = [self.camera, replace(self.camera, device_path="/dev/video3")]
        self.assertTrue(self.wait_health(
            source.id, SourceHealthState.MANUAL_INTERVENTION_REQUIRED))

    def test_denied_reapproval_keeps_source_supervised(self):
        source = self.source()
        runtime = self.runtime(source.id)
        runtime.start()
        with self.assertRaises(Exception):
            runtime.reapprove(self.admin, "not-owner", source.id, self.camera)
        status = runtime.status()
        self.assertIs(status.sources[0].state, SourceRuntimeState.RUNNING)
        self.assertTrue(status.sources[0].worker_running)
        self.assertIsNone(ApprovalStore(self.database).load(source.id))
        with self.assertRaises(ValueError):
            runtime.reapprove(self.admin, "synthetic-owner", uuid4(), self.camera)

    def test_one_to_four_sources_and_one_loss_does_not_stop_others(self):
        cameras = [replace(self.camera, device_path=f"/dev/video{index}",
                           serial=f"serial-{index}") for index in range(4)]
        self.discovery.devices = cameras
        sources = [self.source(f"Synthetic {index}") for index in range(4)]
        runtime = self.runtime(*(source.id for source in sources))
        runtime.start()
        for source, camera in zip(sources, cameras):
            runtime.reapprove(self.admin, "synthetic-owner", source.id, camera)
        for source in sources:
            self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.discovery.devices = cameras[1:]
        self.assertTrue(self.wait_health(sources[0].id, SourceHealthState.OFFLINE))
        for source in sources[1:]:
            before = self.frame_count(source.id)
            self.assertTrue(wait_for(lambda: self.frame_count(source.id) > before))
            self.assertIs(self.health(source.id), SourceHealthState.ONLINE)
        self.assertEqual(4, sum(item.worker_running for item in runtime.status().sources))

        self.assertEqual(1, len(LocalUvcConfiguration((uuid4(),)).source_ids))
        with self.assertRaises(ConfigurationError):
            LocalUvcConfiguration(tuple(uuid4() for _ in range(5)))

    def test_misconfigured_sources_are_rejected_explicitly(self):
        remote_node = self.fixture_registry.create_capture_node("Synthetic node")
        valid = self.source()
        missing = uuid4()
        remote = self.fixture_registry.create_source(
            source_type=SourceType.REMOTE_AGENT, name="Synthetic remote",
            capture_node_id=remote_node.id, enabled=False, desired_capture_profile=None)
        sources = [valid.id, missing, remote.id]
        runtime = self.runtime(*sources)
        status = runtime.start()
        self.assertIs(status.state, LocalUvcRuntimeState.DEGRADED)
        states = {item.source_id: item.state for item in status.sources}
        self.assertIs(states[valid.id], SourceRuntimeState.RUNNING)
        self.assertIs(states[missing], SourceRuntimeState.REJECTED)
        for rejected in sources[1:]:
            self.assertIs(states[rejected], SourceRuntimeState.REJECTED)
            self.assertFalse(next(item for item in status.sources
                                  if item.source_id == rejected).worker_running)

        only_missing = self.runtime(uuid4())
        self.assertIs(only_missing.start().state, LocalUvcRuntimeState.FAILED)

    def test_worker_start_failure_is_visible_and_marks_camera_offline(self):
        source = self.source()
        self.fixture_registry.update_source_health(source.id, health_state=SourceHealthState.ONLINE)

        class FailingSupervisor:
            def __init__(self, adapter, **_kwargs):
                self.adapter = adapter

            def start(self, source_id):
                raise RuntimeError("synthetic thread start failure")

            def status(self, source_id):
                return None

            def close(self):
                return None

        runtime = self.runtime(source.id, supervisor_factory=FailingSupervisor)
        status = runtime.start()
        self.assertIs(status.state, LocalUvcRuntimeState.FAILED)
        self.assertIs(status.sources[0].state, SourceRuntimeState.WORKER_FAILED)
        self.assertIs(self.health(source.id), SourceHealthState.OFFLINE)

    def test_hung_worker_stop_fails_closed_without_cross_thread_close(self):
        source = self.source()
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), poll_timeout_seconds=0.05,
                                  retry_delay_seconds=0.05, join_timeout_seconds=0.1),
            self.registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures,
        )
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.captures.block = block
        time.sleep(0.05)
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOP_FAILED)
        # The adapter was not closed from the stopping thread while the worker
        # still owns the capture poll.
        self.assertFalse(runtime.adapter.closed)
        self.captures.block = None
        block.set()
        self.assertTrue(wait_for(lambda: all(capture.closed
                                             for capture in self.captures.instances)))
        self.assertTrue(wait_for(lambda: self.health(source.id) is SourceHealthState.OFFLINE))

    def test_health_sink_failure_and_event_bound_do_not_stop_capture(self):
        source = self.source()

        def failing_sink(event):
            raise RuntimeError("synthetic sink failure")

        runtime = self.runtime(source.id, health_sink=failing_sink, max_health_events=2)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        for _ in range(2):
            self.discovery.devices = []
            self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
            self.discovery.devices = [self.camera]
            self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        status = runtime.status()
        self.assertGreater(status.health_sink_failures, 0)
        self.assertGreater(status.health_events_dropped, 0)
        self.assertLessEqual(len(runtime.recent_health_events()), 2)
        self.assertTrue(status.sources[0].worker_running)

    def test_flapping_health_logging_is_rate_limited(self):
        from app.cameras.uvc.identity import HealthEvent
        source_id = uuid4()
        clock = [0.0]
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source_id,)), self.registry, on_frame=self.on_frame,
            monotonic=lambda: clock[0],
        )
        with self.assertLogs("app.cameras.uvc.runtime", level="INFO") as logs:
            for index in range(20):
                state = CameraState.OFFLINE if index % 2 else CameraState.DEGRADED
                runtime._health(HealthEvent(source_id, state, "synthetic"))
            clock[0] = 11.0
            runtime._health(HealthEvent(source_id, CameraState.OFFLINE, "synthetic"))
            runtime._health(HealthEvent(source_id, CameraState.MANUAL, "synthetic"))
        self.assertEqual(3, len(logs.output))
        self.assertEqual(19, runtime.status().health_logs_suppressed)
        self.assertEqual(22, len(runtime.recent_health_events()))

    def test_frame_rate_does_not_write_registry_per_frame(self):
        source = self.source()
        runtime = self.runtime(source.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        writes = []
        original = self.registry.update_source_health

        def counted(*args, **kwargs):
            writes.append(kwargs.get("last_seen_at"))
            return original(*args, **kwargs)

        before = self.frame_count(source.id)
        with patch.object(self.registry, "update_source_health", side_effect=counted):
            time.sleep(0.3)
        delivered = self.frame_count(source.id) - before
        self.assertGreater(delivered, 5)
        self.assertLessEqual(len(writes), 1)


class RestartDurabilityTests(RuntimeFixture):
    def test_clean_restart_reconnects_unique_serial_camera(self):
        source = self.source()
        first = self.runtime(source.id)
        first.start()
        first.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.assertIs(first.stop().state, LocalUvcRuntimeState.STOPPED)
        self.discovery.devices = [replace(self.camera, device_path="/dev/video4")]
        second = self.runtime(source.id)
        second.start()
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

    def test_manual_latch_survives_restart(self):
        source = self.source()
        first = self.runtime(source.id)
        first.start()
        first.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.discovery.devices = []
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        self.discovery.devices = [self.camera, replace(self.camera, device_path="/dev/video5")]
        self.assertTrue(self.wait_health(
            source.id, SourceHealthState.MANUAL_INTERVENTION_REQUIRED))
        first.stop()
        self.discovery.devices = [self.camera]
        second = self.runtime(source.id)
        second.start()
        time.sleep(0.2)
        self.assertIs(self.health(source.id), SourceHealthState.MANUAL_INTERVENTION_REQUIRED)
        self.assertEqual(0, sum(1 for capture in self.captures.instances if not capture.closed))


@contextmanager
def synthetic_admission():
    yield


class ApplicationWiringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.settings = Settings(Path(temporary.name))
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial-a")
        self.discovery = Discovery([self.camera])
        self.dependencies = LocalUvcDependencies(
            discovery=self.discovery, capture_factory=CaptureFactory(self.discovery),
        )

    async def assert_surface_closed(self, application):
        for path in ("/", "/api/live", "/preview"):
            messages = await request(application, path)
            self.assertEqual(404, messages[0]["status"])
        messages = await request(application, "/live", kind="websocket")
        self.assertEqual(1008, messages[0]["code"])

    async def test_missing_configuration_is_explicit_unconfigured_state(self):
        application = create_app(self.settings, storage_reservation=synthetic_admission)
        with self.assertLogs("app.main", level="WARNING") as logs:
            async with application.router.lifespan_context(application):
                self.assertIs(application.state.local_uvc_state,
                              LocalUvcRuntimeState.UNCONFIGURED)
                self.assertIsNone(application.state.local_uvc)
                await self.assert_surface_closed(application)
        self.assertTrue(any("local_uvc_unconfigured" in line for line in logs.output))
        self.assertEqual(0, self.discovery.scans)

    async def test_configured_without_storage_admission_never_captures(self):
        configuration = LocalUvcConfiguration((uuid4(),), **FAST)
        application = create_app(self.settings, local_uvc=configuration,
                                 local_uvc_dependencies=self.dependencies)
        async with application.router.lifespan_context(application):
            self.assertIs(application.state.local_uvc_state,
                          LocalUvcRuntimeState.STORAGE_UNADMITTED)
            await asyncio.sleep(0.1)
        self.assertEqual(0, self.discovery.scans)
        self.assertEqual([], self.dependencies.capture_factory.instances)

    async def test_lifespan_starts_and_stops_configured_sources(self):
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=PROFILE,
        )
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(database), PermitOwner()), CameraRegistry(database),
        )
        registry = CameraRegistry(database)
        async with application.router.lifespan_context(application):
            runtime = application.state.local_uvc
            self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.RUNNING)
            runtime.reapprove(admin, "synthetic-owner", source.id, self.camera)
            self.assertTrue(wait_for(lambda: registry.get_source(source.id).health_state
                                     is SourceHealthState.ONLINE))
            await self.assert_surface_closed(application)
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)
        self.assertFalse(runtime.status().sources[0].worker_running)
        self.assertTrue(all(capture.closed
                            for capture in self.dependencies.capture_factory.instances))
        self.assertIs(registry.get_source(source.id).health_state, SourceHealthState.OFFLINE)
        self.assertEqual(0, application.state.local_preview.status.retained_bytes)

    async def test_runtime_start_failure_does_not_abort_application(self):
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((uuid4(),), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        with patch.object(LocalUvcRuntime, "start", side_effect=RuntimeError("synthetic")):
            with self.assertLogs("app.main", level="ERROR"):
                async with application.router.lifespan_context(application):
                    self.assertTrue(application.state.ready)
                    self.assertIs(application.state.local_uvc_state,
                                  LocalUvcRuntimeState.FAILED)

    def test_invalid_configuration_type_is_refused(self):
        with self.assertRaises(TypeError):
            create_app(self.settings, local_uvc={"source_ids": []})


class ConfigurationParsingTests(unittest.TestCase):
    def test_valid_configuration(self):
        identities = [str(uuid4()) for _ in range(4)]
        parsed = parse_local_uvc({"source_ids": identities, "retry_delay_seconds": 2})
        self.assertEqual(tuple(UUID(value) for value in identities), parsed.source_ids)
        self.assertEqual(2.0, parsed.retry_delay_seconds)
        self.assertNotIn(identities[0], repr(parsed))

    def test_invalid_configuration_is_value_free(self):
        identity = str(uuid4())
        cases = [
            None, [], {}, {"source_ids": []}, {"source_ids": identity},
            {"source_ids": [identity, identity]},
            {"source_ids": [identity.upper()]},
            {"source_ids": ["{" + identity + "}"]},
            {"source_ids": [str(uuid4()) for _ in range(5)]},
            {"source_ids": [identity], "device_path": "/dev/video0"},
            {"source_ids": [identity], "serial": "private-serial"},
            {"source_ids": [identity], "poll_timeout_seconds": 0},
            {"source_ids": [identity], "retry_delay_seconds": True},
            {"source_ids": [identity], "join_timeout_seconds": float("nan")},
            {"source_ids": [identity], "retry_delay_seconds": 1e9},
            {"source_ids": [7]},
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ConfigurationError) as raised:
                parse_local_uvc(value)
            self.assertNotIn(identity, str(raised.exception))
            self.assertNotIn("private-serial", str(raised.exception))

    def test_documented_local_uvc_example_passes_validation(self):
        text = (Path(__file__).resolve().parents[1] / "docs" / "DEPLOYMENT.md").read_text()
        section = text.split("### Local UVC section", 1)[1]
        example = json.loads("{" + section.split("```json", 1)[1].split("```", 1)[0] + "}")
        self.assertEqual(1, len(parse_local_uvc(example["local_uvc"]).source_ids))

    def test_launcher_passes_local_uvc_to_application(self):
        from types import SimpleNamespace
        from app.__main__ import run
        handlers = logging.getLogger().handlers[:]
        level = logging.getLogger().level
        self.addCleanup(lambda: (setattr(logging.getLogger(), "handlers", handlers),
                                 logging.getLogger().setLevel(level)))
        configuration = LocalUvcConfiguration((uuid4(),))
        with tempfile.TemporaryDirectory() as temporary:
            with patch("app.__main__.create_app") as create, patch("app.systemd.build_server"):
                run(Settings(Path(temporary)), SimpleNamespace(storage_configured=True),
                    configuration)
        self.assertIs(create.call_args.kwargs["local_uvc"], configuration)

    def test_standalone_installer_validates_local_uvc_with_stdlib_only(self):
        from build_installer import build
        with tempfile.TemporaryDirectory(prefix="server-uvc-installer-") as directory:
            target = Path(directory) / "installer.pyz"
            build(target)
            code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                    "from app.deployment import parse_local_uvc; "
                    "print(len(parse_local_uvc({'source_ids': [sys.argv[2]]}).source_ids))")
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(target), str(uuid4())],
                cwd="/", capture_output=True, text=True, check=True, timeout=60,
            )
        self.assertEqual("1", result.stdout.strip())

    def test_deployment_accepts_optional_local_uvc_object(self):
        with tempfile.TemporaryDirectory(prefix="server-uvc-synthetic-") as directory:
            root = Path(directory)
            runtime = root / "runtime"
            for path in (runtime, runtime / "state", runtime / "recordings", runtime / "audit"):
                path.mkdir(mode=0o700)
            (root / "code").mkdir()
            device = runtime.stat().st_dev
            base = {
                "runtime_root": str(runtime), "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444",
                "service_uid": os.geteuid(),
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }
            config = root / "deployment.json"

            def load(value):
                config.write_text(json.dumps(value))
                config.chmod(0o600)
                with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid()), patch(
                        "app.deployment._approved_filesystem_device", return_value=device), patch(
                        "app.deployment.os.path.ismount", return_value=True), patch(
                        "app.deployment._administrator_directory"), patch(
                        "app.deployment._operating_system_root_device",
                        return_value=device + 1):
                    return Deployment.load(config, code_root=root / "code")

            self.assertIsNone(load(base).local_uvc)
            identity = str(uuid4())
            deployment = load(dict(base, local_uvc={"source_ids": [identity]}))
            self.assertEqual((UUID(identity),), deployment.local_uvc.source_ids)
            self.assertNotIn(identity, repr(deployment))
            with self.assertRaises(ConfigurationError):
                load(dict(base, local_uvc={"source_ids": []}))


class LoggingTests(RuntimeFixture):
    def test_health_logs_carry_no_device_evidence(self):
        from io import StringIO
        from app.logging import configure_logging
        handlers = logging.getLogger().handlers[:]
        level = logging.getLogger().level
        self.addCleanup(lambda: (setattr(logging.getLogger(), "handlers", handlers),
                                 logging.getLogger().setLevel(level)))
        stream = StringIO()
        configure_logging("INFO", stream)
        source = self.source()
        runtime = self.runtime(source.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.discovery.devices = []
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        runtime.stop()
        output = stream.getvalue()
        self.assertIn("local_uvc_source_health_changed", output)
        for private in ("/dev/video0", "serial-a", str(source.id)):
            self.assertNotIn(private, output)


if __name__ == "__main__":
    unittest.main()
