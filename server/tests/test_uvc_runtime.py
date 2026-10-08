"""Synthetic lifecycle tests for the backend local UVC runtime (Issue #11).

No physical camera, V4L2 node or real frame is used: discovery and capture are
in-memory stand-ins and every frame payload is a fixed synthetic byte string.
"""

import asyncio
from contextlib import closing, contextmanager
from dataclasses import asdict, replace
import json
import logging
import os
from pathlib import Path
import stat
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
from app.cameras.uvc.registry_adapter import LocalUvcAdapter
from app.cameras.uvc.config import LocalUvcConfiguration, parse_local_uvc
from app.cameras.uvc import runtime as runtime_module
from app.cameras.uvc.runtime import (
    LocalUvcDependencies, LocalUvcRuntime, LocalUvcRuntimeState, SourceRuntimeState,
)
from app.deployment import Deployment
from app.main import create_app, run_to_completion
from app.monitoring.runtime import MonitoringDependencies, RuntimeState
from app.settings import ConfigurationError, Settings
from app.storage.database import Database, PinnedDatabase
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.asgi import request
from tests.test_recording import SyntheticValidator
from tests.test_monitoring_runtime import RuntimeFixture as MonitoringFixture


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
        # Set once a read has entered ``block``.
        self.blocked = threading.Event()
        # Set to an Event to make close() hang (STREAMOFF/unmap/close).
        self.close_block = None
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
                    factory.blocked.set()
                    block.wait(10)
                time.sleep(0.005)
                if self.candidate not in factory.discovery.devices:
                    raise CaptureError("synthetic unplug")
                self.sequence += 1
                return VideoFrame(b"synthetic-frame", self.sequence, 1.0)

            def close(self):
                close_block = factory.close_block
                if close_block is not None:
                    close_block.wait(30)
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

    def runtime(self, *source_ids, health_sink=None, configuration_timing=None, **kwargs):
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration(tuple(source_ids), **FAST, **(configuration_timing or {})),
            self.registry,
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

    def test_worker_blocked_without_frames_is_not_left_online(self):
        # Reproduces the hardware finding: the worker is stuck inside a call
        # and delivers no frame, so its own read timeout never runs. The
        # supervisor watchdog must still lower the online claim, and only
        # resumed frames restore it.
        source = self.source()
        runtime = self.runtime(source.id, configuration_timing=dict(
            frame_stall_seconds=0.25, frame_stall_reopen_seconds=30.0))
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.captures.block = block
        self.addCleanup(block.set)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.DEGRADED, timeout=3.0))
        self.assertIs(CameraState.DEGRADED, runtime.status().sources[0].camera_state)
        # The descriptor was not torn down by the watchdog.
        self.assertEqual(1, len(self.captures.instances))
        self.assertFalse(self.captures.instances[0].closed)
        self.captures.block = None
        block.set()
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

    def test_hung_health_sink_never_blocks_the_worker(self):
        # Issue #173 item 1 (Codex P2 on #111): a downstream sink that hangs
        # must not stop the capture worker. Before the fix the worker's own
        # delivery waited behind the hung delivery thread, so the transitions
        # after a close (``device_disconnected``, the reconnect) stalled.
        source = self.source()
        armed, entered, release = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        delivered = []

        def hanging_sink(event):
            if armed.is_set() and not release.is_set():
                entered.set()
                release.wait(30)
            delivered.append(event)

        with patch.object(runtime_module, "HEALTH_SINK_STALL_SECONDS", 0.2), \
                patch.object(runtime_module, "HEALTH_SINK_MAX_PENDING", 5):
            runtime = self.runtime(source.id, health_sink=hanging_sink)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.assertTrue(wait_for(lambda: runtime.status().health_sink_pending == 0))
        armed.set()
        # Flap the camera while the sink hangs on the first transition.
        for _ in range(3):
            self.discovery.devices = []
            self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
            self.assertTrue(entered.wait(5))
            self.discovery.devices = [self.camera]
            self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        count = self.frame_count(source.id)
        self.assertTrue(wait_for(lambda: self.frame_count(source.id) > count))
        # The hang is visible: the delivery is stalled, the queue stays
        # bounded by coalescing, and the service is not reported healthy.
        self.assertTrue(wait_for(lambda: runtime.status().health_sink_stalled))
        status = runtime.status()
        self.assertIs(status.state, LocalUvcRuntimeState.DEGRADED)
        self.assertLessEqual(status.health_sink_pending, 5)
        self.assertGreater(status.health_sink_coalesced, 0)
        self.assertTrue(status.sources[0].worker_running)
        release.set()
        self.assertTrue(wait_for(lambda: runtime.status().health_sink_pending == 0
                                 and not runtime.status().health_sink_stalled))
        self.assertIs(runtime.status().state, LocalUvcRuntimeState.RUNNING)
        # Coalescing never drops a source's latest transition.
        self.assertEqual("video_capture_ready", delivered[-1].reason)

    def test_blocking_sink_on_a_watchdog_stall_does_not_stall_the_watchdog(self):
        # The watchdog itself emits ``video_frame_stalled``. A sink that blocks
        # on that event must not run on the watchdog thread, or the reopen
        # deadline (and every other source) would never be checked again.
        source = self.source()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def blocking_sink(event):
            if event.reason == "video_frame_stalled" and not release.is_set():
                entered.set()
                release.wait(10)

        runtime = self.runtime(source.id, health_sink=blocking_sink, configuration_timing=dict(
            frame_stall_seconds=0.25, frame_stall_reopen_seconds=1.0))
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.captures.block = block
        self.addCleanup(block.set)
        self.assertTrue(entered.wait(5))
        # The sink is still blocked; the watchdog keeps enforcing the reopen
        # deadline for the blocked worker.
        self.assertTrue(wait_for(
            lambda: runtime.status().sources[0].camera_state is CameraState.OFFLINE, 5.0))
        release.set()
        self.captures.block = None
        block.set()
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

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
        self.assertTrue(wait_for(
            lambda: CameraState.OFFLINE in [event.state for event in events]))
        self.assertTrue(all(event.source_id == source.id for event in events))

        # A uniquely serial-identified camera on a new video node reconnects.
        self.discovery.devices = [replace(self.camera, device_path="/dev/video7")]
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.assertEqual(source.id, self.registry.get_source(source.id).id)

    def test_registry_read_failure_is_current_capture_loss(self):
        # A read fault while the camera is live closes capture, delivers the
        # offline transition and degrades the service until polls succeed.
        source = self.source()
        events = []
        runtime = self.runtime(source.id, health_sink=events.append)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        self.assertTrue(wait_for(lambda: self.frame_count(source.id) > 0))

        def failing(source_id):
            raise RuntimeError("synthetic read fault")

        with patch.object(self.registry, "get_source", side_effect=failing):
            self.assertTrue(wait_for(
                lambda: runtime.status().state is LocalUvcRuntimeState.DEGRADED))
            self.assertTrue(wait_for(
                lambda: CameraState.OFFLINE in [event.state for event in events]))
            self.assertIsNot(runtime.status().sources[0].camera_state, CameraState.ONLINE)
            self.assertTrue(all(capture.closed for capture in self.captures.instances))
            count = self.frame_count(source.id)
            time.sleep(0.2)
            self.assertEqual(count, self.frame_count(source.id))
        self.assertTrue(wait_for(
            lambda: runtime.status().state is LocalUvcRuntimeState.RUNNING))
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))

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
                                  retry_delay_seconds=0.05, join_timeout_seconds=0.25,
                                  frame_stall_seconds=0.25),
            self.registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures,
        )
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.captures.block = block
        self.assertTrue(self.captures.blocked.wait(5))
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
        # Issue #173: once the worker has exited (its own cleanup succeeded),
        # a later stop() joins it and closes the adapter instead of treating
        # STOP_FAILED as terminal.
        self.assertTrue(wait_for(lambda: not runtime._supervisor.watchdog_running))
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOPPED)
        self.assertTrue(runtime.adapter.closed)

    def test_retried_stop_keeps_a_removed_workers_cleanup_failure(self):
        # Claude review on #188: source A's worker hangs past the join bound
        # while source B's worker exits with a failed stop_source. The first
        # close removes B; the retry after A exits must stay STOP_FAILED
        # instead of reporting a clean stop.
        hung, failing = self.source("Hung"), self.source("Failing")
        released = threading.Event()
        self.addCleanup(released.set)
        entered = threading.Event()
        armed = {"on": False}
        adapters = []

        class Adapter(LocalUvcAdapter):
            close_calls = 0

            def poll_source(self, source_id, *, timeout=1.0):
                if armed["on"] and source_id == hung.id:
                    entered.set()
                    released.wait(10)
                    return False
                return super().poll_source(source_id, timeout=timeout)

            def stop_source(self, source_id):
                result = super().stop_source(source_id)
                if source_id == failing.id:
                    raise RuntimeError("synthetic private cleanup detail")
                return result

            def close(self):
                type(self).close_calls += 1
                return super().close()

        def adapter_factory(*args, **kwargs):
            adapter = Adapter(*args, **kwargs)
            adapters.append(adapter)
            return adapter

        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((hung.id, failing.id), poll_timeout_seconds=0.05,
                                  retry_delay_seconds=0.05, join_timeout_seconds=0.25,
                                  frame_stall_seconds=0.25),
            self.registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures, adapter_factory=adapter_factory,
        )
        self.addCleanup(runtime.stop)
        runtime.start()
        armed["on"] = True
        self.assertTrue(entered.wait(5))
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOP_FAILED)
        # The hung worker keeps the adapter open.
        self.assertEqual(0, Adapter.close_calls)
        self.assertIsNone(runtime._supervisor.status(failing.id))
        released.set()

        def settled():
            hung_status = runtime._supervisor.status(hung.id)
            return ((hung_status is None or not hung_status.running)
                    and not runtime._supervisor.watchdog_running)

        self.assertTrue(wait_for(settled))
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOP_FAILED)
        # Every thread is gone, so the adapter is closed; the failure stays.
        self.assertEqual(1, Adapter.close_calls)
        self.assertTrue(adapters[0].closed)
        self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOP_FAILED)
        self.assertEqual(1, Adapter.close_calls)

    def test_worker_cleanup_failure_survives_a_retried_database_release(self):
        # Claude review on #188: a worker's own cleanup failure is recorded
        # by the runtime, so a retry that only finishes the database release
        # (the adapter is already closed) still reports STOP_FAILED.
        source = self.source()
        pinned = PinnedDatabase(Database(self.database.path))
        registry = CameraRegistry(pinned, reservation=ToggleAdmission())
        self.addCleanup(pinned.release)

        class Adapter(LocalUvcAdapter):
            def stop_source(self, source_id):
                super().stop_source(source_id)
                raise RuntimeError("synthetic private cleanup detail")

        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), **FAST), registry,
            on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures, adapter_factory=Adapter,
        )
        self.addCleanup(runtime.stop)
        runtime.start()
        self.assertTrue(pinned.pinned)
        release = pinned.release
        attempts = []

        def flaky_release():
            attempts.append(None)
            if len(attempts) == 1:
                raise OSError("synthetic private release detail")
            return release()

        with patch.object(pinned, "release", flaky_release):
            self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOP_FAILED)
            self.assertTrue(runtime.adapter.closed)
            self.assertTrue(pinned.pinned)
            self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOP_FAILED)
        self.assertEqual(2, len(attempts))
        self.assertFalse(pinned.pinned)

    def test_worker_blocked_through_a_timed_out_stop_is_not_left_online(self):
        # Issue #122: runtime.stop() closes the supervisor. When the worker is
        # blocked in a kernel call past the join bound, the worker and adapter
        # are left alive; the watchdog must keep running so the stalled source
        # leaves online in memory and in the registry.
        source = self.source()
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), poll_timeout_seconds=0.05,
                                  retry_delay_seconds=0.05, join_timeout_seconds=0.25,
                                  frame_stall_seconds=0.25,
                                  frame_stall_reopen_seconds=30.0),
            self.registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures,
        )
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.addCleanup(block.set)
        self.captures.block = block
        self.assertTrue(self.captures.blocked.wait(5))
        # The join bound (0.25 s) is shorter than the effective stall window
        # (10 frame intervals at 10 fps = 1 s), so the stall is reported only
        # if the watchdog outlives the stop.
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOP_FAILED)
        self.assertTrue(wait_for(
            lambda: runtime.status().sources[0].camera_state is not CameraState.ONLINE, 3))
        self.assertTrue(wait_for(
            lambda: self.health(source.id) is not SourceHealthState.ONLINE, 3))
        self.captures.block = None
        block.set()
        self.assertTrue(wait_for(lambda: all(capture.closed
                                             for capture in self.captures.instances)))
        self.assertTrue(wait_for(lambda: self.health(source.id) is SourceHealthState.OFFLINE))

    def test_stop_never_closes_the_adapter_under_a_running_watchdog_check(self):
        # Codex P2 on #168: when the frame-progress watchdog is still inside
        # a check after the supervisor's finite join, the stop fails and the
        # adapter is not closed under that check.
        source = self.source()
        released = threading.Event()
        self.addCleanup(released.set)
        in_check = threading.Event()
        slow = {"on": False}
        adapters = []

        class SlowCheckAdapter(LocalUvcAdapter):
            close_calls = 0

            def check_frame_progress(self, source_id):
                if slow["on"]:
                    in_check.set()
                    released.wait(5)
                return super().check_frame_progress(source_id)

            def close(self):
                type(self).close_calls += 1
                return super().close()

        def adapter_factory(*args, **kwargs):
            adapter = SlowCheckAdapter(*args, **kwargs)
            adapters.append(adapter)
            return adapter

        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), poll_timeout_seconds=0.05,
                                  retry_delay_seconds=0.05, join_timeout_seconds=0.5,
                                  frame_stall_seconds=0.5),
            self.registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures, adapter_factory=adapter_factory,
        )
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        runtime._supervisor.WATCHDOG_JOIN_MINIMUM_SECONDS = 0.1
        slow["on"] = True
        self.assertTrue(in_check.wait(5))
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOP_FAILED)
        self.assertEqual(0, SlowCheckAdapter.close_calls)
        self.assertFalse(adapters[0].closed)
        # The worker itself stopped and closed its capture.
        self.assertTrue(all(capture.closed for capture in self.captures.instances))
        # A repeated stop while that check still runs keeps the adapter open.
        self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOP_FAILED)
        self.assertEqual(0, SlowCheckAdapter.close_calls)
        released.set()
        # Issue #173 (Codex P2 on #168): once the watchdog is gone, a later
        # stop() retries the supervisor join and closes the adapter.
        self.assertTrue(wait_for(lambda: not runtime._supervisor.watchdog_running))
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOPPED)
        self.assertEqual(1, SlowCheckAdapter.close_calls)
        self.assertTrue(adapters[0].closed)
        self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOPPED)
        self.assertEqual(1, SlowCheckAdapter.close_calls)

    def test_blocked_worker_stop_leaves_durable_non_online_before_pin_release(self):
        # Issue #173 (Claude review on #168): the stop releases the database
        # pin right after the join bound. With join >= stall (now enforced by
        # the configuration) the watchdog has lowered a blocked worker's
        # ``online`` claim durably before that release, so the registry never
        # keeps ``online`` once the pinned database refuses writes.
        source = self.source()
        pinned = PinnedDatabase(Database(self.database.path))
        registry = CameraRegistry(pinned, reservation=ToggleAdmission())
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), poll_timeout_seconds=0.05,
                                  retry_delay_seconds=0.05, join_timeout_seconds=2.0,
                                  frame_stall_seconds=1.0, frame_stall_reopen_seconds=30.0),
            registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures,
        )
        self.addCleanup(runtime.stop)
        self.addCleanup(pinned.release)
        runtime.start()
        self.assertTrue(pinned.pinned)
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.addCleanup(block.set)
        self.captures.block = block
        self.assertTrue(self.captures.blocked.wait(5))
        status = runtime.stop()
        self.assertIs(status.state, LocalUvcRuntimeState.STOP_FAILED)
        self.assertFalse(pinned.pinned)
        self.assertIsNot(self.health(source.id), SourceHealthState.ONLINE)
        self.captures.block = None
        block.set()

    def test_hung_stall_write_does_not_stop_the_watchdog_for_other_sources(self):
        second_camera = DeviceEvidence("/dev/video2", "synthetic", "model", "serial-b")
        self.discovery.devices = [self.camera, second_camera]
        first, second = self.source("First"), self.source("Second")
        runtime = self.runtime(first.id, second.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", first.id, self.camera)
        runtime.reapprove(self.admin, "synthetic-owner", second.id, second_camera)
        self.assertTrue(self.wait_health(first.id, SourceHealthState.ONLINE))
        self.assertTrue(self.wait_health(second.id, SourceHealthState.ONLINE))
        armed, hung, release = threading.Event(), [], threading.Event()
        self.addCleanup(release.set)
        original = self.registry.update_source_health

        def hanging_write(source_id, **values):
            if armed.is_set() and values.get("health_state") is not SourceHealthState.ONLINE:
                with self.frame_lock:
                    first_hang = not hung
                    if first_hang:
                        hung.append(source_id)
                if first_hang:
                    # SQLite/storage hangs indefinitely on the first stall write.
                    release.wait(30)
            return original(source_id, **values)

        self.registry.update_source_health = hanging_write
        block = threading.Event()
        self.addCleanup(block.set)
        armed.set()
        # Both workers block in a kernel read, so only the watchdog can
        # report their stalls.
        self.captures.block = block
        self.assertTrue(wait_for(lambda: bool(hung)))
        other = second.id if hung[0] == first.id else first.id
        self.assertTrue(wait_for(lambda: self.health(other) is not SourceHealthState.ONLINE, 8))
        # The hung source's in-memory state left online too.
        status = runtime.status()
        hung_source = next(item for item in status.sources if item.source_id == hung[0])
        self.assertFalse(hung_source.health_persisted)
        self.assertIsNot(hung_source.camera_state, CameraState.ONLINE)
        self.captures.block = None
        block.set()
        release.set()

    def test_worker_blocked_through_a_refused_reapproval_stays_watched(self):
        source = self.source()
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), poll_timeout_seconds=0.05,
                                  retry_delay_seconds=0.05, join_timeout_seconds=0.25,
                                  frame_stall_seconds=0.25),
            self.registry, on_frame=self.on_frame, discovery=self.discovery,
            capture_factory=self.captures,
        )
        self.addCleanup(runtime.stop)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        block = threading.Event()
        self.addCleanup(block.set)
        self.captures.block = block
        self.assertTrue(self.captures.blocked.wait(5))
        # The worker is blocked in a kernel call, so the stop for the
        # approval times out and the approval is refused; the source is
        # still RUNNING and its worker still registered with stop requested.
        with self.assertRaisesRegex(ValueError, "could not stop"):
            runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertIs(runtime.status().sources[0].state, SourceRuntimeState.RUNNING)
        self.assertTrue(wait_for(lambda: self.health(source.id) is not SourceHealthState.ONLINE))
        self.captures.block = None

    def test_hung_teardown_notifies_offline_and_reports_unpersisted_first(self):
        source = self.source()
        offline = threading.Event()

        def sink(event):
            # Production wiring: local_preview.on_health() runs first here.
            if event.state is CameraState.OFFLINE:
                offline.set()

        runtime = self.runtime(source.id, health_sink=sink)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        release = threading.Event()
        self.addCleanup(release.set)
        original = self.registry.update_source_health

        def hanging_write(source_id, **values):
            if values.get("health_state") is SourceHealthState.OFFLINE and not release.is_set():
                release.wait(30)
            return original(source_id, **values)

        self.registry.update_source_health = hanging_write
        self.captures.close_block = release
        # Unplug: the worker starts the teardown and hangs in close().
        self.discovery.devices = []
        # Before the descriptor is closed, the offline transition already
        # reached the sink (preview invalidation) and the stale ONLINE row is
        # reported unpersisted.
        self.assertTrue(offline.wait(5))
        self.assertTrue(wait_for(lambda: not runtime.status().sources[0].health_persisted))
        self.assertFalse(all(capture.closed for capture in self.captures.instances))
        self.assertIs(self.health(source.id), SourceHealthState.ONLINE)
        self.captures.close_block = None
        release.set()
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))
        self.assertTrue(wait_for(lambda: runtime.status().sources[0].health_persisted))

    def test_teardown_closes_the_descriptor_despite_hung_health_io(self):
        source = self.source()
        armed, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        sink_entered, write_entered = threading.Event(), threading.Event()

        def hanging_sink(event):
            if armed.is_set():
                sink_entered.set()
                release.wait(30)

        runtime = self.runtime(source.id, health_sink=hanging_sink)
        original = self.registry.update_source_health

        def hanging_write(source_id, **values):
            if armed.is_set() and values.get("health_state") is SourceHealthState.OFFLINE:
                write_entered.set()
                release.wait(30)
            return original(source_id, **values)

        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        # SQLite/storage and the downstream health sink both hang.
        self.registry.update_source_health = hanging_write
        armed.set()
        result = []
        stopper = threading.Thread(target=lambda: result.append(runtime.stop()))
        stopper.start()
        stopper.join(10)
        self.assertFalse(stopper.is_alive())
        self.assertIs(result[0].state, LocalUvcRuntimeState.STOPPED)
        self.assertTrue(all(capture.closed for capture in self.captures.instances))
        # The transition itself still happened; only its I/O is pending.
        self.assertIs(result[0].sources[0].camera_state, CameraState.OFFLINE)
        self.assertTrue(write_entered.wait(5))
        self.assertTrue(sink_entered.wait(5))
        release.set()
        self.assertTrue(self.wait_health(source.id, SourceHealthState.OFFLINE))

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
        self.assertTrue(wait_for(lambda: runtime.status().health_sink_failures > 0))
        status = runtime.status()
        self.assertGreater(status.health_events_dropped, 0)
        self.assertLessEqual(len(runtime.recent_health_events()), 2)
        self.assertTrue(status.sources[0].worker_running)

    def test_health_sink_queue_is_bounded_and_keeps_each_sources_latest_event(self):
        # Issue #173 item 1: while the sink hangs, events wait in a bounded
        # queue; overflow coalesces superseded events, never a source's last.
        from app.cameras.uvc.identity import HealthEvent
        first, second, third = uuid4(), uuid4(), uuid4()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        delivered = []

        def hanging_sink(event):
            if not release.is_set():
                entered.set()
                release.wait(30)
            delivered.append(event)

        with patch.object(runtime_module, "HEALTH_SINK_MAX_PENDING", 5):
            runtime = LocalUvcRuntime(
                LocalUvcConfiguration((first, second, third)), self.registry,
                on_frame=self.on_frame, health_sink=hanging_sink,
            )
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        runtime._health(HealthEvent(first, CameraState.ONLINE, "held"))
        self.assertTrue(entered.wait(5))
        runtime._health(HealthEvent(second, CameraState.MANUAL, "second-only"))
        runtime._health(HealthEvent(third, CameraState.OFFLINE, "third-only"))
        for index in range(20):
            runtime._health(HealthEvent(first, CameraState.DEGRADED, f"first-{index}"))
        status = runtime.status()
        self.assertEqual(5, status.health_sink_pending)
        self.assertEqual(17, status.health_sink_coalesced)
        release.set()
        self.assertTrue(wait_for(lambda: runtime.status().health_sink_pending == 0))
        self.assertTrue(wait_for(lambda: len(delivered) == 6))
        reasons = [event.reason for event in delivered]
        self.assertEqual(["held", "second-only", "third-only",
                          "first-17", "first-18", "first-19"], reasons)

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

    def test_manual_watch_helper_reports_events_after_bounded_buffer_evicts(self):
        # scripts/manual/uvc_watch.py must keep reporting transitions of a
        # flapping source after the bounded recent-event deque is full.
        import importlib.util
        from app.cameras.uvc.identity import HealthEvent
        script = Path(__file__).resolve().parents[2] / "scripts" / "manual" / "uvc_watch.py"
        spec = importlib.util.spec_from_file_location("uvc_watch_under_test", script)
        watch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watch)
        log = watch.HealthEventLog()
        source_id = uuid4()
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source_id,)), self.registry, on_frame=self.on_frame,
            health_sink=log.sink, max_health_events=4,
        )
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        for index in range(10):
            state = CameraState.OFFLINE if index % 2 else CameraState.DEGRADED
            runtime._health(HealthEvent(source_id, state, f"synthetic-{index}"))
        self.assertEqual(4, len(runtime.recent_health_events()))

        def drain(count):
            # The sink runs on the runtime's delivery thread (Issue #173).
            events = []
            wait_for(lambda: events.extend(log.drain()) or len(events) >= count)
            return [event.reason for event in events]

        self.assertEqual([f"synthetic-{i}" for i in range(10)], drain(10))
        runtime._health(HealthEvent(source_id, CameraState.ONLINE, "recovered"))
        self.assertEqual(["recovered"], drain(1))
        self.assertEqual([], log.drain())

    def test_manual_watch_helper_prints_events_raised_during_shutdown(self):
        # Transitions arriving after the last timed drain and those produced
        # while the lifespan stops must still be printed, also on error.
        import contextlib
        import importlib.util
        import io
        from types import SimpleNamespace
        from app.cameras.uvc.identity import HealthEvent
        script = Path(__file__).resolve().parents[2] / "scripts" / "manual" / "uvc_watch.py"
        spec = importlib.util.spec_from_file_location("uvc_watch_under_test", script)
        watch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watch)
        source_id = uuid4()

        for fail in (False, True):
            with self.subTest(body_raises=fail):
                log = watch.HealthEventLog()

                @contextlib.asynccontextmanager
                async def lifespan(_app):
                    try:
                        yield
                    finally:
                        log.sink(HealthEvent(source_id, CameraState.OFFLINE, "synthetic-closed"))

                app = SimpleNamespace(router=SimpleNamespace(lifespan_context=lifespan))

                async def body():
                    log.sink(HealthEvent(source_id, CameraState.ONLINE, "synthetic-late"))
                    if fail:
                        raise RuntimeError("synthetic")

                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    try:
                        asyncio.run(watch.run_with_final_drain(app, log, [source_id], body))
                    except RuntimeError:
                        self.assertTrue(fail)
                text = out.getvalue()
                self.assertIn("src1: online (synthetic-late)", text)
                self.assertIn("src1: offline (synthetic-closed)", text)
                self.assertEqual([], log.drain())

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


class RuntimeDuplicateApprovalTests(RuntimeFixture):
    """Real-hardware finding (2026-09-30): one camera approved for two sources."""

    def setUp(self):
        super().setUp()
        self.second_camera = DeviceEvidence("/dev/video2", "synthetic", "model", "serial-b")
        self.discovery.devices = [self.camera, self.second_camera]

    def open_captures(self):
        with self.captures.lock:
            return sum(1 for capture in self.captures.instances if not capture.closed)

    def test_duplicate_reapproval_is_refused_and_audited(self):
        first, second = self.source("First"), self.source("Second")
        runtime = self.runtime(first.id, second.id)
        runtime.start()
        runtime.reapprove(self.admin, "synthetic-owner", first.id, self.camera)
        self.assertTrue(self.wait_health(first.id, SourceHealthState.ONLINE))
        with self.assertRaises(ValueError):
            runtime.reapprove(self.admin, "synthetic-owner", second.id, self.camera)
        outcomes = sorted(record.outcome for record in AuditStore(self.database).list_records()
                          if record.action is AuditAction.APPROVE_CAMERA)
        self.assertEqual(sorted([AuditOutcome.SUCCEEDED, AuditOutcome.FAILED]), outcomes)
        time.sleep(0.3)
        # No EBUSY-style flapping: the refused source never tries the camera.
        self.assertIs(self.health(second.id), SourceHealthState.OFFLINE)
        self.assertIs(self.health(first.id), SourceHealthState.ONLINE)
        self.assertEqual(1, self.open_captures())
        self.assertIsNone(ApprovalStore(self.database).load(second.id))

    def test_persisted_duplicate_is_manual_at_startup_in_any_order(self):
        first, second = self.source("First"), self.source("Second")
        for source in (first, second):
            with closing(self.database.connect()) as connection:
                connection.execute(
                    "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, "
                    "session_token, serial_ambiguous) VALUES (?, ?, 0, NULL, 0)",
                    (str(source.id), json.dumps(asdict(self.camera))),
                )
        for order in ((first.id, second.id), (second.id, first.id)):
            with self.subTest(order=order):
                runtime = self.runtime(*order)
                runtime.start()
                for source_id in order:
                    self.assertTrue(self.wait_health(
                        source_id, SourceHealthState.MANUAL_INTERVENTION_REQUIRED))
                time.sleep(0.2)
                self.assertEqual(0, self.open_captures())
                self.assertEqual(0, self.frame_count(first.id) + self.frame_count(second.id))
                runtime.stop()


@contextmanager
def synthetic_admission():
    yield


class ToggleAdmission:
    """Synthetic storage admission that can later refuse like a hard stop."""

    def __init__(self):
        self.lock = threading.Lock()
        self.refuse = False
        self.admitted = 0
        self.refused = 0

    @contextmanager
    def __call__(self):
        with self.lock:
            if self.refuse:
                self.refused += 1
                raise RuntimeError("synthetic STORAGE_HARD_STOP")
            self.admitted += 1
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

    async def test_blocked_optional_sink_never_delays_preview_invalidation(self):
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=PROFILE,
        )
        release, ready_entered = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def blocking_sink(event):
            # An optional downstream sink hangs while handling video ready.
            if event.reason == "video_capture_ready":
                ready_entered.set()
                release.wait(30)

        self.dependencies = replace(self.dependencies, health_sink=blocking_sink)
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(database), PermitOwner()), CameraRegistry(database),
        )
        block = threading.Event()
        self.addCleanup(block.set)
        async with application.router.lifespan_context(application):
            runtime = application.state.local_uvc
            preview = application.state.local_preview
            runtime.reapprove(admin, "synthetic-owner", source.id, self.camera)
            self.assertTrue(wait_for(ready_entered.is_set))
            self.assertTrue(preview.source(source.id).live)
            # Frames stop; the stall must invalidate the preview although the
            # optional sink is still stuck on the earlier ready event.
            self.dependencies.capture_factory.block = block
            self.assertTrue(wait_for(lambda: not preview.source(source.id).live, 8))
            self.assertIsNone(preview.latest(source.id))
            self.dependencies.capture_factory.block = None
            block.set()
            release.set()

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

    def migrated_source(self):
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=PROFILE,
        )
        return database, source

    async def test_capture_writes_are_admitted_and_refused_by_storage_policy(self):
        # Source health, profile, last-seen and session-marker writes from the
        # capture workers go through the deployment storage admission; after a
        # later hard stop / lost mount nothing more is written and capture
        # fails visibly instead of writing past the reserve.
        database, source = self.migrated_source()
        admission = ToggleAdmission()
        application = create_app(
            self.settings, storage_reservation=admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(database), PermitOwner()), CameraRegistry(database),
        )
        registry = CameraRegistry(database)
        async with application.router.lifespan_context(application):
            runtime = application.state.local_uvc
            runtime.reapprove(admin, "synthetic-owner", source.id, self.camera)
            self.assertTrue(wait_for(lambda: registry.get_source(source.id).health_state
                                     is SourceHealthState.ONLINE))
            admitted = admission.admitted
            self.assertTrue(wait_for(lambda: admission.admitted > admitted + 1))
            admission.refuse = True
            captures = self.dependencies.capture_factory.instances
            self.assertTrue(wait_for(lambda: admission.refused > 0
                                     and runtime.status().sources[0].worker_failures > 0))
            self.assertTrue(wait_for(lambda: all(capture.closed for capture in captures)
                                     or len(captures) > 1))
            before = registry.get_source(source.id)
            written = admission.admitted
            await asyncio.sleep(0.3)
            self.assertEqual(written, admission.admitted)
            self.assertEqual(before.updated_at, registry.get_source(source.id).updated_at)
            self.assertEqual(before.last_seen_at, registry.get_source(source.id).last_seen_at)
            # The durable row may still read ONLINE, but the capture loss is
            # visible in memory: an OFFLINE transition, an unpersisted flag and
            # a degraded service instead of a healthy RUNNING state.
            status = runtime.status()
            self.assertIs(status.state, LocalUvcRuntimeState.DEGRADED)
            self.assertFalse(status.sources[0].health_persisted)
            self.assertIsNot(status.sources[0].camera_state, CameraState.ONLINE)
            self.assertIn(CameraState.OFFLINE,
                          [event.state for event in runtime.recent_health_events()])
            # The in-memory transition also reached the preview hub.
            self.assertFalse(application.state.local_preview.source(source.id).live)
            admission.refuse = False
            self.assertTrue(wait_for(lambda: runtime.status().state
                                     is LocalUvcRuntimeState.RUNNING
                                     and runtime.status().sources[0].health_persisted))
            self.assertTrue(wait_for(lambda: registry.get_source(source.id).health_state
                                     is SourceHealthState.ONLINE))
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)

    async def async_wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            await asyncio.sleep(0.01)
        return predicate()

    async def test_refused_pin_admission_retries_start_after_recovery(self):
        # A hard stop that refuses the pin during startup leaves nothing
        # opened: the runtime reports STORAGE_UNADMITTED and stays startable,
        # and the lifespan starts capture once admission recovers instead of
        # keeping it FAILED until a process restart.
        database, source = self.migrated_source()
        refuse = threading.Event()
        refuse.set()
        original_pin = PinnedDatabase.pin

        def pin(database_, admission=None):
            if refuse.is_set():
                raise RuntimeError("synthetic STORAGE_HARD_STOP")
            return original_pin(database_, admission)

        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        with patch.object(PinnedDatabase, "pin", pin):
            async with application.router.lifespan_context(application):
                runtime = application.state.local_uvc
                self.assertIs(application.state.local_uvc_state,
                              LocalUvcRuntimeState.STORAGE_UNADMITTED)
                self.assertIs(runtime.status().state, LocalUvcRuntimeState.STORAGE_UNADMITTED)
                self.assertFalse(runtime.status().sources[0].worker_running)
                await asyncio.sleep(0.2)
                self.assertEqual([], self.dependencies.capture_factory.instances)
                refuse.clear()
                self.assertTrue(await self.async_wait_for(
                    lambda: application.state.local_uvc_state is LocalUvcRuntimeState.RUNNING))
                self.assertTrue(runtime.status().sources[0].worker_running)
                await self.assert_surface_closed(application)
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)

    def test_refused_pin_leaves_runtime_startable(self):
        _database, source = self.migrated_source()
        admission = ToggleAdmission()
        admission.refuse = True
        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), **FAST),
            CameraRegistry(PinnedDatabase(Database(self.settings.database_path)),
                           reservation=admission),
            on_frame=lambda *_: None, discovery=self.discovery,
            capture_factory=self.dependencies.capture_factory,
        )
        self.addCleanup(runtime.stop)
        with self.assertLogs("app.cameras.uvc.runtime", level="ERROR"):
            status = runtime.start()
        self.assertIs(status.state, LocalUvcRuntimeState.STORAGE_UNADMITTED)
        self.assertFalse(status.sources[0].worker_running)
        with self.assertRaises(ValueError):
            runtime.reapprove(None, "synthetic-owner", source.id, self.camera)
        admission.refuse = False
        self.assertIs(runtime.start().state, LocalUvcRuntimeState.RUNNING)
        self.assertTrue(runtime.status().sources[0].worker_running)

    def test_failed_initialization_releases_database_pin_and_adapter(self):
        # Pinning succeeded but the supervisor constructor raised: the
        # contained startup failure must not keep the admitted descriptor
        # (and its filesystem) busy, nor leave the adapter open.
        _database, source = self.migrated_source()
        pinned = PinnedDatabase(Database(self.settings.database_path))
        self.addCleanup(pinned.release)
        adapters = []

        def adapter_factory(*args, **kwargs):
            adapter = LocalUvcAdapter(*args, **kwargs)
            adapters.append(adapter)
            return adapter

        def failing_supervisor(*_args, **_kwargs):
            raise RuntimeError("synthetic supervisor failure")

        runtime = LocalUvcRuntime(
            LocalUvcConfiguration((source.id,), **FAST),
            CameraRegistry(pinned, reservation=ToggleAdmission()),
            on_frame=lambda *_: None, discovery=self.discovery,
            capture_factory=self.dependencies.capture_factory,
            adapter_factory=adapter_factory, supervisor_factory=failing_supervisor,
        )
        with self.assertLogs("app.cameras.uvc.runtime", level="ERROR"):
            status = runtime.start()
        self.assertIs(status.state, LocalUvcRuntimeState.FAILED)
        self.assertFalse(pinned.pinned)
        self.assertEqual(1, len(adapters))
        self.assertTrue(adapters[0].closed)
        self.assertIs(runtime.stop().state, LocalUvcRuntimeState.STOPPED)
        self.assertFalse(pinned.pinned)

    async def test_application_state_follows_runtime_worker_faults(self):
        # A later capture/storage loss turns the application snapshot from
        # RUNNING into DEGRADED, and recovery back into RUNNING, instead of
        # freezing the value computed at startup.
        database, source = self.migrated_source()
        admission = ToggleAdmission()
        application = create_app(
            self.settings, storage_reservation=admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(database), PermitOwner()), CameraRegistry(database),
        )
        async with application.router.lifespan_context(application):
            runtime = application.state.local_uvc
            await asyncio.to_thread(runtime.reapprove, admin, "synthetic-owner",
                                    source.id, self.camera)
            self.assertTrue(await self.async_wait_for(
                lambda: application.state.local_uvc_state is LocalUvcRuntimeState.RUNNING))
            admission.refuse = True
            self.assertTrue(await self.async_wait_for(
                lambda: application.state.local_uvc_state is LocalUvcRuntimeState.DEGRADED))
            admission.refuse = False
            self.assertTrue(await self.async_wait_for(
                lambda: application.state.local_uvc_state is LocalUvcRuntimeState.RUNNING))
            await self.assert_surface_closed(application)
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)

    def test_approval_session_marker_refused_without_admission(self):
        database, source = self.migrated_source()
        admission = ToggleAdmission()
        admission.refuse = True
        store = ApprovalStore(database, reservation=admission)
        with self.assertRaises(RuntimeError):
            store.start_session(source.id, self.camera)
        self.assertIsNone(store.load(source.id))
        registry = CameraRegistry(database, reservation=admission)
        with self.assertRaises(RuntimeError):
            registry.update_source_health(source.id, health_state=SourceHealthState.ONLINE)
        self.assertIs(registry.get_source(source.id).health_state, SourceHealthState.OFFLINE)

    def test_pinned_database_never_creates_or_opens_a_replacement(self):
        database, _source = self.migrated_source()
        pinned = PinnedDatabase(database)
        with self.assertRaises(ValueError):
            pinned.connect()
        refusing = ToggleAdmission()
        refusing.refuse = True
        with self.assertRaises(RuntimeError):
            pinned.pin(refusing)
        self.assertFalse(pinned.pinned)
        pinned.pin(ToggleAdmission())
        with closing(pinned.connect()) as connection:
            connection.execute("SELECT 1 FROM camera_sources").fetchall()
        path = database.path
        moved = path.with_name("moved.sqlite")
        os.rename(path, moved)
        # A lost mount: the path is missing. Nothing is created there.
        with self.assertRaises(ValueError):
            pinned.connect()
        self.assertFalse(path.exists())
        # A replaced filesystem/file at the same path is never opened.
        with closing(Database(path).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        with self.assertRaises(ValueError):
            pinned.connect()
        os.replace(moved, path)
        with closing(pinned.connect()) as connection:
            self.assertEqual(1, len(connection.execute("SELECT id FROM camera_sources").fetchall()))

    def test_pinned_database_refuses_replacement_with_reused_inode(self):
        # An unlinked-and-recreated file can get the same (device, inode) pair
        # from the allocator. Simulate that reuse deterministically: the path
        # now reports the pinned identity, but it names a replacement file.
        database, _source = self.migrated_source()
        pinned = PinnedDatabase(database)
        self.addCleanup(pinned.release)
        pinned.pin(ToggleAdmission())
        path = database.path
        original = os.stat(path, follow_symlinks=False)
        os.unlink(path)
        with closing(Database(path).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        real_stat = os.stat

        def reused_stat(target, *args, **kwargs):
            info = real_stat(target, *args, **kwargs)
            if os.fspath(target) != os.fspath(path):
                return info
            fields = list(info)
            fields[stat.ST_INO], fields[stat.ST_DEV] = original.st_ino, original.st_dev
            return os.stat_result(fields)

        with patch("os.stat", reused_stat):
            self.assertEqual(original.st_ino, os.stat(path).st_ino)
            with self.assertRaises(ValueError):
                pinned.connect()
        # A renamed-away and restored pinned file is still the same file.
        repinned = PinnedDatabase(Database(path))
        self.addCleanup(repinned.release)
        repinned.pin(ToggleAdmission())
        moved = path.with_name("moved.sqlite")
        os.rename(path, moved)
        with self.assertRaises(ValueError):
            repinned.connect()
        os.replace(moved, path)
        with closing(repinned.connect()) as connection:
            connection.execute("SELECT 1 FROM camera_sources").fetchall()
        repinned.release()
        with self.assertRaises(ValueError):
            repinned.connect()

    async def test_lost_database_file_after_start_is_not_recreated(self):
        # After startup the verified database disappears (lost mount): the
        # capture workers' registry reads never create a fallback file, and
        # the live camera is reported as lost instead of staying ONLINE.
        database, source = self.migrated_source()
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(database), PermitOwner()), CameraRegistry(database),
        )
        registry = CameraRegistry(database)
        path = database.path
        moved = path.with_name("moved.sqlite")
        async with application.router.lifespan_context(application):
            runtime = application.state.local_uvc
            runtime.reapprove(admin, "synthetic-owner", source.id, self.camera)
            self.assertTrue(wait_for(lambda: registry.get_source(source.id).health_state
                                     is SourceHealthState.ONLINE))
            os.rename(path, moved)
            try:
                self.assertTrue(wait_for(
                    lambda: runtime.status().state is LocalUvcRuntimeState.DEGRADED))
                await asyncio.sleep(0.2)
                self.assertFalse(path.exists())
                status = runtime.status()
                self.assertIsNot(status.sources[0].camera_state, CameraState.ONLINE)
                self.assertFalse(application.state.local_preview.source(source.id).live)
                self.assertTrue(all(capture.closed
                                    for capture in self.dependencies.capture_factory.instances))
            finally:
                os.replace(moved, path)
            self.assertTrue(wait_for(lambda: runtime.status().state
                                     is LocalUvcRuntimeState.RUNNING))
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)

    async def test_cancelled_startup_stops_capture_workers(self):
        # A cancelled lifespan startup (embedder shutdown, startup timeout)
        # while the UVC start thread is running must not leave workers or
        # descriptors active after startup failed.
        _database, source = self.migrated_source()
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        entered = threading.Event()
        original = LocalUvcRuntime.start

        def slow_start(runtime):
            entered.set()
            status = original(runtime)
            time.sleep(0.3)
            return status

        async def serve():
            async with application.router.lifespan_context(application):
                await asyncio.sleep(30)

        with patch.object(LocalUvcRuntime, "start", slow_start):
            task = asyncio.create_task(serve())
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        runtime = application.state.local_uvc
        self.assertFalse(application.state.ready)
        self.assertIs(runtime.status().state, LocalUvcRuntimeState.STOPPED)
        self.assertFalse(runtime.status().sources[0].worker_running)
        await asyncio.sleep(0.2)
        self.assertFalse(runtime.status().sources[0].worker_running)

    async def test_cancellation_racing_cleanup_completion_is_preserved(self):
        # The caller is cancelled in the same loop turn the cleanup step
        # finishes: the step's result is not returned in place of the
        # caller's cancellation (a shutdown timeout is never swallowed).
        gate = asyncio.get_running_loop().create_future()
        completed = []

        async def step():
            await gate
            completed.append(True)
            return "done"

        caller = asyncio.create_task(run_to_completion(step()))
        for _ in range(3):
            await asyncio.sleep(0)
        gate.set_result(None)
        caller.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await caller
        self.assertEqual([True], completed)

    async def test_cancellation_is_preserved_when_the_step_then_fails(self):
        # The caller is cancelled while the step runs and the step then
        # raises: the caller still sees its cancellation, not the step's
        # error, so a cancelled startup cannot proceed as a mere failure.
        gate = asyncio.get_running_loop().create_future()

        async def step():
            await gate
            raise RuntimeError("step failed")

        caller = asyncio.create_task(run_to_completion(step()))
        for _ in range(3):
            await asyncio.sleep(0)
        caller.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
        gate.set_result(None)
        with self.assertRaises(asyncio.CancelledError):
            await caller

    async def test_step_failure_without_cancellation_propagates(self):
        async def step():
            raise RuntimeError("step failed")

        with self.assertRaises(RuntimeError):
            await run_to_completion(step())

    async def test_repeated_startup_cancellation_waits_for_start_thread(self):
        # A second cancellation while the startup already waits for the UVC
        # start thread still does not abandon it: its workers are stopped.
        _database, source = self.migrated_source()
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        entered, finished = threading.Event(), []
        original = LocalUvcRuntime.start

        def slow_start(runtime):
            entered.set()
            time.sleep(0.3)
            status = original(runtime)
            finished.append(status.state)
            return status

        async def serve():
            async with application.router.lifespan_context(application):
                await asyncio.sleep(30)

        with patch.object(LocalUvcRuntime, "start", slow_start):
            task = asyncio.create_task(serve())
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            task.cancel()
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        runtime = application.state.local_uvc
        self.assertEqual(1, len(finished))
        self.assertFalse(application.state.ready)
        self.assertIs(runtime.status().state, LocalUvcRuntimeState.STOPPED)
        self.assertFalse(runtime.status().sources[0].worker_running)

    async def test_cancelled_shutdown_finishes_capture_stop_and_cleanup(self):
        # An ASGI shutdown timeout or embedder cancels the lifespan while the
        # UVC stop thread is still joining workers. The stop is not abandoned:
        # the preview is invalidated, the stop finishes, the remaining
        # cleanup (retention task, final state) still runs, and only then
        # is the cancellation re-raised.
        _database, source = self.migrated_source()
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=self.dependencies,
        )
        stopping, started = threading.Event(), asyncio.Event()
        finished = []
        original = LocalUvcRuntime.stop

        def slow_stop(runtime):
            stopping.set()
            time.sleep(0.3)
            status = original(runtime)
            finished.append(status.state)
            return status

        exit_lifespan = asyncio.Event()

        async def serve():
            async with application.router.lifespan_context(application):
                started.set()
                await exit_lifespan.wait()

        with patch.object(LocalUvcRuntime, "stop", slow_stop), \
                self.assertLogs("app.main", level="INFO") as logs:
            task = asyncio.create_task(serve())
            await asyncio.wait_for(started.wait(), 5)
            self.assertTrue(application.state.ready)
            exit_lifespan.set()
            self.assertTrue(await asyncio.to_thread(stopping.wait, 5))
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()  # A repeated cancellation is deferred as well.
            with self.assertRaises(asyncio.CancelledError):
                await task
        runtime = application.state.local_uvc
        self.assertEqual([LocalUvcRuntimeState.STOPPED], finished)
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)
        self.assertFalse(runtime.status().sources[0].worker_running)
        self.assertFalse(application.state.ready)
        preview = application.state.local_preview
        self.assertFalse(preview.source(source.id).live)
        self.assertEqual(0, preview.status.retained_bytes)
        self.assertTrue(any("application_stopped" in line for line in logs.output))

    def test_invalid_configuration_type_is_refused(self):
        with self.assertRaises(TypeError):
            create_app(self.settings, local_uvc={"source_ids": []})


class MonitoringAdmissionTests(MonitoringFixture):
    """UVC capture follows the monitoring runtime's verified storage state."""

    async def test_cancelled_monitoring_startup_stops_monitoring_runtime(self):
        from app.monitoring.runtime import MonitoringRuntime
        application = create_app(
            self.settings, monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=0.01,
            ),
        )
        entered, stopped = asyncio.Event(), []
        original_stop = MonitoringRuntime.stop

        async def hanging_start(runtime):
            entered.set()
            await asyncio.sleep(30)

        async def recorded_stop(runtime):
            stopped.append(runtime)
            await original_stop(runtime)

        async def serve():
            async with application.router.lifespan_context(application):
                await asyncio.sleep(30)

        with patch.object(MonitoringRuntime, "start", hanging_start), \
                patch.object(MonitoringRuntime, "stop", recorded_stop):
            task = asyncio.create_task(serve())
            await asyncio.wait_for(entered.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual([application.state.monitoring], stopped)
        self.assertFalse(application.state.ready)

    async def test_cancelled_shutdown_finishes_monitoring_stop(self):
        # A shutdown cancelled while the monitoring runtime is stopping still
        # finishes that stop (and the final state), then re-raises.
        from app.monitoring.runtime import MonitoringRuntime
        application = create_app(
            self.settings, monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=0.01,
            ),
        )
        stopping, finished = asyncio.Event(), []
        original_stop = MonitoringRuntime.stop

        async def slow_stop(runtime):
            stopping.set()
            await asyncio.sleep(0.2)
            await original_stop(runtime)
            finished.append(runtime)

        started, exit_lifespan = asyncio.Event(), asyncio.Event()

        async def serve():
            async with application.router.lifespan_context(application):
                started.set()
                await exit_lifespan.wait()

        with patch.object(MonitoringRuntime, "stop", slow_stop):
            task = asyncio.create_task(serve())
            await asyncio.wait_for(started.wait(), 5)
            exit_lifespan.set()
            await asyncio.wait_for(stopping.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual([application.state.monitoring], finished)
        self.assertFalse(application.state.audit_storage_admitted)
        self.assertFalse(application.state.ready)

    async def test_failed_monitoring_startup_defers_capture_until_recovery(self):
        from datetime import timedelta
        database = Database(self.settings.database_path)
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=PROFILE,
        )
        discovery = Discovery([DeviceEvidence("/dev/video0", "synthetic", "model", "serial-a")])
        # The recording filesystem identity does not match: startup open fails.
        self.approved_device = self.device + 1
        application = create_app(
            self.settings, monitoring=self.configuration(),
            monitoring_dependencies=MonitoringDependencies(
                integrity_probe=self.probe, segment_validator=SyntheticValidator(),
                slack_opener=self.transport, utcnow=self.clock.utcnow,
                monotonic=lambda: self.clock.monotonic, tick_seconds=0.01,
            ),
            local_uvc=LocalUvcConfiguration((source.id,), **FAST),
            local_uvc_dependencies=LocalUvcDependencies(
                discovery=discovery, capture_factory=CaptureFactory(discovery),
            ),
        )
        async with application.router.lifespan_context(application):
            self.assertEqual(RuntimeState.FAILED, application.state.monitoring_state)
            self.assertIs(application.state.local_uvc_state,
                          LocalUvcRuntimeState.STORAGE_UNADMITTED)
            self.assertFalse(application.state.local_uvc.status().sources[0].worker_running)
            self.approved_device = self.device
            self.clock.advance(timedelta(minutes=15))
            for _ in range(500):
                if application.state.local_uvc_state is LocalUvcRuntimeState.RUNNING:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(RuntimeState.RUNNING, application.state.monitoring_state)
            self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.RUNNING)
            self.assertTrue(application.state.local_uvc.status().sources[0].worker_running)
        self.assertIs(application.state.local_uvc_state, LocalUvcRuntimeState.STOPPED)


class ConfigurationParsingTests(unittest.TestCase):
    def test_valid_configuration(self):
        identities = [str(uuid4()) for _ in range(4)]
        parsed = parse_local_uvc({"source_ids": identities, "retry_delay_seconds": 2})
        self.assertEqual(tuple(UUID(value) for value in identities), parsed.source_ids)
        self.assertEqual(2.0, parsed.retry_delay_seconds)
        self.assertNotIn(identities[0], repr(parsed))

    def test_frame_progress_timing_is_parsed_and_bounded(self):
        identity = str(uuid4())
        parsed = parse_local_uvc({"source_ids": [identity]})
        self.assertEqual(1.0, parsed.frame_stall_seconds)
        self.assertEqual(5.0, parsed.frame_stall_reopen_seconds)
        self.assertEqual(1.0, parsed.presence_scan_seconds)
        parsed = parse_local_uvc({
            "source_ids": [identity], "frame_stall_seconds": 2,
            "frame_stall_reopen_seconds": 10, "presence_scan_seconds": 0.5,
        })
        self.assertEqual((2.0, 10.0, 0.5), (
            parsed.frame_stall_seconds, parsed.frame_stall_reopen_seconds,
            parsed.presence_scan_seconds))

    def test_default_join_bound_covers_an_observed_real_close_and_settle(self):
        # Issue #173 item 3: on the real C960 (MANUAL_TEST P-7, 2026-10-07)
        # STREAMOFF/unmap/close took up to 5.5 s, and stopping a source then
        # waits up to HEALTH_SETTLE_SECONDS for its offline health write. The
        # default join bound must cover both with margin, or a clean shutdown
        # of a camera mid-teardown ends in STOP_FAILED.
        observed_close = 5.5
        required = observed_close + LocalUvcAdapter.HEALTH_SETTLE_SECONDS + 2.0
        parsed = parse_local_uvc({"source_ids": [str(uuid4())]})
        self.assertGreaterEqual(parsed.join_timeout_seconds, required)
        self.assertGreaterEqual(
            LocalUvcConfiguration((uuid4(),)).join_timeout_seconds, required)
        self.assertEqual(10.0, parsed.join_timeout_seconds)
        # The bound stays configurable within the validated range.
        identity = str(uuid4())
        for value in (1, 30, 60):
            self.assertEqual(float(value), parse_local_uvc(
                {"source_ids": [identity], "join_timeout_seconds": value}).join_timeout_seconds)
        self.assertEqual(0.25, parse_local_uvc({
            "source_ids": [identity], "join_timeout_seconds": 0.25,
            "frame_stall_seconds": 0.25}).join_timeout_seconds)
        for value in (0.05, 60.5, 0, -1, True, "10"):
            with self.assertRaises(ConfigurationError):
                parse_local_uvc({"source_ids": [identity], "join_timeout_seconds": value})

    def test_join_bound_shorter_than_the_stall_window_is_refused(self):
        # Issue #173: a join bound below the stall window releases the
        # database pin before the watchdog can durably lower a blocked
        # worker's ``online`` claim, so such a configuration is invalid.
        identity = str(uuid4())
        for join, stall in ((0.5, 30), (0.5, 1.0), (0.9, 1.0), (10, 30)):
            with self.subTest(join=join, stall=stall), self.assertRaises(ConfigurationError):
                parse_local_uvc({"source_ids": [identity], "join_timeout_seconds": join,
                                 "frame_stall_seconds": stall})
        with self.assertRaises(ConfigurationError):
            LocalUvcConfiguration((uuid4(),), join_timeout_seconds=0.5)
        for join, stall in ((1.0, 1.0), (5, 5), (10, 1)):
            parsed = parse_local_uvc({"source_ids": [identity], "join_timeout_seconds": join,
                                      "frame_stall_seconds": stall})
            self.assertEqual((float(join), float(stall)),
                             (parsed.join_timeout_seconds, parsed.frame_stall_seconds))

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
            {"source_ids": [identity], "frame_stall_seconds": 0},
            {"source_ids": [identity], "frame_stall_seconds": 1e9},
            {"source_ids": [identity], "frame_stall_reopen_seconds": float("inf")},
            {"source_ids": [identity], "presence_scan_seconds": 0},
            {"source_ids": [identity], "presence_scan_seconds": 3600},
            # Reopen before the stall is even reported would hide the stall.
            {"source_ids": [identity], "frame_stall_seconds": 5,
             "frame_stall_reopen_seconds": 2},
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
                "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444", "capture_ca_directory": None,
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
