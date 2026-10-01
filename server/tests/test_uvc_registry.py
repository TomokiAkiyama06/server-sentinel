from contextlib import closing, contextmanager
from dataclasses import asdict, replace
from itertools import count
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.audit import (
    AuditAction, AuditOutcome, AuditStorageError, AuditStore, OwnerAuditService,
    OwnerAuthorizationError,
)
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, CaptureProfile, SourceHealthState, SourceType
from app.cameras.uvc.capture import VideoProfile as CaptureVideo
from app.cameras.uvc.identity import DeviceEvidence
from app.cameras.uvc.persistence import ApprovalConflictError, ApprovalStorageError
from app.cameras.uvc.registry_adapter import LocalUvcAdapter
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_uvc_session import Discovery, SyntheticCapture


class UvcRegistryFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = Database(Path(temporary.name) / "synthetic.sqlite")
        self.database = database
        connection = database.connect()
        migrate(connection, APPLICATION_MIGRATIONS)
        connection.close()
        self.registry = CameraRegistry(database, unaudited_writes=True)
        self.source = self.registry.create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=CaptureProfile(640, 480, 10, "MJPG"),
        )
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial")
        self.discovery = Discovery([self.camera])
        self.events, self.frames = [], []
        self.adapter = self.make_adapter()
        self.addCleanup(self.adapter.close)

    def make_adapter(self):
        # Each clock read advances one second, as if every poll came at least
        # one presence-scan interval after the previous one: the synthetic
        # capture does not fail on unplug the way a real descriptor does, so
        # these fixtures observe device changes through the rescan.
        ticks = count(1000.0)
        return LocalUvcAdapter(self.registry, emit_audit=self.events.append,
                               on_frame=lambda source_id, frame: self.frames.append((source_id, frame)),
                               discovery=self.discovery, capture_factory=SyntheticCapture,
                               monotonic=lambda: next(ticks))


class UvcRegistryTests(UvcRegistryFixture):
    def test_owner_admin_uvc_approval_is_atomically_audited(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                if actor_context != "synthetic-owner":
                    raise PermissionError("denied")

        audit = AuditStore(self.database)
        admin = OwnerAdministration(
            OwnerAuditService(audit, PermitOwner()), self.registry,
        )
        admin.approve_uvc(
            "synthetic-owner", self.adapter, self.source.id, self.camera,
        )
        approval = self.adapter.store.load(self.source.id)
        self.assertFalse(approval.requires_approval)
        self.assertEqual(self.camera, approval.approved)
        record = audit.list_records()[0]
        self.assertEqual(AuditAction.APPROVE_CAMERA, record.action)
        self.assertEqual(AuditOutcome.SUCCEEDED, record.outcome)
        self.assertTrue(self.adapter.poll_source(self.source.id))

    def test_frame_stall_is_persisted_as_not_online_and_recovers(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        now = [1000.0]
        self.adapter.monotonic = lambda: now[0]
        admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertEqual(SourceHealthState.ONLINE,
                         self.registry.get_source(self.source.id).health_state)
        # Off-worker check: no frame within the stall window.
        self.assertFalse(self.adapter.check_frame_progress(self.source.id))
        # Past the stall window, still inside the reopen bound.
        now[0] += 2
        self.assertTrue(self.adapter.check_frame_progress(self.source.id))
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        # The watchdog hands the registry write to a background thread.
        self._wait_persisted()
        self.assertEqual(SourceHealthState.DEGRADED,
                         self.registry.get_source(self.source.id).health_state)
        # Frames resuming is the only way back to online.
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertEqual(SourceHealthState.ONLINE,
                         self.registry.get_source(self.source.id).health_state)
        self.assertFalse(self.adapter.check_frame_progress(uuid4()))

    def _wait_persisted(self, timeout=5.0):
        deadline = time.monotonic() + timeout
        while self.adapter.health_unpersisted(self.source.id) and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertFalse(self.adapter.health_unpersisted(self.source.id))

    def _approved_online(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        now = [1000.0]
        self.adapter.monotonic = lambda: now[0]
        admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertEqual(SourceHealthState.ONLINE,
                         self.registry.get_source(self.source.id).health_state)
        return now

    def test_transient_stall_keeps_the_negotiated_profile_through_recovery(self):
        now = self._approved_online()
        negotiated = CaptureProfile(640, 480, 10, "MJPG")
        self.assertEqual(negotiated,
                         self.registry.get_source(self.source.id).negotiated_capture_profile)
        now[0] += 2
        self.assertTrue(self.adapter.check_frame_progress(self.source.id))
        self._wait_persisted()
        stalled = self.registry.get_source(self.source.id)
        self.assertEqual(SourceHealthState.DEGRADED, stalled.health_state)
        # The descriptor stays open with the same profile during a stall.
        self.assertEqual(negotiated, stalled.negotiated_capture_profile)
        now[0] += 1
        self.assertTrue(self.adapter.poll_source(self.source.id))
        recovered = self.registry.get_source(self.source.id)
        self.assertEqual(SourceHealthState.ONLINE, recovered.health_state)
        self.assertEqual(negotiated, recovered.negotiated_capture_profile)

    def test_watchdog_reports_a_stall_while_the_worker_is_blocked_in_a_health_write(self):
        now = self._approved_online()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        original = self.registry.update_source_health

        def blocking_write(source_id, **values):
            if "last_seen_at" in values and not release.is_set():
                # The worker holds a slow SQLite/storage write.
                entered.set()
                release.wait(10)
            return original(source_id, **values)

        self.registry.update_source_health = blocking_write
        now[0] += 1.5
        worker = threading.Thread(target=self.adapter.poll_source, args=(self.source.id,))
        worker.start()
        self.addCleanup(worker.join, 10)
        self.assertTrue(entered.wait(5))
        # No frame arrives while the worker is stuck in the write.
        now[0] += 2
        result = []
        watchdog = threading.Thread(
            target=lambda: result.append(self.adapter.check_frame_progress(self.source.id)))
        watchdog.start()
        watchdog.join(5)
        self.assertFalse(watchdog.is_alive())
        self.assertEqual([True], result)
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        # The durable row is behind the in-memory state until the write ends.
        self.assertTrue(self.adapter.health_unpersisted(self.source.id))
        release.set()
        worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(SourceHealthState.DEGRADED,
                         self.registry.get_source(self.source.id).health_state)
        self.assertFalse(self.adapter.health_unpersisted(self.source.id))

    def test_health_is_unpersisted_while_an_uncontended_write_is_in_flight(self):
        now = self._approved_online()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        original = self.registry.update_source_health

        def blocking_write(source_id, **values):
            if "last_seen_at" in values and not release.is_set():
                entered.set()
                release.wait(10)
            return original(source_id, **values)

        self.registry.update_source_health = blocking_write
        now[0] += 1.5
        worker = threading.Thread(target=self.adapter.poll_source, args=(self.source.id,))
        worker.start()
        self.addCleanup(worker.join, 10)
        self.assertTrue(entered.wait(5))
        # No other flush contends: the write in flight alone means the
        # durable row may still be behind the in-memory state.
        self.assertTrue(self.adapter.health_unpersisted(self.source.id))
        release.set()
        worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertFalse(self.adapter.health_unpersisted(self.source.id))

    def test_uvc_approval_rolls_back_when_audit_append_fails(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        audit = AuditStore(self.database)
        admin = OwnerAdministration(
            OwnerAuditService(audit, PermitOwner()), self.registry,
        )
        before = self.registry.get_source(self.source.id)
        with patch.object(audit, "append_on",
                          side_effect=AuditStorageError("synthetic unavailable")):
            with self.assertRaises(AuditStorageError):
                admin.approve_uvc(
                    "synthetic-owner", self.adapter, self.source.id, self.camera,
                )
        self.assertIsNone(self.adapter.store.load(self.source.id))
        self.assertNotIn(self.source.id, self.adapter._approved_handoffs)
        self.assertEqual(before, self.registry.get_source(self.source.id))

    def test_audited_owner_reapproval_replaces_stopped_cached_session(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        audit = AuditStore(self.database)
        admin = OwnerAdministration(
            OwnerAuditService(audit, PermitOwner()), self.registry,
        )
        admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.adapter.sessions[self.source.id].close()
        duplicate = replace(self.camera, device_path="/dev/video2")
        self.discovery.devices = [self.camera, duplicate]
        self.assertFalse(self.adapter.poll_source(self.source.id))
        cached = self.adapter.sessions[self.source.id]
        self.assertTrue(cached.stopped)
        self.assertTrue(cached.controller.requires_approval)

        self.discovery.devices = [self.camera]
        admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertNotIn(self.source.id, self.adapter.sessions)
        approved = self.adapter.store.load(self.source.id)
        self.assertTrue(approved.serial_ambiguous)
        self.assertFalse(approved.explicit_binding)
        self.assertEqual(self.camera, self.adapter._approved_handoffs[self.source.id])
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertFalse(self.adapter.store.load(self.source.id).explicit_binding)
        self.adapter.sessions[self.source.id].close()
        self.discovery.devices = [duplicate]
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(
            SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
            self.registry.get_source(self.source.id).health_state,
        )
        self.assertTrue(self.adapter.store.load(self.source.id).serial_ambiguous)
        approvals = [record for record in audit.list_records()
                     if record.action is AuditAction.APPROVE_CAMERA]
        self.assertEqual(2, len(approvals))
        self.assertTrue(all(record.outcome is AuditOutcome.SUCCEEDED
                            for record in approvals))

    def test_audited_weak_approval_is_explicit_for_one_live_session(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        audit = AuditStore(self.database)
        admin = OwnerAdministration(
            OwnerAuditService(audit, PermitOwner()), self.registry,
        )
        admin.approve_uvc("owner", self.adapter, self.source.id, weak)
        self.assertFalse(self.adapter.store.load(self.source.id).explicit_binding)
        self.assertEqual(weak, self.adapter._approved_handoffs[self.source.id])
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertFalse(self.adapter.store.load(self.source.id).explicit_binding)
        self.adapter.sessions[self.source.id].close()
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(
            SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
            self.registry.get_source(self.source.id).health_state,
        )

    def test_process_restart_cannot_consume_persisted_explicit_approval(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        admin.approve_uvc("owner", self.adapter, self.source.id, weak)
        restarted = self.make_adapter()
        self.addCleanup(restarted.close)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(
            SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
            self.registry.get_source(self.source.id).health_state,
        )

    def test_committed_handoff_still_requires_the_exact_live_candidate(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        admin.approve_uvc("owner", self.adapter, self.source.id, weak)
        self.discovery.devices = [replace(weak, device_path="/dev/video2")]
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(
            SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
            self.registry.get_source(self.source.id).health_state,
        )

    def test_transient_session_failure_keeps_the_committed_handoff(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        admin.approve_uvc("owner", self.adapter, self.source.id, weak)
        with patch.object(self.adapter, "_session",
                          side_effect=ApprovalStorageError("synthetic transient")):
            with self.assertRaises(ApprovalStorageError):
                self.adapter.poll_source(self.source.id)
        # A transient failure must not discard the only proof of the exact
        # device the Owner selected, which would force another approval.
        self.assertEqual(weak, self.adapter._approved_handoffs[self.source.id])
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertNotIn(self.source.id, self.adapter._approved_handoffs)
        self.assertEqual(
            SourceHealthState.ONLINE,
            self.registry.get_source(self.source.id).health_state,
        )

    def test_superseded_handoff_is_discarded_for_a_newer_approval(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                return None

        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        admin.approve_uvc("owner", self.adapter, self.source.id, weak)
        replacement = replace(weak, device_path="/dev/video3", instance_token=(4, 5, 6))
        self.discovery.devices = [replacement]
        self.adapter._approved_handoffs[self.source.id] = weak
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.adapter.approve_source_on(
                connection, self.adapter.prepare_approval(self.source.id, replacement),
            )
            connection.commit()
        # The stale handoff never binds a device the Owner did not select; the
        # superseded approval falls back to conservative manual intervention.
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertNotIn(self.source.id, self.adapter._approved_handoffs)
        self.assertIsNone(self.adapter.sessions[self.source.id].controller.bound)
        self.assertEqual(
            SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
            self.registry.get_source(self.source.id).health_state,
        )

    def test_device_scan_never_runs_inside_the_audited_transaction(self):
        class PermitOwner:
            def require_owner(self, actor_context):
                if actor_context != "synthetic-owner":
                    raise PermissionError("denied")

        audit = AuditStore(self.database)
        admin = OwnerAdministration(
            OwnerAuditService(audit, PermitOwner()), self.registry,
        )
        scans = []
        original_scan = self.discovery.scan

        def counted_scan():
            scans.append(True)
            return original_scan()

        self.discovery.scan = counted_scan
        original_transaction = audit.transaction
        inside = []

        @contextmanager
        def watched(*args, **kwargs):
            before = len(scans)
            with original_transaction(*args, **kwargs) as connection:
                yield connection
            inside.append(len(scans) - before)

        with patch.object(audit, "transaction", side_effect=watched):
            admin.approve_uvc(
                "synthetic-owner", self.adapter, self.source.id, self.camera,
            )
        # Blocking USB/UVC discovery must not hold the database write lock.
        self.assertTrue(scans)
        self.assertEqual([0], inside)

        # A denied actor never reaches device discovery either.
        scans.clear()
        with self.assertRaises(OwnerAuthorizationError):
            admin.approve_uvc("not-owner", self.adapter, self.source.id, self.camera)
        self.assertEqual([], scans)
        with self.assertRaises(ValueError):
            self.adapter.approve_source_on(object(), self.camera)

    def test_source_does_not_acquire_camera_without_owner_selection(self):
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(self.registry.get_source(self.source.id).health_state, SourceHealthState.OFFLINE)
        self.assertEqual(self.frames, [])

    def test_approval_negotiation_health_and_disable_are_persisted(self):
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.assertEqual(self.registry.get_source(self.source.id).health_state, SourceHealthState.DEGRADED)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        source = self.registry.get_source(self.source.id)
        self.assertEqual(source.health_state, SourceHealthState.ONLINE)
        self.assertEqual(source.negotiated_capture_profile.pixel_format, "MJPG")
        self.assertIsNotNone(source.last_seen_at)
        self.assertEqual(source.image_quality_state, "unknown")
        self.registry.update_source(source.id, enabled=False)
        self.assertFalse(self.adapter.poll_source(source.id))
        self.assertEqual(self.registry.get_source(source.id).health_state, SourceHealthState.OFFLINE)
        self.assertIsNone(self.registry.get_source(source.id).negotiated_capture_profile)

    def test_unplug_and_restart_keep_uuid_and_ambiguity_latch(self):
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.adapter.poll_source(self.source.id)
        self.discovery.devices = []
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(self.events[-1].reason, "device_disconnected")
        self.discovery.devices = [self.camera, replace(self.camera, device_path="/dev/video2")]
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.adapter.close()
        self.discovery.devices = [self.camera]
        restarted = self.make_adapter()
        self.addCleanup(restarted.close)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(self.registry.get_source(self.source.id).health_state,
                         SourceHealthState.MANUAL_INTERVENTION_REQUIRED)
        restarted._approve_live_session(self.source.id, self.camera)
        self.assertTrue(restarted.poll_source(self.source.id))
        self.assertEqual(self.registry.get_source(self.source.id).id, self.source.id)

    def test_clean_shutdown_closes_capture_without_reporting_unplug(self):
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        capture = self.adapter.sessions[self.source.id].capture
        self.events.clear()
        self.adapter.close()
        self.assertTrue(capture.closed)
        self.assertEqual([event.reason for event in self.events], ["video_capture_closed"])
        self.assertEqual(self.registry.get_source(self.source.id).health_state, SourceHealthState.OFFLINE)
        self.assertIsNone(self.adapter.store.load(self.source.id).session_token)

    def test_clean_shutdown_of_disabled_source_does_not_report_unplug(self):
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.registry.update_source(self.source.id, enabled=False)
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.events.clear()
        self.adapter.close()
        self.assertEqual(self.events, [])
        self.assertEqual(self.registry.get_source(self.source.id).health_state, SourceHealthState.OFFLINE)

    def test_clean_shutdown_preserves_manual_state_without_reporting_unplug(self):
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.adapter.sessions[self.source.id].close()
        self.discovery.devices.append(replace(self.camera, device_path="/dev/video2"))
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.events.clear()
        self.adapter.close()
        self.assertEqual(self.events, [])
        self.assertEqual(self.registry.get_source(self.source.id).health_state,
                         SourceHealthState.MANUAL_INTERVENTION_REQUIRED)
        saved = self.adapter.store.load(self.source.id)
        self.assertTrue(saved.requires_approval)
        self.assertIsNone(saved.session_token)

    def test_source_failure_does_not_stop_other_camera(self):
        other = self.registry.create_source(
            source_type=SourceType.LOCAL_UVC, name="Other synthetic source", enabled=True,
            desired_capture_profile=CaptureProfile(640, 480, 10, "MJPG"),
        )
        other_camera = replace(self.camera, serial="other-synthetic", device_path="/dev/video1")
        self.discovery.devices.append(other_camera)
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.adapter._approve_live_session(other.id, other_camera)
        self.adapter.poll_source(self.source.id)
        self.adapter.poll_source(other.id)
        self.discovery.devices = [other_camera]
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertTrue(self.adapter.poll_source(other.id))
        self.assertEqual(self.registry.get_source(other.id).health_state, SourceHealthState.ONLINE)

    def test_failed_weak_reapproval_does_not_reopen_closed_binding(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        self.adapter._approve_live_session(self.source.id, weak)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        closed_capture = self.adapter.sessions[self.source.id].capture
        with patch.object(self.adapter.store, "save", side_effect=ApprovalStorageError("synthetic failure")):
            with self.assertRaises(ApprovalStorageError):
                self.adapter._approve_live_session(self.source.id, weak)
        self.assertTrue(closed_capture.closed)
        self.assertIsNone(self.adapter.sessions[self.source.id].controller.bound)
        # Closing hands the registry write to the background health writer.
        self._wait_persisted()
        self.assertEqual(self.registry.get_source(self.source.id).health_state, SourceHealthState.OFFLINE)
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(len(self.frames), 1)
        self.assertEqual(self.registry.get_source(self.source.id).health_state,
                         SourceHealthState.MANUAL_INTERVENTION_REQUIRED)

    def test_restart_without_profile_keeps_durable_manual_state_without_churn(self):
        self.adapter._approve_live_session(self.source.id, self.camera)
        self.adapter.sessions[self.source.id].close()
        self.discovery.devices.append(replace(self.camera, device_path="/dev/video2"))
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertTrue(self.adapter.store.load(self.source.id).requires_approval)
        self.registry.update_source(self.source.id, desired_capture_profile=None)
        self.adapter.close()
        restarted = self.make_adapter()
        self.addCleanup(restarted.close)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(self.registry.get_source(self.source.id).health_state,
                         SourceHealthState.MANUAL_INTERVENTION_REQUIRED)
        event_count = len(self.events)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(len(self.events), event_count)

    def test_failed_first_approval_never_promotes_candidate_even_after_clean_restart(self):
        with patch.object(self.adapter.store, "save", side_effect=ApprovalStorageError("synthetic failure")):
            with self.assertRaises(ApprovalStorageError):
                self.adapter._approve_live_session(self.source.id, self.camera)
        self.assertTrue(self.adapter.store.load(self.source.id).requires_approval)
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(self.frames, [])
        self.adapter.close()
        restarted = self.make_adapter()
        self.addCleanup(restarted.close)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(self.frames, [])
        restarted._approve_live_session(self.source.id, self.camera)
        self.assertTrue(restarted.poll_source(self.source.id))


class PermitAnyOwner:
    def require_owner(self, actor_context):
        return None


class DuplicateApprovalTests(UvcRegistryFixture):
    """One physical camera is never approved for two enabled sources."""

    def setUp(self):
        super().setUp()
        self.other = self.registry.create_source(
            source_type=SourceType.LOCAL_UVC, name="Second synthetic source", enabled=True,
            desired_capture_profile=CaptureProfile(640, 480, 10, "MJPG"),
        )
        self.second_camera = DeviceEvidence("/dev/video2", "synthetic", "model", "serial-2")
        self.discovery.devices = [self.camera, self.second_camera]
        self.audit = AuditStore(self.database)
        self.admin = OwnerAdministration(
            OwnerAuditService(self.audit, PermitAnyOwner()), self.registry,
        )

    def approvals(self):
        return [record.outcome for record in self.audit.list_records()
                if record.action is AuditAction.APPROVE_CAMERA]

    def persist_duplicate(self, source_id, evidence):
        """Write an approval row as a build without the check could have."""
        with closing(self.database.connect()) as connection:
            connection.execute(
                "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, "
                "session_token, serial_ambiguous) VALUES (?, ?, 0, NULL, 0)",
                (str(source_id), json.dumps(asdict(evidence))),
            )

    def test_same_camera_cannot_be_approved_for_a_second_source(self):
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        moved = replace(self.camera, device_path="/dev/video7")
        self.discovery.devices = [moved, self.second_camera]
        with self.assertRaises(ValueError) as refused:
            self.admin.approve_uvc("owner", self.adapter, self.other.id, moved)
        # Generic reason only: no identifier of the other source or camera.
        self.assertNotIn("serial", str(refused.exception))
        self.assertIsNone(self.adapter.store.load(self.other.id))
        self.assertEqual(sorted([AuditOutcome.SUCCEEDED, AuditOutcome.FAILED]),
                         sorted(self.approvals()))
        self.assertFalse(self.adapter.poll_source(self.other.id))
        self.assertEqual(SourceHealthState.OFFLINE, self.registry.get_source(self.other.id).health_state)
        # The approved source reconnects its camera by serial at its new node.
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertTrue(self.adapter.poll_source(self.source.id))
        # A different camera can still be approved for the second source.
        self.admin.approve_uvc("owner", self.adapter, self.other.id, self.second_camera)
        self.assertTrue(self.adapter.poll_source(self.other.id))

    def test_transaction_rechecks_a_concurrent_approval(self):
        prepared_first = self.adapter.prepare_approval(self.source.id, self.camera)
        prepared_second = self.adapter.prepare_approval(self.other.id, self.camera)
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.adapter.approve_source_on(connection, prepared_first)
            connection.commit()
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ApprovalConflictError):
                self.adapter.approve_source_on(connection, prepared_second)
            connection.rollback()
        self.assertIsNone(self.adapter.store.load(self.other.id))

    def test_concurrent_duplicate_serial_cameras_map_to_separate_sources(self):
        # Two physical cameras that report one serial are told apart only by
        # exact live-instance evidence; each can be explicitly approved once.
        twin = replace(self.camera, device_path="/dev/video4", device_number=4)
        self.discovery.devices = [self.camera, twin]
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.admin.approve_uvc("owner", self.adapter, self.other.id, twin)
        for source_id, expected in ((self.source.id, self.camera), (self.other.id, twin)):
            approval = self.adapter.store.load(source_id)
            self.assertEqual(expected, approval.approved)
            self.assertTrue(approval.serial_ambiguous)
        self.adapter.monotonic = lambda: 1e9
        for _ in range(2):
            self.assertTrue(self.adapter.poll_source(self.source.id))
            self.assertTrue(self.adapter.poll_source(self.other.id))
        for source_id in (self.source.id, self.other.id):
            self.assertEqual(SourceHealthState.ONLINE,
                             self.registry.get_source(source_id).health_state)
        self.assertEqual([AuditOutcome.SUCCEEDED] * 2, self.approvals())

    def test_exact_duplicate_serial_instance_is_still_refused_for_a_second_source(self):
        twin = replace(self.camera, device_path="/dev/video4", device_number=4)
        self.discovery.devices = [self.camera, twin]
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        with self.assertRaises(ValueError):
            self.admin.approve_uvc("owner", self.adapter, self.other.id, self.camera)
        prepared = self.adapter.prepare_approval(self.other.id, twin)
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ApprovalConflictError):
                self.adapter.approve_source_on(
                    connection, replace(prepared, candidate=self.camera))
            connection.rollback()
        self.assertIsNone(self.adapter.store.load(self.other.id))
        # Once the twin is gone, the shared serial again names one camera.
        self.discovery.devices = [replace(self.camera, device_path="/dev/video6")]
        with self.assertRaises(ValueError):
            self.admin.approve_uvc("owner", self.adapter, self.other.id,
                                   self.discovery.devices[0])

    def test_refreshed_alias_metadata_does_not_free_a_duplicate_serial_instance(self):
        # The same live duplicate-serial camera may gain a by-id alias or a
        # different advertised format list between scans; only mutable
        # metadata changed, so it is still held by the first source.
        twin = replace(self.camera, device_path="/dev/video4", device_number=4)
        self.discovery.devices = [self.camera, twin]
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        refreshed = replace(self.camera, by_id=("synthetic-alias",), formats=("YUYV",))
        self.discovery.devices = [refreshed, twin]
        with self.assertRaises(ValueError):
            self.admin.approve_uvc("owner", self.adapter, self.other.id, refreshed)
        prepared = self.adapter.prepare_approval(self.other.id, twin)
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ApprovalConflictError):
                self.adapter.approve_source_on(
                    connection, replace(prepared, candidate=refreshed))
            connection.rollback()
        self.assertIsNone(self.adapter.store.load(self.other.id))

    def test_twin_of_a_serial_held_camera_is_refused_until_holder_is_reapproved(self):
        # S1 was approved before a same-serial twin appeared, so its own
        # runtime check still compares by serial. Approving the twin for S2
        # would make S1 report a conflict, so the approval is refused instead.
        self.discovery.devices = [self.camera]
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertFalse(self.adapter.store.load(self.source.id).serial_ambiguous)
        twin = replace(self.camera, device_path="/dev/video4", device_number=4)
        self.discovery.devices = [self.camera, twin]
        with self.assertRaises(ValueError):
            self.admin.approve_uvc("owner", self.adapter, self.other.id, twin)
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(ApprovalConflictError):
                self.adapter.store.approve_on(connection, self.other.id, twin,
                                              serial_ambiguous=True)
            connection.rollback()
        self.assertIsNone(self.adapter.store.load(self.other.id))
        self.assertCountEqual([AuditOutcome.SUCCEEDED, AuditOutcome.FAILED], self.approvals())
        self.adapter.monotonic = lambda: 1e9
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertEqual(SourceHealthState.ONLINE,
                         self.registry.get_source(self.source.id).health_state)
        # Reapproving S1 while the twin is connected records an exact
        # live-instance binding; the twin can then be approved for S2.
        self.adapter.stop_source(self.source.id)
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.assertTrue(self.adapter.store.load(self.source.id).serial_ambiguous)
        self.admin.approve_uvc("owner", self.adapter, self.other.id, twin)
        for _ in range(2):
            self.assertTrue(self.adapter.poll_source(self.source.id))
            self.assertTrue(self.adapter.poll_source(self.other.id))
        for source_id in (self.source.id, self.other.id):
            self.assertEqual(SourceHealthState.ONLINE,
                             self.registry.get_source(source_id).health_state)

    def test_disabled_or_latched_source_does_not_hold_the_camera(self):
        self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.registry.update_source(self.source.id, enabled=False)
        self.admin.approve_uvc("owner", self.adapter, self.other.id, self.camera)
        self.assertTrue(self.adapter.poll_source(self.other.id))
        self.registry.update_source(self.source.id, enabled=True)
        # Re-enabling the older duplicate never races for the camera: both
        # conflicting sources require the Owner, whichever polls first.
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.adapter.monotonic = lambda: 1e9
        self.assertFalse(self.adapter.poll_source(self.other.id))
        for source_id in (self.source.id, self.other.id):
            self.assertEqual(SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
                             self.registry.get_source(source_id).health_state)
            self.assertIsNone(self.adapter.sessions[source_id].capture)
        # A latched (approval-required) row holds no camera either.
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE uvc_approvals SET requires_approval=1 WHERE source_id=?",
                               (str(self.source.id),))
        self.adapter.stop_source(self.other.id)
        self.assertTrue(self.adapter.poll_source(self.other.id))

    def test_persisted_duplicate_is_manual_in_either_startup_order(self):
        for order in ((self.source.id, self.other.id), (self.other.id, self.source.id)):
            with self.subTest(order=order):
                with closing(self.database.connect()) as connection:
                    connection.execute("DELETE FROM uvc_approvals")
                self.persist_duplicate(self.source.id, self.camera)
                self.persist_duplicate(self.other.id, self.camera)
                adapter = self.make_adapter()
                self.addCleanup(adapter.close)
                opened = len(SyntheticCapture.instances)
                for _ in range(3):
                    for source_id in order:
                        self.assertFalse(adapter.poll_source(source_id))
                self.assertEqual(opened, len(SyntheticCapture.instances))
                for source_id in order:
                    self.assertEqual(SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
                                     self.registry.get_source(source_id).health_state)
                # The durable approvals are unchanged: nothing was rebound.
                for source_id in order:
                    self.assertEqual(self.camera, adapter.store.load(source_id).approved)
                adapter.close()

    def test_owner_resolves_duplicate_by_disabling_one_source(self):
        self.persist_duplicate(self.source.id, self.camera)
        self.persist_duplicate(self.other.id, self.camera)
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertFalse(self.adapter.poll_source(self.other.id))
        self.adapter.stop_source(self.source.id)
        # Reapproving the same camera while the other source still holds it
        # is refused; the Owner disables (or reapproves) the other source.
        with self.assertRaises(ValueError):
            self.admin.approve_uvc("owner", self.adapter, self.source.id, self.camera)
        self.registry.update_source(self.other.id, enabled=False)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        self.assertFalse(self.adapter.poll_source(self.other.id))
        self.assertEqual(SourceHealthState.OFFLINE, self.registry.get_source(self.other.id).health_state)

    def test_unsupported_profile_is_degraded_with_negotiated_profile_recorded(self):
        class AdjustingCapture(SyntheticCapture):
            def open(self):
                negotiated = super().open()
                return replace(negotiated, profile=CaptureVideo(1920, 1080, 30, "MJPG"))

        self.registry.update_source(
            self.source.id, desired_capture_profile=CaptureProfile(3840, 2160, 30, "MJPG"))
        adapter = LocalUvcAdapter(self.registry, emit_audit=self.events.append,
                                  on_frame=lambda source_id, frame: self.frames.append(frame),
                                  discovery=self.discovery, capture_factory=AdjustingCapture)
        self.addCleanup(adapter.close)
        self.admin.approve_uvc("owner", adapter, self.source.id, self.camera)
        for _ in range(3):
            self.assertFalse(adapter.poll_source(self.source.id))
        source = self.registry.get_source(self.source.id)
        self.assertEqual(SourceHealthState.DEGRADED, source.health_state)
        self.assertEqual((1920, 1080, 30, "MJPG"), (
            source.negotiated_capture_profile.width, source.negotiated_capture_profile.height,
            source.negotiated_capture_profile.fps, source.negotiated_capture_profile.pixel_format))
        self.assertEqual([], self.frames)
        self.assertEqual("capture_profile_unavailable", self.events[-1].reason)


    def test_weak_camera_profile_fix_requires_owner_reapproval(self):
        # A non-serial binding lasts only while its descriptor is open. After
        # capture_profile_unavailable closes it, changing the profile cannot
        # rebind the camera by its weak evidence: the Owner reapproves it.
        class AdjustingCapture(SyntheticCapture):
            def open(self):
                negotiated = super().open()
                return replace(negotiated, profile=CaptureVideo(1920, 1080, 30, "MJPG"))

        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak, self.second_camera]
        self.registry.update_source(
            self.source.id, desired_capture_profile=CaptureProfile(3840, 2160, 30, "MJPG"))
        adapter = LocalUvcAdapter(self.registry, emit_audit=self.events.append,
                                  on_frame=lambda source_id, frame: self.frames.append(frame),
                                  discovery=self.discovery, capture_factory=AdjustingCapture)
        self.addCleanup(adapter.close)
        self.admin.approve_uvc("owner", adapter, self.source.id, weak)
        self.assertFalse(adapter.poll_source(self.source.id))
        self.assertEqual(SourceHealthState.DEGRADED,
                         self.registry.get_source(self.source.id).health_state)
        self.registry.update_source(
            self.source.id, desired_capture_profile=CaptureProfile(1920, 1080, 30, "MJPG"))
        for _ in range(2):
            self.assertFalse(adapter.poll_source(self.source.id))
        self.assertEqual(SourceHealthState.MANUAL_INTERVENTION_REQUIRED,
                         self.registry.get_source(self.source.id).health_state)
        self.assertTrue(adapter.store.load(self.source.id).requires_approval)
        self.assertIn("identity_not_unique", [event.reason for event in self.events])
        self.assertEqual([], self.frames)

if __name__ == "__main__":
    unittest.main()
