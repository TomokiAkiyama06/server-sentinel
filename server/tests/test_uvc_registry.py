from contextlib import closing, contextmanager
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.audit import (
    AuditAction, AuditOutcome, AuditStorageError, AuditStore, OwnerAuditService,
    OwnerAuthorizationError,
)
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, CaptureProfile, SourceHealthState, SourceType
from app.cameras.uvc.identity import DeviceEvidence
from app.cameras.uvc.persistence import ApprovalStorageError
from app.cameras.uvc.registry_adapter import LocalUvcAdapter
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_uvc_session import Discovery, SyntheticCapture


class UvcRegistryTests(unittest.TestCase):
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

    def make_adapter(self):
        return LocalUvcAdapter(self.registry, emit_audit=self.events.append,
                               on_frame=lambda source_id, frame: self.frames.append((source_id, frame)),
                               discovery=self.discovery, capture_factory=SyntheticCapture)

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


if __name__ == "__main__":
    unittest.main()
