from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.cameras.registry import CameraRegistry, CaptureProfile, HealthState, SourceType
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
        connection = database.connect()
        migrate(connection, APPLICATION_MIGRATIONS)
        connection.close()
        self.registry = CameraRegistry(database)
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
        return LocalUvcAdapter(self.registry, emit_audit=self.events.append,
                               on_frame=lambda source_id, frame: self.frames.append((source_id, frame)),
                               discovery=self.discovery, capture_factory=SyntheticCapture)

    def test_source_does_not_acquire_camera_without_owner_selection(self):
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(self.registry.get_source(self.source.id).health_state, HealthState.OFFLINE)
        self.assertEqual(self.frames, [])

    def test_approval_negotiation_health_and_disable_are_persisted(self):
        self.adapter.approve_source(self.source.id, self.camera)
        self.assertEqual(self.registry.get_source(self.source.id).health_state, HealthState.DEGRADED)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        source = self.registry.get_source(self.source.id)
        self.assertEqual(source.health_state, HealthState.ONLINE)
        self.assertEqual(source.negotiated_capture_profile.pixel_format, "MJPG")
        self.assertIsNotNone(source.last_seen_at)
        self.assertEqual(source.image_quality_state, "unknown")
        self.registry.update_source(source.id, enabled=False)
        self.assertFalse(self.adapter.poll_source(source.id))
        self.assertEqual(self.registry.get_source(source.id).health_state, HealthState.OFFLINE)
        self.assertIsNone(self.registry.get_source(source.id).negotiated_capture_profile)

    def test_unplug_and_restart_keep_uuid_and_ambiguity_latch(self):
        self.adapter.approve_source(self.source.id, self.camera)
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
                         HealthState.MANUAL_INTERVENTION_REQUIRED)
        restarted.approve_source(self.source.id, self.camera)
        self.assertTrue(restarted.poll_source(self.source.id))
        self.assertEqual(self.registry.get_source(self.source.id).id, self.source.id)

    def test_source_failure_does_not_stop_other_camera(self):
        other = self.registry.create_source(
            source_type=SourceType.LOCAL_UVC, name="Other synthetic source", enabled=True,
            desired_capture_profile=CaptureProfile(640, 480, 10, "MJPG"),
        )
        other_camera = replace(self.camera, serial="other-synthetic", device_path="/dev/video1")
        self.discovery.devices.append(other_camera)
        self.adapter.approve_source(self.source.id, self.camera)
        self.adapter.approve_source(other.id, other_camera)
        self.adapter.poll_source(self.source.id)
        self.adapter.poll_source(other.id)
        self.discovery.devices = [other_camera]
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertTrue(self.adapter.poll_source(other.id))
        self.assertEqual(self.registry.get_source(other.id).health_state, HealthState.ONLINE)

    def test_failed_weak_reapproval_does_not_reopen_closed_binding(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        self.adapter.approve_source(self.source.id, weak)
        self.assertTrue(self.adapter.poll_source(self.source.id))
        closed_capture = self.adapter.sessions[self.source.id].capture
        with patch.object(self.adapter.store, "save", side_effect=ApprovalStorageError("synthetic failure")):
            with self.assertRaises(ApprovalStorageError):
                self.adapter.approve_source(self.source.id, weak)
        self.assertTrue(closed_capture.closed)
        self.assertIsNone(self.adapter.sessions[self.source.id].controller.bound)
        self.assertEqual(self.registry.get_source(self.source.id).health_state, HealthState.OFFLINE)
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(len(self.frames), 1)
        self.assertEqual(self.registry.get_source(self.source.id).health_state,
                         HealthState.MANUAL_INTERVENTION_REQUIRED)

    def test_restart_without_profile_keeps_durable_manual_state_without_churn(self):
        self.adapter.approve_source(self.source.id, self.camera)
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
                         HealthState.MANUAL_INTERVENTION_REQUIRED)
        event_count = len(self.events)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(len(self.events), event_count)

    def test_failed_first_approval_never_promotes_candidate_even_after_clean_restart(self):
        with patch.object(self.adapter.store, "save", side_effect=ApprovalStorageError("synthetic failure")):
            with self.assertRaises(ApprovalStorageError):
                self.adapter.approve_source(self.source.id, self.camera)
        self.assertTrue(self.adapter.store.load(self.source.id).requires_approval)
        self.assertFalse(self.adapter.poll_source(self.source.id))
        self.assertEqual(self.frames, [])
        self.adapter.close()
        restarted = self.make_adapter()
        self.addCleanup(restarted.close)
        self.assertFalse(restarted.poll_source(self.source.id))
        self.assertEqual(self.frames, [])
        restarted.approve_source(self.source.id, self.camera)
        self.assertTrue(restarted.poll_source(self.source.id))


if __name__ == "__main__":
    unittest.main()
