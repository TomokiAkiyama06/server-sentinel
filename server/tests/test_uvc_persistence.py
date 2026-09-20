from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from app.cameras.uvc.identity import CameraState, DeviceEvidence, ReconnectController
from app.cameras.uvc.persistence import ApprovalStorageError, ApprovalStore, SCHEMA


class SyntheticDatabase:
    def __init__(self, path):
        self.path = path

    def connect(self):
        connection = sqlite3.connect(self.path, isolation_level=None)
        return connection


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = SyntheticDatabase(Path(temporary.name) / "synthetic.sqlite")
        connection = self.database.connect()
        connection.execute("CREATE TABLE camera_sources (id TEXT PRIMARY KEY)")
        connection.execute(SCHEMA)
        connection.close()
        self.source_id = UUID(int=1)
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial", instance_token=(1, 2, 3))
        self.store = ApprovalStore(self.database)

    def controller(self):
        new_source = self.store.load(self.source_id) is None
        control = ReconnectController(self.source_id, self.camera, lambda event: None, store=self.store)
        if new_source:
            control.approve(self.camera, [self.camera])
            control.capture_closed()
        return control

    def test_ambiguity_remains_latched_after_process_restart(self):
        control = self.controller()
        control.reconcile([self.camera, replace(self.camera, device_path="/dev/video1")])
        restarted = self.controller()
        self.assertIsNone(restarted.reconcile([self.camera]))
        self.assertEqual(restarted.state, CameraState.MANUAL)
        restarted.approve(self.camera, [self.camera])
        restarted.capture_closed()
        restarted.shutdown()
        second_restart = self.controller()
        self.assertIsNone(second_restart.reconcile([self.camera]))
        self.assertEqual(second_restart.state, CameraState.MANUAL)
        self.assertTrue(self.store.load(self.source_id).serial_ambiguous)

    def test_weak_approval_survives_live_poll_but_not_restart(self):
        weak = replace(self.camera, serial=None)
        control = self.controller()
        control.approve(weak, [weak])
        control.capture_ready(weak)
        self.assertEqual(control.reconcile([weak]), weak)
        self.assertEqual(control.state, CameraState.ONLINE)
        restarted = self.controller()
        self.assertIsNone(restarted.reconcile([weak]))
        self.assertEqual(restarted.state, CameraState.MANUAL)

    def test_failed_persistent_approval_does_not_clear_latch(self):
        control = self.controller()
        control.reconcile([self.camera, replace(self.camera, device_path="/dev/video1")])
        connection = self.database.connect()
        connection.execute("DROP TABLE uvc_approvals")
        connection.close()
        with self.assertRaises(ApprovalStorageError):
            control.approve(self.camera, [self.camera])
        self.assertTrue(control.requires_approval)
        with self.assertRaises(ValueError):
            control.capture_ready(self.camera)

    def test_failed_ambiguity_write_is_fail_closed_after_restart(self):
        control = self.controller()
        with patch.object(self.store, "save", side_effect=ApprovalStorageError("synthetic write failure")):
            with self.assertRaises(ApprovalStorageError):
                control.reconcile([self.camera, replace(self.camera, device_path="/dev/video1")])
        # The failed write left the old approval value, but the pre-armed session
        # marker is durable and prevents trusting that stale value after restart.
        persisted = self.store.load(self.source_id)
        self.assertFalse(persisted.requires_approval)
        self.assertIsNotNone(persisted.session_token)
        restarted = self.controller()
        self.assertIsNone(restarted.reconcile([self.camera]))
        self.assertEqual(restarted.state, CameraState.MANUAL)
        restarted.approve(self.camera, [self.camera])
        restarted.capture_ready(self.camera)
        self.assertEqual(restarted.state, CameraState.ONLINE)

    def test_old_controller_cannot_clear_new_session_recovery_state(self):
        old = self.controller()
        current = self.controller()
        token = self.store.load(self.source_id).session_token
        with self.assertRaises(ApprovalStorageError):
            old.shutdown()
        self.assertEqual(self.store.load(self.source_id).session_token, token)
        self.assertTrue(current.requires_approval)
        self.assertIsNone(current.reconcile([self.camera]))

    def test_clean_shutdown_allows_unique_serial_reconnect(self):
        control = self.controller()
        control.reconcile([self.camera])
        control.capture_ready(self.camera)
        control.capture_closed()
        control.shutdown()
        self.assertIsNone(self.store.load(self.source_id).session_token)
        with self.assertRaises(ValueError):
            control.reconcile([self.camera])
        restarted = self.controller()
        self.assertEqual(restarted.reconcile([self.camera]), self.camera)

    def test_session_cannot_start_if_recovery_marker_cannot_be_written(self):
        connection = self.database.connect()
        connection.execute(
            "CREATE TRIGGER synthetic_write_failure BEFORE INSERT ON uvc_approvals "
            "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
        connection.close()
        with self.assertRaises(ApprovalStorageError):
            self.controller()
        self.assertIsNone(self.store.load(self.source_id))

    def test_owner_selection_of_a_different_unique_serial_can_establish_new_identity(self):
        control = self.controller()
        control.reconcile([self.camera, replace(self.camera, device_path="/dev/video1")])
        new_camera = replace(self.camera, serial="new-synthetic-unique-serial")
        control.approve(new_camera, [new_camera])
        self.assertFalse(control.serial_ambiguous)
        control.capture_closed()
        control.shutdown()
        restarted = self.controller()
        self.assertEqual(restarted.reconcile([new_camera]), new_camera)


if __name__ == "__main__":
    unittest.main()
