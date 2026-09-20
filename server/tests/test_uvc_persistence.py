from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
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
        return ReconnectController(self.source_id, self.camera, lambda event: None, store=self.store)

    def test_ambiguity_remains_latched_after_process_restart(self):
        control = self.controller()
        control.reconcile([self.camera, replace(self.camera, device_path="/dev/video1")])
        restarted = self.controller()
        self.assertIsNone(restarted.reconcile([self.camera]))
        self.assertEqual(restarted.state, CameraState.MANUAL)
        restarted.approve(self.camera, [self.camera])
        second_restart = self.controller()
        self.assertEqual(second_restart.reconcile([self.camera]), self.camera)
        self.assertEqual(second_restart.state, CameraState.DEGRADED)

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


if __name__ == "__main__":
    unittest.main()
