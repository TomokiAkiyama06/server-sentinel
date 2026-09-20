"""Synthetic identity/health transitions; no physical devices are opened."""

from dataclasses import replace
import unittest
from uuid import UUID

from app.cameras.uvc.identity import (
    CameraState, DeviceEvidence, ReconnectController, match_reconnect,
)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.camera = DeviceEvidence("/dev/video0", "synthetic-vendor", "synthetic-model", "synthetic-serial")
        self.events = []
        self.source_id = UUID(int=1)
        self.control = ReconnectController(self.source_id, self.camera, self.events.append)

    def test_serial_match_survives_device_number_and_usb_port_change(self):
        returned = replace(self.camera, device_path="/dev/video7", topology="synthetic-port-2")
        self.assertEqual(self.control.reconcile([returned]), returned)
        self.assertEqual(self.control.state, CameraState.DEGRADED)
        self.control.capture_ready(returned)
        self.assertEqual(self.control.state, CameraState.ONLINE)
        self.assertEqual(self.control.source_id, self.source_id)

    def test_other_serial_never_substitutes_even_same_path(self):
        other = replace(self.camera, serial="another-synthetic-serial")
        self.assertIsNone(self.control.reconcile([other]))
        self.assertEqual(self.control.state, CameraState.OFFLINE)

    def test_duplicate_serial_requires_owner_and_latches(self):
        other = replace(self.camera, device_path="/dev/video1")
        self.assertIsNone(self.control.reconcile([self.camera, other]))
        self.assertEqual(self.control.state, CameraState.MANUAL)
        self.assertIsNone(self.control.reconcile([self.camera]))
        with self.assertRaises(ValueError):
            self.control.capture_ready(self.camera)
        self.control.approve(self.camera, [self.camera])
        self.control.capture_ready(self.camera)
        self.assertEqual(self.control.state, CameraState.ONLINE)

    def test_nonserial_path_topology_by_id_do_not_prove_identity(self):
        weak = replace(self.camera, serial=None, topology="synthetic-port", by_id=("synthetic-usb-model",))
        for candidates in ([weak], [weak, replace(weak, device_path="/dev/video2")]):
            result = match_reconnect(weak, tuple(candidates))
            self.assertEqual(result.state, CameraState.MANUAL)
            self.assertIsNone(result.device)

    def test_disconnect_is_audited_and_other_source_survives(self):
        other_events = []
        other = ReconnectController(UUID(int=2), self.camera, other_events.append)
        for control in (self.control, other):
            control.reconcile([self.camera])
            control.capture_ready(self.camera)
        self.control.disconnected()
        self.assertEqual(self.events[-1].reason, "device_disconnected")
        self.assertEqual(self.control.state, CameraState.OFFLINE)
        self.assertEqual(other.state, CameraState.ONLINE)
        self.control.reconcile([self.camera])
        self.control.capture_ready(self.camera)
        self.assertEqual(self.control.state, CameraState.ONLINE)

    def test_disabled_and_failed_capture_never_report_healthy(self):
        self.control.reconcile([self.camera])
        self.control.capture_failed()
        with self.assertRaises(ValueError):
            self.control.capture_ready(self.camera)
        self.control.set_enabled(False)
        self.assertIsNone(self.control.reconcile([self.camera]))
        with self.assertRaises(ValueError):
            self.control.approve(self.camera, [self.camera])

    def test_approval_needs_exact_single_current_candidate(self):
        for candidates in ([], [self.camera, self.camera], [replace(self.camera, serial="changed")]):
            with self.assertRaises(ValueError):
                self.control.approve(self.camera, candidates)

    def test_event_and_repr_exclude_physical_device_values(self):
        self.control.reconcile([self.camera])
        for text in (repr(self.camera), repr(self.events[-1])):
            self.assertNotIn("synthetic-serial", text)
            self.assertNotIn("/dev/video0", text)


if __name__ == "__main__":
    unittest.main()
