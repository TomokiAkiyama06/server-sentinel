from dataclasses import replace
import unittest
from uuid import UUID

from app.cameras.uvc.capture import CaptureError, NegotiatedVideo, VideoFrame, VideoProfile
from app.cameras.uvc.discovery import DiscoveryResult
from app.cameras.uvc.identity import CameraState, DeviceEvidence, ReconnectController
from app.cameras.uvc.session import CaptureSession


class Discovery:
    def __init__(self, devices):
        self.devices = devices

    def scan(self):
        return DiscoveryResult(tuple(self.devices), 0)


class SyntheticCapture:
    instances = []

    def __init__(self, candidate, profile, *, verify_identity):
        self.candidate, self.profile, self.verify = candidate, profile, verify_identity
        self.closed = False
        self.failed = False
        self.instances.append(self)

    def open(self):
        if not self.verify(self.candidate):
            raise CaptureError("synthetic identity changed")
        return NegotiatedVideo(self.profile, 0, 1024)

    def read_frame(self, timeout):
        if self.failed:
            raise CaptureError("synthetic unplug")
        return VideoFrame(b"synthetic", 0, 1.0)

    def close(self):
        self.closed = True


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial")
        self.discovery = Discovery([self.camera])
        self.events, self.frames, self.profiles = [], [], []
        self.controller = ReconnectController(UUID(int=1), self.camera, self.events.append)
        self.profile = VideoProfile(640, 480, 10, "MJPG")
        self.session = CaptureSession(
            self.controller, self.discovery, self.profile, on_frame=self.frames.append,
            on_profile=self.profiles.append, capture_factory=SyntheticCapture,
        )

    def test_unplug_audits_offline_then_serial_reconnect_delivers_video(self):
        self.assertTrue(self.session.step())
        self.assertEqual(self.controller.state, CameraState.ONLINE)
        old_capture = self.session.capture
        self.discovery.devices = []
        self.assertFalse(self.session.step())
        self.assertTrue(old_capture.closed)
        self.assertEqual(self.events[-1].reason, "device_disconnected")
        self.discovery.devices = [replace(self.camera, device_path="/dev/video5")]
        self.assertTrue(self.session.step())
        self.assertEqual(len(self.frames), 2)
        self.assertEqual(self.controller.state, CameraState.ONLINE)

    def test_capture_failure_does_not_escape_worker(self):
        self.session.step()
        self.session.capture.failed = True
        self.assertFalse(self.session.step())
        self.assertEqual(self.controller.state, CameraState.OFFLINE)
        self.assertIsNone(self.session.capture)

    def test_manual_ambiguity_stops_active_capture(self):
        self.session.step()
        self.discovery.devices.append(replace(self.camera, device_path="/dev/video1"))
        self.assertFalse(self.session.step())
        self.assertEqual(self.controller.state, CameraState.MANUAL)
        self.assertIsNone(self.session.capture)
        self.assertEqual(len(self.frames), 1)

    def test_disable_stops_capture_and_reenable_waits_for_new_frame(self):
        self.session.step()
        old_capture = self.session.capture
        self.session.configure(enabled=False, profile=self.profile)
        self.assertTrue(old_capture.closed)
        self.assertFalse(self.session.step())
        self.assertEqual(len(self.frames), 1)
        self.session.configure(enabled=True, profile=self.profile)
        self.assertTrue(self.session.step())
        self.assertEqual(len(self.frames), 2)

    def test_missing_explicit_profile_never_captures_or_reports_online(self):
        self.session.configure(enabled=True, profile=None)
        initial_events = len(self.events)
        self.assertFalse(self.session.step())
        self.assertFalse(self.session.step())
        self.assertNotEqual(self.controller.state, CameraState.ONLINE)
        self.assertEqual(self.frames, [])
        self.assertEqual(len(self.events), initial_events)

    def test_weak_candidate_recreated_before_open_requires_new_approval(self):
        original = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.controller.approve(original, [original])
        replacement = replace(original, instance_token=(1, 4, 5))
        self.discovery.devices = [replacement]
        self.assertFalse(self.session.step())
        self.assertEqual(self.controller.state, CameraState.MANUAL)
        self.assertEqual(self.frames, [])

    def test_owner_can_select_one_current_duplicate_until_descriptor_closes(self):
        duplicate = replace(self.camera, device_path="/dev/video1", instance_token=(1, 3, 4))
        self.discovery.devices.append(duplicate)
        self.assertFalse(self.session.step())
        self.controller.approve(duplicate, self.discovery.devices)
        self.assertTrue(self.session.step())
        self.assertEqual(self.controller.state, CameraState.ONLINE)
        self.session.close()
        self.assertFalse(self.session.step())
        self.assertEqual(self.controller.state, CameraState.MANUAL)


if __name__ == "__main__":
    unittest.main()
