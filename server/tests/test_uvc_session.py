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
    # A driver that silently adjusts an unsupported request, like V4L2 S_FMT.
    negotiate = None

    def __init__(self, candidate, profile, *, verify_identity):
        self.candidate, self.profile, self.verify = candidate, profile, verify_identity
        self.closed = False
        self.failed = False
        self.instances.append(self)

    def open(self):
        if not self.verify(self.candidate):
            raise CaptureError("synthetic identity changed")
        adjusted = self.negotiate(self.profile) if self.negotiate else self.profile
        return NegotiatedVideo(adjusted, 0, 1024)

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


class CountingDiscovery(Discovery):
    def __init__(self, devices):
        super().__init__(devices)
        self.scans = 0

    def scan(self):
        self.scans += 1
        return super().scan()


class ProfileNegotiationTests(unittest.TestCase):
    """Driver-adjusted profiles are recorded but never reported online."""

    def setUp(self):
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial")
        self.discovery = CountingDiscovery([self.camera])
        self.events, self.frames, self.profiles = [], [], []
        self.controller = ReconnectController(UUID(int=1), self.camera, self.events.append)
        self.instances = []
        self.adjust = None
        self.profile = VideoProfile(1920, 1080, 30, "MJPG")
        self.session = self.make_session(self.profile)

    def make_session(self, profile):
        def factory(candidate, profile, *, verify_identity):
            capture = SyntheticCapture(candidate, profile, verify_identity=verify_identity)
            capture.negotiate = self.adjust
            self.instances.append(capture)
            return capture

        return CaptureSession(
            self.controller, self.discovery, profile, on_frame=self.frames.append,
            on_profile=self.profiles.append, capture_factory=factory,
        )

    def assert_unavailable(self, requested, negotiated):
        self.adjust = lambda profile: negotiated
        self.session.configure(enabled=True, profile=requested)
        delivered = len(self.frames)
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("capture_profile_unavailable", self.events[-1].reason)
        self.assertEqual(negotiated, self.profiles[-1].profile)
        self.assertIsNone(self.session.capture)
        self.assertTrue(self.instances[-1].closed)
        self.assertEqual(delivered, len(self.frames))

    def test_unsupported_resolution_is_not_online(self):
        self.assert_unavailable(VideoProfile(3840, 2160, 30, "MJPG"),
                                VideoProfile(1920, 1080, 30, "MJPG"))

    def test_unsupported_frame_rate_is_not_online(self):
        self.assert_unavailable(VideoProfile(1920, 1080, 60, "MJPG"),
                                VideoProfile(1920, 1080, 30, "MJPG"))
        self.assert_unavailable(VideoProfile(1920, 1080, 15, "MJPG"),
                                VideoProfile(1920, 1080, 30, "MJPG"))

    def test_unsupported_pixel_format_is_not_online(self):
        self.assert_unavailable(VideoProfile(1920, 1080, 30, "H264"),
                                VideoProfile(1920, 1080, 30, "MJPG"))
        self.assert_unavailable(VideoProfile(1920, 1080, 30, "YUYV"),
                                VideoProfile(640, 480, 30, "YUYV"))

    def test_unavailable_profile_is_not_reopened_every_poll(self):
        self.assert_unavailable(VideoProfile(3840, 2160, 30, "MJPG"),
                                VideoProfile(1920, 1080, 30, "MJPG"))
        opened, events, profiles = len(self.instances), len(self.events), len(self.profiles)
        for _ in range(3):
            self.assertFalse(self.session.step())
        self.assertEqual(opened, len(self.instances))
        self.assertEqual(events, len(self.events))
        self.assertEqual(profiles, len(self.profiles))
        self.assertEqual(CameraState.DEGRADED, self.controller.state)

    def test_supported_profile_change_recovers_and_unplug_clears_hold(self):
        self.assert_unavailable(VideoProfile(3840, 2160, 30, "MJPG"),
                                VideoProfile(1920, 1080, 30, "MJPG"))
        self.adjust = None
        self.session.configure(enabled=True, profile=self.profile)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.assert_unavailable(VideoProfile(1920, 1080, 60, "MJPG"),
                                VideoProfile(1920, 1080, 30, "MJPG"))
        self.discovery.devices = []
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        opened = len(self.instances)
        self.discovery.devices = [replace(self.camera, device_path="/dev/video4")]
        self.assertFalse(self.session.step())
        # A re-enumerated device is negotiated again, and still refused.
        self.assertEqual(opened + 1, len(self.instances))
        self.assertEqual("capture_profile_unavailable", self.events[-1].reason)

    def test_driver_rounded_ntsc_rate_satisfies_request(self):
        self.adjust = lambda profile: VideoProfile(1920, 1080, 30000 / 1001, "MJPG")
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)

    def test_disabled_or_latched_source_does_not_rescan_devices(self):
        self.session.configure(enabled=False, profile=self.profile)
        self.assertFalse(self.session.step())
        self.assertEqual(0, self.discovery.scans)
        self.session.configure(enabled=True, profile=self.profile)
        self.controller.requires_approval = True
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)
        self.assertEqual(0, self.discovery.scans)

    def test_weak_explicit_binding_stays_degraded_without_reopening(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        self.adjust = lambda profile: VideoProfile(1920, 1080, 30, "MJPG")
        self.session = self.make_session(VideoProfile(1920, 1080, 60, "MJPG"))
        self.controller.approve(weak, [weak])
        for _ in range(3):
            self.assertFalse(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("capture_profile_unavailable", self.events[-1].reason)
        self.assertEqual(1, len(self.instances))
        # A replaced device instance is never treated as the held binding.
        self.discovery.devices = [replace(weak, instance_token=(4, 5, 6))]
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)
        self.assertEqual(1, len(self.instances))


    def assert_hold_survives_metadata_refresh(self, held, *, approve):
        self.discovery.devices = [held]
        self.adjust = lambda profile: VideoProfile(1920, 1080, 30, "MJPG")
        self.session = self.make_session(VideoProfile(1920, 1080, 60, "MJPG"))
        if approve:
            self.controller.approve(held, [held])
        self.assertFalse(self.session.step())
        self.assertEqual("capture_profile_unavailable", self.events[-1].reason)
        opened, events = len(self.instances), len(self.events)
        # A rescan refreshes mutable metadata of the same live device node.
        refreshed = replace(held, by_id=("synthetic-alias",), formats=("MJPG", "YUYV"))
        self.discovery.devices = [refreshed]
        for _ in range(3):
            self.assertFalse(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("capture_profile_unavailable", self.events[-1].reason)
        self.assertEqual(opened, len(self.instances))
        self.assertEqual(events, len(self.events))
        self.assertTrue(self.controller.profile_unavailable)
        return refreshed

    def test_weak_hold_survives_metadata_refresh_but_not_instance_change(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        refreshed = self.assert_hold_survives_metadata_refresh(weak, approve=True)
        # An actual instance change still releases the hold and never
        # auto-binds the indistinguishable non-serial device.
        self.discovery.devices = [replace(refreshed, instance_token=(4, 5, 6))]
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)
        self.assertTrue(self.controller.requires_approval)

    def test_weak_hold_with_identical_twin_never_binds_the_twin(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        refreshed = self.assert_hold_survives_metadata_refresh(weak, approve=True)
        twin = replace(refreshed, device_path="/dev/video1", instance_token=(7, 8, 9))
        self.discovery.devices = [refreshed, twin]
        opened = len(self.instances)
        self.assertFalse(self.session.step())
        self.assertEqual(opened, len(self.instances))
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.discovery.devices = [twin]
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)
        self.assertEqual(opened, len(self.instances))

    def test_unique_serial_hold_is_not_reopened_after_metadata_refresh(self):
        self.assert_hold_survives_metadata_refresh(replace(self.camera, instance_token=(1, 2, 3)),
                                                   approve=False)

    def test_ambiguous_serial_explicit_hold_survives_metadata_refresh(self):
        live = replace(self.camera, instance_token=(1, 2, 3))
        twin = replace(live, device_path="/dev/video1", instance_token=(4, 5, 6))
        self.controller.approve(live, [live, twin])
        self.assertTrue(self.controller.serial_ambiguous)
        refreshed = self.assert_hold_survives_metadata_refresh(live, approve=False)
        self.discovery.devices = [refreshed, twin]
        opened = len(self.instances)
        self.assertFalse(self.session.step())
        self.assertEqual(opened, len(self.instances))
        self.assertEqual(CameraState.DEGRADED, self.controller.state)

if __name__ == "__main__":
    unittest.main()
