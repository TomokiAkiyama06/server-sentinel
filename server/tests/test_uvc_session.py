from dataclasses import replace
import unittest
from uuid import UUID

import threading

from app.cameras.uvc.capture import (
    CaptureError, FrameTimeout, NegotiatedVideo, VideoFrame, VideoProfile,
)
from app.cameras.uvc.discovery import DiscoveryResult
from app.cameras.uvc.identity import CameraState, DeviceEvidence, ReconnectController
from app.cameras.uvc.session import CaptureSession


class Discovery:
    def __init__(self, devices):
        self.devices = devices

    def scan(self):
        return DiscoveryResult(tuple(self.devices), 0)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class SyntheticCapture:
    instances = []
    # A driver that silently adjusts an unsupported request, like V4L2 S_FMT.
    negotiate = None

    def __init__(self, candidate, profile, *, verify_identity):
        self.candidate, self.profile, self.verify = candidate, profile, verify_identity
        self.closed = False
        self.failed = False
        # Synthetic stall: read_frame times out like a V4L2 select() timeout.
        self.stalled = False
        self.timeouts = []
        self.instances.append(self)

    def open(self):
        if not self.verify(self.candidate):
            raise CaptureError("synthetic identity changed")
        adjusted = self.negotiate(self.profile) if self.negotiate else self.profile
        return NegotiatedVideo(adjusted, 0, 1024)

    def read_frame(self, timeout):
        if self.failed:
            raise CaptureError("synthetic unplug")
        if self.stalled:
            self.timeouts.append(timeout)
            raise FrameTimeout("synthetic frame timeout")
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
        self.clock = FakeClock()
        self.session = CaptureSession(
            self.controller, self.discovery, self.profile, on_frame=self.frames.append,
            on_profile=self.profiles.append, capture_factory=SyntheticCapture,
            clock=self.clock,
        )

    def rescan_due(self):
        self.clock.advance(self.session.presence_scan_seconds)

    def test_unplug_audits_offline_then_serial_reconnect_delivers_video(self):
        self.assertTrue(self.session.step())
        self.assertEqual(self.controller.state, CameraState.ONLINE)
        old_capture = self.session.capture
        self.discovery.devices = []
        self.rescan_due()
        self.assertFalse(self.session.step())
        self.assertTrue(old_capture.closed)
        self.assertEqual(self.events[-1].reason, "device_disconnected")
        self.discovery.devices = [replace(self.camera, device_path="/dev/video5")]
        self.assertTrue(self.session.step())
        self.assertEqual(len(self.frames), 2)
        self.assertEqual(self.controller.state, CameraState.ONLINE)

    def test_new_serial_instance_on_the_same_path_closes_the_live_capture(self):
        # Issue #173 item 2: the live check compares the live instance, not
        # the device path. A serial camera re-enumerated on the same node
        # (a new instance marker) must close the old descriptor, even though
        # the old capture still returns frames and the serial still matches.
        live = replace(self.camera, instance_token=(1, 2, 3))
        self.discovery.devices = [live]
        self.assertTrue(self.session.step())
        self.assertEqual(self.controller.state, CameraState.ONLINE)
        old_capture = self.session.capture
        self.discovery.devices = [replace(live, instance_token=(4, 5, 6))]
        self.rescan_due()
        self.assertFalse(self.session.step())
        self.assertTrue(old_capture.closed)
        self.assertIsNone(self.session.capture)
        self.assertEqual(["video_capture_closed", "device_disconnected"],
                         [event.reason for event in self.events[-2:]])
        # The unique serial reconnects through the identity path on a new
        # descriptor.
        self.assertTrue(self.session.step())
        self.assertIsNot(self.session.capture, old_capture)
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
        self.rescan_due()
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


    def test_weak_live_binding_survives_metadata_refresh(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        self.controller.approve(weak, [weak])
        self.assertTrue(self.session.step())
        capture = self.session.capture
        refreshed = replace(weak, by_id=("synthetic-alias",), formats=("MJPG", "YUYV"))
        self.discovery.devices = [refreshed]
        for _ in range(3):
            # Each step is a due presence rescan (#122 suppresses the rest).
            self.rescan_due()
            self.assertTrue(self.session.step())
        self.assertIs(capture, self.session.capture)
        self.assertFalse(capture.closed)
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.assertFalse(self.controller.requires_approval)
        # The stored binding evidence is refreshed from the scan entry.
        self.assertEqual(refreshed, self.controller.bound)
        # An actual instance change still ends the weak binding and never
        # auto-binds the indistinguishable replacement.
        self.discovery.devices = [replace(refreshed, instance_token=(4, 5, 6))]
        self.rescan_due()
        self.assertFalse(self.session.step())
        self.assertTrue(capture.closed)
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)
        self.assertIsNone(self.session.capture)

    def test_metadata_refresh_during_open_verification_still_opens(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        refreshed = replace(weak, by_id=("synthetic-alias",))
        scans = iter([[weak], [refreshed]])
        self.discovery.scan = lambda: DiscoveryResult(tuple(next(scans, [refreshed])), 0)
        self.controller.approve(weak, [weak])
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)

    def test_ambiguous_serial_live_binding_survives_metadata_refresh(self):
        live = replace(self.camera, instance_token=(1, 2, 3))
        twin = replace(live, device_path="/dev/video1", instance_token=(1, 3, 4))
        self.discovery.devices = [live, twin]
        self.controller.approve(twin, self.discovery.devices)
        self.assertTrue(self.session.step())
        capture = self.session.capture
        self.discovery.devices = [live, replace(twin, formats=("MJPG",))]
        self.assertTrue(self.session.step())
        self.assertIs(capture, self.session.capture)
        self.assertEqual(twin.live_instance_key, self.controller.bound.live_instance_key)
        self.assertEqual(CameraState.ONLINE, self.controller.state)

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


class FrameProgressTests(unittest.TestCase):
    """A live capture that stops delivering frames is never reported online."""

    def setUp(self):
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial")
        self.discovery = CountingDiscovery([self.camera])
        self.events, self.frames, self.profiles = [], [], []
        self.controller = ReconnectController(UUID(int=1), self.camera, self.events.append)
        self.clock = FakeClock()
        self.instances = []
        self.session = self.make_session(VideoProfile(1920, 1080, 30, "MJPG"))

    def make_session(self, profile, **timing):
        def factory(candidate, profile, *, verify_identity):
            capture = SyntheticCapture(candidate, profile, verify_identity=verify_identity)
            self.instances.append(capture)
            return capture

        return CaptureSession(
            self.controller, self.discovery, profile, on_frame=self.frames.append,
            on_profile=self.profiles.append, capture_factory=factory, clock=self.clock,
            **timing,
        )

    def go_online(self):
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        return self.session.capture

    def test_short_poll_timeout_under_low_light_never_flaps_stalled(self):
        """poll 0.1 s while a dark scene delivers 8 fps (profile 30 fps).

        Deterministic replay of the supervisor loop: a step that returns
        False sleeps the retry delay (1.0 s) while the 0.25 s watchdog keeps
        checking; a step that returns True polls again at once.
        """
        clock = self.clock
        interval = 1 / 8

        class LowLight(SyntheticCapture):
            next_frame = None

            def read_frame(self, timeout):
                if self.next_frame is None:
                    self.next_frame = clock.now + interval
                wait = self.next_frame - clock.now
                if wait > timeout:
                    clock.advance(timeout)
                    raise FrameTimeout("synthetic dark-scene timeout")
                clock.advance(max(wait, 0))
                self.next_frame += interval
                return VideoFrame(b"synthetic", 0, 1.0)

        def factory(candidate, profile, *, verify_identity):
            capture = LowLight(candidate, profile, verify_identity=verify_identity)
            self.instances.append(capture)
            return capture

        session = CaptureSession(
            self.controller, self.discovery, VideoProfile(1920, 1080, 30, "MJPG"),
            on_frame=self.frames.append, on_profile=self.profiles.append,
            capture_factory=factory, clock=clock,
        )
        end = clock.now + 60
        while clock.now < end:
            if not session.step(timeout=0.1):
                for _ in range(4):
                    clock.advance(0.25)
                    session.check_frame_progress()
            session.check_frame_progress()
        reasons = [event.reason for event in self.events]
        self.assertNotIn("video_frame_stalled", reasons)
        self.assertNotIn("video_capture_failed", reasons)
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.assertGreater(len(self.frames), 400)

    def test_stall_degrades_without_teardown_and_recovers_on_next_frame(self):
        capture = self.go_online()
        capture.stalled = True
        self.clock.advance(self.session.frame_stall_seconds)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        # The descriptor (and with it any live weak binding) is kept open.
        self.assertIs(capture, self.session.capture)
        self.assertFalse(capture.closed)
        self.assertEqual(1, len(self.instances))
        self.assertEqual(1, len(self.frames))
        capture.stalled = False
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.assertEqual("video_capture_ready", self.events[-1].reason)
        self.assertEqual(1, len(self.instances))

    def test_read_waits_no_longer_than_the_stall_window(self):
        self.session = self.make_session(VideoProfile(1920, 1080, 30, "MJPG"),
                                         frame_stall_seconds=0.5)
        capture = self.go_online()
        capture.stalled = True
        self.assertTrue(self.session.step(timeout=1.0))
        self.assertLessEqual(capture.timeouts[-1], 0.5)

    def test_timeout_inside_the_window_stays_online(self):
        capture = self.go_online()
        capture.stalled = True
        self.clock.advance(self.session.frame_stall_seconds / 2)
        # A plain read timeout on an open capture: keep reading, no backoff.
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.assertFalse(capture.closed)

    def test_low_negotiated_frame_rate_widens_the_window(self):
        # A dark scene or a slow profile legitimately delivers frames far apart;
        # the window scales with the negotiated frame interval so it cannot flap.
        self.session = self.make_session(VideoProfile(640, 480, 2, "MJPG"))
        capture = self.go_online()
        capture.stalled = True
        self.clock.advance(3.0)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.clock.advance(2.0)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("video_frame_stalled", self.events[-1].reason)

    def test_prolonged_stall_closes_and_reopens_capture(self):
        capture = self.go_online()
        capture.stalled = True
        self.clock.advance(self.session.frame_stall_seconds)
        self.assertTrue(self.session.step())
        self.clock.advance(self.session.frame_stall_reopen_seconds)
        self.assertFalse(self.session.step())
        self.assertTrue(capture.closed)
        self.assertIsNone(self.session.capture)
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        self.assertEqual("video_capture_failed", self.events[-1].reason)
        self.assertTrue(self.session.step())
        self.assertEqual(2, len(self.instances))
        self.assertEqual(CameraState.ONLINE, self.controller.state)

    def test_first_frame_never_arriving_is_reported_stalled_not_online(self):
        def stalled_factory(candidate, profile, *, verify_identity):
            capture = SyntheticCapture(candidate, profile, verify_identity=verify_identity)
            capture.stalled = True
            self.instances.append(capture)
            return capture

        self.session.capture_factory = stalled_factory
        self.clock.advance(0)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.clock.advance(self.session.frame_stall_seconds)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        self.assertEqual([], self.frames)

    def test_watchdog_degrades_online_source_while_worker_is_blocked(self):
        capture = self.go_online()
        # The worker thread is blocked (e.g. in a kernel call) and cannot run
        # its own check; a second thread still sees no frame progress.
        self.assertFalse(self.session.check_frame_progress())
        self.clock.advance(self.session.frame_stall_seconds)
        checker = threading.Thread(target=self.session.check_frame_progress)
        checker.start()
        checker.join(5)
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        self.assertFalse(capture.closed)
        self.assertTrue(self.session.step())
        self.assertEqual(CameraState.ONLINE, self.controller.state)

    def test_hung_capture_teardown_never_leaves_the_source_online(self):
        capture = self.go_online()
        entered, release = threading.Event(), threading.Event()

        def blocking_close():
            # STREAMOFF/unmap/close hung in the kernel.
            entered.set()
            release.wait(5)
            capture.closed = True

        capture.close = blocking_close
        self.discovery.devices = []
        self.clock.advance(self.session.presence_scan_seconds)
        worker = threading.Thread(target=self.session.step)
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            self.assertEqual(CameraState.OFFLINE, self.controller.state)
            self.assertEqual("video_capture_closed", self.events[-1].reason)
            self.assertIsNone(self.controller.bound)
            self.assertFalse(self.session.stopped)
            self.clock.advance(60)
            self.assertFalse(self.session.check_frame_progress())
            self.assertEqual(CameraState.OFFLINE, self.controller.state)
        finally:
            release.set()
            worker.join(5)
        self.assertTrue(capture.closed)
        self.assertTrue(self.session.stopped)
        self.assertEqual("device_disconnected", self.events[-1].reason)

    def test_stall_is_reported_after_a_metadata_only_rescan(self):
        # #115 x #122: a due rescan that only refreshes mutable metadata keeps
        # the live capture, and the stall checks still match the refreshed
        # binding by live instance.
        capture = self.go_online()
        refreshed = replace(self.camera, by_id=("synthetic-alias",), formats=("MJPG", "YUYV"))
        self.discovery.devices = [refreshed]
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertTrue(self.session.step())
        self.assertEqual(refreshed, self.controller.bound)
        self.assertIs(capture, self.session.capture)
        capture.stalled = True
        self.clock.advance(self.session.frame_stall_seconds)
        self.assertTrue(self.session.check_frame_progress())
        self.assertEqual(CameraState.DEGRADED, self.controller.state)
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        self.assertTrue(self.session.step())
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        self.assertFalse(capture.closed)

    def test_watchdog_never_raises_a_closed_or_offline_source(self):
        self.go_online()
        self.session.close()
        self.clock.advance(60)
        self.assertFalse(self.session.check_frame_progress())
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        self.assertEqual("video_capture_closed", self.events[-1].reason)

    def test_watchdog_skips_when_controller_is_busy(self):
        self.go_online()
        self.clock.advance(self.session.frame_stall_seconds)
        with self.controller.lock:
            done = threading.Event()
            result = []
            thread = threading.Thread(
                target=lambda: (result.append(self.session.check_frame_progress()), done.set()))
            thread.start()
            self.assertTrue(done.wait(5))
        self.assertEqual([False], result)
        self.assertEqual(CameraState.ONLINE, self.controller.state)


    def test_watchdog_rechecks_progress_before_reporting_a_stall(self):
        capture = self.go_online()
        self.clock.advance(self.session.frame_stall_seconds)
        original = self.controller.frame_stalled

        def worker_delivers_first(*args, **kwargs):
            # The watchdog read an expired progress time, then the worker
            # delivered a frame and went online before the watchdog resumed.
            self.assertTrue(self.session.step())
            return original(*args, **kwargs)

        self.controller.frame_stalled = worker_delivers_first
        self.assertFalse(self.session.check_frame_progress())
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        self.assertEqual("video_capture_ready", self.events[-1].reason)
        self.assertFalse(capture.closed)

    def test_watchdog_enforces_the_reopen_deadline_while_the_worker_is_blocked(self):
        capture = self.go_online()
        self.clock.advance(self.session.frame_stall_seconds)
        self.assertTrue(self.session.check_frame_progress())
        self.assertEqual("video_frame_stalled", self.events[-1].reason)
        self.clock.advance(self.session.frame_stall_reopen_seconds)
        self.assertTrue(self.session.check_frame_progress())
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        self.assertEqual("video_capture_failed", self.events[-1].reason)
        # The blocked worker owns the descriptor; the watchdog never closes it.
        self.assertFalse(capture.closed)
        self.assertFalse(self.session.check_frame_progress())
        # When the worker returns, it tears down and reopens through the
        # identity path instead of resuming the old descriptor.
        self.assertFalse(self.session.step())
        self.assertTrue(capture.closed)
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        self.assertTrue(self.session.step())
        self.assertEqual(2, len(self.instances))
        self.assertEqual(CameraState.ONLINE, self.controller.state)

    def test_reopen_requested_during_a_blocked_presence_scan_skips_the_next_read(self):
        capture = self.go_online()
        reads = []
        read = capture.read_frame
        capture.read_frame = lambda timeout: (reads.append(timeout), read(timeout))[1]
        scan = self.discovery.scan

        def blocked_scan():
            # The watchdog runs while the worker is stuck in discovery.
            self.clock.advance(self.session.frame_stall_reopen_seconds)
            self.assertTrue(self.session.check_frame_progress())
            return scan()

        self.discovery.scan = blocked_scan
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertFalse(self.session.step())
        self.assertEqual([], reads)
        self.assertTrue(capture.closed)
        self.assertIsNone(self.session.capture)
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        self.assertEqual("video_capture_failed", self.events[-1].reason)

    def test_frame_returned_after_a_watchdog_reopen_is_not_reported_online(self):
        capture = self.go_online()
        read = capture.read_frame

        def blocked_read(timeout):
            # The watchdog runs while the worker is inside this read.
            self.clock.advance(self.session.frame_stall_reopen_seconds)
            self.assertTrue(self.session.check_frame_progress())
            return read(timeout)

        capture.read_frame = blocked_read
        self.clock.advance(0.5)
        self.assertFalse(self.session.step())
        self.assertTrue(capture.closed)
        self.assertEqual(CameraState.OFFLINE, self.controller.state)
        self.assertEqual("video_capture_failed", self.events[-1].reason)
        self.assertEqual(1, len(self.frames))


class PresenceScanTests(unittest.TestCase):
    """Live capture does not open every video node on each frame."""

    def setUp(self):
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial")
        self.discovery = CountingDiscovery([self.camera])
        self.events, self.frames = [], []
        self.controller = ReconnectController(UUID(int=1), self.camera, self.events.append)
        self.clock = FakeClock()
        self.session = CaptureSession(
            self.controller, self.discovery, VideoProfile(640, 480, 30, "MJPG"),
            on_frame=self.frames.append, on_profile=lambda _: None,
            capture_factory=SyntheticCapture, clock=self.clock,
        )

    def test_live_capture_rescans_at_a_bounded_rate(self):
        self.assertTrue(self.session.step())
        opened = self.discovery.scans
        for _ in range(30):
            self.clock.advance(1 / 30)
            self.assertTrue(self.session.step())
        # 30 frames within one presence interval need at most one more scan.
        self.assertLessEqual(self.discovery.scans - opened, 1)
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertTrue(self.session.step())
        self.assertLessEqual(self.discovery.scans - opened, 2)
        self.assertEqual(31 + 1, len(self.frames))

    def test_slow_presence_scan_does_not_rescan_after_every_frame(self):
        # Issue #122: a scan that outlasts the interval (USB re-enumeration
        # stalling open/ioctl) must count the interval from its completion.
        self.assertTrue(self.session.step())
        clock, discovery = self.clock, self.discovery
        slow = 2 * self.session.presence_scan_seconds

        class SlowDiscovery:
            def scan(self):
                result = discovery.scan()
                clock.advance(slow)
                return result

        self.session.discovery = SlowDiscovery()
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertTrue(self.session.step())
        after_slow_scan = self.discovery.scans
        for _ in range(10):
            self.clock.advance(1 / 30)
            self.assertTrue(self.session.step())
        self.assertEqual(after_slow_scan, self.discovery.scans)
        # The bounded rescan still happens once a full interval has elapsed.
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertTrue(self.session.step())
        self.assertEqual(after_slow_scan + 1, self.discovery.scans)
        self.assertEqual(CameraState.ONLINE, self.controller.state)

    def test_closed_capture_always_rescans_before_binding(self):
        self.assertTrue(self.session.step())
        self.session.close()
        before = self.discovery.scans
        self.assertTrue(self.session.step())
        self.assertGreater(self.discovery.scans, before)

    def test_incomplete_scan_does_not_tear_down_live_capture(self):
        self.assertTrue(self.session.step())
        capture = self.session.capture

        class FailingProbe:
            scans = 0

            def scan(self):
                return DiscoveryResult((), 1)

        self.session.discovery = FailingProbe()
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertTrue(self.session.step())
        self.assertIs(capture, self.session.capture)
        self.assertEqual(CameraState.ONLINE, self.controller.state)
        # A complete scan without the device is still a disconnect.
        self.session.discovery = Discovery([])
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertFalse(self.session.step())
        self.assertTrue(capture.closed)
        self.assertEqual("device_disconnected", self.events[-1].reason)

    def test_duplicate_serial_appearing_while_live_still_requires_owner(self):
        self.assertTrue(self.session.step())
        self.discovery.devices.append(replace(self.camera, device_path="/dev/video1"))
        self.clock.advance(self.session.presence_scan_seconds)
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)
        self.assertIsNone(self.session.capture)

    def test_weak_binding_is_never_rebound_after_a_stall_reopen(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.discovery.devices = [weak]
        self.controller.approve(weak, [weak])
        self.assertTrue(self.session.step())
        self.session.capture.stalled = True
        self.clock.advance(self.session.frame_stall_reopen_seconds)
        self.assertFalse(self.session.step())
        self.assertIsNone(self.session.capture)
        # Losing the descriptor ends the weak live binding: Owner reapproval.
        self.assertFalse(self.session.step())
        self.assertEqual(CameraState.MANUAL, self.controller.state)



if __name__ == "__main__":
    unittest.main()
