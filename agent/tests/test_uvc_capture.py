"""UVC capture adapter with synthetic frames, fake sysfs/udev trees and fake pipelines.

No camera, microphone or real media is used. Frames are generated JPEG-shaped
byte structures (marker segments around deterministic filler), never images of
people or rooms. Subprocess tests run the current Python as a synthetic source.
"""

import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import textwrap
import time
import unittest
from unittest import mock
from uuid import UUID

from media_capture_agent.health import SourceHealth
from media_capture_agent.runtime import Agent
from media_capture_agent.storage import MediaStore
from media_capture_agent.uvc_approvals import FILENAME, ApprovalStorageError, ApprovalStore
from media_capture_agent import uvc_capture
from media_capture_agent.uvc_capture import (CaptureCleanupError, CaptureLimits, CaptureRefused,
                                             UvcCapture, UvcSourceConfig)
from media_capture_agent.uvc_discovery import DiscoveryResult, LinuxDiscovery, VideoCapabilities
from media_capture_agent.uvc_identity import DeviceEvidence
from media_capture_agent.uvc_pipeline import (FrameError, FrameQueue, GStreamerLauncher,
                                              MjpegFrameParser, MjpegProfile, PipelineError,
                                              SubprocessLauncher, SubprocessPipeline,
                                              gstreamer_argv,
                                              minimal_environment, require_trusted_executable)
from tests.support import MockSession, settings


SOURCES = [UUID(f"00000000-0000-4000-8000-00000000001{index}") for index in range(5)]
PROFILE = MjpegProfile(640, 480, 15)


def segment(marker, payload):
    return bytes((0xFF, marker)) + (len(payload) + 2).to_bytes(2, "big") + payload


def synthetic_jpeg(index=0, *, entropy_bytes=64):
    """A structurally valid JPEG-shaped byte sequence with generated filler."""
    # APP1 payload deliberately contains FF D9: only structure ends a frame.
    app = segment(0xE1, b"synthetic\x00\xff\xd9" + bytes([index % 256]) * 4)
    header = segment(0xC0, bytes(15))
    scan = segment(0xDA, bytes(10))
    filler = bytes((index + offset) % 0xFE for offset in range(entropy_bytes))
    entropy = filler[:16] + b"\xff\x00" + filler[16:32] + b"\xff\xd0" + filler[32:]
    return b"\xff\xd8" + app + header + scan + entropy + b"\xff\xd9"


def evidence(number=0, *, serial="SYN-0001", vendor="1d6b", product="0102",
             formats=("MJPG", "YUYV"), token=None):
    return DeviceEvidence(f"/dev/video{number}", vendor, product, serial, "0",
                          (), f"devices/synthetic/usb1/1-{number}", formats,
                          os.makedev(81, number), token or (1, 100 + number, 1))


class FakeDiscovery:
    def __init__(self, *devices):
        self.devices = list(devices)
        self.failures = 0
        self.after = None  # Devices returned from the next scan onward.
        self.scans = 0

    def scan(self):
        self.scans += 1
        result = DiscoveryResult(tuple(self.devices), self.failures)
        if self.after is not None:
            self.devices, self.after = list(self.after), None
        return result


class FakePipeline:
    def __init__(self):
        self.chunks = queue.Queue()
        self.dead = False
        self.stop_result = True
        self.stops = 0
        self.stop_timeouts = []
        self.closed = False

    def feed(self, data):
        self.chunks.put(data)

    def end(self):
        self.chunks.put(b"")

    def read(self, size):
        data = self.chunks.get()
        if not data:
            self.dead = True
        return data

    def exited(self):
        return self.dead

    def stop(self, timeout):
        self.stops += 1
        self.stop_timeouts.append(timeout)
        if self.stop_result:
            self.dead = True
            self.chunks.put(b"")
        return self.stop_result

    def close(self):
        self.closed = True


class FakeLauncher:
    def __init__(self):
        self.pipelines = []
        self.fail = False
        self.descriptors = []

    def launch(self, device_fd, profile):
        if self.fail:
            raise PipelineError("synthetic launch failure")
        os.fstat(device_fd)  # The verified descriptor is still open at launch.
        self.descriptors.append(device_fd)
        pipeline = FakePipeline()
        self.pipelines.append(pipeline)
        return pipeline


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


class CaptureCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agent-uvc-")
        self.addCleanup(self.temporary.cleanup)
        self.settings = settings(Path(self.temporary.name))
        self.clock = Clock()
        self.launcher = FakeLauncher()
        self.limits = CaptureLimits(max_frame_bytes=4096, queue_frames=4, startup_timeout=5,
                                    stall_timeout=2, stop_timeout=1, backoff_initial=1,
                                    backoff_max=4)

    def capture(self, discovery, count=1, **kwargs):
        kwargs.setdefault("launcher", self.launcher)
        kwargs.setdefault("open_device",
                          lambda _candidate: os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC))
        capture = UvcCapture(
            self.settings, [UvcSourceConfig(SOURCES[index], PROFILE) for index in range(count)],
            discovery=discovery, limits=self.limits, clock=self.clock, **kwargs)
        self.addCleanup(self._close, capture)
        return capture

    @staticmethod
    def _close(capture):
        try:
            capture.close()
        except CaptureCleanupError:
            pass

    def state(self, capture, index=0):
        health = capture.poll()[index]
        return health.state, health.reason

    def stream(self, capture, pipeline, count=1, index=0):
        queue_ = capture.frames(SOURCES[index])
        before = capture._sources[SOURCES[index]].active.frames
        for number in range(count):
            pipeline.feed(synthetic_jpeg(number))
        self.assertTrue(wait_for(lambda: capture._sources[SOURCES[index]].active.frames
                                 >= before + count))
        return queue_

    def approved_online(self, discovery, device, count=1):
        capture = self.capture(discovery, count)
        self.assertEqual(self.state(capture), ("manual_intervention_required",
                                               "owner_approval_required"))
        capture.approve(SOURCES[0], device)
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        pipeline = self.launcher.pipelines[-1]
        self.stream(capture, pipeline)
        self.assertEqual(self.state(capture), ("online", "video_ready"))
        return capture, pipeline


class ParserTests(unittest.TestCase):
    def test_frames_split_on_structure_across_any_chunking(self):
        frames = [synthetic_jpeg(index) for index in range(3)]
        stream = frames[0] + b"\x00\x00" + frames[1] + frames[2]
        for size in (1, 2, 7, 64, len(stream)):
            parser, output = MjpegFrameParser(4096), []
            for offset in range(0, len(stream), size):
                output.extend(parser.feed(stream[offset:offset + size]))
            with self.subTest(size=size):
                self.assertEqual(output, frames)
                self.assertFalse(parser.partial)

    def test_malformed_or_unbounded_streams_fail_closed(self):
        cases = {
            "oversize": synthetic_jpeg(entropy_bytes=8192),
            "garbage": b"\x01" * 5000,
            "no_scan": b"\xff\xd8" + segment(0xC0, bytes(15)) + b"\xff\xd9",
            "short_segment": b"\xff\xd8\xff\xe0\x00\x01",
            "nested_start": b"\xff\xd8\xff\xd8",
            "not_marker": b"\xff\xd8\x12\x34",
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(FrameError):
                MjpegFrameParser(4096).feed(data)

    def test_unfinished_frame_is_retained_within_bound(self):
        parser = MjpegFrameParser(4096)
        self.assertEqual(parser.feed(synthetic_jpeg()[:-1]), [])
        self.assertTrue(parser.partial)

    def test_queue_is_bounded_and_counts_drops(self):
        frames = FrameQueue(2, clock=lambda: 5.0)
        for index in range(5):
            frames.put(index)
        self.assertEqual(len(frames), 2)
        self.assertEqual((frames.dropped, frames.last_drop), (3, 5.0))
        self.assertEqual([frames.get(0), frames.get(0), frames.get(0)], [3, 4, None])
        frames.close()
        frames.put(9)
        self.assertIsNone(frames.get(0))

    def test_profile_bounds(self):
        for arguments in ((8, 480, 15), (640, 480, 0), (640, 480, 1000, 1), (640.0, 480, 15)):
            with self.subTest(arguments), self.assertRaises(ValueError):
                MjpegProfile(*arguments)


class PipelineCommandTests(unittest.TestCase):
    def test_gstreamer_command_is_video_only_and_uses_verified_descriptor(self):
        argv = gstreamer_argv("/usr/bin/gst-launch-1.0", 7, PROFILE)
        self.assertEqual(argv[1:], [
            "-q", "v4l2src", "device=/proc/self/fd/7", "do-timestamp=true", "!",
            "image/jpeg,width=640,height=480,framerate=15/1", "!", "fdsink", "fd=1", "sync=false"])
        text = " ".join(argv)
        for forbidden in ("/dev/video", "audio", "alsa", "pulse", "location", "host", "port"):
            self.assertNotIn(forbidden, text)
        # Exactly one source and one sink element: nothing else is expressible.
        self.assertEqual([item for item in argv if item.endswith(("src", "sink"))],
                         ["v4l2src", "fdsink"])
        with self.assertRaises(PipelineError):
            gstreamer_argv("/usr/bin/gst-launch-1.0", 7, object())

    def test_environment_never_inherits_secrets_or_plugin_paths(self):
        os.environ["SERVERSENTINEL_SYNTHETIC_SECRET"] = "sentinel-value"
        self.addCleanup(os.environ.pop, "SERVERSENTINEL_SYNTHETIC_SECRET", None)
        environment = SubprocessLauncher(lambda fd, profile: ["x"]).environment
        self.assertEqual(environment, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        for extra in ({"LD_PRELOAD": "x"}, {"GST_X": "a\0b"}):
            with self.subTest(extra), self.assertRaises(ValueError):
                minimal_environment(extra)

    def test_untrusted_or_relative_executables_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "gst-launch-1.0"
            path.write_text("#!/bin/sh\n")
            path.chmod(0o755)
            for candidate in (path, Path("gst-launch-1.0"), Path(temporary) / "missing"):
                with self.subTest(candidate=candidate.name), self.assertRaises(PipelineError):
                    require_trusted_executable(candidate)
            with self.assertRaises(PipelineError):
                GStreamerLauncher(path)

    def test_launcher_rejects_invalid_descriptor_and_spawn_errors(self):
        def refuse(*_args, **_kwargs):
            raise OSError("synthetic private detail /dev/video3")
        launcher = SubprocessLauncher(lambda fd, profile: ["x"], popen=refuse)
        with self.assertRaises(PipelineError) as raised:
            launcher.launch(9, PROFILE)
        self.assertNotIn("/dev/video", str(raised.exception))
        with self.assertRaises(PipelineError):
            launcher.launch(1, PROFILE)


class DiscoveryTreeTests(unittest.TestCase):
    """A fake sysfs/udev tree; the ioctl probe is injected."""

    def build(self, root, cameras):
        sys_root, dev_root = root / "sys", root / "dev"
        (sys_root / "class/video4linux").mkdir(parents=True)
        (dev_root / "v4l/by-id").mkdir(parents=True)
        for number, serial in cameras:
            usb = sys_root / f"devices/pci0000:00/usb1/1-{number + 1}"
            node = usb / f"1-{number + 1}:1.0/video4linux/video{number}"
            node.mkdir(parents=True)
            (usb / "idVendor").write_text("1d6b\n")
            (usb / "idProduct").write_text("0102\n")
            if serial is not None:
                (usb / "serial").write_text(serial + "\n")
            (node / "dev").write_text(f"81:{number}\n")
            (node / "index").write_text("0\n")
            (node / "device").symlink_to(f"../../../1-{number + 1}:1.0")
            (sys_root / f"class/video4linux/video{number}").symlink_to(node)
            (dev_root / f"video{number}").touch()
            name = f"usb-synthetic_{serial or 'none'}_{number}-video-index0"
            (dev_root / "v4l/by-id" / name).symlink_to(f"../../video{number}")
        return sys_root, dev_root

    def test_serial_by_id_topology_and_ambiguous_non_serial(self):
        with tempfile.TemporaryDirectory() as temporary:
            sys_root, dev_root = self.build(Path(temporary), [(0, "SYN-A"), (1, None), (2, None)])
            def probe(path, device):
                return VideoCapabilities(1, 0x04000001, ("MJPG",))
            result = LinuxDiscovery(sys_root=sys_root, dev_root=dev_root, probe=probe).scan()
            self.assertEqual(result.failures, 0)
            devices = {Path(device.device_path).name: device for device in result.devices}
            self.assertEqual(devices["video0"].serial, "SYN-A")
            self.assertIsNotNone(devices["video0"].strong_key)
            self.assertEqual(devices["video0"].by_id, ("usb-synthetic_SYN-A_0-video-index0",))
            self.assertEqual(devices["video0"].device_number, os.makedev(81, 0))
            self.assertIsNone(devices["video1"].strong_key)
            self.assertEqual(devices["video1"].model_key, devices["video2"].model_key)
            self.assertNotEqual(devices["video1"].topology, devices["video2"].topology)
            # Evidence repr never exposes serial/path/topology.
            self.assertNotIn("SYN-A", repr(devices["video0"]))

    def test_probe_failures_are_counted_not_hidden(self):
        with tempfile.TemporaryDirectory() as temporary:
            sys_root, dev_root = self.build(Path(temporary), [(0, "SYN-A")])

            def probe(path, device):
                raise OSError("synthetic")
            result = LinuxDiscovery(sys_root=sys_root, dev_root=dev_root, probe=probe).scan()
            self.assertEqual((result.devices, result.failures), ((), 1))


class CaptureTests(CaptureCase):
    def test_approval_frames_online_and_unplug_keeps_agent_online(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        frame = capture.frames(SOURCES[0]).get(1)
        self.assertEqual((frame.data, frame.generation, frame.sequence), (synthetic_jpeg(0), 1, 1))
        self.assertNotIn("SYN", repr(frame))
        store = MediaStore(self.settings, stable_device=lambda _expected: True)
        agent = Agent(self.settings, store, capture=capture, session=MockSession())
        self.addCleanup(store.close)
        heartbeat = agent.tick()
        self.assertEqual(heartbeat["node_state"], "online")
        self.assertEqual(heartbeat["sources"][0]["state"], "online")
        discovery.devices = []
        heartbeat = agent.tick()
        self.assertEqual(heartbeat["node_state"], "online")
        self.assertEqual((heartbeat["sources"][0]["state"], heartbeat["sources"][0]["reason"]),
                         ("offline", "camera_missing"))
        self.assertTrue(pipeline.dead and pipeline.closed)
        text = json.dumps(heartbeat)
        for private in ("SYN-0001", "/dev/video", "devices/synthetic", "1d6b"):
            self.assertNotIn(private, text)
        # Serial-backed identity reconnects automatically and must stream again.
        discovery.devices = [evidence(3, token=(1, 400, 2))]
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        self.assertEqual(len(self.launcher.pipelines), 2)
        self.stream(capture, self.launcher.pipelines[-1])
        self.assertEqual(self.state(capture), ("online", "video_ready"))

    def test_descriptor_is_closed_after_launch_and_on_failure(self):
        opened = []

        def opener(_candidate):
            descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            opened.append(descriptor)
            return descriptor
        device = evidence()
        capture = self.capture(FakeDiscovery(device))
        capture.open_device = opener
        capture.approve(SOURCES[0], device)
        capture.poll()
        self.launcher.fail = True
        self.launcher.pipelines[-1].end()
        self.assertTrue(wait_for(lambda: capture._sources[SOURCES[0]].active.eof))
        capture.poll()
        self.clock.now += 10
        capture.poll()
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_non_serial_camera_never_rebinds_without_owner(self):
        device = evidence(serial=None)
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        pipeline.end()  # Crash: the live weak binding ends with the descriptor.
        self.assertTrue(wait_for(lambda: capture._sources[SOURCES[0]].active.eof))
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.clock.now += 10
        self.assertEqual(self.state(capture), ("manual_intervention_required", "identity_ambiguous"))
        self.assertEqual(len(self.launcher.pipelines), 1)

    def test_identical_non_serial_cameras_are_not_bound(self):
        first, second = evidence(0, serial=None), evidence(1, serial=None)
        capture = self.capture(FakeDiscovery(first, second))
        capture.approve(SOURCES[0], first)
        capture._sources[SOURCES[0]].controller.capture_closed()  # Simulated restart of binding.
        self.assertEqual(self.state(capture), ("manual_intervention_required", "identity_ambiguous"))
        self.assertEqual(self.launcher.pipelines, [])

    def test_duplicate_serial_latch_survives_clean_restart(self):
        device = evidence(0)
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        discovery.devices = [device, evidence(1, token=(1, 900, 1))]
        pipeline.end()
        self.assertTrue(wait_for(lambda: capture._sources[SOURCES[0]].active.eof))
        capture.poll()
        self.clock.now += 10
        self.assertEqual(self.state(capture), ("manual_intervention_required", "identity_ambiguous"))
        capture.close()
        discovery.devices = [device]  # The duplicate vanished before restart.
        restarted = self.capture(discovery)
        self.assertEqual(self.state(restarted)[0], "manual_intervention_required")
        restarted.approve(SOURCES[0], device)
        restarted._sources[SOURCES[0]].controller.capture_closed()
        # Even after re-approval the duplicated serial is never auto-reconnected.
        restarted._teardown(restarted._sources[SOURCES[0]])
        self.assertEqual(self.state(restarted)[0], "manual_intervention_required")

    def test_clean_restart_reconnects_serial_but_unclean_requires_owner(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, _pipeline = self.approved_online(discovery, device)
        capture.close()
        restarted = self.capture(discovery)
        self.assertEqual(self.state(restarted), ("degraded", "capture_starting"))
        # No close(): simulate a crash, the armed marker persists.
        restarted._teardown(restarted._sources[SOURCES[0]])
        restarted._closed = True
        restarted.store.close()
        crashed = self.capture(discovery)
        self.assertEqual(self.state(crashed), ("manual_intervention_required",
                                               "owner_approval_required"))

    def test_incomplete_discovery_never_binds(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture = self.capture(discovery)
        capture.approve(SOURCES[0], device)
        capture._sources[SOURCES[0]].controller.capture_closed()
        discovery.failures = 1
        self.assertEqual(self.state(capture), ("offline", "discovery_failed"))
        self.assertEqual(self.launcher.pipelines, [])
        with self.assertRaises(CaptureRefused):
            capture.approve(SOURCES[0], device)

    def test_live_capture_survives_unrelated_discovery_failure(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        discovery.failures = 1
        self.stream(capture, pipeline)
        self.assertEqual(self.state(capture), ("online", "video_ready"))
        discovery.devices = []
        self.assertEqual(self.state(capture), ("offline", "discovery_failed"))
        self.assertTrue(pipeline.dead)

    def test_identity_change_after_open_prevents_launch(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture = self.capture(discovery)
        capture.approve(SOURCES[0], device)
        discovery.after = [evidence(0, token=(1, 100, 99))]  # Replugged during open.
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(self.launcher.pipelines, [])

    def test_stall_startup_timeout_and_malformed_stream_retry_with_backoff(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        self.clock.now += 3  # Stall beyond stall_timeout.
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertTrue(pipeline.dead)
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(len(self.launcher.pipelines), 1)  # Backoff honoured.
        self.clock.now += 1
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        self.clock.now += 6  # No first frame within startup_timeout.
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.clock.now += 1.5
        capture.poll()
        self.assertEqual(len(self.launcher.pipelines), 2)  # Doubled backoff.
        self.clock.now += 0.6
        capture.poll()
        self.assertEqual(len(self.launcher.pipelines), 3)
        self.launcher.pipelines[-1].feed(b"\xff\xd8\x12\x34")
        self.assertTrue(wait_for(lambda: capture._sources[SOURCES[0]].active.error))
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))

    def test_retry_backoff_starts_after_slow_failed_open(self):
        device = evidence()
        opens = []

        def slow_failing_open(_candidate):
            opens.append(self.clock.now)
            self.clock.now += 2  # Driver error after longer than the backoff.
            raise OSError("synthetic slow open failure")

        capture = self.capture(FakeDiscovery(device), open_device=slow_failing_open)
        capture.approve(SOURCES[0], device)
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(len(opens), 1)
        # No clock advance: the 1s backoff counts from the end of the failure.
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(len(opens), 1)
        self.clock.now += 1
        capture.poll()
        self.assertEqual(len(opens), 2)
        # Doubled backoff (2s) again counts from after the slow failure.
        self.clock.now += 1.5
        capture.poll()
        self.assertEqual(len(opens), 2)

    def test_retry_backoff_starts_after_slow_teardown(self):
        device = evidence()
        capture, pipeline = self.approved_online(FakeDiscovery(device), device)
        original_stop = pipeline.stop

        def slow_stop(timeout):
            self.clock.now += 2  # Teardown longer than the backoff.
            return original_stop(timeout)

        pipeline.stop = slow_stop
        self.clock.now += 3  # Stall beyond stall_timeout.
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(len(self.launcher.pipelines), 1)
        self.clock.now += 1
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        self.assertEqual(len(self.launcher.pipelines), 2)

    def test_stall_is_judged_after_another_sources_slow_teardown(self):
        devices = [evidence(index, serial=f"SYN-{index}") for index in range(2)]
        discovery = FakeDiscovery(*devices)
        capture = self.capture(discovery, count=2)
        for index, device in enumerate(devices):
            capture.approve(SOURCES[index], device)
        capture.poll()
        for index in range(2):
            self.stream(capture, self.launcher.pipelines[index], index=index)
        self.assertEqual([item.state for item in capture.poll()], ["online"] * 2)
        first = self.launcher.pipelines[0]
        original_stop = first.stop

        def slow_stop(timeout):
            self.clock.now += 1.5  # Camera 0's bounded teardown takes time.
            return original_stop(timeout)

        first.stop = slow_stop
        self.clock.now += 1  # Camera 1's last frame is still inside stall_timeout.
        discovery.devices = devices[1:]
        health = capture.poll()
        # Camera 1 produced nothing for 2.5s > stall_timeout by the heartbeat.
        self.assertEqual((health[1].state, health[1].reason), ("offline", "capture_failed"))

    def test_startup_timeout_counts_from_launch_not_before_slow_open(self):
        device = evidence()

        def slow_open(_candidate):
            self.clock.now += 6  # Longer than startup_timeout, then succeeds.
            return os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)

        capture = self.capture(FakeDiscovery(device), open_device=slow_open)
        capture.approve(SOURCES[0], device)
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        self.assertEqual(len(self.launcher.pipelines), 1)
        self.clock.now += 5.5
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))

    def test_launch_failure_and_unsupported_format_are_visible(self):
        device = evidence()
        capture = self.capture(FakeDiscovery(device))
        self.launcher.fail = True
        capture.approve(SOURCES[0], device)
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))  # Backoff.
        capture.close()
        other = evidence(1, serial="SYN-0002", formats=("YUYV",))
        unsupported = self.capture(FakeDiscovery(other))
        unsupported.approve(SOURCES[0], other)
        self.assertEqual(self.state(unsupported), ("offline", "capture_unsupported"))
        self.clock.now += 10
        self.assertEqual(self.state(unsupported), ("offline", "capture_unsupported"))
        self.assertEqual(len(self.launcher.pipelines), 0)

    def test_consumer_backpressure_is_degraded_not_healthy(self):
        device = evidence()
        capture, pipeline = self.approved_online(FakeDiscovery(device), device)
        self.stream(capture, pipeline, count=6)
        self.assertEqual(len(capture.frames(SOURCES[0])), 4)
        self.assertEqual(self.state(capture), ("degraded", "capture_overloaded"))
        # A consumer drains the queue; recovery only after a drop-free window.
        while capture.frames(SOURCES[0]).get(0) is not None:
            pass
        self.clock.now += 1.5
        self.stream(capture, pipeline)
        self.assertEqual(self.state(capture), ("degraded", "capture_overloaded"))
        self.clock.now += 1.5
        self.stream(capture, pipeline)
        self.assertEqual(self.state(capture), ("online", "video_ready"))

    def test_drops_between_slow_polls_are_reported_before_recovery(self):
        device = evidence()
        capture, pipeline = self.approved_online(FakeDiscovery(device), device)
        self.stream(capture, pipeline, count=6)
        while capture.frames(SOURCES[0]).get(0) is not None:
            pass
        # Poll interval longer than stall_timeout: the drop burst is already
        # outside the time window but was never reported.
        self.clock.now += 10
        self.stream(capture, pipeline)
        self.assertEqual(self.state(capture), ("degraded", "capture_overloaded"))
        # Reported once; with no new drops the source may recover.
        self.clock.now += 1
        self.stream(capture, pipeline)
        self.assertEqual(self.state(capture), ("online", "video_ready"))
        self.assertEqual(capture.frames(SOURCES[0]).drop_stats()[0], 3)

    def test_hung_discovery_never_blocks_poll_or_grows_threads(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        self.limits = CaptureLimits(max_frame_bytes=4096, queue_frames=4, startup_timeout=5,
                                    stall_timeout=2, stop_timeout=1, backoff_initial=1,
                                    backoff_max=4, device_timeout=0.2)
        capture, pipeline = self.approved_online(discovery, device)
        release = threading.Event()
        original = discovery.scan

        def hung_scan():
            release.wait(10)  # A V4L2 ioctl blocked by a faulty driver.
            return original()

        discovery.scan = hung_scan
        self.addCleanup(release.set)
        scans = discovery.scans
        started = time.monotonic()
        self.assertEqual(self.state(capture), ("offline", "discovery_failed"))
        # Still blocked: fails at once without starting another worker.
        self.assertEqual(self.state(capture), ("offline", "discovery_failed"))
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(discovery.scans, scans)
        self.assertEqual(len([thread for thread in threading.enumerate()
                              if thread.name == "media-capture-agent-uvc-discovery"]), 1)
        discovery.scan = original
        release.set()
        self.assertTrue(wait_for(lambda: self.state(capture) == ("degraded",
                                                                 "capture_starting")))
        self.assertEqual(len(self.launcher.pipelines), 2)

    def test_hung_device_open_fails_source_and_closes_late_descriptor(self):
        self.limits = CaptureLimits(max_frame_bytes=4096, queue_frames=4, startup_timeout=5,
                                    stall_timeout=2, stop_timeout=1, backoff_initial=1,
                                    backoff_max=4, device_timeout=0.2)
        release = threading.Event()
        self.addCleanup(release.set)
        opened, closed = [], []

        def hung_open(_candidate):
            release.wait(10)
            descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            opened.append(descriptor)
            return descriptor

        def close_device(descriptor):
            closed.append(descriptor)
            os.close(descriptor)

        device = evidence()
        capture = self.capture(FakeDiscovery(device), open_device=hung_open,
                               close_device=close_device)
        capture.poll()
        started = time.monotonic()
        capture.approve(SOURCES[0], device)
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(self.launcher.pipelines, [])
        release.set()
        # The descriptor that arrives after the bound is closed, never launched.
        self.assertTrue(wait_for(lambda: opened and closed == opened))
        self.assertEqual(self.launcher.pipelines, [])

    def short_device_limits(self, device_timeout):
        self.limits = CaptureLimits(max_frame_bytes=4096, queue_frames=4, startup_timeout=5,
                                    stall_timeout=2, stop_timeout=1, backoff_initial=1,
                                    backoff_max=4, device_timeout=device_timeout)

    def four_approved(self, **kwargs):
        devices = [evidence(index, serial=f"SYN-{index}") for index in range(4)]
        discovery = FakeDiscovery(*devices)
        capture = self.capture(discovery, count=4, **kwargs)
        for index, device in enumerate(devices):
            capture.approve(SOURCES[index], device)
        return capture, discovery, devices

    def test_hung_opens_of_several_sources_share_one_device_bound(self):
        self.short_device_limits(0.5)
        release = threading.Event()
        self.addCleanup(release.set)

        def hung_open(_candidate):
            release.wait(10)
            return os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)

        capture, _discovery, _devices = self.four_approved(open_device=hung_open)
        started = time.monotonic()
        health = capture.poll()
        # Old behavior: 4 x device_timeout before the heartbeat.
        self.assertLess(time.monotonic() - started, 1.2)
        self.assertEqual(self.launcher.pipelines, [])
        self.assertNotIn("online", [item.state for item in health])
        release.set()

        def later_tick():
            self.clock.now += 100  # Past any bounded backoff.
            capture.poll()
            return len(self.launcher.pipelines) == 4

        # Once the driver recovers, every source launches on later ticks.
        self.assertTrue(wait_for(later_tick))

    def test_hung_descriptor_close_never_blocks_poll(self):
        self.short_device_limits(0.2)
        release = threading.Event()
        self.addCleanup(release.set)
        closed = []

        def hung_close(descriptor):
            release.wait(10)  # A driver release callback that never returns.
            closed.append(descriptor)
            os.close(descriptor)

        device = evidence()
        capture = self.capture(FakeDiscovery(device), close_device=hung_close)
        capture.poll()
        capture.approve(SOURCES[0], device)
        started = time.monotonic()
        # Old behavior: the timed-out close counted as done ("capture_starting").
        self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(len(self.launcher.pipelines), 1)
        self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
        with self.assertRaises(CaptureRefused):
            capture.approve(SOURCES[0], device)
        release.set()
        self.assertTrue(wait_for(lambda: len(closed) == 1))
        self.assertTrue(wait_for(lambda: self.state(capture) == ("degraded",
                                                                 "capture_starting")))

    def test_shutdown_during_timed_out_close_keeps_recovery_marker(self):
        self.short_device_limits(0.2)
        release = threading.Event()
        self.addCleanup(release.set)

        def hung_close(descriptor):
            release.wait(10)
            os.close(descriptor)

        device = evidence(serial="SYN-CLOSE")
        discovery = FakeDiscovery(device)
        capture = self.capture(discovery, close_device=hung_close)
        capture.poll()
        capture.approve(SOURCES[0], device)
        capture.poll()
        started = time.monotonic()
        # Old behavior: close() returned cleanly and disarmed the marker.
        with self.assertRaises(CaptureCleanupError):
            capture.close()
        self.assertLess(time.monotonic() - started, 2.0)
        release.set()
        restarted = self.capture(discovery)
        self.assertEqual(self.state(restarted), ("manual_intervention_required",
                                                 "owner_approval_required"))

    def test_shutdown_during_hung_open_keeps_recovery_marker(self):
        self.short_device_limits(0.2)
        release = threading.Event()
        self.addCleanup(release.set)

        def hung_open(_candidate):
            release.wait(10)
            return os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)

        device = evidence(serial="SYN-OPEN")
        discovery = FakeDiscovery(device)
        capture = self.capture(discovery, open_device=hung_open)
        capture.poll()
        capture.approve(SOURCES[0], device)
        self.assertEqual(self.state(capture), ("offline", "capture_failed"))
        # The late descriptor would still be released in the worker.
        with self.assertRaises(CaptureCleanupError):
            capture.close()
        release.set()
        restarted = self.capture(discovery)
        self.assertEqual(self.state(restarted), ("manual_intervention_required",
                                                 "owner_approval_required"))

    def test_close_worker_exhaustion_is_a_source_cleanup_failure(self):
        closed = []

        def close_device(descriptor):
            closed.append(descriptor)
            os.close(descriptor)

        device = evidence()
        discovery = FakeDiscovery(device)
        capture = self.capture(discovery, close_device=close_device)
        capture.poll()
        capture.approve(SOURCES[0], device)
        original_start = threading.Thread.start
        device_starts = []
        exhausted = [True]

        def start(thread):
            if thread.name == "media-capture-agent-uvc-device":
                device_starts.append(thread)
                # The open worker starts; every close worker hits exhaustion.
                if len(device_starts) > 1 and exhausted[0]:
                    raise RuntimeError("can't start new thread")
            return original_start(thread)

        with mock.patch.object(threading.Thread, "start", start):
            # Old behavior: the unguarded fallback start raised out of poll().
            self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
            self.assertEqual(closed, [])  # Never closed on the tick thread.
            with self.assertRaises(CaptureRefused):
                capture.approve(SOURCES[0], device)
            self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
            exhausted[0] = False
            capture.poll()
        # The retained descriptor is closed by a bounded worker once one starts.
        self.assertTrue(wait_for(lambda: len(closed) == 1))
        self.assertEqual(closed, self.launcher.descriptors)

    def test_teardowns_during_launch_share_the_poll_stop_bound(self):
        capture, _discovery, _devices = self.four_approved()

        def hanging_stop(pipeline):
            def stop(timeout):
                pipeline.stop_timeouts.append(timeout)
                time.sleep(timeout)
                return False
            return stop

        original_launch = self.launcher.launch

        def launch(device_fd, profile):
            pipeline = original_launch(device_fd, profile)
            pipeline.stop = hanging_stop(pipeline)
            return pipeline

        self.launcher.launch = launch
        original_init = uvc_capture._Active.__init__

        def init(active, *args):
            original_init(active, *args)
            # Reader thread cannot start (e.g. thread/resource exhaustion).
            active.thread = mock.Mock(ident=None, **{"start.side_effect": RuntimeError,
                                                     "is_alive.return_value": False})

        with mock.patch.object(uvc_capture._Active, "__init__", init):
            started = time.monotonic()
            health = capture.poll()
            elapsed = time.monotonic() - started
        self.assertEqual(len(self.launcher.pipelines), 4)
        self.assertEqual([item.reason for item in health], ["capture_cleanup_failed"] * 4)
        # Old behavior: 4 x stop_timeout after the shared deadline was cleared.
        self.assertLess(elapsed, 1.8 * self.limits.stop_timeout)
        for pipeline in self.launcher.pipelines:
            pipeline.stop_result = True
            del pipeline.stop
            pipeline.stop(0)

    def test_device_timeout_bound_is_validated(self):
        for value in (0, -1, 61, "2"):
            with self.assertRaises(ValueError):
                CaptureLimits(device_timeout=value)

    def test_unreapable_pipeline_blocks_relaunch_and_keeps_recovery_marker(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        pipeline.stop_result = False
        discovery.devices = []
        self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
        discovery.devices = [device]
        self.clock.now += 100
        self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
        self.assertEqual(len(self.launcher.pipelines), 1)
        with self.assertRaises(CaptureCleanupError):
            capture.close()
        pipeline.stop_result = True
        pipeline.stop(0)
        restarted = self.capture(discovery)
        self.assertEqual(self.state(restarted), ("manual_intervention_required",
                                                 "owner_approval_required"))

    def test_stuck_pipeline_retry_does_not_stall_every_poll(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        pipeline.stop_result = False
        discovery.devices = []
        capture.poll()
        # The first teardown gets (what remains of) the full per-poll bound.
        self.assertEqual(len(pipeline.stop_timeouts), 1)
        self.assertAlmostEqual(pipeline.stop_timeouts[0], self.limits.stop_timeout, delta=0.1)
        started = time.monotonic()
        for _ in range(3):
            self.assertEqual(self.state(capture), ("offline", "capture_cleanup_failed"))
        # Later attempts re-signal without waiting the full bound each poll.
        self.assertLess(time.monotonic() - started, self.limits.stop_timeout)
        self.assertEqual(pipeline.stop_timeouts[1:], [0.0] * 3)
        with self.assertRaises(CaptureCleanupError):
            capture.close()
        # Shutdown still grants the stuck pipeline one more full bound.
        self.assertEqual(pipeline.stop_timeouts[-1], self.limits.stop_timeout)

    def test_simultaneous_stuck_teardowns_share_one_stop_bound(self):
        devices = [evidence(index, serial=f"SYN-{index}") for index in range(4)]
        discovery = FakeDiscovery(*devices)
        capture = self.capture(discovery, count=4)
        for index, device in enumerate(devices):
            capture.approve(SOURCES[index], device)
        capture.poll()
        for index in range(4):
            self.stream(capture, self.launcher.pipelines[index], index=index)
        self.assertEqual([item.state for item in capture.poll()], ["online"] * 4)

        def hanging_stop(pipeline):
            def stop(timeout):
                pipeline.stop_timeouts.append(timeout)
                time.sleep(timeout)  # A D-state process never exits.
                return False
            return stop

        for pipeline in self.launcher.pipelines:
            pipeline.stop = hanging_stop(pipeline)
        discovery.devices = []  # E.g. the shared USB hub disappears.
        started = time.monotonic()
        health = capture.poll()
        elapsed = time.monotonic() - started
        self.assertEqual([(item.state, item.reason) for item in health],
                         [("offline", "capture_cleanup_failed")] * 4)
        # Old behavior: 4 x (stop + join) = 8 x stop_timeout before the heartbeat.
        self.assertLess(elapsed, 1.8 * self.limits.stop_timeout)
        for pipeline in self.launcher.pipelines:
            pipeline.stop_result = True
            del pipeline.stop
            pipeline.stop(0)

    def test_stuck_pipeline_recovers_when_finally_reaped(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture, pipeline = self.approved_online(discovery, device)
        pipeline.stop_result = False
        discovery.devices = []
        capture.poll()
        pipeline.stop_result = True
        discovery.devices = [device]
        # A non-waiting retry may observe the reader just before it exits.
        self.assertTrue(wait_for(lambda: self.state(capture) == ("degraded", "capture_starting")))
        self.assertTrue(pipeline.closed)
        self.assertEqual(len(self.launcher.pipelines), 2)

    def test_two_sources_resolving_to_one_camera_require_owner(self):
        device = evidence()
        discovery = FakeDiscovery(device)
        capture = self.capture(discovery, count=2)
        capture.approve(SOURCES[0], device)
        capture.poll()
        with self.assertRaises(CaptureRefused):
            capture.approve(SOURCES[1], device)
        # Force the conflicting durable approval directly (e.g. stale state).
        controller = capture._sources[SOURCES[1]].controller
        controller.approve(device, (device,))
        health = capture.poll()
        self.assertEqual([item.state for item in health], ["manual_intervention_required"] * 2)
        self.assertTrue(all(pipeline.dead for pipeline in self.launcher.pipelines))

    def test_one_to_four_independent_sources(self):
        devices = [evidence(index, serial=f"SYN-{index}") for index in range(4)]
        discovery = FakeDiscovery(*devices)
        capture = self.capture(discovery, count=4)
        for index, device in enumerate(devices):
            capture.approve(SOURCES[index], device)
        capture.poll()
        for index in range(4):
            self.stream(capture, self.launcher.pipelines[index], index=index)
        self.assertEqual([item.state for item in capture.poll()], ["online"] * 4)
        discovery.devices = devices[1:]
        health = capture.poll()
        self.assertEqual([(item.state, item.reason) for item in health],
                         [("offline", "camera_missing")] + [("online", "video_ready")] * 3)
        with self.assertRaises(ValueError):
            UvcCapture(self.settings, [UvcSourceConfig(source, PROFILE) for source in SOURCES],
                       launcher=self.launcher, discovery=discovery)
        with self.assertRaises(ValueError):
            UvcCapture(self.settings, [], launcher=self.launcher, discovery=discovery)

    def test_root_is_refused_and_store_corruption_fails_closed(self):
        with self.assertRaises(CaptureRefused):
            UvcCapture(self.settings, [UvcSourceConfig(SOURCES[0], PROFILE)],
                       launcher=self.launcher, discovery=FakeDiscovery(), geteuid=lambda: 0)
        path = self.settings.runtime_root / FILENAME
        path.write_text("{not json")
        path.chmod(0o600)
        with self.assertRaises(ApprovalStorageError):
            UvcCapture(self.settings, [UvcSourceConfig(SOURCES[0], PROFILE)],
                       launcher=self.launcher, discovery=FakeDiscovery())
        path.write_text("{}")
        path.chmod(0o644)
        with self.assertRaises(ApprovalStorageError):
            ApprovalStore(self.settings)

    def test_approval_store_is_private_single_writer_and_bounded(self):
        store = ApprovalStore(self.settings)
        self.addCleanup(store.close)
        with self.assertRaises(ApprovalStorageError):
            ApprovalStore(self.settings)
        state = store.start_session(SOURCES[0])
        self.assertTrue(state.requires_approval)
        store.save(SOURCES[0], evidence(), False, session_token=state.session_token,
                   serial_ambiguous=False)
        path = self.settings.runtime_root / FILENAME
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ApprovalStorageError):
            store.save(SOURCES[0], evidence(), False, session_token="stale", serial_ambiguous=False)
        self.assertEqual([name for name in os.listdir(self.settings.runtime_root)
                          if ".tmp-" in name], [])

    def test_close_is_idempotent_and_poll_after_close_refuses(self):
        device = evidence()
        capture, pipeline = self.approved_online(FakeDiscovery(device), device)
        capture.close()
        capture.close()
        self.assertTrue(pipeline.dead and pipeline.closed)
        with self.assertRaises(CaptureRefused):
            capture.poll()
        self.assertIsNone(capture.frames(SOURCES[0]).get(0))

    def test_health_values_are_valid_source_health(self):
        capture = self.capture(FakeDiscovery())
        self.assertTrue(all(isinstance(item, SourceHealth) for item in capture.poll()))


GENERATOR = textwrap.dedent("""
    import os, signal, sys, time
    mode = sys.argv[1]
    if mode == "grandchild":
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(60)
            os._exit(0)
        with open(sys.argv[2], "w") as stream:
            stream.write(str(pid))
    if mode == "ignore":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    frame = bytes.fromhex(sys.argv[3])
    out = os.fdopen(1, "wb", buffering=0)
    os.fstat(int(sys.argv[4]))  # Inherited verified descriptor is usable.
    while True:
        out.write(frame)
        time.sleep(0.02)
""")


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            return stream.read().split(") ")[-1][0] != "Z"
    except FileNotFoundError:
        return False


class SubprocessPipelineTests(unittest.TestCase):
    def launch(self, mode, marker="-"):
        launcher = SubprocessLauncher(lambda fd, profile: [
            sys.executable, "-c", GENERATOR, mode, marker, synthetic_jpeg(1).hex(), str(fd)])
        descriptor = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            return launcher.launch(descriptor, PROFILE)
        finally:
            os.close(descriptor)

    def test_synthetic_process_frames_and_group_teardown(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "pid"
            process = self.launch("grandchild", str(marker))
            parser, frames = MjpegFrameParser(4096), []
            while len(frames) < 3:
                data = process.read(4096)
                self.assertTrue(data)
                frames.extend(parser.feed(data))
            self.assertEqual(frames[0], synthetic_jpeg(1))
            self.assertTrue(wait_for(marker.exists))
            self.assertTrue(wait_for(lambda: marker.read_text().isdigit()))
            grandchild = int(marker.read_text())
            self.assertFalse(process.exited())
            self.assertTrue(process.stop(2))
            process.close()
            self.assertTrue(process.exited())
            self.assertTrue(wait_for(lambda: not alive(grandchild)))
            self.assertTrue(process.stop(1))  # Idempotent.

    def test_surviving_group_member_keeps_leader_unreaped(self):
        # A member stuck in uninterruptible sleep cannot be produced without
        # hardware, so the process table is a synthetic tree listing one.
        leader = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, start_new_session=True)
        with tempfile.TemporaryDirectory() as proc:
            member = Path(proc) / "999999"
            member.mkdir()
            stat = member / "stat"
            stat.write_bytes(f"999999 (gst ) x) D {leader.pid} {leader.pid} 0 0".encode())
            (Path(proc) / str(leader.pid)).mkdir()
            (Path(proc) / "self").mkdir()
            pipeline = SubprocessPipeline(leader, proc_root=proc)
            started = time.monotonic()
            self.assertFalse(pipeline.stop(0.3))
            self.assertLess(time.monotonic() - started, 1)
            self.assertTrue(pipeline.exited())
            self.assertIsNone(leader.returncode)  # Group ID stays reserved.
            self.assertFalse(pipeline.stop(0.0))
            # Once the member is dead the leader is reaped.
            stat.write_bytes(f"999999 (gst) Z {leader.pid} {leader.pid} 0 0".encode())
            self.assertTrue(pipeline.stop(0.0))
            self.assertIsNotNone(leader.returncode)
        pipeline.close()
        # Without a readable process table cleanup is never reported.
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        unprovable = SubprocessPipeline(other, proc_root=os.path.join(proc, "missing"))
        self.assertFalse(unprovable.stop(0.1))
        self.assertIsNone(other.returncode)
        other.wait(5)
        other.stdout.close()

    def test_sigterm_ignoring_pipeline_is_killed_within_bound(self):
        process = self.launch("ignore")
        self.assertTrue(process.read(16))
        started = time.monotonic()
        self.assertTrue(process.stop(1))
        self.assertLess(time.monotonic() - started, 2)
        process.close()

    def test_real_process_integrates_with_capture_adapter(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-uvc-process-")
        self.addCleanup(temporary.cleanup)
        config = settings(Path(temporary.name))
        launcher = SubprocessLauncher(lambda fd, profile: [
            sys.executable, "-c", GENERATOR, "plain", "-", synthetic_jpeg(2).hex(), str(fd)])
        device = evidence()
        capture = UvcCapture(config, [UvcSourceConfig(SOURCES[0], PROFILE)], launcher=launcher,
                             discovery=FakeDiscovery(device),
                             open_device=lambda _c: os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC))
        capture.approve(SOURCES[0], device)
        capture.poll()
        frame = capture.frames(SOURCES[0]).get(5)
        self.assertEqual(frame.data, synthetic_jpeg(2))
        self.assertTrue(wait_for(lambda: capture.poll()[0].state in ("online", "degraded")))
        process = capture._sources[SOURCES[0]].active.process.process
        capture.close()
        self.assertIsNotNone(process.returncode)


@unittest.skipUnless(shutil.which("gst-launch-1.0"), "GStreamer is not installed")
class OptionalGStreamerParserTests(unittest.TestCase):
    """Local-only: GStreamer's synthetic test pattern, never a camera."""

    def test_jpegenc_output_splits_into_frames(self):
        argv = [shutil.which("gst-launch-1.0"), "-q", "videotestsrc", "num-buffers=5",
                "pattern=smpte", "!", "video/x-raw,width=64,height=48", "!", "jpegenc",
                "!", "fdsink", "fd=1"]
        try:
            output = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=30, env=minimal_environment()).stdout
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("GStreamer test pipeline unavailable")
        if not output:
            self.skipTest("GStreamer jpegenc unavailable")
        frames = MjpegFrameParser(1024 * 1024).feed(output)
        self.assertEqual(len(frames), 5)
        self.assertTrue(all(frame.startswith(b"\xff\xd8") and frame.endswith(b"\xff\xd9")
                            for frame in frames))


if __name__ == "__main__":
    unittest.main()
