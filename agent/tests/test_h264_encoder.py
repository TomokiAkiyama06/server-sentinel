"""Deviceless OpenH264 encoder child (Issue #16 PR B).

Synthetic children only, except ``RealOpenH264Tests``, which encodes
GStreamer's ``videotestsrc`` pattern (never a camera) when the distribution
encoder plugins are installed. ``AGENT_OPENH264_REQUIRED=1`` (the Ubuntu 24.04
apt CI job) turns a missing encoder or Landlock into a failure, not a skip.
"""
from __future__ import annotations

import json
import os
import select
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from media_capture_agent import uvc_sandbox
from media_capture_agent.fmp4 import read_boxes, write_segment
from media_capture_agent.h264_annexb import AccessUnitSplitter, validate_segment
from media_capture_agent.h264_encoder import (ENCODER_PLUGINS, ENCODER_THREADS, EncoderLauncher,
                                              EncoderProcess, EncoderProfile, encoder_argv,
                                              no_device_sandbox_argv)
from media_capture_agent.uvc_pipeline import (GSTREAMER_ENVIRONMENT, MjpegFrameParser,
                                              MjpegProfile, PipelineError,
                                              default_plugin_dirs, minimal_environment)


REQUIRED = os.environ.get("AGENT_OPENH264_REQUIRED") == "1"
CAPTURE = MjpegProfile(1280, 720, 30)
PROFILE = EncoderProfile(CAPTURE, 2_000_000, 4_000_000, 60)


class ProfileTests(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(PROFILE.gop_frames, 60)
        for args in ((CAPTURE, 0, 1, 1), (CAPTURE, 2, 1, 1), (CAPTURE, 1, 100_000_001, 1),
                     (CAPTURE, 1, 1, 0), (CAPTURE, 1, 1, 1001), (CAPTURE, True, 1, 1),
                     ((1280, 720, 30), 1, 1, 1), (CAPTURE, 1, 1, 1.0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                EncoderProfile(*args)


class CommandTests(unittest.TestCase):
    def test_encoder_pipeline_is_fixed_and_deviceless(self):
        argv = encoder_argv("/usr/bin/gst-launch-1.0", PROFILE, plugins=["/p/a.so", "/p/b.so"])
        self.assertEqual(argv[:3], ["/usr/bin/gst-launch-1.0", "-q",
                                    "--gst-plugin-load=/p/a.so,/p/b.so"])
        elements = [argv[3]] + [argv[i + 1] for i, item in enumerate(argv) if item == "!"]
        self.assertEqual(elements, [
            "fdsrc", "image/jpeg,width=1280,height=720,framerate=30/1", "jpegparse", "jpegdec",
            "videoconvert", "video/x-raw,format=I420", "openh264enc",
            "video/x-h264,stream-format=byte-stream,alignment=au,profile=constrained-baseline",
            "fdsink"])
        encoder = argv[argv.index("openh264enc"):]
        for setting in ("bitrate=2000000", "max-bitrate=4000000", "gop-size=60",
                        "rate-control=bitrate", "enable-frame-skip=false",
                        f"multi-thread={ENCODER_THREADS}"):
            self.assertIn(setting, encoder)
        self.assertIn("fd=0", argv)
        self.assertEqual(argv[-2:], ["fd=1", "sync=false"])
        text = " ".join(argv)
        for forbidden in ("v4l2", "/dev/", "device=", "alsa", "pulse", "audio", "filesink",
                          "tcp", "udp", "location="):
            self.assertNotIn(forbidden, text)

    def test_refusals(self):
        with self.assertRaises(PipelineError):
            encoder_argv("/usr/bin/gst-launch-1.0", CAPTURE)
        with self.assertRaises(PipelineError):
            encoder_argv("/usr/bin/gst-launch-1.0", PROFILE, plugins=["/a,b.so"])

    def test_sandbox_argv_selects_no_device(self):
        argv = no_device_sandbox_argv("/usr/bin/python3", "/opt/a/media-capture-agent",
                                      ["/usr", "/x.so"], ["/usr/bin/gst-launch-1.0", "-q"],
                                      (uvc_sandbox.ARCHIVE_ENTRY,))
        self.assertEqual(argv, ["/usr/bin/python3", "-I", "-S", "-B", "/opt/a/media-capture-agent",
                                uvc_sandbox.ARCHIVE_ENTRY, "--no-device", "--read", "/usr",
                                "--read", "/x.so", "--", "/usr/bin/gst-launch-1.0", "-q"])
        self.assertNotIn("--device-fd", argv)
        for python, helper, extra in (("python3", "/h", ()), ("/usr/bin/python3", "h", ()),
                                      ("/usr/bin/python3", "/h", ("--other",))):
            with self.subTest(python=python, helper=helper), self.assertRaises(PipelineError):
                no_device_sandbox_argv(python, helper, [], ["/bin/true"], extra)

    def test_sandbox_parses_no_device_strictly(self):
        self.assertEqual(uvc_sandbox.parse(["--no-device", "--", "/bin/true"]),
                         (None, uvc_sandbox.DEFAULT_READ_PATHS, ["/bin/true"]))
        self.assertEqual(uvc_sandbox.parse(["--read", "/usr", "--no-device", "--", "/bin/true"]),
                         (None, ("/usr",), ["/bin/true"]))
        for argv in (["--no-device", "--no-device", "--", "/bin/true"],
                     ["--no-device", "--device-fd", "5", "--", "/bin/true"],
                     ["--device-fd", "5", "--no-device", "--", "/bin/true"],
                     ["--no-device", "--", "true"], ["--no-device", "--"], ["--no-device"]):
            with self.subTest(argv), self.assertRaises(uvc_sandbox.SandboxError):
                uvc_sandbox.parse(argv)


def landlock_available():
    """A supported ABI for mocked launchers, so they never need a real Landlock."""
    return 1


def plugin_dir(temporary, names=ENCODER_PLUGINS):
    plugins = Path(temporary) / "plugins"
    plugins.mkdir()
    for name in names:
        (plugins / name).write_bytes(b"synthetic")
    return plugins


class LauncherTests(unittest.TestCase):
    def test_missing_plugin_or_sandbox_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            plugins = plugin_dir(temporary, ENCODER_PLUGINS[:-1])
            with self.assertRaisesRegex(PipelineError, "encoder plugins are unavailable"):
                EncoderLauncher("/bin/true", trust=Path, trust_file=Path, plugin_dirs=[plugins],
                                sandbox_abi=landlock_available)
        with tempfile.TemporaryDirectory() as temporary:
            plugins = plugin_dir(temporary)
            with self.assertRaisesRegex(PipelineError, "sandbox is unavailable"):
                EncoderLauncher("/bin/true", trust=Path, trust_file=Path, plugin_dirs=[plugins],
                                sandbox_abi=lambda: 0)

    def test_every_start_rechecks_trust_and_uses_a_minimal_environment(self):
        calls = []

        def trust(path):
            calls.append(str(path))
            return Path(path)

        with tempfile.TemporaryDirectory() as temporary:
            plugins = plugin_dir(temporary)
            popen = mock.Mock(side_effect=OSError("synthetic"))
            launcher = EncoderLauncher("/usr/bin/gst-launch-1.0", trust=trust, trust_file=trust,
                                       plugin_dirs=[plugins], python="/usr/bin/python3",
                                       helper="/opt/helper", helper_args=(), popen=popen,
                                       sandbox_abi=landlock_available)
            calls.clear()
            with self.assertRaisesRegex(PipelineError, "could not start"):
                launcher.launch(PROFILE)
        self.assertIn("/usr/bin/gst-launch-1.0", calls)
        self.assertIn("/usr/bin/python3", calls)
        self.assertIn("/opt/helper", calls)
        self.assertEqual(sum(call.startswith(str(plugins)) for call in calls), len(ENCODER_PLUGINS))
        argv, options = popen.call_args.args[0], popen.call_args.kwargs
        self.assertIn("--no-device", argv)
        self.assertEqual(options["env"], minimal_environment(GSTREAMER_ENVIRONMENT))
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(options["stdin"], subprocess.PIPE)
        self.assertTrue(options["start_new_session"])
        self.assertNotIn("pass_fds", options)

    def test_untrusted_file_is_refused(self):
        def refuse(path):
            raise PipelineError("pipeline executable is not root-controlled")

        with tempfile.TemporaryDirectory() as temporary:
            plugins = plugin_dir(temporary)
            with self.assertRaises(PipelineError):
                EncoderLauncher("/usr/bin/gst-launch-1.0", trust=Path, trust_file=refuse,
                                plugin_dirs=[plugins], sandbox_abi=landlock_available)


SLOW_READER = """#!/usr/bin/python3 -I
import sys, time
time.sleep(30)
"""


class ProcessTests(unittest.TestCase):
    def process(self, script):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(script)
        self.addCleanup(os.unlink, handle.name)
        child = subprocess.Popen([sys.executable, "-I", handle.name], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 start_new_session=True, bufsize=0)
        process = EncoderProcess(child)
        self.addCleanup(process.close)
        self.addCleanup(process.stop, 10)
        return process

    def test_a_child_that_stops_reading_times_out_instead_of_blocking(self):
        process = self.process(SLOW_READER)
        started = time.monotonic()
        with self.assertRaisesRegex(PipelineError, "^video encoder stalled$"):
            process.write(b"\xff" * (8 << 20), timeout=0.3)
        self.assertLess(time.monotonic() - started, 5)

    def test_an_exited_child_is_a_fixed_error(self):
        process = self.process("import sys\nsys.exit(0)\n")
        self.assertTrue(process.process.wait(10) == 0)
        with self.assertRaisesRegex(PipelineError, "^video encoder stopped$"):
            for _ in range(64):
                process.write(b"\xff" * 65536, timeout=1)

    def test_echo_round_trip_and_end_of_input(self):
        process = self.process("import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n")
        process.write(b"abc", timeout=5)
        process.write(memoryview(b"def"), timeout=5)
        process.close_input()
        output = b""
        while chunk := process.read(65536):
            output += chunk
        self.assertEqual(output, b"abcdef")
        with self.assertRaises(TypeError):
            process.write("text", timeout=1)


FAKE_ENCODER = """#!/usr/bin/python3 -I
import json, os, socket, sys
def attempt(path, flags=os.O_RDONLY):
    try:
        os.close(os.open(path, flags))
        return "opened"
    except OSError as error:
        return error.errno
data = sys.stdin.buffer.read()
result = {"argv": sys.argv[1:], "env": dict(os.environ), "input": len(data),
          "device": attempt("/dev/zero", os.O_RDWR), "dev_listing": attempt("/dev", os.O_RDONLY | os.O_DIRECTORY),
          "private_file": attempt(sys.argv[0] + ".private"),
          "write_tmp": attempt(os.path.join(os.path.dirname(sys.argv[0]), "new"), os.O_WRONLY | os.O_CREAT)}
try:
    socket.create_connection(("127.0.0.1", 9), timeout=1).close()
    result["tcp"] = "connected"
except OSError as error:
    result["tcp"] = error.errno
sys.stdout.write(json.dumps(result))
"""


class LandlockEncoderTests(unittest.TestCase):
    @unittest.skipUnless(uvc_sandbox.abi_version() > 0 or REQUIRED, "Landlock is unavailable")
    @unittest.skipUnless(os.path.exists("/usr/bin/python3"), "no system Python")
    def test_fake_encoder_child_can_open_no_device_and_no_private_file(self):
        os.environ["SERVERSENTINEL_SYNTHETIC_SECRET"] = "sentinel-value"
        self.addCleanup(os.environ.pop, "SERVERSENTINEL_SYNTHETIC_SECRET", None)
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "gst-launch-1.0"
            executable.write_text(FAKE_ENCODER)
            executable.chmod(0o700)
            Path(f"{executable}.private").write_text("synthetic")
            plugins = plugin_dir(temporary)
            launcher = EncoderLauncher(executable, trust=Path, trust_file=Path,
                                       plugin_dirs=[plugins])
            process = launcher.launch(PROFILE)
            process.write(b"\xff\xd8synthetic\xff\xd9", timeout=10)
            process.close_input()
            output = b""
            while chunk := process.read(65536):
                output += chunk
            self.assertTrue(process.stop(10))
            process.close()
            self.assertFalse((Path(temporary) / "new").exists())
        result = json.loads(output)
        self.assertEqual(result["input"], 13)
        self.assertEqual(result["device"], 13)  # EACCES
        self.assertEqual(result["dev_listing"], 13)
        self.assertEqual(result["private_file"], 13)
        self.assertEqual(result["write_tmp"], 13)
        if uvc_sandbox.abi_version() >= 4:
            self.assertEqual(result["tcp"], 13)
        environment = result["env"]
        environment.pop("LC_CTYPE", None)
        self.assertEqual(environment, {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                       **GSTREAMER_ENVIRONMENT})
        self.assertEqual(result["argv"][:2], [
            "-q", "--gst-plugin-load=" + ",".join(str(plugins / name) for name in ENCODER_PLUGINS)])


def _encoder_available():
    gst = shutil.which("gst-launch-1.0")
    if not gst:
        return None
    for directory in default_plugin_dirs():
        if all((Path(directory) / name).exists() for name in ENCODER_PLUGINS):
            return gst
    return None


class RealOpenH264Tests(unittest.TestCase):
    """Synthetic test pattern through the real, sandboxed OpenH264 child."""

    def setUp(self):
        self.gst = _encoder_available()
        if self.gst is None:
            if REQUIRED:
                self.fail("AGENT_OPENH264_REQUIRED=1 but the OpenH264 GStreamer plugins are missing")
            self.skipTest("the OpenH264 GStreamer plugins are not installed")
        if uvc_sandbox.abi_version() < 1:
            if REQUIRED:
                self.fail("AGENT_OPENH264_REQUIRED=1 but Landlock is unavailable")
            self.skipTest("Landlock is unavailable")

    def test_frames_in_are_access_units_out_and_a_playable_segment(self):
        count, gop = 60, 30
        capture = MjpegProfile(320, 240, 30)
        argv = [self.gst, "-q", "videotestsrc", f"num-buffers={count}", "pattern=ball", "!",
                "video/x-raw,width=320,height=240,framerate=30/1", "!", "jpegenc", "!",
                "fdsink", "fd=1"]
        jpeg = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
                              env=minimal_environment(), check=True).stdout
        frames = MjpegFrameParser(1 << 20).feed(jpeg)
        self.assertEqual(len(frames), count)
        # The checkout's helper is not root-owned; the system files still are.
        launcher = EncoderLauncher(self.gst, trust=Path, trust_file=Path,
                                   python="/usr/bin/python3")
        process = launcher.launch(EncoderProfile(capture, 500_000, 1_000_000, gop))
        output = bytearray()
        try:
            for frame in frames:
                process.write(frame, timeout=10)
                # Drain as we go so a full stdout pipe never stalls the child.
                while True:
                    ready, _w, _x = select.select([process.process.stdout], [], [], 0)
                    if not ready:
                        break
                    chunk = process.read(65536)
                    if not chunk:
                        break
                    output += chunk
            process.close_input()
            while chunk := process.read(65536):
                output += chunk
            self.assertEqual(process.process.wait(30), 0)
        finally:
            process.stop(10)
            process.close()
        splitter = AccessUnitSplitter(max_nal_bytes=1 << 20, max_access_unit_bytes=1 << 20)
        units = splitter.feed(bytes(output)) + splitter.flush()
        segment = validate_segment(units, expected_count=count)
        self.assertEqual(sum(segment.sync), count // gop)
        self.assertEqual((segment.info.width, segment.info.height), (320, 240))
        self.assertEqual(segment.info.profile_idc, 66)
        data = write_segment(segment, timescale=90000, sample_duration=3000,
                             sequence_number=1, base_decode_time=0)
        self.assertEqual([box.kind for box in read_boxes(data)],
                         [b"ftyp", b"moov", b"moof", b"mdat"])


if __name__ == "__main__":
    unittest.main()
