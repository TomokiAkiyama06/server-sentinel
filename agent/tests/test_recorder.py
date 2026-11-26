"""Camera frames to ring segments (Issue #16 PR C2).

The state machine is driven synchronously with an injected clock and a fake
encoder that turns every frame into one synthetic access unit. One test runs
the real sandboxed OpenH264 child into a real temporary-filesystem ring on
GStreamer's ``videotestsrc`` pattern (never a camera); ``AGENT_OPENH264_REQUIRED=1``
makes it fail instead of skip.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import queue
import shutil
import struct
import subprocess
import threading
import time
import unittest

from media_capture_agent.config import RingSourceSetting, Settings
from media_capture_agent.fmp4 import read_boxes
from media_capture_agent.recorder import LATENCY_US, SegmentRecorder
from media_capture_agent.ring_models import SECOND, RingConfig, RingRefused, SegmentProfile
from media_capture_agent.uvc_pipeline import MjpegFrameParser, MjpegProfile, PipelineError
from tests.support import SOURCE
from tests.test_recording_segment import PPS, SPS, annexb, idr, slice_


FPS = 30
CAPTURE = MjpegProfile(320, 240, FPS)
SETTING = RingSourceSetting(SOURCE, 500_000, 1_000_000, 500_000, 30)
PROFILE = SegmentProfile(SOURCE, 1_000_000, 500_000, SECOND, 4096)
JPEG = b"\xff\xd8synthetic\xff\xd9"


class FakeProcess:
    """In-process stand-in for ``EncoderProcess``: one access unit per frame."""

    def __init__(self, launcher):
        self.launcher = launcher
        self.chunks = queue.Queue()
        self.count = 0
        self.stopped = False
        self.process = self

    def write(self, data, timeout):
        if self.launcher.fail_writes:
            raise PipelineError("video encoder stopped")
        unit = annexb(SPS, PPS, idr(self.count)) if self.count == 0 else annexb(slice_(self.count))
        self.count += 1
        if self.count <= self.launcher.emit_limit:
            self.chunks.put(unit)

    def close_input(self):
        self.chunks.put(None)

    def read(self, size):
        chunk = self.chunks.get(timeout=5)
        return chunk or b""

    def wait(self, timeout):
        return 0

    def stop(self, timeout):
        self.stopped = True
        return True

    def close(self):
        self.chunks.put(None)


class FakeLauncher:
    def __init__(self):
        self.launched = []
        self.fail_launch = False
        self.fail_writes = False
        self.emit_limit = 1 << 30

    def launch(self, profile):
        if self.fail_launch:
            raise PipelineError("video encoder could not start")
        process = FakeProcess(self)
        self.launched.append(process)
        return process


class FakeRing:
    def __init__(self):
        self.config = RingConfig("duration", 600)
        self.profiles = {SOURCE: PROFILE}
        self.appended = []
        self.refuse = None

    def append(self, source_id, start_us, end_us, data, *, now_us, clock_trusted):
        if self.refuse:
            raise RingRefused(self.refuse)
        self.appended.append((start_us, end_us, data, now_us, clock_trusted))


class FakeMonitor:
    reconfiguration_required = False

    def clock_trusted(self, utc, monotonic):
        return True


class Clock:
    def __init__(self, monotonic=0.0, offset=1000.25):
        self.mono, self.offset = monotonic, offset

    def utc(self):
        return self.mono + self.offset

    def monotonic(self):
        return self.mono


class RecorderCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.launcher, self.ring = FakeLauncher(), FakeRing()
        self.recorder = SegmentRecorder(
            SOURCE, CAPTURE, SETTING, segment_seconds=1, ring=self.ring, monitor=FakeMonitor(),
            launcher=self.launcher, step_limit_seconds=0.5, utc=self.clock.utc,
            monotonic=self.clock.monotonic, start=False, finish_inline=True)
        self.addCleanup(self.recorder.close)

    def frames(self, start, stop, *, every=1 / FPS):
        """Feed frames captured from ``start`` to ``stop`` seconds (monotonic)."""
        index = 0
        while True:
            captured = start + index * every
            if captured >= stop:
                break
            self.clock.mono = captured
            self.recorder.feed(round(captured * SECOND), JPEG)
            index += 1
        self.clock.mono = stop

    def settle(self, at):
        self.clock.mono = at
        self.recorder.poll(round(at * SECOND))

    def stored(self):
        return [(start // SECOND, end // SECOND) for start, end, *_ in self.ring.appended]


class RecorderTests(RecorderCase):
    def test_steady_frames_make_contiguous_utc_aligned_segments(self):
        # UTC = monotonic + 1000.25, so the first boundary (1001 s) is at 0.75.
        self.frames(0.0, 3.5)
        self.settle(3.5 + 0.5)
        self.assertEqual(self.stored(), [(1001, 1002), (1002, 1003), (1003, 1004)])
        start, end, data, now_us, trusted = self.ring.appended[0]
        self.assertTrue(trusted)
        self.assertGreaterEqual(now_us, end)
        top = read_boxes(data)
        self.assertEqual([item.kind for item in top], [b"ftyp", b"moov", b"moof", b"mdat"])
        traf = next(item for item in read_boxes(top[2].payload) if item.kind == b"traf")
        trun = next(item for item in read_boxes(traf.payload) if item.kind == b"trun")
        self.assertEqual(struct.unpack(">I", trun.payload[4:8])[0], FPS)
        tfdt = next(item for item in read_boxes(traf.payload) if item.kind == b"tfdt")
        self.assertEqual(struct.unpack(">Q", tfdt.payload[4:12])[0], 1001 * 30 * 3000)
        # One encoder per begun segment (the fourth began at 3.75 s), plus the
        # spare started for the next one.
        self.assertEqual(len(self.launcher.launched), 5)
        self.assertEqual(self.recorder.status().get("segments_stored"), 3)

    def test_a_slow_camera_is_paced_by_repetition(self):
        self.frames(0.0, 2.9, every=1 / 20)
        self.settle(3.0)
        self.assertEqual(self.stored(), [(1001, 1002), (1002, 1003)])
        self.assertGreater(self.recorder.status()["frames_repeated"], 0)

    def test_an_interruption_drops_only_the_segments_it_touches(self):
        # Segments start at 0.75 s + k. The last frame before the outage
        # (1.2 s) may fill slots for 1 s, which still completes [0.75, 1.75).
        self.frames(0.0, 1.2)
        self.frames(3.0, 5.0)  # nothing between 1.2 s and 3.0 s
        self.settle(6.1)
        self.assertEqual(self.stored(), [(1001, 1002), (1004, 1005), (1005, 1006)])
        status = self.recorder.status()
        self.assertEqual(status["segment_dropped_frame_gap"], 2)
        self.assertGreater(status["frame_gap_slots"], 0)

    def test_an_encoder_failure_costs_one_segment(self):
        # The failing writes stay inside the segment [1.75, 2.75).
        self.frames(0.0, 1.9)
        self.launcher.fail_writes = True
        self.frames(1.9, 2.2)
        self.launcher.fail_writes = False
        self.frames(2.2, 3.5)
        self.settle(4.1)
        self.assertIn((1001, 1002), self.stored())
        self.assertEqual(self.recorder.status()["segment_dropped_encoder_failed"], 1)
        self.assertIn((1003, 1004), self.stored())
        self.assertNotIn((1002, 1003), self.stored())

    def test_a_stream_with_missing_access_units_is_not_stored(self):
        self.launcher.emit_limit = 10
        self.frames(0.0, 1.9)
        self.settle(2.0)
        self.assertEqual(self.stored(), [])
        self.assertEqual(self.recorder.status()["segment_dropped_invalid_stream"], 1)

    def test_a_ring_refusal_is_counted(self):
        self.ring.refuse = "profile_bound_violation"
        self.frames(0.0, 1.9)
        self.settle(2.0)
        self.assertEqual(self.recorder.status()["segment_refused_profile_bound_violation"], 1)

    def test_an_unready_ring_runs_no_encoder(self):
        self.ring.config = None
        self.frames(0.0, 2.9)
        self.settle(3.0)
        self.assertEqual((self.launcher.launched, self.ring.appended), ([], []))
        self.assertNotIn("segment_dropped_ring_not_ready", self.recorder.status())

    def test_an_unavailable_encoder_is_counted(self):
        self.launcher.fail_launch = True
        self.frames(0.0, 1.9)
        self.settle(2.0)
        self.assertEqual(self.recorder.status()["segment_dropped_encoder_unavailable"], 1)

    def test_a_wall_clock_step_remaps_at_the_next_boundary(self):
        self.frames(0.0, 1.5)
        self.clock.offset += 10.0  # the wall clock steps 10 s forward
        self.frames(1.5, 4.5)
        self.settle(5.0)
        # The segment in progress when the clock stepped ([1001, 1002)) is not
        # stored with its old-mapping times (PR #434 review), and the next one
        # begins under the new mapping.
        self.assertEqual(self.recorder.status()["segment_dropped_clock_remapped"], 2)
        starts = [start for start, _end in self.stored()]
        self.assertTrue(starts)
        self.assertTrue(all(start >= 1012 for start in starts), starts)

    def test_an_unreaped_encoder_blocks_new_encoders_until_it_is_gone(self):
        # PR #434 review: a process group that cannot be reaped is kept and
        # retried; no replacement encoder starts meanwhile.
        stuck = []
        self.launcher.fail_writes = True

        def stop(process, timeout, wait=True):
            if process in stuck:
                return False
            process.stopped = True
            return True

        def launch(profile, original=self.launcher.launch):
            process = original(profile)
            process.stop = lambda timeout, wait=True, process=process: stop(process, timeout, wait)
            if not self.launcher.launched[:-1]:
                stuck.append(process)  # the first encoder never dies
            return process

        self.launcher.launch = launch
        self.frames(0.0, 1.0)  # the first segment's encoder fails on write
        self.launcher.fail_writes = False
        launched = len(self.launcher.launched)
        self.frames(1.0, 2.9)
        self.settle(3.0)
        self.assertEqual(self.recorder.status()["encoder_cleanup_pending"], 1)
        self.assertEqual(self.ring.appended, [])
        self.assertLessEqual(len(self.launcher.launched), launched)
        stuck.clear()  # the process group is finally gone
        self.frames(3.0, 4.9)
        self.settle(5.0)
        self.assertTrue(self.ring.appended)

    def test_no_ring_operation_runs_between_the_clock_read_and_the_append(self):
        # PR #434 review: a heartbeat tick (or another source's append) that
        # records a newer time between this finisher's clock read and its
        # append made a healthy clock look rolled back.
        self.ring.lock = threading.RLock()
        order = []
        started = threading.Event()

        def tick():
            started.set()
            with self.ring.lock:
                order.append("tick")

        class Monitor(FakeMonitor):
            def clock_trusted(monitor, utc, monotonic):
                thread = threading.Thread(target=tick)
                thread.start()
                started.wait(5)
                thread.join(0.2)  # blocked on the ring lock this finisher holds
                order.append("tick blocked" if thread.is_alive() else "tick ran")
                monitor.thread = thread
                return True

        monitor = Monitor()
        self.recorder.monitor = monitor
        original = self.ring.append

        def append(*args, **kwargs):
            order.append("append")
            return original(*args, **kwargs)

        self.ring.append = append
        self.frames(0.0, 1.9)
        self.settle(2.0)
        monitor.thread.join(5)
        self.assertEqual(order, ["tick blocked", "append", "tick"])

    def test_frames_out_of_order_are_ignored(self):
        self.recorder.feed(SECOND, JPEG)
        self.recorder.feed(SECOND // 2, JPEG)
        self.assertEqual(self.recorder.status()["frames_out_of_order"], 1)

    def test_the_latency_allowance_keeps_queued_frames_usable(self):
        self.assertGreater(LATENCY_US, 0)
        self.frames(0.0, 1.0)
        # Poll before the frames up to 1.0 s "arrived": nothing is a gap yet.
        self.settle(1.0)
        self.frames(1.0, 2.0)
        self.settle(2.0)
        self.assertNotIn("segment_dropped_frame_gap", self.recorder.status())


class OfferTests(unittest.TestCase):
    def test_the_queue_is_bounded_and_never_blocks(self):
        recorder = SegmentRecorder(
            SOURCE, CAPTURE, SETTING, segment_seconds=1, ring=FakeRing(), monitor=FakeMonitor(),
            launcher=FakeLauncher(), step_limit_seconds=0.5, start=False)
        frame = type("Frame", (), {"data": JPEG, "received_monotonic": 1.0})()
        for _ in range(FPS * 2 + 5):
            recorder.offer(frame)
        self.assertEqual(recorder.status()["frames_dropped_queue"], 5)
        recorder.offer(type("Frame", (), {"data": "text", "received_monotonic": 1.0})())
        self.assertEqual(recorder.status()["frames_dropped_queue"], 5)
        recorder.close()

    def test_the_thread_records_and_stops(self):
        ring = FakeRing()
        recorder = SegmentRecorder(
            SOURCE, CAPTURE, SETTING, segment_seconds=1, ring=ring, monitor=FakeMonitor(),
            launcher=FakeLauncher(), step_limit_seconds=0.5)
        start = time.monotonic()
        try:
            while time.monotonic() - start < 3.0 and not ring.appended:
                now = time.monotonic()
                recorder.offer(type("Frame", (), {"data": JPEG, "received_monotonic": now})())
                time.sleep(1 / FPS)
        finally:
            recorder.close()
        self.assertTrue(ring.appended)
        self.assertFalse(any(thread.name.startswith("media-capture-agent-recorder")
                             and thread.is_alive() for thread in threading.enumerate()))


class FinishingTests(unittest.TestCase):
    def recorder(self, ring, launcher, **options):
        clock = Clock()
        recorder = SegmentRecorder(
            SOURCE, CAPTURE, SETTING, segment_seconds=1, ring=ring, monitor=FakeMonitor(),
            launcher=launcher, step_limit_seconds=0.5, utc=clock.utc,
            monotonic=clock.monotonic, **options)
        return recorder, clock

    def test_the_pending_segments_are_bounded(self):
        # PR #434 review (P1): no finisher drains here, so the backlog fills.
        from media_capture_agent.recorder import MAX_PENDING_SEGMENTS
        launcher = FakeLauncher()
        recorder, clock = self.recorder(FakeRing(), launcher, start=False)
        index = 0
        while index / FPS < MAX_PENDING_SEGMENTS + 3:
            clock.mono = index / FPS
            recorder.feed(round(clock.mono * SECOND), JPEG)
            index += 1
        self.assertEqual(len(recorder._finishing), MAX_PENDING_SEGMENTS)
        self.assertGreaterEqual(recorder.status()["segment_dropped_finish_backlog"], 1)
        dropped = [process for process in launcher.launched if process.stopped]
        self.assertGreaterEqual(len(dropped), 1)
        recorder.close()
        self.assertEqual(recorder.status()["segment_dropped_shutdown"], MAX_PENDING_SEGMENTS)
        self.assertEqual(len(recorder._finishing), 0)

    def test_the_finisher_drains_until_the_recorder_has_stopped(self):
        # PR #434 review (P2): a segment queued after "stopping" was set, while
        # the recorder thread is still running, is still finished.
        ring = FakeRing()
        recorder, clock = self.recorder(ring, FakeLauncher(), start=False)
        recorder._finisher = threading.Thread(target=recorder._finish_loop, daemon=True)
        recorder._finisher.start()
        with recorder._wake:
            recorder._stopping = True
            recorder._wake.notify_all()
        time.sleep(0.2)
        self.assertTrue(recorder._finisher.is_alive())
        index = 0
        while index / FPS < 1.9:
            clock.mono = index / FPS
            recorder.feed(round(clock.mono * SECOND), JPEG)
            index += 1
        clock.mono = 2.2
        recorder.poll(round(clock.mono * SECOND))
        recorder.close()
        self.assertEqual([(start // SECOND, end // SECOND) for start, end, *_ in ring.appended],
                         [(1001, 1002)])
        self.assertFalse(recorder._finisher.is_alive())


REQUIRED = os.environ.get("AGENT_OPENH264_REQUIRED") == "1"


class RealRecorderTests(unittest.TestCase):
    """Real OpenH264 child into a real temporary-filesystem ring."""

    def setUp(self):
        from tests.test_h264_encoder import _encoder_available
        from media_capture_agent import uvc_sandbox
        self.gst = _encoder_available()
        if self.gst is None or uvc_sandbox.abi_version() < 1:
            if REQUIRED:
                self.fail("AGENT_OPENH264_REQUIRED=1 but OpenH264 or Landlock is unavailable")
            self.skipTest("the OpenH264 GStreamer plugins or Landlock are unavailable")

    def test_videotestsrc_frames_become_stored_ring_segments(self):
        from media_capture_agent.h264_encoder import EncoderLauncher
        from media_capture_agent.ring import DiskRing
        from media_capture_agent.ring_service import ring_profiles
        from media_capture_agent.storage import MediaStore
        from media_capture_agent.uvc_pipeline import minimal_environment
        from tests import support
        from tests.support import ring_temporary_directory
        from tests.test_ring import AllowControls, Quota

        temporary = ring_temporary_directory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        value = copy.deepcopy(support.configuration(root))
        value["max_segment_bytes"] = 4 << 20
        value["capture"] = {"gst_launch": self.gst,
                            "sources": [{"source_id": str(SOURCE), "profile": "320x240@30/MJPG"}]}
        value["ring"] = {"segment_seconds": 10, "overhead_bytes": 65536,
                         "ledger_maximum_bytes": 64 << 20, "clock_holdover_seconds": 900,
                         "sources": [{"source_id": str(SOURCE), "target_bitrate": 500_000,
                                      "maximum_bitrate": 1_000_000, "expected_bitrate": 500_000,
                                      "gop_frames": 60}]}
        settings = Settings.parse(value, code_root=root / "code")
        store = MediaStore(settings, space=Quota(settings.media_root),
                           stable_device=lambda _expected: True)
        self.addCleanup(store.close)
        ring = DiskRing(settings, store, ledger_maximum_bytes=64 << 20, authority=AllowControls())
        self.addCleanup(ring.close)
        clock = Clock(offset=1_800_000_000.25)
        ring.configure(RingConfig("duration", 600), ring_profiles(settings),
                       now_us=round(clock.utc() * SECOND), clock_trusted=True)

        jpeg = subprocess.run(
            [self.gst, "-q", "videotestsrc", "num-buffers=1000", "pattern=ball", "!",
             "video/x-raw,width=320,height=240,framerate=30/1", "!", "jpegenc", "!",
             "fdsink", "fd=1"], stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
            env=minimal_environment(), check=True).stdout
        frames = MjpegFrameParser(1 << 20).feed(jpeg)
        launcher = EncoderLauncher(self.gst, trust=Path, trust_file=Path,
                                   python=shutil.which("python3") and "/usr/bin/python3")
        recorder = SegmentRecorder(
            SOURCE, CAPTURE, settings.ring.sources[0], segment_seconds=10, ring=ring,
            monitor=FakeMonitor(), launcher=launcher, step_limit_seconds=0.5,
            utc=clock.utc, monotonic=clock.monotonic, start=False, finish_inline=True)
        try:
            for index, frame in enumerate(frames):
                clock.mono = index / FPS
                recorder.feed(round(clock.mono * SECOND), frame)
            clock.mono = len(frames) / FPS + 1.0
            recorder.poll(round(clock.mono * SECOND))
        finally:
            recorder.close()
        rows = ring.db.execute("SELECT start, end, length, clock_trusted FROM segments "
                               "ORDER BY start").fetchall()
        self.assertEqual([(row["start"] // SECOND, row["end"] // SECOND) for row in rows],
                         # Boundaries are multiples of 10 s in UTC; the start
                         # (…000.25 s) makes [10, 20) and [20, 30) the full ones.
                         [(1_800_000_010, 1_800_000_020), (1_800_000_020, 1_800_000_030)],
                         recorder.status())
        bound = SegmentProfile(SOURCE, 1_000_000, 500_000, 10 * SECOND, 65536).segment_bytes()
        self.assertTrue(all(0 < row["length"] <= bound and row["clock_trusted"] for row in rows))


if __name__ == "__main__":
    unittest.main()
