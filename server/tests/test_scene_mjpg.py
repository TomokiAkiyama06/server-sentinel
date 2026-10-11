"""Reviewed MJPG luma reader (Issue #217) with generated synthetic JPEGs only.

Every frame is generated in memory with numpy and encoded with the reviewed
simplejpeg encoder; no camera, real scene or person is used. Decoding runs in
the real resident decode child (`mjpg_child.py`); contract violations use the
synthetic stand-ins in `mjpg_child_fakes.py`.
"""

import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock
from uuid import UUID

import numpy as np
import simplejpeg

from app.cameras.registry.models import SourceType
from app.cameras.uvc.capture import VideoFrame
from app.detection.foundation import Observation
from app.detection.roi import CriticalKind
from app.detection.roi import mjpg, mjpg_child, mjpg_worker
from app.detection.roi.mjpg import (
    MAXIMUM_DECODE_PIXELS, MAXIMUM_FRAME_BYTES, MAXIMUM_SEGMENTS, MjpgFrameRejected,
    MjpgLumaLayout, inspect_frame,
)
from app.detection.roi.mjpg_worker import (
    CHILD_ENVIRONMENT, DecodeRequest, MjpgDecoderLimits, MjpgDecoderProcess,
)
from app.detection.roi.runtime import (
    PackedLumaLayout, SceneRuntimeState, SceneSourceState, capture_luma_layout,
)

from tests.test_detector_roi import HEIGHT, SOURCE, WIDTH, pixels
from tests.test_scene_runtime import (
    INTERVAL, MOVED, OTHER, THIRD, Harness, binding, wait_for,
)


SCALE = 8
CAPTURE_WIDTH, CAPTURE_HEIGHT = WIDTH * SCALE, HEIGHT * SCALE
FOURTH = UUID(int=903)
FAKES = Path(__file__).with_name("mjpg_child_fakes.py")
# Test-only limits: a backoff shorter than one harness frame step, so a
# replacement child may start at the next frame.
FAST = MjpgDecoderLimits(restart_backoff_ns=1, maximum_backoff_ns=1, failing_after=2)


def fake(behaviour):
    return (sys.executable, "-I", "-B", str(FAKES), behaviour)


def encode(luma, *, width=WIDTH, height=HEIGHT, scale=SCALE, subsampling="422", quality=100):
    """Upscale a generated luma image and encode it like a UVC YCbCr MJPG frame."""
    image = np.frombuffer(luma, dtype=np.uint8).reshape(height, width)
    image = np.repeat(np.repeat(image, scale, axis=0), scale, axis=1)
    rgb = np.ascontiguousarray(np.stack([image] * 3, axis=-1))
    return simplejpeg.encode_jpeg(rgb, quality=quality, colorsubsampling=subsampling)


def noise_frame(width, height, *, seed=217, subsampling="422"):
    """Synthetic gradient + rectangle + uniform noise frame (no real scene)."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width]
    image = np.stack([(x * 255 // width), (y * 255 // height), (x + y) % 256], axis=-1)
    image[height // 8:height // 3, width // 6:width // 2] = 40
    image = np.clip(image + rng.integers(-12, 12, image.shape), 0, 255).astype(np.uint8)
    return simplejpeg.encode_jpeg(np.ascontiguousarray(image), quality=85,
                                  colorsubsampling=subsampling)


def segment(data, marker):
    """Offset of the first top-level segment with `marker` (generated frames)."""
    position = 2
    while data[position + 1] != marker:
        position += 2 + int.from_bytes(data[position + 2:position + 4], "big")
    return position


def segment_count(data):
    """Top-level segments up to and including `SOS` (generated frames)."""
    position, count = 2, 0
    while True:
        count += 1
        if data[position + 1] == 0xDA:
            return count
        position += 2 + int.from_bytes(data[position + 2:position + 4], "big")


def with_sof(data, width, height):
    offset = segment(data, 0xC0) + 5
    return (data[:offset] + height.to_bytes(2, "big") + width.to_bytes(2, "big")
            + data[offset + 4:])


def scan_start(data):
    position = segment(data, 0xDA)
    return position + 2 + int.from_bytes(data[position + 2:position + 4], "big")


def alive(pid):
    """True while `pid` is a live (not zombie) process."""
    try:
        with open(f"/proc/{pid}/stat") as stat:
            return stat.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return False


class Clock:
    def __init__(self):
        self.value = 0

    def __call__(self):
        return self.value


class DecoderCase(unittest.TestCase):
    def decoder(self, limits=None, *, behaviour=None, clock=None):
        decoder = MjpgDecoderProcess(limits or MjpgDecoderLimits(), MAXIMUM_FRAME_BYTES,
                                     clock_ns=clock or Clock(),
                                     command=fake(behaviour) if behaviour else None)
        self.addCleanup(decoder.close)
        return decoder


class MjpgPrecheckTests(DecoderCase):
    def setUp(self):
        self.frame = encode(pixels())
        self.layout = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT)
        self.child = self.decoder()

    def rejected(self, data, layout=None):
        with self.assertRaises(MjpgFrameRejected) as caught:
            (layout or self.layout).luma(data, WIDTH, HEIGHT, self.child)
        return caught.exception.reason

    def refused_before_decoding(self, data, layout=None):
        unused = mock.Mock()
        with self.assertRaises(MjpgFrameRejected) as caught:
            (layout or self.layout).luma(data, WIDTH, HEIGHT, unused)
        unused.decode.assert_not_called()
        return caught.exception.reason

    def test_valid_frame_decodes_to_reference_luma_in_the_child(self):
        structure = inspect_frame(self.frame, width=CAPTURE_WIDTH, height=CAPTURE_HEIGHT)
        self.assertEqual((3, 16, 8, True, 0), (structure.components, structure.mcu_width,
                                               structure.mcu_height, structure.huffman_tables,
                                               structure.trailing))
        luma = self.layout.luma(self.frame, WIDTH, HEIGHT, self.child)
        self.assertEqual(WIDTH * HEIGHT, len(luma))
        self.assertLessEqual(max(abs(a - b) for a, b in zip(luma, pixels())), 1)
        self.assertNotEqual(os.getpid(), self.child.pid)
        self.assertNotIn("simplejpeg", sys.modules.get("app.detection.roi.mjpg").__dict__)
        # bytearray / flat memoryview capture buffers are read the same way.
        self.assertEqual(luma, self.layout.luma(bytearray(self.frame), WIDTH, HEIGHT, self.child))
        self.assertEqual(luma, self.layout.luma(memoryview(self.frame), WIDTH, HEIGHT, self.child))
        self.assertEqual(1, self.child.status().starts)

    def test_non_flat_capture_buffers_are_refused(self):
        doubled = memoryview(bytes(a for byte in self.frame for a in (byte, 0)))[::2]
        self.assertEqual("frame_type_invalid", self.refused_before_decoding(doubled))
        square = memoryview((self.frame + bytes(4096))[:4096]).cast("B", (64, 64))
        self.assertEqual("frame_type_invalid", self.refused_before_decoding(square))
        wide = memoryview(bytearray(self.frame[:len(self.frame) // 4 * 4])).cast("I")
        self.assertEqual("frame_type_invalid", self.refused_before_decoding(wide))
        self.assertEqual("frame_type_invalid", self.refused_before_decoding("not bytes"))

    def test_grayscale_and_420_frames_decode(self):
        for subsampling in ("420", "444"):
            with self.subTest(subsampling=subsampling):
                luma = self.layout.luma(encode(pixels(), subsampling=subsampling),
                                        WIDTH, HEIGHT, self.child)
                self.assertLessEqual(max(abs(a - b) for a, b in zip(luma, pixels())), 1)
        image = np.repeat(np.repeat(np.frombuffer(pixels(), np.uint8).reshape(HEIGHT, WIDTH),
                                    SCALE, 0), SCALE, 1)[:, :, None]
        gray = simplejpeg.encode_jpeg(np.ascontiguousarray(image), quality=100,
                                      colorspace="GRAY", colorsubsampling="Gray")
        self.assertEqual(1, inspect_frame(gray, width=CAPTURE_WIDTH,
                                          height=CAPTURE_HEIGHT).components)
        luma = self.layout.luma(gray, WIDTH, HEIGHT, self.child)
        self.assertLessEqual(max(abs(a - b) for a, b in zip(luma, pixels())), 1)

    def test_truncated_frame_is_refused(self):
        start = scan_start(self.frame)
        self.assertEqual("missing_eoi", self.refused_before_decoding(
            self.frame[:start + (len(self.frame) - start) // 2]))
        self.assertEqual("missing_soi", self.refused_before_decoding(self.frame[2:]))
        self.assertEqual("missing_soi", self.refused_before_decoding(b""))
        self.assertEqual("segment_invalid", self.refused_before_decoding(
            self.frame[:segment(self.frame, 0xC0) + 6]))

    def test_scan_truncated_and_reterminated_is_refused_by_strict_decoding(self):
        start = scan_start(self.frame)
        for fraction in (0.25, 0.5, 0.75, 0.95):
            with self.subTest(fraction=fraction):
                cut = start + int((len(self.frame) - 2 - start) * fraction)
                data = self.frame[:cut].rstrip(b"\xff") + b"\xff\xd9"
                self.assertEqual("decode_failed", self.rejected(data))
        # A refusal by a healthy child is not a child failure.
        self.assertEqual((1, 0, False), (self.child.status().starts,
                                         self.child.status().failures, self.child.failing))

    def test_missing_eoi_is_refused(self):
        self.assertEqual("missing_eoi", self.refused_before_decoding(self.frame[:-2]))
        self.assertEqual("missing_eoi", self.refused_before_decoding(self.frame[:-2] + bytes(64)))

    def test_bit_flipped_entropy_data_is_refused(self):
        frame = noise_frame(1280, 720)
        layout = MjpgLumaLayout(1280, 720)
        start = scan_start(frame)
        middle = start + (len(frame) - start) // 2
        flipped = bytearray(frame)
        for offset in range(middle, middle + 41):
            flipped[offset] ^= 0x5A
        with self.assertRaises(MjpgFrameRejected):
            layout.luma(bytes(flipped), 320, 180, self.child)
        # A flip that forges a marker inside the scan is refused before decoding.
        forged = bytearray(frame)
        forged[middle:middle + 2] = b"\xff\xc4"
        self.assertEqual("scan_invalid", self.refused_before_decoding(bytes(forged), layout))

    def test_wrong_and_oversized_sof_are_refused_before_decoding(self):
        cases = ((CAPTURE_WIDTH * 2, CAPTURE_HEIGHT), (CAPTURE_WIDTH, CAPTURE_HEIGHT - 8),
                 (65500, 65500), (0, CAPTURE_HEIGHT))
        for width, height in cases:
            with self.subTest(width=width, height=height):
                reason = self.refused_before_decoding(with_sof(self.frame, width, height))
                self.assertIn(reason, ("sof_dimension_mismatch", "sof_invalid"))
        with self.assertRaises(ValueError):
            MjpgLumaLayout(7680, 4320)
        self.assertLessEqual(3840 * 2160, MAXIMUM_DECODE_PIXELS)

    def test_duplicate_sof_and_scan_header_fields_are_refused(self):
        sof = segment(self.frame, 0xC0)
        length = 2 + int.from_bytes(self.frame[sof + 2:sof + 4], "big")
        duplicate = self.frame[:sof] + self.frame[sof:sof + length] + self.frame[sof:]
        self.assertEqual("sof_invalid", self.refused_before_decoding(duplicate))
        sos = segment(self.frame, 0xDA)
        count = sos + 4
        tail = scan_start(self.frame) - 3
        for offset, value in ((count, 1), (count, 2), (tail, 1), (tail + 1, 62),
                              (tail + 2, 0x10), (tail + 2, 0x01)):
            with self.subTest(offset=offset - sos, value=value):
                changed = bytearray(self.frame)
                changed[offset] = value
                self.assertEqual("scan_invalid", self.refused_before_decoding(bytes(changed)))

    def test_segment_and_fill_byte_bounds(self):
        sos = segment(self.frame, 0xDA)
        spare = MAXIMUM_SEGMENTS - segment_count(self.frame)
        comment = b"\xff\xfe\x00\x03x"
        within = self.frame[:sos] + comment * spare + self.frame[sos:]
        inspect_frame(within, width=CAPTURE_WIDTH, height=CAPTURE_HEIGHT)
        over = self.frame[:sos] + comment * (spare + 1) + self.frame[sos:]
        self.assertEqual("segment_invalid", self.refused_before_decoding(over))
        self.assertEqual(len(self.layout.luma(within, WIDTH, HEIGHT, self.child)), WIDTH * HEIGHT)
        filled = self.frame[:sos] + b"\xff" * 16 + self.frame[sos:]
        inspect_frame(filled, width=CAPTURE_WIDTH, height=CAPTURE_HEIGHT)
        overfilled = self.frame[:sos] + b"\xff" * 17 + self.frame[sos:]
        self.assertEqual("marker_invalid", self.refused_before_decoding(overfilled))

    def test_total_frame_size_is_bounded_in_both_checks(self):
        with mock.patch.object(mjpg, "MAXIMUM_FRAME_BYTES", len(self.frame) - 1):
            with self.assertRaises(MjpgFrameRejected) as caught:
                inspect_frame(self.frame, width=CAPTURE_WIDTH, height=CAPTURE_HEIGHT)
            self.assertEqual("frame_too_large", caught.exception.reason)
            # The wrapper refuses an oversized buffer before copying or
            # parsing it.
            with mock.patch.object(mjpg, "inspect_frame") as inspect:
                self.assertEqual("frame_too_large",
                                 self.refused_before_decoding(bytearray(self.frame)))
            inspect.assert_not_called()
        # The child is told the same bound and the parent never sends more.
        with self.assertRaises(mjpg_worker.DecoderRefusal):
            self.child.decode(bytes(MAXIMUM_FRAME_BYTES + 1),
                              DecodeRequest(WIDTH, HEIGHT, WIDTH, HEIGHT, 8, 8, 2))
        self.assertIsNone(self.child.pid)

    def test_trailing_padding_is_bounded(self):
        layout = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, maximum_trailing_bytes=64)
        expected = layout.luma(self.frame, WIDTH, HEIGHT, self.child)
        self.assertEqual(expected, layout.luma(self.frame + bytes(64), WIDTH, HEIGHT, self.child))
        self.assertEqual(64, inspect_frame(self.frame + bytes(64), width=CAPTURE_WIDTH,
                                           height=CAPTURE_HEIGHT,
                                           maximum_trailing=64).trailing)
        self.assertEqual("trailing_bytes_exceeded",
                         self.refused_before_decoding(self.frame + bytes(65), layout))
        # A second EOI or a second image after the frame is not padding.
        self.assertEqual("trailing_marker",
                         self.refused_before_decoding(self.frame + b"\x00\xff\xd9", layout))
        self.assertEqual("trailing_marker",
                         self.refused_before_decoding(self.frame + b"\xff\xd8\xff", layout))
        with self.assertRaises(ValueError):
            MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, maximum_trailing_bytes=-1)

    def test_extraneous_bytes_and_unsupported_processes_are_refused(self):
        before = segment(self.frame, 0xDA)
        self.assertEqual("marker_invalid", self.refused_before_decoding(
            self.frame[:before] + bytes(16) + self.frame[before:]))
        sof = segment(self.frame, 0xC0)
        progressive = self.frame[:sof + 1] + b"\xc2" + self.frame[sof + 2:]
        self.assertEqual("unsupported_process", self.refused_before_decoding(progressive))
        double = self.frame[:2] + self.frame[2:-2] + self.frame[2:]
        self.assertIn(self.refused_before_decoding(double), ("scan_invalid", "sof_invalid"))
        self.assertEqual("marker_invalid", self.refused_before_decoding(b"\xff\xd8\xff\xd9"))

    def test_missing_or_unreviewed_decoder_is_unavailable(self):
        self.assertTrue(self.layout.available())
        for package in ("simplejpeg", "numpy"):
            with self.subTest(package=package):
                real = mjpg.importlib.metadata.version

                def version(name, package=package):
                    return "0.0" if name == package else real(name)

                with mock.patch("importlib.metadata.version", version):
                    self.assertFalse(mjpg.decoder_available())
                    self.assertEqual("decoder_unavailable", self.refused_before_decoding(self.frame))
        with mock.patch("importlib.metadata.version", side_effect=ImportError):
            self.assertFalse(mjpg.decoder_available())
        with mock.patch.object(mjpg, "CHILD", Path("/nonexistent/mjpg_child.py")):
            self.assertFalse(mjpg.decoder_available())

    def test_dct_scale_and_reference_compatibility(self):
        frame = noise_frame(1280, 720)
        layout = MjpgLumaLayout(1280, 720)
        for size in ((160, 90), (320, 180), (640, 360), (1280, 720), (80, 45)):
            with self.subTest(size=size):
                self.assertTrue(layout.compatible(*size))
                self.assertEqual(size[0] * size[1], len(layout.luma(frame, *size, self.child)))
        self.assertFalse(layout.compatible(300, 180))
        unused = mock.Mock()
        with self.assertRaises(MjpgFrameRejected) as caught:
            layout.luma(frame, 300, 180, unused)
        unused.decode.assert_not_called()
        self.assertEqual("reference_incompatible", caught.exception.reason)

    def test_negotiated_format_selects_the_reviewed_reader(self):
        self.assertIsInstance(capture_luma_layout(1920, 1080, "MJPG"), MjpgLumaLayout)
        self.assertIsInstance(capture_luma_layout(640, 480, "YUYV"), PackedLumaLayout)
        for fourcc in ("H264", "NV12"):
            with self.assertRaises(ValueError):
                capture_luma_layout(640, 480, fourcc)


class FakeSimplejpeg:
    """Records the decode arguments; returns a prepared array."""

    def __init__(self, result):
        self.result, self.calls = result, []

    def decode_jpeg(self, data, **options):
        self.calls.append(options)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def child_request(scaled=(WIDTH, HEIGHT), output=(WIDTH, HEIGHT), mcu=(2, 1), band=7):
    header = DecodeRequest(*scaled, *output, *mcu, band).header(5)
    return bytearray(header + b"jpeg")


class MjpgChildDecodeTests(unittest.TestCase):
    """The child's decode step, with a stand-in decoder (no native code)."""

    def image(self):
        return np.frombuffer(pixels(), np.uint8).reshape(HEIGHT, WIDTH, 1).copy()

    def test_strict_accurate_luma_decode_options(self):
        decoder = FakeSimplejpeg(self.image())
        pixels_out, refusal = mjpg_child._decode(decoder, np, child_request())
        self.assertEqual((pixels(), 0), (pixels_out, refusal))
        self.assertEqual([dict(colorspace="GRAY", fastdct=False, fastupsample=False,
                               min_width=WIDTH, min_height=HEIGHT, strict=True)], decoder.calls)

    def test_decoder_error_shape_and_dtype_are_refused(self):
        cases = ((ValueError("synthetic libjpeg warning"), mjpg_child.DECODE_FAILED),
                 (np.zeros((HEIGHT, WIDTH + 1, 1), np.uint8), mjpg_child.SHAPE_MISMATCH),
                 (np.zeros((HEIGHT, WIDTH), np.uint8), mjpg_child.SHAPE_MISMATCH),
                 (np.zeros((HEIGHT, WIDTH, 1), np.uint16), mjpg_child.SHAPE_MISMATCH),
                 (self.image().tolist(), mjpg_child.SHAPE_MISMATCH))
        for result, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual((None, expected),
                                 mjpg_child._decode(FakeSimplejpeg(result), np, child_request()))

    def test_undecoded_mid_grey_band_is_refused(self):
        image = self.image()
        # libjpeg stopped mid-row: the last 7 MCUs (2x1 at 1/8) are 128.
        image.reshape(-1)[-14:] = 128
        self.assertEqual((None, mjpg_child.UNDECODED_BAND),
                         mjpg_child._decode(FakeSimplejpeg(image), np, child_request()))
        # Six trailing MCUs are not the band.
        image = self.image()
        image.reshape(-1)[-12:] = 128
        self.assertIsNotNone(mjpg_child._decode(FakeSimplejpeg(image), np, child_request())[0])
        # A dark (covered-lens-like) uniform frame is not mistaken for the band;
        # an exactly mid-grey uniform scene is (documented false positive).
        dark = np.full((HEIGHT, WIDTH, 1), 4, np.uint8)
        self.assertIsNotNone(mjpg_child._decode(FakeSimplejpeg(dark), np, child_request())[0])
        grey = np.full((HEIGHT, WIDTH, 1), 128, np.uint8)
        self.assertEqual(mjpg_child.UNDECODED_BAND,
                         mjpg_child._decode(FakeSimplejpeg(grey), np, child_request())[1])

    def test_decimation_and_invalid_requests(self):
        image = np.arange(4 * WIDTH * HEIGHT, dtype=np.uint32).astype(np.uint8)
        image = image.reshape(HEIGHT * 2, WIDTH * 2, 1)
        output, _ = mjpg_child._decode(FakeSimplejpeg(image), np, child_request(
            scaled=(WIDTH * 2, HEIGHT * 2)))
        self.assertEqual(image[::2, ::2, 0].tobytes(), output)
        for request in (child_request(scaled=(WIDTH + 1, HEIGHT)), child_request(band=0),
                        child_request(mcu=(0, 1))):
            with self.assertRaises(ValueError):
                mjpg_child._decode(FakeSimplejpeg(self.image()), np, request)


class MjpgDecoderProcessTests(DecoderCase):
    REQUEST = DecodeRequest(WIDTH, HEIGHT, WIDTH, HEIGHT, 2, 1, 7)

    def setUp(self):
        self.frame = encode(pixels())
        self.layout = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT)

    def refused(self, decoder, data=None, layout=None):
        with self.assertRaises(MjpgFrameRejected) as caught:
            (layout or self.layout).luma(data or self.frame, WIDTH, HEIGHT, decoder)
        return caught.exception.reason

    def test_child_is_confined_and_limited(self):
        decoder = self.decoder(MjpgDecoderLimits(address_space_bytes=200 * 1024 * 1024))
        self.layout.luma(self.frame, WIDTH, HEIGHT, decoder)
        with open(f"/proc/{decoder.pid}/status") as status:
            fields = dict(line.split(":", 1) for line in status)
        self.assertEqual(("1", "1", str(os.getpid())),
                         (fields["NoNewPrivs"].strip(), fields["Threads"].strip(),
                          fields["PPid"].strip()))
        self.assertEqual(os.getuid(), int(fields["Uid"].split()[0]))
        with open(f"/proc/{decoder.pid}/limits") as limits:
            values = {line[:26].strip(): line[26:].split()[:2] for line in limits}
        self.assertEqual([str(200 * 1024 * 1024)] * 2, values["Max address space"])
        self.assertEqual(["16", "16"], values["Max open files"])
        self.assertEqual(["0", "0"], values["Max processes"])
        self.assertEqual(["0", "0"], values["Max core file size"])
        self.assertEqual(["0", "0"], values["Max file size"])
        self.assertEqual(10, os.getpriority(os.PRIO_PROCESS, decoder.pid))
        # Not dumpable: another process of the service account cannot read
        # its memory or environment.
        with self.assertRaises(PermissionError):
            open(f"/proc/{decoder.pid}/environ").close()

    def test_child_gets_minimal_environment_and_only_its_socket(self):
        decoder = self.decoder(behaviour="inspect")
        with mock.patch.dict(os.environ, {"SERVERSENTINEL_SYNTHETIC_SECRET": "x"}):
            report = decoder.decode(b"\xff", DecodeRequest(64, 64, 64, 64, 8, 8, 8))
        report = json.loads(report)
        self.assertEqual(CHILD_ENVIRONMENT, report["environment"])
        # stdio, the private socket and the descriptor listing itself.
        self.assertEqual(5, len(report["descriptors"]))
        self.assertEqual([0, 1, 2], report["descriptors"][:3])
        self.assertIn(report["socket"], report["descriptors"])

    def test_idle_child_kill_is_unknown_then_respawned_after_backoff(self):
        clock = Clock()
        decoder = self.decoder(MjpgDecoderLimits(restart_backoff_ns=100), clock=clock)
        first = self.layout.luma(self.frame, WIDTH, HEIGHT, decoder)
        pid = decoder.pid
        os.kill(pid, signal.SIGKILL)
        self.assertTrue(wait_for(lambda: not alive(pid)))
        self.assertEqual("decoder_crashed", self.refused(decoder))
        self.assertEqual("backoff", decoder.status().state)
        # During the backoff a frame is refused at once, never waited on.
        started = time.monotonic()
        self.assertEqual("decoder_unavailable", self.refused(decoder))
        self.assertLess(time.monotonic() - started, 0.1)
        clock.value = 100
        self.assertEqual(first, self.layout.luma(self.frame, WIDTH, HEIGHT, decoder))
        self.assertNotEqual(pid, decoder.pid)
        status = decoder.status()
        self.assertEqual((2, 1, 0), (status.starts, status.crashes, status.consecutive_failures))

    def test_hung_child_is_killed_at_the_frame_deadline(self):
        decoder = self.decoder(MjpgDecoderLimits(frame_timeout_ns=300_000_000))
        self.layout.luma(self.frame, WIDTH, HEIGHT, decoder)
        pid = decoder.pid
        os.kill(pid, signal.SIGSTOP)
        started = time.monotonic()
        self.assertEqual("decoder_timeout", self.refused(decoder))
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertFalse(alive(pid))
        self.assertEqual(1, decoder.status().timeouts)
        hang = self.decoder(MjpgDecoderLimits(frame_timeout_ns=300_000_000), behaviour="hang")
        self.assertEqual("decoder_timeout", self.refused(hang))
        self.assertIsNone(hang.pid)

    def test_crashing_child_is_unknown(self):
        for behaviour in ("exit", "sigkill"):
            with self.subTest(behaviour=behaviour):
                decoder = self.decoder(behaviour=behaviour)
                self.assertEqual("decoder_crashed", self.refused(decoder))
                self.assertEqual(1, decoder.status().crashes)
                self.assertIsNone(decoder.pid)

    def test_malformed_replies_are_protocol_failures(self):
        limits = MjpgDecoderLimits(frame_timeout_ns=300_000_000)
        for behaviour, reason in (("short", "decoder_protocol"), ("wrong_id", "decoder_protocol"),
                                  ("wrong_kind", "decoder_protocol"),
                                  ("bad_refusal", "decoder_protocol"),
                                  ("oversized", "decoder_protocol"),
                                  ("partial", "decoder_timeout")):
            with self.subTest(behaviour=behaviour):
                decoder = self.decoder(limits, behaviour=behaviour)
                self.assertEqual(reason, self.refused(decoder))
                self.assertIsNone(decoder.pid)
                self.assertEqual(1, decoder.status().failures)

    def test_failed_starts_are_unavailable(self):
        limits = MjpgDecoderLimits(start_timeout_ns=300_000_000)
        for behaviour in ("exit_at_start", "hang_at_start", "wrong_ready"):
            with self.subTest(behaviour=behaviour):
                decoder = self.decoder(limits, behaviour=behaviour)
                self.assertEqual("decoder_unavailable", self.refused(decoder))
                self.assertEqual(1, decoder.status().start_failures)
                self.assertIsNone(decoder.pid)
        # The real child refuses to start with any other numpy version.
        with mock.patch.object(mjpg_worker, "NUMPY_VERSION", "0.0"):
            decoder = self.decoder(limits)
            self.assertEqual("decoder_unavailable", self.refused(decoder))
        self.assertEqual(1, decoder.status().start_failures)

    def test_memory_cap_exceeded_is_unknown(self):
        # Too small for the interpreter with numpy: the start fails.
        tiny = self.decoder(MjpgDecoderLimits(address_space_bytes=64 * 1024 * 1024))
        self.assertEqual("decoder_unavailable", self.refused(tiny))
        self.assertEqual(1, tiny.status().start_failures)
        # Just above the started child's size: a full-size 4K decode cannot
        # allocate its output.
        probe = self.decoder()
        self.layout.luma(self.frame, WIDTH, HEIGHT, probe)
        with open(f"/proc/{probe.pid}/status") as status:
            size = next(int(line.split()[1]) for line in status if line.startswith("VmSize"))
        cap = (size + 4096) * 1024
        clock = Clock()
        tight = self.decoder(MjpgDecoderLimits(address_space_bytes=cap, restart_backoff_ns=1,
                                               maximum_backoff_ns=1), clock=clock)
        layout = MjpgLumaLayout(3840, 2160)
        frame = noise_frame(3840, 2160, subsampling="444")
        with self.assertRaises(MjpgFrameRejected) as caught:
            layout.luma(frame, 3840, 2160, tight)
        self.assertIn(caught.exception.reason, ("decode_failed", "decoder_crashed"))
        clock.value += 10
        # The child (or its replacement) still decodes a frame that fits.
        self.assertEqual(WIDTH * HEIGHT, len(self.layout.luma(self.frame, WIDTH, HEIGHT, tight)))

    def test_repeated_failures_report_failing_until_a_success(self):
        clock = Clock()
        decoder = self.decoder(FAST, behaviour="exit_second", clock=clock)
        self.assertEqual(WIDTH * HEIGHT, len(decoder.decode(b"\xff", self.REQUEST)))
        for count in range(1, 3):
            clock.value += 10
            with self.assertRaises(mjpg_worker.DecoderRefusal):
                decoder.decode(b"\xff", self.REQUEST)
            clock.value += 10
            # A replacement child answers the first frame, then exits again.
            self.assertEqual(WIDTH * HEIGHT, len(decoder.decode(b"\xff", self.REQUEST)))
            self.assertFalse(decoder.failing)
        always = self.decoder(FAST, behaviour="exit", clock=clock)
        for count in range(1, 4):
            clock.value += 10
            with self.assertRaises(mjpg_worker.DecoderRefusal):
                always.decode(b"\xff", self.REQUEST)
            self.assertEqual(count >= 2, always.failing)

    def test_backoff_is_exponential_and_bounded(self):
        clock = Clock()
        limits = MjpgDecoderLimits(restart_backoff_ns=10, maximum_backoff_ns=35)
        decoder = self.decoder(limits, behaviour="exit_at_start", clock=clock)
        waits = []
        for _ in range(4):
            with self.assertRaises(mjpg_worker.DecoderRefusal):
                decoder.decode(b"\xff", self.REQUEST)
            waits.append(decoder._retry_at - clock.value)
            clock.value = decoder._retry_at
        self.assertEqual([10, 20, 35, 35], waits)

    def test_close_reaps_and_retire_prevents_restart(self):
        decoder = self.decoder()
        self.layout.luma(self.frame, WIDTH, HEIGHT, decoder)
        pid = decoder.pid
        self.assertTrue(decoder.close())
        self.assertFalse(alive(pid))
        self.assertEqual("decoder_unavailable", self.refused(decoder))
        self.assertTrue(decoder.close())
        retired = self.decoder()
        retired.retire()
        self.assertEqual("decoder_unavailable", self.refused(retired))
        self.assertIsNone(retired.pid)

    def test_limits_are_validated(self):
        for changes in (dict(frame_timeout_ns=0), dict(address_space_bytes=1 << 20),
                        dict(open_files=4), dict(niceness=20), dict(restart_backoff_ns=0),
                        dict(restart_backoff_ns=10, maximum_backoff_ns=5),
                        dict(failing_after=0), dict(start_timeout_ns=-1),
                        dict(frame_timeout_ns=1.5)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                MjpgDecoderLimits(**changes)
        with self.assertRaises(ValueError):
            MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, decoder=None)

    def test_child_dies_with_its_parent(self):
        """No orphan: SIGKILL the parent and the decode child goes too."""
        program = (
            "import sys, time\n"
            "from app.detection.roi.mjpg_worker import *\n"
            "from app.detection.roi.mjpg import MAXIMUM_FRAME_BYTES\n"
            "decoder = MjpgDecoderProcess(MjpgDecoderLimits(), MAXIMUM_FRAME_BYTES)\n"
            "frame = sys.stdin.buffer.read()\n"
            "decoder.decode(frame, DecodeRequest(%d, %d, %d, %d, 2, 1, 7))\n"
            "print(decoder.pid, flush=True)\n"
            "time.sleep(60)\n" % (WIDTH, HEIGHT, WIDTH, HEIGHT))
        parent = subprocess.Popen([sys.executable, "-c", program], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, cwd=Path(__file__).parents[1])
        self.addCleanup(parent.stdout.close)
        self.addCleanup(parent.wait)
        self.addCleanup(parent.kill)
        parent.stdin.write(self.frame)
        parent.stdin.close()
        pid = int(parent.stdout.readline())
        self.assertTrue(alive(pid))
        parent.kill()
        parent.wait()
        self.assertTrue(wait_for(lambda: not alive(pid)))


class MjpgHarness(Harness):
    def frame(self, luma=None, source=SOURCE, advance=INTERVAL, data=None):
        self.clock.value += advance
        number = self.sequence.get(source, 0) + 1
        self.sequence[source] = number
        before = self._handled(source)
        payload = data if data is not None else encode(luma or pixels())
        self.runtime.on_uvc_frame(source, VideoFrame(payload, number, 0.0))
        if self.threaded:
            assert wait_for(lambda: self._handled(source) > before)
        else:
            self.runtime.step()
        return self.source(source)

    def use(self, source, behaviour=None, limits=FAST):
        """Replace a source's decode child with a synthetic stand-in."""
        self.runtime._contexts[source].decoder = MjpgDecoderProcess(
            limits, MAXIMUM_FRAME_BYTES, clock_ns=self.clock,
            command=fake(behaviour) if behaviour else None)

    def pid(self, source=SOURCE):
        return self.runtime._contexts[source].decoder.pid


MJPG_LAYOUT = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT)
FAST_LAYOUT = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, decoder=FAST)


class SceneRuntimeMjpgTests(unittest.TestCase):
    def harness(self, *bindings, **options):
        harness = MjpgHarness(*bindings, **options)
        self.addCleanup(harness.runtime.stop)
        return harness

    def test_local_uvc_mjpg_frames_confirm_server_movement(self):
        harness = self.harness(binding(layout=MJPG_LAYOUT))
        harness.runtime.start()
        harness.frame()
        self.assertEqual(Observation.ABSENT, harness.frame().movement)
        harness.frame(MOVED)
        confirmed = harness.frame(MOVED)
        self.assertEqual(Observation.PRESENT, confirmed.movement)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())
        self.assertNotEqual(os.getpid(), harness.pid())

    def test_corrupt_mjpg_frame_is_unknown_never_no_movement(self):
        harness = self.harness(binding(layout=MJPG_LAYOUT), binding(OTHER, layout=MJPG_LAYOUT))
        harness.runtime.start()
        for _ in range(2):
            harness.frame(source=OTHER, advance=0)
            harness.frame()
        good = encode(pixels())
        start = scan_start(good)
        corrupt = (good[:start + (len(good) - start) // 2],
                   with_sof(good, CAPTURE_WIDTH * 2, CAPTURE_HEIGHT),
                   good + bytes(mjpg.DEFAULT_TRAILING_BYTES + 1), good[:-2],
                   good[:start + (len(good) - start) // 2].rstrip(b"\xff") + b"\xff\xd9")
        for index, data in enumerate(corrupt, 1):
            with self.subTest(index=index):
                harness.frame(source=OTHER, advance=0, data=data)
                harness.frame()
                broken = harness.source(OTHER)
                self.assertEqual("frame_undecodable", broken.reason)
                self.assertIs(SceneSourceState.DEGRADED, broken.state)
                self.assertEqual((Observation.UNKNOWN, Observation.UNKNOWN),
                                 (broken.movement, broken.tamper))
                self.assertEqual(index, broken.unusable)
        self.assertEqual((("decode_failed", 1), ("missing_eoi", 2), ("sof_dimension_mismatch", 1),
                          ("trailing_bytes_exceeded", 1)),
                         harness.source(OTHER).undecodable_reasons)
        # The other source keeps running.
        self.assertEqual(Observation.ABSENT, harness.source().movement)
        self.assertEqual((), harness.source().undecodable_reasons)
        self.assertEqual([], harness.recorder.items)

    def test_child_crash_is_unknown_and_a_replacement_resumes(self):
        harness = self.harness(binding(layout=FAST_LAYOUT), binding(OTHER, layout=FAST_LAYOUT))
        harness.runtime.start()
        harness.frame(source=OTHER, advance=0)
        harness.frame()
        self.assertEqual(Observation.ABSENT, harness.frame().movement)
        pid, other = harness.pid(), harness.pid(OTHER)
        self.assertNotEqual(pid, other)
        os.kill(pid, signal.SIGKILL)
        self.assertTrue(wait_for(lambda: not alive(pid)))
        broken = harness.frame(MOVED)
        self.assertEqual(("frame_undecodable", Observation.UNKNOWN, Observation.UNKNOWN, 1),
                         (broken.reason, broken.movement, broken.tamper, broken.decoder_failures))
        self.assertEqual((("decoder_crashed", 1),), broken.undecodable_reasons)
        # The replacement starts after the backoff and evaluation resumes.
        resumed = harness.frame()
        self.assertIs(SceneSourceState.ACTIVE, resumed.state)
        self.assertNotEqual(pid, harness.pid())
        # The other source's child was never affected.
        self.assertEqual(other, harness.pid(OTHER))
        self.assertEqual(SceneSourceState.ACTIVE, harness.frame(source=OTHER, advance=0).state)
        self.assertEqual([], harness.recorder.items)

    def test_hung_child_is_killed_and_the_frame_is_unknown(self):
        limits = MjpgDecoderLimits(frame_timeout_ns=300_000_000, restart_backoff_ns=1,
                                   maximum_backoff_ns=1)
        harness = self.harness(binding(layout=FAST_LAYOUT))
        harness.use(SOURCE, "hang", limits)
        harness.runtime.start()
        source = harness.frame()
        self.assertEqual(("frame_undecodable", (("decoder_timeout", 1),)),
                         (source.reason, source.undecodable_reasons))
        self.assertIsNone(harness.pid())

    def test_repeated_failures_lower_the_source_and_the_runtime(self):
        harness = self.harness(binding(layout=FAST_LAYOUT), binding(OTHER, layout=FAST_LAYOUT))
        harness.use(SOURCE, "exit")
        harness.runtime.start()
        harness.frame(source=OTHER, advance=0)
        harness.frame(source=OTHER, advance=0)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            for _ in range(4):
                source = harness.frame(MOVED)
        self.assertEqual(1, sum("scene_frame_decoder_failing" in line for line in logs.output))
        self.assertTrue(all("scene_frame_decoder" in line for line in logs.output))
        self.assertEqual((SceneSourceState.DEGRADED, "frame_decoder_failing", Observation.UNKNOWN),
                         (source.state, source.reason, source.movement))
        self.assertEqual(4, source.decoder_failures)
        status = harness.runtime.status()
        self.assertIs(SceneRuntimeState.DEGRADED, status.state)
        # One successful exchange clears it, logged once.
        harness.use(SOURCE)
        with self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            harness.frame()
            recovered = harness.frame()
        self.assertEqual(1, sum("scene_frame_decoder_recovered" in line for line in logs.output))
        self.assertIs(SceneSourceState.ACTIVE, recovered.state)
        self.assertEqual([], harness.recorder.items)

    def test_decoder_unavailable_keeps_source_inactive(self):
        with mock.patch.object(mjpg, "decoder_available", return_value=False):
            harness = self.harness(binding(layout=MJPG_LAYOUT))
            harness.runtime.start()
            for luma in (None, MOVED, MOVED, MOVED):
                source = harness.frame(luma)
        self.assertIs(SceneSourceState.INACTIVE, source.state)
        self.assertEqual("frame_decoder_unavailable", source.reason)
        self.assertEqual(Observation.UNKNOWN, source.movement)
        self.assertIsNone(harness.pid())
        self.assertEqual([], harness.recorder.items)

    def test_without_calibration_mjpg_source_fails_closed(self):
        harness = self.harness(binding(layout=MJPG_LAYOUT), calibrations=None)
        harness.runtime.start()
        for luma in (None, MOVED, MOVED):
            source = harness.frame(luma)
        self.assertEqual("calibration_provider_unconfigured", source.reason)
        self.assertEqual(0, source.evaluated)
        self.assertIsNone(harness.pid())
        harness = self.harness(binding(layout=MJPG_LAYOUT), recorder=False)
        self.assertEqual("critical_recorder_unavailable",
                         harness.runtime.start().sources[0].reason)

    def test_incompatible_mjpg_layout_is_not_bound(self):
        harness = self.harness(binding(layout=MjpgLumaLayout(CAPTURE_WIDTH + 4, CAPTURE_HEIGHT)))
        harness.runtime.start()
        self.assertEqual("capture_layout_incompatible", harness.frame().reason)
        with self.assertRaises(ValueError):
            binding(source_type=SourceType.REMOTE_AGENT, layout=MJPG_LAYOUT)

    def test_decoding_runs_on_the_scene_worker_not_the_capture_thread(self):
        threads = []
        original = MjpgLumaLayout.luma

        def recording(layout, data, width, height, decoder):
            threads.append(threading.current_thread().name)
            return original(layout, data, width, height, decoder)

        with mock.patch.object(MjpgLumaLayout, "luma", recording):
            harness = self.harness(binding(layout=MJPG_LAYOUT))
            harness.runtime.start()
            harness.clock.value += INTERVAL
            harness.runtime.on_uvc_frame(SOURCE, VideoFrame(encode(pixels()), 1, 0.0))
            self.assertEqual([], threads)  # the capture callback only queues
            self.assertIsNone(harness.pid())
            harness.runtime.step()
            self.assertEqual(1, len(threads))
            threaded = MjpgHarness(binding(layout=MJPG_LAYOUT), threaded=True)
            threaded.runtime.start()
            try:
                threaded.frame()
            finally:
                threaded.runtime.stop()
        self.assertEqual("scene-monitoring", threads[-1])

    def test_stop_kills_and_reaps_every_child(self):
        harness = MjpgHarness(binding(layout=MJPG_LAYOUT), binding(OTHER, layout=MJPG_LAYOUT),
                              threaded=True)
        harness.runtime.start()
        try:
            harness.frame()
            harness.frame(source=OTHER, advance=0)
            pids = (harness.pid(), harness.pid(OTHER))
            self.assertTrue(all(alive(pid) for pid in pids))
            # One child hangs in the middle of a frame when stop() begins.
            os.kill(pids[1], signal.SIGSTOP)
            harness.clock.value += INTERVAL
            harness.runtime.on_uvc_frame(OTHER, VideoFrame(encode(pixels()), 99, 0.0))
        finally:
            started = time.monotonic()
            status = harness.runtime.stop()
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertIs(SceneRuntimeState.STOPPED, status.state)
        self.assertFalse(any(alive(pid) for pid in pids))
        self.assertEqual((None, None), (harness.pid(), harness.pid(OTHER)))

    def test_stop_reports_failure_when_a_child_cannot_be_reaped(self):
        harness = self.harness(binding(layout=MJPG_LAYOUT))
        harness.runtime.start()
        harness.frame()
        with mock.patch.object(MjpgDecoderProcess, "close", return_value=False), \
                self.assertLogs("app.detection.roi.runtime", level="ERROR") as logs:
            status = harness.runtime.stop()
        self.assertTrue(any("scene_monitoring_stop_failed" in line for line in logs.output))
        self.assertIs(SceneRuntimeState.STOP_FAILED, status.state)

    def test_four_sources_at_one_frame_per_second_fit_the_budget(self):
        """Performance smoke: 4 sources x 1 fps, synthetic 1080p 4:2:2 frames."""
        layout = MjpgLumaLayout(1920, 1080)
        decoders = [MjpgDecoderProcess(layout.decoder, MAXIMUM_FRAME_BYTES) for _ in range(4)]
        for decoder in decoders:
            self.addCleanup(decoder.close)
        frames = [noise_frame(1920, 1080, seed=seed) for seed in range(4)]
        for decoder, frame in zip(decoders, frames):
            layout.luma(frame, 480, 270, decoder)  # child start, not timed
        rounds, durations = [], []
        for _ in range(5):
            started = time.perf_counter()
            for decoder, frame in zip(decoders, frames):
                before = time.perf_counter()
                layout.luma(frame, 480, 270, decoder)
                durations.append(time.perf_counter() - before)
            rounds.append(time.perf_counter() - started)
        # Generous bounds for a shared CI core; measured values are a few ms
        # per frame. One round must fit well inside the 1 s sampling interval.
        self.assertLess(statistics.median(durations), 0.1)
        self.assertLess(max(rounds), 0.5)
        self.assertEqual([1] * 4, [decoder.status().starts for decoder in decoders])
        # The runtime with four MJPG sources evaluates each through its child.
        sources = (SOURCE, OTHER, THIRD, FOURTH)
        harness = self.harness(*(binding(item, layout=MJPG_LAYOUT) for item in sources))
        harness.runtime.start()
        for item in sources:
            self.assertEqual(1, harness.frame(source=item, advance=0).evaluated)
        self.assertEqual(4, len({harness.pid(item) for item in sources}))


if __name__ == "__main__":
    unittest.main()
