"""Reviewed MJPG luma reader (Issue #217) with generated synthetic JPEGs only.

Every frame is generated in memory with numpy and encoded with the reviewed
simplejpeg encoder; no camera, real scene or person is used.
"""

import statistics
import threading
import time
import unittest
from unittest import mock

import numpy as np
import simplejpeg

from app.cameras.registry.models import SourceType
from app.cameras.uvc.capture import VideoFrame
from app.detection.foundation import Observation
from app.detection.roi import CriticalKind
from app.detection.roi import mjpg
from app.detection.roi.mjpg import (
    MAXIMUM_DECODE_PIXELS, MjpgFrameRejected, MjpgLumaLayout, inspect_frame,
)
from app.detection.roi.runtime import (
    PackedLumaLayout, SceneSourceState, capture_luma_layout,
)

from tests.test_detector_roi import HEIGHT, SOURCE, WIDTH, pixels
from tests.test_scene_runtime import (
    INTERVAL, MOVED, OTHER, Harness, binding, wait_for,
)


SCALE = 8
CAPTURE_WIDTH, CAPTURE_HEIGHT = WIDTH * SCALE, HEIGHT * SCALE


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


def with_sof(data, width, height):
    offset = segment(data, 0xC0) + 5
    return (data[:offset] + height.to_bytes(2, "big") + width.to_bytes(2, "big")
            + data[offset + 4:])


def scan_start(data):
    position = segment(data, 0xDA)
    return position + 2 + int.from_bytes(data[position + 2:position + 4], "big")


class Ticks:
    """Deterministic decode clock advancing by `step` ns per read."""

    def __init__(self, step):
        self.value, self.step = 0, step

    def __call__(self):
        self.value += self.step
        return self.value


class MjpgPrecheckTests(unittest.TestCase):
    def setUp(self):
        self.frame = encode(pixels())
        self.layout = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT)

    def rejected(self, data, layout=None):
        with self.assertRaises(MjpgFrameRejected) as caught:
            (layout or self.layout).luma(data, WIDTH, HEIGHT)
        return caught.exception.reason

    def test_valid_frame_decodes_to_reference_luma(self):
        structure = inspect_frame(self.frame, width=CAPTURE_WIDTH, height=CAPTURE_HEIGHT)
        self.assertEqual((3, 16, 8, True, 0), (structure.components, structure.mcu_width,
                                               structure.mcu_height, structure.huffman_tables,
                                               structure.trailing))
        luma = self.layout.luma(self.frame, WIDTH, HEIGHT)
        self.assertEqual(WIDTH * HEIGHT, len(luma))
        self.assertLessEqual(max(abs(a - b) for a, b in zip(luma, pixels())), 1)
        # bytearray / memoryview capture buffers are read the same way.
        self.assertEqual(luma, self.layout.luma(bytearray(self.frame), WIDTH, HEIGHT))
        self.assertEqual(luma, self.layout.luma(memoryview(self.frame), WIDTH, HEIGHT))

    def test_grayscale_and_420_frames_decode(self):
        for subsampling in ("420", "444"):
            with self.subTest(subsampling=subsampling):
                luma = self.layout.luma(encode(pixels(), subsampling=subsampling), WIDTH, HEIGHT)
                self.assertLessEqual(max(abs(a - b) for a, b in zip(luma, pixels())), 1)
        image = np.repeat(np.repeat(np.frombuffer(pixels(), np.uint8).reshape(HEIGHT, WIDTH),
                                    SCALE, 0), SCALE, 1)[:, :, None]
        gray = simplejpeg.encode_jpeg(np.ascontiguousarray(image), quality=100,
                                      colorspace="GRAY", colorsubsampling="Gray")
        self.assertEqual(1, inspect_frame(gray, width=CAPTURE_WIDTH,
                                          height=CAPTURE_HEIGHT).components)
        luma = self.layout.luma(gray, WIDTH, HEIGHT)
        self.assertLessEqual(max(abs(a - b) for a, b in zip(luma, pixels())), 1)

    def test_truncated_frame_is_refused(self):
        start = scan_start(self.frame)
        self.assertEqual("missing_eoi",
                         self.rejected(self.frame[:start + (len(self.frame) - start) // 2]))
        self.assertEqual("missing_soi", self.rejected(self.frame[2:]))
        self.assertEqual("missing_soi", self.rejected(b""))
        self.assertEqual("segment_invalid", self.rejected(self.frame[:segment(self.frame, 0xC0) + 6]))

    def test_scan_truncated_and_reterminated_is_refused_by_strict_decoding(self):
        start = scan_start(self.frame)
        for fraction in (0.25, 0.5, 0.75, 0.95):
            with self.subTest(fraction=fraction):
                cut = start + int((len(self.frame) - 2 - start) * fraction)
                data = self.frame[:cut].rstrip(b"\xff") + b"\xff\xd9"
                self.assertEqual("decode_failed", self.rejected(data))

    def test_missing_eoi_is_refused(self):
        self.assertEqual("missing_eoi", self.rejected(self.frame[:-2]))
        self.assertEqual("missing_eoi", self.rejected(self.frame[:-2] + bytes(64)))

    def test_bit_flipped_entropy_data_is_refused(self):
        frame = noise_frame(1280, 720)
        layout = MjpgLumaLayout(1280, 720)
        start = scan_start(frame)
        middle = start + (len(frame) - start) // 2
        flipped = bytearray(frame)
        for offset in range(middle, middle + 41):
            flipped[offset] ^= 0x5A
        with self.assertRaises(MjpgFrameRejected):
            layout.luma(bytes(flipped), 320, 180)
        # A flip that forges a marker inside the scan is refused before decoding.
        forged = bytearray(frame)
        forged[middle:middle + 2] = b"\xff\xc4"
        with mock.patch.object(mjpg, "_load") as load:
            with self.assertRaises(MjpgFrameRejected) as caught:
                layout.luma(bytes(forged), 320, 180)
        self.assertEqual("scan_invalid", caught.exception.reason)
        load.assert_not_called()

    def test_wrong_and_oversized_sof_are_refused_before_decoding(self):
        cases = ((CAPTURE_WIDTH * 2, CAPTURE_HEIGHT), (CAPTURE_WIDTH, CAPTURE_HEIGHT - 8),
                 (65500, 65500), (0, CAPTURE_HEIGHT))
        for width, height in cases:
            with self.subTest(width=width, height=height):
                with mock.patch.object(mjpg, "_load") as load:
                    reason = self.rejected(with_sof(self.frame, width, height))
                self.assertIn(reason, ("sof_dimension_mismatch", "sof_invalid"))
                load.assert_not_called()
        with self.assertRaises(ValueError):
            MjpgLumaLayout(7680, 4320)
        self.assertLessEqual(3840 * 2160, MAXIMUM_DECODE_PIXELS)

    def test_trailing_padding_is_bounded(self):
        layout = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, maximum_trailing_bytes=64)
        expected = layout.luma(self.frame, WIDTH, HEIGHT)
        self.assertEqual(expected, layout.luma(self.frame + bytes(64), WIDTH, HEIGHT))
        self.assertEqual(64, inspect_frame(self.frame + bytes(64), width=CAPTURE_WIDTH,
                                           height=CAPTURE_HEIGHT,
                                           maximum_trailing=64).trailing)
        self.assertEqual("trailing_bytes_exceeded", self.rejected(self.frame + bytes(65), layout))
        # A second EOI or a second image after the frame is not padding.
        self.assertEqual("trailing_marker", self.rejected(self.frame + b"\x00\xff\xd9", layout))
        self.assertEqual("trailing_marker", self.rejected(self.frame + b"\xff\xd8\xff", layout))
        with self.assertRaises(ValueError):
            MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, maximum_trailing_bytes=-1)

    def test_extraneous_bytes_and_unsupported_processes_are_refused(self):
        before = segment(self.frame, 0xDA)
        self.assertEqual("marker_invalid",
                         self.rejected(self.frame[:before] + bytes(16) + self.frame[before:]))
        sof = segment(self.frame, 0xC0)
        progressive = self.frame[:sof + 1] + b"\xc2" + self.frame[sof + 2:]
        self.assertEqual("unsupported_process", self.rejected(progressive))
        double = self.frame[:2] + self.frame[2:-2] + self.frame[2:]
        self.assertIn(self.rejected(double), ("scan_invalid", "sof_invalid"))
        self.assertEqual("marker_invalid", self.rejected(b"\xff\xd8\xff\xd9"))

    def test_decoder_error_and_unexpected_output_are_refused(self):
        class Broken:
            __version__ = "1.9.0"

            @staticmethod
            def decode_jpeg(*args, **kwargs):
                raise ValueError("synthetic libjpeg warning")

        with mock.patch.object(mjpg, "_load", return_value=(Broken, np)):
            self.assertEqual("decode_failed", self.rejected(self.frame))

        class Wrong(Broken):
            @staticmethod
            def decode_jpeg(*args, **kwargs):
                return np.zeros((HEIGHT, WIDTH + 1, 1), np.uint8)

        with mock.patch.object(mjpg, "_load", return_value=(Wrong, np)):
            self.assertEqual("decoded_shape_mismatch", self.rejected(self.frame))

    def test_undecoded_mid_grey_band_is_refused(self):
        def banded(*args, **kwargs):
            image = np.frombuffer(pixels(), np.uint8).reshape(HEIGHT, WIDTH, 1).copy()
            # libjpeg stopped mid-row: the last 7 MCUs (2x1 at 1/8) are 128.
            image.reshape(-1)[-14:] = 128
            return image

        decoder = mock.Mock(__version__="1.9.0", decode_jpeg=banded)
        with mock.patch.object(mjpg, "_load", return_value=(decoder, np)):
            self.assertEqual("undecoded_band", self.rejected(self.frame))
        # A dark (covered-lens-like) uniform frame is not mistaken for the band.
        dark = bytes([4] * (WIDTH * HEIGHT))
        self.assertEqual(WIDTH * HEIGHT, len(self.layout.luma(encode(dark), WIDTH, HEIGHT)))

    def test_slow_decode_is_refused(self):
        layout = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT, maximum_decode_ns=1_000,
                                clock=Ticks(2_000))
        self.assertEqual("decode_too_slow", self.rejected(self.frame, layout))

    def test_missing_or_unreviewed_decoder_is_unavailable(self):
        with mock.patch.object(mjpg, "_load", return_value=None):
            self.assertFalse(self.layout.available())
            self.assertEqual("decoder_unavailable", self.rejected(self.frame))
        self.assertTrue(self.layout.available())
        with mock.patch.object(mjpg, "_LOADED", None), mock.patch(
                "importlib.metadata.version", return_value="0.0"):
            self.assertIsNone(mjpg._load())
        mjpg._LOADED = None
        self.assertTrue(mjpg.decoder_available())

    def test_dct_scale_and_reference_compatibility(self):
        frame = noise_frame(1280, 720)
        layout = MjpgLumaLayout(1280, 720)
        for size in ((160, 90), (320, 180), (640, 360), (1280, 720), (80, 45)):
            with self.subTest(size=size):
                self.assertTrue(layout.compatible(*size))
                self.assertEqual(size[0] * size[1], len(layout.luma(frame, *size)))
        self.assertFalse(layout.compatible(300, 180))
        with self.assertRaises(MjpgFrameRejected) as caught:
            layout.luma(frame, 300, 180)
        self.assertEqual("reference_incompatible", caught.exception.reason)

    def test_negotiated_format_selects_the_reviewed_reader(self):
        self.assertIsInstance(capture_luma_layout(1920, 1080, "MJPG"), MjpgLumaLayout)
        self.assertIsInstance(capture_luma_layout(640, 480, "YUYV"), PackedLumaLayout)
        for fourcc in ("H264", "NV12"):
            with self.assertRaises(ValueError):
                capture_luma_layout(640, 480, fourcc)

    def test_decode_time_smoke_is_bounded(self):
        """Synthetic 1080p 4:2:2 frames (heavier than typical scenes)."""
        layout = MjpgLumaLayout(1920, 1080)
        frames = [noise_frame(1920, 1080, seed=seed) for seed in range(4)]
        for frame in frames:
            layout.luma(frame, 480, 270)
        durations = []
        for _ in range(5):
            for frame in frames:
                started = time.perf_counter()
                layout.luma(frame, 480, 270)
                durations.append(time.perf_counter() - started)
        # Generous bound for a shared CI core; measured values are a few ms.
        self.assertLess(statistics.median(durations), 0.1)
        self.assertLess(max(durations), mjpg.DEFAULT_DECODE_NS / 1e9)


MJPG_LAYOUT = MjpgLumaLayout(CAPTURE_WIDTH, CAPTURE_HEIGHT)


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


class SceneRuntimeMjpgTests(unittest.TestCase):
    def test_local_uvc_mjpg_frames_confirm_server_movement(self):
        harness = MjpgHarness(binding(layout=MJPG_LAYOUT))
        harness.runtime.start()
        harness.frame()
        self.assertEqual(Observation.ABSENT, harness.frame().movement)
        harness.frame(MOVED)
        confirmed = harness.frame(MOVED)
        self.assertEqual(Observation.PRESENT, confirmed.movement)
        self.assertEqual([CriticalKind.SERVER_MOVEMENT], harness.recorder.kinds())

    def test_corrupt_mjpg_frame_is_unknown_never_no_movement(self):
        harness = MjpgHarness(binding(layout=MJPG_LAYOUT), binding(OTHER, layout=MJPG_LAYOUT))
        harness.runtime.start()
        for _ in range(2):
            harness.frame(source=OTHER, advance=0)
            harness.frame()
        good = encode(pixels())
        start = scan_start(good)
        corrupt = (good[:start + (len(good) - start) // 2], with_sof(good, CAPTURE_WIDTH * 2, CAPTURE_HEIGHT),
                   good + bytes(mjpg.DEFAULT_TRAILING_BYTES + 1), good[:-2])
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
        # The other source keeps running.
        self.assertEqual(Observation.ABSENT, harness.source().movement)
        self.assertEqual([], harness.recorder.items)

    def test_decoder_unavailable_keeps_source_inactive(self):
        with mock.patch.object(mjpg, "_load", return_value=None):
            harness = MjpgHarness(binding(layout=MJPG_LAYOUT))
            harness.runtime.start()
            for luma in (None, MOVED, MOVED, MOVED):
                source = harness.frame(luma)
        self.assertIs(SceneSourceState.INACTIVE, source.state)
        self.assertEqual("frame_decoder_unavailable", source.reason)
        self.assertEqual(Observation.UNKNOWN, source.movement)
        self.assertEqual([], harness.recorder.items)

    def test_without_calibration_mjpg_source_fails_closed(self):
        harness = MjpgHarness(binding(layout=MJPG_LAYOUT), calibrations=None)
        harness.runtime.start()
        for luma in (None, MOVED, MOVED):
            source = harness.frame(luma)
        self.assertEqual("calibration_provider_unconfigured", source.reason)
        self.assertEqual(0, source.evaluated)
        harness = MjpgHarness(binding(layout=MJPG_LAYOUT), recorder=False)
        self.assertEqual("critical_recorder_unavailable",
                         harness.runtime.start().sources[0].reason)

    def test_incompatible_mjpg_layout_is_not_bound(self):
        harness = MjpgHarness(binding(layout=MjpgLumaLayout(CAPTURE_WIDTH + 4, CAPTURE_HEIGHT)))
        harness.runtime.start()
        self.assertEqual("capture_layout_incompatible", harness.frame().reason)
        with self.assertRaises(ValueError):
            binding(source_type=SourceType.REMOTE_AGENT, layout=MJPG_LAYOUT)

    def test_decoding_runs_on_the_scene_worker_not_the_capture_thread(self):
        threads = []
        original = MjpgLumaLayout.luma

        def recording(layout, data, width, height):
            threads.append(threading.current_thread().name)
            return original(layout, data, width, height)

        with mock.patch.object(MjpgLumaLayout, "luma", recording):
            harness = MjpgHarness(binding(layout=MJPG_LAYOUT))
            harness.runtime.start()
            harness.clock.value += INTERVAL
            harness.runtime.on_uvc_frame(SOURCE, VideoFrame(encode(pixels()), 1, 0.0))
            self.assertEqual([], threads)  # the capture callback only queues
            harness.runtime.step()
            self.assertEqual(1, len(threads))
            threaded = MjpgHarness(binding(layout=MJPG_LAYOUT), threaded=True)
            threaded.runtime.start()
            try:
                threaded.frame()
            finally:
                threaded.runtime.stop()
        self.assertEqual("scene-monitoring", threads[-1])


if __name__ == "__main__":
    unittest.main()
