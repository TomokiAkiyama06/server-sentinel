"""Reviewed MJPG luma reader for local UVC scene samples (Issue #217).

The Owner adopted simplejpeg 1.9.0 (statically linked libjpeg-turbo 3.1.2)
with numpy 2.3.5 on 2026-10-11 (`docs/decisions/2026-10-11-mjpg-decoder-survey.md`).
Camera-supplied bytes reach the native parser only after a pure-Python
structural pre-check, and every failure is a refusal (`MjpgFrameRejected`)
that the scene runtime maps to `unknown`, never to "no movement" or
"no tamper":

1. pre-check before decoding: `SOI` first; one baseline / extended-sequential
   Huffman frame whose `SOF` dimensions equal the negotiated V4L2 format and
   fit the pixel budget (a decompression-bomb header is refused before the
   decoder allocates anything); exactly one interleaved scan followed by a
   single `EOI`; at most a bounded number of padding bytes after it; a bounded
   total size and marker count;
2. decode with simplejpeg `strict=True` (libjpeg-turbo warnings such as a
   premature end of the entropy-coded data or extraneous bytes become
   errors) straight to luma (`GRAY`), using libjpeg's DCT scaling to the
   smallest power-of-two scale whose output decimates exactly to the
   reference size, with the accurate integer IDCT;
3. post-check the decoded shape and type, and refuse a decode whose trailing
   MCUs in scan order are all exactly mid-grey (the band libjpeg leaves after
   it stops decoding a scan early), or whose decode exceeded the per-frame
   time bound.

Decode success never proves frame integrity: a bit flip that keeps the
entropy-coded syntax valid yields locally wrong pixels that no check here can
see. The quality gate and the detector's temporal confirmation still apply.

This runs only on the scene worker thread (one worker, at most one sample per
second per source), never on a capture thread. Nothing decoded is retained.
"""

from dataclasses import dataclass, field
import importlib
import importlib.metadata
import math
import threading
import time


SIMPLEJPEG_VERSION = "1.9.0"
NUMPY_VERSION = "2.3.5"
# Pixel budget for the negotiated format and the SOF header (4K UHD).
MAXIMUM_DECODE_PIXELS = 3840 * 2160
# Upper bound for a whole MJPG payload, independent of the pixel budget.
MAXIMUM_FRAME_BYTES = 32 * 1024 * 1024
# Padding a UVC payload may carry after `EOI`. Provisional until real C960
# frames are measured (MANUAL_TEST.md, Issue #217); a deployment can lower it
# or raise it up to `MAXIMUM_TRAILING_LIMIT`.
DEFAULT_TRAILING_BYTES = 8192
MAXIMUM_TRAILING_LIMIT = 1024 * 1024
MAXIMUM_SEGMENTS = 64
# A decode slower than this is refused (it would delay every other source on
# the single scene worker). Synthetic 1080p luma decodes take a few ms.
DEFAULT_DECODE_NS = 250_000_000
# libjpeg DCT scaling denominators, smallest output first.
SCALE_DENOMINATORS = (8, 4, 2, 1)
# Value of a block libjpeg leaves undecoded (all coefficients zero) in luma.
UNDECODED_LUMA = 128

# Markers.
SOI, EOI, SOS, DHT, DQT, DRI, COM = 0xD8, 0xD9, 0xDA, 0xC4, 0xDB, 0xDD, 0xFE
SUPPORTED_SOF = frozenset({0xC0, 0xC1})  # baseline / extended sequential, Huffman
OTHER_SOF = frozenset({0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
APPLICATION = frozenset(range(0xE0, 0xF0))
RESTART = frozenset(range(0xD0, 0xD8))

REASONS = frozenset({
    "frame_type_invalid", "frame_too_large", "missing_soi", "marker_invalid",
    "segment_invalid", "unsupported_process", "sof_invalid", "sof_dimension_mismatch",
    "sof_missing", "scan_invalid", "missing_eoi", "trailing_bytes_exceeded",
    "trailing_marker", "decoder_unavailable", "decode_failed", "decoded_shape_mismatch",
    "undecoded_band", "decode_too_slow", "reference_incompatible",
})


class MjpgFrameRejected(ValueError):
    """A fixed, value-free reason why an MJPG frame yields no luma sample."""

    def __init__(self, reason: str):
        if reason not in REASONS:
            reason = "decode_failed"
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class JpegStructure:
    """What the pre-check learned; no pixel data."""

    width: int
    height: int
    components: int
    mcu_width: int
    mcu_height: int
    huffman_tables: bool
    end: int
    trailing: int


def _u16(data, offset):
    return (data[offset] << 8) | data[offset + 1]


def inspect_frame(data: bytes, *, width: int, height: int,
                  maximum_trailing: int = DEFAULT_TRAILING_BYTES) -> JpegStructure:
    """Structural pre-check of one MJPG payload; never calls a decoder."""
    if type(data) is not bytes:
        raise MjpgFrameRejected("frame_type_invalid")
    size = len(data)
    if size > MAXIMUM_FRAME_BYTES:
        raise MjpgFrameRejected("frame_too_large")
    if size < 4 or data[0] != 0xFF or data[1] != SOI:
        raise MjpgFrameRejected("missing_soi")
    position, segments = 2, 0
    frame = None
    huffman = False
    while True:
        segments += 1
        if segments > MAXIMUM_SEGMENTS:
            raise MjpgFrameRejected("segment_invalid")
        if position + 1 >= size or data[position] != 0xFF:
            raise MjpgFrameRejected("marker_invalid")
        # Optional 0xFF fill bytes before a marker, bounded per marker.
        fill = 0
        while data[position + 1] == 0xFF:
            position += 1
            fill += 1
            if fill > 16 or position + 1 >= size:
                raise MjpgFrameRejected("marker_invalid")
        marker = data[position + 1]
        if marker in (0x00, 0x01, SOI, EOI) or marker in RESTART:
            # No standalone marker is valid before the scan.
            raise MjpgFrameRejected("marker_invalid")
        if position + 4 > size:
            raise MjpgFrameRejected("segment_invalid")
        length = _u16(data, position + 2)
        end = position + 2 + length
        if length < 2 or end > size:
            raise MjpgFrameRejected("segment_invalid")
        body = position + 4
        if marker in SUPPORTED_SOF:
            if frame is not None:
                raise MjpgFrameRejected("sof_invalid")
            frame = _frame_header(data, body, length, width, height)
        elif marker in OTHER_SOF or marker == 0xCC:
            # Progressive, lossless, hierarchical or arithmetic coding: not
            # what a UVC camera sends, and not reviewed here.
            raise MjpgFrameRejected("unsupported_process")
        elif marker == DHT:
            huffman = True
        elif marker == SOS:
            if frame is None:
                raise MjpgFrameRejected("sof_missing")
            _scan_header(data, body, length, frame[0])
            scan_end = _entropy_end(data, end)
            trailing = size - scan_end
            if trailing > maximum_trailing:
                raise MjpgFrameRejected("trailing_bytes_exceeded")
            tail = data[scan_end:]
            if b"\xff\xd8" in tail or b"\xff\xd9" in tail:
                # A second image or `EOI` after the frame is not padding.
                raise MjpgFrameRejected("trailing_marker")
            components, mcu_width, mcu_height = frame
            return JpegStructure(width, height, components, mcu_width, mcu_height,
                                 huffman, scan_end, trailing)
        elif marker not in (DQT, DRI, COM) and marker not in APPLICATION:
            raise MjpgFrameRejected("marker_invalid")
        position = end


def _frame_header(data, body, length, width, height):
    if length < 8:
        raise MjpgFrameRejected("sof_invalid")
    precision, rows, columns, count = data[body], _u16(data, body + 1), _u16(data, body + 3), data[body + 5]
    if precision != 8 or count not in (1, 3) or length != 8 + 3 * count:
        raise MjpgFrameRejected("sof_invalid")
    if rows == 0 or columns == 0:
        # A DNL-defined height is not used by UVC MJPG.
        raise MjpgFrameRejected("sof_invalid")
    if (columns, rows) != (width, height) or columns * rows > MAXIMUM_DECODE_PIXELS:
        # Checked before any decoder allocation: a forged header cannot make
        # the decoder allocate a frame other than the negotiated one.
        raise MjpgFrameRejected("sof_dimension_mismatch")
    identifiers, factors = set(), []
    for index in range(count):
        offset = body + 6 + 3 * index
        identifier, sampling, table = data[offset], data[offset + 1], data[offset + 2]
        horizontal, vertical = sampling >> 4, sampling & 0x0F
        if identifier in identifiers or not 1 <= horizontal <= 4 or not 1 <= vertical <= 4 or table > 3:
            raise MjpgFrameRejected("sof_invalid")
        identifiers.add(identifier)
        factors.append((horizontal, vertical))
    if sum(h * v for h, v in factors) > 10:
        raise MjpgFrameRejected("sof_invalid")
    if count == 1:
        # A single-component scan is non-interleaved: one 8x8 block per MCU.
        return count, 8, 8
    return count, 8 * max(h for h, _ in factors), 8 * max(v for _, v in factors)


def _scan_header(data, body, length, components):
    if length < 6:
        raise MjpgFrameRejected("scan_invalid")
    count = data[body]
    if count != components or length != 6 + 2 * count:
        # Exactly one scan carrying every component (UVC baseline MJPG).
        raise MjpgFrameRejected("scan_invalid")
    tail = body + 1 + 2 * count
    start, end, approximation = data[tail], data[tail + 1], data[tail + 2]
    if (start, end, approximation) != (0, 63, 0):
        raise MjpgFrameRejected("scan_invalid")


def _entropy_end(data, position):
    """Index just after the `EOI` that ends the single scan."""
    size = len(data)
    while True:
        found = data.find(b"\xff", position)
        if found < 0 or found + 1 >= size:
            raise MjpgFrameRejected("missing_eoi")
        following = data[found + 1]
        if following == 0x00 or following in RESTART:
            position = found + 2
        elif following == 0xFF:
            position = found + 1
        elif following == EOI:
            return found + 2
        else:
            # Another segment after the scan (a second scan, tables, a new
            # image): not a single-scan UVC frame.
            raise MjpgFrameRejected("scan_invalid")


_LOCK = threading.Lock()
_LOADED = None


def _load():
    """The reviewed decoder modules, or None when the exact pins are absent."""
    global _LOADED
    with _LOCK:
        if _LOADED is None:
            try:
                if (importlib.metadata.version("simplejpeg") != SIMPLEJPEG_VERSION
                        or importlib.metadata.version("numpy") != NUMPY_VERSION):
                    raise ImportError("unreviewed decoder version")
                simplejpeg = importlib.import_module("simplejpeg")
                numpy = importlib.import_module("numpy")
                if getattr(simplejpeg, "__version__", None) != SIMPLEJPEG_VERSION:
                    raise ImportError("unreviewed decoder version")
                _LOADED = (simplejpeg, numpy)
            except Exception:
                _LOADED = False
        return _LOADED or None


def decoder_available() -> bool:
    return _load() is not None


def _scale(width, height, target_width, target_height):
    for denominator in SCALE_DENOMINATORS:
        scaled_width = math.ceil(width / denominator)
        scaled_height = math.ceil(height / denominator)
        if scaled_width % target_width == 0 and scaled_height % target_height == 0:
            return denominator, scaled_width, scaled_height
    return None


def _undecoded_band(numpy, image, mcu_width, mcu_height, minimum):
    """True when the last `minimum` MCUs in scan order are all exactly 128."""
    rows, columns = image.shape
    across, down = -(-columns // mcu_width), -(-rows // mcu_height)
    padded = numpy.full((down * mcu_height, across * mcu_width), UNDECODED_LUMA, dtype=numpy.uint8)
    padded[:rows, :columns] = image
    uniform = (padded.reshape(down, mcu_height, across, mcu_width) == UNDECODED_LUMA).all(axis=(1, 3))
    flat = uniform.reshape(-1)
    minimum = min(minimum, flat.size)
    return bool(flat[-minimum:].all())


@dataclass(frozen=True)
class MjpgLumaLayout:
    """Negotiated MJPG capture whose luma is decoded by the reviewed decoder.

    The SOF header must state exactly `width` x `height`. Decoding uses the
    accurate integer IDCT and libjpeg DCT scaling to the smallest power of two
    (1/8, 1/4, 1/2, 1) whose output is an integer multiple of the reference
    size, followed by nearest-sample decimation; a calibration reference for
    such a source must come through this same reader.
    """

    width: int
    height: int
    maximum_trailing_bytes: int = DEFAULT_TRAILING_BYTES
    maximum_decode_ns: int = DEFAULT_DECODE_NS
    clock: object = field(default=time.perf_counter_ns, repr=False, compare=False)
    pixel_format = "MJPG"

    def __post_init__(self):
        for value in (self.width, self.height):
            if type(value) is not int or not 1 <= value <= 16384:
                raise ValueError("invalid capture dimensions")
        if self.width * self.height > MAXIMUM_DECODE_PIXELS:
            raise ValueError("capture dimensions exceed the decode pixel budget")
        if (type(self.maximum_trailing_bytes) is not int
                or not 0 <= self.maximum_trailing_bytes <= MAXIMUM_TRAILING_LIMIT):
            raise ValueError("invalid trailing byte bound")
        if type(self.maximum_decode_ns) is not int or not 0 < self.maximum_decode_ns <= 5_000_000_000:
            raise ValueError("invalid decode time bound")
        if not callable(self.clock):
            raise ValueError("invalid decode clock")

    def available(self) -> bool:
        return decoder_available()

    def compatible(self, width: int, height: int) -> bool:
        return (type(width) is int and type(height) is int and width > 0 and height > 0
                and _scale(self.width, self.height, width, height) is not None)

    def luma(self, data, width: int, height: int) -> bytes:
        """Decoded luma of one frame at `width` x `height`, or a refusal."""
        started = self.clock()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise MjpgFrameRejected("frame_type_invalid")
        view = memoryview(data)
        if view.nbytes > MAXIMUM_FRAME_BYTES:
            raise MjpgFrameRejected("frame_too_large")
        buffer = data if type(data) is bytes else bytes(view.cast("B"))
        structure = inspect_frame(buffer, width=self.width, height=self.height,
                                  maximum_trailing=self.maximum_trailing_bytes)
        scale = _scale(self.width, self.height, width, height) if self.compatible(width, height) else None
        if scale is None:
            raise MjpgFrameRejected("reference_incompatible")
        denominator, scaled_width, scaled_height = scale
        loaded = _load()
        if loaded is None:
            raise MjpgFrameRejected("decoder_unavailable")
        simplejpeg, numpy = loaded
        try:
            decoded = simplejpeg.decode_jpeg(
                buffer[:structure.end], colorspace="GRAY", fastdct=False, fastupsample=False,
                min_width=scaled_width, min_height=scaled_height, strict=True)
        except Exception:
            # Includes libjpeg warnings promoted to errors by strict mode.
            raise MjpgFrameRejected("decode_failed") from None
        finally:
            buffer = None
        if (not isinstance(decoded, numpy.ndarray) or decoded.dtype != numpy.uint8
                or decoded.shape != (scaled_height, scaled_width, 1)):
            raise MjpgFrameRejected("decoded_shape_mismatch")
        image = decoded[:, :, 0]
        mcu_width = max(1, structure.mcu_width // denominator)
        mcu_height = max(1, structure.mcu_height // denominator)
        if _undecoded_band(numpy, image, mcu_width, mcu_height,
                           -(-scaled_width // mcu_width)):
            raise MjpgFrameRejected("undecoded_band")
        step_x, step_y = scaled_width // width, scaled_height // height
        pixels = numpy.ascontiguousarray(image[::step_y, ::step_x]).tobytes()
        if len(pixels) != width * height:
            raise MjpgFrameRejected("decoded_shape_mismatch")
        if self.clock() - started > self.maximum_decode_ns:
            raise MjpgFrameRejected("decode_too_slow")
        return pixels
