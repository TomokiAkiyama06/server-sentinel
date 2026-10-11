"""Reviewed MJPG luma reader for local UVC scene samples (Issue #217).

The Owner adopted simplejpeg 1.9.0 (statically linked libjpeg-turbo 3.1.2)
with numpy 2.3.5 on 2026-10-11 (`docs/decisions/2026-10-11-mjpg-decoder-survey.md`).
Camera-supplied bytes reach the native parser only after a pure-Python
structural pre-check in the Main process, and the native parser itself runs
only in a separate, resource-limited, resident child process per source
(`mjpg_worker.MjpgDecoderProcess` running `mjpg_child.py`; Owner decision
2026-10-11 on PR #225). Every failure is a refusal (`MjpgFrameRejected`) that
the scene runtime maps to `unknown`, never to "no movement" or "no tamper":

1. pre-check in Main before decoding: `SOI` first; one baseline /
   extended-sequential Huffman frame whose `SOF` dimensions equal the
   negotiated V4L2 format and fit the pixel budget (a decompression-bomb
   header is refused before the decoder allocates anything); exactly one
   interleaved scan followed by a single `EOI`; at most a bounded number of
   padding bytes after it; a total size bounded by the negotiated resolution
   (`frame_byte_budget`) and a bounded marker count. The entropy-coded data is
   scanned with C-level byte operations, so its cost is linear in that budget
   and never one Python iteration per stuffed byte. Only the validated bytes
   up to `EOI` are sent to the child;
2. decode in the child with simplejpeg `strict=True` (libjpeg-turbo warnings
   such as a premature end of the entropy-coded data or extraneous bytes
   become errors) straight to luma (`GRAY`), using libjpeg's DCT scaling to
   the smallest power-of-two scale whose output decimates exactly to the
   reference size, with the accurate integer IDCT; the child refuses a decode
   whose shape differs or whose trailing MCUs in scan order are all exactly
   mid-grey (the band libjpeg leaves after it stops decoding a scan early);
3. in Main, check the reply's type, request id and exact pixel count. A child
   crash, kill (including an OOM kill), exit, per-frame timeout (the child is
   killed) or malformed reply refuses that frame; a replacement child is
   started after a bounded backoff, and repeated failures lower the source to
   `degraded`. Starting and reaping a child run on the source's own
   supervisor thread: a frame that arrives meanwhile is refused at once
   (`decoder_starting` / `decoder_unavailable`).

Decode success never proves frame integrity: a corruption that keeps the
entropy-coded data decodable can yield substantially wrong pixels (large
areas, or a bottom band clamped to 0 by a DC desync, which the exactly-128
band check does not see). The band check is deliberately not widened to 0 or
255, because that would also refuse a covered lens and hide camera tamper; and
a real scene whose trailing MCUs are exactly 128 is refused (fail-closed). The
quality gate and the detector's temporal confirmation still apply.

This runs only on the scene worker thread (one worker, at most one sample per
second per source), never on a capture thread; the worker waits only for one
exchange with a ready child (bounded by the per-frame deadline), never for a
child start or reap. Nothing decoded is retained.
"""

from dataclasses import dataclass, field
import importlib.metadata
import math

from .mjpg_worker import (CHILD, NUMPY_VERSION, SIMPLEJPEG_VERSION, DecodeRequest,
                          DecoderRefusal, MjpgDecoderLimits)


# Pixel budget for the negotiated format and the SOF header (4K UHD).
MAXIMUM_DECODE_PIXELS = 3840 * 2160
# Upper bound for a whole MJPG payload, independent of the pixel budget.
MAXIMUM_FRAME_BYTES = 32 * 1024 * 1024
# Per-format payload budget (`frame_byte_budget`): at most
# `MAXIMUM_BYTES_PER_PIXEL` bytes per negotiated pixel, plus
# `HEADER_ALLOWANCE_BYTES` for the marker segments and the configured trailing
# padding, never above `MAXIMUM_FRAME_BYTES`. Two bytes per pixel is the size
# of the same frame as uncompressed YUYV, which UVC devices commonly report as
# the MJPG `dwMaxVideoFrameSize`; a baseline frame from a camera encoder stays
# far below it (MANUAL_TEST.md records the real C960 sizes). A larger payload
# is refused (`frame_too_large`, so `unknown`) before it is scanned, which
# bounds the pre-check work on the shared scene worker by the negotiated
# resolution rather than by the 32 MiB cap.
MAXIMUM_BYTES_PER_PIXEL = 2
HEADER_ALLOWANCE_BYTES = 256 * 1024
# Padding a UVC payload may carry after `EOI`. Provisional until real C960
# frames are measured (MANUAL_TEST.md, Issue #217); a deployment can lower it
# or raise it up to `MAXIMUM_TRAILING_LIMIT`.
DEFAULT_TRAILING_BYTES = 8192
MAXIMUM_TRAILING_LIMIT = 1024 * 1024
MAXIMUM_SEGMENTS = 64
# libjpeg DCT scaling denominators, smallest output first.
SCALE_DENOMINATORS = (8, 4, 2, 1)

# Markers.
SOI, EOI, SOS, DHT, DQT, DRI, COM = 0xD8, 0xD9, 0xDA, 0xC4, 0xDB, 0xDD, 0xFE
SUPPORTED_SOF = frozenset({0xC0, 0xC1})  # baseline / extended sequential, Huffman
OTHER_SOF = frozenset({0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
APPLICATION = frozenset(range(0xE0, 0xF0))
RESTART = frozenset(range(0xD0, 0xD8))
# Entropy-coded data scan (`_entropy_end`): every byte is mapped to its class,
# 0xFF -> 0xFF, a byte that may follow 0xFF inside the scan (`00` stuffing or
# an `RST` marker) -> 0x00, anything else -> 0x01, so a forbidden pair is
# found with one C-level `bytes.find`. Fill bytes (0xFF 0xFF) stay 0xFF 0xFF.
_ENTROPY_CLASSES = bytes(0xFF if value == 0xFF else 0x00 if value == 0x00 or value in RESTART
                         else 0x01 for value in range(256))
_FORBIDDEN_PAIR = b"\xff\x01"
# Bytes translated at a time, so the scan never holds a second copy of a
# whole frame.
_SCAN_CHUNK_BYTES = 1024 * 1024

REASONS = frozenset({
    "frame_type_invalid", "frame_too_large", "missing_soi", "marker_invalid",
    "segment_invalid", "unsupported_process", "sof_invalid", "sof_dimension_mismatch",
    "sof_missing", "scan_invalid", "missing_eoi", "trailing_bytes_exceeded",
    "trailing_marker", "decoder_unavailable", "decode_failed", "decoded_shape_mismatch",
    "undecoded_band", "reference_incompatible",
    "decoder_crashed", "decoder_timeout", "decoder_protocol", "decoder_starting",
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


def frame_byte_budget(width: int, height: int,
                      maximum_trailing: int = DEFAULT_TRAILING_BYTES) -> int:
    """Largest payload accepted for a `width` x `height` negotiated format."""
    return min(MAXIMUM_FRAME_BYTES,
               MAXIMUM_BYTES_PER_PIXEL * width * height + HEADER_ALLOWANCE_BYTES
               + maximum_trailing)


def _u16(data, offset):
    return (data[offset] << 8) | data[offset + 1]


def inspect_frame(data: bytes, *, width: int, height: int,
                  maximum_trailing: int = DEFAULT_TRAILING_BYTES) -> JpegStructure:
    """Structural pre-check of one MJPG payload; never calls a decoder."""
    if type(data) is not bytes:
        raise MjpgFrameRejected("frame_type_invalid")
    size = len(data)
    if size > frame_byte_budget(width, height, maximum_trailing):
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
    """Index just after the `EOI` that ends the single scan.

    Inside the scan a 0xFF byte may only be followed by `00` (stuffing), an
    `RST` marker or another 0xFF (fill); the first `FF D9` ends the scan, and
    any other marker before it (a second scan, tables, a new image) refuses
    the frame. The work is C-level (`bytes.find` / `bytes.translate`, in
    bounded chunks) and linear in the frame size, which `frame_byte_budget`
    bounds: dense `FF 00` stuffing costs no Python iteration per byte.
    """
    size = len(data)
    eoi = data.find(b"\xff\xd9", position)
    limit = size if eoi < 0 else eoi
    start = position
    while start < limit:
        stop = min(start + _SCAN_CHUNK_BYTES, limit)
        # One byte past the chunk, so a pair across the boundary is checked;
        # in the last chunk that byte is the 0xFF of `EOI` (a fill pair).
        if data[start:stop + 1].translate(_ENTROPY_CLASSES).find(_FORBIDDEN_PAIR) >= 0:
            # Another segment after the scan: not a single-scan UVC frame.
            raise MjpgFrameRejected("scan_invalid")
        start = stop
    if eoi < 0:
        raise MjpgFrameRejected("missing_eoi")
    return eoi + 2


def decoder_available() -> bool:
    """True when the exact reviewed simplejpeg / numpy pins are installed.

    Only package metadata is read: the Main process never imports the native
    decoder (or numpy). The decode child checks the imported versions again
    and refuses to start on any difference.
    """
    try:
        return (importlib.metadata.version("simplejpeg") == SIMPLEJPEG_VERSION
                and importlib.metadata.version("numpy") == NUMPY_VERSION
                and CHILD.is_file())
    except Exception:
        return False


def _scale(width, height, target_width, target_height):
    for denominator in SCALE_DENOMINATORS:
        scaled_width = math.ceil(width / denominator)
        scaled_height = math.ceil(height / denominator)
        if scaled_width % target_width == 0 and scaled_height % target_height == 0:
            return denominator, scaled_width, scaled_height
    return None


@dataclass(frozen=True)
class MjpgLumaLayout:
    """Negotiated MJPG capture whose luma is decoded by the reviewed decoder.

    The SOF header must state exactly `width` x `height`. Decoding (in the
    source's decode child, `mjpg_worker`) uses the accurate integer IDCT and
    libjpeg DCT scaling to the smallest power of two (1/8, 1/4, 1/2, 1) whose
    output is an integer multiple of the reference size, followed by
    nearest-sample decimation; a calibration reference for such a source must
    come through this same reader.
    """

    width: int
    height: int
    maximum_trailing_bytes: int = DEFAULT_TRAILING_BYTES
    decoder: MjpgDecoderLimits = field(default_factory=MjpgDecoderLimits)
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
        if not isinstance(self.decoder, MjpgDecoderLimits):
            raise ValueError("invalid MJPG decoder limits")

    def available(self) -> bool:
        return decoder_available()

    def compatible(self, width: int, height: int) -> bool:
        return (type(width) is int and type(height) is int and width > 0 and height > 0
                and _scale(self.width, self.height, width, height) is not None)

    def request(self, data, width: int, height: int):
        """Pre-check one frame: the validated JPEG bytes and the decode request.

        Pure Python; raises `MjpgFrameRejected` before any decoder is reached.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise MjpgFrameRejected("frame_type_invalid")
        view = memoryview(data)
        if view.nbytes > frame_byte_budget(self.width, self.height, self.maximum_trailing_bytes):
            raise MjpgFrameRejected("frame_too_large")
        if type(data) is bytes:
            buffer = data
        elif not view.c_contiguous or view.itemsize != 1 or view.ndim != 1:
            # A capture buffer is one flat run of bytes; anything else is not
            # a frame this reader understands.
            raise MjpgFrameRejected("frame_type_invalid")
        else:
            buffer = view.tobytes()
        structure = inspect_frame(buffer, width=self.width, height=self.height,
                                  maximum_trailing=self.maximum_trailing_bytes)
        scale = _scale(self.width, self.height, width, height) if self.compatible(width, height) else None
        if scale is None:
            raise MjpgFrameRejected("reference_incompatible")
        denominator, scaled_width, scaled_height = scale
        mcu_width = max(1, structure.mcu_width // denominator)
        mcu_height = max(1, structure.mcu_height // denominator)
        # Only the bytes up to `EOI` reach the decoder; trailing padding never
        # leaves the Main process.
        encoded = buffer[:structure.end]
        return encoded, DecodeRequest(scaled_width, scaled_height, width, height,
                                      mcu_width, mcu_height, -(-scaled_width // mcu_width))

    def luma(self, data, width: int, height: int, decoder) -> bytes:
        """Decoded luma of one frame at `width` x `height`, or a refusal.

        `decoder` is this source's `MjpgDecoderProcess`; every child failure,
        timeout or malformed reply is a refusal, never a frame.
        """
        encoded, request = self.request(data, width, height)
        if not self.available():
            raise MjpgFrameRejected("decoder_unavailable")
        try:
            pixels = decoder.decode(encoded, request)
        except DecoderRefusal as refusal:
            raise MjpgFrameRejected(refusal.reason) from None
        except Exception:
            raise MjpgFrameRejected("decode_failed") from None
        finally:
            encoded = None
        if type(pixels) is not bytes or len(pixels) != width * height:
            raise MjpgFrameRejected("decoded_shape_mismatch")
        return pixels
