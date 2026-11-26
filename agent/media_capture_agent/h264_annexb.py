"""H.264 Annex B byte-stream parsing and recording-segment validation (Issue #16).

Owner decision 2026-11-26: the Agent re-encodes each approved camera to H.264
with OpenH264 and stores fixed-duration segments in its disk ring. The encoder
child writes an Annex B byte stream (``stream-format=byte-stream``); this
module, standard library only, turns that stream into access units and checks
that one segment's worth of them is what the ring may store:

* ``AccessUnitSplitter`` splits a byte stream fed in arbitrary chunks into
  NAL units and access units (ITU-T H.264 7.4.1.2.3: a new access unit starts
  at an access unit delimiter, SPS, PPS, SEI or types 14-18 NAL unit, or at a
  slice whose ``first_mb_in_slice`` is 0, once the current unit has a slice).
  NAL and access unit sizes are bounded; a larger unit is refused rather than
  buffered.
* ``parse_sps`` reads the fields needed for the MP4 sample entry (profile,
  level, chroma format, bit depths) and the cropped picture size.
* ``validate_segment`` refuses a segment unless it has exactly the expected
  number of access units, each with at least one slice; the first carries
  SPS, PPS and only IDR slices; every parameter set in it is byte-identical to
  the first; and only NAL types 1, 5, 6, 7, 8 and 9 appear (no SVC/MVC or
  auxiliary data). It returns the parameter sets and every access unit as an
  MP4 sample (4-byte length prefixes; SPS, PPS and delimiters removed) with
  its sync flag.

Parsing establishes structure only; it does not decode pictures. Decodability
is checked separately (D13: ``openh264dec`` in a confined child). No byte of
video is logged; errors carry fixed reason words.
"""
from __future__ import annotations

from dataclasses import dataclass, field


NAL_SLICE = 1
NAL_IDR = 5
NAL_SEI = 6
NAL_SPS = 7
NAL_PPS = 8
NAL_AUD = 9
VCL_TYPES = frozenset({NAL_SLICE, NAL_IDR})
# Types that may appear in a single-layer OpenH264 stream the Agent stores.
ALLOWED_TYPES = frozenset({NAL_SLICE, NAL_IDR, NAL_SEI, NAL_SPS, NAL_PPS, NAL_AUD})
# Types that start a new access unit once the current one has a slice.
_AU_START_TYPES = frozenset({NAL_SEI, NAL_SPS, NAL_PPS, NAL_AUD, 14, 15, 16, 17, 18})
# Profiles whose SPS carries chroma format and bit depth (7.3.2.1.1).
_HIGH_PROFILES = frozenset({100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135})
_START_CODE = b"\x00\x00\x01"
# Zero bytes the splitter keeps pending at the end of its buffer: a NAL's
# trailing_zero_8bits, a four-byte start code's zero_byte and the first two
# bytes of the next start code. An encoder emits a handful; a longer run is
# refused instead of growing without bound.
MAX_ZERO_RUN = 4096
_MAX_EXP_GOLOMB_ZEROS = 31

SYNC_SAMPLE_FLAGS = 0x02000000
NON_SYNC_SAMPLE_FLAGS = 0x01010000


class AnnexBError(ValueError):
    """A refused byte stream or segment; ``reason`` is a fixed word."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NalUnit:
    data: bytes = field(repr=False)

    @property
    def type(self) -> int:
        return self.data[0] & 0x1F

    @property
    def is_vcl(self) -> bool:
        return self.type in VCL_TYPES


@dataclass(frozen=True)
class AccessUnit:
    nals: tuple[NalUnit, ...] = field(repr=False)

    @property
    def types(self) -> tuple[int, ...]:
        return tuple(nal.type for nal in self.nals)

    @property
    def is_idr(self) -> bool:
        types = [kind for kind in self.types if kind in VCL_TYPES]
        return bool(types) and all(kind == NAL_IDR for kind in types)

    @property
    def size(self) -> int:
        return sum(len(nal.data) for nal in self.nals)


@dataclass(frozen=True)
class SpsInfo:
    profile_idc: int
    constraint_flags: int
    level_idc: int
    chroma_format_idc: int
    bit_depth_luma: int
    bit_depth_chroma: int
    width: int
    height: int
    frame_mbs_only: bool


@dataclass(frozen=True)
class SegmentStream:
    """One validated segment: parameter sets and MP4-ready samples."""

    sps: bytes = field(repr=False)
    pps: bytes = field(repr=False)
    info: SpsInfo
    samples: tuple[bytes, ...] = field(repr=False)
    sync: tuple[bool, ...]


def _nal(data: bytes) -> NalUnit:
    if not data:
        raise AnnexBError("empty_nal_unit")
    if data[0] & 0x80:
        raise AnnexBError("forbidden_zero_bit")
    return NalUnit(data)


class AccessUnitSplitter:
    """Incremental Annex B splitter; ``feed`` then ``flush`` at end of stream."""

    def __init__(self, *, max_nal_bytes: int, max_access_unit_bytes: int):
        for value in (max_nal_bytes, max_access_unit_bytes):
            if type(value) is not int or value < 1:
                raise ValueError("bounds must be positive integers")
        self.max_nal_bytes = max_nal_bytes
        self.max_access_unit_bytes = max_access_unit_bytes
        self._buffer = bytearray()
        self._started = False
        self._current: list[NalUnit] = []
        self._current_size = 0
        self._has_vcl = False

    def feed(self, chunk: bytes) -> list[AccessUnit]:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("chunk must be bytes")
        self._buffer += chunk
        done: list[AccessUnit] = []
        if not self._started:
            first = self._buffer.find(_START_CODE)
            if first < 0:
                # Only zero bytes may precede the first start code
                # (leading_zero_8bits); keep at most two of them.
                if any(self._buffer):
                    raise AnnexBError("missing_start_code")
                del self._buffer[:-2]
                return done
            if any(self._buffer[:first]):
                raise AnnexBError("missing_start_code")
            del self._buffer[:first + len(_START_CODE)]
            self._started = True
        while True:
            end = self._buffer.find(_START_CODE)
            if end < 0:
                # The pending NAL keeps growing. Its trailing zero bytes may
                # still be a zero_byte/trailing_zero_8bits plus the start of
                # the next start code, so they do not count toward the NAL
                # bound (PR #431 review); their run has its own bound.
                zeros = _trailing_zeros(self._buffer, MAX_ZERO_RUN + 1)
                if zeros > MAX_ZERO_RUN:
                    raise AnnexBError("zero_byte_run_too_long")
                if len(self._buffer) - zeros > self.max_nal_bytes:
                    raise AnnexBError("nal_unit_too_large")
                return done
            data = bytes(self._buffer[:end]).rstrip(b"\x00")
            del self._buffer[:end + len(_START_CODE)]
            self._accept(_nal_or_skip(data), done)

    def flush(self) -> list[AccessUnit]:
        done: list[AccessUnit] = []
        if self._started and self._buffer:
            data = bytes(self._buffer).rstrip(b"\x00")
            self._buffer.clear()
            self._accept(_nal_or_skip(data), done)
        if self._current:
            done.append(self._finish())
        return done

    def _accept(self, nal: NalUnit | None, done: list[AccessUnit]) -> None:
        if nal is None:
            return
        if len(nal.data) > self.max_nal_bytes:
            raise AnnexBError("nal_unit_too_large")
        if self._has_vcl and (nal.type in _AU_START_TYPES
                              or nal.is_vcl and _first_mb_is_zero(nal)):
            done.append(self._finish())
        self._current.append(nal)
        self._current_size += len(nal.data)
        self._has_vcl = self._has_vcl or nal.is_vcl
        if self._current_size > self.max_access_unit_bytes:
            raise AnnexBError("access_unit_too_large")

    def _finish(self) -> AccessUnit:
        unit = AccessUnit(tuple(self._current))
        self._current, self._current_size, self._has_vcl = [], 0, False
        return unit


def _trailing_zeros(buffer, limit: int) -> int:
    """Count trailing 0x00 bytes of ``buffer``, stopping at ``limit``."""
    count = 0
    index = len(buffer) - 1
    while index >= 0 and count < limit and buffer[index] == 0:
        count += 1
        index -= 1
    return count


def _nal_or_skip(data: bytes) -> NalUnit | None:
    # Back-to-back start codes leave an empty NAL; it carries nothing.
    return _nal(data) if data else None


def _first_mb_is_zero(nal: NalUnit) -> bool:
    if len(nal.data) < 2:
        raise AnnexBError("truncated_slice_header")
    # first_mb_in_slice is ue(v); the value 0 is the single bit "1".
    return bool(nal.data[1] & 0x80)


def rbsp(payload: bytes) -> bytes:
    """Remove emulation prevention bytes (0x000003 -> 0x0000)."""
    out = bytearray()
    zeros = 0
    for byte in payload:
        if zeros >= 2 and byte == 3:
            zeros = 0
            continue
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


class _Bits:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    def bit(self) -> int:
        index = self.position >> 3
        if index >= len(self.data):
            raise AnnexBError("truncated_parameter_set")
        value = (self.data[index] >> (7 - (self.position & 7))) & 1
        self.position += 1
        return value

    def bits(self, count: int) -> int:
        value = 0
        for _ in range(count):
            value = (value << 1) | self.bit()
        return value

    def ue(self) -> int:
        zeros = 0
        while self.bit() == 0:
            zeros += 1
            if zeros > _MAX_EXP_GOLOMB_ZEROS:
                raise AnnexBError("invalid_exp_golomb")
        return (1 << zeros) - 1 + self.bits(zeros)

    def se(self) -> int:
        value = self.ue()
        return (value + 1) // 2 if value & 1 else -(value // 2)


def _skip_scaling_list(bits: _Bits, size: int) -> None:
    last, following = 8, 8
    for _ in range(size):
        if following != 0:
            delta = bits.se()
            if not -128 <= delta <= 127:
                raise AnnexBError("invalid_parameter_set")
            following = (last + delta + 256) % 256
        last = following if following != 0 else last


def parse_sps(nal: bytes) -> SpsInfo:
    """Parse an SPS NAL unit (header byte included) per H.264 7.3.2.1.1."""
    if not nal or nal[0] & 0x1F != NAL_SPS:
        raise AnnexBError("not_a_sequence_parameter_set")
    bits = _Bits(rbsp(nal[1:]))
    profile = bits.bits(8)
    constraints = bits.bits(8)
    level = bits.bits(8)
    if bits.ue() > 31:
        raise AnnexBError("invalid_parameter_set")
    chroma, separate_planes, depth_luma, depth_chroma = 1, 0, 8, 8
    if profile in _HIGH_PROFILES:
        chroma = bits.ue()
        if chroma > 3:
            raise AnnexBError("invalid_parameter_set")
        if chroma == 3:
            separate_planes = bits.bit()
        depth_luma = bits.ue() + 8
        depth_chroma = bits.ue() + 8
        if depth_luma > 14 or depth_chroma > 14:
            raise AnnexBError("invalid_parameter_set")
        bits.bit()  # qpprime_y_zero_transform_bypass_flag
        if bits.bit():  # seq_scaling_matrix_present_flag
            for index in range(8 if chroma != 3 else 12):
                if bits.bit():
                    _skip_scaling_list(bits, 16 if index < 6 else 64)
    if bits.ue() > 12:  # log2_max_frame_num_minus4
        raise AnnexBError("invalid_parameter_set")
    order_type = bits.ue()
    if order_type == 0:
        if bits.ue() > 12:  # log2_max_pic_order_cnt_lsb_minus4
            raise AnnexBError("invalid_parameter_set")
    elif order_type == 1:
        bits.bit()
        bits.se()
        bits.se()
        cycle = bits.ue()
        if cycle > 255:
            raise AnnexBError("invalid_parameter_set")
        for _ in range(cycle):
            bits.se()
    elif order_type != 2:
        raise AnnexBError("invalid_parameter_set")
    bits.ue()  # max_num_ref_frames
    bits.bit()  # gaps_in_frame_num_value_allowed_flag
    width_mbs = bits.ue() + 1
    height_units = bits.ue() + 1
    frame_mbs_only = bits.bit()
    if not frame_mbs_only:
        bits.bit()  # mb_adaptive_frame_field_flag
    bits.bit()  # direct_8x8_inference_flag
    crop = (0, 0, 0, 0)
    if bits.bit():
        crop = (bits.ue(), bits.ue(), bits.ue(), bits.ue())
    array_type = 0 if separate_planes else chroma
    sub_width = 2 if array_type in (1, 2) else 1
    sub_height = 2 if array_type == 1 else 1
    unit_x = 1 if array_type == 0 else sub_width
    unit_y = (2 - frame_mbs_only) * (1 if array_type == 0 else sub_height)
    width = width_mbs * 16 - unit_x * (crop[0] + crop[1])
    height = (2 - frame_mbs_only) * height_units * 16 - unit_y * (crop[2] + crop[3])
    if width < 1 or height < 1 or width > 65535 or height > 65535:
        raise AnnexBError("invalid_parameter_set")
    return SpsInfo(profile, constraints, level, chroma, depth_luma, depth_chroma,
                   width, height, bool(frame_mbs_only))


def validate_segment(units, *, expected_count: int) -> SegmentStream:
    """Check one segment's access units and convert them to MP4 samples."""
    if type(expected_count) is not int or expected_count < 1:
        raise ValueError("expected_count must be a positive integer")
    units = tuple(units)
    if len(units) != expected_count:
        raise AnnexBError("access_unit_count_mismatch")
    sps = pps = None
    samples: list[bytes] = []
    sync: list[bool] = []
    for position, unit in enumerate(units):
        if not isinstance(unit, AccessUnit) or not unit.nals:
            raise AnnexBError("empty_access_unit")
        payload = bytearray()
        for nal in unit.nals:
            if nal.type not in ALLOWED_TYPES:
                raise AnnexBError("unsupported_nal_type")
            if nal.type == NAL_SPS:
                if sps is None and position == 0:
                    sps = nal.data
                elif nal.data != sps:
                    raise AnnexBError("parameter_set_changed")
                continue
            if nal.type == NAL_PPS:
                if pps is None and position == 0:
                    pps = nal.data
                elif nal.data != pps:
                    raise AnnexBError("parameter_set_changed")
                continue
            if nal.type == NAL_AUD:
                continue
            payload += len(nal.data).to_bytes(4, "big") + nal.data
        if not any(nal.is_vcl for nal in unit.nals):
            raise AnnexBError("access_unit_without_slice")
        if position == 0 and (sps is None or pps is None or not unit.is_idr):
            raise AnnexBError("segment_must_start_with_idr")
        samples.append(bytes(payload))
        sync.append(unit.is_idr)
    return SegmentStream(sps, pps, parse_sps(sps), tuple(samples), tuple(sync))
