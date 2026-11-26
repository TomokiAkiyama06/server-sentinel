"""Structural validation of H.264 fragmented-MP4 recording segments (Issue #313, D13).

Owner decision D13 (2026-11-08): recordings are H.264 (OpenH264) in one
self-contained fragmented MP4 per segment, written by the project's own
standard-library writer, and every segment is validated before it is stored
(``SegmentValidator``): a structural check by an own, narrow parser plus a
full decode of every frame in a confined child process (``openh264dec``).

This module is the structural half, standard library only. Following D13's
"accept only the subset we write" rule, it accepts exactly the layout of the
project's writer (``agent/media_capture_agent/fmp4.py``; Issue #16):

    ftyp | moov(mvhd, trak(tkhd, mdia(mdhd, hdlr 'vide',
           minf(vmhd, dinf(dref(url)), stbl(stsd(avc1(avcC)), empty stts, stsc,
           stsz, stco)))), mvex(trex)) | moof(mfhd, traf(tfhd, tfdt, trun)) | mdat

and refuses anything else with one fixed ``RecordingError`` code: a second
track or any audio, metadata or unknown box; a sample table that is not
empty; sample data outside ``mdat`` or not covering it exactly; a first sample
that is not an IDR picture; NAL units of other types than slices, IDR slices
and SEI; an SPS outside the profile allowlist or above the configured picture
size, or one that disagrees with the track's declared size; and a duration
that does not match the segment's ``start_ms``..``end_ms`` within one frame.

Passing this check is not decodability: ``ValidatedH264Segments`` also runs
the injected full-frame decoder. Until such a decoder exists in production,
Main keeps refusing every segment (``RefuseUnvalidatedSegments``).
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Protocol

from .model import RecordingError, Segment


CODEC = "h264"
CONTAINER = "fmp4"
# Constrained Baseline / Baseline (66), Main (77), High (100).
DEFAULT_PROFILES = frozenset({66, 77, 100})
_HIGH_PROFILES = frozenset({100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135})
_SAMPLE_NAL_TYPES = frozenset({1, 5, 6})
_SYNC_FLAGS = 0x02000000
_NON_SYNC_FLAGS = 0x01010000
_MAX_BOXES = 64
_MAX_EXP_GOLOMB_ZEROS = 31


def _refuse(code: str):
    raise RecordingError(code)


@dataclass(frozen=True)
class _Box:
    kind: bytes
    payload: bytes


def _boxes(data: bytes, expected: tuple[bytes, ...]) -> list[_Box]:
    """The sibling boxes of ``data``; they must be exactly ``expected`` in order."""
    boxes = []
    position = 0
    while position < len(data):
        if len(data) - position < 8 or len(boxes) >= _MAX_BOXES:
            _refuse("SEGMENT_CONTAINER_INVALID")
        size, kind = struct.unpack_from(">I4s", data, position)
        if size < 8 or position + size > len(data):
            _refuse("SEGMENT_CONTAINER_INVALID")
        boxes.append(_Box(kind, data[position + 8:position + size]))
        position += size
    if tuple(box.kind for box in boxes) != expected:
        _refuse("SEGMENT_CONTAINER_UNEXPECTED_BOX")
    return boxes


def _full(payload: bytes, version: int, flags: int, minimum: int) -> bytes:
    if len(payload) < 4 + minimum:
        _refuse("SEGMENT_CONTAINER_INVALID")
    header = struct.unpack_from(">I", payload)[0]
    if header >> 24 != version or header & 0xFFFFFF != flags:
        _refuse("SEGMENT_CONTAINER_UNEXPECTED_BOX")
    return payload[4:]


def _rbsp(payload: bytes) -> bytes:
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
        self.data, self.position = data, 0

    def bit(self) -> int:
        index = self.position >> 3
        if index >= len(self.data):
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
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
                _refuse("SEGMENT_PARAMETER_SET_INVALID")
        return (1 << zeros) - 1 + self.bits(zeros)

    def se(self) -> int:
        value = self.ue()
        return (value + 1) // 2 if value & 1 else -(value // 2)


@dataclass(frozen=True)
class SpsInfo:
    profile_idc: int
    level_idc: int
    width: int
    height: int


def parse_sps(nal: bytes) -> SpsInfo:
    """The profile, level and cropped picture size of an SPS NAL unit (7.3.2.1.1)."""
    if len(nal) < 4 or nal[0] & 0x9F != 0x07:
        _refuse("SEGMENT_PARAMETER_SET_INVALID")
    bits = _Bits(_rbsp(nal[1:]))
    profile = bits.bits(8)
    bits.bits(8)  # constraint_set flags and reserved bits
    level = bits.bits(8)
    if bits.ue() > 31:
        _refuse("SEGMENT_PARAMETER_SET_INVALID")
    chroma, separate = 1, 0
    if profile in _HIGH_PROFILES:
        chroma = bits.ue()
        if chroma > 3:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        if chroma == 3:
            separate = bits.bit()
        if bits.ue() > 6 or bits.ue() > 6:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        bits.bit()
        if bits.bit():
            for index in range(8 if chroma != 3 else 12):
                if bits.bit():
                    last = following = 8
                    for _ in range(16 if index < 6 else 64):
                        if following:
                            delta = bits.se()
                            if not -128 <= delta <= 127:
                                _refuse("SEGMENT_PARAMETER_SET_INVALID")
                            following = (last + delta + 256) % 256
                        last = following or last
    if bits.ue() > 12:
        _refuse("SEGMENT_PARAMETER_SET_INVALID")
    order = bits.ue()
    if order == 0:
        if bits.ue() > 12:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
    elif order == 1:
        bits.bit()
        bits.se()
        bits.se()
        cycle = bits.ue()
        if cycle > 255:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        for _ in range(cycle):
            bits.se()
    elif order != 2:
        _refuse("SEGMENT_PARAMETER_SET_INVALID")
    bits.ue()
    bits.bit()
    width_mbs, height_units = bits.ue() + 1, bits.ue() + 1
    frame_mbs_only = bits.bit()
    if not frame_mbs_only:
        bits.bit()
    bits.bit()
    crop = (bits.ue(), bits.ue(), bits.ue(), bits.ue()) if bits.bit() else (0, 0, 0, 0)
    array = 0 if separate else chroma
    unit_x = 1 if array == 0 else (2 if array in (1, 2) else 1)
    unit_y = (2 - frame_mbs_only) * (1 if array == 0 else (2 if array == 1 else 1))
    width = width_mbs * 16 - unit_x * (crop[0] + crop[1])
    height = (2 - frame_mbs_only) * height_units * 16 - unit_y * (crop[2] + crop[3])
    if not 1 <= width <= 65535 or not 1 <= height <= 65535:
        _refuse("SEGMENT_PARAMETER_SET_INVALID")
    return SpsInfo(profile, level, width, height)


@dataclass(frozen=True)
class SegmentStructure:
    """What the structural check established about one segment."""

    width: int
    height: int
    profile_idc: int
    timescale: int
    sample_count: int
    duration: int
    sync_samples: int
    sps: bytes
    pps: bytes


class StructuralH264Fmp4:
    """The structural check; ``inspect`` returns the facts or raises ``RecordingError``."""

    def __init__(self, *, maximum_width: int, maximum_height: int,
                 profiles: frozenset = DEFAULT_PROFILES, maximum_samples: int = 36000):
        for value in (maximum_width, maximum_height, maximum_samples):
            if type(value) is not int or not 1 <= value <= 65535 * 16:
                raise ValueError("invalid structural limits")
        if not profiles or any(type(item) is not int for item in profiles):
            raise ValueError("invalid profile allowlist")
        self.maximum_width, self.maximum_height = maximum_width, maximum_height
        self.profiles, self.maximum_samples = frozenset(profiles), maximum_samples

    def validate(self, segment: Segment) -> None:
        self.inspect(segment)

    def inspect(self, segment: Segment) -> SegmentStructure:
        if segment.codec != CODEC or segment.container != CONTAINER:
            _refuse("SEGMENT_FORMAT_UNSUPPORTED")
        data = segment.data
        ftyp, moov, moof, mdat = _boxes(data, (b"ftyp", b"moov", b"moof", b"mdat"))
        if len(ftyp.payload) < 8 or ftyp.payload[:4] not in (b"iso6", b"isom", b"iso5"):
            _refuse("SEGMENT_CONTAINER_INVALID")
        timescale, width, height, sps, pps = self._moov(moov.payload)
        info = parse_sps(sps)
        if info.profile_idc not in self.profiles:
            _refuse("SEGMENT_PROFILE_UNSUPPORTED")
        if info.width > self.maximum_width or info.height > self.maximum_height:
            _refuse("SEGMENT_DIMENSIONS_EXCEEDED")
        if (info.width, info.height) != (width, height):
            _refuse("SEGMENT_DIMENSIONS_INCONSISTENT")
        moof_offset = len(ftyp.payload) + 8 + len(moov.payload) + 8
        mdat_start = moof_offset + len(moof.payload) + 8 + 8
        sizes, flags, sample_duration = self._moof(moof.payload, moof_offset, mdat_start)
        if sum(sizes) != len(mdat.payload):
            _refuse("SEGMENT_SAMPLES_INCONSISTENT")
        position = 0
        for index, (size, sample_flags) in enumerate(zip(sizes, flags)):
            idr = self._sample(mdat.payload[position:position + size])
            if (sample_flags == _SYNC_FLAGS) != idr:
                _refuse("SEGMENT_SYNC_FLAGS_INCONSISTENT")
            if index == 0 and not idr:
                _refuse("SEGMENT_MUST_START_WITH_IDR")
            position += size
        duration = sample_duration * len(sizes)
        expected_ms = segment.end_ms - segment.start_ms
        frame_ms = -(-sample_duration * 1000 // timescale)
        if abs(duration * 1000 // timescale - expected_ms) > frame_ms:
            _refuse("SEGMENT_DURATION_INCONSISTENT")
        return SegmentStructure(info.width, info.height, info.profile_idc, timescale, len(sizes),
                                duration, sum(item == _SYNC_FLAGS for item in flags), sps, pps)

    def _moov(self, payload):
        mvhd, trak, mvex = _boxes(payload, (b"mvhd", b"trak", b"mvex"))
        _full(mvhd.payload, 0, 0, 96)
        tkhd, mdia = _boxes(trak.payload, (b"tkhd", b"mdia"))
        body = _full(tkhd.payload, 0, 0x000003, 80)
        width, height = struct.unpack_from(">II", body, 72)
        if width & 0xFFFF or height & 0xFFFF:
            _refuse("SEGMENT_CONTAINER_INVALID")
        width, height = width >> 16, height >> 16
        mdhd, hdlr, minf = _boxes(mdia.payload, (b"mdhd", b"hdlr", b"minf"))
        timescale = struct.unpack_from(">I", _full(mdhd.payload, 0, 0, 20), 8)[0]
        if timescale == 0:
            _refuse("SEGMENT_CONTAINER_INVALID")
        if _full(hdlr.payload, 0, 0, 20)[4:8] != b"vide":
            _refuse("SEGMENT_NOT_VIDEO_ONLY")
        vmhd, dinf, stbl = _boxes(minf.payload, (b"vmhd", b"dinf", b"stbl"))
        _full(vmhd.payload, 0, 1, 8)
        (dref,) = _boxes(dinf.payload, (b"dref",))
        if struct.unpack_from(">I", _full(dref.payload, 0, 0, 4))[0] != 1:
            _refuse("SEGMENT_CONTAINER_INVALID")
        stsd, stts, stsc, stsz, stco = _boxes(stbl.payload,
                                              (b"stsd", b"stts", b"stsc", b"stsz", b"stco"))
        for box, size in ((stts, 4), (stsc, 4), (stsz, 8), (stco, 4)):
            body = _full(box.payload, 0, 0, size)
            if len(body) != size or any(body):
                # Fragmented: every sample lives in the movie fragment.
                _refuse("SEGMENT_CONTAINER_INVALID")
        body = _full(stsd.payload, 0, 0, 4)
        if struct.unpack_from(">I", body)[0] != 1:
            _refuse("SEGMENT_NOT_VIDEO_ONLY")
        (avc1,) = _boxes(body[4:], (b"avc1",))
        entry = avc1.payload
        if len(entry) < 78 or struct.unpack_from(">HH", entry, 24) != (width, height):
            _refuse("SEGMENT_DIMENSIONS_INCONSISTENT")
        (avcc,) = _boxes(entry[78:], (b"avcC",))
        sps, pps = self._avcc(avcc.payload)
        (trex,) = _boxes(mvex.payload, (b"trex",))
        _full(trex.payload, 0, 0, 20)
        return timescale, width, height, sps, pps

    @staticmethod
    def _avcc(body):
        if len(body) < 7 or body[0] != 1 or body[4] != 0xFF or body[5] != 0xE1:
            # One SPS, 4-byte NAL lengths: the writer's only form.
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        length = struct.unpack_from(">H", body, 6)[0]
        sps = body[8:8 + length]
        rest = body[8 + length:]
        if len(sps) != length or len(rest) < 3 or rest[0] != 1:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        length = struct.unpack_from(">H", rest, 1)[0]
        pps = rest[3:3 + length]
        if len(pps) != length or not pps or pps[0] & 0x1F != 8:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        if sps[1:4] != body[1:4]:
            _refuse("SEGMENT_PARAMETER_SET_INVALID")
        return sps, pps

    def _moof(self, payload, moof_offset, mdat_start):
        mfhd, traf = _boxes(payload, (b"mfhd", b"traf"))
        _full(mfhd.payload, 0, 0, 4)
        tfhd, tfdt, trun = _boxes(traf.payload, (b"tfhd", b"tfdt", b"trun"))
        track, sample_duration = struct.unpack_from(">II", _full(tfhd.payload, 0, 0x020008, 8))
        if track != 1 or sample_duration == 0:
            _refuse("SEGMENT_CONTAINER_INVALID")
        _full(tfdt.payload, 1, 0, 8)
        body = _full(trun.payload, 0, 0x000601, 8)
        count, offset = struct.unpack_from(">Ii", body)
        if not 1 <= count <= self.maximum_samples or len(body) != 8 + 8 * count:
            _refuse("SEGMENT_SAMPLES_INCONSISTENT")
        if moof_offset + offset != mdat_start:
            _refuse("SEGMENT_SAMPLES_INCONSISTENT")
        entries = [struct.unpack_from(">II", body, 8 + 8 * index) for index in range(count)]
        if any(flags not in (_SYNC_FLAGS, _NON_SYNC_FLAGS) for _size, flags in entries):
            _refuse("SEGMENT_SYNC_FLAGS_INCONSISTENT")
        return [size for size, _flags in entries], [flags for _size, flags in entries], \
            sample_duration

    @staticmethod
    def _sample(sample):
        """Whether the sample is an IDR picture; its NAL units must fill it exactly."""
        if not sample:
            _refuse("SEGMENT_SAMPLES_INCONSISTENT")
        position, types = 0, []
        while position < len(sample):
            if len(sample) - position < 5:
                _refuse("SEGMENT_SAMPLES_INCONSISTENT")
            length = struct.unpack_from(">I", sample, position)[0]
            if length == 0 or position + 4 + length > len(sample):
                _refuse("SEGMENT_SAMPLES_INCONSISTENT")
            header = sample[position + 4]
            if header & 0x80:
                _refuse("SEGMENT_SAMPLES_INCONSISTENT")
            types.append(header & 0x1F)
            position += 4 + length
        if any(kind not in _SAMPLE_NAL_TYPES for kind in types):
            _refuse("SEGMENT_NAL_TYPE_UNSUPPORTED")
        slices = [kind for kind in types if kind in (1, 5)]
        if not slices or len(set(slices)) != 1:
            _refuse("SEGMENT_SAMPLES_INCONSISTENT")
        return slices[0] == 5


class FrameDecoder(Protocol):
    def decode_all(self, data: bytes, structure: SegmentStructure) -> None:
        """Decode every frame of the segment in a confined child; raise ``RecordingError``."""


class ValidatedH264Segments:
    """``SegmentValidator``: the structural check, then the full-frame decode."""

    def __init__(self, structure: StructuralH264Fmp4, decoder: FrameDecoder):
        if not isinstance(structure, StructuralH264Fmp4) or not callable(
                getattr(decoder, "decode_all", None)):
            raise ValueError("a structural check and a frame decoder are required")
        self.structure, self.decoder = structure, decoder

    def validate(self, segment: Segment) -> None:
        facts = self.structure.inspect(segment)
        self.decoder.decode_all(segment.data, facts)
