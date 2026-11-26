"""Self-contained fragmented-MP4 recording segments for H.264 (Issue #16).

Owner decisions: D13 (2026-11-08) chose an own fragmented-MP4 writer for
H.264 recordings with GStreamer only in the encode/decode children, and
2026-11-26 chose OpenH264 H.264 for the Agent ring. Each ring segment is
written by ``write_segment`` as one independent file:

    ftyp | moov (mvhd, trak(tkhd, mdia(mdhd, hdlr 'vide', minf(vmhd, dinf,
    stbl(stsd(avc1(avcC)), empty stts/stsc/stsz/stco)))), mvex(trex))
    | moof (mfhd, traf(tfhd, tfdt, trun)) | mdat

so a segment is playable and verifiable on its own, without an init segment
or the segments around it. There is exactly one video track and no audio
track (video only, by requirement). The ``trun`` gives every sample its size
and sync flag; all samples share one fixed duration (``tfhd`` default), so
the segment's duration is ``sample_count * sample_duration`` exactly. Times in
the file are media time from ``base_decode_time``; wall-clock times stay in
the ring ledger, and no date, host, camera or other identifying metadata is
written. ``read_boxes`` is a bounded ISO BMFF box reader used to verify the
written structure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct

from .h264_annexb import (NON_SYNC_SAMPLE_FLAGS, SYNC_SAMPLE_FLAGS, SegmentStream,
                          _HIGH_PROFILES)


TRACK_ID = 1
_UINT32 = 0xFFFFFFFF
_MATRIX = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
_LANGUAGE_UND = 0x55C4  # ISO 639-2 "und", packed 5-bit letters
_DEFAULT_BASE_IS_MOOF = 0x020000
_DEFAULT_SAMPLE_DURATION_PRESENT = 0x000008
_TRUN_DATA_OFFSET = 0x000001
_TRUN_SAMPLE_SIZE = 0x000200
_TRUN_SAMPLE_FLAGS = 0x000400


class Fmp4Error(ValueError):
    """A refused segment or box structure; ``reason`` is a fixed word."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def box(kind: bytes, *payload: bytes) -> bytes:
    body = b"".join(payload)
    size = 8 + len(body)
    if len(kind) != 4 or size > _UINT32:
        raise Fmp4Error("box_too_large")
    return struct.pack(">I", size) + kind + body


def full_box(kind: bytes, version: int, flags: int, *payload: bytes) -> bytes:
    return box(kind, struct.pack(">I", (version << 24) | flags), *payload)


def _avcc(stream: SegmentStream) -> bytes:
    sps, pps, info = stream.sps, stream.pps, stream.info
    if len(sps) > 0xFFFF or len(pps) > 0xFFFF:
        raise Fmp4Error("parameter_set_too_large")
    body = bytes([1, sps[1], sps[2], sps[3], 0xFF, 0xE1])
    body += struct.pack(">H", len(sps)) + sps + bytes([1]) + struct.pack(">H", len(pps)) + pps
    if info.profile_idc in _HIGH_PROFILES:
        body += bytes([0xFC | info.chroma_format_idc, 0xF8 | (info.bit_depth_luma - 8),
                       0xF8 | (info.bit_depth_chroma - 8), 0])
    return box(b"avcC", body)


def _avc1(stream: SegmentStream) -> bytes:
    info = stream.info
    return box(
        b"avc1",
        bytes(6), struct.pack(">H", 1),            # reserved, data_reference_index
        bytes(16),                                  # pre_defined / reserved
        struct.pack(">HH", info.width, info.height),
        struct.pack(">II", 0x00480000, 0x00480000),  # 72 dpi
        bytes(4), struct.pack(">H", 1),             # reserved, frame_count
        bytes(32),                                  # compressorname (empty)
        struct.pack(">Hh", 0x0018, -1),             # depth, pre_defined
        _avcc(stream),
    )


def _moov(stream: SegmentStream, timescale: int) -> bytes:
    info = stream.info
    mvhd = full_box(b"mvhd", 0, 0, struct.pack(">IIII", 0, 0, timescale, 0),
                    struct.pack(">IH", 0x00010000, 0x0100), bytes(10), _MATRIX, bytes(24),
                    struct.pack(">I", TRACK_ID + 1))
    tkhd = full_box(b"tkhd", 0, 0x000003, struct.pack(">IIIII", 0, 0, TRACK_ID, 0, 0),
                    bytes(8), struct.pack(">hhhH", 0, 0, 0, 0), _MATRIX,
                    struct.pack(">II", info.width << 16, info.height << 16))
    mdhd = full_box(b"mdhd", 0, 0, struct.pack(">IIIIHH", 0, 0, timescale, 0, _LANGUAGE_UND, 0))
    hdlr = full_box(b"hdlr", 0, 0, bytes(4), b"vide", bytes(12), b"VideoHandler\x00")
    vmhd = full_box(b"vmhd", 0, 1, bytes(8))
    dinf = box(b"dinf", full_box(b"dref", 0, 0, struct.pack(">I", 1), full_box(b"url ", 0, 1)))
    stbl = box(b"stbl",
               full_box(b"stsd", 0, 0, struct.pack(">I", 1), _avc1(stream)),
               full_box(b"stts", 0, 0, struct.pack(">I", 0)),
               full_box(b"stsc", 0, 0, struct.pack(">I", 0)),
               full_box(b"stsz", 0, 0, struct.pack(">II", 0, 0)),
               full_box(b"stco", 0, 0, struct.pack(">I", 0)))
    trak = box(b"trak", tkhd, box(b"mdia", mdhd, hdlr, box(b"minf", vmhd, dinf, stbl)))
    trex = full_box(b"trex", 0, 0, struct.pack(">IIIII", TRACK_ID, 1, 0, 0, 0))
    return box(b"moov", mvhd, trak, box(b"mvex", trex))


def _moof(stream: SegmentStream, sequence_number: int, base_decode_time: int,
          sample_duration: int, data_offset: int) -> bytes:
    tfhd = full_box(b"tfhd", 0, _DEFAULT_BASE_IS_MOOF | _DEFAULT_SAMPLE_DURATION_PRESENT,
                    struct.pack(">II", TRACK_ID, sample_duration))
    tfdt = full_box(b"tfdt", 1, 0, struct.pack(">Q", base_decode_time))
    entries = b"".join(
        struct.pack(">II", len(sample), SYNC_SAMPLE_FLAGS if is_sync else NON_SYNC_SAMPLE_FLAGS)
        for sample, is_sync in zip(stream.samples, stream.sync))
    trun = full_box(b"trun", 0, _TRUN_DATA_OFFSET | _TRUN_SAMPLE_SIZE | _TRUN_SAMPLE_FLAGS,
                    struct.pack(">Ii", len(stream.samples), data_offset), entries)
    return box(b"moof", full_box(b"mfhd", 0, 0, struct.pack(">I", sequence_number)),
               box(b"traf", tfhd, tfdt, trun))


def _uint(value, name, *, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name} out of range")


def write_segment(stream: SegmentStream, *, timescale: int, sample_duration: int,
                  sequence_number: int, base_decode_time: int) -> bytes:
    """Return one independent fMP4 segment holding every sample of ``stream``."""
    if not isinstance(stream, SegmentStream) or not stream.samples:
        raise ValueError("a validated, non-empty SegmentStream is required")
    if len(stream.samples) != len(stream.sync) or not stream.sync[0]:
        raise Fmp4Error("segment_must_start_with_sync_sample")
    _uint(timescale, "timescale", maximum=_UINT32)
    _uint(sample_duration, "sample_duration", maximum=_UINT32)
    _uint(sequence_number, "sequence_number", maximum=_UINT32)
    _uint(base_decode_time, "base_decode_time", maximum=(1 << 64) - 1)
    if timescale == 0 or sample_duration == 0 or sequence_number == 0:
        raise ValueError("timescale, sample_duration and sequence_number must be positive")
    head = box(b"ftyp", b"iso6", struct.pack(">I", 0), b"iso6", b"isom", b"avc1", b"mp41")
    head += _moov(stream, timescale)
    # The moof size does not depend on the offset value, so measure it once.
    moof_size = len(_moof(stream, sequence_number, base_decode_time, sample_duration, 0))
    moof = _moof(stream, sequence_number, base_decode_time, sample_duration, moof_size + 8)
    return head + moof + box(b"mdat", *stream.samples)


@dataclass(frozen=True)
class Box:
    kind: bytes
    offset: int
    payload: bytes = field(repr=False)


def read_boxes(data: bytes, *, start: int = 0, end: int | None = None,
               max_boxes: int = 4096) -> list[Box]:
    """Read the sibling boxes of ``data[start:end]``; refuse any malformed size."""
    end = len(data) if end is None else end
    boxes: list[Box] = []
    position = start
    while position < end:
        if end - position < 8:
            raise Fmp4Error("truncated_box")
        size, kind = struct.unpack_from(">I4s", data, position)
        header = 8
        if size == 1:
            if end - position < 16:
                raise Fmp4Error("truncated_box")
            size = struct.unpack_from(">Q", data, position + 8)[0]
            header = 16
        if size < header or position + size > end:
            raise Fmp4Error("invalid_box_size")
        boxes.append(Box(kind, position, data[position + header:position + size]))
        if len(boxes) > max_boxes:
            raise Fmp4Error("too_many_boxes")
        position += size
    return boxes
