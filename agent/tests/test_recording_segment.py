"""Recording segment format core (Issue #16 PR A): Annex B, fMP4 and pacing.

Synthetic bitstreams only: the parameter sets are built bit by bit from the
H.264 syntax, and slice payloads are opaque bytes. These tests establish the
byte-stream structure, the MP4 box layout and the slot pacing; they do not
claim that a real encoder's output decodes (that is PR B and the real host).
"""
from __future__ import annotations

import struct
import unittest

from media_capture_agent.fmp4 import Fmp4Error, read_boxes, write_segment
from media_capture_agent.frame_pacer import FramePacer, PacedFrame, PacedGap
from media_capture_agent.h264_annexb import (AccessUnitSplitter, AnnexBError,
                                             NON_SYNC_SAMPLE_FLAGS, SYNC_SAMPLE_FLAGS,
                                             parse_sps, rbsp, validate_segment)


class BitWriter:
    def __init__(self):
        self.bits: list[int] = []

    def u(self, count, value):
        self.bits.extend((value >> (count - 1 - i)) & 1 for i in range(count))
        return self

    def ue(self, value):
        code = value + 1
        length = code.bit_length()
        return self.u(length - 1, 0).u(length, code)

    def se(self, value):
        return self.ue(2 * value - 1 if value > 0 else -2 * value)

    def rbsp(self) -> bytes:
        bits = self.bits + [1]  # rbsp_stop_one_bit
        bits += [0] * (-len(bits) % 8)
        return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))


def escape(payload: bytes) -> bytes:
    """Insert emulation prevention bytes (the inverse of ``rbsp``)."""
    out = bytearray()
    zeros = 0
    for byte in payload:
        if zeros >= 2 and byte <= 3:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def sps(*, profile=66, width_mbs=80, height_mbs=45, crop=None, chroma=1, scaling=False,
        level=31, order_type=0):
    bits = BitWriter().u(8, profile).u(8, 0xC0 if profile == 66 else 0).u(8, level).ue(0)
    if profile in (100, 110, 122, 244):
        bits.ue(chroma)
        if chroma == 3:
            bits.u(1, 0)
        bits.ue(0).ue(0).u(1, 0).u(1, 1 if scaling else 0)
        if scaling:
            for index in range(8 if chroma != 3 else 12):
                present = 1 if index in (0, 6) else 0
                bits.u(1, present)
                if present:
                    for _ in range(16 if index < 6 else 64):
                        bits.se(1)
    bits.ue(0).ue(order_type)
    if order_type == 0:
        bits.ue(2)
    elif order_type == 1:
        bits.u(1, 0).se(0).se(0).ue(2).se(1).se(-1)
    bits.ue(1).u(1, 0).ue(width_mbs - 1).ue(height_mbs - 1).u(1, 1).u(1, 1)
    if crop:
        bits.u(1, 1)
        for value in crop:
            bits.ue(value)
    else:
        bits.u(1, 0)
    bits.u(1, 0)  # vui_parameters_present_flag
    return bytes([0x67]) + escape(bits.rbsp())


SPS = sps()
PPS = bytes([0x68, 0xCE, 0x3C, 0x80])
AUD = bytes([0x09, 0xF0])
SEI = bytes([0x06, 0x05, 0x01, 0x00, 0x80])


def _filler(tag):
    # Opaque slice data; never 0x00, so no start-code-like run can occur
    # (a real encoder guarantees this with emulation prevention bytes).
    return bytes([tag % 254 + 1])


def idr(tag=0, first_mb_zero=True, size=40):
    return bytes([0x65, 0x88 if first_mb_zero else 0x48]) + _filler(tag) * size


def slice_(tag=0, first_mb_zero=True, size=20):
    return bytes([0x41, 0x9A if first_mb_zero else 0x5A]) + _filler(tag) * size


def annexb(*nals, four=True):
    code = b"\x00\x00\x00\x01" if four else b"\x00\x00\x01"
    return b"".join(code + nal for nal in nals)


def stream(count, gop):
    nals = []
    for index in range(count):
        if index % gop == 0:
            nals += [SPS, PPS, idr(index)]
        else:
            nals.append(slice_(index))
    return annexb(*nals)


def split(data, chunk=None):
    splitter = AccessUnitSplitter(max_nal_bytes=1 << 16, max_access_unit_bytes=1 << 18)
    units = []
    if chunk is None:
        units += splitter.feed(data)
    else:
        for offset in range(0, len(data), chunk):
            units += splitter.feed(data[offset:offset + chunk])
    return units + splitter.flush()


class SpsTests(unittest.TestCase):
    def test_baseline_720p(self):
        info = parse_sps(SPS)
        self.assertEqual((info.profile_idc, info.level_idc, info.width, info.height),
                         (66, 31, 1280, 720))
        self.assertEqual((info.chroma_format_idc, info.bit_depth_luma), (1, 8))
        self.assertTrue(info.frame_mbs_only)

    def test_cropped_1080p(self):
        info = parse_sps(sps(width_mbs=120, height_mbs=68, crop=(0, 0, 0, 4)))
        self.assertEqual((info.width, info.height), (1920, 1080))

    def test_high_profile_with_scaling_lists_and_poc_type_one(self):
        info = parse_sps(sps(profile=100, scaling=True, order_type=1, width_mbs=40,
                             height_mbs=30))
        self.assertEqual((info.profile_idc, info.width, info.height), (100, 640, 480))

    def test_high_444_crop_unit(self):
        info = parse_sps(sps(profile=244, chroma=3, width_mbs=2, height_mbs=2, crop=(1, 1, 1, 1)))
        self.assertEqual((info.chroma_format_idc, info.width, info.height), (3, 30, 30))

    def test_emulation_prevention_is_removed(self):
        self.assertEqual(rbsp(b"\x00\x00\x03\x01\x00\x00\x03\x00"), b"\x00\x00\x01\x00\x00\x00")

    def test_refusals(self):
        for nal, reason in ((PPS, "not_a_sequence_parameter_set"),
                            (SPS[:4], "truncated_parameter_set"),
                            (bytes([0x67, 66, 0, 31]) + b"\x00" * 6, "invalid_exp_golomb")):
            with self.subTest(reason=reason), self.assertRaises(AnnexBError) as caught:
                parse_sps(nal)
            self.assertEqual(caught.exception.reason, reason)


class SplitterTests(unittest.TestCase):
    def test_access_units_are_split_at_parameter_sets_and_first_slices(self):
        units = split(stream(6, 3))
        self.assertEqual([unit.types for unit in units],
                         [(7, 8, 5), (1,), (1,), (7, 8, 5), (1,), (1,)])
        self.assertEqual([unit.is_idr for unit in units], [True, False, False] * 2)

    def test_any_chunking_gives_the_same_units(self):
        data = annexb(AUD, SPS, PPS, SEI, idr(1), AUD, slice_(2), slice_(3, first_mb_zero=False),
                      AUD, slice_(4), four=False)
        whole = [unit.nals for unit in split(data)]
        self.assertEqual(len(whole), 3)
        self.assertEqual([len(nals) for nals in whole], [5, 3, 2])
        for chunk in (1, 2, 3, 7, 64):
            with self.subTest(chunk=chunk):
                self.assertEqual([unit.nals for unit in split(data, chunk)], whole)

    def test_trailing_zero_bytes_belong_to_the_next_start_code(self):
        units = split(b"\x00\x00" + annexb(SPS, PPS, idr(1)) + b"\x00\x00" + annexb(slice_(2)))
        self.assertEqual([nal.data for nal in units[0].nals], [SPS, PPS, idr(1)])
        self.assertEqual(units[1].nals[0].data, slice_(2))

    def test_garbage_before_the_first_start_code_is_refused(self):
        splitter = AccessUnitSplitter(max_nal_bytes=64, max_access_unit_bytes=64)
        with self.assertRaises(AnnexBError) as caught:
            splitter.feed(b"\x01\x00\x00\x01\x67")
        self.assertEqual(caught.exception.reason, "missing_start_code")

    def test_forbidden_bit_and_size_bounds(self):
        with self.assertRaises(AnnexBError) as caught:
            split(annexb(bytes([0xE5, 0x88])))
        self.assertEqual(caught.exception.reason, "forbidden_zero_bit")
        splitter = AccessUnitSplitter(max_nal_bytes=32, max_access_unit_bytes=1 << 10)
        with self.assertRaises(AnnexBError) as caught:
            splitter.feed(b"\x00\x00\x01" + idr(size=64))
        self.assertEqual(caught.exception.reason, "nal_unit_too_large")
        splitter = AccessUnitSplitter(max_nal_bytes=1 << 10, max_access_unit_bytes=50)
        with self.assertRaises(AnnexBError) as caught:
            splitter.feed(annexb(SPS, PPS, idr(size=40), slice_()))
        self.assertEqual(caught.exception.reason, "access_unit_too_large")

    def test_a_nal_at_the_bound_survives_any_chunk_boundary(self):
        # PR #431 review: a chunk ending inside the next four-byte start code
        # (after "00 00 00", before "01") must not count those zeros.
        nal = idr(size=30)  # 32 bytes
        data = annexb(nal, slice_(), four=True)
        for split_at in range(len(data) + 1):
            splitter = AccessUnitSplitter(max_nal_bytes=len(nal), max_access_unit_bytes=1 << 10)
            with self.subTest(split_at=split_at):
                units = splitter.feed(data[:split_at]) + splitter.feed(data[split_at:])
                units += splitter.flush()
                self.assertEqual([[n.data for n in unit.nals] for unit in units],
                                 [[nal], [slice_()]])

    def test_zero_byte_runs_are_bounded(self):
        splitter = AccessUnitSplitter(max_nal_bytes=64, max_access_unit_bytes=1 << 10)
        splitter.feed(b"\x00\x00\x01" + idr(size=10))
        with self.assertRaises(AnnexBError) as caught:
            for _ in range(10):
                splitter.feed(bytes(1024))
        self.assertEqual(caught.exception.reason, "zero_byte_run_too_long")

    def test_pending_bytes_stay_bounded_without_a_start_code(self):
        splitter = AccessUnitSplitter(max_nal_bytes=100, max_access_unit_bytes=1 << 10)
        splitter.feed(b"\x00\x00\x01")
        with self.assertRaises(AnnexBError):
            for _ in range(20):
                splitter.feed(b"\x41" * 10)


class ValidateSegmentTests(unittest.TestCase):
    def test_valid_segment_becomes_length_prefixed_samples(self):
        segment = validate_segment(split(stream(6, 3)), expected_count=6)
        self.assertEqual((segment.sps, segment.pps), (SPS, PPS))
        self.assertEqual(segment.sync, (True, False, False, True, False, False))
        self.assertEqual(segment.samples[0], struct.pack(">I", len(idr(0))) + idr(0))
        self.assertEqual(segment.samples[1], struct.pack(">I", len(slice_(1))) + slice_(1))
        self.assertEqual((segment.info.width, segment.info.height), (1280, 720))

    def test_delimiters_are_dropped_and_sei_is_kept(self):
        units = split(annexb(AUD, SPS, PPS, SEI, idr(1), AUD, slice_(2)))
        segment = validate_segment(units, expected_count=2)
        self.assertEqual(segment.samples[0],
                         struct.pack(">I", len(SEI)) + SEI + struct.pack(">I", len(idr(1))) + idr(1))

    def test_refusals(self):
        other_sps = sps(width_mbs=40, height_mbs=30)
        cases = (
            (stream(5, 3), 6, "access_unit_count_mismatch"),
            (annexb(slice_(0), slice_(1)), 2, "segment_must_start_with_idr"),
            (annexb(SPS, idr(0), slice_(1)), 2, "segment_must_start_with_idr"),
            (annexb(SPS, PPS, idr(0), other_sps, PPS, idr(1)), 2, "parameter_set_changed"),
            (annexb(SPS, PPS, idr(0), bytes([0x74, 0x80])), 1, "unsupported_nal_type"),
            (annexb(SPS, PPS, idr(0), SEI, AUD), 2, "access_unit_without_slice"),
        )
        for data, count, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(AnnexBError) as caught:
                validate_segment(split(data), expected_count=count)
            self.assertEqual(caught.exception.reason, reason)


def boxes(data, path):
    """Return the payload of the box at ``path`` (e.g. b"moov/trak/tkhd")."""
    node = data
    found = None
    for kind in path.split(b"/"):
        found = next(item for item in read_boxes(node) if item.kind == kind)
        node = found.payload
    return found


class Fmp4Tests(unittest.TestCase):
    def segment(self, count=6, gop=3, **kwargs):
        options = dict(timescale=90000, sample_duration=3000, sequence_number=7,
                       base_decode_time=123456789)
        options.update(kwargs)
        stream_ = validate_segment(split(stream(count, gop)), expected_count=count)
        return stream_, write_segment(stream_, **options)

    def test_layout_is_one_self_contained_video_segment(self):
        stream_, data = self.segment()
        self.assertEqual([item.kind for item in read_boxes(data)],
                         [b"ftyp", b"moov", b"moof", b"mdat"])
        moov = boxes(data, b"moov").payload
        self.assertEqual([item.kind for item in read_boxes(moov)], [b"mvhd", b"trak", b"mvex"])
        self.assertEqual(sum(item.kind == b"trak" for item in read_boxes(moov)), 1)
        hdlr = boxes(data, b"moov/trak/mdia/hdlr").payload
        self.assertEqual(hdlr[8:12], b"vide")
        tkhd = boxes(data, b"moov/trak/tkhd").payload
        self.assertEqual(struct.unpack(">II", tkhd[-8:]), (1280 << 16, 720 << 16))
        mdhd = boxes(data, b"moov/trak/mdia/mdhd").payload
        self.assertEqual(struct.unpack(">I", mdhd[12:16])[0], 90000)

    def test_sample_entry_carries_the_parameter_sets(self):
        _stream, data = self.segment()
        stsd = boxes(data, b"moov/trak/mdia/minf/stbl/stsd").payload
        avc1 = read_boxes(stsd, start=8)[0]
        self.assertEqual(avc1.kind, b"avc1")
        self.assertEqual(struct.unpack(">HH", avc1.payload[24:28]), (1280, 720))
        avcc = read_boxes(avc1.payload, start=78)[0]
        self.assertEqual(avcc.kind, b"avcC")
        body = avcc.payload
        self.assertEqual(body[:6], bytes([1, 66, 0xC0, 31, 0xFF, 0xE1]))
        sps_length = struct.unpack(">H", body[6:8])[0]
        self.assertEqual(body[8:8 + sps_length], SPS)
        rest = body[8 + sps_length:]
        self.assertEqual(rest[0], 1)
        self.assertEqual(rest[3:3 + struct.unpack(">H", rest[1:3])[0]], PPS)

    def test_high_profile_avcc_has_chroma_and_depth(self):
        high = sps(profile=100)
        units = split(annexb(high, PPS, idr(0), slice_(1)))
        data = write_segment(validate_segment(units, expected_count=2), timescale=90000,
                             sample_duration=3000, sequence_number=1, base_decode_time=0)
        stsd = boxes(data, b"moov/trak/mdia/minf/stbl/stsd").payload
        avcc = read_boxes(read_boxes(stsd, start=8)[0].payload, start=78)[0].payload
        self.assertEqual(avcc[-4:], bytes([0xFD, 0xF8, 0xF8, 0]))

    def test_trun_points_at_every_sample_in_mdat(self):
        stream_, data = self.segment()
        top = read_boxes(data)
        moof, mdat = top[2], top[3]
        traf = boxes(moof.payload, b"traf").payload
        tfhd = boxes(traf, b"tfhd").payload
        flags = struct.unpack(">I", tfhd[:4])[0] & 0xFFFFFF
        self.assertEqual(flags, 0x020008)
        self.assertEqual(struct.unpack(">II", tfhd[4:12]), (1, 3000))
        tfdt = boxes(traf, b"tfdt").payload
        self.assertEqual(tfdt[0], 1)
        self.assertEqual(struct.unpack(">Q", tfdt[4:12])[0], 123456789)
        trun = boxes(traf, b"trun").payload
        count, offset = struct.unpack(">Ii", trun[4:12])
        self.assertEqual(count, 6)
        self.assertEqual(moof.offset + offset, mdat.offset + 8)
        entries = [struct.unpack(">II", trun[12 + 8 * i:20 + 8 * i]) for i in range(count)]
        self.assertEqual([size for size, _flags in entries], [len(s) for s in stream_.samples])
        self.assertEqual([flags for _size, flags in entries],
                         [SYNC_SAMPLE_FLAGS if s else NON_SYNC_SAMPLE_FLAGS for s in stream_.sync])
        self.assertEqual(mdat.payload, b"".join(stream_.samples))
        mfhd = boxes(moof.payload, b"mfhd").payload
        self.assertEqual(struct.unpack(">I", mfhd[4:8])[0], 7)

    def test_no_identifying_metadata(self):
        _stream, data = self.segment()
        moov = boxes(data, b"moov").payload
        kinds = set()

        def walk(payload, start=0):
            for item in read_boxes(payload, start=start):
                kinds.add(item.kind)
                if item.kind in {b"trak", b"mdia", b"minf", b"stbl", b"mvex", b"dinf"}:
                    walk(item.payload)
        walk(moov)
        self.assertFalse(kinds & {b"udta", b"meta", b"\xa9too", b"uuid"})
        mvhd = boxes(data, b"moov/mvhd").payload
        self.assertEqual(mvhd[4:12], bytes(8))  # creation/modification times are zero

    def test_parameter_refusals(self):
        stream_, _data = self.segment()
        for change in ({"timescale": 0}, {"sample_duration": 0}, {"sequence_number": 0},
                       {"timescale": 1 << 32}, {"base_decode_time": -1}, {"timescale": True}):
            options = dict(timescale=90000, sample_duration=3000, sequence_number=1,
                           base_decode_time=0)
            options.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                write_segment(stream_, **options)

    def test_box_reader_refuses_malformed_sizes(self):
        for data, reason in ((b"\x00\x00\x00\x10free", "invalid_box_size"),
                             (b"\x00\x00\x00\x04free", "invalid_box_size"),
                             (b"\x00\x00\x00", "truncated_box"),
                             (b"\x00\x00\x00\x01free\x00", "truncated_box")):
            with self.subTest(reason=reason), self.assertRaises(Fmp4Error) as caught:
                read_boxes(data)
            self.assertEqual(caught.exception.reason, reason)
        large = struct.pack(">I4sQ", 1, b"free", 16)
        self.assertEqual(read_boxes(large)[0].payload, b"")


class PacerTests(unittest.TestCase):
    def pacer(self, origin=0, period=1000, hold=1500):
        return FramePacer(origin_us=origin, period_us=period, max_hold_us=hold)

    def test_exact_rate_frames_fill_each_slot_once(self):
        pacer = self.pacer()
        out = []
        for index in range(5):
            out += pacer.offer(index * 1000, f"f{index}")
        self.assertEqual(out, [PacedFrame(i, f"f{i}", False) for i in range(5)])
        self.assertEqual((pacer.repeated, pacer.dropped), (0, 0))

    def test_slow_camera_repeats_and_fast_camera_drops(self):
        slow = self.pacer()
        out = []
        for time in (0, 1500, 3000):
            out += slow.offer(time, time)
        out += slow.advance(3000)
        self.assertEqual([(f.index, f.item, f.repeated) for f in out],
                         [(0, 0, False), (1, 0, True), (2, 1500, False), (3, 3000, False)])
        self.assertEqual(slow.repeated, 1)
        fast = self.pacer()
        out = []
        for time in (0, 400, 800, 1200, 1600, 2000):
            out += fast.offer(time, time)
        self.assertEqual([(f.index, f.item) for f in out], [(0, 0), (1, 800), (2, 2000)])
        self.assertEqual(fast.dropped, 3)

    def test_a_long_interruption_is_one_gap_not_a_stretched_frame(self):
        pacer = self.pacer(hold=1500)
        out = pacer.offer(0, "a")
        out += pacer.advance(10_000_000_000)  # a clock jump: still one bounded range
        self.assertEqual(out[:2], [PacedFrame(0, "a", False), PacedFrame(1, "a", True)])
        self.assertEqual(out[2:], [PacedGap(2, 10_000_001)])
        out = pacer.offer(10_000_001_000, "b")
        self.assertEqual(out, [PacedFrame(10_000_001, "b", False)])

    def test_gap_before_the_first_frame_and_origin_offset(self):
        pacer = self.pacer(origin=5000)
        self.assertEqual(pacer.advance(4999), [])
        out = pacer.offer(7200, "a")
        self.assertEqual(out, [PacedGap(0, 3)])
        self.assertEqual(pacer.advance(8000), [PacedFrame(3, "a", False)])

    def test_stale_advance_time_decides_nothing(self):
        pacer = self.pacer()
        pacer.offer(0, "a")
        out = pacer.offer(5000, "b")
        self.assertEqual(out[-1], PacedFrame(5, "b", False))
        self.assertEqual(pacer.advance(3000), [])

    def test_validation(self):
        with self.assertRaises(ValueError):
            self.pacer(period=0)
        with self.assertRaises(TypeError):
            self.pacer(origin=0.5)
        pacer = self.pacer()
        pacer.offer(1000, "a")
        with self.assertRaises(ValueError):
            pacer.offer(999, "b")
        with self.assertRaises(TypeError):
            pacer.offer(True, "c")


if __name__ == "__main__":
    unittest.main()
