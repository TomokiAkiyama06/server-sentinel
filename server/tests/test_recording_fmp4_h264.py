"""Structural validation of H.264 fMP4 segments (Issue #313, D13).

Contract with the Agent's writer (Issue #16): a segment written by
``agent/media_capture_agent/fmp4.py`` passes; every deviation from that exact
layout is refused with a fixed code. Synthetic parameter sets and opaque
slice bytes only (no decoding happens here; that is the decoder's half).
"""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest
from uuid import UUID

from app.media.recording.fmp4_h264 import (StructuralH264Fmp4, ValidatedH264Segments,
                                           parse_sps)
from app.media.recording.model import RecordingError, Segment


AGENT = str(Path(__file__).resolve().parents[2] / "agent")
SOURCE = UUID(int=7)
STREAM = UUID(int=8)
writer = None


def setUpModule():
    # A module adds a path only while its tests run (Issue #284).
    global writer
    sys.path.insert(0, AGENT)
    unittest.addModuleCleanup(lambda: sys.path.remove(AGENT))
    from media_capture_agent import fmp4, h264_annexb
    writer = (fmp4, h264_annexb)


class Bits:
    def __init__(self):
        self.bits = []

    def u(self, count, value):
        self.bits.extend((value >> (count - 1 - i)) & 1 for i in range(count))
        return self

    def ue(self, value):
        code = value + 1
        return self.u(code.bit_length() - 1, 0).u(code.bit_length(), code)

    def rbsp(self):
        bits = self.bits + [1]
        bits += [0] * (-len(bits) % 8)
        return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))


def sps(width_mbs=80, height_mbs=45, profile=66):
    bits = Bits().u(8, profile).u(8, 0xC0).u(8, 31).ue(0)
    bits.ue(0).ue(0).ue(2).ue(1).u(1, 0).ue(width_mbs - 1).ue(height_mbs - 1).u(1, 1).u(1, 1)
    bits.u(1, 0).u(1, 0)
    return bytes([0x67]) + bits.rbsp()


PPS = bytes([0x68, 0xCE, 0x3C, 0x80])


def slice_(kind, tag, size=30):
    first = 0x65 if kind == 5 else 0x41
    return bytes([first, 0x88]) + bytes([tag % 254 + 1]) * size


def segment_bytes(count=30, gop=15, parameter_set=None, sample_duration=3000):
    fmp4, annexb = writer
    code = b"\x00\x00\x00\x01"
    stream = b""
    for index in range(count):
        if index % gop == 0:
            stream += code + (parameter_set or sps()) + code + PPS + code + slice_(5, index)
        else:
            stream += code + slice_(1, index)
    splitter = annexb.AccessUnitSplitter(max_nal_bytes=1 << 20, max_access_unit_bytes=1 << 20)
    units = splitter.feed(stream) + splitter.flush()
    validated = annexb.validate_segment(units, expected_count=count)
    return fmp4.write_segment(validated, timescale=90000, sample_duration=sample_duration,
                              sequence_number=1, base_decode_time=0)


def segment(data, *, start_ms=1_000_000, end_ms=1_001_000, codec="h264", container="fmp4"):
    return Segment(SOURCE, STREAM, 0, start_ms, end_ms, codec, container, data)


def check():
    return StructuralH264Fmp4(maximum_width=1920, maximum_height=1080)


def replace_box(data, kind, new_payload):
    """Rewrite the first box of ``kind`` (searching nested containers) and fix sizes."""
    containers = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"mvex", b"moof",
                  b"traf"}

    def walk(blob):
        out, position, done = b"", 0, False
        while position < len(blob):
            size, box = struct.unpack_from(">I4s", blob, position)
            payload = blob[position + 8:position + size]
            if not done and box == kind:
                payload, done = new_payload(payload), True
            elif not done and box in containers:
                payload, done = walk(payload)
            out += struct.pack(">I", len(payload) + 8) + box + payload
            position += size
        return out, done

    result, found = walk(data)
    assert found, kind
    return result


class StructureTests(unittest.TestCase):
    def assertRefused(self, data, code, **options):
        with self.assertRaises(RecordingError) as caught:
            check().validate(segment(data, **options))
        self.assertEqual(str(caught.exception), code)

    def test_the_agent_writers_segment_is_accepted(self):
        facts = check().inspect(segment(segment_bytes()))
        self.assertEqual((facts.width, facts.height, facts.profile_idc), (1280, 720, 66))
        self.assertEqual((facts.timescale, facts.sample_count, facts.sync_samples),
                         (90000, 30, 2))
        self.assertEqual(facts.duration, 90000)

    def test_format_labels_must_match(self):
        self.assertRefused(segment_bytes(), "SEGMENT_FORMAT_UNSUPPORTED", codec="mjpeg")
        self.assertRefused(segment_bytes(), "SEGMENT_FORMAT_UNSUPPORTED", container="mkv")

    def test_duration_must_match_the_segment_interval(self):
        check().validate(segment(segment_bytes(), end_ms=1_001_033))  # within one frame
        self.assertRefused(segment_bytes(), "SEGMENT_DURATION_INCONSISTENT", end_ms=1_002_000)

    def test_dimensions_and_profiles_are_bounded(self):
        with self.assertRaises(RecordingError) as caught:
            StructuralH264Fmp4(maximum_width=1280, maximum_height=719).validate(
                segment(segment_bytes()))
        self.assertEqual(str(caught.exception), "SEGMENT_DIMENSIONS_EXCEEDED")
        with self.assertRaises(RecordingError) as caught:
            StructuralH264Fmp4(maximum_width=1920, maximum_height=1080,
                               profiles=frozenset({100})).validate(segment(segment_bytes()))
        self.assertEqual(str(caught.exception), "SEGMENT_PROFILE_UNSUPPORTED")

    def test_an_extra_box_or_second_track_is_refused(self):
        data = segment_bytes()
        self.assertRefused(data + struct.pack(">I", 8) + b"free", "SEGMENT_CONTAINER_UNEXPECTED_BOX")
        audio = replace_box(data, b"moov", lambda payload: payload + struct.pack(">I", 8) + b"trak")
        self.assertRefused(audio, "SEGMENT_CONTAINER_UNEXPECTED_BOX")
        meta = replace_box(data, b"moov", lambda payload: payload + struct.pack(">I", 8) + b"udta")
        self.assertRefused(meta, "SEGMENT_CONTAINER_UNEXPECTED_BOX")

    def test_a_non_video_handler_is_refused(self):
        data = replace_box(segment_bytes(), b"hdlr",
                           lambda payload: payload[:8] + b"soun" + payload[12:])
        self.assertRefused(data, "SEGMENT_NOT_VIDEO_ONLY")

    def test_declared_size_must_match_the_sps(self):
        data = replace_box(segment_bytes(), b"tkhd",
                           lambda payload: payload[:-8] + struct.pack(">II", 640 << 16, 480 << 16))
        self.assertRefused(data, "SEGMENT_DIMENSIONS_INCONSISTENT")

    def test_sample_data_must_cover_mdat_exactly(self):
        data = replace_box(segment_bytes(), b"mdat", lambda payload: payload + b"\x00")
        self.assertRefused(data, "SEGMENT_SAMPLES_INCONSISTENT")

    def test_the_first_sample_must_be_an_idr_with_a_matching_sync_flag(self):
        data = segment_bytes()

        def flip(payload):
            body = bytearray(payload)
            struct.pack_into(">I", body, 12 + 4, 0x01010000)  # first sample: non-sync
            return bytes(body)

        self.assertRefused(replace_box(data, b"trun", flip), "SEGMENT_SYNC_FLAGS_INCONSISTENT")

    def test_other_nal_types_are_refused(self):
        data = segment_bytes()

        def inject(payload):
            # Turn the first slice of the second sample into a type 20 NAL.
            body = bytearray(payload)
            first = struct.unpack_from(">I", body)[0]
            # sample 1 starts after sample 0; its first NAL header byte:
            body[4 + first + 4] = 0x74
            return bytes(body)

        self.assertRefused(replace_box(data, b"mdat", inject), "SEGMENT_NAL_TYPE_UNSUPPORTED")

    def test_a_non_empty_sample_table_is_refused(self):
        data = replace_box(segment_bytes(), b"stts", lambda payload: payload[:4] + b"\x00\x00\x00\x01")
        self.assertRefused(data, "SEGMENT_CONTAINER_INVALID")

    def test_truncation_is_refused(self):
        data = segment_bytes()
        for cut in (7, 40, len(data) // 2, len(data) - 1):
            with self.subTest(cut=cut), self.assertRaises(RecordingError):
                check().validate(segment(data[:cut]))

    def test_sps_parsing(self):
        info = parse_sps(sps(120, 68))
        self.assertEqual((info.width, info.height), (1920, 1088))
        for bad in (b"", PPS, bytes([0x67, 66, 0, 31]) + bytes(6)):
            with self.subTest(bad=bad), self.assertRaises(RecordingError):
                parse_sps(bad)


class CompositeTests(unittest.TestCase):
    def test_the_decoder_runs_only_after_the_structure_passed(self):
        calls = []

        class Decoder:
            def decode_all(self, data, structure):
                calls.append(structure.sample_count)

        validator = ValidatedH264Segments(check(), Decoder())
        validator.validate(segment(segment_bytes()))
        self.assertEqual(calls, [30])
        with self.assertRaises(RecordingError):
            validator.validate(segment(b"\x00" * 16))
        self.assertEqual(calls, [30])

    def test_a_decoder_refusal_refuses_the_segment(self):
        class Decoder:
            def decode_all(self, data, structure):
                raise RecordingError("SEGMENT_UNDECODABLE")

        with self.assertRaises(RecordingError) as caught:
            ValidatedH264Segments(check(), Decoder()).validate(segment(segment_bytes()))
        self.assertEqual(str(caught.exception), "SEGMENT_UNDECODABLE")
        with self.assertRaises(ValueError):
            ValidatedH264Segments(check(), object())


if __name__ == "__main__":
    unittest.main()
