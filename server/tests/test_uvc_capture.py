"""Synthetic driver responses only; never opens a physical camera or audio node."""

from dataclasses import replace
import errno
import os
import stat
import struct
from types import SimpleNamespace
import unittest

from app.cameras.uvc.capture import (
    CaptureError, DQBUF, G_FMT, G_PARM, MmapCapture, QBUF, QUERYBUF,
    REQBUFS, S_FMT, S_PARM, STREAMING, STREAMOFF, STREAMON, VideoProfile,
)
from app.cameras.uvc.discovery import ENUM_FMT, QUERYCAP, VIDEO_CAPTURE
from app.cameras.uvc.identity import DeviceEvidence


class Mapping(bytearray):
    closed = False

    def close(self):
        self.closed = True


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.opened = []
        self.closed = []
        self.maps = []
        self.frame_flags = 0
        self.frame_size = 8
        self.frame_index = 0
        self.driver_failure = None
        self.buffer_count = 2
        self.camera = DeviceEvidence("/dev/video2", "synthetic", "camera", "serial",
                                     device_number=os.makedev(81, 2))
        self.profile = VideoProfile(1280, 720, 30, "MJPG")
        self.capture = self.make_capture()
        self.addCleanup(self.capture.close)

    def make_capture(self, **changes):
        arguments = dict(
            verify_identity=lambda candidate: candidate == self.camera,
            ioctl=self.ioctl, opener=self.open, closer=self.closed.append,
            fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(81, 2)),
            mapper=self.map, wait=lambda read, write, error, timeout: (read, [], []),
        )
        arguments.update(changes)
        return MmapCapture(self.camera, self.profile, **arguments)

    def open(self, path, flags):
        self.opened.append((str(path), flags))
        return 8

    def map(self, fd, length, **kwargs):
        self.assertEqual(fd, 8)
        self.assertEqual(length, 4096)
        mapping = Mapping(b"SYNTHETC" + bytes(length - 8))
        self.maps.append(mapping)
        return mapping

    def ioctl(self, fd, command, value, mutate):
        self.assertEqual(fd, 8)
        self.calls.append(command)
        if command == self.driver_failure:
            raise OSError(errno.ENODEV, "synthetic unplug")
        if command == QUERYCAP:
            struct.pack_into("=II", value, 84, VIDEO_CAPTURE | STREAMING, 0)
        elif command == ENUM_FMT:
            if struct.unpack_from("=I", value)[0]:
                raise OSError(errno.EINVAL, "end")
            value[44:48] = b"MJPG"
        elif command == G_FMT:
            self.assertEqual(len(value), 208)
        elif command == S_FMT:
            self.assertEqual(struct.unpack_from("=II", value, 8), (1280, 720))
            struct.pack_into("=IIIIII", value, 8, 640, 480,
                             int.from_bytes(b"MJPG", "little"), 0, 0, 4096)
        elif command == G_PARM:
            struct.pack_into("=I", value, 4, 0x1000)
        elif command == S_PARM:
            self.assertEqual(struct.unpack_from("=II", value, 12), (1, 30))
            struct.pack_into("=II", value, 12, 1, 15)
        elif command == REQBUFS:
            struct.pack_into("=I", value, 0, self.buffer_count)
        elif command == QUERYBUF:
            index = struct.unpack_from("=I", value)[0]
            struct.pack_into("=I", value, 64, index * 4096)
            struct.pack_into("=I", value, 72, 4096)
        elif command == DQBUF:
            struct.pack_into("=IIII", value, 0, self.frame_index, 1, self.frame_size, self.frame_flags)
            struct.pack_into("=I", value, 56, 42)
        else:
            self.assertIn(command, (QBUF, STREAMON, STREAMOFF))

    def test_negotiated_values_and_video_frame_without_audio(self):
        negotiated = self.capture.open()
        self.assertEqual(negotiated.profile, VideoProfile(640, 480, 15, "MJPG"))
        frame = self.capture.read_frame()
        self.assertEqual(frame.data, b"SYNTHETC")
        self.assertEqual(frame.sequence, 42)
        self.assertNotIn("SYNTHETC", repr(frame))
        self.assertEqual(len(self.opened), 1)
        self.assertEqual(self.opened[0][0], "/dev/video2")
        self.assertTrue(self.opened[0][1] & os.O_NOFOLLOW)
        self.assertEqual(self.calls[-1], QBUF)
        self.capture.close()
        self.assertTrue(all(mapping.closed for mapping in self.maps))
        self.assertEqual(self.closed, [8])

    def test_audio_and_non_device_paths_never_open(self):
        for path in ("/dev/snd/pcmC0D0c", "/dev/audio", "/tmp/video0"):
            self.capture.candidate = replace(self.camera, device_path=path)
            with self.assertRaises(CaptureError):
                self.capture.open()
        self.assertEqual(self.opened, [])

    def test_post_open_identity_change_aborts_before_capture(self):
        capture = self.make_capture(verify_identity=lambda candidate: False)
        with self.assertRaises(CaptureError):
            capture.open()
        self.assertFalse(self.calls)
        self.assertEqual(self.closed, [8])

    def test_weak_candidate_without_instance_is_refused_before_open(self):
        self.capture.candidate = replace(self.camera, serial=None)
        with self.assertRaisesRegex(CaptureError, "lacks a current instance"):
            self.capture.open()
        self.assertFalse(self.opened)

    def test_device_number_reuse_does_not_match_other_node(self):
        capture = self.make_capture(fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=0))
        with self.assertRaises(CaptureError):
            capture.open()
        self.assertEqual(self.closed, [8])

    def test_unplug_fails_with_safe_message_and_cleanup(self):
        self.capture.open()
        self.driver_failure = DQBUF
        with self.assertRaisesRegex(CaptureError, "^video capture was interrupted$"):
            self.capture.read_frame()
        self.driver_failure = STREAMOFF
        self.capture.close()
        self.assertTrue(all(mapping.closed for mapping in self.maps))
        self.assertEqual(self.closed, [8])

    def test_corrupt_frame_is_never_delivered_and_buffer_requeued(self):
        self.capture.open()
        self.frame_flags = 0x40
        with self.assertRaisesRegex(CaptureError, "corrupt"):
            self.capture.read_frame()
        self.assertEqual(self.calls[-1], QBUF)

    def test_unbounded_driver_buffers_are_refused_and_closed(self):
        self.buffer_count = 9
        with self.assertRaisesRegex(CaptureError, "count exceeds"):
            self.capture.open()
        self.assertFalse(self.maps)
        self.assertEqual(self.closed, [8])

    def test_invalid_frame_size_or_index_cannot_access_mapping(self):
        self.capture.open()
        for index, size in ((0, 0), (0, 4097), (8, 8)):
            self.frame_index, self.frame_size = index, size
            with self.assertRaisesRegex(CaptureError, "invalid captured"):
                self.capture.read_frame()

    def test_timeout_is_not_healthy_video(self):
        capture = self.make_capture(wait=lambda *args: ([], [], []))
        capture.open()
        self.addCleanup(capture.close)
        with self.assertRaisesRegex(CaptureError, "timed out"):
            capture.read_frame()

    def test_tiny_positive_rate_fails_safely_before_fraction_overflow(self):
        self.capture.desired = VideoProfile(1280, 720, 1e-300, "MJPG")
        with self.assertRaisesRegex(CaptureError, "frame interval exceeds"):
            self.capture.open()
        self.assertNotIn(S_PARM, self.calls)
        self.assertEqual(self.closed, [8])


if __name__ == "__main__":
    unittest.main()
