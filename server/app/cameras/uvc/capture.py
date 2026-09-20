"""Bounded single-planar V4L2 MMAP video capture, without audio or networking.

The ABI below is restricted to Linux LP64 x86_64/aarch64. Constants/offsets
follow linux/videodev2.h; no third-party binding or copied driver is bundled.
"""

from dataclasses import dataclass, field
import errno
import fcntl
from fractions import Fraction
import math
import mmap
import os
from pathlib import Path
import platform
import re
import select
import stat
import struct
import time

from .discovery import query_capabilities


G_FMT, S_FMT = 0xC0D05604, 0xC0D05605
G_PARM, S_PARM = 0xC0CC5615, 0xC0CC5616
REQBUFS, QUERYBUF = 0xC0145608, 0xC0585609
QBUF, DQBUF = 0xC058560F, 0xC0585611
STREAMON, STREAMOFF = 0x40045612, 0x40045613
STREAMING = 0x04000000
MAX_BUFFER_BYTES = 64 * 1024 * 1024
MAX_BUFFERS = 8


class CaptureError(RuntimeError):
    """Safe capture failure; never attach frame bytes or OS exception values."""


@dataclass(frozen=True)
class VideoProfile:
    width: int
    height: int
    fps: float
    pixel_format: str

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= 16384 for v in (self.width, self.height)):
            raise ValueError("invalid video dimensions")
        if type(self.fps) not in (int, float) or not math.isfinite(self.fps) or not 0 < self.fps <= 1000:
            raise ValueError("invalid video frame rate")
        if not isinstance(self.pixel_format, str) or not re.fullmatch(r"[ -~]{4}", self.pixel_format):
            raise ValueError("invalid video pixel format")


@dataclass(frozen=True)
class NegotiatedVideo:
    profile: VideoProfile
    bytes_per_line: int
    size_image: int


@dataclass(frozen=True)
class VideoFrame:
    data: bytes = field(repr=False)
    sequence: int
    received_monotonic: float


def _buffer(index=0):
    value = bytearray(88)
    struct.pack_into("=II", value, 0, index, 1)  # VIDEO_CAPTURE only
    struct.pack_into("=I", value, 60, 1)  # MEMORY_MMAP
    return value


def negotiate(fd, desired, ioctl=fcntl.ioctl):
    """Return driver-adjusted dimensions, FourCC and rate, never desired-as-actual."""
    if not isinstance(desired, VideoProfile):
        raise ValueError("explicit video profile is required")
    value = bytearray(208)
    struct.pack_into("=I", value, 0, 1)
    ioctl(fd, G_FMT, value, True)
    struct.pack_into("=IIII", value, 8, desired.width, desired.height,
                     int.from_bytes(desired.pixel_format.encode("ascii"), "little"), 0)
    ioctl(fd, S_FMT, value, True)
    width, height, fourcc, _field, stride, size = struct.unpack_from("=IIIIII", value, 8)
    if not 0 < size <= MAX_BUFFER_BYTES:
        raise CaptureError("video frame size exceeds capture bound")
    parameters = bytearray(204)
    struct.pack_into("=I", parameters, 0, 1)
    ioctl(fd, G_PARM, parameters, True)
    if struct.unpack_from("=I", parameters, 4)[0] & 0x1000:
        interval = (Fraction(1, 1) / Fraction(str(desired.fps))).limit_denominator(1_000_000)
        if not 0 < interval.numerator <= 0xFFFFFFFF or not 0 < interval.denominator <= 0xFFFFFFFF:
            raise CaptureError("video frame interval exceeds V4L2 bounds")
        struct.pack_into("=II", parameters, 12, interval.numerator, interval.denominator)
        ioctl(fd, S_PARM, parameters, True)
    numerator, denominator = struct.unpack_from("=II", parameters, 12)
    if numerator == 0 or denominator == 0:
        raise CaptureError("video frame rate is unavailable")
    try:
        profile = VideoProfile(width, height, denominator / numerator,
                               fourcc.to_bytes(4, "little").decode("ascii"))
    except (ValueError, UnicodeError):
        raise CaptureError("invalid negotiated video profile") from None
    return NegotiatedVideo(profile, stride, size)


class MmapCapture:
    """One descriptor and at most eight bounded video buffers; no disk output.

    verify_identity must rescan physical evidence after opening the descriptor,
    and approve this exact current candidate. Capture never authorizes itself.
    Multi-planar-only/read-only devices are explicitly unsupported by this
    adapter, instead of silently falling back to a different capture path.
    """

    def __init__(self, candidate, profile, *, verify_identity,
                 ioctl=fcntl.ioctl, opener=os.open, closer=os.close,
                 fstat=os.fstat, mapper=mmap.mmap, wait=select.select,
                 clock=time.monotonic):
        self.candidate = candidate
        self.desired = profile
        self.verify_identity = verify_identity
        self.ioctl, self.opener, self.closer = ioctl, opener, closer
        self.fstat, self.mapper, self.wait, self.clock = fstat, mapper, wait, clock
        self.fd = None
        self.maps = []
        self.streaming = False
        self.negotiated = None

    def open(self):
        if self.fd is not None:
            raise CaptureError("video capture is already open")
        if (platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}
                or struct.calcsize("P") != 8):
            raise CaptureError("unsupported V4L2 ABI")
        path = Path(self.candidate.device_path)
        if path.parent != Path("/dev") or not re.fullmatch(r"video[0-9]+", path.name):
            raise CaptureError("invalid video capture node")
        if self.candidate.device_number is None:
            raise CaptureError("video device number is unavailable")
        if self.candidate.strong_key is None and self.candidate.instance_token is None:
            raise CaptureError("weak video identity lacks a current instance")
        try:
            self.fd = self.opener(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
            info = self.fstat(self.fd)
            if not stat.S_ISCHR(info.st_mode) or info.st_rdev != self.candidate.device_number:
                raise CaptureError("video capture node changed")
            if self.verify_identity(self.candidate) is not True:
                raise CaptureError("video capture identity changed")
            caps = query_capabilities(self.fd, self.ioctl)
            if caps is None or caps.capture_type != 1 or not caps.flags & STREAMING:
                raise CaptureError("single-planar video streaming is unavailable")
            self.negotiated = negotiate(self.fd, self.desired, self.ioctl)
            request = bytearray(20)
            struct.pack_into("=III", request, 0, 4, 1, 1)
            self.ioctl(self.fd, REQBUFS, request, True)
            count = struct.unpack_from("=I", request)[0]
            if not 1 <= count <= MAX_BUFFERS:
                raise CaptureError("video buffer count exceeds capture bound")
            for index in range(count):
                buffer = _buffer(index)
                self.ioctl(self.fd, QUERYBUF, buffer, True)
                offset, length = struct.unpack_from("=I", buffer, 64)[0], struct.unpack_from("=I", buffer, 72)[0]
                if not self.negotiated.size_image <= length <= MAX_BUFFER_BYTES:
                    raise CaptureError("video buffer size exceeds capture bound")
                mapping = self.mapper(self.fd, length, flags=mmap.MAP_SHARED,
                                      prot=mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
                self.maps.append(mapping)
                self.ioctl(self.fd, QBUF, _buffer(index), True)
            self.ioctl(self.fd, STREAMON, bytearray(struct.pack("=I", 1)), True)
            self.streaming = True
            return self.negotiated
        except BaseException as error:
            self.close()
            if isinstance(error, (OSError, ValueError)):
                raise CaptureError("video capture could not start") from None
            raise

    def read_frame(self, timeout=1.0):
        if self.fd is None or not self.streaming:
            raise CaptureError("video capture is not active")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("invalid capture timeout")
        deadline = self.clock() + timeout
        try:
            while True:
                remaining = deadline - self.clock()
                if remaining <= 0 or not self.wait([self.fd], [], [], remaining)[0]:
                    raise CaptureError("video frame timed out")
                buffer = _buffer()
                try:
                    self.ioctl(self.fd, DQBUF, buffer, True)
                except OSError as error:
                    if error.errno == errno.EAGAIN:
                        continue
                    raise
                index, _type, used, flags = struct.unpack_from("=IIII", buffer)
                if index >= len(self.maps) or not 0 < used <= len(self.maps[index]):
                    raise CaptureError("invalid captured video buffer")
                try:
                    if flags & 0x40:
                        raise CaptureError("captured video frame is corrupt")
                    # Copy only this dequeued frame before requeuing driver memory.
                    data = bytes(self.maps[index][:used])
                    sequence = struct.unpack_from("=I", buffer, 56)[0]
                    frame = VideoFrame(data, sequence, self.clock())
                finally:
                    self.ioctl(self.fd, QBUF, _buffer(index), True)
                return frame
        except OSError:
            raise CaptureError("video capture was interrupted") from None

    def close(self):
        """Best effort cleanup continues after unplug/STREAMOFF failures."""
        if self.fd is not None and self.streaming:
            try:
                self.ioctl(self.fd, STREAMOFF, bytearray(struct.pack("=I", 1)), True)
            except OSError:
                pass
        self.streaming = False
        for mapping in self.maps:
            try:
                mapping.close()
            except OSError:
                pass
        self.maps.clear()
        if self.fd is not None:
            try:
                self.closer(self.fd)
            except OSError:
                pass
            self.fd = None
