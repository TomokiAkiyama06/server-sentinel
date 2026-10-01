"""Agent-side Linux V4L2 video-only discovery with replaceable sysfs/probe inputs.

Standalone port of server/app/cameras/uvc/discovery.py (the Agent artifact
never imports Main Server code); keep both evidence rules in step.

This reads descriptors; it does not start capture or open ALSA/OSS devices.
See Linux userspace-api/media/v4l/vidioc-querycap, vidioc-enum-fmt,
vidioc-enum-framesizes and vidioc-enum-frameintervals.
"""

from dataclasses import dataclass
import errno
import fcntl
from fractions import Fraction
import os
from pathlib import Path
import platform
import re
import stat
import struct

from .uvc_identity import DeviceEvidence
from .uvc_pipeline import MjpegProfile


VIDEO_CAPTURE = 0x00000001
VIDEO_CAPTURE_MPLANE = 0x00001000
DEVICE_CAPS = 0x80000000
QUERYCAP = 0x80685600
ENUM_FMT = 0xC0405602
MAX_FORMATS = 256
ENUM_FRAMESIZES = 0xC02C564A  # _IOWR('V', 74, struct v4l2_frmsizeenum), 44 bytes
ENUM_FRAMEINTERVALS = 0xC034564B  # _IOWR('V', 75, struct v4l2_frmivalenum), 52 bytes
MAX_FRAME_MODES = 256
FRMSIZE_DISCRETE, FRMSIZE_CONTINUOUS, FRMSIZE_STEPWISE = 1, 2, 3
FRMIVAL_DISCRETE, FRMIVAL_CONTINUOUS, FRMIVAL_STEPWISE = 1, 2, 3
MJPEG_FOURCC = int.from_bytes(b"MJPG", "little")
# A requested rate is offered when an offered rate is within 1 % of it, so a
# camera advertising 30000/1001 satisfies a 30 fps profile.
FPS_TOLERANCE = Fraction(1, 100)


class ProbeError(RuntimeError):
    """A fixed message only: device details must not escape into public logs."""


@dataclass(frozen=True)
class VideoCapabilities:
    capture_type: int
    flags: int
    formats: tuple[str, ...]


def query_capabilities(fd, ioctl=fcntl.ioctl):
    """Read exactly the opened video node's capabilities, not its siblings'."""
    capability = bytearray(104)
    ioctl(fd, QUERYCAP, capability, True)
    flags, device_flags = struct.unpack_from("=II", capability, 84)
    flags = device_flags if flags & DEVICE_CAPS else flags
    if flags & VIDEO_CAPTURE:
        capture_type = 1
    elif flags & VIDEO_CAPTURE_MPLANE:
        capture_type = 9
    else:
        return None
    formats = []
    for index in range(MAX_FORMATS):
        descriptor = bytearray(64)
        struct.pack_into("=II", descriptor, 0, index, capture_type)
        try:
            ioctl(fd, ENUM_FMT, descriptor, True)
        except OSError as error:
            if error.errno == errno.EINVAL:
                return VideoCapabilities(capture_type, flags, tuple(formats))
            raise
        fourcc = bytes(descriptor[44:48])
        # Descriptors are untrusted kernel/device data, never terminal strings.
        if any(value < 32 or value > 126 for value in fourcc):
            raise ProbeError("invalid video format descriptor")
        name = fourcc.decode("ascii")
        if name in formats:
            raise ProbeError("duplicate video format descriptor")
        formats.append(name)
    raise ProbeError("video format enumeration exceeds bound")


def _require_v4l2_abi():
    # Linux generic ioctl encoding is the same on these supported targets.
    # Refuse other ABIs instead of issuing a guessed ioctl command.
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise ProbeError("unsupported V4L2 ABI")


class _NotImplemented(Exception):
    """The driver does not implement a frame size/interval enumeration ioctl."""


def _enumerate(ioctl, fd, request, size, header, fields):
    """Yield raw entries of one V4L2 enumeration, bounded; stops at ``EINVAL``."""
    for index in range(MAX_FRAME_MODES):
        buffer = bytearray(size)
        struct.pack_into(header, buffer, 0, index, *fields)
        try:
            ioctl(fd, request, buffer, True)
        except OSError as error:
            if error.errno == errno.EINVAL:
                return
            if error.errno == errno.ENOTTY and index == 0:
                raise _NotImplemented() from None
            raise
        yield index, buffer
    raise ProbeError("video mode enumeration exceeds bound")


def _stepwise_values(minimum, maximum, step, *, continuous):
    if minimum <= 0 or maximum < minimum or (not continuous and step <= 0):
        raise ProbeError("invalid video mode descriptor")
    return minimum, maximum, (None if continuous else step)


def _in_range(value, minimum, maximum, step):
    return minimum <= value <= maximum and (step is None or (value - minimum) % step == 0)


def _size_offered(fd, ioctl, width, height):
    offered = False
    for index, buffer in _enumerate(ioctl, fd, ENUM_FRAMESIZES, 44, "=III", (MJPEG_FOURCC, 0)):
        kind = struct.unpack_from("=I", buffer, 8)[0]
        if kind == FRMSIZE_DISCRETE:
            offered = offered or struct.unpack_from("=II", buffer, 12) == (width, height)
            continue
        if kind not in (FRMSIZE_CONTINUOUS, FRMSIZE_STEPWISE) or index != 0:
            raise ProbeError("invalid video mode descriptor")
        min_w, max_w, step_w, min_h, max_h, step_h = struct.unpack_from("=6I", buffer, 12)
        continuous = kind == FRMSIZE_CONTINUOUS
        widths = _stepwise_values(min_w, max_w, step_w, continuous=continuous)
        heights = _stepwise_values(min_h, max_h, step_h, continuous=continuous)
        # A stepwise/continuous range is the only entry of its enumeration.
        return _in_range(width, *widths) and _in_range(height, *heights)
    return offered


def _fraction(numerator, denominator):
    if numerator <= 0 or denominator <= 0:
        return None
    return Fraction(numerator, denominator)


def _rate_within_tolerance(offered, requested):
    return abs(offered - requested) <= requested * FPS_TOLERANCE


def _offered_rate(fd, ioctl, width, height, requested):
    """The exact offered rate that satisfies ``requested`` (fps), or ``None``.

    V4L2 reports frame *intervals* (seconds per frame); rates are their inverse.
    An exact offer wins; otherwise the closest offer within the tolerance.
    """
    best = None
    for index, buffer in _enumerate(ioctl, fd, ENUM_FRAMEINTERVALS, 52, "=IIIII",
                                    (MJPEG_FOURCC, width, height, 0)):
        kind = struct.unpack_from("=I", buffer, 16)[0]
        if kind == FRMIVAL_DISCRETE:
            interval = _fraction(*struct.unpack_from("=II", buffer, 20))
            if interval is None:
                continue  # A zero interval can satisfy no profile.
            candidates = (1 / interval,)
        elif kind in (FRMIVAL_CONTINUOUS, FRMIVAL_STEPWISE) and index == 0:
            values = struct.unpack_from("=6I", buffer, 20)
            minimum, maximum, step = (_fraction(*values[0:2]), _fraction(*values[2:4]),
                                      _fraction(*values[4:6]))
            continuous = kind == FRMIVAL_CONTINUOUS
            if minimum is None or maximum is None or maximum < minimum or (
                    not continuous and step is None):
                raise ProbeError("invalid video mode descriptor")
            # Nearest offered interval to the requested one (clamped, on-step).
            wanted = min(max(1 / requested, minimum), maximum)
            if not continuous:
                steps = min(round((wanted - minimum) / step), (maximum - minimum) // step)
                wanted = minimum + max(0, steps) * step
            candidates = (1 / wanted,)
        else:
            raise ProbeError("invalid video mode descriptor")
        for rate in candidates:
            if rate == requested:
                return rate
            if _rate_within_tolerance(rate, requested) and (
                    best is None or abs(rate - requested) < abs(best - requested)):
                best = rate
    return best


def match_mjpeg_profile(fd, profile, ioctl=fcntl.ioctl):
    """Check ``profile`` against the MJPEG modes the opened node advertises.

    Read-only ``VIDIOC_QUERYCAP``/``ENUM_FMT``/``ENUM_FRAMESIZES``/
    ``ENUM_FRAMEINTERVALS`` on this descriptor only (the approved capture node;
    no other node is opened). Returns the profile to request from the pipeline
    (the requested one, or the exact offered rate within ``FPS_TOLERANCE``), or
    ``None`` when the camera does not offer it. A driver that does not implement
    frame size/interval enumeration (``ENOTTY``) proves nothing: the requested
    profile is returned and the pipeline's own negotiation remains the check, as
    it does for a driver that advertises a mode it then refuses.
    """
    _require_v4l2_abi()
    capabilities = query_capabilities(fd, ioctl)
    if capabilities is None or "MJPG" not in capabilities.formats:
        return None
    requested = Fraction(profile.fps_numerator, profile.fps_denominator)
    try:
        if not _size_offered(fd, ioctl, profile.width, profile.height):
            return None
        rate = _offered_rate(fd, ioctl, profile.width, profile.height, requested)
    except _NotImplemented:
        return profile
    if rate is None:
        return None
    if rate == requested:
        return profile
    try:
        return MjpegProfile(profile.width, profile.height, rate.numerator, rate.denominator)
    except ValueError:
        return None


def probe_video_node(path, expected_device):
    _require_v4l2_abi()
    if not re.fullmatch(r"video[0-9]+", path.name):
        raise ProbeError("invalid video node")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != expected_device:
            raise ProbeError("video node changed during discovery")
        return query_capabilities(descriptor)
    except OSError:
        raise ProbeError("video descriptor unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _text(path):
    try:
        with path.open("rb") as stream:
            value = stream.read(4097)
        if len(value) > 4096:
            raise ProbeError("device property exceeds bound")
        text = value.decode("utf-8", errors="strict").strip()
        if any(ord(character) < 32 or ord(character) == 127 for character in text):
            raise ProbeError("invalid device property")
        return text or None
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError):
        raise ProbeError("device property unavailable") from None


@dataclass(frozen=True)
class DiscoveryResult:
    devices: tuple[DeviceEvidence, ...]
    failures: int


class LinuxDiscovery:
    def __init__(self, *, sys_root=Path("/sys"), dev_root=Path("/dev"), probe=probe_video_node):
        self.sys_root = sys_root.resolve()
        self.dev_root = dev_root
        self.probe = probe

    def scan(self):
        devices, failures = [], 0
        directory = self.sys_root / "class/video4linux"
        try:
            entries = sorted(directory.iterdir())
        except FileNotFoundError:
            return DiscoveryResult((), 0)
        except OSError:
            return DiscoveryResult((), 1)
        for entry in entries:
            if not re.fullmatch(r"video[0-9]+", entry.name):
                continue
            try:
                result = self._inspect(entry)
                if result is not None:
                    devices.append(result)
            except (ProbeError, OSError, ValueError):
                # Never include private serial/topology/path or OS exception text.
                failures += 1
        return DiscoveryResult(tuple(devices), failures)

    def _inspect(self, entry):
        resolved = entry.resolve(strict=True)
        if not resolved.is_relative_to(self.sys_root):
            raise ProbeError("device leaves expected sysfs tree")
        info = resolved.stat()
        instance_token = (info.st_dev, info.st_ino, info.st_ctime_ns)
        raw_device = _text(resolved / "dev")
        if raw_device is None or not re.fullmatch(r"[0-9]+:[0-9]+", raw_device):
            raise ProbeError("missing device number")
        major, minor = map(int, raw_device.split(":"))
        path = self.dev_root / entry.name
        capabilities = self.probe(path, os.makedev(major, minor))
        if capabilities is None:
            return None
        device = (resolved / "device").resolve(strict=True)
        if not device.is_relative_to(self.sys_root):
            raise ProbeError("device leaves expected sysfs tree")
        vendor = product = serial = topology = None
        for ancestor in (device, *device.parents):
            if not ancestor.is_relative_to(self.sys_root):
                break
            vendor = _text(ancestor / "idVendor")
            product = _text(ancestor / "idProduct")
            if vendor and product:
                serial = _text(ancestor / "serial")
                topology = str(ancestor.relative_to(self.sys_root))
                break
        # Scope is USB cameras. Non-USB capture adapters need their own evidence.
        if not vendor or not product:
            return None
        index = _text(resolved / "index")
        if index is None or not index.isdecimal():
            raise ProbeError("missing video interface index")
        aliases = []
        by_id = self.dev_root / "v4l/by-id"
        try:
            for alias in by_id.iterdir():
                if alias.is_symlink() and alias.resolve() == path.resolve():
                    aliases.append(alias.name)
        except FileNotFoundError:
            pass
        info = resolved.stat()
        if instance_token != (info.st_dev, info.st_ino, info.st_ctime_ns):
            raise ProbeError("device changed during discovery")
        return DeviceEvidence(str(path), vendor, product, serial, index,
                              tuple(sorted(aliases)), topology, capabilities.formats,
                              os.makedev(major, minor), instance_token)
