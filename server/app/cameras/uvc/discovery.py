"""Linux V4L2 video-only discovery with replaceable filesystem/probe inputs.

This reads descriptors; it does not start capture or open ALSA/OSS devices.
See Linux userspace-api/media/v4l/vidioc-querycap and vidioc-enum-fmt.
"""

from dataclasses import dataclass
import errno
import fcntl
import os
from pathlib import Path
import platform
import re
import stat
import struct

from .identity import DeviceEvidence


VIDEO_CAPTURE = 0x00000001
VIDEO_CAPTURE_MPLANE = 0x00001000
DEVICE_CAPS = 0x80000000
QUERYCAP = 0x80685600
ENUM_FMT = 0xC0405602
MAX_FORMATS = 256


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


def probe_video_node(path, expected_device):
    # Linux generic ioctl encoding is the same on these supported targets.
    # Refuse other ABIs instead of issuing a guessed ioctl command.
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise ProbeError("unsupported V4L2 ABI")
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
        return DeviceEvidence(str(path), vendor, product, serial, index,
                              tuple(sorted(aliases)), topology, capabilities.formats,
                              os.makedev(major, minor))
