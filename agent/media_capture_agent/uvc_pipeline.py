"""Video-only capture pipeline abstraction, bounded MJPEG framing and frame queue.

The production launcher runs an operator-installed ``gst-launch-1.0`` with only
``v4l2src`` and ``fdsink`` elements: no audio element, GUI sink, network sink or
file sink can be named. The pipeline receives an already verified V4L2
descriptor instead of a ``/dev/videoN`` path, runs in its own process group with
a minimal environment, and its stderr is discarded (never logged) because it can
contain device details. Tests inject a synthetic launcher; production never
substitutes one silently.
"""

from collections import deque
from dataclasses import dataclass, field
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
import time
from typing import Protocol


MAX_FRAME_BYTES = 32 * 1024 * 1024
MAX_QUEUE_FRAMES = 64
READ_CHUNK_BYTES = 65536
_STANDALONE = frozenset({0x01, *range(0xD0, 0xD8)})


class PipelineError(RuntimeError):
    """Fixed safe failure text; never includes argv, stderr, paths or frame bytes."""


class FrameError(PipelineError):
    """The byte stream is not a bounded sequence of complete JPEG images."""


@dataclass(frozen=True)
class MjpegProfile:
    """Explicit per-source capture profile; the camera must offer MJPEG."""

    width: int
    height: int
    fps_numerator: int
    fps_denominator: int = 1

    def __post_init__(self):
        for value in (self.width, self.height):
            if type(value) is not int or not 16 <= value <= 16384:
                raise ValueError("invalid video dimensions")
        for value in (self.fps_numerator, self.fps_denominator):
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError("invalid video frame rate")
        if not 0 < self.fps_numerator / self.fps_denominator <= 240:
            raise ValueError("invalid video frame rate")

    def caps(self):
        return (f"image/jpeg,width={self.width},height={self.height},"
                f"framerate={self.fps_numerator}/{self.fps_denominator}")


class MjpegFrameParser:
    """Incremental JPEG splitter with strict size and resynchronization bounds.

    Markers are parsed structurally; inside entropy-coded data only a marker
    other than byte stuffing/RSTn ends the scan, so an ``FFD9`` byte pair can
    never be mistaken for the end of an image. Anything malformed is an error:
    the caller restarts capture rather than emitting a guessed frame.
    """

    def __init__(self, max_frame_bytes, *, max_gap_bytes=4096):
        if type(max_frame_bytes) is not int or not 64 <= max_frame_bytes <= MAX_FRAME_BYTES:
            raise ValueError("invalid frame bound")
        if type(max_gap_bytes) is not int or not 0 <= max_gap_bytes <= 65536:
            raise ValueError("invalid gap bound")
        self.max_frame_bytes = max_frame_bytes
        self.max_gap_bytes = max_gap_bytes
        self._buffer = bytearray()
        self._in_frame = False
        self._entropy = False
        self._scans = 0
        self._position = 0

    @property
    def partial(self):
        return bool(self._buffer)

    def feed(self, data):
        self._buffer += data
        frames = []
        while True:
            if not self._in_frame:
                start = self._buffer.find(b"\xff\xd8")
                if start < 0:
                    keep = 1 if self._buffer.endswith(b"\xff") else 0
                    if len(self._buffer) - keep > self.max_gap_bytes:
                        raise FrameError("video stream lost JPEG framing")
                    return frames
                # UVC payloads may pad between images; bound what is skipped.
                if start > self.max_gap_bytes:
                    raise FrameError("video stream lost JPEG framing")
                del self._buffer[:start]
                self._in_frame, self._entropy, self._scans, self._position = True, False, 0, 2
            end = self._scan()
            if end is None:
                if len(self._buffer) > self.max_frame_bytes:
                    raise FrameError("video frame exceeds bound")
                return frames
            if end > self.max_frame_bytes:
                raise FrameError("video frame exceeds bound")
            frames.append(bytes(self._buffer[:end]))
            del self._buffer[:end]
            self._in_frame = False

    def _scan(self):
        data, position = self._buffer, self._position
        while True:
            if self._entropy:
                index = data.find(b"\xff", position)
                if index < 0 or index + 1 >= len(data):
                    self._position = len(data) if index < 0 else index
                    return None
                following = data[index + 1]
                if following == 0x00 or 0xD0 <= following <= 0xD7:
                    position = index + 2
                    continue
                if following == 0xFF:
                    position = index + 1
                    continue
                position, self._entropy = index, False
            if position + 2 > len(data):
                self._position = position
                return None
            if data[position] != 0xFF:
                raise FrameError("invalid JPEG marker")
            marker = data[position + 1]
            if marker == 0xFF:
                position += 1
                continue
            if marker in _STANDALONE:
                position += 2
                continue
            if marker in (0x00, 0xD8):
                raise FrameError("invalid JPEG marker")
            if marker == 0xD9:
                if self._scans == 0:
                    raise FrameError("JPEG image has no scan")
                return position + 2
            if position + 4 > len(data):
                self._position = position
                return None
            length = int.from_bytes(data[position + 2:position + 4], "big")
            if length < 2:
                raise FrameError("invalid JPEG segment")
            if position + 2 + length > len(data):
                self._position = position
                return None
            position += 2 + length
            if marker == 0xDA:
                self._scans += 1
                self._entropy = True


@dataclass(frozen=True)
class Frame:
    """One compressed video frame; bytes never appear in repr/logs."""

    data: bytes = field(repr=False)
    sequence: int
    generation: int
    received_monotonic: float


class FrameQueue:
    """Bounded drop-oldest queue. Every drop is counted and made visible."""

    def __init__(self, capacity, *, clock=time.monotonic):
        if type(capacity) is not int or not 1 <= capacity <= MAX_QUEUE_FRAMES:
            raise ValueError("invalid frame queue bound")
        self._frames = deque()
        self._capacity = capacity
        self._condition = threading.Condition()
        self._clock = clock
        self.dropped = 0
        self.last_drop = None
        self._closed = False

    def put(self, frame):
        with self._condition:
            if self._closed:
                return
            if len(self._frames) >= self._capacity:
                self._frames.popleft()
                self.dropped += 1
                self.last_drop = self._clock()
            self._frames.append(frame)
            self._condition.notify()

    def get(self, timeout):
        """Return the oldest frame, or ``None`` on timeout/close."""
        if type(timeout) not in (int, float) or not 0 <= timeout <= 60:
            raise ValueError("invalid frame wait")
        with self._condition:
            self._condition.wait_for(lambda: self._frames or self._closed, timeout)
            return self._frames.popleft() if self._frames else None

    def __len__(self):
        with self._condition:
            return len(self._frames)

    def drop_stats(self):
        """Consistent ``(dropped, last_drop)`` snapshot for health reporting."""
        with self._condition:
            return self.dropped, self.last_drop

    def close(self):
        with self._condition:
            self._closed = True
            self._frames.clear()
            self._condition.notify_all()


class PipelineProcess(Protocol):
    def read(self, size: int) -> bytes: ...
    def exited(self) -> bool: ...
    def stop(self, timeout: float) -> bool: ...
    def close(self) -> None: ...


class PipelineLauncher(Protocol):
    """Start one video-only pipeline reading the given verified V4L2 descriptor."""

    def launch(self, device_fd: int, profile: MjpegProfile) -> PipelineProcess: ...


class SubprocessPipeline:
    """A child process group whose stdout carries compressed frames.

    Exit is observed with ``WNOWAIT`` so the zombie leader keeps its process
    group ID reserved while stragglers are SIGKILLed; it is reaped only once no
    other live member of the group remains (e.g. one stuck in uninterruptible
    sleep that still holds the camera or the output pipe).
    """

    def __init__(self, process, *, proc_root="/proc"):
        self.process = process
        self._proc_root = proc_root
        self._stdout = process.stdout
        self._reaped = False

    def read(self, size):
        try:
            return self._stdout.read(size) or b""
        except (OSError, ValueError):
            return b""

    def exited(self):
        if self._reaped:
            return True
        try:
            return os.waitid(os.P_PID, self.process.pid,
                             os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None
        except ChildProcessError:
            return True

    def _signal(self, signum):
        try:
            os.killpg(self.process.pid, signum)
        except (ProcessLookupError, PermissionError):
            pass

    def _wait_exit(self, deadline):
        while not self.exited():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def _group_member_alive(self):
        """True while a non-leader member of the group is not yet dead.

        Unprovable absence (no readable process table) counts as alive, so
        cleanup is never reported without evidence.
        """
        pgid = self.process.pid
        try:
            entries = os.listdir(self._proc_root)
        except OSError:
            return True
        for name in entries:
            if not name.isdigit() or int(name) == pgid:
                continue
            try:
                with open(os.path.join(self._proc_root, name, "stat"), "rb") as stream:
                    data = stream.read()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue  # Exited meanwhile, or another user's process.
            except OSError:
                return True
            fields = data[data.rfind(b")") + 1:].split()
            if len(fields) < 3 or not fields[2].isdigit():
                return True
            if int(fields[2]) == pgid and fields[0] not in (b"Z", b"X"):
                return True
        return False

    def _wait_group_gone(self, deadline):
        while self._group_member_alive():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def stop(self, timeout):
        """Terminate the whole group within ``timeout``; False means not reaped."""
        if self._reaped:
            return True
        deadline = time.monotonic() + timeout
        if not self.exited():
            self._signal(signal.SIGTERM)
            self._wait_exit(time.monotonic() + timeout / 2)
        # Also removes any surviving group member of an already exited leader.
        self._signal(signal.SIGKILL)
        if not self._wait_exit(deadline):
            return False
        # The unreaped zombie leader keeps the group ID from being reused, so
        # a surviving member is still identified by it on a later retry.
        if not self._wait_group_gone(deadline):
            return False
        try:
            self.process.wait(timeout=max(0.0, deadline - time.monotonic()) or 0.01)
        except subprocess.TimeoutExpired:
            return False
        self._reaped = True
        return True

    def close(self):
        """Release the output pipe only after the reader stopped using it."""
        try:
            self._stdout.close()
        except OSError:
            pass


def minimal_environment(extra=None):
    """No inherited secrets, plugin paths or display/audio server variables."""
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    for key, value in (extra or {}).items():
        if not key.startswith("GST_") or not isinstance(value, str) or "\0" in value:
            raise ValueError("invalid pipeline environment")
        environment[key] = value
    return environment


class SubprocessLauncher:
    """Generic launcher: ``argv_factory(fd, profile)`` builds a fixed argv."""

    def __init__(self, argv_factory, *, environment=None, popen=subprocess.Popen):
        self.argv_factory = argv_factory
        self.environment = minimal_environment(environment)
        self.popen = popen

    def launch(self, device_fd, profile):
        if type(device_fd) is not int or device_fd < 3:
            raise PipelineError("invalid video descriptor")
        argv = self.argv_factory(device_fd, profile)
        if (not isinstance(argv, list) or not argv
                or any(not isinstance(item, str) or "\0" in item for item in argv)):
            raise PipelineError("invalid pipeline command")
        try:
            process = self.popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, pass_fds=(device_fd,), close_fds=True,
                start_new_session=True, env=self.environment, cwd="/", bufsize=0,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            raise PipelineError("video pipeline could not start") from None
        return SubprocessPipeline(process)


GSTREAMER_ELEMENTS = ("v4l2src", "fdsink")


def gstreamer_argv(executable, device_fd, profile):
    """``v4l2src ! image/jpeg caps ! fdsink``; nothing else can be expressed."""
    if not isinstance(profile, MjpegProfile):
        raise PipelineError("explicit MJPEG profile is required")
    return [str(executable), "-q",
            GSTREAMER_ELEMENTS[0], f"device=/proc/self/fd/{device_fd}", "do-timestamp=true",
            "!", profile.caps(),
            "!", GSTREAMER_ELEMENTS[1], "fd=1", "sync=false"]


def require_trusted_executable(path):
    """Refuse a pipeline binary that the service account (or anyone) could replace."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PipelineError("pipeline executable must be an absolute path")
    try:
        info = os.stat(path, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            path = path.resolve(strict=True)
            info = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not info.st_mode & 0o111):
            raise PipelineError("pipeline executable is not root-controlled")
        for parent in path.parents:
            parent_info = os.stat(parent, follow_symlinks=False)
            if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise PipelineError("pipeline executable is not root-controlled")
    except OSError:
        raise PipelineError("pipeline executable is unavailable") from None
    return path


class GStreamerLauncher(SubprocessLauncher):
    """Operator-installed GStreamer; not bundled, never downloaded, never PATH-searched.

    ``registry`` optionally points GStreamer's plugin cache into the private
    runtime root, because a hardened unit hides the service account's home.
    """

    def __init__(self, executable, *, registry=None, trust=require_trusted_executable,
                 popen=subprocess.Popen):
        self.executable = trust(executable)
        self._trust = trust
        environment = {}
        if registry is not None:
            registry = Path(registry)
            if not registry.is_absolute() or ".." in registry.parts:
                raise ValueError("invalid pipeline registry path")
            environment["GST_REGISTRY"] = str(registry)
        super().__init__(self._argv, environment=environment, popen=popen)

    def _argv(self, device_fd, profile):
        # Re-check at every start: a package change must not be trusted blindly.
        return gstreamer_argv(self._trust(self.executable), device_fd, profile)
