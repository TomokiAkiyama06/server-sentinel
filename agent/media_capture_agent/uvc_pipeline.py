"""Video-only capture pipeline abstraction, bounded MJPEG framing and frame queue.

The production launcher runs an operator-installed ``gst-launch-1.0`` with only
``v4l2src`` and ``fdsink`` elements: no audio element, GUI sink, network sink or
file sink can be named. The pipeline receives an already verified V4L2
descriptor instead of a ``/dev/videoN`` path, runs in its own process group with
a minimal environment, and its stderr is discarded (never logged) because it can
contain device details. Only the ``coreelements`` and ``video4linux2`` plugins
can load, and the child runs under a Landlock sandbox (``uvc_sandbox``) that
lets it open no device node other than the approved one. Tests inject a
synthetic launcher; production never substitutes one silently.
"""

from collections import deque
from dataclasses import dataclass, field
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import sysconfig
import threading
import time
from typing import Protocol

from . import uvc_sandbox


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
    def stop(self, timeout: float, *, wait: bool = True) -> bool: ...
    def close(self) -> None: ...


class PipelineLauncher(Protocol):
    """Start one video-only pipeline reading the given verified V4L2 descriptor."""

    def launch(self, device_fd: int, profile: MjpegProfile) -> PipelineProcess: ...


class _GroupScan:
    """Result of one process-table scan; any failure counts as a live member."""

    def __init__(self):
        self.done = threading.Event()
        self.alive = True

    def run(self, scan, deadline):
        try:
            self.alive = scan(deadline)
        except Exception:  # Fail closed; an error is never evidence of absence.
            self.alive = True
        finally:
            self.done.set()


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
        self._scan = None

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

    def _group_member_alive(self, deadline):
        """True while a non-leader member of the group is not yet dead.

        Unprovable absence (no readable process table, or a scan that could
        not finish before ``deadline``) counts as alive, so cleanup is never
        reported without evidence. The scan runs in a worker thread because a
        busy or stalled ``/proc`` can block ``listdir``/``open``/``read`` past
        any per-entry check; at most one scan per pipeline is outstanding, so
        a stalled one is awaited again instead of starting more threads.
        """
        while True:
            scan, fresh = self._scan, self._scan is None
            if fresh:
                scan = _GroupScan()
                thread = threading.Thread(target=scan.run, args=(self._scan_group, deadline),
                                          name="media-capture-agent-pgscan", daemon=True)
                try:
                    thread.start()
                except RuntimeError:
                    return True
                self._scan = scan
            if not scan.done.wait(max(0.0, deadline - time.monotonic())):
                return True
            self._scan = None
            # Absence is stable once proven: the unreaped zombie leader keeps
            # the group ID reserved, so an earlier scan's "gone" is still valid
            # evidence; its "alive" (possibly its own expired bound) is not
            # final, so one fresh scan runs within this deadline.
            if fresh or not scan.alive:
                return scan.alive

    def _scan_group(self, deadline):
        pgid = self.process.pid
        try:
            entries = os.listdir(self._proc_root)
        except OSError:
            return True
        for name in entries:
            if time.monotonic() >= deadline:
                return True
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

    def _wait_group_gone(self, deadline, wait_deadline):
        while self._group_member_alive(deadline):
            if time.monotonic() >= wait_deadline:
                return False
            time.sleep(0.01)
        return True

    def stop(self, timeout, *, wait=True):
        """Terminate the whole group within ``timeout``; False means not reaped.

        With ``wait=False`` the group is signalled and checked once without
        sleeping; ``timeout`` then only bounds that check (the process-table
        scan), so a later retry can still prove the group gone.
        """
        if self._reaped:
            return True
        deadline = time.monotonic() + timeout
        wait_deadline = deadline if wait else time.monotonic()
        if not self.exited():
            self._signal(signal.SIGTERM)
            self._wait_exit(min(wait_deadline, time.monotonic() + timeout / 2))
        # Also removes any surviving group member of an already exited leader.
        self._signal(signal.SIGKILL)
        if not self._wait_exit(wait_deadline):
            return False
        # The unreaped zombie leader keeps the group ID from being reused, so
        # a surviving member is still identified by it on a later retry.
        if not self._wait_group_gone(deadline, wait_deadline):
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
# The only plugins the child may load: ``fdsink`` (core) and ``v4l2src``.
GSTREAMER_PLUGINS = ("libgstcoreelements.so", "libgstvideo4linux2.so")
# No plugin directory is scanned (so no audio/GUI/network plugin is ever
# loaded, not even by the registry scanner), the registry cache is neither read
# nor written, and no ``gst-plugin-scanner`` helper process is spawned.
GSTREAMER_ENVIRONMENT = {
    "GST_PLUGIN_SYSTEM_PATH_1_0": "", "GST_PLUGIN_SYSTEM_PATH": "",
    "GST_PLUGIN_PATH_1_0": "", "GST_PLUGIN_PATH": "",
    "GST_REGISTRY_DISABLE": "yes", "GST_REGISTRY_FORK": "no",
}


def gstreamer_argv(executable, device_fd, profile, *, plugins=()):
    """``v4l2src ! image/jpeg caps ! fdsink``; nothing else can be expressed."""
    if not isinstance(profile, MjpegProfile):
        raise PipelineError("explicit MJPEG profile is required")
    if any(not isinstance(plugin, str) or "," in plugin for plugin in plugins):
        raise PipelineError("invalid pipeline plugin")
    preload = [f"--gst-plugin-load={','.join(plugins)}"] if plugins else []
    return [str(executable), "-q", *preload,
            GSTREAMER_ELEMENTS[0], f"device=/proc/self/fd/{device_fd}", "do-timestamp=true",
            "!", profile.caps(),
            "!", GSTREAMER_ELEMENTS[1], "fd=1", "sync=false"]


SANDBOX_HELPER = Path(uvc_sandbox.__file__).resolve()


def sandbox_argv(python, helper, device_fd, read_paths, command):
    """Run ``command`` under ``uvc_sandbox``: only the approved device is openable."""
    python, helper = Path(python), Path(helper)
    if not python.is_absolute() or not helper.is_absolute():
        raise PipelineError("video pipeline sandbox is unavailable")
    reads = []
    for path in read_paths:
        reads += ["--read", str(path)]
    return [str(python), "-I", "-S", "-B", str(helper),
            "--device-fd", str(device_fd), *reads, "--", *command]


def require_trusted_executable(path):
    """Refuse a pipeline binary that the service account (or anyone) could replace."""
    return _require_root_controlled(path, executable=True)


def require_trusted_file(path):
    """Refuse a plugin file that the service account (or anyone) could replace."""
    return _require_root_controlled(path, executable=False)


def _require_root_controlled(path, *, executable):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PipelineError("pipeline executable must be an absolute path")
    try:
        info = os.stat(path, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            path = path.resolve(strict=True)
            info = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (executable and not info.st_mode & 0o111)):
            raise PipelineError("pipeline executable is not root-controlled")
        for parent in path.parents:
            parent_info = os.stat(parent, follow_symlinks=False)
            if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise PipelineError("pipeline executable is not root-controlled")
    except OSError:
        raise PipelineError("pipeline executable is unavailable") from None
    return path


def default_plugin_dirs():
    multiarch = sysconfig.get_config_var("MULTIARCH")
    dirs = [f"/usr/lib/{multiarch}/gstreamer-1.0"] if multiarch else []
    return (*dirs, "/usr/lib64/gstreamer-1.0", "/usr/lib/gstreamer-1.0")


class GStreamerLauncher(SubprocessLauncher):
    """Operator-installed GStreamer; not bundled, never downloaded, never PATH-searched.

    ``gst-launch-1.0`` itself probes every ``/dev/video*`` node read-write when
    its ``video4linux2`` plugin loads, so the child is started through the
    Landlock helper (``uvc_sandbox``), which leaves it able to open only the
    approved descriptor's device. Without Landlock the launcher refuses to run
    (fail closed) instead of exposing every camera to the pipeline. The helper
    and the interpreter that runs it get the same root-controlled check as the
    executable and plugins at every start, because either one could otherwise
    skip the confinement; the resolved interpreter path is executed so a
    replaceable symlink (e.g. in a virtual environment) is never followed later.
    """

    def __init__(self, executable, *, plugin_dirs=None, trust=require_trusted_executable,
                 trust_file=require_trusted_file, sandbox_abi=uvc_sandbox.abi_version,
                 python=sys.executable, helper=SANDBOX_HELPER, popen=subprocess.Popen):
        self.executable = trust(executable)
        self._trust = trust
        self._trust_file = trust_file
        if sandbox_abi() < 1:
            raise PipelineError("video pipeline sandbox is unavailable")
        self.plugins = self._find_plugins(default_plugin_dirs() if plugin_dirs is None
                                          else plugin_dirs)
        if not python:
            raise PipelineError("video pipeline sandbox is unavailable")
        self.python, self.helper = python, helper
        self._trusted_sandbox()
        super().__init__(self._argv, environment=GSTREAMER_ENVIRONMENT, popen=popen)

    def _find_plugins(self, plugin_dirs):
        for directory in plugin_dirs:
            candidates = [Path(directory) / name for name in GSTREAMER_PLUGINS]
            if all(candidate.exists() for candidate in candidates):
                return tuple(self._trust_file(candidate) for candidate in candidates)
        raise PipelineError("required GStreamer plugins are unavailable")

    def _trusted_sandbox(self):
        return self._trust(self.python), self._trust_file(self.helper)

    def _argv(self, device_fd, profile):
        # Re-check at every start: a package change must not be trusted blindly.
        python, helper = self._trusted_sandbox()
        executable = self._trust(self.executable)
        plugins = tuple(self._trust_file(plugin) for plugin in self.plugins)
        command = gstreamer_argv(executable, device_fd, profile,
                                 plugins=[str(plugin) for plugin in plugins])
        read_paths = (*uvc_sandbox.DEFAULT_READ_PATHS, str(executable),
                      *(str(plugin) for plugin in plugins))
        return sandbox_argv(python, helper, device_fd, read_paths, command)
