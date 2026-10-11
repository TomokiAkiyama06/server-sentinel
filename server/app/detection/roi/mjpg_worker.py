"""Supervised resident MJPG decode child for one scene source (Issue #217).

Owner decision 2026-10-11 (PR #225, Option 1): the native simplejpeg /
libjpeg-turbo decoder never runs in the Main process. `MjpgDecoderProcess`
owns at most one child process (`mjpg_child.py`) for one local UVC source and
exchanges one frame at a time with it over a private `AF_UNIX` socketpair.

It mirrors the isolated inference worker (`app.detection.foundation.isolation`):

* the child is started with fork+exec of the service's own interpreter
  (`python -I -B`, no `preexec_fn`, so nothing runs in a forked copy of the
  threaded Main process), with an explicit minimal environment, stdio on
  ``/dev/null`` and only the socket inherited (`close_fds`);
* inside the child, before any third-party import: `no_new_privs`, a
  parent-death `SIGKILL` (Linux delivers it when the *thread* that started the
  child exits, so the child is started on the scene worker thread), a lower
  CPU priority and equal soft/hard rlimits (address space, descriptors, no new
  process/thread, no core dump, no file writes);
* every exchange runs under a wall-clock deadline that covers the frame
  transfer as well as the wait; a crash, `SIGKILL` (including an OOM kill), a
  non-zero exit, a timeout (the child is then killed), an oversized or
  malformed reply, or a reply for another request kills and reaps the child
  and refuses that frame as `MjpgFrameRejected` (the scene runtime maps it to
  `unknown`, never to "no movement" / "no tamper");
* a replacement is started only after a bounded exponential backoff; until
  then frames are refused immediately (never waited on). After
  `failing_after` consecutive child failures the decoder reports `failing`,
  which lowers the source to `degraded`; one successful exchange clears it.

The parent never unpickles or evaluates child output: a reply is a length-
prefixed byte message whose type, request id and exact pixel count are
checked.

This is fault isolation, not an untrusted-code sandbox: the child runs as the
same unprivileged service account, keeps its filesystem view and network
namespace (it opens no socket itself), and confinement beyond the rlimits and
prctl flags belongs to the systemd unit.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Callable

CHILD = Path(__file__).with_name("mjpg_child.py")
SIMPLEJPEG_VERSION = "1.9.0"
NUMPY_VERSION = "2.3.5"
REQUEST_HEADER_BYTES = 1 + 8 + 2 + 2 + 2 + 2 + 1 + 1 + 4
_REPLY_HEADER_BYTES = 1 + 8
_MAXIMUM_READY_BYTES = 64
# Mechanism constant: how long to wait for the kernel to reap a child that has
# already received SIGKILL.
_REAP_TIMEOUT_S = 2.0
# The child's environment: nothing from the service environment (which may
# carry deployment values) is inherited. One BLAS / OpenMP thread keeps the
# numpy import inside the address-space limit and creates no thread.
CHILD_ENVIRONMENT = {
    "LC_ALL": "C", "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
}
REFUSALS = {1: "decode_failed", 2: "decoded_shape_mismatch", 3: "undecoded_band"}


class DecoderRefusal(Exception):
    """A fixed, value-free reason; mapped to `MjpgFrameRejected` by the caller."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class MjpgDecoderLimits:
    """Per-source decode child limits (deployment-overridable defaults).

    `frame_timeout_ns` is the hard per-frame bound, transfer included: a child
    that has not replied by then is killed. The default leaves room for a
    loaded host; synthetic 1080p luma decodes take a few ms (MANUAL_TEST.md
    records the real C960 value to confirm it). `address_space_bytes` bounds
    the child's virtual memory: the interpreter with numpy and simplejpeg
    needs about 100 MiB, a 4K luma decode about 10 MiB more, plus the frame.
    """

    frame_timeout_ns: int = 500_000_000
    start_timeout_ns: int = 5_000_000_000
    address_space_bytes: int = 256 * 1024 * 1024
    open_files: int = 16
    niceness: int = 10
    restart_backoff_ns: int = 1_000_000_000
    maximum_backoff_ns: int = 30_000_000_000
    failing_after: int = 3

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError("invalid MJPG decoder limit")
        if not 0 < self.frame_timeout_ns <= 5_000_000_000:
            raise ValueError("invalid MJPG decode timeout")
        if not 0 < self.start_timeout_ns <= 30_000_000_000:
            raise ValueError("invalid MJPG decoder start timeout")
        if not 64 * 1024 * 1024 <= self.address_space_bytes <= 1 << 40:
            # Below 64 MiB the interpreter itself cannot start.
            raise ValueError("invalid MJPG decoder address-space limit")
        if not 8 <= self.open_files <= 1024:
            raise ValueError("invalid MJPG decoder descriptor limit")
        if not 0 <= self.niceness <= 19:
            raise ValueError("invalid MJPG decoder niceness")
        if not 0 < self.restart_backoff_ns <= self.maximum_backoff_ns <= 3_600_000_000_000:
            raise ValueError("invalid MJPG decoder backoff")
        if not 1 <= self.failing_after <= 1000:
            raise ValueError("invalid MJPG decoder failure threshold")


@dataclass(frozen=True)
class DecodeRequest:
    scaled_width: int
    scaled_height: int
    width: int
    height: int
    mcu_width: int
    mcu_height: int
    band_mcus: int

    def header(self, request: int) -> bytes:
        return b"".join((
            b"D", request.to_bytes(8, "big"),
            self.scaled_width.to_bytes(2, "big"), self.scaled_height.to_bytes(2, "big"),
            self.width.to_bytes(2, "big"), self.height.to_bytes(2, "big"),
            bytes((self.mcu_width, self.mcu_height)), self.band_mcus.to_bytes(4, "big"),
        ))


@dataclass(frozen=True)
class MjpgDecoderStatus:
    state: str
    starts: int
    start_failures: int
    crashes: int
    timeouts: int
    protocol_errors: int
    consecutive_failures: int
    failing: bool

    @property
    def failures(self) -> int:
        return self.start_failures + self.crashes + self.timeouts + self.protocol_errors


def _read_exact(connection, size, deadline):
    buffer = bytearray(size)
    view, received = memoryview(buffer), 0
    while received < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)
        count = connection.recv_into(view[received:], size - received)
        if count == 0:
            raise EOFError
        received += count
    return bytes(buffer)


class MjpgDecoderProcess:
    """At most one supervised decode child for one source.

    `decode()` runs only on the scene worker thread. It starts a child when
    none is running and the backoff has elapsed (on that thread, so the
    parent-death signal is tied to the worker), otherwise it refuses the frame
    at once. `retire()` forbids further starts (shutdown); `kill()` signals
    the child without waiting and may be called from any thread; `close()`
    kills and reaps it within a bound.
    """

    def __init__(self, limits: MjpgDecoderLimits, maximum_frame_bytes: int, *,
                 clock_ns: Callable[[], int] = time.monotonic_ns,
                 command: tuple[str, ...] | None = None):
        if not isinstance(limits, MjpgDecoderLimits):
            raise ValueError("invalid MJPG decoder limits")
        if type(maximum_frame_bytes) is not int or maximum_frame_bytes <= 0:
            raise ValueError("invalid MJPG frame bound")
        self._limits = limits
        self._maximum = maximum_frame_bytes
        self._clock = clock_ns
        # Tests substitute a synthetic child program; deployments never pass it.
        self._command = command
        self._lock = threading.Lock()
        self._process = None
        self._connection = None
        self._request = 0
        self._retry_at = None
        self._retired = False
        self._reap_failed = False
        self._starts = self._start_failures = self._crashes = 0
        self._timeouts = self._protocol_errors = self._consecutive = 0

    @property
    def pid(self) -> int | None:
        process = self._process
        return process.pid if process is not None else None

    @property
    def failing(self) -> bool:
        return self._consecutive >= self._limits.failing_after

    def status(self) -> MjpgDecoderStatus:
        if self._reap_failed:
            state = "reap_failed"
        elif self._process is not None:
            state = "running"
        elif self._retired:
            state = "closed"
        elif self._retry_at is not None:
            state = "backoff"
        else:
            state = "stopped"
        return MjpgDecoderStatus(state, self._starts, self._start_failures, self._crashes,
                                 self._timeouts, self._protocol_errors, self._consecutive,
                                 self.failing)

    # -- worker thread ----------------------------------------------------
    def decode(self, data: bytes, request: DecodeRequest) -> bytes:
        if type(data) is not bytes or not 0 < len(data) <= self._maximum:
            raise DecoderRefusal("frame_too_large")
        with self._lock:
            if self._reap_failed:
                # A child that could not be reaped blocks any replacement.
                self._terminate(0)
                if self._reap_failed:
                    raise DecoderRefusal("decoder_unavailable")
            if self._process is not None and self._process.poll() is not None:
                # The idle child died (crash, kill, OOM kill) since the last
                # frame: this frame is refused and the backoff starts.
                self._failed("crash")
                raise DecoderRefusal("decoder_crashed")
            if self._process is None:
                if (self._retired or self._reap_failed
                        or (self._retry_at is not None and self._clock() < self._retry_at)):
                    raise DecoderRefusal("decoder_unavailable")
                if not self._spawn():
                    raise DecoderRefusal("decoder_unavailable")
            self._request = (self._request + 1) % (1 << 64)
            identifier = self._request.to_bytes(8, "big")
            body = request.header(self._request)
            expected = request.width * request.height
            deadline = time.monotonic() + self._limits.frame_timeout_ns / 1e9
            connection = self._connection
            try:
                connection.settimeout(self._limits.frame_timeout_ns / 1e9)
                connection.sendall((len(body) + len(data)).to_bytes(4, "big") + body)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.settimeout(remaining)
                connection.sendall(data)
                size = int.from_bytes(_read_exact(connection, 4, deadline), "big")
                if size not in (_REPLY_HEADER_BYTES + 1, _REPLY_HEADER_BYTES + expected):
                    raise _Protocol
                reply = _read_exact(connection, size, deadline)
            except _Protocol:
                self._failed("protocol")
                raise DecoderRefusal("decoder_protocol") from None
            except (TimeoutError, socket.timeout):
                self._failed("timeout")
                raise DecoderRefusal("decoder_timeout") from None
            except (EOFError, OSError, ValueError, OverflowError):
                self._failed("crash")
                raise DecoderRefusal("decoder_crashed") from None
            kind, echoed = reply[:1], reply[1:_REPLY_HEADER_BYTES]
            if echoed != identifier:
                self._failed("protocol")
                raise DecoderRefusal("decoder_protocol")
            if kind == b"K" and size == _REPLY_HEADER_BYTES + expected:
                self._consecutive = 0
                return reply[_REPLY_HEADER_BYTES:]
            if kind == b"F" and size == _REPLY_HEADER_BYTES + 1 and reply[-1] in REFUSALS:
                # A healthy child refused this frame; the child stays.
                self._consecutive = 0
                raise DecoderRefusal(REFUSALS[reply[-1]])
            self._failed("protocol")
            raise DecoderRefusal("decoder_protocol")

    def retire(self) -> None:
        """No further child is started (shutdown); a running one stays."""
        self._retired = True

    # -- any thread -------------------------------------------------------
    def kill(self) -> None:
        """Signal the child without waiting (unblocks a pending exchange)."""
        self._retired = True
        process = self._process
        if process is not None:
            try:
                process.kill()
            except (OSError, ValueError):
                pass

    def close(self, timeout: float = _REAP_TIMEOUT_S) -> bool:
        """Kill and reap the child; True once no child process remains."""
        self.kill()
        if not self._lock.acquire(timeout=max(0.0, timeout)):
            return False
        try:
            self._terminate(timeout)
            return self._process is None
        finally:
            self._lock.release()

    # -- internals (caller holds the lock) --------------------------------
    def _argv(self, descriptor: int) -> list[str]:
        limits = self._limits
        prefix = list(self._command) if self._command else [sys.executable, "-I", "-B", str(CHILD)]
        return prefix + [str(descriptor), str(os.getpid()), str(limits.address_space_bytes),
                         str(limits.open_files), str(limits.niceness), str(self._maximum),
                         SIMPLEJPEG_VERSION, NUMPY_VERSION]

    def _spawn(self) -> bool:
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            self._failed("start")
            return False
        try:
            process = subprocess.Popen(
                self._argv(child.fileno()), env=dict(CHILD_ENVIRONMENT), cwd="/",
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(child.fileno(),), shell=False)
        except Exception:
            parent.close()
            child.close()
            self._failed("start")
            return False
        child.close()
        self._process, self._connection = process, parent
        expected = f"R{SIMPLEJPEG_VERSION} {NUMPY_VERSION}".encode("ascii")
        deadline = time.monotonic() + self._limits.start_timeout_ns / 1e9
        try:
            size = int.from_bytes(_read_exact(parent, 4, deadline), "big")
            if size != len(expected):
                raise ValueError
            ready = _read_exact(parent, size, deadline) == expected
        except (EOFError, OSError, ValueError, TimeoutError, socket.timeout):
            ready = False
        if not ready:
            # A child that failed hardening, could not import the reviewed
            # pair, or reported other versions is never used.
            self._failed("start")
            return False
        self._starts += 1
        return True

    def _failed(self, kind: str) -> None:
        self._terminate(_REAP_TIMEOUT_S)
        if kind == "start":
            self._start_failures += 1
        elif kind == "timeout":
            self._timeouts += 1
        elif kind == "protocol":
            self._protocol_errors += 1
        else:
            self._crashes += 1
        self._consecutive += 1
        exponent = min(self._consecutive - 1, 32)
        backoff = min(self._limits.restart_backoff_ns << exponent, self._limits.maximum_backoff_ns)
        self._retry_at = self._clock() + backoff

    def _terminate(self, timeout: float) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        process = self._process
        if process is None:
            self._reap_failed = False
            return
        try:
            process.kill()
        except (OSError, ValueError):
            pass
        try:
            process.wait(timeout=max(0.0, timeout))
        except subprocess.TimeoutExpired:
            # Keep the handle: never start a second child alongside it.
            self._reap_failed = True
            return
        except OSError:
            pass
        self._process = None
        self._reap_failed = False


class _Protocol(Exception):
    pass
