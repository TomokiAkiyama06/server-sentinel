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
  child exits, so the child is started by this source's own supervisor
  thread, which lives until `close()`), a lower CPU priority and equal
  soft/hard rlimits (address space, descriptors, no new process/thread, no
  core dump, no file writes);
* starting a child (fork+exec, the ready handshake, bounded by
  `start_timeout_ns`) and reaping a killed one run on that supervisor thread,
  never on the shared scene worker: a frame that arrives while this source's
  child is starting, backing off or being reaped is refused at once, so a
  broken child never delays (or refuses) another source's frames;
* every exchange runs under a wall-clock deadline that covers the frame
  transfer as well as the wait; a crash, `SIGKILL` (including an OOM kill), a
  non-zero exit, a timeout (the child is then killed), an oversized or
  malformed reply, or a reply for another request kills the child (it is
  reaped by the supervisor) and refuses that frame as `MjpgFrameRejected` (the
  scene runtime maps it to `unknown`, never to "no movement" / "no tamper");
* a replacement is started only after a bounded exponential backoff and only
  once the previous child has been reaped; until then frames are refused
  immediately (never waited on). After `failing_after` consecutive child
  failures the decoder reports `failing`, which lowers the source to
  `degraded`; one successful exchange (or a refusal by a healthy child) clears
  it.

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
# Mechanism constants. How long the supervisor waits for the kernel to reap a
# child that has already received SIGKILL before it reports `reap_failed`
# (it keeps trying afterwards, every `_REAP_RETRY_S`, and never starts a
# second child meanwhile).
_REAP_TIMEOUT_S = 2.0
_REAP_RETRY_S = 0.5
# Slice of the supervisor's waits on a child (ready message, reaping): a
# retire or stop is noticed within it, never only after a whole start timeout.
_SLICE_S = 0.05
# The child's environment: nothing from the service environment (which may
# carry deployment values) is inherited. One BLAS / OpenMP thread keeps the
# numpy import inside the address-space limit and creates no thread.
CHILD_ENVIRONMENT = {
    "LC_ALL": "C", "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
}
REFUSALS = {1: "decode_failed", 2: "decoded_shape_mismatch", 3: "undecoded_band"}

# Child lifecycle phases (guarded by `MjpgDecoderProcess._state`).
_IDLE, _STARTING, _READY, _DYING = "idle", "starting", "ready", "dying"


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
    records the real C960 value to confirm it). `start_timeout_ns` bounds the
    ready handshake of a new child; it runs on the source's supervisor thread
    (never on the scene worker) and a stop interrupts it within `_SLICE_S`, so
    it does not add to the scene stop bounds. `address_space_bytes` bounds
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


def _read_exact(connection, size, deadline, cancelled=None):
    """Read exactly `size` bytes before the absolute `deadline`.

    The deadline bounds the whole read (a peer that drips bytes still times
    out). With `cancelled`, the wait is sliced and `EOFError` is raised once
    it returns True.
    """
    buffer = bytearray(size)
    view, received = memoryview(buffer), 0
    while received < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        if cancelled is not None:
            if cancelled():
                raise EOFError
            remaining = min(remaining, _SLICE_S)
        connection.settimeout(remaining)
        try:
            count = connection.recv_into(view[received:], size - received)
        except TimeoutError:
            if cancelled is None:
                raise
            continue
        if count == 0:
            raise EOFError
        received += count
    return bytes(buffer)


def _signal(process) -> None:
    try:
        process.kill()
    except (OSError, ValueError):
        pass


class MjpgDecoderProcess:
    """At most one supervised decode child for one source.

    A per-source supervisor thread (started on demand and kept until
    `close()`) starts the child, waits for its ready message and reaps it
    after a failure. The child is started by that thread, so its parent-death
    signal is tied to a thread that outlives it. None of these waits runs on
    the caller: `decode()` (scene worker only) exchanges one frame with a
    ready child under the per-frame deadline, or refuses the frame at once
    (`decoder_starting` while a start is under way, `decoder_unavailable`
    during the backoff, a reap or after `retire()`) and, when the backoff
    allows, asks the supervisor for a child. `prepare()` asks for a child
    without a frame (non-blocking); `retire()` forbids further starts
    (shutdown); `kill()` signals the child without waiting and may be called
    from any thread; `close()` stops the supervisor and kills and reaps the
    child within a bound.
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
        # One exchange at a time; held only by `decode()` and `close()`.
        self._exchange = threading.Lock()
        # Lifecycle state; never held across a wait on the child or a socket.
        self._state = threading.Condition(threading.Lock())
        self._thread = None
        self._phase = _IDLE
        self._process = None
        self._connection = None
        self._request = 0
        self._retry_at = None
        self._retired = False
        self._stopping = False
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
        with self._state:
            if self._reap_failed:
                state = "reap_failed"
            elif self._phase == _READY:
                state = "running"
            elif self._phase == _STARTING:
                state = "starting"
            elif self._phase == _DYING:
                state = "reaping"
            elif self._retired:
                state = "closed"
            elif self._retry_at is not None:
                state = "backoff"
            else:
                state = "stopped"
            return MjpgDecoderStatus(state, self._starts, self._start_failures, self._crashes,
                                     self._timeouts, self._protocol_errors, self._consecutive,
                                     self.failing)

    # -- scene worker -----------------------------------------------------
    def prepare(self) -> None:
        """Ask for a child when none is running and the backoff allows.

        Never waits: the supervisor starts it in the background.
        """
        with self._state:
            self._want_locked()

    def decode(self, data: bytes, request: DecodeRequest) -> bytes:
        if type(data) is not bytes or not 0 < len(data) <= self._maximum:
            raise DecoderRefusal("frame_too_large")
        with self._exchange:
            with self._state:
                if self._phase == _READY and self._process.poll() is not None:
                    # The idle child died (crash, kill, OOM kill) since the
                    # last frame: this frame is refused and the backoff starts.
                    self._failed_locked("crash")
                    raise DecoderRefusal("decoder_crashed")
                if self._phase != _READY:
                    # Starting, backing off, reaping or retired: refused at
                    # once, never waited on.
                    raise DecoderRefusal(self._want_locked())
                connection = self._connection
                self._request = (self._request + 1) % (1 << 64)
                number = self._request
            identifier = number.to_bytes(8, "big")
            body = request.header(number)
            expected = request.width * request.height
            deadline = time.monotonic() + self._limits.frame_timeout_ns / 1e9
            kind = None
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
                    # Refused before reading (or allocating for) the body.
                    raise _Protocol
                reply = _read_exact(connection, size, deadline)
            except _Protocol:
                kind, reason = "protocol", "decoder_protocol"
            except TimeoutError:
                kind, reason = "timeout", "decoder_timeout"
            except (EOFError, OSError, ValueError, OverflowError):
                kind, reason = "crash", "decoder_crashed"
            if kind is None:
                code, echoed = reply[:1], reply[1:_REPLY_HEADER_BYTES]
                if echoed == identifier and code == b"K" and size == _REPLY_HEADER_BYTES + expected:
                    with self._state:
                        self._consecutive = 0
                    return reply[_REPLY_HEADER_BYTES:]
                if (echoed == identifier and code == b"F" and size == _REPLY_HEADER_BYTES + 1
                        and reply[-1] in REFUSALS):
                    # A healthy child refused this frame; the child stays.
                    with self._state:
                        self._consecutive = 0
                    raise DecoderRefusal(REFUSALS[reply[-1]])
                kind, reason = "protocol", "decoder_protocol"
            with self._state:
                self._failed_locked(kind)
            raise DecoderRefusal(reason)

    def retire(self) -> None:
        """No further child is started (shutdown); a running one stays, a
        start still in progress is abandoned (that child is killed)."""
        with self._state:
            self._retired = True
            self._state.notify_all()

    # -- any thread -------------------------------------------------------
    def kill(self) -> None:
        """Signal the child without waiting (unblocks a pending exchange or
        start) and forbid further starts."""
        with self._state:
            self._retired = True
            process = self._process
            if process is not None:
                _signal(process)
            self._state.notify_all()

    def close(self, timeout: float = _REAP_TIMEOUT_S) -> bool:
        """Stop the supervisor, kill and reap the child; True once neither
        the supervisor nor a child process remains."""
        deadline = time.monotonic() + max(0.0, timeout)
        self.kill()
        with self._state:
            self._stopping = True
            self._state.notify_all()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                return False
        if not self._exchange.acquire(timeout=max(0.0, deadline - time.monotonic())):
            return False
        try:
            with self._state:
                connection, self._connection = self._connection, None
                process = self._process
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            if process is not None:
                _signal(process)
                try:
                    process.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    with self._state:
                        self._reap_failed = True
                    return False
                except OSError:
                    pass
            with self._state:
                if self._process is process:
                    self._process, self._phase, self._reap_failed = None, _IDLE, False
            return True
        finally:
            self._exchange.release()

    # -- internals (caller holds `_state`) ---------------------------------
    def _want_locked(self) -> str:
        """Request a start when allowed; the refusal reason for this frame."""
        if self._phase == _READY:
            # Only `prepare()` gets here with a running child: nothing to do.
            return "decoder_unavailable"
        if self._phase == _STARTING:
            return "decoder_starting"
        if self._reap_failed or self._phase == _DYING:
            # A child that is not yet reaped blocks any replacement.
            if not self._stopping:
                self._supervisor_locked()
            return "decoder_unavailable"
        if (self._retired or self._stopping
                or (self._retry_at is not None and self._clock() < self._retry_at)):
            return "decoder_unavailable"
        if not self._supervisor_locked():
            self._failed_locked("start")
            return "decoder_unavailable"
        self._phase = _STARTING
        self._state.notify_all()
        return "decoder_starting"

    def _supervisor_locked(self) -> bool:
        thread = self._thread
        if thread is not None and thread.is_alive():
            return True
        thread = threading.Thread(target=self._supervise, name="mjpg-decoder", daemon=True)
        try:
            thread.start()
        except RuntimeError:
            return False
        self._thread = thread
        return True

    def _failed_locked(self, kind: str) -> None:
        """Kill the child (the supervisor reaps it) and start the backoff."""
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        process = self._process
        if process is not None:
            _signal(process)
            self._phase = _DYING
            if not self._stopping:
                # Reaped in the background (`close()` reaps after a stop).
                self._supervisor_locked()
        else:
            self._phase = _IDLE
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
        self._state.notify_all()

    def _cancelled(self) -> bool:
        return self._retired or self._stopping

    # -- supervisor thread ------------------------------------------------
    def _supervise(self) -> None:
        try:
            while True:
                with self._state:
                    while not self._stopping and self._phase not in (_STARTING, _DYING):
                        self._state.wait()
                    if self._stopping:
                        # `close()` reaps whatever is left.
                        return
                    phase, process = self._phase, self._process
                if phase == _STARTING:
                    self._start()
                elif process is not None:
                    self._reap(process)
        finally:
            with self._state:
                if self._thread is threading.current_thread():
                    self._thread = None
                if not self._stopping and self._phase == _STARTING:
                    # Only on an unexpected supervisor failure: the start is
                    # abandoned (the child dies with this thread).
                    self._failed_locked("start")

    def _start(self) -> None:
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            with self._state:
                self._start_abandoned_locked()
            return
        try:
            process = subprocess.Popen(
                self._argv(child.fileno()), env=dict(CHILD_ENVIRONMENT), cwd="/",
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(child.fileno(),), shell=False)
        except Exception:
            parent.close()
            child.close()
            with self._state:
                self._start_abandoned_locked()
            return
        child.close()
        with self._state:
            # Published before anything else happens, under the same lock as
            # `kill()`: a kill from now on reaches this child, and one that
            # came first (between Popen returning and here) is applied now.
            self._process = process
            cancelled = self._cancelled()
        if cancelled:
            _signal(process)
        ready = False
        if not cancelled:
            expected = f"R{SIMPLEJPEG_VERSION} {NUMPY_VERSION}".encode("ascii")
            deadline = time.monotonic() + self._limits.start_timeout_ns / 1e9
            try:
                size = int.from_bytes(_read_exact(parent, 4, deadline, self._cancelled), "big")
                if size == len(expected):
                    ready = _read_exact(parent, size, deadline, self._cancelled) == expected
            except (EOFError, OSError, ValueError, TimeoutError):
                ready = False
        with self._state:
            if ready and not self._cancelled():
                self._connection, self._phase = parent, _READY
                self._starts += 1
                self._state.notify_all()
                return
            self._start_abandoned_locked()
        parent.close()

    def _start_abandoned_locked(self) -> None:
        if self._cancelled():
            # Shutdown, not a child failure: kill whatever was started.
            if self._process is not None:
                _signal(self._process)
                self._phase = _DYING
            else:
                self._phase = _IDLE
            self._state.notify_all()
        else:
            # A child that failed hardening, could not import the reviewed
            # pair, reported other versions or did not report in time is
            # never used.
            self._failed_locked("start")

    def _reap(self, process) -> None:
        _signal(process)
        deadline = time.monotonic() + _REAP_TIMEOUT_S
        while True:
            try:
                process.wait(timeout=_SLICE_S)
                break
            except subprocess.TimeoutExpired:
                pass
            except OSError:
                break
            with self._state:
                if self._stopping:
                    return
                if time.monotonic() >= deadline:
                    # Keep the handle: no second child is started alongside
                    # it. The reap is retried until it succeeds or a stop.
                    self._reap_failed = True
                    self._state.wait(_REAP_RETRY_S)
                    if self._stopping:
                        return
        with self._state:
            if self._process is process:
                self._process, self._phase, self._reap_failed = None, _IDLE, False
            self._state.notify_all()

    def _argv(self, descriptor: int) -> list[str]:
        limits = self._limits
        prefix = list(self._command) if self._command else [sys.executable, "-I", "-B", str(CHILD)]
        return prefix + [str(descriptor), str(os.getpid()), str(limits.address_space_bytes),
                         str(limits.open_files), str(limits.niceness), str(self._maximum),
                         SIMPLEJPEG_VERSION, NUMPY_VERSION]


class _Protocol(Exception):
    pass
