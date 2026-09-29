"""Watchdog-supervised, resource-limited detector worker process.

`IsolatedDetector` satisfies the `Detector` protocol, but the reviewed
detector itself is constructed and evaluated inside one spawned child process.
A wall-clock watchdog covers every request (frame transfer included). A hang,
crash, start failure, resource-limit failure or protocol violation kills and
reaps the child and yields `unknown` with a worker reason; it never yields
`absent`. The parent never unpickles child output: replies are small,
strictly-validated JSON documents.

Linux delivers the child's parent-death SIGKILL when the *thread* that
started it exits, so `maintain()` belongs on the long-lived inference worker
thread. The consecutive-failure latch is in memory; a service restart starts
from the reloaded deployment configuration.

This is fault isolation, not an untrusted-code sandbox. The child keeps the
service account's filesystem view and network namespace; confinement beyond
the rlimits/prctl flags below belongs to the systemd unit and reviewed code.
"""

from dataclasses import dataclass, field
import json
import math
import multiprocessing
import os
import threading
import time
from typing import Any, Callable, Mapping
from uuid import UUID

from .contracts import (Detection, DetectorKind, GrayFrame, Observation, Reason,
                        RgbFrame, positive_integer)

# Wire format: 1-byte operation, 8-byte request id, then for evaluation a fixed
# header (source, stream, sequence, width, height, channels) and raw pixels.
_REQUEST_ID_BYTES = 8
_HEADER_BYTES = 16 + 16 + 8 + 4 + 4 + 1
_MAX_REPLY_BYTES = 512
# Mechanism constant, not a deployment policy: how long to wait for the kernel
# to reap a child that has already received SIGKILL.
_REAP_TIMEOUT_S = 5.0
_PR_SET_PDEATHSIG = 1
_PR_SET_NO_NEW_PRIVS = 38
_ARGUMENT_TYPES = (str, int, float, bool, type(None))


class DetectorWorkerFailure(RuntimeError):
    """Fixed message; child exception text, paths and pixels never escape."""

    def __init__(self) -> None:
        super().__init__("isolated detector worker failed")


@dataclass(frozen=True)
class WorkerLimits:
    """Explicit deployment limits; this module chooses none of these values."""

    evaluation_timeout_ns: int
    start_timeout_ns: int
    restart_backoff_ns: int
    maximum_consecutive_failures: int
    address_space_bytes: int
    open_files: int
    maximum_frame_bytes: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            positive_integer(getattr(self, name), name)
        # stdio, the request pipe and interpreter internals need descriptors.
        if self.open_files < 8:
            raise ValueError("open_files is too small for a worker interpreter")


@dataclass(frozen=True)
class WorkerSpec:
    """A reviewed, importable top-level factory and primitive arguments.

    The factory is pickled by reference and called only in the child, so model
    loading and native runtime initialisation happen after the rlimits apply.
    """

    kind: DetectorKind
    implementation: str
    version: str
    factory: Callable[..., Any] = field(repr=False)
    arguments: tuple[tuple[str, object], ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DetectorKind):
            raise ValueError("invalid detector kind")
        for value in (self.implementation, self.version):
            if not isinstance(value, str) or not value:
                raise ValueError("detector implementation and version are required")
        if not callable(self.factory) or "<locals>" in getattr(self.factory, "__qualname__", "<locals>"):
            raise ValueError("worker factory must be an importable top-level callable")
        if isinstance(self.arguments, Mapping):
            object.__setattr__(self, "arguments", tuple(sorted(self.arguments.items())))
        if (not isinstance(self.arguments, tuple)
                or any(not isinstance(item, tuple) or len(item) != 2
                       or not isinstance(item[0], str)
                       or not isinstance(item[1], _ARGUMENT_TYPES)
                       for item in self.arguments)):
            raise ValueError("worker arguments must be primitive keyword values")


@dataclass(frozen=True)
class WorkerStatus:
    state: str
    starts: int
    start_failures: int
    crashes: int
    timeouts: int
    protocol_errors: int
    consecutive_failures: int
    last_failure: Reason | None


def _unknown(reason: Reason) -> Detection:
    return Detection(Observation.UNKNOWN, reason)


# ---------------------------------------------------------------- child side

def _harden(parent_pid: int, address_space: int, open_files: int) -> None:
    import ctypes
    import resource
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError("no_new_privs unavailable")
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError("parent-death signal unavailable")
    if os.getppid() != parent_pid:
        # The parent died before the death signal was armed.
        raise OSError("parent is gone")
    for limit, value in ((resource.RLIMIT_AS, address_space),
                         (resource.RLIMIT_NOFILE, open_files),
                         (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        _soft, hard = resource.getrlimit(limit)
        if hard != resource.RLIM_INFINITY and value > hard:
            raise OSError("requested limit exceeds the service limit")
        # Equal soft/hard limits: the detector cannot raise them again.
        resource.setrlimit(limit, (value, value))
    # Plugin diagnostics could contain paths or runtime details; discard them.
    null = os.open(os.devnull, os.O_RDWR)
    for descriptor in (0, 1, 2):
        os.dup2(null, descriptor)
    os.close(null)


def _reply(connection, value: dict) -> None:
    connection.send_bytes(json.dumps(value, allow_nan=False).encode("ascii"))


def _worker_main(connection, parent_pid, factory, arguments, address_space,
                 open_files, maximum_frame_bytes) -> None:
    try:
        _harden(parent_pid, address_space, open_files)
        detector = factory(**dict(arguments))
        identity = (detector.kind.value, detector.implementation, detector.version)
        if not all(isinstance(value, str) for value in identity):
            raise ValueError("invalid identity")
    except BaseException:
        try:
            _reply(connection, {"ready": False})
        finally:
            os._exit(3)
    _reply(connection, {"ready": True, "kind": identity[0],
                        "implementation": identity[1], "version": identity[2]})
    maximum = 1 + _REQUEST_ID_BYTES + _HEADER_BYTES + maximum_frame_bytes
    while True:
        try:
            message = connection.recv_bytes(maximum)
        except (EOFError, OSError):
            os._exit(0)
        operation = message[:1]
        request = int.from_bytes(message[1:1 + _REQUEST_ID_BYTES], "big")
        if operation == b"R":
            try:
                detector.reset()
                ok = True
            except Exception:
                ok = False
            _reply(connection, {"id": request, "ok": ok})
            continue
        if operation != b"E":
            os._exit(4)
        body = message[1 + _REQUEST_ID_BYTES:]
        try:
            header, pixels = body[:_HEADER_BYTES], body[_HEADER_BYTES:]
            source, stream = UUID(bytes=header[:16]), UUID(bytes=header[16:32])
            sequence = int.from_bytes(header[32:40], "big")
            width = int.from_bytes(header[40:44], "big")
            height = int.from_bytes(header[44:48], "big")
            channels = header[48]
            frame_type = RgbFrame if channels == 3 else GrayFrame
            frame = frame_type(source, stream, sequence, width, height, pixels)
            result = detector.evaluate(frame)
            if not isinstance(result, Detection):
                raise ValueError("invalid result")
            value = {"id": request, "o": result.observation.value,
                     "r": result.reason.value, "m": result.measurement}
        except Exception:
            value = {"id": request, "o": Observation.UNKNOWN.value,
                     "r": Reason.FAILURE.value, "m": None}
        _reply(connection, value)


# --------------------------------------------------------------- parent side

def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite value")


def _decode(payload: bytes) -> dict | None:
    try:
        value = json.loads(payload.decode("ascii"), parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        return None
    return value if type(value) is dict else None


def _parse_detection(payload: bytes, request: int) -> Detection | None:
    value = _decode(payload)
    if value is None or set(value) != {"id", "o", "r", "m"} or value["id"] != request:
        return None
    measurement = value["m"]
    try:
        # An integer too large for a float raises OverflowError here; it is a
        # protocol violation like any other malformed measurement.
        if measurement is not None and (type(measurement) not in (int, float)
                                        or not math.isfinite(measurement)):
            return None
        return Detection(Observation(value["o"]), Reason(value["r"]), measurement)
    except (TypeError, ValueError, OverflowError):
        return None


class IsolatedDetector:
    """One supervised child process per source binding.

    `evaluate()` never spawns a process: without a running worker it returns
    `unknown/detector_worker_unavailable` immediately, so start/restart latency
    is never charged to an inference budget. The inference worker thread (not
    a capture/recording/health thread) calls `maintain()` between evaluations;
    it restarts after the explicit backoff. After the explicit number of
    consecutive failures the binding latches unavailable until the control
    plane calls `recover()`. At most one child exists; a child that cannot be
    reaped blocks any replacement.
    """

    def __init__(self, spec: WorkerSpec, limits: WorkerLimits, *,
                 clock_ns: Callable[[], int] = time.monotonic_ns) -> None:
        if not isinstance(spec, WorkerSpec) or not isinstance(limits, WorkerLimits):
            raise ValueError("invalid isolated detector configuration")
        self.kind = spec.kind
        self.implementation = spec.implementation
        self.version = spec.version
        self._spec = spec
        self._limits = limits
        self._clock = clock_ns
        self._context = multiprocessing.get_context("spawn")
        self._lock = threading.Lock()
        self._process = None
        self._connection = None
        self._request = 0
        self._retry_at: int | None = None
        self._latched = False
        self._closed = False
        self._reap_failed = False
        self._starts = self._start_failures = self._crashes = 0
        self._timeouts = self._protocol_errors = self._consecutive = 0
        self._last_failure: Reason | None = None

    # -- control plane -----------------------------------------------------

    def maintain(self) -> WorkerStatus:
        """Reap a dead child and (re)start one when permitted. May block."""
        with self._lock:
            crashed = (self._process is not None and not self._reap_failed
                       and not self._process.is_alive())
            if crashed:
                self._failed(Reason.WORKER_CRASHED)
            if self._reap_failed:
                self._reap()
            # Never replace a child in the same call that found it dead: the
            # caller must observe a non-running state (and invalidate the
            # dead worker's published conclusion) even when the backoff is
            # shorter than the time this call took.
            if (not crashed and self._process is None and not self._closed
                    and not self._latched and not self._reap_failed
                    and (self._retry_at is None or self._clock() >= self._retry_at)):
                self._spawn()
            return self._status()

    def recover(self) -> None:
        """Explicit acknowledgement that a latched binding may restart."""
        with self._lock:
            if self._closed:
                raise RuntimeError("isolated detector is closed")
            self._latched = False
            self._consecutive = 0
            self._retry_at = None

    def close(self) -> bool:
        """Stop the child; True once its process has been reaped."""
        self._closed = True
        process = self._process
        if process is not None:
            try:
                process.kill()
            except (OSError, ValueError, AttributeError):
                pass
        with self._lock:
            self._terminate()
            return self._process is None

    def status(self) -> WorkerStatus:
        with self._lock:
            return self._status()

    # -- Detector protocol -------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            if self._process is None and not self._reap_failed:
                return  # A fresh worker constructs a fresh, reset detector.
            if self._reap_failed:
                raise DetectorWorkerFailure()
            self._request += 1
            request = self._request
            reply = self._exchange(b"R" + request.to_bytes(_REQUEST_ID_BYTES, "big"),
                                   self._limits.evaluation_timeout_ns)
            if reply is None:
                raise DetectorWorkerFailure()
            value = _decode(reply)
            if value is None or set(value) != {"id", "ok"} or value["id"] != request:
                self._protocol_violation()
                raise DetectorWorkerFailure()
            if value["ok"] is not True:
                # The detector's temporal state is now unknown; discard it.
                self._failed(Reason.FAILURE)
                raise DetectorWorkerFailure()

    def evaluate(self, frame: GrayFrame) -> Detection:
        if not isinstance(frame, GrayFrame) or frame.channels not in (1, 3):
            return _unknown(Reason.QUALITY)
        if len(frame.pixels) > self._limits.maximum_frame_bytes:
            return _unknown(Reason.RESOURCE_LIMIT)
        with self._lock:
            if self._process is None or self._reap_failed:
                return _unknown(Reason.WORKER_UNAVAILABLE)
            self._request += 1
            request = self._request
            message = b"".join((
                b"E", request.to_bytes(_REQUEST_ID_BYTES, "big"),
                frame.source_id.bytes, frame.stream_id.bytes,
                frame.sequence.to_bytes(8, "big"), frame.width.to_bytes(4, "big"),
                frame.height.to_bytes(4, "big"), bytes([frame.channels]), frame.pixels,
            ))
            reply = self._exchange(message, self._limits.evaluation_timeout_ns)
            if reply is None:
                return _unknown(self._last_failure or Reason.WORKER_CRASHED)
            result = _parse_detection(reply, request)
            if result is None:
                self._protocol_violation()
                return _unknown(Reason.FAILURE)
            self._consecutive = 0
            return result

    # -- internals (caller holds the lock) ---------------------------------

    def _status(self) -> WorkerStatus:
        if self._closed:
            state = "closed" if self._process is None else "reap_failed"
        elif self._reap_failed:
            state = "reap_failed"
        elif self._process is not None:
            state = "running"
        elif self._latched:
            state = "latched"
        elif self._retry_at is not None:
            state = "backoff"
        else:
            state = "stopped"
        return WorkerStatus(state, self._starts, self._start_failures, self._crashes,
                            self._timeouts, self._protocol_errors, self._consecutive,
                            self._last_failure)

    def _spawn(self) -> None:
        limits = self._limits
        try:
            parent, child = self._context.Pipe(duplex=True)
        except OSError:
            self._failed(Reason.WORKER_UNAVAILABLE, start=True)
            return
        try:
            process = self._context.Process(
                target=_worker_main, name="serversentinel-detector", daemon=True,
                args=(child, os.getpid(), self._spec.factory, self._spec.arguments,
                      limits.address_space_bytes, limits.open_files,
                      limits.maximum_frame_bytes))
            process.start()
        except Exception:
            parent.close()
            child.close()
            self._failed(Reason.WORKER_UNAVAILABLE, start=True)
            return
        child.close()
        self._process, self._connection = process, parent
        reply = self._exchange(None, limits.start_timeout_ns, start=True)
        if reply is None:
            return
        value = _decode(reply)
        expected = {"ready": True, "kind": self.kind.value,
                    "implementation": self.implementation, "version": self.version}
        if value != expected:
            # A failed factory, or a detector whose identity differs from the
            # reviewed binding, is never published under that binding.
            self._terminate()
            self._failed(Reason.WORKER_UNAVAILABLE, start=True)
            return
        self._starts += 1

    def _exchange(self, message: bytes | None, timeout_ns: int, *,
                  start: bool = False) -> bytes | None:
        """Send and await one reply under a watchdog; None after a failure.

        The watchdog covers the frame transfer as well as the wait, so a child
        that stops reading its pipe cannot block the inference worker.
        """
        process, connection = self._process, self._connection
        guard = threading.Lock()
        state = {"done": False, "fired": False}

        def expire() -> None:
            with guard:
                if state["done"]:
                    return
                state["fired"] = True
            try:
                process.kill()
            except (OSError, ValueError, AttributeError):
                pass

        watchdog = threading.Timer(timeout_ns / 1e9, expire)
        watchdog.daemon = True
        reply, failure = None, Reason.WORKER_CRASHED
        try:
            # Without a watchdog no request may be sent: fail this worker.
            watchdog.start()
            if message is not None:
                connection.send_bytes(message)
            if connection.poll(timeout_ns / 1e9):
                try:
                    reply = connection.recv_bytes(_MAX_REPLY_BYTES)
                except OSError:
                    # Oversized reply: the child broke the wire contract.
                    failure = Reason.FAILURE
                    self._protocol_errors += 1
            else:
                failure = Reason.WORKER_TIMEOUT
        except (EOFError, OSError, ValueError, RuntimeError):
            reply = None
        finally:
            watchdog.cancel()
            with guard:
                state["done"] = True
                fired = state["fired"]
        if reply is not None and not fired:
            return reply
        if fired:
            failure = Reason.WORKER_TIMEOUT
        if start:
            self._terminate()
            self._failed(Reason.WORKER_TIMEOUT if failure is Reason.WORKER_TIMEOUT
                         else Reason.WORKER_UNAVAILABLE, start=True)
        else:
            self._failed(failure)
        return None

    def _protocol_violation(self) -> None:
        self._protocol_errors += 1
        self._failed(Reason.FAILURE)

    def _failed(self, reason: Reason, *, start: bool = False) -> None:
        self._terminate()
        if start:
            self._start_failures += 1
        elif reason is Reason.WORKER_TIMEOUT:
            self._timeouts += 1
        elif reason is Reason.WORKER_CRASHED:
            self._crashes += 1
        self._last_failure = reason
        self._consecutive += 1
        self._retry_at = self._clock() + self._limits.restart_backoff_ns
        if self._consecutive >= self._limits.maximum_consecutive_failures:
            self._latched = True

    def _terminate(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        if self._process is not None:
            try:
                self._process.kill()
            except (OSError, ValueError, AttributeError):
                pass
            self._reap()

    def _reap(self) -> None:
        process = self._process
        if process is None:
            self._reap_failed = False
            return
        try:
            process.join(_REAP_TIMEOUT_S)
        except (OSError, ValueError, AssertionError):
            pass
        if process.exitcode is None:
            # Keep the handle: never start a second child alongside it.
            self._reap_failed = True
            return
        try:
            process.close()
        except ValueError:
            pass
        self._process = None
        self._reap_failed = False
