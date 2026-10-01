"""Explicit local-artifact synthetic check; not run with weights in CI."""

import argparse
from contextlib import contextmanager
import importlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import UUID

RTDETR = "rtdetr-v2-r18vd-onnx-cpu"
YOLOX_FACTORY = "app.detection.foundation.yolox:create_yolox_person"
# Every DNS entry point has its own audit event: gethostbyname(_ex) raise
# socket.gethostbyname, reverse lookup socket.gethostbyaddr / getnameinfo.
# An unconnected datagram send raises socket.sendto or socket.sendmsg.
LAUNCH_EVENT = "serversentinel.smoke.fork_exec"
OUTBOUND_EVENTS = frozenset({"socket.connect", "socket.getaddrinfo",
                             "socket.gethostbyname", "socket.gethostbyaddr",
                             "socket.getnameinfo", "socket.sendto", "socket.sendmsg",
                             "subprocess.Popen", "os.system", "os.posix_spawn",
                             "os.fork", "os.forkpty", "os.exec",
                             LAUNCH_EVENT})
# The multiprocessing "spawn" start (the IsolatedDetector worker) calls
# `_posixsubprocess.fork_exec` directly. CPython 3.12 raises no audit event for
# it, so `observe_process_launches` wraps that module attribute to raise
# LAUNCH_EVENT on every Python-level call, on every runtime; the native event
# that newer runtimes add is then ignored to avoid double counting. Only the
# expected worker spawn (and its resource tracker), inside
# `permit_worker_launch()`, is permitted.
# Native code forking without these entry points is not observed.
WORKER_LAUNCH_EVENTS = frozenset({LAUNCH_EVENT})
# The worker itself and the multiprocessing resource tracker that the spawn
# context starts once per process, told apart by their fixed argv.
PERMITTED_WORKER_LAUNCHES = frozenset({"multiprocessing.spawn",
                                       "multiprocessing.resource_tracker"})
# Per process: the smoke process and the spawned worker each record their own.
_attempts = []
_permitted_launches = []
_worker_launch_open = False
_audit_installed = False


def observe_process_launches():
    """Make the stdlib fork_exec path observable; idempotent, per process."""
    import _posixsubprocess
    native = _posixsubprocess.fork_exec
    if getattr(native, "_smoke_observed", False):
        return

    def fork_exec(*args, **kwargs):
        sys.audit(LAUNCH_EVENT, _launch_kind(args[0] if args else ()))
        return native(*args, **kwargs)

    fork_exec._smoke_observed = True
    _posixsubprocess.fork_exec = fork_exec


def _launch_kind(argv):
    """Classify a launch by its argv: the two multiprocessing spawn children."""
    try:
        text = " ".join(os.fsdecode(part) for part in argv)
    except (TypeError, ValueError):
        return "other"
    for kind in ("multiprocessing.spawn import spawn_main",
                 "multiprocessing.resource_tracker import main"):
        if kind in text:
            return kind.split(" ")[0]
    return "other"


def install_audit():
    """Observe launches, then record and refuse outbound/process attempts."""
    global _audit_installed
    observe_process_launches()
    if not _audit_installed:
        sys.addaudithook(reject_outbound)
        _audit_installed = True


class SmokeFailure(RuntimeError):
    """The smoke check failed; raised unconditionally (unlike `assert`, which
    `python -O` / PYTHONOPTIMIZE strips), before any result is emitted."""


def require(condition, detail):
    if not condition:
        raise SmokeFailure(str(detail))


@contextmanager
def permit_worker_launch():
    """Permit (and count) only the expected worker spawn while the block runs."""
    global _worker_launch_open
    _worker_launch_open = True
    try:
        yield
    finally:
        _worker_launch_open = False


def reject_outbound(event, args):
    if (_worker_launch_open and event in WORKER_LAUNCH_EVENTS
            and args and args[0] in PERMITTED_WORKER_LAUNCHES):
        _permitted_launches.append(args[0])
        return
    if event in OUTBOUND_EVENTS:
        # Recorded before refusing, so an attempt whose refusal a library
        # swallows is still reported.
        _attempts.append(event)
        raise RuntimeError("unexpected outbound/process attempt")


class _AuditedWorkerDetector:
    """Worker-side wrapper: any attempt recorded in the child fails the result."""

    def __init__(self, detector):
        self._detector = detector
        self.kind = detector.kind
        self.implementation = detector.implementation
        self.version = detector.version

    def _check(self):
        if _attempts:
            raise RuntimeError("unexpected outbound/process attempt")

    def reset(self):
        self._detector.reset()
        self._check()

    def evaluate(self, frame):
        result = self._detector.evaluate(frame)
        self._check()
        return result


def audited_worker(target, **arguments):
    """Worker factory: audit hook first, then import, load and evaluate.

    Runs inside the spawned child, so the child's own artifact loading and
    evaluation are observed; the parent's hook cannot see another process.
    """
    install_audit()
    module, _, name = target.partition(":")
    detector = getattr(importlib.import_module(module), name)(**arguments)
    if _attempts:
        raise RuntimeError("unexpected outbound/process attempt")
    return _AuditedWorkerDetector(detector)


def isolated_check(implementation, artifact, size, target=YOLOX_FACTORY):
    """Run the YOLOX adapter in the watchdog-supervised spawned worker.

    `main` installs this process's audit hook first, so parent-side YOLOX
    import and setup are observed too; only the worker spawn during start is
    explicitly permitted (`permit_worker_launch`): exactly one worker and at
    most one multiprocessing resource tracker, identified by argv. Without `install_audit()` (unit tests that must not hook the test
    runner) launches are reported as unobserved rather than as zero. The child
    applies its own rlimits and installs its own recording audit hook
    (`audited_worker`) before the adapter is imported; a recorded child
    attempt fails the start or the evaluation.
    """
    from app.detection.foundation import (DetectorKind, IsolatedDetector,
                                         Observation, RgbFrame, WorkerLimits, WorkerSpec)
    from app.detection.foundation.yolox import RELEASE
    spec = WorkerSpec(DetectorKind.PERSON, implementation, RELEASE, audited_worker,
                      {"target": target, "implementation": implementation,
                       "artifact": str(artifact), "score_threshold": 0.5,
                       "intra_op_threads": 1})
    # Explicit smoke-only limits, never deployment defaults.
    limits = WorkerLimits(evaluation_timeout_ns=5_000_000_000,
                          start_timeout_ns=60_000_000_000, restart_backoff_ns=1,
                          maximum_consecutive_failures=1, address_space_bytes=4 << 30,
                          open_files=256, maximum_frame_bytes=size * size * 3)
    detector = IsolatedDetector(spec, limits)
    try:
        with permit_worker_launch():
            state = detector.maintain().state
        frame = RgbFrame(UUID(int=1), UUID(int=2), 0, size, size,
                         bytes([0, 128, 255]) * (size * size))
        started = time.perf_counter_ns()
        result = detector.evaluate(frame)
        elapsed = time.perf_counter_ns() - started
        require(state == "running", state)
        require(result.observation is not Observation.UNKNOWN, result.reason)
        require(not _attempts, "unexpected outbound/process attempt in the smoke process")
        # Exactly the one expected worker; another launch during start (from
        # the same stdlib path) would make this differ. Without this process's
        # hook (unit tests only) launches are not observed and not claimed.
        if _audit_installed:
            require(_permitted_launches.count("multiprocessing.spawn") == 1
                    and _permitted_launches.count("multiprocessing.resource_tracker") <= 1,
                    "unexpected worker launch count")
        # Reaching here means the child's hook recorded no attempt.
        return {"worker_state": state, "worker_observation": result.observation.value,
                "worker_evaluation_ns": elapsed, "worker_python_outbound_attempts": 0,
                "process_launch_observed": _audit_installed,
                "permitted_worker_launches": (sorted(_permitted_launches)
                                              if _audit_installed else None)}
    finally:
        detector.close()


def main():
    # First, so parent-side YOLOX import and setup are audited as well.
    install_audit()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--adapter", default=RTDETR,
                        choices=[RTDETR, "yolox-s-onnx-cpu", "yolox-tiny-onnx-cpu"])
    args = parser.parse_args()
    worker = {}
    if args.adapter == RTDETR:
        size = 640
    else:
        from app.detection.foundation import yolox
        size = yolox.ARTIFACTS[yolox.ADAPTERS[args.adapter].variant].input_size
        worker = isolated_check(args.adapter, args.artifact, size)
    from app.detection.foundation import GrayFrame, Observation, RgbFrame
    from app.detection.foundation.person import RtDetrPersonDetector
    import onnxruntime
    started = time.perf_counter_ns()
    # Explicit test-only evaluation settings, never deployment defaults.
    if args.adapter == RTDETR:
        detector = RtDetrPersonDetector(args.artifact, score_threshold=0.5, intra_op_threads=1)
    else:
        detector = yolox.ADAPTERS[args.adapter](args.artifact, score_threshold=0.5,
                                                intra_op_threads=1)
    loaded = time.perf_counter_ns()
    pixels = bytes([0, 128, 255]) * (size * size)
    frame = RgbFrame(UUID(int=1), UUID(int=2), 0, size, size, pixels)
    result = detector.evaluate(frame)
    evaluated = time.perf_counter_ns()
    require(result.observation is not Observation.UNKNOWN, result.reason)
    invalid = GrayFrame(UUID(int=1), UUID(int=2), 1, 1, 1, bytes([0]))
    require(detector.evaluate(invalid).observation is Observation.UNKNOWN,
            "malformed frame was not unknown")
    print(json.dumps({
        "workload": "generated uniform RGB only; not person accuracy acceptance",
        "adapter": args.adapter,
        "runtime": onnxruntime.__version__,
        "build": onnxruntime.get_build_info(),
        "available_providers": onnxruntime.get_available_providers(),
        "enabled_providers": detector._session.get_providers(),
        "load_ns": loaded - started,
        "evaluation_ns": evaluated - loaded,
        "synthetic_observation": result.observation.value,
        "synthetic_score": result.measurement,
        "malformed_frame": "unknown",
        "python_outbound_attempts": len(_attempts),
        **worker,
    }, sort_keys=True))
    if _attempts:
        sys.exit(1)


if __name__ == "__main__":
    main()
