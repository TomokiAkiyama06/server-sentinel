"""Explicit local-artifact synthetic check; not run with weights in CI."""

import argparse
import importlib
import json
from pathlib import Path
import sys
import time
from uuid import UUID

RTDETR = "rtdetr-v2-r18vd-onnx-cpu"
YOLOX_FACTORY = "app.detection.foundation.yolox:create_yolox_person"
# Every DNS entry point has its own audit event: gethostbyname(_ex) raise
# socket.gethostbyname, reverse lookup socket.gethostbyaddr / getnameinfo.
OUTBOUND_EVENTS = frozenset({"socket.connect", "socket.getaddrinfo",
                             "socket.gethostbyname", "socket.gethostbyaddr",
                             "socket.getnameinfo", "socket.sendto",
                             "subprocess.Popen", "os.system", "os.posix_spawn"})
# Per process: the smoke process and the spawned worker each record their own.
_attempts = []


class SmokeFailure(RuntimeError):
    """The smoke check failed; raised unconditionally (unlike `assert`, which
    `python -O` / PYTHONOPTIMIZE strips), before any result is emitted."""


def require(condition, detail):
    if not condition:
        raise SmokeFailure(str(detail))


def reject_outbound(event, args):
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
    sys.addaudithook(reject_outbound)
    module, _, name = target.partition(":")
    detector = getattr(importlib.import_module(module), name)(**arguments)
    if _attempts:
        raise RuntimeError("unexpected outbound/process attempt")
    return _AuditedWorkerDetector(detector)


def isolated_check(implementation, artifact, size, target=YOLOX_FACTORY):
    """Run the YOLOX adapter in the watchdog-supervised spawned worker.

    Called before this process installs its audit hook, because spawning the
    worker is itself a process launch. The child applies its own rlimits and
    installs its own recording audit hook (`audited_worker`) before the adapter
    is imported; a recorded child attempt fails the start or the evaluation.
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
        state = detector.maintain().state
        frame = RgbFrame(UUID(int=1), UUID(int=2), 0, size, size,
                         bytes([0, 128, 255]) * (size * size))
        started = time.perf_counter_ns()
        result = detector.evaluate(frame)
        elapsed = time.perf_counter_ns() - started
        require(state == "running", state)
        require(result.observation is not Observation.UNKNOWN, result.reason)
        # Reaching here means the child's hook recorded no attempt.
        return {"worker_state": state, "worker_observation": result.observation.value,
                "worker_evaluation_ns": elapsed, "worker_python_outbound_attempts": 0}
    finally:
        detector.close()


def main():
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
    sys.addaudithook(reject_outbound)
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
