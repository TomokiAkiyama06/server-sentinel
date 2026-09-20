"""Explicit local-artifact synthetic check; not run with weights in CI."""

import argparse
import json
from pathlib import Path
import sys
import time
from uuid import UUID


def reject_outbound(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto",
                 "subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError("unexpected outbound/process attempt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    sys.addaudithook(reject_outbound)
    from app.detection.foundation import GrayFrame, Observation, RgbFrame
    from app.detection.foundation.person import RtDetrPersonDetector
    import onnxruntime
    started = time.perf_counter_ns()
    # Explicit test-only evaluation settings, never deployment defaults.
    detector = RtDetrPersonDetector(args.artifact, score_threshold=0.5, intra_op_threads=1)
    loaded = time.perf_counter_ns()
    pixels = bytes([0, 128, 255]) * (640 * 640)
    frame = RgbFrame(UUID(int=1), UUID(int=2), 0, 640, 640, pixels)
    result = detector.evaluate(frame)
    evaluated = time.perf_counter_ns()
    assert result.observation is not Observation.UNKNOWN, result.reason
    invalid = GrayFrame(UUID(int=1), UUID(int=2), 1, 1, 1, bytes([0]))
    assert detector.evaluate(invalid).observation is Observation.UNKNOWN
    print(json.dumps({
        "workload": "generated uniform RGB only; not person accuracy acceptance",
        "runtime": onnxruntime.__version__,
        "build": onnxruntime.get_build_info(),
        "available_providers": onnxruntime.get_available_providers(),
        "enabled_providers": detector._session.get_providers(),
        "load_ns": loaded - started,
        "evaluation_ns": evaluated - loaded,
        "synthetic_observation": result.observation.value,
        "synthetic_score": result.measurement,
        "malformed_frame": "unknown",
        "python_outbound_attempts": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
