"""Synthetic local CPU microbenchmark, not deployment or accuracy acceptance."""

import argparse
import json
import platform
import statistics
import time
from uuid import UUID

from .contracts import GrayFrame
from .motion import MotionBaseline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--width", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--frames", type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.width * args.height <= 1048576 or min(args.width, args.height) < 1:
        parser.error("synthetic workload must contain 1 to 1048576 pixels per frame")
    if not 2 <= args.frames <= 10000:
        parser.error("synthetic workload must contain 2 to 10000 frames")
    detector = MotionBaseline(pixel_delta=20, changed_fraction=0.25)
    samples = []
    source_id, stream_id = UUID(int=1), UUID(int=2)
    # Numerical values are fixed synthetic stimulus/benchmark settings only.
    pixels = (bytes([0]) * (args.width * args.height),
              bytes([255]) * (args.width * args.height))
    for sequence in range(args.frames):
        frame = GrayFrame(source_id, stream_id, sequence, args.width, args.height, pixels[sequence % 2])
        start = time.perf_counter_ns()
        detector.evaluate(frame)
        elapsed = time.perf_counter_ns() - start
        if sequence:
            samples.append(elapsed)
    print(json.dumps({
        "workload": "generated alternating uniform grayscale; motion only",
        "deployment_acceptance": False,
        "python": platform.python_version(),
        "implementation": detector.implementation,
        "version": detector.version,
        "width": args.width, "height": args.height,
        "measured_frames": len(samples),
        "median_evaluation_ns": int(statistics.median(samples)),
        "maximum_evaluation_ns": max(samples),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
