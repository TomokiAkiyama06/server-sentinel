"""Local RT-DETRv2 CPU benchmark with synthetic pixels and scheduler replay.

This operator-run harness never downloads a model or media.  It measures the
already reviewed local adapter, then replays those timings through the bounded
inference scheduler.  Its output is evidence for a deployment decision, not a
deployment default or an accuracy result.
"""

import argparse
from collections import Counter
from dataclasses import dataclass
import json
import math
from pathlib import Path
import platform
import time
from typing import Callable
from uuid import UUID

from .contracts import (Detection, Detector, DetectorKind, Quality, RgbFrame,
                        positive_integer)
from .person import MODEL_INPUT_SIZE, MODEL_SHA256, RtDetrPersonDetector
from .scheduler import InferenceScheduler, SourcePolicy, SourceSnapshot

_MAX_CYCLES = 10_000
_PIXELS = bytes(MODEL_INPUT_SIZE * MODEL_INPUT_SIZE * 3)


@dataclass(frozen=True)
class BenchmarkConfig:
    artifact: Path
    score_threshold: float
    intra_op_threads: int
    sources: int
    warmup_cycles: int
    measured_cycles: int
    capture_interval_ns: int
    cadence_ns: int
    maximum_cadence_ns: int
    evaluation_budget_ns: int
    maximum_queue_age_ns: int
    maximum_observation_age_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, Path):
            raise ValueError("artifact must be a path")
        if (isinstance(self.score_threshold, bool)
                or not isinstance(self.score_threshold, (int, float))
                or not math.isfinite(self.score_threshold)
                or not 0 < self.score_threshold < 1):
            raise ValueError("score threshold must be a finite fraction in (0,1)")
        positive_integer(self.intra_op_threads, "intra_op_threads")
        if self.intra_op_threads > 64:
            raise ValueError("intra_op_threads exceeds the adapter ceiling")
        if type(self.sources) is not int or not 1 <= self.sources <= 4:
            raise ValueError("sources must be between one and four")
        if (type(self.warmup_cycles) is not int or self.warmup_cycles < 0
                or self.warmup_cycles > _MAX_CYCLES):
            raise ValueError("warmup_cycles must be between zero and 10000")
        positive_integer(self.measured_cycles, "measured_cycles")
        if self.measured_cycles > _MAX_CYCLES:
            raise ValueError("measured_cycles exceeds 10000")
        for name in ("capture_interval_ns", "cadence_ns", "maximum_cadence_ns",
                     "evaluation_budget_ns", "maximum_queue_age_ns",
                     "maximum_observation_age_ns"):
            positive_integer(getattr(self, name), name)
        if self.maximum_cadence_ns < self.cadence_ns:
            raise ValueError("maximum cadence must allow configured cadence")


@dataclass(frozen=True)
class _Measurement:
    latency_ns: int
    result: Detection


class _SimulationClock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value

    def advance_to(self, value: int) -> None:
        if value > self.value:
            self.value = value

    def advance(self, duration: int) -> None:
        self.value += duration


class _ReplayDetector:
    kind = DetectorKind.PERSON

    def __init__(self, measurements: list[_Measurement], clock: _SimulationClock,
                 *, implementation: str, version: str) -> None:
        if not measurements:
            raise ValueError("replay requires measured inference results")
        self.implementation = implementation
        self.version = version
        self._measurements = measurements
        self._clock = clock
        self._position = 0

    def reset(self) -> None:
        pass

    def evaluate(self, frame: RgbFrame) -> Detection:
        measurement = self._measurements[self._position % len(self._measurements)]
        self._position += 1
        self._clock.advance(measurement.latency_ns)
        return measurement.result


def _nearest_rank(values: list[int], percentile: int) -> int:
    """Return the nearest-rank percentile: sorted[ceil(p/100*n)-1]."""
    if not values:
        raise ValueError("latency summary requires at least one sample")
    if type(percentile) is not int or not 1 <= percentile <= 100:
        raise ValueError("percentile must be between one and 100")
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered) / 100) - 1]


def _latency_summary(measurements: list[_Measurement]) -> dict[str, int]:
    values = [item.latency_ns for item in measurements]
    return {
        "samples": len(values),
        "p50": _nearest_rank(values, 50),
        "p95": _nearest_rank(values, 95),
        "max": max(values),
    }


def _outcomes(measurements: list[_Measurement]) -> dict[str, int]:
    counts = Counter(
        f"{item.result.observation.value}/{item.result.reason.value}"
        for item in measurements
    )
    return dict(sorted(counts.items()))


def _frame(source_index: int, sequence: int) -> RgbFrame:
    return RgbFrame(UUID(int=source_index + 1), UUID(int=source_index + 101),
                    sequence, MODEL_INPUT_SIZE, MODEL_INPUT_SIZE, _PIXELS)


def _measure(config: BenchmarkConfig, detectors: list[Detector],
             timer_ns: Callable[[], int]) -> list[list[_Measurement]]:
    measurements: list[list[_Measurement]] = [[] for _ in detectors]
    for detector in detectors:
        detector.reset()
    for cycle in range(config.warmup_cycles):
        for source_index, detector in enumerate(detectors):
            result = detector.evaluate(_frame(source_index, cycle))
            if not isinstance(result, Detection):
                raise ValueError("detector returned an invalid result")
    for cycle in range(config.measured_cycles):
        sequence = config.warmup_cycles + cycle
        for source_index, detector in enumerate(detectors):
            started = timer_ns()
            result = detector.evaluate(_frame(source_index, sequence))
            finished = timer_ns()
            if not isinstance(result, Detection):
                raise ValueError("detector returned an invalid result")
            if type(started) is not int or type(finished) is not int or finished < started:
                raise ValueError("timer must return monotonic integer nanoseconds")
            measurements[source_index].append(_Measurement(finished - started, result))
    return measurements


def _replay(config: BenchmarkConfig, measurements: list[list[_Measurement]],
            implementation: str, version: str) -> list[SourceSnapshot]:
    clock = _SimulationClock()
    scheduler = InferenceScheduler(clock_ns=clock, maximum_sources=config.sources)
    policy = SourcePolicy(
        cadence_ns=config.cadence_ns,
        maximum_cadence_ns=config.maximum_cadence_ns,
        maximum_queue_age_ns=config.maximum_queue_age_ns,
        maximum_evaluation_ns=config.evaluation_budget_ns,
        maximum_observation_age_ns=config.maximum_observation_age_ns,
        maximum_pixels=MODEL_INPUT_SIZE * MODEL_INPUT_SIZE,
    )
    for source_index, source_measurements in enumerate(measurements):
        scheduler.register(
            UUID(int=source_index + 1),
            _ReplayDetector(source_measurements, clock,
                            implementation=implementation, version=version),
            policy,
        )

    capture_tick = 0
    # Inference is serial. If one evaluation crosses several capture ticks, all
    # those capture admissions are delivered before the next worker selection.
    while capture_tick < config.measured_cycles:
        clock.advance_to(capture_tick * config.capture_interval_ns)
        while (capture_tick < config.measured_cycles
               and capture_tick * config.capture_interval_ns <= clock.value):
            for source_index in range(config.sources):
                scheduler.offer(_frame(source_index, capture_tick), quality=Quality.SUFFICIENT)
            capture_tick += 1
        scheduler.run_one()

    # Drain work that is runnable now. Work delayed by a throttled cadence stays
    # pending and is reported as such instead of advancing simulated time.
    while scheduler.run_one() is not None:
        pass
    return [scheduler.snapshot(UUID(int=index + 1)) for index in range(config.sources)]


def run_benchmark(config: BenchmarkConfig, *,
                  detector_factory: Callable[[int], Detector] | None = None,
                  timer_ns: Callable[[], int] = time.perf_counter_ns) -> dict[str, object]:
    if detector_factory is None:
        def detector_factory(_index: int) -> Detector:
            return RtDetrPersonDetector(
                config.artifact,
                score_threshold=config.score_threshold,
                intra_op_threads=config.intra_op_threads,
            )
    detectors = [detector_factory(index) for index in range(config.sources)]
    first = detectors[0]
    if (first.kind is not DetectorKind.PERSON
            or not isinstance(first.implementation, str) or not first.implementation
            or not isinstance(first.version, str) or not first.version
            or any(item.kind is not DetectorKind.PERSON
                   or item.implementation != first.implementation
                   or item.version != first.version for item in detectors)):
        raise ValueError("benchmark requires one consistent person adapter per source")

    measurements = _measure(config, detectors, timer_ns)
    snapshots = _replay(config, measurements, first.implementation, first.version)
    aggregate = [item for source in measurements for item in source]
    sources = []
    for index, (source_measurements, snapshot) in enumerate(zip(measurements, snapshots)):
        sources.append({
            "source_index": index + 1,
            "latency_ns": _latency_summary(source_measurements),
            "outcomes": _outcomes(source_measurements),
            "scheduler": {
                "health": snapshot.health.value,
                "reason": snapshot.result.reason.value,
                "active_cadence_ns": snapshot.cadence_ns,
                "processed": snapshot.processed,
                "dropped": snapshot.dropped,
                "sampled_out": snapshot.sampled_out,
                "pending": snapshot.pending,
            },
        })
    return {
        "schema_version": 1,
        "deployment_acceptance": False,
        "workload": "generated uniform 640x640 RGB; repeated local CPU inference",
        "adapter": {
            "implementation": first.implementation,
            "version": first.version,
            "artifact_sha256": MODEL_SHA256,
            "execution_provider": "CPUExecutionProvider",
        },
        "host": {
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "config": {
            "score_threshold": config.score_threshold,
            "intra_op_threads": config.intra_op_threads,
            "sources": config.sources,
            "warmup_cycles": config.warmup_cycles,
            "measured_cycles": config.measured_cycles,
            "capture_interval_ns": config.capture_interval_ns,
            "cadence_ns": config.cadence_ns,
            "maximum_cadence_ns": config.maximum_cadence_ns,
            "evaluation_budget_ns": config.evaluation_budget_ns,
            "maximum_queue_age_ns": config.maximum_queue_age_ns,
            "maximum_observation_age_ns": config.maximum_observation_age_ns,
        },
        "latency_ns": _latency_summary(aggregate),
        "sources": sources,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--score-threshold", type=float, required=True)
    parser.add_argument("--intra-op-threads", type=int, required=True)
    parser.add_argument("--sources", type=int, required=True)
    parser.add_argument("--warmup-cycles", type=int, required=True)
    parser.add_argument("--measured-cycles", type=int, required=True)
    parser.add_argument("--capture-interval-ns", type=int, required=True)
    parser.add_argument("--cadence-ns", type=int, required=True)
    parser.add_argument("--maximum-cadence-ns", type=int, required=True)
    parser.add_argument("--evaluation-budget-ns", type=int, required=True)
    parser.add_argument("--maximum-queue-age-ns", type=int, required=True)
    parser.add_argument("--maximum-observation-age-ns", type=int, required=True)
    return parser


def main() -> None:
    parser = _parser()
    try:
        config = BenchmarkConfig(**vars(parser.parse_args()))
        result = run_benchmark(config)
    except (RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
