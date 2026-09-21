"""Synthetic tests for the operator-run RT-DETRv2 benchmark harness."""

from dataclasses import replace
import json
from pathlib import Path
import unittest

from app.detection.foundation import Detection, DetectorKind, Observation, Reason
from app.detection.foundation.person_benchmark import (
    BenchmarkConfig, _nearest_rank, run_benchmark,
)


class StubDetector:
    kind = DetectorKind.PERSON
    implementation = "rtdetr-v2-synthetic-test-double"
    version = "test-revision"

    def __init__(self) -> None:
        self.resets = 0
        self.evaluations = 0

    def reset(self) -> None:
        self.resets += 1

    def evaluate(self, _frame):
        self.evaluations += 1
        return Detection(Observation.ABSENT, Reason.EVALUATED, 0.25)


class Timer:
    def __init__(self, latencies):
        self.values = []
        now = 0
        for latency in latencies:
            self.values.extend((now, now + latency))
            now += latency
        self.position = 0

    def __call__(self):
        value = self.values[self.position]
        self.position += 1
        return value


def config(**changes):
    base = BenchmarkConfig(
        artifact=Path("/private/operator/model.onnx"),
        score_threshold=0.75,
        intra_op_threads=1,
        sources=1,
        warmup_cycles=1,
        measured_cycles=3,
        capture_interval_ns=100,
        cadence_ns=100,
        maximum_cadence_ns=800,
        evaluation_budget_ns=50,
        maximum_queue_age_ns=10_000,
        maximum_observation_age_ns=10_000,
    )
    return replace(base, **changes)


class PersonBenchmarkTests(unittest.TestCase):
    def test_nearest_rank_is_defined_for_small_samples(self):
        self.assertEqual(_nearest_rank([7], 50), 7)
        self.assertEqual(_nearest_rank([40, 10, 30, 20], 50), 20)
        self.assertEqual(_nearest_rank([40, 10, 30, 20], 95), 40)
        with self.assertRaises(ValueError):
            _nearest_rank([], 50)

    def test_one_source_schema_and_measurement_boundaries(self):
        detectors = []

        def factory(_index):
            detector = StubDetector()
            detectors.append(detector)
            return detector

        result = run_benchmark(
            config(evaluation_budget_ns=1_000),
            detector_factory=factory,
            timer_ns=Timer([10, 20, 30]),
        )
        self.assertEqual(result["schema_version"], 1)
        self.assertFalse(result["deployment_acceptance"])
        self.assertEqual(result["latency_ns"], {"samples": 3, "p50": 20, "p95": 30, "max": 30})
        self.assertEqual(result["sources"][0]["latency_ns"], result["latency_ns"])
        self.assertEqual(result["sources"][0]["outcomes"], {"absent/evaluated": 3})
        self.assertEqual(detectors[0].resets, 1)
        self.assertEqual(detectors[0].evaluations, 4)
        encoded = json.dumps(result)
        self.assertNotIn("/private/operator", encoded)
        self.assertNotIn("pixels", encoded)

    def test_four_source_replay_exposes_drops_and_budget_throttling(self):
        result = run_benchmark(
            config(sources=4, warmup_cycles=0, measured_cycles=4,
                   capture_interval_ns=5, cadence_ns=5,
                   maximum_cadence_ns=40, evaluation_budget_ns=10),
            detector_factory=lambda _index: StubDetector(),
            timer_ns=Timer([20] * 16),
        )
        self.assertEqual(result["latency_ns"], {"samples": 16, "p50": 20, "p95": 20, "max": 20})
        self.assertEqual(len(result["sources"]), 4)
        schedulers = [source["scheduler"] for source in result["sources"]]
        self.assertTrue(any(item["dropped"] for item in schedulers))
        self.assertTrue(all(item["active_cadence_ns"] > 5 for item in schedulers))
        self.assertTrue(all(item["health"] == "unavailable" for item in schedulers))
        self.assertTrue(all(item["reason"] in {"inference_dropped", "inference_over_budget"}
                            for item in schedulers))

    def test_invalid_source_count_cycles_and_policy_are_rejected(self):
        for changes in (
            {"sources": 0}, {"sources": 5}, {"measured_cycles": 0},
            {"warmup_cycles": -1}, {"score_threshold": float("nan")},
            {"maximum_cadence_ns": 99},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                config(**changes)

    def test_non_monotonic_timer_and_inconsistent_adapter_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "timer"):
            run_benchmark(config(measured_cycles=1),
                          detector_factory=lambda _index: StubDetector(),
                          timer_ns=Timer([-1]))

        class OtherDetector(StubDetector):
            version = "other"

        with self.assertRaisesRegex(ValueError, "consistent person adapter"):
            run_benchmark(config(sources=2, measured_cycles=1),
                          detector_factory=lambda index: StubDetector() if index == 0 else OtherDetector(),
                          timer_ns=Timer([1, 1]))


if __name__ == "__main__":
    unittest.main()
