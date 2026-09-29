"""Detector deployment schema: explicit values only, fail-closed when unset."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from app.deployment import Deployment
from app.detection.foundation import DetectorKind, GrayFrame, Observation, Quality, Reason
from app.detection.foundation.config import (build_inference, create_motion,
                                             parse_detection)
from app.detection.foundation.person import MODEL_REVISION, MODEL_SHA256
from app.settings import ConfigurationError

SOURCES = [str(UUID(int=index)) for index in range(1, 6)]
ARTIFACT = "/srv/operator-private/model.onnx"
# Test-only values, not deployment defaults.
CADENCE = {"cadence_ns": 200_000_000, "maximum_cadence_ns": 1_600_000_000,
           "maximum_queue_age_ns": 400_000_000, "maximum_evaluation_ns": 300_000_000,
           "maximum_observation_age_ns": 2_000_000_000, "maximum_pixels": 409_600}
WORKER = {"evaluation_timeout_ns": 1_000_000_000, "start_timeout_ns": 30_000_000_000,
          "restart_backoff_ns": 5_000_000_000, "maximum_consecutive_failures": 5,
          "address_space_bytes": 4 << 30, "open_files": 64}
MOTION = {"kind": "motion", "implementation": "server-sentinel-gray-difference",
          "version": "1", "pixel_delta": 12, "changed_fraction": 0.02}
PERSON = {"kind": "person", "implementation": "rtdetr-v2-r18vd-onnx-cpu",
          "version": MODEL_REVISION, "artifact": ARTIFACT, "artifact_sha256": MODEL_SHA256,
          "score_threshold": 0.5, "intra_op_threads": 2}


def binding(source=SOURCES[0], detector=MOTION, **changes):
    value = {"source_id": source, "detector": dict(detector), "cadence": dict(CADENCE),
             "worker": dict(WORKER)}
    value.update(changes)
    return value


def configuration(*bindings):
    return {"bindings": list(bindings) or [binding()]}


class DetectionConfigurationTests(unittest.TestCase):
    def test_explicit_motion_and_person_bindings_parse(self):
        parsed = parse_detection(configuration(
            binding(), binding(detector=PERSON), binding(SOURCES[1], PERSON)))
        self.assertEqual((DetectorKind.MOTION, DetectorKind.PERSON), parsed.kinds())
        motion, person = parsed.bindings[:2]
        self.assertEqual(200_000_000, motion.policy.cadence_ns)
        self.assertEqual(409_600 * 3, motion.limits.maximum_frame_bytes)
        self.assertIs(create_motion, motion.spec.factory)
        self.assertEqual(MODEL_REVISION, person.spec.version)
        self.assertIn(("artifact", ARTIFACT), person.spec.arguments)
        self.assertNotIn(ARTIFACT, repr(parsed))
        self.assertNotIn(ARTIFACT, repr(person))

    def test_every_key_is_required_and_no_extras_are_accepted(self):
        base = configuration()
        paths = [("bindings", 0, section, key)
                 for section, keys in (("cadence", CADENCE), ("worker", WORKER),
                                       ("detector", MOTION)) for key in keys]
        paths += [("bindings", 0, key) for key in ("source_id", "detector", "cadence", "worker")]
        for path in paths:
            with self.subTest(missing=path):
                value = copy.deepcopy(base)
                target = value
                for part in path[:-1]:
                    target = target[part]
                del target[path[-1]]
                with self.assertRaises(ConfigurationError):
                    parse_detection(value)
        for section in ("cadence", "worker", "detector"):
            with self.subTest(extra=section):
                value = copy.deepcopy(base)
                value["bindings"][0][section]["default"] = 1
                with self.assertRaises(ConfigurationError):
                    parse_detection(value)
        for value in ({}, {"bindings": []}, {"bindings": {}}, [], None,
                      {"bindings": [binding()], "enabled": True}):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                parse_detection(value)

    def test_unreviewed_models_and_invalid_values_are_rejected(self):
        invalid = [
            binding(detector=dict(MOTION, implementation="other-motion")),
            binding(detector=dict(MOTION, version="2")),
            binding(detector=dict(MOTION, kind="face")),
            binding(detector=dict(MOTION, pixel_delta=256)),
            binding(detector=dict(MOTION, pixel_delta=True)),
            binding(detector=dict(MOTION, changed_fraction=0)),
            binding(detector=dict(MOTION, changed_fraction=float("nan"))),
            binding(detector=dict(PERSON, artifact_sha256="0" * 64)),
            binding(detector=dict(PERSON, version="main")),
            binding(detector=dict(PERSON, implementation="yolox")),
            binding(detector=dict(PERSON, artifact="relative/model.onnx")),
            binding(detector=dict(PERSON, score_threshold=1)),
            binding(detector=dict(PERSON, intra_op_threads=65)),
            binding(source="not-a-uuid"),
            binding(source=str(UUID(int=0xABC)).upper()),
            binding(cadence=dict(CADENCE, cadence_ns=0)),
            binding(cadence=dict(CADENCE, maximum_cadence_ns=1)),
            binding(cadence=dict(CADENCE, cadence_ns=1.5)),
            binding(worker=dict(WORKER, open_files=2)),
            binding(worker=dict(WORKER, evaluation_timeout_ns=1)),
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ConfigurationError) as caught:
                    parse_detection(configuration(value))
                self.assertNotIn(ARTIFACT, str(caught.exception))
                self.assertNotIn("relative", str(caught.exception))

    def test_source_limits_and_duplicates(self):
        with self.assertRaises(ConfigurationError):
            parse_detection(configuration(binding(), binding()))
        with self.assertRaises(ConfigurationError):
            parse_detection(configuration(*(binding(source) for source in SOURCES)))
        parsed = parse_detection(configuration(*(binding(source) for source in SOURCES[:4])))
        self.assertEqual(4, len(parsed.bindings))

    def test_inference_refuses_to_start_without_configuration(self):
        for value in (None, object()):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                build_inference(value)

    def test_build_registers_unstarted_isolated_workers(self):
        runtime = build_inference(parse_detection(configuration(
            binding(), binding(detector=PERSON), binding(SOURCES[1]))))
        self.addCleanup(runtime.close)
        self.assertEqual({DetectorKind.MOTION, DetectorKind.PERSON}, set(runtime.schedulers))
        self.assertEqual(3, len(runtime.detectors))
        source = UUID(SOURCES[0])
        snapshot = runtime.schedulers[DetectorKind.PERSON].snapshot(source)
        self.assertEqual((Observation.UNKNOWN, Reason.NOT_STARTED),
                         (snapshot.result.observation, snapshot.result.reason))
        detector = runtime.detectors[(DetectorKind.PERSON, source)]
        self.assertEqual("stopped", detector.status().state)
        self.assertTrue(runtime.close())

    def test_maintain_invalidates_published_result_after_idle_worker_crash(self):
        clock = Clock()
        runtime = build_inference(parse_detection(configuration()), clock_ns=clock)
        self.addCleanup(runtime.close)
        key = (DetectorKind.MOTION, UUID(SOURCES[0]))
        self.assertEqual("running", runtime.maintain()[key].state)
        scheduler = runtime.schedulers[DetectorKind.MOTION]
        for sequence in range(2):
            clock.value += CADENCE["cadence_ns"]
            self.assertTrue(scheduler.offer(
                GrayFrame(key[1], UUID(int=77), sequence, 2, 2, bytes(4)),
                quality=Quality.SUFFICIENT))
            snapshot = scheduler.run_one()
        self.assertEqual(Observation.ABSENT, snapshot.result.observation)
        process = runtime.detectors[key]._process
        process.kill()
        process.join(5)
        status = runtime.maintain()[key]
        self.assertEqual(("backoff", 1), (status.state, status.crashes))
        self.assertEqual(Reason.WORKER_CRASHED, scheduler.snapshot(key[1]).result.reason)
        clock.value += WORKER["restart_backoff_ns"]
        self.assertEqual("running", runtime.maintain()[key].state)
        # Restarting does not resurrect the old conclusion.
        self.assertEqual(Observation.UNKNOWN, scheduler.snapshot(key[1]).result.observation)


class Clock:
    value = 0

    def __call__(self):
        return self.value


class DeploymentDetectionTests(unittest.TestCase):
    def test_deployment_accepts_optional_detection_and_rejects_invalid(self):
        with tempfile.TemporaryDirectory(prefix="server-detection-synthetic-") as directory:
            root = Path(directory)
            runtime = root / "runtime"
            for path in (runtime, runtime / "state", runtime / "recordings", runtime / "audit"):
                path.mkdir(mode=0o700)
            (root / "code").mkdir()
            device = runtime.stat().st_dev
            base = {
                "runtime_root": str(runtime), "runtime_mount_point": str(root),
                "runtime_device": [os.major(device), os.minor(device)],
                "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444",
                "service_uid": os.geteuid(),
                "human_host": "127.0.0.1", "human_port": 8000, "log_level": "INFO",
            }
            config = root / "deployment.json"

            def load(value):
                config.write_text(json.dumps(value))
                config.chmod(0o600)
                with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid()), patch(
                        "app.deployment._approved_filesystem_device", return_value=device), patch(
                        "app.deployment.os.path.ismount", return_value=True), patch(
                        "app.deployment._administrator_directory"), patch(
                        "app.deployment._operating_system_root_device",
                        return_value=device + 1):
                    return Deployment.load(config, code_root=root / "code")

            self.assertIsNone(load(base).detection)
            deployment = load(dict(base, detection=configuration(binding(detector=PERSON))))
            self.assertEqual(1, len(deployment.detection.bindings))
            self.assertNotIn(ARTIFACT, repr(deployment))
            with self.assertRaises(ConfigurationError):
                load(dict(base, detection={"bindings": []}))
            with self.assertRaises(ConfigurationError):
                load(dict(base, detection=configuration(
                    binding(detector=dict(MOTION, pixel_delta=None)))))


if __name__ == "__main__":
    unittest.main()
