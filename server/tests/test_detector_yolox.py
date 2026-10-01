"""YOLOX evaluation adapter: generated arrays/graphs only; no weights in CI."""

import hashlib
import importlib.metadata
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from uuid import UUID

import numpy as np

from app.detection.foundation import (Detection, DetectorKind, GrayFrame,
                                     IsolatedDetector, Observation, Reason,
                                     RgbFrame, WorkerLimits, WorkerSpec)
from app.detection.foundation import person, yolox
from app.detection.foundation.config import parse_detection
from app.settings import ConfigurationError

try:
    from . import detector_model_smoke, detector_worker_fakes, generated_onnx
except ImportError:  # discovered as a top-level module
    import detector_model_smoke
    import detector_worker_fakes
    import generated_onnx

SOURCE = UUID(int=1)
STREAM = UUID(int=2)


def rgb(width, height, pixel=(0, 128, 255), sequence=0):
    return RgbFrame(SOURCE, STREAM, sequence, width, height, bytes(pixel) * (width * height))


def reviewed_runtime():
    try:
        return (platform.system() == "Linux" and platform.machine() == "x86_64"
                and sys.version_info[:2] == (3, 12)
                and importlib.metadata.version("onnxruntime") == person.RUNTIME_VERSION
                and importlib.metadata.version("numpy") == person.NUMPY_VERSION)
    except importlib.metadata.PackageNotFoundError:
        return False


class YoloxSessionDoubleTests(unittest.TestCase):
    """Adapter contract with an ONNX session double (like the RT-DETRv2 tests)."""

    def setUp(self):
        self.pinned = yolox.ARTIFACTS["yolox-s"]
        self.session = MagicMock()
        self.session.get_providers.return_value = ["CPUExecutionProvider"]
        self.session.get_inputs.return_value = [SimpleNamespace(
            name="images", type="tensor(float)", shape=[1, 3, 640, 640])]
        self.session.get_outputs.return_value = [SimpleNamespace(name="output")]
        self.output = np.zeros((1, self.pinned.anchors, 85), dtype=np.float32)
        self.session.run.return_value = (self.output,)

    def detector(self, cls=yolox.YoloxSPersonDetector):
        with patch.object(yolox, "_read_pinned_artifact", return_value=b"synthetic") as read, \
             patch.object(yolox, "require_reviewed_runtime"), \
             patch("onnxruntime.InferenceSession", return_value=self.session) as create:
            detector = cls(Path("/unused"), score_threshold=0.5, intra_op_threads=1)
            pinned = yolox.ARTIFACTS[cls.variant]
            self.assertEqual(read.call_args.args[1:], (pinned.size, pinned.sha256))
            self.assertEqual(create.call_args.kwargs["providers"], ["CPUExecutionProvider"])
            self.assertFalse(create.call_args.kwargs["enable_fallback"])
            self.session.disable_fallback.assert_called_once()
            return detector

    def test_pins_are_exact_and_distinct(self):
        self.assertEqual(yolox.ARTIFACTS["yolox-s"].anchors, 8400)
        self.assertEqual(yolox.ARTIFACTS["yolox-tiny"].anchors, 3549)
        self.assertEqual(
            {name: adapter.variant for name, adapter in yolox.ADAPTERS.items()},
            {"yolox-s-onnx-cpu": "yolox-s", "yolox-tiny-onnx-cpu": "yolox-tiny"})
        for adapter in yolox.ADAPTERS.values():
            self.assertIs(adapter.kind, DetectorKind.PERSON)
            self.assertEqual(adapter.version, "0.1.1rc0")

    def test_bgr_unnormalized_letterbox_and_no_person(self):
        detector = self.detector()
        result = detector.evaluate(rgb(640, 360))
        self.assertEqual(result, Detection(Observation.ABSENT, Reason.EVALUATED, 0.0))
        values = self.session.run.call_args.args[1]["images"]
        self.assertEqual(values.shape, (1, 3, 640, 640))
        self.assertEqual(values.dtype, np.float32)
        # RGB (0,128,255) arrives as BGR, un-normalized, top-left aligned.
        np.testing.assert_array_equal(values[0, :, 0, 0], [255, 128, 0])
        np.testing.assert_array_equal(values[0, :, 359, 639], [255, 128, 0])
        np.testing.assert_array_equal(values[0, :, 360, 0], [114, 114, 114])
        portrait = detector.evaluate(rgb(200, 640))
        self.assertEqual(portrait.observation, Observation.ABSENT)
        values = self.session.run.call_args.args[1]["images"]
        np.testing.assert_array_equal(values[0, :, 639, 200], [114, 114, 114])

    def test_person_score_is_objectness_times_class_zero_only(self):
        detector = self.detector()
        self.output[0, 10, 4] = 0.9
        self.output[0, 10, 5] = 0.8
        self.output[0, 11, 4] = 1.0
        self.output[0, 11, 6] = 1.0  # another class is never a person
        result = detector.evaluate(rgb(640, 640))
        self.assertEqual(result.observation, Observation.PRESENT)
        self.assertAlmostEqual(result.measurement, 0.72, places=6)
        self.output[0, 10, 5] = 0.5
        self.assertEqual(detector.evaluate(rgb(640, 640)).observation, Observation.ABSENT)

    def test_wrong_size_or_grayscale_is_unknown_without_execution(self):
        detector = self.detector()
        for frame in (rgb(639, 360), rgb(641, 360), rgb(416, 416),
                      GrayFrame(SOURCE, STREAM, 0, 640, 640, bytes(640 * 640))):
            with self.subTest(size=(frame.width, frame.height, frame.channels)):
                self.assertEqual(detector.evaluate(frame),
                                 Detection(Observation.UNKNOWN, Reason.QUALITY))
        self.session.run.assert_not_called()

    def test_invalid_outputs_and_exceptions_are_unknown_never_absent(self):
        detector = self.detector()
        cases = []
        nan = self.output.copy()
        nan[0, 0, 0] = np.nan
        cases.append(nan)
        above = self.output.copy()
        above[0, 0, 4] = 1.5
        cases.append(above)
        below = self.output.copy()
        below[0, 0, 5] = -0.1
        cases.append(below)
        # Non-person class columns are sigmoid scores too.
        for column, value in ((6, 1.5), (84, -0.1), (40, np.inf)):
            other = self.output.copy()
            other[0, 7, column] = value
            cases.append(other)
        cases.append(np.zeros((1, 3549, 85), dtype=np.float32))
        for output in cases:
            self.session.run.return_value = (output,)
            self.assertEqual(detector.evaluate(rgb(640, 640)),
                             Detection(Observation.UNKNOWN, Reason.FAILURE))
        self.session.run.side_effect = RuntimeError("/private/path must not appear")
        result = detector.evaluate(rgb(640, 640))
        self.assertEqual(result, Detection(Observation.UNKNOWN, Reason.FAILURE))
        self.assertNotIn("private", repr(result))

    def test_interface_or_provider_mismatch_is_unavailable(self):
        for change in (
            lambda: setattr(self.session.get_inputs.return_value[0], "shape", [1, 3, 416, 416]),
            lambda: setattr(self.session.get_inputs.return_value[0], "name", "pixel_values"),
            lambda: self.session.get_outputs.return_value.append(SimpleNamespace(name="x")),
            lambda: self.session.get_providers.configure_mock(return_value=["CUDAExecutionProvider"]),
        ):
            self.setUp()
            change()
            with self.assertRaisesRegex(person.ModelUnavailable,
                                        "^approved local person detector is unavailable$"):
                self.detector()

    def test_tiny_variant_uses_its_own_pin_and_input(self):
        self.session.get_inputs.return_value[0].shape = [1, 3, 416, 416]
        self.session.run.return_value = (np.zeros((1, 3549, 85), dtype=np.float32),)
        detector = self.detector(yolox.YoloxTinyPersonDetector)
        self.assertEqual(detector.evaluate(rgb(416, 234)).observation, Observation.ABSENT)
        self.assertEqual(detector.evaluate(rgb(640, 640)).reason, Reason.QUALITY)

    def test_runtime_platform_and_artifact_failures_are_fixed_unavailable(self):
        with patch("platform.system", return_value="Windows"), \
             patch.object(yolox, "_read_pinned_artifact") as read:
            with self.assertRaises(person.ModelUnavailable):
                yolox.YoloxSPersonDetector(Path("/unused"), score_threshold=0.5,
                                           intra_op_threads=1)
            read.assert_not_called()
        with patch.object(yolox, "require_reviewed_runtime"):
            with self.assertRaisesRegex(person.ModelUnavailable, "^approved local"):
                yolox.YoloxSPersonDetector(Path("/missing-private-artifact"),
                                           score_threshold=0.5, intra_op_threads=1)
        with self.assertRaises(person.ModelUnavailable):
            yolox.create_yolox_person("unreviewed", "/x", 0.5, 1)
        for threshold in (0, 1, float("nan"), True):
            with self.assertRaises(ValueError):
                yolox.YoloxSPersonDetector(Path("/unused"), score_threshold=threshold,
                                           intra_op_threads=1)

    def test_wrong_digest_and_symlink_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "model.onnx"
            content = b"synthetic artifact only"
            artifact.write_bytes(content)
            link = Path(directory) / "link.onnx"
            link.symlink_to(artifact)
            digest = hashlib.sha256(content).hexdigest()
            self.assertEqual(person._read_pinned_artifact(artifact, len(content), digest), content)
            for path, size, sha in ((link, len(content), digest),
                                    (artifact, len(content), "0" * 64),
                                    (artifact, len(content) + 1, digest)):
                with self.assertRaises(person.ModelUnavailable):
                    person._read_pinned_artifact(path, size, sha)

    def test_deployment_schema_rejects_evaluation_only_yolox(self):
        detector = {"kind": "person", "implementation": "yolox-s-onnx-cpu",
                    "version": "0.1.1rc0", "artifact": "/srv/operator/model.onnx",
                    "artifact_sha256": yolox.ARTIFACTS["yolox-s"].sha256,
                    "score_threshold": 0.5, "intra_op_threads": 1}
        cadence = {"cadence_ns": 1, "maximum_cadence_ns": 2, "maximum_queue_age_ns": 1,
                   "maximum_evaluation_ns": 1, "maximum_observation_age_ns": 1,
                   "maximum_pixels": 409_600}
        worker = {"evaluation_timeout_ns": 1, "start_timeout_ns": 1, "restart_backoff_ns": 1,
                  "maximum_consecutive_failures": 1, "address_space_bytes": 1 << 30,
                  "open_files": 64}
        with self.assertRaises(ConfigurationError):
            parse_detection({"bindings": [{"source_id": str(SOURCE), "detector": detector,
                                           "cadence": cadence, "worker": worker}]})

    def test_normal_and_failure_paths_do_not_attempt_python_network(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")) as network:
            detector = self.detector()
            detector.evaluate(rgb(640, 640))
            self.session.run.side_effect = RuntimeError("synthetic failure")
            self.assertEqual(detector.evaluate(rgb(640, 640)).observation, Observation.UNKNOWN)
            network.assert_not_called()


class ModelSmokeWorkerAuditTests(unittest.TestCase):
    """The model smoke's audit hook must run inside the spawned worker."""

    def check(self, factory):
        target = f"{detector_worker_fakes.__name__}:{factory}"
        return detector_model_smoke.isolated_check("yolox-tiny-onnx-cpu", "/unused", 4,
                                                   target=target)

    def test_clean_worker_reports_zero_worker_attempts(self):
        result = self.check("smoke_adapter")
        self.assertEqual(result["worker_state"], "running")
        self.assertEqual(result["worker_observation"], "absent")
        self.assertEqual(result["worker_python_outbound_attempts"], 0)

    def test_swallowed_worker_attempt_at_load_fails_the_smoke(self):
        with self.assertRaises(detector_model_smoke.SmokeFailure):
            self.check("smoke_adapter_outbound_at_start")

    def test_swallowed_worker_attempt_at_evaluation_fails_the_smoke(self):
        with self.assertRaises(detector_model_smoke.SmokeFailure):
            self.check("smoke_adapter_outbound_at_evaluation")

    def test_every_swallowed_dns_entry_point_fails_the_smoke(self):
        # gethostbyname(_ex)/gethostbyaddr/getnameinfo raise their own audit
        # events, not socket.getaddrinfo.
        for lookup in detector_worker_fakes.LOOKUPS:
            with self.subTest(lookup=lookup), \
                    self.assertRaises(detector_model_smoke.SmokeFailure):
                self.check(f"smoke_adapter_{lookup}")

    def test_every_swallowed_datagram_send_fails_the_smoke(self):
        # An unconnected UDP sendmsg raises socket.sendmsg, not socket.sendto.
        for send in detector_worker_fakes.DATAGRAMS:
            with self.subTest(send=send), \
                    self.assertRaises(detector_model_smoke.SmokeFailure):
                self.check(f"smoke_adapter_{send}")

    def test_parent_hook_records_every_dns_and_datagram_entry_point(self):
        # The parent process uses the same event set; checked in a child so
        # this test runner's own process never gains an audit hook.
        tests = Path(__file__).resolve().parent
        program = (
            "import sys\n"
            f"sys.path[:0] = [{str(tests)!r}, {str(tests.parent)!r}]\n"
            "import detector_model_smoke, detector_worker_fakes\n"
            "sys.addaudithook(detector_model_smoke.reject_outbound)\n"
            "for name in detector_worker_fakes.OUTBOUND_CALLS:\n"
            "    before = len(detector_model_smoke._attempts)\n"
            "    detector_worker_fakes._swallowed_lookup(name)\n"
            "    if len(detector_model_smoke._attempts) == before:\n"
            "        print(name); sys.exit(3)\n"
            "sys.exit(0)\n")
        completed = subprocess.run([sys.executable, "-c", program],
                                   cwd=tests.parent, capture_output=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout.decode(errors="replace"))

    def test_parent_hook_audits_yolox_setup_and_permits_only_the_worker_spawn(self):
        # The smoke process installs its hook before any YOLOX import; the
        # worker spawn is observed on every runtime (CPython 3.12 raises no
        # native event for it) and is the only permitted launch.
        tests = Path(__file__).resolve().parent
        program = (
            "import multiprocessing, sys\n"
            f"sys.path[:0] = [{str(tests)!r}, {str(tests.parent)!r}]\n"
            "import detector_model_smoke as smoke\n"
            "install = sys.addaudithook\n"
            "def ordered(hook):\n"
            "    if 'app.detection.foundation.yolox' in sys.modules: sys.exit(4)\n"
            "    install(hook)\n"
            "sys.addaudithook = ordered\n"
            "def stop(*args, **kwargs): raise SystemExit(0)\n"
            "smoke.isolated_check, real_check = stop, smoke.isolated_check\n"
            "sys.argv = ['smoke', '/unused', '--adapter', 'yolox-tiny-onnx-cpu']\n"
            "try:\n"
            "    smoke.main()\n"
            "except SystemExit as stopped:\n"
            "    if stopped.code: raise\n"
            "result = real_check('yolox-tiny-onnx-cpu', '/unused', 4,\n"
            "    target='detector_worker_fakes:smoke_adapter')\n"
            "if smoke._attempts or result['permitted_worker_launches'].count('multiprocessing.spawn') != 1\\\n"
            "        or result['process_launch_observed'] is not True: sys.exit(5)\n"
            "def noop(): pass\n"
            "if __name__ == '__main__':\n"
            "    try:\n"
            "        multiprocessing.get_context('spawn').Process(target=noop).start()\n"
            "    except RuntimeError:\n"
            "        pass\n"
            "    if smoke._attempts != [smoke.LAUNCH_EVENT]: sys.exit(6)\n"
            "    sys.exit(0)\n")
        completed = subprocess.run([sys.executable, "-c", program],
                                   cwd=tests.parent, capture_output=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))

    def test_unhooked_check_reports_launches_as_unobserved(self):
        result = self.check("smoke_adapter")
        self.assertIs(result["process_launch_observed"], False)
        self.assertIsNone(result["permitted_worker_launches"])

    def test_worker_attempt_still_fails_the_smoke_under_python_optimize(self):
        # `python -O` strips `assert`; the failure must not depend on it.
        tests = Path(__file__).resolve().parent
        program = (
            "import sys\n"
            f"sys.path[:0] = [{str(tests)!r}, {str(tests.parent)!r}]\n"
            "import detector_model_smoke\n"
            "try:\n"
            "    detector_model_smoke.isolated_check('yolox-tiny-onnx-cpu', '/unused', 4,\n"
            "        target='detector_worker_fakes:smoke_adapter_outbound_at_evaluation')\n"
            "except detector_model_smoke.SmokeFailure:\n"
            "    sys.exit(0)\n"
            "sys.exit(3)\n")
        completed = subprocess.run([sys.executable, "-O", "-c", program],
                                   cwd=tests.parent, capture_output=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))


@unittest.skipUnless(reviewed_runtime(), "requires the reviewed Linux CPython 3.12 ORT closure")
class YoloxGeneratedGraphTests(unittest.TestCase):
    """Real ONNX Runtime on a generated YOLOX-shaped graph (no learned weights)."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path, self.sha256, self.size = generated_onnx.write_model(Path(directory.name), 416)
        pinned = yolox.ARTIFACTS["yolox-tiny"]
        patcher = patch.dict(yolox.ARTIFACTS, {"yolox-tiny": yolox.YoloxArtifact(
            pinned.variant, self.sha256, self.size, pinned.input_size)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_real_runtime_pixel_path_and_letterbox_padding(self):
        detector = yolox.YoloxTinyPersonDetector(self.path, score_threshold=0.5,
                                                 intra_op_threads=1)
        self.assertEqual(detector._session.get_providers(), ["CPUExecutionProvider"])
        bright = detector.evaluate(rgb(416, 416, (255, 255, 255)))
        self.assertEqual(bright.observation, Observation.PRESENT)
        self.assertAlmostEqual(bright.measurement, 1.0, places=5)
        dark = detector.evaluate(rgb(416, 416, (0, 0, 0)))
        self.assertEqual(dark.observation, Observation.ABSENT)
        # 416x208 of 255 plus 416x208 of pad 114 has mean 184.5.
        padded = detector.evaluate(rgb(416, 208, (255, 255, 255)))
        self.assertAlmostEqual(padded.measurement, 184.5 / 255, places=5)
        self.assertEqual(detector.evaluate(rgb(415, 208)).reason, Reason.QUALITY)

    def test_changed_generated_artifact_is_unavailable(self):
        self.path.write_bytes(self.path.read_bytes()[:-1] + b"\x01")
        with self.assertRaises(person.ModelUnavailable):
            yolox.YoloxTinyPersonDetector(self.path, score_threshold=0.5, intra_op_threads=1)

    def test_isolated_worker_evaluates_and_fails_closed(self):
        spec = WorkerSpec(DetectorKind.PERSON, "yolox-tiny-onnx-cpu", "0.1.1rc0",
                          generated_onnx.pinned_yolox,
                          {"implementation": "yolox-tiny-onnx-cpu", "artifact": str(self.path),
                           "sha256": self.sha256, "size": self.size,
                           "score_threshold": 0.5, "intra_op_threads": 1})
        # Test-only limits, not deployment defaults.
        limits = WorkerLimits(evaluation_timeout_ns=10_000_000_000,
                              start_timeout_ns=60_000_000_000, restart_backoff_ns=1,
                              maximum_consecutive_failures=2, address_space_bytes=8 << 30,
                              open_files=256, maximum_frame_bytes=416 * 416 * 3)
        detector = IsolatedDetector(spec, limits)
        self.addCleanup(detector.close)
        self.assertEqual(detector.maintain().state, "running")
        self.assertEqual(detector.evaluate(rgb(416, 416, (255, 255, 255))).observation,
                         Observation.PRESENT)
        self.assertEqual(detector.evaluate(rgb(416, 416, (0, 0, 0), 1)).observation,
                         Observation.ABSENT)
        self.assertEqual(detector.evaluate(rgb(300, 300, sequence=2)),
                         Detection(Observation.UNKNOWN, Reason.QUALITY))

    def test_isolated_worker_with_wrong_digest_never_runs(self):
        spec = WorkerSpec(DetectorKind.PERSON, "yolox-tiny-onnx-cpu", "0.1.1rc0",
                          yolox.create_yolox_person,
                          {"implementation": "yolox-tiny-onnx-cpu", "artifact": str(self.path),
                           "score_threshold": 0.5, "intra_op_threads": 1})
        limits = WorkerLimits(evaluation_timeout_ns=10_000_000_000,
                              start_timeout_ns=60_000_000_000, restart_backoff_ns=1,
                              maximum_consecutive_failures=1, address_space_bytes=8 << 30,
                              open_files=256, maximum_frame_bytes=416 * 416 * 3)
        detector = IsolatedDetector(spec, limits)
        self.addCleanup(detector.close)
        # The child uses the real pin, which the generated graph cannot match.
        self.assertNotEqual(detector.maintain().state, "running")
        self.assertEqual(detector.evaluate(rgb(416, 416)),
                         Detection(Observation.UNKNOWN, Reason.WORKER_UNAVAILABLE))


if __name__ == "__main__":
    unittest.main()
