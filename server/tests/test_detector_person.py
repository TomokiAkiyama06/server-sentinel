"""CPU adapter contract tests use generated arrays; no model download in CI."""

import hashlib
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from uuid import UUID

import numpy as np

from app.detection.foundation import GrayFrame, Observation, Reason, RgbFrame
from app.detection.foundation import person


class PersonAdapterTests(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.session.get_providers.return_value = ["CPUExecutionProvider"]
        self.session.get_inputs.return_value = [SimpleNamespace(name="pixel_values", type="tensor(float)")]
        self.session.get_outputs.return_value = [SimpleNamespace(name="logits"), SimpleNamespace(name="pred_boxes")]
        self.logits = np.full((1, 300, 80), -20, dtype=np.float32)
        self.boxes = np.zeros((1, 300, 4), dtype=np.float32)
        self.session.run.return_value = (self.logits, self.boxes)
        self.frame = RgbFrame(UUID(int=1), UUID(int=2), 0, 640, 640, bytes([0, 128, 255]) * (640 * 640))

    def detector(self):
        with patch.object(person, "_read_approved_artifact", return_value=b"synthetic graph double"), \
             patch("onnxruntime.InferenceSession", return_value=self.session) as create:
            detector = person.RtDetrPersonDetector(Path("/unused"), score_threshold=0.5, intra_op_threads=1)
            self.assertEqual(create.call_args.kwargs["providers"], ["CPUExecutionProvider"])
            self.assertFalse(create.call_args.kwargs["enable_fallback"])
            self.session.disable_fallback.assert_called_once()
            return detector

    def test_exact_channels_normalization_shape_and_no_person_result(self):
        detector = self.detector()
        result = detector.evaluate(self.frame)
        self.assertEqual(result.observation, Observation.ABSENT)
        values = self.session.run.call_args.args[1]["pixel_values"]
        self.assertEqual(values.shape, (1, 3, 640, 640))
        self.assertEqual(values.dtype, np.float32)
        np.testing.assert_allclose(values[0, :, 0, 0], [0, 128 / 255, 1], rtol=1e-6)

    def test_person_class_and_focal_global_top_queries(self):
        self.logits[0, 15, 0] = 3
        detector = self.detector()
        self.assertEqual(detector.evaluate(self.frame).observation, Observation.PRESENT)
        # A person score excluded from global top300 is not an emitted candidate.
        self.logits.fill(10)
        self.logits[:, :, 0] = 3
        self.assertEqual(detector.evaluate(self.frame).observation, Observation.ABSENT)

    def test_wrong_channel_or_shape_is_unknown_without_execution(self):
        detector = self.detector()
        invalid = GrayFrame(UUID(int=1), UUID(int=2), 0, 640, 640, bytes(640 * 640))
        self.assertEqual(detector.evaluate(invalid).reason, Reason.QUALITY)
        invalid_rgb = RgbFrame(UUID(int=1), UUID(int=2), 0, 1, 1, bytes(3))
        self.assertEqual(detector.evaluate(invalid_rgb).observation, Observation.UNKNOWN)
        self.session.run.assert_not_called()

    def test_nan_wrong_outputs_and_inference_exception_are_unknown(self):
        detector = self.detector()
        self.logits[0, 0, 0] = float("nan")
        self.assertEqual(detector.evaluate(self.frame).reason, Reason.FAILURE)
        self.session.run.return_value = (np.zeros((1, 1, 80)), self.boxes)
        self.assertEqual(detector.evaluate(self.frame).reason, Reason.FAILURE)
        self.session.run.side_effect = RuntimeError("must not appear in the result")
        result = detector.evaluate(self.frame)
        self.assertEqual(result.observation, Observation.UNKNOWN)
        self.assertNotIn("must not appear", repr(result))

    def test_other_provider_never_silently_runs(self):
        self.session.get_providers.return_value = ["AzureExecutionProvider"]
        with self.assertRaises(person.ModelUnavailable):
            self.detector()

    def test_model_digest_same_bytes_regular_file_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "model.onnx"
            content = b"synthetic artifact only"
            artifact.write_bytes(content)
            link = Path(directory) / "link.onnx"
            link.symlink_to(artifact)
            with patch.object(person, "MODEL_BYTES", len(content)), \
                 patch.object(person, "MODEL_SHA256", hashlib.sha256(content).hexdigest()):
                self.assertEqual(person._read_approved_artifact(artifact), content)
                with self.assertRaises(person.ModelUnavailable):
                    person._read_approved_artifact(link)
                artifact.write_bytes(b"x" * len(content))
                with self.assertRaises(person.ModelUnavailable):
                    person._read_approved_artifact(artifact)

    def test_missing_model_and_wrong_runtime_are_fixed_unavailable_errors(self):
        with self.assertRaisesRegex(person.ModelUnavailable, "^approved local person detector is unavailable$"):
            person._read_approved_artifact(Path("/missing-private-artifact"))
        with patch("importlib.metadata.version", return_value="1.30.0"), \
             patch.object(person, "_read_approved_artifact") as read:
            with self.assertRaises(person.ModelUnavailable):
                person.RtDetrPersonDetector(Path("/unused"), score_threshold=0.5, intra_op_threads=1)
            read.assert_not_called()

    def test_unsupported_platform_rejected_before_runtime_or_model_load(self):
        with patch("platform.system", return_value="Windows"), \
             patch.object(person, "_read_approved_artifact") as read:
            with self.assertRaises(person.ModelUnavailable):
                person.RtDetrPersonDetector(Path("/unused"), score_threshold=0.5, intra_op_threads=1)
            read.assert_not_called()

    def test_thresholds_are_explicit_finite_and_bounded(self):
        for threshold in (0, 1, float("nan"), True):
            with self.assertRaises(ValueError):
                person.RtDetrPersonDetector(Path("/unused"), score_threshold=threshold, intra_op_threads=1)

    def test_normal_and_failure_paths_do_not_attempt_python_network(self):
        with patch.object(socket, "socket", side_effect=AssertionError("unexpected network")) as network:
            detector = self.detector()
            detector.evaluate(self.frame)
            self.session.run.side_effect = RuntimeError("synthetic failure")
            self.assertEqual(detector.evaluate(self.frame).observation, Observation.UNKNOWN)
            network.assert_not_called()
