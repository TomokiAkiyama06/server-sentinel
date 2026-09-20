"""Digest-pinned, local-artifact RT-DETRv2 CPU adapter. No network/downloads."""

import hashlib
import importlib.metadata
import math
import os
from pathlib import Path
import platform
import stat
import sys

from .contracts import (Detection, DetectorKind, GrayFrame, Observation,
                        Reason, positive_integer)

MODEL_REVISION = "936f90b6a476c6da4dfe053fc521af55285976ba"
MODEL_SHA256 = "583a236ac21c95a7fd94f284fc21485e42355bfef82c27011ba78fbc09ee87e2"
MODEL_BYTES = 81057510
MODEL_INPUT_SIZE = 640
RUNTIME_VERSION = "1.28.0"
NUMPY_VERSION = "2.3.5"


class ModelUnavailable(RuntimeError):
    """Fixed message deliberately omits artifact paths and runtime exceptions."""

    def __init__(self) -> None:
        super().__init__("approved local person detector is unavailable")


def _read_approved_artifact(path: Path) -> bytes:
    """Hash the same bounded regular-file bytes that the runtime will consume."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != MODEL_BYTES:
                raise ModelUnavailable()
            content = stream.read(MODEL_BYTES + 1)
        if len(content) != MODEL_BYTES or hashlib.sha256(content).hexdigest() != MODEL_SHA256:
            raise ModelUnavailable()
        return content
    except (OSError, ValueError):
        raise ModelUnavailable() from None


class RtDetrPersonDetector:
    """One CPU-only session per binding; thresholds and CPU budget are explicit.

    The sampler supplies 640x640 RGB frames (upstream bilinear resize, no padding).
    The adapter normalizes channels to [0,1]; no mean/std transform is required.
    Arbitrary sizes or grayscale are unknown, never trusted negative results.
    """

    kind = DetectorKind.PERSON
    implementation = "rtdetr-v2-r18vd-onnx-cpu"
    version = MODEL_REVISION

    def __init__(self, artifact: Path, *, score_threshold: float,
                 intra_op_threads: int) -> None:
        if isinstance(score_threshold, bool) or not isinstance(score_threshold, (float, int)):
            raise ValueError("score threshold must be a finite fraction")
        if not math.isfinite(score_threshold) or not 0 < score_threshold < 1:
            raise ValueError("score threshold must be in (0,1)")
        positive_integer(intra_op_threads, "intra_op_threads")
        if intra_op_threads > 64:
            raise ValueError("intra_op_threads exceeds the adapter ceiling")
        self.threshold = score_threshold
        try:
            # Only the reviewed Linux runtime closure is supported. Installing a
            # newer runtime never silently enables different reporting behavior.
            if (platform.system() != "Linux" or platform.machine() != "x86_64"
                    or sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 12)):
                raise ModelUnavailable()
            if importlib.metadata.version("onnxruntime") != RUNTIME_VERSION:
                raise ModelUnavailable()
            if importlib.metadata.version("numpy") != NUMPY_VERSION:
                raise ModelUnavailable()
            import numpy
            import onnxruntime
            content = _read_approved_artifact(Path(artifact))
            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = intra_op_threads
            options.inter_op_num_threads = 1
            options.execution_mode = onnxruntime.ExecutionMode.ORT_SEQUENTIAL
            options.log_severity_level = 4
            self._session = onnxruntime.InferenceSession(
                content, sess_options=options, providers=["CPUExecutionProvider"], enable_fallback=False)
            del content
            self._session.disable_fallback()
            if self._session.get_providers() != ["CPUExecutionProvider"]:
                raise ModelUnavailable()
            inputs = self._session.get_inputs()
            if len(inputs) != 1 or inputs[0].name != "pixel_values" or inputs[0].type != "tensor(float)":
                raise ModelUnavailable()
            if {output.name for output in self._session.get_outputs()} != {"logits", "pred_boxes"}:
                raise ModelUnavailable()
            self._numpy = numpy
        except Exception:
            raise ModelUnavailable() from None

    def reset(self) -> None:
        # This model does not retain a temporal image history.
        pass

    def evaluate(self, frame: GrayFrame) -> Detection:
        if frame.channels != 3 or (frame.width, frame.height) != (MODEL_INPUT_SIZE, MODEL_INPUT_SIZE):
            return Detection(Observation.UNKNOWN, Reason.QUALITY)
        np = self._numpy
        try:
            values = np.frombuffer(frame.pixels, dtype=np.uint8).reshape(640, 640, 3)
            values = values.transpose(2, 0, 1).astype(np.float32)[None, ...] / np.float32(255)
            logits, boxes = self._session.run(["logits", "pred_boxes"], {"pixel_values": values})
            if logits.shape != (1, 300, 80) or boxes.shape != (1, 300, 4):
                return Detection(Observation.UNKNOWN, Reason.FAILURE)
            if not np.isfinite(logits).all() or not np.isfinite(boxes).all():
                return Detection(Observation.UNKNOWN, Reason.FAILURE)
            # RT-DETR focal-loss postprocessing takes the top 300 query/class
            # scores globally. COCO class zero is person, not a named identity.
            scores = (np.float32(1) / (np.float32(1) + np.exp(np.clip(-logits[0], -80, 80)))).reshape(-1)
            candidates = np.argpartition(scores, -300)[-300:]
            person = candidates[candidates % 80 == 0]
            maximum = float(scores[person].max()) if len(person) else 0.0
            result = Observation.PRESENT if maximum >= self.threshold else Observation.ABSENT
            return Detection(result, Reason.EVALUATED, maximum)
        except Exception:
            return Detection(Observation.UNKNOWN, Reason.FAILURE)
