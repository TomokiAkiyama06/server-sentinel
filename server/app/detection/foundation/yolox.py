"""Digest-pinned, local-artifact YOLOX ONNX CPU person adapters (evaluation).

Owner decision 2026-09-30 (docs/decisions/2026-09-30-yolox-person-evaluation.md)
approves *evaluating* YOLOX as the #20 person detector. It is not production
adoption: the official pretrained weights have no explicit license grant (see
server/docs/YOLOX_EVALUATION_AUDIT.md). Weights are never committed, bundled,
or downloaded by this code; an operator supplies a local file whose exact size
and SHA-256 are fixed below. No URL, model identifier, downloader, GPU/cloud
provider or fallback model is accepted.
"""

from dataclasses import dataclass
from pathlib import Path

from .contracts import (Detection, DetectorKind, GrayFrame, Observation, Reason)
from .person import (ModelUnavailable, _read_pinned_artifact, cpu_session,
                     require_reviewed_runtime, validate_adapter_arguments)

RELEASE = "0.1.1rc0"
# Preprocessing/postprocessing follow the pinned upstream revision (tag 0.3.0),
# whose demo/ONNXRuntime pairs these exact release assets with un-normalized
# BGR input: letterbox (top-left, pad 114), float32 0..255, no mean/std.
UPSTREAM_REVISION = "419778480ab6ec0590e5d3831b3afb3b46ab2aa3"
PAD_VALUE = 114
CLASSES = 80
STRIDES = (8, 16, 32)


@dataclass(frozen=True)
class YoloxArtifact:
    variant: str
    sha256: str
    size: int
    input_size: int

    @property
    def anchors(self) -> int:
        return sum((self.input_size // stride) ** 2 for stride in STRIDES)


ARTIFACTS = {
    "yolox-s": YoloxArtifact(
        "yolox-s", "c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063",
        35858002, 640),
    "yolox-tiny": YoloxArtifact(
        "yolox-tiny", "427cc366d34e27ff7a03e2899b5e3671425c262ea2291f88bb942bc1cc70b0f7",
        20219662, 416),
}


def letterbox_shape(artifact: YoloxArtifact, width: int, height: int) -> bool:
    """True for the aspect-preserving resize YOLOX expects before padding.

    The longer side equals the model input and the shorter side fits in it;
    the caller renders that size (bilinear), the adapter pads bottom/right.
    """
    size = artifact.input_size
    return (max(width, height) == size and 0 < min(width, height) <= size)


class YoloxPersonDetector:
    """One CPU-only session per binding; threshold and CPU budget are explicit.

    Accepts only RGB frames already resized with preserved aspect ratio so the
    longer side equals the model input (see `letterbox_shape`). Any other
    size, grayscale input, non-finite/out-of-range output or runtime error is
    `unknown`, never a trusted no-person result. The measurement is the
    highest objectness x person-class score over all anchors (COCO class 0);
    it is a detector score, not a probability or an identity.
    """

    kind = DetectorKind.PERSON
    variant = ""

    def __init__(self, artifact: Path, *, score_threshold: float,
                 intra_op_threads: int) -> None:
        pinned = ARTIFACTS.get(self.variant)
        if pinned is None:
            raise ModelUnavailable()
        validate_adapter_arguments(score_threshold, intra_op_threads)
        self.threshold = score_threshold
        self._pinned = pinned
        try:
            require_reviewed_runtime()
            import numpy
            content = _read_pinned_artifact(Path(artifact), pinned.size, pinned.sha256)
            self._session = cpu_session(content, intra_op_threads)
            del content
            inputs = self._session.get_inputs()
            if (len(inputs) != 1 or inputs[0].name != "images"
                    or inputs[0].type != "tensor(float)"
                    or list(inputs[0].shape) != [1, 3, pinned.input_size, pinned.input_size]):
                raise ModelUnavailable()
            outputs = self._session.get_outputs()
            if len(outputs) != 1 or outputs[0].name != "output":
                raise ModelUnavailable()
            self._numpy = numpy
        except Exception:
            raise ModelUnavailable() from None

    def reset(self) -> None:
        # This model does not retain a temporal image history.
        pass

    def evaluate(self, frame: GrayFrame) -> Detection:
        pinned = self._pinned
        if frame.channels != 3 or not letterbox_shape(pinned, frame.width, frame.height):
            return Detection(Observation.UNKNOWN, Reason.QUALITY)
        np = self._numpy
        size = pinned.input_size
        try:
            rgb = np.frombuffer(frame.pixels, dtype=np.uint8).reshape(frame.height, frame.width, 3)
            values = np.full((1, 3, size, size), PAD_VALUE, dtype=np.float32)
            # Upstream consumes OpenCV BGR channel order.
            values[0, :, :frame.height, :frame.width] = rgb[:, :, ::-1].transpose(2, 0, 1)
            (output,) = self._session.run(["output"], {"images": values})
            if output.shape != (1, pinned.anchors, 5 + CLASSES):
                return Detection(Observation.UNKNOWN, Reason.FAILURE)
            # Every column from 4 on (objectness and all 80 classes) is a
            # sigmoid score; any value outside [0, 1] is an out-of-contract
            # result and must never become a trusted absence.
            sigmoid = output[0, :, 4:]
            if not np.isfinite(output).all() or (sigmoid < 0).any() or (sigmoid > 1).any():
                return Detection(Observation.UNKNOWN, Reason.FAILURE)
            scores = sigmoid[:, 0:2]
            # The exported head already applies sigmoid to objectness/classes;
            # the final score is objectness x class score, as upstream does
            # before NMS. NMS cannot raise the maximum, so it is not needed.
            maximum = float((scores[:, 0] * scores[:, 1]).max())
            result = Observation.PRESENT if maximum >= self.threshold else Observation.ABSENT
            return Detection(result, Reason.EVALUATED, maximum)
        except Exception:
            return Detection(Observation.UNKNOWN, Reason.FAILURE)


class YoloxSPersonDetector(YoloxPersonDetector):
    variant = "yolox-s"
    implementation = "yolox-s-onnx-cpu"
    version = RELEASE


class YoloxTinyPersonDetector(YoloxPersonDetector):
    variant = "yolox-tiny"
    implementation = "yolox-tiny-onnx-cpu"
    version = RELEASE


ADAPTERS = {
    YoloxSPersonDetector.implementation: YoloxSPersonDetector,
    YoloxTinyPersonDetector.implementation: YoloxTinyPersonDetector,
}


def create_yolox_person(implementation: str, artifact: str, score_threshold: float,
                        intra_op_threads: int) -> YoloxPersonDetector:
    """Importable worker factory for `IsolatedDetector` evaluation runs.

    The adapter re-verifies the pinned artifact size and digest inside the
    spawned child. The deployment schema (`config.parse_detection`) does not
    accept YOLOX: the Owner approved evaluation only, not deployment use.
    """
    adapter = ADAPTERS.get(implementation) if type(implementation) is str else None
    if adapter is None:
        raise ModelUnavailable()
    return adapter(Path(artifact), score_threshold=score_threshold,
                   intra_op_threads=intra_op_threads)
