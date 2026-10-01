"""Generate a tiny YOLOX-shaped ONNX graph in memory; no weights or media.

The graph has the pinned YOLOX interface (`images` [1,3,S,S] -> `output`
[1,A,85]) and computes, for anchor zero only, objectness = mean(images)/255
and person score = 1. A uniform generated frame of value v therefore yields a
person score of v/255 after letterbox padding, which exercises the real ONNX
Runtime path, pixel layout and padding without any learned parameters.

Factories here are importable top-level callables so a spawned isolated
worker can receive them by reference.
"""

import hashlib
from pathlib import Path
import struct

STRIDES = (8, 16, 32)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _int_field(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _string(number: int, text: str) -> bytes:
    return _field(number, text.encode())


def _tensor_type(dims) -> bytes:
    shape = b"".join(_field(1, _int_field(1, dim)) for dim in dims)
    return _field(1, _int_field(1, 1) + _field(2, shape))  # FLOAT


def _value_info(name: str, dims) -> bytes:
    return _string(1, name) + _field(2, _tensor_type(dims))


def _initializer(name: str, dims, values) -> bytes:
    raw = struct.pack(f"<{len(values)}f", *values)
    return (b"".join(_int_field(1, dim) for dim in dims) + _int_field(2, 1)
            + _string(8, name) + _field(9, raw))


def _node(op: str, inputs, outputs, attributes=b"") -> bytes:
    return (b"".join(_string(1, item) for item in inputs)
            + b"".join(_string(2, item) for item in outputs)
            + _string(4, op) + attributes)


def yolox_shaped_model(input_size: int) -> bytes:
    anchors = sum((input_size // stride) ** 2 for stride in STRIDES)
    width = anchors * 85
    scale = [0.0] * width
    bias = [0.0] * width
    scale[4] = 1 / 255   # anchor 0 objectness follows the mean pixel value
    bias[5] = 1.0        # anchor 0 person class score
    axes = _string(1, "axes") + b"".join(_int_field(8, axis) for axis in (1, 2, 3)) \
        + _int_field(20, 7)  # INTS
    keep = _string(1, "keepdims") + _int_field(3, 0) + _int_field(20, 2)  # INT, shape [1]
    graph = (
        _field(1, _node("ReduceMean", ["images"], ["mean"],
                        _field(5, axes) + _field(5, keep)))
        + _field(1, _node("Mul", ["mean", "scale"], ["scaled"]))
        + _field(1, _node("Add", ["scaled", "bias"], ["output"]))
        + _string(2, "generated-yolox-shaped-test-graph")
        + _field(5, _initializer("scale", [1, anchors, 85], scale))
        + _field(5, _initializer("bias", [1, anchors, 85], bias))
        + _field(11, _value_info("images", [1, 3, input_size, input_size]))
        + _field(12, _value_info("output", [1, anchors, 85]))
    )
    opset = _field(8, _string(1, "") + _int_field(2, 11))
    return _int_field(1, 6) + _string(2, "server-sentinel-tests") + opset + _field(7, graph)


def write_model(directory: Path, input_size: int) -> tuple[Path, str, int]:
    content = yolox_shaped_model(input_size)
    path = Path(directory) / "generated.onnx"
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest(), len(content)


def pinned_yolox(implementation, artifact, sha256, size, score_threshold, intra_op_threads):
    """Worker factory: pin the generated graph, then build the real adapter."""
    from app.detection.foundation import yolox
    adapter = yolox.ADAPTERS[implementation]
    pinned = yolox.ARTIFACTS[adapter.variant]
    yolox.ARTIFACTS[adapter.variant] = yolox.YoloxArtifact(
        pinned.variant, sha256, size, pinned.input_size)
    return yolox.create_yolox_person(implementation, artifact, score_threshold,
                                     intra_op_threads)
