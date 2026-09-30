# YOLOX person-detector evaluation audit (Issue #20, 2026-09-30)

Scope: **evaluation only**, per the Owner decision
[`docs/decisions/2026-09-30-yolox-person-evaluation.md`](../../docs/decisions/2026-09-30-yolox-person-evaluation.md).
This supplements the earlier [candidate audit](DETECTOR_MODEL_AUDIT.md). It does
not certify accuracy and does not approve deployment or redistribution.

## Summary

| Item | Finding |
| --- | --- |
| Source code | Apache-2.0 (Megvii-BaseDetection/YOLOX, tag 0.3.0 = `419778480ab6ec0590e5d3831b3afb3b46ab2aa3`). No YOLOX source is copied into ServerSentinel; the adapter independently implements the documented ONNX interface. |
| Official pretrained weights | **License unclear.** No weights-specific license grant was found in the release, README, model zoo or ONNX docs; upstream [Issue #1865](https://github.com/Megvii-BaseDetection/YOLOX/issues/1865) asking exactly this was still open with zero comments on 2026-09-30. Not claimed Apache-2.0. |
| Training data | COCO 2017 (per upstream model zoo). See "COCO implications" below. |
| Runtime | Existing reviewed `onnxruntime==1.28.0` / `numpy==2.3.5` CPU closure (`requirements-detector.lock`). **No new dependency.** |
| GPU | Not measured: the reviewed CPU wheel exposes only `AzureExecutionProvider`/`CPUExecutionProvider`; a CUDA provider would need `onnxruntime-gpu` (or similar), which is a new unapproved dependency and was not added. |
| Weights in repo | None. Downloaded only to a local scratch directory for measurement. |

## Exact artifacts (official Megvii release `0.1.1rc0`)

Release: <https://github.com/Megvii-BaseDetection/YOLOX/releases/tag/0.1.1rc0>
(published 2021-08-18 by `FateScript`; tag resolved to commit
`e1052df71842031413f6030723c3607b839c80ce` on 2026-09-30). GitHub reports
`digest: null` for every asset and ships no checksum manifest, so the SHA-256
values below were **computed locally** after download on 2026-09-30; the
download size matched the release API size. A release URL is not
content-addressed; the adapter pins size + SHA-256.

| Variant | URL | Bytes | SHA-256 | Input |
| --- | --- | ---: | --- | --- |
| YOLOX-S | `https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_s.onnx` | 35,858,002 | `c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063` | 640×640 |
| YOLOX-Tiny | `https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_tiny.onnx` | 20,219,662 | `427cc366d34e27ff7a03e2899b5e3671425c262ea2291f88bb942bc1cc70b0f7` | 416×416 |

`yolox_nano.onnx` (3,659,407 bytes, locally computed SHA-256
`c789161ed43c8269fcd4e67c67eeeb4e80c622da2eb296a20bc6007bd18a0b7d`) was downloaded
for inspection but is not pinned by the adapter.

Graph inspection (standard-library protobuf wire reader plus ORT session
metadata): IR 6, producer `pytorch`, only the standard ONNX domain at opset 11,
no external-data initializers. Operators: Add, Concat, Conv, MaxPool, Mul,
Reshape, Resize, Sigmoid, Slice, Transpose. Input `images` float32
`[1,3,S,S]`; output `output` float32 `[1,A,85]` with A = 8400 (S) / 3549 (Tiny),
i.e. undecoded grid regression plus sigmoid objectness and 80 sigmoid class
scores.

## Pre/postprocessing basis

The pinned upstream revision's
[`demo/ONNXRuntime/README.md`](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/demo/ONNXRuntime/README.md)
links exactly these `0.1.1rc0` assets, and its
[`onnx_inference.py`](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/demo/ONNXRuntime/onnx_inference.py)
uses [`preproc`](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/yolox/data/data_augment.py):
OpenCV BGR, aspect-preserving `INTER_LINEAR` resize, top-left placement on a
114-filled canvas, float32 0–255, no mean/std. The `0.1.1rc0` release notes
state the normalization was removed for these weights. Scores are
`objectness × class`, class 0 = person. The adapter:

- accepts only RGB frames whose longer side equals S and shorter side ≤ S
  (the caller renders the bilinear aspect-preserving resize), pads bottom/right
  with 114 and converts RGB→BGR;
- reports the maximum `objectness × person` score over all anchors (NMS cannot
  raise the maximum, so boxes are not decoded) against an explicit threshold;
- returns `unknown` for any other frame shape, grayscale input, wrong output
  shape, non-finite values, scores outside [0,1], or runtime exceptions.

Caveat: the ONNX demo at the release commit `e1052df` itself still used mean/std
normalization; the later pinned revision pairs the same assets with
un-normalized input and the release notes support that. This was **not**
verified empirically on real images (no real-person media was used).

## COCO implications (not a legal conclusion)

The upstream model zoo reports COCO results, and the weights were trained on
COCO. COCO's [terms of use](https://cocodataset.org/#termsofuse) publish the
annotations under CC BY 4.0 and leave the images under their individual Flickr
terms, with the consortium not owning image copyrights (that page is
script-rendered and was not re-fetched verbatim during this audit; re-read it
before any adoption decision). COCO images include real people.
Whether learned parameters carry obligations from the training images is not
settled, and no upstream statement addresses it for these weights. Combined
with the missing weights license, the artifact is treated as **license-unclear**:
local evaluation only, no bundling/redistribution, no CI download, no
repository fixture. ServerSentinel does not use COCO images; only generated
frames were used.

## Network / telemetry

The adapter imports only NumPy and ONNX Runtime (reviewed in
[RTDETR_RUNTIME_AUDIT.md](RTDETR_RUNTIME_AUDIT.md)); YOLOX's Python package,
PyTorch, OpenCV, W&B logging and `load_state_dict_from_url` paths are **not**
installed or used. Only `CPUExecutionProvider` is enabled; construction and
run-time provider fallback are disabled and the enabled provider list is
checked. No URL, downloader, model id or fallback model is accepted.

On 2026-09-30 the explicit smoke (`python -m tests.detector_model_smoke
--adapter yolox-s-onnx-cpu|yolox-tiny-onnx-cpu <artifact>`) ran both pinned
artifacts in a `--network none`, read-only, non-root (UID 65534), 1-CPU,
2 GiB container built from the pinned `python:3.12.14-slim-bookworm` base with
`requirements-ci.lock`. Enabled providers were `["CPUExecutionProvider"]`; the
generated frame evaluated in-process and inside the spawned
`IsolatedDetector` worker (state `running`); malformed input returned
`unknown`; Python socket/DNS/process audit hooks saw zero attempts (the worker
is spawned before the hook is installed). Native syscalls were not traced.

## Not established

- Detection accuracy on real room footage, low light, occlusion or the target
  camera angles (Plan 21 / `MANUAL_TEST.md`).
- A weights license. Deployment adoption stays blocked on it.
- GPU performance (no approved GPU runtime).
- Target Main Server performance under real concurrent capture/recording load.
