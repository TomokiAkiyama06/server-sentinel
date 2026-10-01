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
| GPU | Evaluation-only measurement with `onnxruntime-gpu==1.28.0` in an **uncommitted scratch venv** (Owner approval for evaluation only, 2026-09-30). Its NVIDIA CUDA/cuDNN wheels are under NVIDIA proprietary EULAs and are **not** in any repository lock or the license allowlist. Production stays CPU-only. See "GPU evaluation runtime" below. |
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
`unknown`. Python socket/DNS/process audit hooks recorded zero attempts in
the smoke process and, separately, in the spawned worker, whose own hook is
installed before the adapter is imported, loaded or evaluated
(`worker_python_outbound_attempts`; a recorded worker attempt fails the start
or evaluation). The worker-side hook was added after the first run and the
container smoke was re-run with it on 2026-09-30. Since 2026-10-01 the smoke
process installs its hook before any YOLOX import or setup, permitting only
the worker spawn during start (`permitted_worker_launches`; CPython 3.12 raises
no audit event for that spawn); the container smoke has not been re-run since
this ordering change. `--network none` blocks
delivery; the hooks, not the network namespace, are the attempt evidence.
The smoke's pass/fail checks raise unconditionally (`SmokeFailure`) rather
than using `assert`, so `python -O` / `PYTHONOPTIMIZE` cannot turn a worker
failure into a zero-attempt success (regression-tested with `-O`).
Native syscalls were not traced.

## Not established

- Detection accuracy on real room footage, low light, occlusion or the target
  camera angles (Plan 21 / `MANUAL_TEST.md`).
- A weights license. Deployment adoption stays blocked on it.
- Production GPU use (evaluation-only runtime; NVIDIA terms not accepted into the allowlist).
- Network/telemetry behavior of the CUDA/TensorRT provider code and NVIDIA libraries (not audited or traced).
- Target Main Server performance under real concurrent capture/recording load.

## GPU evaluation runtime (evaluation only, 2026-09-30)

Owner decision (confirmed directly in the 2026-09-30 session): `onnxruntime-gpu`
is approved **for evaluation only**. It was installed with
`pip install --only-binary=:all: "onnxruntime-gpu[cuda,cudnn]==1.28.0" numpy==2.3.5
flatbuffers==25.12.19 packaging==25.0 protobuf==6.33.5` into a Python 3.12 venv
in the session scratch directory. **Nothing from this environment is committed**:
no lock, requirements file, component record or approval entry.

A committed evaluation requirements file was considered and rejected: the
license gate treats every committed requirements file as a reviewed input whose
every entry needs a `components.json` record, and the NVIDIA wheels' license is
outside the permissive set, so representing them would require an Owner approval
entry, i.e. allowlisting NVIDIA terms. That is exactly what the Owner excluded.

Resolved artifacts (from the pip installation report):

| Distribution | Version | License metadata | Wheel SHA-256 |
| --- | --- | --- | --- |
| onnxruntime-gpu | 1.28.0 | MIT (OSI classifier) | `3b3a63cecd239d72432cd44569d047de8f4d69e471cd5f60f7ac7fc8769be5ec` |
| nvidia-cuda-runtime | 13.4.92 | `LicenseRef-NVIDIA-Proprietary` | `9641f797da20ce1dd8e779b6e96d08cf9ba564cec8e8225458811ee26423f3a5` |
| nvidia-cuda-nvrtc | 13.4.92 | `LicenseRef-NVIDIA-Proprietary` | `5ce8c97b00b232c4f50c8c4b5a3b68cafee08bdb82ea86f2052ff01d03194f4a` |
| nvidia-cublas | 13.8.1.7 | `LicenseRef-NVIDIA-Proprietary` | `c11a27fd4379510e5b1f84b367a2514d1e52fe5cc13442117a0e0a1addee3cf2` |
| nvidia-cufft | 12.4.0.43 | `LicenseRef-NVIDIA-Proprietary` | `0e8385013596b112d29c9ce8c63dc575b308d77636c7169104e18714f03961a8` |
| nvidia-curand | 10.4.4.72 | `LicenseRef-NVIDIA-Proprietary` | `25c3457ae7a224fdd484dab90b0fc5dc0e842fab5db3012afa4a5bd2af4eb7e5` |
| nvidia-nvjitlink | 13.4.92 | `LicenseRef-NVIDIA-Proprietary` | `e0391f24ed94ec879b84e3da4d4ec320c879aff681f2c7a638462f7199284323` |
| nvidia-cudnn-cu13 | 9.27.0.42 | `LicenseRef-NVIDIA-Proprietary` | `9677e76f21862eb5da7ee5ed69d544738b2d8b5c3ce7e5ec125c5592e6cdbdc8` |

`onnxruntime-gpu` 1.28.0 declares the NVIDIA wheels only through its `cuda` and
`cudnn` extras (`nvidia-cuda-nvrtc~=13.0`, `nvidia-cuda-runtime~=13.0`,
`nvidia-cufft~=12.0`, `nvidia-curand~=10.0`, `nvidia-cudnn-cu13~=9.0`); cuBLAS
and nvJitLink arrived transitively. The system has NVIDIA driver 595.91.07.

### NVIDIA license findings (not a legal conclusion)

- The six CUDA wheels ship the same `License.txt` (SHA-256
  `ad6f5853fba0ca0d159d0f58d49ae49830c2f8c93f7a92648b9ce90adb4c6ccd`), the CUDA
  Toolkit **End User License Agreement**. The cuDNN wheel ships the "License
  Agreement for NVIDIA Software Development Kits" (SHA-256
  `49cf79bdb35734b52fe6203013b3bd759f81e998cd32aa2c65c51db9a88c61d2`). Both are
  proprietary, not OSI-approved.
- Grant: non-exclusive, non-transferable, no sublicensing; installing/using is
  accepting the agreement.
- Redistribution is limited to portions listed as distributable, incorporated
  in object code into an application with "material additional functionality",
  accessed only by that application, under terms consistent with NVIDIA's; the
  distributor must notify NVIDIA of known non-compliant distribution.
- The agreements prohibit using the SDK "in any manner that would cause it to
  become subject to an open source software license", including terms requiring
  it be redistributable at no charge. This conflicts with shipping it as part of
  an Apache-2.0 distribution and is the main reason it stays out of the repo.
- They exclude, absent a separate NVIDIA agreement, systems whose failure can
  reasonably be expected to cause personal injury, death or catastrophic loss.
  A room-security monitor is not obviously in that class, but this needs Owner
  review before any production use.
- NVIDIA may terminate on non-compliance; copies must then be destroyed.

These terms are acceptable for a developer's local evaluation on this host;
they are **not** accepted into ServerSentinel's release inventory.

### Runtime provenance and provider placement

`onnxruntime-gpu` reports build commit `0368187f8403b9050f8dbc55b16966883bc93fb9`
("ORT 1.28.0 release cherry-pick round 2"). That is the direct parent of the
audited CPU wheel's `45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc`, whose only change
is NuGet packaging tooling (`tools/nuget/*`), so the Linux reporting source audit
in [RTDETR_RUNTIME_AUDIT.md](RTDETR_RUNTIME_AUDIT.md) covers the same core
runtime source. The CUDA/TensorRT provider code and the NVIDIA libraries were
**not** audited for network behavior. Available providers were
`TensorrtExecutionProvider`, `CUDAExecutionProvider`, `CPUExecutionProvider`;
only CUDA was requested.

The measurement driver lives in the scratch directory and reuses the repository
adapters and benchmark harness unchanged, substituting only the session factory:
`providers=[CUDAExecutionProvider]`, `enable_fallback=False` plus
`disable_fallback()`, and NVIDIA libraries loaded with `onnxruntime.preload_dlls()`.
Before `preload_dlls()` the CUDA provider failed to initialize and adapter
construction failed closed (`ModelUnavailable`), confirming no silent CPU run.
Placement was verified with ORT node profiling on a generated zero frame:

| Model | Session option `session.disable_cpu_ep_fallback=1` | Kernel nodes on CUDA | Kernel nodes on CPU |
| --- | --- | ---: | ---: |
| YOLOX-Tiny | set (session creation fails if any node lands on CPU) | 203 | 0 |
| YOLOX-S | set | 203 | 0 |
| RT-DETRv2 | cannot be set: creation fails because ORT deliberately places shape subgraph nodes on CPU | 895 | 134 (Gather 42, Concat 27, Unsqueeze 19, Equal 12, Where 12, Slice 7, Mul 7, Cast 6, Add 2) |

`session.get_providers()` reports `["CUDAExecutionProvider", "CPUExecutionProvider"]`
in every case because ORT always registers the CPU provider; the profile, not
that list, is the placement evidence. Results are in
[DETECTOR_FOUNDATION.md](DETECTOR_FOUNDATION.md).
