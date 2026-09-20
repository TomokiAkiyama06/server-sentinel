# Exact RT-DETRv2 CPU candidate audit

Audited 2026-09-20. This supplies model-license/provenance and exact Linux CPython3.12 x86_64 wheels. It does not certify model accuracy or establish hardware performance.

## Model and code separately

- Original code: https://github.com/lyuwenyu/RT-DETR/tree/29320b6fd828f8e0987a71426cf2d961b09dfed7 ; Apache-2.0 LICENSE at that same revision.
- Official model: https://huggingface.co/PekingU/rtdetr_v2_r18vd/blob/5650961749fa93567c0d46fc7f43ea4f9e914107/README.md ; model-card metadata explicitly declares apache-2.0. Original safetensors LFS SHA256 d18309d0d7ea57048138885c4c6ecfcb1e24506fc6153b94ad484f8ab62c7115, 80,904,640 bytes. Original weights were not downloaded.
- Chosen converted model: https://huggingface.co/onnx-community/rtdetr_v2_r18vd-ONNX/blob/936f90b6a476c6da4dfe053fc521af55285976ba/README.md ; card explicitly declares apache-2.0 and base_model PekingU/rtdetr_v2_r18vd. This is a separately distributed community conversion, not an original-author ONNX artifact. Its card does not claim the exact original source-weight revision; do not invent one. The converted artifact itself is pinned below, and both publishers explicitly supply the permissive model license.
- onnx/model.onnx: SHA256 583a236ac21c95a7fd94f284fc21485e42355bfef82c27011ba78fbc09ee87e2, 81,057,510 bytes. Frozen revision in URL and digest verification are required. Avoid the older onnx-community/rtdetr_r18vd conversion: its card does not explicitly declare a license.
- Pinned preprocessing config: RGB; bilinear direct resize to640x640; float32 /255; no mean/std normalization; no padding. class0=person; 300 queries; focal-loss class scores (sigmoid). For no resize dependency, accept only pre-sized640 RGB and reject other shapes rather than silently applying a different resize algorithm.

## Exact Python distribution closure

`requirements-rtdetr-cpu-linux-py312.lock` has five exact wheel hashes: ONNX Runtime1.28.0, NumPy2.3.5, flatbuffers25.12.19, packaging25.0, protobuf6.33.5. Each wheel was fetched directly from PyPI distribution metadata, SHA256 checked, and retained under wheels/. The four latter distributions declare no runtime dependencies; ORT requires only these four without extras. Do not install symbolic/quantization/training extras, Transformers, HF Hub, OpenCV, Torch, or a model downloader.

Licenses: ORT MIT; flatbuffers Apache-2.0; packaging Apache-2.0 OR BSD-2-Clause; protobuf BSD-3-Clause. NumPy is BSD-3-Clause with additional bundled licenses described below. Copy full installed notices, not only top-level metadata. Flatbuffers wheel omits a LICENSE file, so preserve the upstream v25.12.19 LICENSE (saved flatbuffers-LICENSE) with distribution notices.

## Material bundled obligations

NumPy2.3.5 installed wheel LICENSE.txt explicitly identifies OpenBLAS BSD-3-Clause, bundled LAPACK BSD-3-Clause-Open-MPI, libgfortran GPL-3.0-or-later WITH GCC-exception-3.1, libquadmath LGPL-2.1-or-later; source components include MIT dragon4 and Zlib libdivide. No CC0 declaration occurs in the inspected2.3.5 wheel notices. NumPy2.4+/2.5 inspected candidates add Highway CC0 code and are excluded from this candidate.

The GCC runtime exception permits independent compiled modules to use the covered runtime without imposing GPL on the application. It does not remove the runtime libraries' own license/source obligations. If ServerSentinel redistributes native binaries/container images, preserve full copyright/license/exception texts, provide corresponding library source under applicable terms, and preserve replacement/relinking and reverse-engineering-for-debugging rights for LGPL components. An unmodified wheel lock in source plus local user installation is different from publishing redistributed binaries; do not silently convert this audit into approval to publish images without those delivery obligations.

ORT full universal ThirdPartyNotices.txt is saved under wheel-notices/onnxruntime/onnxruntime/. It lists multiple platform/provider components, including Eigen MPL-2.0 and Intel MKL's Intel Simplified Software License; presence in the universal notices is not evidence every component is in this CPU wheel. The inspected native wheel contains only libonnxruntime.so.1.28.0, libonnxruntime_providers_shared.so, and the Python extension. readelf NEEDED lists glibc/libm/libpthread/libdl/librt/libstdc++/libgcc_s, no MKL/DNNL library. No libmkl marker found. CMake DNNL defaults OFF. Static binary/provider-to-source correlation should be confirmed by integration get_build_info/get_available_providers before accepting any native-provider expansion; do not enable optional execution providers or plugins. Preserve all supplied notices rather than deleting apparently irrelevant sections.

## Linux telemetry path

ORT1.28.0 fixed code revision da9b5e364c465de65c49d91e696cd6485270757f, CPU wheel uploaded2026-07-25. Official Privacy.md says collection is implemented only on Windows at this revision. Source proof: core/platform/posix/env.cc uses a plain Telemetry instance; core/platform/telemetry.cc IsEnabled returnsfalse and EnableTelemetryEvents is empty. Thus the Linux provider cannot be switched into remote reporting via that API; merely disabling an otherwise-active uploader is not the claim.

Source links:
- https://github.com/microsoft/onnxruntime/blob/da9b5e364c465de65c49d91e696cd6485270757f/docs/Privacy.md
- https://github.com/microsoft/onnxruntime/blob/da9b5e364c465de65c49d91e696cd6485270757f/onnxruntime/core/platform/posix/env.cc
- https://github.com/microsoft/onnxruntime/blob/da9b5e364c465de65c49d91e696cd6485270757f/onnxruntime/core/platform/telemetry.cc

ORT1.29/1.30 official builds add cross-platform1DS reporting and are excluded. Do not relax the exactpin or Linux platform restriction automatically. Missing/mismatched runtime or model yields unavailable/unknown. A network-isolated synthetic smoke and request/socket-attempt monitoring remain needed; no claim about observed runtime network behavior follows solely from this source audit.

## Integration verification

The verified ONNX artifact ran successfully with only CPUExecutionProvider in a read-only, non-root, network-isolated CPython 3.12 container on 2026-09-20. Runtime build info was `git-branch=HEAD, git-commit-id=45de2a8b06, fp8-kv-cache=1, build type=Release`. Available providers were AzureExecutionProvider and CPUExecutionProvider; the enabled session contained only CPUExecutionProvider. Adapter construction now explicitly sets enable_fallback=False and also disables later fallback. Generated 640x640 RGB inference completed, malformed grayscale returned unknown, and Python socket/DNS/process audit hooks observed no attempts. Native syscall monitoring was not performed; the Linux reporting conclusion also rests on the exact source audit above. Full run details and limits are in DETECTOR_FOUNDATION.md. No real-person or real-room data was used. Target Main Server performance, scene accuracy, GPU, production worker isolation and final thresholds remain unaccepted.
