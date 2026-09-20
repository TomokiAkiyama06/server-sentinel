# Exact RT-DETRv2 CPU candidate audit

Audited 2026-09-20. This supplies model-license/provenance and exact Linux CPython3.12 x86_64 wheels. It does not certify model accuracy or establish hardware performance.

## Model and code separately

- Original code: https://github.com/lyuwenyu/RT-DETR/tree/29320b6fd828f8e0987a71426cf2d961b09dfed7 ; Apache-2.0 LICENSE at that same revision.
- Official model: https://huggingface.co/PekingU/rtdetr_v2_r18vd/blob/5650961749fa93567c0d46fc7f43ea4f9e914107/README.md ; model-card metadata explicitly declares apache-2.0. Original safetensors LFS SHA256 d18309d0d7ea57048138885c4c6ecfcb1e24506fc6153b94ad484f8ab62c7115, 80,904,640 bytes. Original weights were not downloaded.
- Chosen converted model: https://huggingface.co/onnx-community/rtdetr_v2_r18vd-ONNX/blob/936f90b6a476c6da4dfe053fc521af55285976ba/README.md ; card explicitly declares apache-2.0 and base_model PekingU/rtdetr_v2_r18vd. This is a separately distributed community conversion, not an original-author ONNX artifact. Its card does not claim the exact original source-weight revision; do not invent one. The converted artifact itself is pinned below, and both publishers explicitly supply the permissive model license.
- onnx/model.onnx: SHA256 583a236ac21c95a7fd94f284fc21485e42355bfef82c27011ba78fbc09ee87e2, 81,057,510 bytes. Frozen revision in URL and digest verification are required. Avoid the older onnx-community/rtdetr_r18vd conversion: its card does not explicitly declare a license.
- Pinned preprocessing config: RGB; bilinear direct resize to640x640; float32 /255; no mean/std normalization; no padding. class0=person; 300 queries; focal-loss class scores (sigmoid). For no resize dependency, accept only pre-sized640 RGB and reject other shapes rather than silently applying a different resize algorithm.

## Exact Python distribution closure

`../requirements-detector.lock` has five exact wheel hashes: ONNX Runtime1.28.0, NumPy2.3.5, flatbuffers25.12.19, packaging25.0, protobuf6.33.5. Each wheel was fetched directly from PyPI distribution metadata, SHA256 checked, and retained under wheels/. The four latter distributions declare no runtime dependencies; ORT requires only these four without extras. Do not install symbolic/quantization/training extras, Transformers, HF Hub, OpenCV, Torch, or a model downloader.

Licenses: ORT MIT; flatbuffers Apache-2.0; packaging Apache-2.0 OR BSD-2-Clause; protobuf BSD-3-Clause. NumPy is BSD-3-Clause with additional bundled licenses described below. Copy full installed notices, not only top-level metadata. Flatbuffers wheel omits a LICENSE file, so preserve the upstream v25.12.19 LICENSE (saved flatbuffers-LICENSE) with distribution notices.

## Material bundled obligations

NumPy2.3.5 installed wheel LICENSE.txt explicitly identifies OpenBLAS BSD-3-Clause, bundled LAPACK BSD-3-Clause-Open-MPI, libgfortran GPL-3.0-or-later WITH GCC-exception-3.1, libquadmath LGPL-2.1-or-later; source components include MIT dragon4 and Zlib libdivide. No CC0 declaration occurs in the inspected2.3.5 wheel notices. NumPy2.4+/2.5 inspected candidates add Highway CC0 code and are excluded from this candidate.

The GCC runtime exception permits independent compiled modules to use the covered runtime without imposing GPL on the application. It does not remove the runtime libraries' own license/source obligations. If ServerSentinel redistributes native binaries/container images, preserve full copyright/license/exception texts, provide corresponding library source under applicable terms, and preserve replacement/relinking and reverse-engineering-for-debugging rights for LGPL components. An unmodified wheel lock in source plus local user installation is different from publishing redistributed binaries; do not silently convert this audit into approval to publish images without those delivery obligations.

ORT full universal ThirdPartyNotices.txt is saved under wheel-notices/onnxruntime/onnxruntime/. It lists multiple platform/provider components, including Eigen MPL-2.0 and Intel MKL's Intel Simplified Software License; presence in the universal notices is not evidence every component is in this CPU wheel. The inspected native wheel contains only libonnxruntime.so.1.28.0, libonnxruntime_providers_shared.so, and the Python extension. readelf NEEDED lists glibc/libm/libpthread/libdl/librt/libstdc++/libgcc_s, no MKL/DNNL library. No libmkl marker found. CMake DNNL defaults OFF. Static binary/provider-to-source correlation should be confirmed by integration get_build_info/get_available_providers before accepting any native-provider expansion; do not enable optional execution providers or plugins. Preserve all supplied notices rather than deleting apparently irrelevant sections.

## Linux telemetry path

ORT 1.28.0 actual wheel code revision 45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc, CPU wheel uploaded2026-07-25. Official Privacy.md says collection is implemented only on Windows at this revision. Source proof: core/platform/posix/env.cc uses a plain Telemetry instance; core/platform/telemetry.cc IsEnabled returnsfalse and EnableTelemetryEvents is empty. Thus the Linux provider cannot be switched into remote reporting via that API; merely disabling an otherwise-active uploader is not the claim.

Source links:
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/docs/Privacy.md
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/platform/posix/env.cc
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/platform/telemetry.cc

ORT1.29/1.30 official builds add cross-platform1DS reporting and are excluded. Do not relax the exactpin or Linux platform restriction automatically. Missing/mismatched runtime or model yields unavailable/unknown. A network-isolated synthetic smoke and request/socket-attempt monitoring remain needed; no claim about observed runtime network behavior follows solely from this source audit.

## Integration verification

The verified ONNX artifact ran successfully with only CPUExecutionProvider in a read-only, non-root, network-isolated CPython 3.12 container on 2026-09-20. Runtime build info was `git-branch=HEAD, git-commit-id=45de2a8b06, fp8-kv-cache=1, build type=Release`. Available providers were AzureExecutionProvider and CPUExecutionProvider; the enabled session contained only CPUExecutionProvider. Adapter construction now explicitly sets enable_fallback=False and also disables later fallback. Generated 640x640 RGB inference completed, malformed grayscale returned unknown, and Python socket/DNS/process audit hooks observed no attempts. Native syscall monitoring was not performed; the Linux reporting conclusion also rests on the exact source audit above. Full run details and limits are in DETECTOR_FOUNDATION.md. No real-person or real-room data was used. Target Main Server performance, scene accuracy, GPU, production worker isolation and final thresholds remain unaccepted.

## Verified converted artifact structure

Downloaded the explicitly Apache-2.0 converted artifact to `/tmp/server-sentinel-rtdetr-audit/rtdetr-v2-r18vd.onnx`; both publisher LFS SHA256 and size matched. At this metadata-only audit stage, no model execution occurred; the later CPU smoke is recorded above. A standard-library protobuf wire reader inspected metadata only: IR8, producer PyTorch2.6.0, standard-domain opset16, no nonstandard node domains or external-data initializers. Input `pixel_values` float32 `[batch_size,3,height,width]`; outputs `logits` float32 `[batch_size,300,80]` and `pred_boxes` float32 `[batch_size,300,4]`. Adapter should constrain batch1, height640,width640 even though axes are dynamic. Complete observed operator list is in `graph-metadata.json`; it includes standard GridSample. The later synthetic runtime smoke above confirmed CPU kernel support for this exact graph.

## Actual wheel build revision correction and Azure provider audit

The integrated wheel reports git-commit-id=45de2a8b06. Resolved full build source is **45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc**. Use this exact40-character hash in the manifest.

The tag da9b5e364c465de65c49d91e696cd6485270757f is one commit later; the sole diff copies `.inc` headers in Windows artifact packaging YAML. No runtime/build dependency/license source changed. The actual commit's Linux PosixEnv, empty Telemetry implementation, LICENSE, ThirdPartyNotices, deps.txt, common CMake and main CMake were fetched and byte-compared equal to the previously reviewed tag. This resolves the source/binary-provenance discrepancy explicitly; the wheel's published SHA remains unchanged.

Comparison: https://github.com/microsoft/onnxruntime/compare/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc...da9b5e364c465de65c49d91e696cd6485270757f

Actual-code Linux references:
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/platform/posix/env.cc
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/platform/telemetry.cc
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/docs/Privacy.md

Integration observed `get_available_providers()` returning AzureExecutionProvider and CPUExecutionProvider, with the session explicitly enabling CPU only. The exact Azure provider sources comprise a provider class storing a configuration map and a factory constructing it; there is no HTTP client, uploader, or overridden inference/kernel implementation in these provider files. Its CMake target links ORT/ONNX core and declares MIT source headers. Provider availability is therefore not evidence of an outbound request or analytics feature. Do not claim the wheel was built without Azure support: it demonstrably contains the provider name/factory.

Exact Azure source:
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/providers/azure/azure_execution_provider.cc
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/providers/azure/azure_execution_provider.h
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/onnxruntime/core/providers/azure/azure_provider_factory_creator.cc
- https://github.com/microsoft/onnxruntime/blob/45de2a8b06d62989b3ab55ba7dc58a27ca83f9fc/cmake/onnxruntime_providers_azure.cmake

The product adapter must keep `providers=["CPUExecutionProvider"]`, no provider/session configuration supplied by callers, no EP plugin registration, only the digest-approved standard-domain model, and validate session.get_providers()==["CPUExecutionProvider"]. Set constructor `enable_fallback=False` as well as `disable_fallback()` after creation: disabling after construction alone does not disable constructor retries (the inspected1.28 wrapper accepts enable_fallback through kwargs). Neither constructor nor run fallback lists Azure in this wrapper; constraining both still makes failures report unknown rather than silently retrying. Test initialization, inference, and corrupt-model/error paths while monitoring attempts. This is a specific reachability restriction under existing no-cloud/no-reporting policy, not permission to enable cloud inference.

## CI provenance inventory

`detector-wheel-audit.json` records each of the five accepted wheel filenames, PyPI release/download URLs, artifact SHA-256, declared dependency metadata, and the original license-file SHA-256 values. Flatbuffers omits its license in the wheel, so its record explicitly identifies the reviewed upstream notice instead. `tests/test_dependency_audit.py` recursively follows local requirements includes and compares the complete installed artifact set with the base and detector inventories. Extra/missing/changed hashes, include cycles and component-directory escapes fail CI; nested includes cannot skip the audit. This mechanical correspondence supplements the exact manual license and native-component review above.
