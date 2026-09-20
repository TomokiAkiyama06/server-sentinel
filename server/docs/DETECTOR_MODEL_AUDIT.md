# Issue #20: YOLOX candidate audit (2026-09-20)

Decision for this implementation: **evaluation candidate only; no YOLOX package,
pretrained weights, exported ONNX model, or automatic download is approved or
installed by this audit.** Motion baseline and a fail-closed person-detector
contract can proceed independently. An unavailable person model must report
`unknown`/unavailable, never a dependable `no person` result.

## Implementation code

- Upstream: [Megvii-BaseDetection/YOLOX](https://github.com/Megvii-BaseDetection/YOLOX).
- Stable release: [0.3.0](https://github.com/Megvii-BaseDetection/YOLOX/releases/tag/0.3.0),
  published 2022-04-22. GitHub ref API resolved this tag to commit
  `419778480ab6ec0590e5d3831b3afb3b46ab2aa3` during this audit. Pin this full
  revision for any later code evaluation; a tag alone is not immutable.
- [LICENSE at that revision](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/LICENSE)
  is Apache-2.0, with Megvii's 2021–2022 copyright notice. Redistribution requires
  the license, preserved applicable notices, change notices on modified files,
  and applicable NOTICE content if included by the distributed work. This code
  license finding does **not** establish the licensing of separately distributed
  learned parameters.

## Pretrained weights: unresolved, not accepted

- The [pinned model zoo](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/docs/model_zoo.md)
  links Nano/Tiny/S/M/L/X COCO weights to the `0.1.1rc0` assets. The
  [pinned ONNX instructions](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/demo/ONNXRuntime/README.md)
  separately link ONNX exports under that release. Neither reviewed document
  establishes a separate model/weights license grant.
- The [official release](https://github.com/Megvii-BaseDetection/YOLOX/releases/tag/0.1.1rc0)
  notes describe training changes and compatibility, not a separate weights
  license. The release API lists 22 assets; every asset has `digest: null`, and
  no checksum manifest is among the assets. Example candidate locations are
  `releases/download/0.1.1rc0/yolox_nano.pth` (7,694,953 bytes) and
  `releases/download/0.1.1rc0/yolox_nano.onnx` (3,659,407 bytes).
- [Upstream Issue #1865](https://github.com/Megvii-BaseDetection/YOLOX/issues/1865)
  explicitly asks whether the official pretrained weights share Apache-2.0 and
  whether separate restrictions apply. It remains open and its comments API
  returned an empty list at audit time. This is supporting evidence of an open
  clarification request, not authoritative proof of a particular license.
- No weights were downloaded. Consequently this audit has **no artifact SHA-256**
  and makes no claim that the release URL is content-addressed. A future approved
  artifact needs its own provenance, license evidence, and locally computed
  SHA-256 checked before load; an operator-supplied file alone does not satisfy
  the license gate. Exporting to ONNX would not resolve source-weight rights.

## Dependencies and material obligations

The [pinned requirements](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/requirements.txt)
are largely unpinned: NumPy, PyTorch (`>=1.7`), OpenCV Python, Loguru,
scikit-image, tqdm, torchvision, Pillow, THOP, Ninja, tabulate, TensorBoard,
and pycocotools (`>=2.0.2`). Only ONNX `1.8.1`, ONNX Runtime `1.8.0`, and
ONNX Simplifier `0.3.5` are exact there. The stock dependency graph is therefore
**not an accepted hash-locked or fully license-reviewed graph**.

- [setup.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/setup.py)
  uses the complete requirements file and can compile COCO evaluation code on
  Linux; a basic install is not an inference-only dependency set.
- [OpenCV Python's upstream licensing section](https://github.com/opencv/opencv-python#licensing)
  identifies the packaging code as MIT, OpenCV as Apache-2.0, bundled FFmpeg as
  LGPLv2.1, and non-headless Linux Qt 5 as LGPLv3. Thus checking only the top-level
  package's MIT metadata misses material redistribution obligations. Any chosen
  exact wheel requires its bundled notices/source/relinking obligations to be
  evaluated; this audit does not approve that binary distribution.
- [model_utils.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/yolox/utils/model_utils.py)
  imports THOP at module load. The original
  [Lyken17 THOP upstream](https://github.com/Lyken17/pytorch-OpCounter) identifies
  its code as MIT. This is not a license determination for any similarly named
  fork/package or an unpinned future resolution.

## Network, inference, export, and reporting behavior

- [models/build.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/yolox/models/build.py)
  defaults model factories to `pretrained=True` and calls
  `load_state_dict_from_url` against GitHub release assets. Stock hub/model
  construction can therefore attempt an automatic network download.
- [tools/demo.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/tools/demo.py)
  and [tools/export_onnx.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/tools/export_onnx.py)
  load local `.pth` checkpoints through `torch.load`; the exporter invokes ONNX
  simplification unless explicitly disabled. These scripts are not a reviewed
  safe loader for arbitrary operator-provided checkpoints.
- [utils/logger.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/yolox/utils/logger.py)
  implements optional W&B reporting and artifact/checkpoint upload.
  [core/trainer.py](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/yolox/core/trainer.py)
  activates it when the corresponding training logger is selected. The audit
  found this optional path, **not evidence that default inference sends data**.
  ServerSentinel must exclude this reporting feature even as an opt-in.
- The [ONNX inference sample](https://github.com/Megvii-BaseDetection/YOLOX/blob/419778480ab6ec0590e5d3831b3afb3b46ab2aa3/demo/ONNXRuntime/onnx_inference.py)
  loads a local model but imports YOLOX's wider utility/data stack. It is not
  evidence that only NumPy and ONNX Runtime are needed or that its transitive
  graph has no reporting/download paths. Any eventual runtime/build needs its
  own exact dependency/privacy audit and request interception tests.

This YOLOX audit does not approve an alternative. A subsequent separate
[RT-DETRv2 audit](RTDETR_RUNTIME_AUDIT.md) establishes a specifically pinned,
explicitly licensed CPU adapter and its tested local artifact. No model execution,
accuracy, hardware performance, export correctness, network behavior, or real
benchmark dataset was tested. Only upstream metadata and source text were read;
source snapshots are under `/tmp/server-sentinel-yolox-license-audit`.
