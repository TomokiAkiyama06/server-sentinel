# 2026-10-11: MJPG frame decoder survey for ROI / camera tamper (accepted: Option B)

- Status: **accepted (Owner decision recorded)** — the Owner chose **Option B
  (simplejpeg)** on 2026-10-11. The comparison below is kept as the decision
  record.
- Date: 2026-10-11
- Related: Issue #217, Issue #205, PR #213, `docs/THIRD_PARTY_POLICY.md`,
  `agent/docs/DEPENDENCIES.md` (operator-installed GStreamer precedent)
- Scope: decision record only. This document adds **no runtime dependency, no
  lock entry, no `license/components.json` or `license/owner-approvals.json`
  record and no code**. The decoder is adopted by a separate adoption PR (which
  closes Issue #217). Until that PR is merged, an `MJPG` source stays outside
  scene detection and reports `unknown` (Owner decision 2026-10-11, Issue #217).

## Owner decision (2026-10-11)

The Owner adopted **Option B — simplejpeg** for Main-host MJPG decoding, on the
strength of its failure behaviour (the strictest of the candidates, see
"Corrupt / edge frame behaviour"). Options A and C and the status quo are not
adopted; their rows remain below as the comparison the decision was based on.

The adoption PR must do all of the following; until it does, MJPG stays
`unknown`:

1. **numpy becomes a ROI runtime dependency**, hash-pinned with
   `--require-hashes` in the runtime lock (not only the optional detector lock),
   with matching entries in the wheel audit inventory and
   `license/components.json`. simplejpeg itself is added the same way.
2. **Every supported runtime artifact is pinned and audited** (see "Artifacts
   needed for Option B" below), or the decoder runtime is explicitly narrowed;
   narrowing requires a separate Owner approval.
3. **libjpeg-turbo's `IJG` license is recorded through the license gate**
   (allowlist extension with the exact SPDX id or an exact entry in
   `license/owner-approvals.json`, whichever the Owner approves in that PR),
   together with the IJG notice and the Modified BSD text that binary
   distribution requires (see "License, license gate, pinning and packaging").
4. **SOF dimension check before decoding** (rule 2): width/height in the SOF
   header must equal the negotiated V4L2 format before simplejpeg is called,
   because a full-size decode of a 65500x65500 header was OOM-killed.
5. **Real C960 frame checks recorded in `MANUAL_TEST.md`**: whether frames carry
   DHT segments, whether and how many bytes follow `EOI` (UVC padding, rule 2),
   and real decode time; plus a check that decoding works inside the actual
   `server-sentinel.service` systemd sandbox.
6. **Every failure maps to `unknown`** (rule 1): pre-check rejection, decoder
   exception, post-check mismatch, plausibility check (rule 7), worker exit,
   timeout or kill.

The decoder-independent rules below still apply in full.

### License gate record for the adoption (Issue #217)

For item 3 the Owner approved `IJG` **for this component only**, as an exact
entry in `license/owner-approvals.json`, not as an allowlist extension:

| Field | Value |
| --- | --- |
| `component_id` | `pypi:simplejpeg@1.9.0` |
| `license` | `MIT AND IJG AND BSD-3-Clause AND Zlib` (simplejpeg's own MIT plus the statically linked libjpeg-turbo 3.1.2) |
| `upstream` | `https://pypi.org/project/simplejpeg/1.9.0/` |
| `approved_by` / `approved_on` | `repository-owner` / `2026-10-11` |
| `decision` | this document |

`IJG` stays outside `scripts/ci/license_gate.py`'s permissive allowlist, so any
other component carrying IJG terms needs its own Owner approval. NumPy 2.3.5 is
recorded as `BSD-3-Clause` (allowlisted) with its bundled terms as obligations.
The exact pins, audits and notices are in `server/requirements.lock`,
`server/docs/wheel-audit.json`, `server/docs/DEPENDENCIES.md` ("Issue #217
addition"), `server/docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md` and `NOTICE`.

## Question

The Main host's EMEET C960 cameras are captured as `MJPG`. PR #213 reads only
packed `GREY`/`YUYV` luma, so ROI movement and camera tamper cannot run on those
sources until a reviewed JPEG decoder exists. The Owner asked for a comparison of
candidate decoders (license, license-gate fit, hash pinning, CPU load and latency
at 1 frame/s/source with 1 worker for 1-4 sources, non-root/sandbox fit, and
failure behaviour that must map to `unknown`) before choosing one.

## Method (mock / synthetic only)

- **No camera and no live host was used.** Frames were generated
  synthetically (gradient, rectangles, a checkerboard "ROI target" and uniform
  per-pixel noise, `numpy` seed 217), JPEG-encoded at quality 85 with 4:2:2
  (typical of UVC MJPG) and 4:2:0 chroma subsampling; 20 distinct frames per
  size. Mean frame size: 1280x720 4:2:2 ≈ 203 KB, 1920x1080 4:2:2 ≈ 425 KB.
  The added noise makes entropy decoding heavier than for a typical indoor
  scene, so the numbers are intended as an upper bound for this content; real
  C960 frames were **not** measured (see "Not verified").
- Corrupt/edge variants were derived from a synthetic 1280x720 frame: missing
  Huffman tables (`no_dht`, common in UVC MJPG), truncated at 50 %, missing EOI,
  bit flips in the entropy-coded data, SOF dimensions patched to 1920x1080
  (`sof_dims_mismatch`), SOF dimensions patched to 65500x65500
  (`sof_huge_dims`, decompression bomb), empty input, random bytes, and
  `SOI`+`EOI` only. A near-black synthetic frame (`ok_dark`) checks that a dark
  but valid frame decodes (darkness is the quality gate's job, not the decoder's).
  The first `entropy bit flips` variant is a **single sample** (about 41 bytes
  XOR `0x5A` from the middle of the scan).
- Follow-up variants (added after review) derived from the same `ok` frame:
  the scan cut at 25 / 50 / 75 / 95 % and **re-terminated with `EOI`**
  (`trunc_eoi_*`, the shape a UVC packet loss can leave once the payload is
  re-framed), 16 extraneous bytes inserted before the `DQT` or `SOS` marker, and
  **30 bit-flip samples** (1, 4 or 16 single-bit flips at random offsets inside
  the entropy-coded data, Python `random` seed 217, 10 samples each). Each
  decode ran in a forked child as above; GStreamer ran one `gst-launch-1.0`
  process per frame. For returned frames the probe also counted the trailing
  rows of the 1/4 grayscale decode whose luma is constant (a "uniform bottom
  band", which libjpeg leaves when it stops decoding the scan early).
- All decoding ran inside `docker run --cpus=1 --network none --memory=2g` as an
  unprivileged uid, with `python -I`. Candidate wheels and the Debian
  `libturbojpeg0` package were downloaded into a scratch directory as untrusted
  data and loaded from there; nothing was installed on the host. Wheel-based
  candidates ran in `python:3.12.14-slim-bookworm@sha256:392307d2...` (the CI
  base image); host-provided candidates (Ubuntu GStreamer, Ubuntu
  `python3-pil`) ran in a `debian:12` container with the host `/usr` mounted
  read-only. Host CPU: AMD Ryzen 9 9950X; the 1-CPU CFS quota bounds every
  measurement to one core's worth of time.
- Per mode: 5 warm-up decodes, then 3 rounds x 20 frames; wall time
  (`perf_counter`) and process CPU time per decode. A paced run then simulated
  **one worker** receiving 1 or 4 frames together once per second for 10 s
  (worst-case phase alignment), recording CPU fraction and the latency of the
  last frame in each second. OpenCV ran with `cv2.setNumThreads(1)`.
- Corrupt-frame behaviour was observed in a fresh forked child (Python
  bindings) or a fresh process per frame (GStreamer, because a forked GStreamer
  process is not usable), so an OOM kill or crash is visible as such.

### Candidates and artifacts examined (not pinned, not adopted)

| Candidate | Version | Artifact SHA-256 (downloaded for survey only) |
| --- | --- | --- |
| Pillow (PyPI wheel, cp312 manylinux_2_28) | 12.3.0, bundles libjpeg-turbo 3.1.4.1 | `78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91` |
| simplejpeg (PyPI wheel, cp312 manylinux_2_28) | 1.9.0, statically bundles libjpeg-turbo 3.1.2 | `5be1c8932f43f99b6cc52f8ac4c28e3ac19a1a830351efdb159715fd683e2053` |
| PyTurboJPEG (pure-Python wheel) | 2.5.0 | `2c10c2de86aa0e4fd9d08de187e46e975d108db35c25842d342393913cf54c36` |
| libturbojpeg0 (Debian, for PyTurboJPEG) | 3.1.3-4 | `42ba489e84ef89bb45e6b87d6f796fa86263ca41b1e3f9251675e8e177a5c841` |
| opencv-python-headless (PyPI wheel, abi3 manylinux_2_28) | 5.0.0.93 | `ed709fdf9aa0bd1f2ed8549e71d19449b03a675bb581eb292285f6861953be37` |
| numpy (needed by simplejpeg / PyTurboJPEG / OpenCV) | 2.3.5 | `0d8163f43acde9a73c2a33605353a4f1bc4798745a8b1d73183b28e5b435ae28` (same hash as `server/requirements-detector.lock`) |
| GStreamer `jpegdec` (Ubuntu `gstreamer1.0-plugins-good`) | 1.28.2-2ubuntu0.4, system libjpeg-turbo8 2.1.5 | OS package, already on the Main host |
| Pillow (Ubuntu `python3-pil`) | 12.1.1, system libjpeg-turbo8 2.1.5 | OS package, already on the Main host |

FFmpeg (`mjpeg` decoder) was not measured: it is not installed on the Main host,
its build configuration decides between LGPL and GPL terms, and it would add a
much larger parser surface than a JPEG-only decoder.

### Artifacts needed for Option B (adopted)

`server/pyproject.toml` supports CPython 3.12 and 3.14, and the backend
dependency inventory (`server/docs/DEPENDENCIES.md`, `server/docs/wheel-audit.json`)
covers Linux x86-64 for both plus CPython 3.12 aarch64. Option B therefore needs
**six native wheels** (two packages x three runtimes). The PyPI JSON API
(read-only check, 2026-10-11) lists all six for the surveyed versions, so there
is **no gap on PyPI**; only the cp312 x86-64 pair was downloaded and exercised.

| Package | Runtime | Wheel (PyPI) | SHA-256 (PyPI JSON, not a pin) | Surveyed |
| --- | --- | --- | --- | --- |
| simplejpeg 1.9.0 | cp312 x86-64 | `simplejpeg-1.9.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` | `5be1c8932f43f99b6cc52f8ac4c28e3ac19a1a830351efdb159715fd683e2053` | yes |
| simplejpeg 1.9.0 | cp314 x86-64 | `simplejpeg-1.9.0-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` | `f22024286577a4e9bb30c4b3c1a66a3b0c6e56801b26c83d0581ad294d1b99e3` | no |
| simplejpeg 1.9.0 | cp312 aarch64 | `simplejpeg-1.9.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl` | `08ab337ca3b26d7562f5ad686ab8f3966fb206fced607d248e693cbc57fc53b3` | no |
| numpy 2.3.5 | cp312 x86-64 | `numpy-2.3.5-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` | `0d8163f43acde9a73c2a33605353a4f1bc4798745a8b1d73183b28e5b435ae28` (already in `server/requirements-detector.lock`) | yes |
| numpy 2.3.5 | cp314 x86-64 | `numpy-2.3.5-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` | `fffe29a1ef00883599d1dc2c51aa2e5d80afe49523c261a74933df395c15c520` | no |
| numpy 2.3.5 | cp312 aarch64 | `numpy-2.3.5-cp312-cp312-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl` | `8b973c57ff8e184109db042c842423ff4f60446239bd585a5131cc47f06f789d` | no |

simplejpeg 1.9.0 declares `numpy>=1.19.3`; numpy 2.3.5 requires Python >= 3.11.
The adoption PR may choose newer versions, but must then pin and audit the same
three runtimes for both packages. The four unsurveyed wheels each carry their
own bundled native code (numpy's OpenBLAS / gfortran runtime differs between
x86-64 and aarch64; simplejpeg's statically linked libjpeg-turbo uses Neon
instead of x86 SIMD on aarch64), so each needs its own license-file and
native-library audit entry, and their decode behaviour on the corrupt-frame set
was not measured. The existing detector lock is x86-64 / CPython 3.12 only, so
numpy's other two wheels are new review items. If the adoption PR instead
narrows the decoder runtime (for example to CPython 3.12 x86-64 only, with MJPG
remaining `unknown` elsewhere), that narrowing must be stated explicitly and
approved by the Owner.

For the comparison rows (not adopted): Pillow 12.3.0 also publishes cp312
x86-64, cp314 x86-64 and cp312 aarch64 wheels on PyPI, each bundling its own set
of about 18 native libraries (three wheels, three native audits); OpenCV
5.0.0.93 publishes `abi3` wheels for x86-64 and aarch64 (two very large wheels,
each to audit); GStreamer (Option C) is not a pip artifact, so per-architecture
Ubuntu packages would be needed (arm64 availability of the exact versions was
not checked).

## Results

### Decode time per frame (median / p95 wall ms, 1 CPU)

`gray 1/4` is a grayscale (luma-only) decode with libjpeg's DCT scaling to 1/4
width and height (Pillow `draft("L", ...)`, simplejpeg `min_width/min_height`,
TurboJPEG `scaling_factor`, OpenCV `IMREAD_REDUCED_GRAYSCALE_4`). GStreamer
`jpegdec` has no DCT-scaling option; its row is a full-size decode to the native
planar YUV output (the luma plane is directly usable) and, separately, through
`videoconvert` to `GRAY8`.

| Candidate | Mode | 1280x720 4:2:2 | 1920x1080 4:2:2 | 1280x720 4:2:0 | 1920x1080 4:2:0 |
| --- | --- | --- | --- | --- | --- |
| Pillow 12.3.0 wheel | RGB full | 1.94 / 1.97 | 4.43 / 4.56 | 1.63 / 1.68 | 3.86 / 3.92 |
| | gray full | 1.42 / 1.43 | 3.14 / 3.17 | 1.26 / 1.27 | 2.76 / 2.78 |
| | gray 1/4 | 1.28 / 1.32 | 2.76 / 2.78 | 1.10 / 1.11 | 2.37 / 2.41 |
| Pillow 12.1.1 Ubuntu | RGB full | 1.94 / 1.95 | 4.25 / 4.27 | 1.67 / 1.69 | 3.66 / 3.70 |
| | gray 1/4 | 1.28 / 1.29 | 2.71 / 2.73 | 1.09 / 1.10 | 2.35 / 2.35 |
| simplejpeg 1.9.0 | RGB full | 1.87 / 1.89 | 4.11 / 4.12 | 1.59 / 1.60 | 3.50 / 3.51 |
| | gray 1/4 | 1.26 / 1.59 | 2.73 / 3.37 | 1.10 / 1.42 | 2.38 / 2.95 |
| PyTurboJPEG 2.5.0 + libturbojpeg 3.1.3 | RGB full | 1.83 / 1.84 | 3.99 / 4.04 | 1.56 / 1.58 | 3.41 / 3.45 |
| | gray 1/4 | 1.24 / 2.83 | 2.68 / 2.82 | 1.08 / 3.13 | 2.34 / 2.45 |
| OpenCV 5.0.0 headless | RGB full | 1.90 / 1.97 | 4.29 / 4.31 | 1.65 / 1.66 | 3.74 / 4.11 |
| | gray 1/4 | 1.24 / 1.25 | 2.68 / 2.70 | 1.06 / 1.07 | 2.30 / 2.31 |
| GStreamer jpegdec 1.28.2 (in-process, PyGObject) | native YUV full | 1.60 / 1.61 | 3.39 / 3.43 | 1.31 / 1.36 | 2.83 / 2.86 |
| | GRAY8 full | 1.59 / 1.60 | 3.45 / 3.47 | 1.31 / 1.43 | 2.85 / 2.86 |
| GStreamer, one `gst-launch-1.0` process per frame | GRAY8 full | — | 10.7 median wall, 10.2 ms CPU per frame (incl. process start) | — | — |

Per-frame CPU time equals wall time within ±0.1 ms for every in-process
candidate (single-threaded decode). All candidates use libjpeg-turbo with SIMD
underneath, so they are within about 15 % of each other. DCT scaling saves less
than expected on these frames because Huffman decoding of the noisy synthetic
content dominates; on real, smoother frames the saving may be larger (not
verified).

### Load at 1 frame/s/source, 1 worker (1920x1080 4:2:2)

CPU fraction of one core and the worst latency of the last frame when all
sources' frames arrive in the same second (measured paced runs; 720p is about
half of these values).

| Candidate / mode | 1 source CPU | 4 sources CPU | 4 sources worst last-frame latency |
| --- | --- | --- | --- |
| Pillow wheel, gray 1/4 | 0.35 % | 1.26 % | 11.6 ms |
| Pillow wheel, RGB full | 0.54 % | 2.02 % | 18.7 ms |
| simplejpeg, gray 1/4 | 0.34 % | 1.25 % | 11.4 ms |
| PyTurboJPEG, gray 1/4 | 0.33 % | 1.23 % | 12.1 ms |
| OpenCV, gray 1/4 | 0.33 % | 1.22 % | 11.2 ms |
| Pillow Ubuntu, gray 1/4 | 0.34 % | 1.27 % | 12.0 ms |
| GStreamer in-process, GRAY8 | 0.46 % | 1.65 % | 17.5 ms |
| GStreamer process per frame (computed: 4 x 10.2 ms) | ≈ 1.0 % | ≈ 4.1 % | ≈ 43 ms (sequential) |

No backlog occurred in any paced run. Two and three sources scale linearly
between the 1- and 4-source values. **CPU cost does not distinguish the
candidates**: at the Owner's 1 frame/s/source budget every option stays below
about 5 % of one core, which also keeps the decode negligible next to the GPU
benchmarks other sessions run on the Main host. The choice should be made on
license, packaging and failure behaviour.

### Corrupt / edge frame behaviour

`raises` means the binding signalled failure (exception, `None`, non-zero exit
or no output). `silent` means a frame was returned as if valid.

| Variant | Pillow (wheel & Ubuntu) | simplejpeg (`strict=True`, default) | PyTurboJPEG 2.5.0 | OpenCV `imdecode` | GStreamer jpegdec |
| --- | --- | --- | --- | --- | --- |
| `ok`, `ok_dark`, `no_dht` | decoded | decoded | decoded | decoded | decoded |
| truncated 50 % / no EOI | raises `OSError: image file is truncated` | raises `Premature end of JPEG file` | **silent** (Python `warnings.warn` only) | returns `None` | **silent**: full-size frame emitted, no bus message, exit 0 |
| entropy bit flips (1 sample; see the 30-sample table below) | raises `OSError: broken data stream` | raises `Bogus DAC index` | **silent** (warning only) | **silent** (libjpeg warning on stderr only) | frame dropped: no output, no bus message, exit 0 |
| SOF dims 1920x1080 on 720p scan | **silent** 1920x1080 frame | raises `premature end of data segment` | **silent** (warning only) | **silent** 1920x1080 frame | **silent** 1920x1080 frame (caps renegotiated) |
| SOF dims 65500x65500 | raises `DecompressionBombError` | full-size: **process OOM-killed** (no pixel limit); 1/4: raises | full-size: **process OOM-killed**; 1/4: **silent** 16375x16375 | full-size: raises (`CV_IO_MAX_IMAGE_PIXELS`); 1/4: **silent** 16375x16375 | pipeline `ERROR` (negotiation), pipeline must be restarted |
| empty / random bytes / SOI+EOI only | raises `UnidentifiedImageError` | raises | raises `OSError` | raises / `None` | no output (empty and random: exit 0; SOI+EOI: exit 1 "No valid frames decoded") |
| scan cut at 25/50/75/95 % and re-terminated with `EOI` | **silent** (all 4; uniform bottom band) | raises `premature end of data segment` (all 4) | **silent** (Python warning, all 4) | **silent** (all 4) | **silent**: full-size frame emitted, exit 0 (all 4) |
| 16 extraneous bytes before `DQT` / before `SOS` | **silent** (both) | raises `16 extraneous bytes before marker` (both) | **silent** (Python warnings, both) | **silent** (both) | **silent**: frame emitted, exit 0 (both) |

The Ubuntu `python3-pil` 12.1.1 gave exactly the same result as the 12.3.0
wheel on every follow-up variant.

**Pillow does not report libjpeg warnings.** libjpeg-turbo signals the
recoverable corruptions above (premature end of the entropy-coded segment,
extraneous bytes before a marker, most bad Huffman codes) as *warnings* and
keeps decoding; Pillow has no API that turns them into errors. Pillow's
`ImageFile.LOAD_TRUNCATED_IMAGES` (default `False`) only governs the case where
the **input bytes run out** before the decoder finishes (`image file is
truncated`); it has no effect once the frame ends with `EOI`. It must stay
`False`: when `True`, Pillow also ignores negative decoder error codes, so fatal
errors such as `broken data stream` would be returned as frames. Pillow therefore
raises only for that input exhaustion, for errors libjpeg treats as fatal, for
the decompression-bomb limit and for unidentifiable data. The single
`entropy bit flips` sample in the first table happened to hit a fatal error and
is not representative, as the 30-sample run shows:

| 30 bit-flip samples (10 each with 1 / 4 / 16 flipped bits) | signalled failure (1 / 4 / 16 bits) | returned silently | of the silent ones: uniform bottom band in the 1/4 gray decode |
| --- | --- | --- | --- |
| Pillow (wheel & Ubuntu) | 2 of 30 (0 / 1 / 1), `broken data stream` | 28 | 7 |
| simplejpeg `strict=True` | 15 of 30 (1 / 6 / 8) | 15 | 3 |
| PyTurboJPEG 2.5.0 | 0 (a Python warning in exactly the 15 samples simplejpeg rejected) | 30 | 8 |
| OpenCV `imdecode` | 0 | 30 | 8 |
| GStreamer jpegdec (per-frame process) | 2 of 30 frames dropped silently (exit 0, no output), same samples as Pillow | 28 emitted | 7 (full-size GRAY8) |

Of the 28 samples Pillow returned silently, simplejpeg rejected 13 and 3 more
showed a uniform bottom band; the remaining 12 decoded to locally wrong pixels
with neither a warning nor a band. The results depend on where the flips land,
so these counts describe this sample set, not a rate to expect from real
cameras.

`TJFLAG_STOPONWARNING` did not turn PyTurboJPEG's warnings into exceptions in
this test; its warnings are ordinary Python `warnings`, so a `warnings` filter
set to `error` around the call would turn them into exceptions (inferred from
the recorded warnings, not run separately). `simplejpeg` with `strict=False`
behaves like PyTurboJPEG without such a filter (every recoverable corruption is
returned as a frame). A bit flip that does not break the entropy-coded syntax
(for example inside a coefficient) produces wrong pixels that **no decoder can
detect**, and even simplejpeg's strict mode returned 3 banded frames without a
warning; decode success therefore never proves frame integrity, and the scene
quality gate remains responsible for implausible content.

### License, license gate, pinning and packaging

| Candidate | Own license | Material bundled / required native code | License gate fit (`scripts/ci/license_gate.py`) | Hash pinning | Non-root / sandbox notes |
| --- | --- | --- | --- | --- | --- |
| Pillow wheel | `MIT-CMU` (HPND-style) | 18 bundled shared libraries and statically linked code: libjpeg-turbo (`IJG AND BSD-3-Clause AND Zlib`), FreeType (`FTL` / GPL-2.0 dual), HarfBuzz (MIT), libtiff (`libtiff`), libwebp (BSD-3-Clause), OpenJPEG (BSD-2-Clause), Little CMS (MIT), libavif (BSD-2-Clause), libpng (`libpng-2.0`, the license of libpng 1.6.36 and later), libxcb/libXau (`X11`), zlib-ng 2.3.3 (Zlib), brotli, zstd, xz; the SBOM also lists libimagequant (GPL-3.0-or-later) and FriBiDi (LGPL-2.1-or-later), which are **not** shipped in the wheel (FriBiDi is only loaded at runtime if the OS provides it) | `MIT-CMU`, `IJG`, `FTL`, `libtiff`, `libpng-2.0`, `X11` are **not** in the permissive allowlist: needs an Owner decision (allowlist extension or exact approvals) and a native-library audit like `server/docs/wheel-audit.json` | Yes, `--require-hashes`, but one native wheel **per supported runtime**: three wheels (cp312 x86-64, cp314 x86-64, cp312 aarch64; all three exist on PyPI) each with its own native-library audit; only cp312 x86-64 was examined | Pure in-process, no device or network access. Must open with `Image.open(fp, formats=["JPEG"])` so only the JPEG plugin parses camera bytes. No numpy needed (`Image.tobytes()` yields luma bytes). |
| simplejpeg | MIT | libjpeg-turbo 3.1.2 statically linked (`IJG AND BSD-3-Clause AND Zlib`); requires numpy (BSD-3-Clause, bundles OpenBLAS / gfortran runtime, already reviewed for the optional detector lock) | MIT is allowlisted; `IJG` is not; numpy would move from the optional detector lock into the ROI runtime | Yes: six wheels (simplejpeg + numpy for cp312 x86-64, cp314 x86-64, cp312 aarch64; all exist on PyPI, see "Artifacts needed for Option B"); only the cp312 x86-64 pair was examined | Smallest native surface (one 1 MB extension). Single maintainer; latest release 2025-10-10 with libjpeg-turbo 3.1.2, so upstream libjpeg-turbo fixes arrive only with a new simplejpeg release. |
| PyTurboJPEG 2.5.0 | MIT (pure Python, `ctypes`) | Requires `libturbojpeg.so` **3.x**; Ubuntu on the Main host ships libjpeg-turbo 2.1.5 and has no `libturbojpeg` installed, so a non-distribution library would be needed (PyTurboJPEG 1.x would be needed for 2.x) | Python part allowlisted; the shared library is outside pip, so the gate cannot pin or review it | Python wheel yes; native library no | Recoverable corruption is a Python warning, not an error (see above); no default pixel limit on full-size decode. **Not recommended.** |
| OpenCV headless | Apache-2.0 | About 150 MB of extracted code including FFmpeg (LGPL-2.1-or-later), OpenSSL 1.1.1k (upstream end-of-life), OpenBLAS + libgfortran, libvpx, libaom, statically linked Intel IPP ICV (Intel Simplified Software License) and more | Many non-allowlisted bundled licenses; LGPL and proprietary-licensed IPP need Owner review | Yes, but one huge `abi3` wheel per architecture (x86-64 and aarch64) | Large parser surface for a JPEG-only need; silent success on corrupt data. **Not recommended.** |
| GStreamer `jpegdec` (+ `videoconvert`, `gst-launch-1.0`) | `jpegdec`: LGPL-2.1-or-later (gst-plugins-good) with system libjpeg-turbo8 (`IJG AND BSD-3-Clause AND Zlib`); see the stack inventory below for the rest | Operator-installed OS packages; nothing bundled. The measured pipeline needs more than `jpegdec` (see below) | Outside the pip/npm gate, same as the Agent's operator-installed GStreamer; running an unmodified distribution package as a separate program places no license obligation on ServerSentinel code (see `agent/docs/DEPENDENCIES.md`), but adopting it on Main needs the Owner decision that precedent requires | No: apt package version only, updated by the distribution | Main's capture path does not use GStreamer today (direct V4L2 `mmap`), so this is a new runtime component on Main. Best fit is a separate `gst-launch-1.0` process confined like the Agent's Landlock-sandboxed capture child; PyGObject in the release venv is not an option (LGPL OS package, not in the venv). Per-frame output must be matched to input by the caller because a corrupt frame is dropped silently. |

**Option C stack inventory (incomplete).** The measured per-frame pipeline
(`gst-launch-1.0 ... ! jpegdec ! videoconvert ! video/x-raw,format=GRAY8 ! ...`)
loads more than `jpegdec`. Packages on the Main host (Ubuntu, `dpkg -l`, read
only), with the license as declared in each package's Debian `copyright` file:

| Component | Ubuntu package (version) | License (Debian copyright, summary) |
| --- | --- | --- |
| `gst-launch-1.0` | `gstreamer1.0-tools` 1.28.2-1 | LGPL-2.1-or-later (GStreamer core) |
| GStreamer core (`libgstreamer-1.0`, `libgstbase-1.0`, `coreelements`) | `libgstreamer1.0-0` 1.28.2-1 | mainly LGPL-2+ / LGPL-2.1+, a few MPL-2.0 and public-domain files |
| `videoconvert` (`libgstvideoconvertscale.so`) and `libgstvideo-1.0` / `libgstallocators-1.0` | `gstreamer1.0-plugins-base` / `libgstreamer-plugins-base1.0-0` 1.28.2-1ubuntu0.1 | mainly LGPL-2+, some BSD-3-Clause / MIT files |
| `jpegdec` (`libgstjpeg.so`) | `gstreamer1.0-plugins-good` 1.28.2-2ubuntu0.4 | LGPL-2.1-or-later |
| ORC runtime compiler (`liborc-0.4`, used by `videoconvert`) | `liborc-0.4-0t64` 1:0.4.42-2 | BSD-2-Clause style |
| GLib / GObject / GModule | `libglib2.0-0t64` 2.88.0-1ubuntu0.1 | LGPL-2.1-or-later with many differently licensed files |
| libjpeg-turbo | `libjpeg-turbo8` 2.1.5-4ubuntu4 | `IJG AND BSD-3-Clause AND Zlib` |
| other shared libraries from `ldd` | libffi, libpcre2-8, libdrm, libatomic, libc/libm | not reviewed |

This inventory is **incomplete**: the transitive closure was listed with `ldd`
only, the per-file licenses were not reviewed, plugins loaded at runtime by
the registry scan were not enumerated, and arm64 packages were not checked.
ORC's JIT would also conflict with `MemoryDenyWriteExecute=` (see below). Since
Option C was not adopted, this inventory was not completed.

All libjpeg-turbo based options (every candidate above) carry the IJG
obligation for binary distribution: product documentation must state "This
software is based in part on the work of the Independent JPEG Group", and the
Modified BSD license text when the TurboJPEG API is used (simplejpeg,
PyTurboJPEG). The Main unit has no `MemoryDenyWriteExecute=`; libjpeg-turbo's
SIMD code needs no writable-executable memory, while GStreamer's ORC JIT would
conflict with that hardening if it is added later.

## Requirements for any adoption (decoder-independent)

Whichever decoder is chosen, the observations above suggest these fail-closed
rules, to be implemented and tested in the adoption PR:

1. **Every failure is `unknown`, never "no movement" / "no tamper".** An
   exception, warning, `None`, missing output, process exit, timeout or kill all
   map to `unknown` for that sample, with the existing gap accounting.
2. **Pre-validate before decoding**: `SOI` at the start, an `EOI` marker
   followed by at most a small, bounded number of trailing bytes (UVC MJPG
   payloads may be padded after `EOI`, so requiring `EOI` as the very last two
   bytes could reject every valid frame; the bound is to be set from real C960
   frames, see "Not verified"), a bounded total byte size, and SOF width/height
   equal to the negotiated V4L2 format. This catches the truncation without `EOI`, dimension-mismatch and
   decompression-bomb cases where some decoders were silent or were
   OOM-killed. It does **not** catch a scan cut short and re-terminated with
   `EOI`, extraneous bytes before a marker, or bit flips.
3. **Treat decoder warnings as errors where the binding exposes them**
   (simplejpeg `strict=True`; PyTurboJPEG under a `warnings` filter set to
   `error`) and **post-check** the decoded size against the expected (scaled)
   size. Pillow, OpenCV and GStreamer expose no libjpeg warnings at all
   (`LOAD_TRUNCATED_IMAGES` must stay `False`: it only rejects input that runs
   out before `EOI`, but setting it to `True` would additionally suppress the
   decoder's negative error codes, turning even fatal decode errors into
   returned frames), so with them a warning-level corruption arrives as a normal
   frame and must be handled by rule 7 or by the Owner decision below.
4. **Decode in an isolated worker** with an address-space limit, not in the
   process that holds sessions and the database, because a native parser reads
   camera-supplied bytes and a swapped or faulty camera can feed it arbitrary
   data.
5. **Keep calibration and runtime on the same decode path.** DCT-scaled
   grayscale (area-like) and the current byte-slicing decimation (nearest
   sample) give different luma; the reference must be captured through the same
   decoder, scale and decimation, and a decoder change should invalidate the
   calibration version.
6. **Account frames in and out.** With a streaming decoder (GStreamer) a
   silently dropped frame must not shift the association between later frames
   and their timestamps.
7. **Post-decode plausibility check maps to `unknown`.** A decoded frame whose
   bottom rows are one flat value (the band libjpeg leaves after stopping early)
   or which is otherwise implausible must be reported as `unknown` by the
   quality gate, not compared against the ROI reference. This is needed for
   every candidate (even simplejpeg's strict mode returned 3 banded frames
   without a warning) and is the only detection path for warning-level
   corruption with Pillow. Implementation note: libjpeg stops at an MCU
   boundary, so the band starts mid-row; the check should look at the trailing
   MCUs / 8x8 blocks (scaled to the decode factor) in scan order, not only at
   whole trailing rows. It is a heuristic: a legitimately flat scene can
   trigger it (fail-closed to `unknown`), and locally wrong pixels without a
   band are not detected by any rule here.

## Options and recommendation (for the Owner)

These options and the survey's recommendation are kept as written before the
Owner decision; the Owner chose Option B (see "Owner decision" above).

- **Option A — Pillow wheel (recommended on maintenance and packaging, not on
  failure behaviour).** Actively maintained, ships the newest libjpeg-turbo of
  the candidates (3.1.4.1), needs no numpy and has a built-in
  decompression-bomb limit (only a `DecompressionBombWarning` between 1x and 2x
  `Image.MAX_IMAGE_PIXELS`; `DecompressionBombError` only above 2x, so the
  warning must be promoted to an error or the SOF pre-check of rule 2 relied
  upon). It raises only when the input runs out before `EOI`
  and on fatal libjpeg errors (2 of 30 bit-flip samples); it returns
  `EOI`-terminated mid-scan truncations, extraneous bytes and most bit flips as
  normal frames, because it does not expose libjpeg warnings. Costs: an Owner
  decision on `MIT-CMU`, `IJG`, `FTL`, `libtiff`, `libpng-2.0` and `X11`, a
  native-library audit of the 18 bundled libraries for every supported runtime
  wheel, the IJG notice, the SOF-dimension pre-check (rule 2), and a decision
  on how warning-level corruption is detected (decision 6 below).
- **Option B — simplejpeg (adopted by the Owner, 2026-10-11).** Strictest failure behaviour observed: it rejected
  every `EOI`-terminated truncation, both extraneous-byte frames and 15 of 30
  bit-flip samples, and it has the smallest native surface (MIT + statically
  linked libjpeg-turbo). Costs: an Owner decision on `IJG`, numpy as a ROI
  runtime dependency, an explicit header-dimension check (full-size decode of a
  bomb header was OOM-killed), wheels and audits for every supported runtime,
  the rule-7 plausibility check (it still returned 3 banded frames), and a
  single-maintainer project whose libjpeg-turbo updates lag upstream.
- **Option C — GStreamer `jpegdec` in a sandboxed per-frame process.** No new
  pip dependency and an existing Agent precedent for an operator-installed,
  Landlock-confined `gst-launch-1.0`. Costs: an LGPL OS dependency on Main that
  cannot be hash-pinned, a GStreamer core + plugins-base (`videoconvert`) +
  plugins-good + ORC + GLib stack whose inventory above is incomplete, about 4 % of one core at 4 sources from process
  start-up, and the most silent failure modes (truncated frames emitted as
  valid, corrupt frames dropped without a message, no warnings), which rules 2,
  6 and 7 must cover.
- **Not recommended:** OpenCV (large mixed-license bundle including LGPL
  FFmpeg, an end-of-life OpenSSL and proprietary IPP; silent decoding of corrupt
  data) and PyTurboJPEG (needs a non-distribution libjpeg-turbo 3.x on the Main
  host; corruption is reported only as Python warnings, which the caller must
  promote to errors itself).
- **Keep the status quo** (MJPG stays `unknown`): always available; ROI and
  tamper stay unarmed for the C960 sources, which must stay visible to the Owner
  as degraded rather than healthy.

Within A-C the measured CPU and latency are equivalent at 1 frame/s/source. The
recommendation of A rests on maintenance, packaging (no numpy) and update
cadence; on failure behaviour B is clearly stronger, so the choice between A and
B is a trade-off for the Owner rather than a clear win for A.

## Decisions requested from the Owner (resolved 2026-10-11)

Resolution: item 1 → **Option B**; item 3 → numpy becomes a ROI runtime
dependency (hash-pinned, lock and license inventory updated in the adoption
PR); item 2 → `IJG` is recorded through the license gate / owner approvals in
the adoption PR; item 7 → all supported runtimes are pinned and audited unless
the Owner separately approves a narrowing; items 4 and 6 lapse with Option B
(rule 7 still applies). Item 5 (decoding on the Agent) remains open and is out
of scope here. The original list is kept below.

1. Which option (A / B / C / status quo) to adopt for Main-host MJPG decoding.
2. For A or B: whether to extend the license-gate allowlist with the exact SPDX
   ids `IJG` (and for A `MIT-CMU`, `FTL`, `libtiff`, `libpng-2.0`, `X11`) as was done for
   `MIT-0`, or to record exact per-component approvals instead.
3. For B: whether numpy may become a ROI runtime dependency (today it is only in
   the optional detector lock).
4. For C: approval of GStreamer as an operator-installed runtime component on
   the Main host (the Agent precedent explicitly requires this decision).
5. Whether remote-agent sources should later decode on the Agent instead
   (`offer_luma()` path in PR #213); this survey covers Main-host decoding only.
6. For A (and for C, which also exposes no warnings): how warning-level
   corruption is detected. Possible answers:
   (a) rely on the rule-7 plausibility check in the quality gate (uniform
   bottom band and similar checks mapped to `unknown`) and accept that locally
   wrong pixels without a band are not detected;
   (b) add a path that does report warnings, for example choosing B, or running
   libjpeg-turbo's `djpeg` as the isolated worker and treating its warning exit
   status as failure (not evaluated in this survey: `djpeg` is not installed on
   the Main host and would be another operator-installed component);
   (c) both (a) and (b).
   Until this is decided no decoder is adopted, so MJPG stays `unknown`.
7. For A or B: whether the decoder runtime is narrowed to the surveyed CPython
   3.12 x86-64, or wheels for every supported runtime (CPython 3.14 x86-64 and
   CPython 3.12 aarch64 as well) are pinned and audited.

## Not verified

- Real EMEET C960 MJPG frames (whether they carry DHT segments, whether and how
  many bytes follow `EOI`, their size and entropy) and real decode time on them
  were not measured; checking this, including the trailing-byte bound of rule 2,
  belongs in `MANUAL_TEST.md` with the adoption PR.
- Behaviour inside the actual `server-sentinel.service` systemd sandbox was not
  exercised; only an unprivileged, network-less container was used.
- Only one candidate version each was examined; versions and hashes above are
  survey evidence, not pins. Only CPython 3.12 x86-64 wheels were examined; the
  CPython 3.14 x86-64 and CPython 3.12 aarch64 wheels were only confirmed to
  exist on PyPI (hashes from the PyPI JSON API), and their bundled libraries
  and behaviour were not examined.
- The Option C GStreamer stack inventory is incomplete (see above).
- The corrupt-frame variants are synthetic and few (one bit-flip sample in the
  first table, 30 in the follow-up). How real UVC transfer errors on the C960
  damage MJPG payloads (dropped packets, re-framing, extraneous bytes) and how
  often a uniform-band check would fire on real scenes were not measured.
