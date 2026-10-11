# 2026-10-11: MJPG frame decoder survey for ROI / camera tamper (proposed)

- Status: **proposed — the repository owner decides**. Nothing here is adopted.
- Date: 2026-10-11
- Related: Issue #217, Issue #205, PR #213, `docs/THIRD_PARTY_POLICY.md`,
  `agent/docs/DEPENDENCIES.md` (operator-installed GStreamer precedent)
- Scope: decision support only. This document adds **no runtime dependency, no
  lock entry, no `license/components.json` or `license/owner-approvals.json`
  record and no code**. Until the Owner decides, an `MJPG` source stays outside
  scene detection and reports `unknown` (Owner decision 2026-10-11, Issue #217).

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
| entropy bit flips | raises `OSError: broken data stream` | raises `Bogus DAC index` | **silent** (warning only) | **silent** (libjpeg warning on stderr only) | frame dropped: no output, no bus message, exit 0 |
| SOF dims 1920x1080 on 720p scan | **silent** 1920x1080 frame | raises `premature end of data segment` | **silent** (warning only) | **silent** 1920x1080 frame | **silent** 1920x1080 frame (caps renegotiated) |
| SOF dims 65500x65500 | raises `DecompressionBombError` | full-size: **process OOM-killed** (no pixel limit); 1/4: raises | full-size: **process OOM-killed**; 1/4: **silent** 16375x16375 | full-size: raises (`CV_IO_MAX_IMAGE_PIXELS`); 1/4: **silent** 16375x16375 | pipeline `ERROR` (negotiation), pipeline must be restarted |
| empty / random bytes / SOI+EOI only | raises `UnidentifiedImageError` | raises | raises `OSError` | raises / `None` | no output (empty and random: exit 0; SOI+EOI: exit 1 "No valid frames decoded") |

`TJFLAG_STOPONWARNING` did not turn PyTurboJPEG's warnings into exceptions in
this test; `simplejpeg` with `strict=False` behaves like PyTurboJPEG (every
recoverable corruption is returned as a frame). A bit flip that does not break
the entropy-coded syntax (for example inside a coefficient) produces wrong
pixels that **no decoder can detect**; decode success therefore never proves
frame integrity, and the scene quality gate remains responsible for implausible
content.

### License, license gate, pinning and packaging

| Candidate | Own license | Material bundled / required native code | License gate fit (`scripts/ci/license_gate.py`) | Hash pinning | Non-root / sandbox notes |
| --- | --- | --- | --- | --- | --- |
| Pillow wheel | `MIT-CMU` (HPND-style) | 18 bundled shared libraries and statically linked code: libjpeg-turbo (`IJG AND BSD-3-Clause AND Zlib`), FreeType (`FTL` / GPL-2.0 dual), HarfBuzz (MIT), libtiff (`libtiff`), libwebp (BSD-3-Clause), OpenJPEG (BSD-2-Clause), Little CMS (MIT), libavif (BSD-2-Clause), libpng (`Libpng`), libxcb/libXau (`X11`), zlib-ng 2.3.3 (Zlib), brotli, zstd, xz; the SBOM also lists libimagequant (GPL-3.0-or-later) and FriBiDi (LGPL-2.1-or-later), which are **not** shipped in the wheel (FriBiDi is only loaded at runtime if the OS provides it) | `MIT-CMU`, `IJG`, `FTL`, `libtiff`, `Libpng`, `X11` are **not** in the permissive allowlist: needs an Owner decision (allowlist extension or exact approvals) and a native-library audit like `server/docs/wheel-audit.json` | Yes: one wheel, `--require-hashes` | Pure in-process, no device or network access. Must open with `Image.open(fp, formats=["JPEG"])` so only the JPEG plugin parses camera bytes. No numpy needed (`Image.tobytes()` yields luma bytes). |
| simplejpeg | MIT | libjpeg-turbo 3.1.2 statically linked (`IJG AND BSD-3-Clause AND Zlib`); requires numpy (BSD-3-Clause, bundles OpenBLAS / gfortran runtime, already reviewed for the optional detector lock) | MIT is allowlisted; `IJG` is not; numpy would move from the optional detector lock into the ROI runtime | Yes: two wheels | Smallest native surface (one 1 MB extension). Single maintainer; latest release 2025-10-10 with libjpeg-turbo 3.1.2, so upstream libjpeg-turbo fixes arrive only with a new simplejpeg release. |
| PyTurboJPEG 2.5.0 | MIT (pure Python, `ctypes`) | Requires `libturbojpeg.so` **3.x**; Ubuntu on the Main host ships libjpeg-turbo 2.1.5 and has no `libturbojpeg` installed, so a non-distribution library would be needed (PyTurboJPEG 1.x would be needed for 2.x) | Python part allowlisted; the shared library is outside pip, so the gate cannot pin or review it | Python wheel yes; native library no | Recoverable corruption is a Python warning, not an error (see above); no default pixel limit on full-size decode. **Not recommended.** |
| OpenCV headless | Apache-2.0 | About 150 MB of extracted code including FFmpeg (LGPL-2.1-or-later), OpenSSL 1.1.1k (upstream end-of-life), OpenBLAS + libgfortran, libvpx, libaom, statically linked Intel IPP ICV (Intel Simplified Software License) and more | Many non-allowlisted bundled licenses; LGPL and proprietary-licensed IPP need Owner review | Yes, but one huge wheel | Large parser surface for a JPEG-only need; silent success on corrupt data. **Not recommended.** |
| GStreamer `jpegdec` | LGPL-2.1-or-later (gst-plugins-good), with system libjpeg-turbo8 (`IJG AND BSD-3-Clause AND Zlib`) | Operator-installed OS packages; nothing bundled | Outside the pip/npm gate, same as the Agent's operator-installed GStreamer; running an unmodified distribution package as a separate program places no license obligation on ServerSentinel code (see `agent/docs/DEPENDENCIES.md`), but adopting it on Main needs the Owner decision that precedent requires | No: apt package version only, updated by the distribution | Main's capture path does not use GStreamer today (direct V4L2 `mmap`), so this is a new runtime component on Main. Best fit is a separate `gst-launch-1.0` process confined like the Agent's Landlock-sandboxed capture child; PyGObject in the release venv is not an option (LGPL OS package, not in the venv). Per-frame output must be matched to input by the caller because a corrupt frame is dropped silently. |

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
2. **Pre-validate before decoding**: `SOI` at the start, `EOI` at the end, a
   bounded byte size, and SOF width/height equal to the negotiated V4L2 format.
   This alone catches the truncation, dimension-mismatch and decompression-bomb
   cases where some decoders were silent or were OOM-killed.
3. **Treat warnings as errors** (simplejpeg `strict=True`; Pillow without
   `LOAD_TRUNCATED_IMAGES`) and **post-check** the decoded size against the
   expected (scaled) size.
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

## Options and recommendation (for the Owner)

- **Option A — Pillow wheel (recommended).** Actively maintained, ships the
  newest libjpeg-turbo of the candidates (3.1.4.1), needs no numpy, raises on
  truncation and bit flips and has a built-in decompression-bomb limit. Costs:
  an Owner decision on `MIT-CMU`, `IJG`, `FTL`, `libtiff`, `Libpng` and `X11`, a
  native-library audit of the 18 bundled libraries, the IJG notice, and the
  SOF-dimension pre-check (rule 2) for the one silent case observed.
- **Option B — simplejpeg.** Strictest default failure behaviour and the
  smallest native surface (MIT + statically linked libjpeg-turbo). Costs: an
  Owner decision on `IJG`, numpy as a ROI runtime dependency, an explicit
  header-dimension check (full-size decode of a bomb header was OOM-killed), and
  a single-maintainer project whose libjpeg-turbo updates lag upstream.
- **Option C — GStreamer `jpegdec` in a sandboxed per-frame process.** No new
  pip dependency and an existing Agent precedent for an operator-installed,
  Landlock-confined `gst-launch-1.0`. Costs: an LGPL OS dependency on Main that
  cannot be hash-pinned, about 4 % of one core at 4 sources from process
  start-up, and the most silent failure modes (truncated frames emitted as
  valid, corrupt frames dropped without a message), which rules 2 and 6 must
  fully cover.
- **Not recommended:** OpenCV (large mixed-license bundle including LGPL
  FFmpeg, an end-of-life OpenSSL and proprietary IPP; silent decoding of corrupt
  data) and PyTurboJPEG (needs a non-distribution libjpeg-turbo 3.x on the Main
  host; corruption is reported only as Python warnings).
- **Keep the status quo** (MJPG stays `unknown`): always available; ROI and
  tamper stay unarmed for the C960 sources, which must stay visible to the Owner
  as degraded rather than healthy.

Within A-C the measured CPU and latency are equivalent at 1 frame/s/source; the
recommendation rests on maintenance, failure behaviour and license review cost.

## Decisions requested from the Owner

1. Which option (A / B / C / status quo) to adopt for Main-host MJPG decoding.
2. For A or B: whether to extend the license-gate allowlist with the exact SPDX
   ids `IJG` (and for A `MIT-CMU`, `FTL`, `libtiff`, `Libpng`, `X11`) as was done for
   `MIT-0`, or to record exact per-component approvals instead.
3. For B: whether numpy may become a ROI runtime dependency (today it is only in
   the optional detector lock).
4. For C: approval of GStreamer as an operator-installed runtime component on
   the Main host (the Agent precedent explicitly requires this decision).
5. Whether remote-agent sources should later decode on the Agent instead
   (`offer_luma()` path in PR #213); this survey covers Main-host decoding only.

## Not verified

- Real EMEET C960 MJPG frames (whether they carry DHT segments, their size and
  entropy) and real decode time on them were not measured; checking this belongs
  in `MANUAL_TEST.md` with the adoption PR.
- Behaviour inside the actual `server-sentinel.service` systemd sandbox was not
  exercised; only an unprivileged, network-less container was used.
- Only one candidate version each was examined; versions and hashes above are
  survey evidence, not pins.
