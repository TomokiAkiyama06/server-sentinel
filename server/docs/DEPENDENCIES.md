# Issue #7 dependency audit

Reviewed 2026-09-20 for the Main Server foundation. This inventory covers exact application wheels and the CI-only container base; no model or weights are introduced.

## Runtime selection

FastAPI 0.141.1 + Uvicorn 0.53.0, both WITHOUT extras. Do not use `fastapi[standard]` or `uvicorn[standard]`.
FastAPI >= current release requires Pydantic >=2.9; using Pydantic v1 would require deliberately selecting older FastAPI.
Latest stable package wheels are compatible with Python 3.12; local Python 3.14 x86_64 and Linux Python 3.12 aarch64 pydantic-core wheels were also downloaded and hash verified.

`../requirements.lock` and `../requirements-ci.lock` contain the 13 runtime / 2 development packages with exact SHA256 hashes of downloaded wheels. Only the three selected native wheels are permitted by the reviewed lock. `wheel-audit.json` records all 17 permitted artifacts individually, including each native wheel's filename, SHA256, release metadata URL, download URL, dependencies, and included license-file hashes. The CPython 3.12 aarch64 and CPython 3.14 x86_64 wheels' MIT license bytes match the CPython 3.12 x86_64 wheel; the same source-version Rust dependency audit and accompanying notices apply. An offline CI check requires exact agreement between every permitted lock hash and the audit inventory.

| Package | Exact version | Declared license |
|---|---|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| fastapi | 0.141.1 | MIT |
| h11 | 0.16.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| pycodestyle | 2.14.0 | MIT |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| pyflakes | 3.4.0 | MIT |
| starlette | 1.6.0 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| uvicorn | 0.53.0 | BSD-3-Clause |

Wheel archives, PyPI metadata, included license files and `wheel-audit.json` provide provenance and exact upstream URLs. All release dates are on/before the audit date. Exact PyPI release metadata reports no known vulnerabilities; this is not a complete independent CVE audit.

### Notice obligations

- MIT/BSD packages: retain copyright, license, disclaimer; BSD no endorsement.
- typing-extensions metadata identifies PSF-2.0. The included LICENSE contains the complete Python license history and agreements (PSF, BeOpen, CNRI, CWI and 0BSD documentation). Preserve it intact. PSF's stand-alone SPDX entry is not separately OSI-marked; the included combined historical Python-2.0 license is OSI-approved. This is a permissive Python license family, not a source-available restriction. SPDX records saved for exact comparison.
- pydantic-core wheel carries only its own MIT license. Its source Cargo.lock resolves 103 third-party Rust crates. `rust-audit.json` records all exact versions, checksums, license expressions, upstream repositories and license files from checksummed crates. Include `BACKEND_THIRD_PARTY_LICENSE_TEXTS.md` with deployment/distribution; the installed wheel alone does not preserve the Rust transitive notices.
- Select MIT for MIT OR Apache-2.0 alternatives and Unlicense OR MIT. r-efi additionally offers LGPL but MIT is available; AUTHORS contains the MIT grant and copyrights. r-efi and wasi/wit-bindgen are target-conditional and are not Linux runtime additions.
- ICU4X crates use Unicode-3.0; unicode-ident and certain embedded Unicode tables carry Unicode-DFS-2016. Both license families are OSI-approved in current SPDX metadata; preserve copyright/permission notice and do not imply endorsement.
- foldhash Zlib permits commercial use/modification/redistribution; preserve notice and mark modifications. target-lexicon Apache-2.0 WITH LLVM-exception retains permissive Apache obligations plus an exception. No application dependency requires an AGPL/GPL/SSPL/BSL or noncommercial choice.
- wit-bindgen-rt omitted license files from its crate; MIT/Apache texts were retrieved from the precise crate VCS commit f2393e6e98fa5f9236cac580db8a3fc9de6a4b70 and included conservatively.

Static Python-wheel network review found no telemetry SDK or opaque runtime download code in the selected packages. Starlette TestClient references optional httpx/httpx2, neither is installed. Standard FastAPI CLI/cloud extras are excluded. Runtime egress behavior still needs the component smoke test; a static search is not a network test.

## Official Python container

Pin: `docker.io/library/python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e`.
Linux amd64 manifest: `sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a`.
Image build source: https://github.com/docker-library/python/blob/688a0b86bb44289df16a363e9f41d90514c1a5f9/3.12/slim-bookworm/Dockerfile .
Debian base manifest: `sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b`.
Recorded build time: 2026-09-19T01:08:17.794790714Z. Debian/debian-security snapshot comments: 20260918T000000Z.

`image-dpkg-packages-amd64.json` lists 105 exact installed Debian packages. The upstream SPDX SBOM has 153 entries including binary/source packages, Python, and pip; a separate SLSA provenance document records the build. These upstream documents are retrievable by the blob digests in `image-attestation-manifest-amd64.json`. They came from attestation manifest `sha256:a6a6eca5df5ab60a7e8a5c616c94048e2287124e4963da7f4411c616fd9a406e`. `image-attestation-manifest-amd64.json` records both checksummed blob digests. SPDX `licenseConcluded` is NOASSERTION; its licenseDeclared scanner output does not substitute for package copyright files.

### Image notices and distribution obligations

The CI-only Dockerfile uses the unmodified, digest-pinned Docker Official Python image as an operating-system/runtime aggregate. ServerSentinel application dependencies are independently licensed as listed above. The base image is not wholly MIT/PSF: it also includes Debian GPL utilities, LGPL system libraries, and separately licensed interpreter components. Preserve `/usr/share/doc/*/copyright`, `/usr/share/common-licenses`, Python LICENSE, pip vendored notices, and the exact image/SBOM inventory. Docker recipes and private local builds do not publish a ServerSentinel binary image. Before redistributing a built image, fulfill each included component's notices and applicable corresponding-source/relinking obligations; upstream image URLs alone are not a universal substitute for a source offer.

Image source/notice references:
- https://hub.docker.com/_/python (upstream image licensing guidance)
- https://docs.python.org/3.12/license.html (Python and bundled-software terms)
- https://github.com/docker-library/python/tree/688a0b86bb44289df16a363e9f41d90514c1a5f9 (build recipe)
- https://snapshot.debian.org/archive/debian/20260918T000000Z/ and https://snapshot.debian.org/archive/debian-security/20260918T000000Z/ (exact Debian archive snapshots)
- https://sources.debian.org/ (package source corresponding to the source/version fields in inventory)

Concrete material base components include glibc LGPL-2.1+, GCC runtime under its runtime-library exception, readline GPL-3+, and gdbm GPL-3+. Readline/_gdbm are optional interpreter extensions; do not add application use/linkage to these GPL APIs in this issue. No image is declared wholly permissive, no project license is changed, and no independent app code is copied from GPL utilities.

This recipe is compatible unmodified OS aggregation, not a linked GPL application dependency. It does not grant an exception for a future linked GPL app/model dependency or a binary-image publication with incomplete corresponding source.

The optional Issue #20 detector runtime has a separate Linux x86_64 / CPython 3.12-only [hash lock](../requirements-detector.lock) and [exact native/model audit](RTDETR_RUNTIME_AUDIT.md). Its narrower platform scope does not alter the base backend lock. CI installs both to test the optional adapter without model weights.
