# Agent dependency and distribution review

**2026-09-30 update (Issue #13).** The Owner approved `cryptography` 50.0.1 for
capture-node key, CSR and certificate handling; it is the single approval
shared with the Main Server's WebAuthn use
(`../../docs/decisions/2026-09-30-cryptography-dependency.md`). `../requirements.lock`
pins cryptography 50.0.1, cffi 2.1.1 (MIT-0) and pycparser 3.0 with exact wheel
hashes for CPython 3.12/3.14 on Linux x86_64/aarch64 (glibc); every permitted
wheel (filename, SHA-256, download URL, license-file hashes) is recorded in
`cryptography-wheel-audit.json`. The Agent lock is wider than the Main lock
because capture hosts are more often aarch64 single-board computers on varied
distributions: cryptography `cp311-abi3` `manylinux_2_34` and `manylinux_2_28`
(glibc 2.28-2.33 fallback), each x86_64 and aarch64; cffi `cp312` and `cp314`,
each x86_64 and aarch64; pycparser `py3-none-any`. musl, free-threaded CPython,
PyPy, 32-bit ARM and non-Linux wheels are not permitted. Every permitted
cryptography wheel statically links the same OpenSSL 4.0.2 and is built from the
same 50.0.1 sdist `Cargo.lock`, so the license, OpenSSL, libffi and Rust-crate
review in `../../server/docs/DEPENDENCIES.md`, `../../server/docs/rust-audit.json`
and `../../server/docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md` applies unchanged.
Only `media_capture_agent.node_tls` imports it. The zipapp still contains only
application sources: it does not bundle these native wheels, and how an installed
Agent provisions them for the non-root service account is open installer work.
The statement below that the runtime is stdlib-only now applies to every module
except `node_tls`.

Reviewed 2026-09-20. The Agent runtime, installer and artifact builder use the
Python standard library only. No model, media codec, third-party runtime library,
SDK, native extension, or implicit package download is introduced. CPython 3.12
or 3.14 is required (3.13 has no reviewed `cffi` wheel in the mTLS adapter lock
above); exact CI interpreter is 3.12.14. Project code remains Apache-2.0;
`agent/LICENSE` is a copy of the root license included in the executable zipapp.
The zipapp contains application source and its license, not an interpreter or
operating-system image. Deployments supply their separately licensed Python.

CI lint tools use the same reviewed, universal MIT wheels in
`../../.ci/requirements.txt`, duplicated in `requirements-ci.lock` with exact
SHA-256 hashes. Pyflakes 3.4.0 and pycodestyle 2.14.0 have no runtime dependencies;
see `../../THIRD_PARTY_NOTICES.md`. Neither is bundled into the agent artifact.

The CI-only image is the exact Docker Official Python image reviewed for #7:
`python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e`.
Its amd64 manifest is `sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a`.
The upstream build recipe is pinned at
https://github.com/docker-library/python/blob/688a0b86bb44289df16a363e9f41d90514c1a5f9/3.12/slim-bookworm/Dockerfile .
The image includes PSF/Python, permissive packages, LGPL libraries and ordinary
GPL system utilities; it is not represented as wholly permissive. Agent code
uses neither readline nor gdbm optional GPL interpreter APIs. Unmodified OS
aggregation does not change the application license. Preserve all base-image
notices, `/usr/share/doc/*/copyright`, `/usr/share/common-licenses`, Python license
and pip notices. This change supplies a CI recipe and publishes no binary image;
image redistribution needs corresponding-source and other applicable obligations.
The full audited package/attestation inventory is maintained with the backend's
`server/docs/DEPENDENCIES.md` from #7; the Agent uses the identical image digest.

Primary license references:
- https://docs.python.org/3.12/license.html
- https://hub.docker.com/_/python
- https://github.com/PyCQA/pyflakes/blob/3.4.0/LICENSE
- https://github.com/PyCQA/pycodestyle/blob/2.14.0/LICENSE
