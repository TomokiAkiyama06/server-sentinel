# cryptography dependency audit — Issue #13

Reviewed 2026-09-30 for the ADR-0006 capture-node mTLS adapters. Owner approval:
[`docs/decisions/2026-09-30-cryptography-mtls.md`](../../docs/decisions/2026-09-30-cryptography-mtls.md).
No model, weights, telemetry SDK or runtime download is introduced.

## Pinned closure

| Package | Exact version | License (as shipped) | Why |
|---|---|---|---|
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause (used under Apache-2.0) | X.509 CA/leaf issuance, CSR, EC P-256 keys |
| cffi | 2.1.1 | MIT-0 | Required by cryptography on CPython (`cffi>=2.0.0`) |
| pycparser | 3.0 | BSD-3-Clause | Required by cffi |

The same exact versions are pinned in [`../requirements.lock`](../requirements.lock)
(Main, scope `backend`) and [`../../agent/requirements.lock`](../../agent/requirements.lock)
(`media-capture-agent`, scope `transport`). The Main lock entries are
byte-identical to those of the Issue #10 branch (PR #97) so either branch can
rebase onto the other without a lock conflict. `wheel-audit.json` records every
wheel the Main lock permits; `../../agent/docs/cryptography-wheel-audit.json`
records every wheel the Agent lock permits. Each row carries the filename,
SHA-256, download URL and license-file hashes, all verified after download.

Main lock (`server/requirements.lock`, matching its existing platform line):

- cryptography: `cp311-abi3-manylinux_2_34` x86_64 and aarch64. The abi3 wheel
  serves CPython 3.12 and 3.14 on glibc >= 2.34 (Ubuntu 22.04+, Debian 12+).
- cffi: `cp312` x86_64 and aarch64, `cp314` x86_64 (`manylinux2014`).
- pycparser: universal `py3-none-any`.

Agent lock (`agent/requirements.lock`), wider because capture hosts are more
often aarch64 single-board computers on varied distributions:

- cryptography: `cp311-abi3` `manylinux_2_34` and `manylinux_2_28` (glibc
  2.28-2.33 fallback), each x86_64 and aarch64.
- cffi: `cp312` and `cp314`, each x86_64 and aarch64.
- pycparser: universal `py3-none-any`.

Source build fallback is disabled (`--only-binary=:all:`); musl, free-threaded
CPython (`cp314t`), PyPy, 32-bit ARM and non-Linux wheels are not permitted.
PyPI release metadata for all three exact releases reported no known
vulnerabilities on the audit date; that is not an independent CVE audit.

## Native and transitive content

- Every pinned cryptography wheel has one native module,
  `cryptography/hazmat/bindings/_rust.abi3.so`. It statically links
  **OpenSSL 4.0.2** (version string `OpenSSL 4.0.2 25 Aug 2026` found in each
  wheel). OpenSSL 3.0+ is Apache-2.0; the wheel does not ship OpenSSL's license,
  so `CRYPTOGRAPHY_THIRD_PARTY_LICENSE_TEXTS.md` reproduces it.
- The cryptography 50.0.1 sdist (`sha256:5dd9bda1c12b4162f6ff568eeb5e0ff956c28d14406e875cfe8a63a2d414ff20`)
  `Cargo.lock` resolves 40 packages: 8 cryptography workspace crates and 32
  crates.io crates. `cryptography-rust-audit.json` records every crate's exact
  version, Cargo.lock checksum (verified against the downloaded `.crate`),
  license expression and license-file hashes. Build-only and target-conditional
  crates are included conservatively.
- License families in that closure: MIT/Apache-2.0 alternatives (MIT selected),
  BSD-3-Clause (`asn1`), Apache-2.0 (`openssl`), MIT (`openssl-sys`, `pem`),
  Apache-2.0 WITH LLVM-exception (`target-lexicon`, build only),
  `(MIT OR Apache-2.0) AND Unicode-3.0` (`unicode-ident`, proc-macro build
  only), and `Apache-2.0 OR GPL-2.0-only` (`self_cell`, Apache-2.0 selected).
  No AGPL/SSPL/BSL/source-available or GPL-only obligation is taken.
- cffi 2.0.0's metadata says MIT but its LICENSE is MIT-0; 2.1.1 metadata and
  text agree on MIT-0. The Owner decided on 2026-09-30 to add `MIT-0` to the
  license gate's permissive allowlist (PR #97 makes that change; this branch
  carries the identical one-token change so its gate passes independently).

## Network and runtime behaviour

Static review of the selected packages found no telemetry or runtime download
path. cryptography performs no network I/O; TLS sockets in ServerSentinel use
the Python standard library `ssl` module, configured explicitly (no
`create_default_context`, so `SSLKEYLOGFILE` is not honoured). This is a static
review, not a network test.

## Notice obligations

Preserve [`CRYPTOGRAPHY_THIRD_PARTY_LICENSE_TEXTS.md`](CRYPTOGRAPHY_THIRD_PARTY_LICENSE_TEXTS.md)
with any deployment or redistribution that ships these wheels: Apache-2.0 notice
and license for cryptography and OpenSSL, BSD-3-Clause copyright/disclaimer and
non-endorsement for cryptography and pycparser, and the Rust crate texts.
ServerSentinel does not vendor or republish the wheels.

## Agent footprint

`media-capture-agent` imports cryptography only from
`media_capture_agent.node_tls`; the stdlib-only runtime, CLI, ring buffer and
zipapp build do not import it. How an installed Agent obtains the hash-pinned
wheels (for example a dedicated virtual environment owned by the non-root
service account) is not decided here and remains installer follow-up work.
