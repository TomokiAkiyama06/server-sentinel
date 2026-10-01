# Owner decision: Python `cryptography` dependency

Date: 2026-09-30
Decision by: repository owner
Recorded in: Issue #10 pull request (the same approval was given for Issue #13)

## Decision

The repository owner approved adding the Python `cryptography` package as a
Main Server runtime dependency. Issue #10 uses it only to verify WebAuthn
signatures over COSE public keys (ES256, EdDSA, RS256) in
`server/app/auth/webauthn.py`; Issue #13 uses it for its mTLS adapters.

The approval is for `cryptography` itself. Its license expression
`Apache-2.0 OR BSD-3-Clause` is outside `scripts/ci/license_gate.py`'s direct
permissive allowlist, so `license/owner-approvals.json` records this exact
component (`pypi:cryptography@50.0.1`).

No other new dependency is approved by this decision. In particular a
WebAuthn/FIDO library (`webauthn`/py_webauthn, `fido2`) is not added.

## `cffi` (MIT-0): allowlist extension

`cryptography` requires `cffi` on CPython. `cffi` 2.1.1 ships the MIT No
Attribution (MIT-0) license, which was outside the gate's allowlist. On
2026-09-30 the repository owner decided to add the exact SPDX id `MIT-0` to the
permissive allowlist of `scripts/ci/license_gate.py` (and the preferred
families in `docs/THIRD_PARTY_POLICY.md`), rather than recording a per-package
approval. The gate matches the exact id only; a variant spelling or an
expression containing `MIT-0` still needs its own approval. `pycparser` 3.0
(BSD-3-Clause) was already within the allowlist.

## Evidence

- Exact pins, wheel hashes and notices: `server/requirements.lock`,
  `server/docs/wheel-audit.json`, `server/docs/rust-audit.json`,
  `server/docs/DEPENDENCIES.md` ("Issue #10 addition").
- Agent lock (Issue #13): `agent/requirements.lock`,
  `agent/docs/cryptography-wheel-audit.json`, `agent/docs/DEPENDENCIES.md`.
- This is the only approval record for `pypi:cryptography@50.0.1`; Issue #10
  and Issue #13 share it, the same lock pins and the same notices.

## Issue #13 scope (capture-node mTLS)

The approval given for Issue #13 covers, on the conditions above (one exact
version, SHA-256 hashes for every permitted wheel, offline license gate, single
approval record):

- Main Server: deployment-local capture-node CA, node client certificate
  issuance bound to the pairing ledger, Main ingest server certificate, and the
  ingest-listener `ssl.SSLContext` and peer-certificate admission adapter.
- `media-capture-agent`: node key generation, CSR (proof of possession),
  deployment trust-bundle parsing, issued-credential validation and the client
  `ssl.SSLContext`. Only `media_capture_agent.node_tls` imports it. The Agent
  continues to run as a dedicated non-root account and gains no network
  listener, GUI, Tailscale or administrative requirement.
- TLS itself remains the Python standard library `ssl` module; `cryptography`
  is not used for the record layer.

Media transport selection (Issue #15) or any other new use of `cryptography`
needs its own review.
