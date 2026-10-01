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
- Overlap: the Issue #13 branch adds the same package; whichever pull request
  merges second rebases onto the other's lock, audit and approval entries.
