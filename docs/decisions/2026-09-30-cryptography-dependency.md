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

## Not covered: `cffi` (MIT-0)

`cryptography` requires `cffi` on CPython. `cffi` 2.1.1 ships the MIT No
Attribution (MIT-0) license, which is also outside the gate's allowlist. The
owner's approval named `cryptography` only, so no approval record for `cffi` is
written here. It needs an explicit owner decision — either an approval record
for `pypi:cffi@2.1.1` or adding `MIT-0` to the gate's permissive allowlist —
before the license gate can pass. `pycparser` 3.0 (BSD-3-Clause) is within the
allowlist.

## Evidence

- Exact pins, wheel hashes and notices: `server/requirements.lock`,
  `server/docs/wheel-audit.json`, `server/docs/rust-audit.json`,
  `server/docs/DEPENDENCIES.md` ("Issue #10 addition").
- Overlap: the Issue #13 branch adds the same package; whichever pull request
  merges second rebases onto the other's lock, audit and approval entries.
