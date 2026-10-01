# WebAuthn dependency decision — Issue #10

Status: **decided 2026-09-30.** No WebAuthn/FIDO library is added.

## Decision

The relying-party ceremony (registration and assertion verification) is
implemented in-repo in `server/app/auth/webauthn.py`. The only new runtime
dependency is the Python `cryptography` package, which the Owner approved on
2026-09-30, plus its required transitive packages `cffi` and `pycparser`. It is
used solely to verify signatures over COSE public keys:

- ES256 (COSE alg -7, ECDSA P-256 / SHA-256);
- EdDSA (COSE alg -8, Ed25519);
- RS256 (COSE alg -257, RSASSA-PKCS1-v1_5 / SHA-256).

The exact pins, wheel hashes, statically linked native content (OpenSSL,
libffi), Rust crate inventory and notice obligations are in
[`DEPENDENCIES.md`](DEPENDENCIES.md) ("Issue #10 addition"),
`wheel-audit.json`, `rust-audit.json` and
`BACKEND_THIRD_PARTY_LICENSE_TEXTS.md`.

## Not adopted

- `webauthn` (Duo Labs / py_webauthn, BSD-3-Clause) and `fido2` (Yubico,
  BSD-2-Clause) were earlier candidates. Both would be new dependencies beyond
  the Owner-approved `cryptography`, and new dependencies are not approved for
  this issue, so neither is added. Revisiting this requires a separate Owner
  decision and the full lock/license review described in `DEPENDENCIES.md`.

## Consequences

- The in-repo verifier carries the parsing burden (CBOR/COSE subset,
  authenticator data, client data) and is covered by synthetic authenticator
  tests generated in the test suite; no real credential or authenticator
  output is committed.
- Real browser/authenticator interoperability is not established by those
  tests; `MANUAL_TEST.md` holds the unverified real-device steps.
- The `cryptography` addition overlaps with the Issue #13 branch that adds the
  same package; the later of the two PRs rebases onto the other's lock and
  inventory entries.
