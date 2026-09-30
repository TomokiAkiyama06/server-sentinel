# Owner decision: `cryptography` for capture-node mTLS (Issue #13)

- Date: 2026-09-30
- Decided by: repository Owner, in the working session that implemented Issue #13
- Related: ADR-0006 (Implementation and license plan, item 4), Issue #13, Issue #14
- Recorded in: `license/owner-approvals.json`

## Decision

The Python `cryptography` package is approved as a dependency for Issue #13
capture-node certificate, CSR and private-key handling, on these conditions,
all of which this change applies:

1. the release is pinned to one exact version with SHA-256 hashes for every
   permitted wheel (`server/requirements.lock`, `agent/requirements.lock`);
2. it passes the offline license gate (`scripts/ci/license_gate.py`);
3. it is registered in `license/owner-approvals.json`.

The approved release is **cryptography 50.0.1** (`Apache-2.0 OR BSD-3-Clause`,
used under Apache-2.0). Its license expression is a disjunction of two
permissive licenses; it needs an explicit record only because the gate's
allowlist matches exact SPDX expressions.

## Scope

- Main Server: deployment-local capture-node CA, node client certificate
  issuance bound to the pairing ledger, Main ingest server certificate, and the
  ingest-listener `ssl.SSLContext` and peer-certificate admission adapter.
- `media-capture-agent`: node key generation, CSR (proof of possession),
  deployment trust-bundle parsing, issued-credential validation and the client
  `ssl.SSLContext`. The Agent continues to run as a dedicated non-root account
  and gains no network listener, GUI, Tailscale or administrative requirement.
- TLS itself remains the Python standard library `ssl` module; `cryptography`
  is not used for the record layer.

Not in scope: WebAuthn/passkey verification (Issue #10), media transport
selection (Issue #15), or any other use of `cryptography` that is not reviewed
in its own change. The Issue #10 branch (`feat/issue-10-passkey-credentials`,
PR #97) pins the same versions with byte-identical `server/requirements.lock`
entries and records the same approval under
`docs/decisions/2026-09-30-cryptography-dependency.md`. Whichever branch merges
second must keep exactly one `pypi:cryptography@50.0.1` approval record (the gate
rejects duplicates) and merge the two decision scopes.

## Transitive closure

`cryptography` 50.0.1 requires `cffi>=2.0.0` on CPython, and `cffi` requires
`pycparser`. These are pinned at `cffi` 2.1.1 and `pycparser` 3.0.

- `pycparser` 3.0 is BSD-3-Clause and passes the gate's permissive allowlist.
- `cffi` 2.1.1 declares and ships `MIT-0` (MIT No Attribution). The previous
  release 2.0.0 declares `MIT` in metadata but ships the same MIT-0 text, so an
  older pin would not avoid it. The Owner decided on 2026-09-30 to add `MIT-0`
  to the license gate's permissive allowlist. PR #97 (Issue #10) makes that
  change; this change carries the identical one-token addition so the gate
  passes on either branch, and no separate `cffi` approval record is needed.

The wheels statically link OpenSSL 4.0.2 (Apache-2.0) and 32 crates.io
packages with permissive licenses (`self_cell` is used under Apache-2.0 from
`Apache-2.0 OR GPL-2.0-only`). See `server/docs/CRYPTOGRAPHY_AUDIT.md`.

## Redistribution obligations

ServerSentinel does not vendor these wheels. A deployment or redistribution
that ships them must preserve `server/docs/CRYPTOGRAPHY_THIRD_PARTY_LICENSE_TEXTS.md`
(cryptography Apache-2.0/BSD texts, cffi MIT-0, pycparser BSD-3-Clause, the
OpenSSL Apache-2.0 license, and the Rust crate license texts).
