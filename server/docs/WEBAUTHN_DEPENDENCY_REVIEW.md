# WebAuthn dependency decision — Issue #10

Status: **recommended, not yet added**. This review does not authorize a
credential ceremony or a dependency change. The current access foundation stores
only opaque credential bytes and never parses a WebAuthn response.

## Candidate

Use `webauthn` (Duo Labs / `py_webauthn`) when the separate ceremony PR is ready.
The official project page states Python 3.10+ support and exposes the four
server-side operations needed by an RP: registration options/verification and
authentication options/verification. It is therefore a closer fit than a
client/authenticator-oriented FIDO library for this FastAPI RP.

- Official package page: <https://pypi.org/project/webauthn/>
- Official source license: <https://github.com/duo-labs/py_webauthn/blob/master/LICENSE>
- License: BSD-3-Clause. Redistribution must retain the copyright notice,
  conditions, and disclaimer; the authors/contributors' names cannot endorse a
  derivative without permission. This is compatible with the project's
  permissive-license policy, provided notices are shipped.

`fido2` from Yubico is a viable BSD-2-Clause alternative:
<https://github.com/Yubico/python-fido2/blob/main/COPYING>. It has the same
notice/disclaimer retention obligation, but `webauthn` is recommended because
its documented public interface directly maps to browser WebAuthn RP ceremonies.

## Before adding it

Pin one reviewed release in `server/requirements.lock` and
`server/requirements-ci.lock`, collect hashes, inspect the exact release's
runtime/transitive dependency graph and licenses, add all required notices to
`server/docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md`, and test registration and
assertion failure paths. The exact release must be rechecked at that time; this
document intentionally does not bless a floating version.
