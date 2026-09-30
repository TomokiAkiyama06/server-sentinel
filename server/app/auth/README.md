# Human Authorization

Owns owner invitations/allowlists, independent `live:view` and `recordings:view` permissions, owner-only operations, and prompt revocation.

- Accepts Tailscale/trusted-proxy identity only through a non-bypassable local listener boundary; ordinary LAN clients cannot supply trusted identity headers directly.
- Requires application authorization in addition to private-network reachability. Tailnet membership alone grants no access.
- Treats a verified Tailscale/trusted-proxy identity as supplementary: the deployment shares one Tailscale account, so authorization requires the requesting principal's own ServerSentinel credential (WebAuthn/passkey, ADR 0004) on every human route. No route authorizes on an identity header alone.
- Verifies the transient WebAuthn data a registration or assertion carries (challenge, client data, authenticator data, signature, signature counter, user-verification flag, relying-party id and origin) and persists only public credential material, the signature counter, the backup-eligibility and backup-state flags, and owner-visible metadata. No viewer biometric template reaches the server; it never leaves the authenticator.
- Relies on the dashboard owning its browser origin, with no other application sharing it, and on that origin being a secure context (AUTH-012); browsers withhold WebAuthn elsewhere. Reserving the name is a deployment obligation (ADR-0003), and the startup/daily check over real listeners and proxy routes closes human access and notifies the Owner rather than preventing the bind.
- Treats revocation as credential-scoped rather than device-scoped, and persists the last accepted signature counter so the clone check has something to compare against. The comparison runs whenever the stored or received counter is non-zero, so a received 0 after a stored non-zero is a regression; only a stored-and-received 0 is exempt.
- Accepts `none` attestation at registration, verifying the challenge, origin/relying-party id, authenticator data, credential public key and user-verification flag instead; a present-but-invalid attestation statement fails.
- Records the authenticator's backup-eligibility and backup-state flags with the credential so the owner UI can show whether it syncs, and refuses a backup-eligible registration where the deployment requires device-bound credentials. Eligibility is fixed at registration and a differing value in a later assertion is refused and reported; backup state is refreshed from every verified assertion.
- Keeps at most the last observed proxy identity on the principal: optional and non-unique (every holder of the shared account presents the same login), owner-visible, overwritten each authentication, cleared on revocation or deletion, out of diagnostic exports, and never an authorization input. Sessions keep only its deployment-keyed HMAC binding.
- Supports revoking a single credential and revoking a whole principal, and binds sessions to the credential that created them.
- Exposes exactly two pre-credential routes, enrollment-code redemption and authentication; local owner bootstrap is a host-side action that issues an authorization for the same redemption route rather than a third endpoint. They return no application data, redemption is single-use and rate-limited, an absent/unknown/expired/redeemed code gets the uninvited response, and enrollment codes stay out of logs.
- Generates enrollment codes and bootstrap authorizations from a CSPRNG with at least 128 bits of entropy in the checked value, stores only their hash and compares in constant time; lifetime and rate limits bound guessing but do not replace the entropy.
- Requires a fresh user verification for owner-only operations. Freshness comes from the server-side session record, a stale owner session receives a distinct step-up-required response with no other data, and a cancelled or failed step-up changes nothing. Unauthenticated, uninvited and revoked requests keep receiving the generic response.
- Binds the step-up to the session: the challenge allows only `principal_session.credential_id`, and an assertion from any other registered credential is refused without updating the session's verification time.
- Keeps historical events/timeline under `recordings:view` and provides generic, non-branding denial for uninvited identities.
- Does not modify Tailscale ACLs/Grants, store Tailscale administrative credentials, or treat an agent identity as a human/admin identity.
- Separates general human/system access from Owner-only access. `require_owner_access` is an independent gate for Owner-only routes such as diagnostic export; an authorizer that implements no Owner check is denied rather than treated as the Owner.

## Current foundation

ADR-0004 (per-person WebAuthn/passkey credentials) was accepted on 2026-09-30,
alongside ADR-0003. No human route is mounted yet: route mounting stays closed
until the remaining Issue #10 gates pass.

- `webauthn.py` is pure relying-party verification over the Owner-approved
  `cryptography` package, with no WebAuthn/FIDO library. It checks the
  `clientDataJSON` type, challenge, exact origin and cross-origin markers; the
  relying-party id hash; the UP and UV flags; the BE/BS flags (BS without BE is
  malformed); the COSE key (ES256/P-256, EdDSA/Ed25519, RS256 with at least
  2048 bits); `none` attestation, or `packed` self attestation with its
  signature verified; and the assertion signature. Other attestation formats,
  including `packed` with a certificate chain, are refused rather than accepted
  unverified. CBOR parsing is strict and bounded. `RelyingParty` accepts only
  a secure-context origin (`https://host[:port]` or `http://localhost[:port]`)
  whose host equals the relying-party id. An explicit default port (`:443`
  for https, `:80` for http) is refused at construction, because browsers
  serialize `clientDataJSON.origin` without it and the exact comparison could
  never match.
- `passkeys.py` (`PasskeyCeremonies`) composes that verifier with the store:
  invitation redemption (registration), sign-in (authentication) and Owner
  step-up. Every failure before a session exists is one `CeremonyDenied` with
  a fixed message and no chained cause. There are only two distinct outcomes:
  `StepUpRequired`, returned only to a valid but stale Owner session, and
  `DeviceBoundCredentialRequired`, returned only after a verified ceremony
  with a valid invitation, where the deployment requires device-bound
  credentials.
- `store.py` persists challenge digests only. Each challenge is single-use,
  bound to its ceremony, and to its invitation or session where the ceremony
  has one. It is deleted on use or expiry, and a backward clock step refuses
  it. The store also enforces the counter rule, marks a credential whose BE
  changed as inconsistent and revokes that credential's sessions in the same
  transaction, and establishes sessions with the ADR-0003 lifetimes (30 minutes
  idle, 12 hours absolute). A session records its user-verification time, and
  `authorize_owner` enforces the ADR-0003 five-minute step-up freshness. A
  session created by the low-level `establish_session` records no verification
  time, so it is never fresh.
- Shared Tailscale login (ADR-0004 §1, SPECIFICATION §11.4/§11.8): the
  invitation and the passkey credential are the only per-person key. An
  invitation carries no proxy identity, the enrollment secret alone selects
  the invitation, and the discoverable credential alone selects the principal
  at sign-in, so several invited people behind one Tailscale login each
  register and sign in with their own passkey. `access_principals.external_identity`
  is nullable and non-unique (migration 18): it holds only the identity last
  observed at authentication, is overwritten on every sign-in and step-up, is
  cleared on principal revocation, and is never compared with anything.
- Session binding (`session_binding.py`): every ceremony and session check
  requires a present, well-formed trusted-proxy identity (ADR-0003 rejects a
  missing human identity). A session stores only
  `HMAC-SHA-256(key, canonical identity)` in `external_identity_binding`,
  never the raw value, and each later request recomputes it and compares in
  constant time. The binding is cleared whenever the session is invalidated
  (revocation, grant change, inconsistent credential) and, for sessions past
  their idle or absolute lifetime, at the next session establishment. The
  deployment-local key is a 32-byte file (`Settings.session_binding_key_path`)
  created once with mode `0600` in a directory owned by the service account
  and not group/other writable; a wrong owner, mode, link count, size or a
  symlink fails closed rather than being repaired or replaced. The key never
  enters the database, logs, errors, `repr`, pickling or diagnostics, and an
  `AccessStore` without it establishes and accepts no session.
- Binding mismatch policy (conservative choice pending Owner confirmation):
  a request whose identity does not reproduce the binding receives the generic
  denial for that request only. The session is neither revoked nor sent to
  step-up, and nothing is audited, because in the shared-account deployment a
  mismatch cannot identify a person and revoking on it would let anyone with a
  stolen cookie sign its holder out. The binding is therefore a necessary
  consistency signal, never an authorization input.
- Audit: sign-in (`authenticate_principal`), step-up
  (`verify_principal_step_up`), an inconsistent credential
  (`mark_principal_credential_inconsistent`) and a counter regression
  (`detect_principal_credential_sign_count_regression`) commit their records
  in the same transaction as their effect. As with redemption, an attempt that
  matches no credential writes nothing.

Not implemented yet, and required before routes open:

- the HTTP routes and their cookie handling;
- per-source rate limiting (only the per-code attempt bound exists here);
- the runtime composition that loads the session-binding key with
  `SessionBindingKey.load_or_create(Settings.session_binding_key_path)` and
  hands it to `AccessStore` (no human route constructs the store yet);
- delivery of `CredentialFindingSink` to the Owner notification channel;
- local owner bootstrap and recovery commands;
- the startup/daily listener and route reservation check.

Owner-only mutations — invitation, invitation issue, grant change, single
credential revocation and principal revocation — are exposed as `*_on`
methods on a caller-owned transaction and reached at runtime only through
`app.audit.integration.AccessAdministration`, which authorizes the Owner and
commits each mutation with its security audit record. The plain wrappers refuse
with `UnauditedAccessWriteError` unless the store is constructed with
`unaudited_writes=True` for non-runtime fixtures. Invitation redemption
(`enroll_credential`) records its own audit row in the redemption transaction
and therefore requires `audit=`; the log receives only the principal's logical
UUID. A redemption that matches no valid invitation records nothing and does
not affect health; when a matched redemption's audit append or commit fails,
the redemption rolls back and the lost outcome is counted in the store's
`audit_delivery_failed` / `undelivered_audit_records` health instead of being
appended separately. See `server/app/audit/README.md`.
