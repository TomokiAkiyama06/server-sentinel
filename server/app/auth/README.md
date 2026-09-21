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
- Keeps at most the last observed proxy identity on the principal: owner-visible, overwritten each authentication, cleared on revocation or deletion, out of diagnostic exports, and never an authorization input.
- Supports revoking a single credential and revoking a whole principal, and binds sessions to the credential that created them.
- Exposes exactly two pre-credential routes, enrollment-code redemption and authentication; local owner bootstrap is a host-side action that issues an authorization for the same redemption route rather than a third endpoint. They return no application data, redemption is single-use and rate-limited, an absent/unknown/expired/redeemed code gets the uninvited response, and enrollment codes stay out of logs.
- Generates enrollment codes and bootstrap authorizations from a CSPRNG with at least 128 bits of entropy in the checked value, stores only their hash and compares in constant time; lifetime and rate limits bound guessing but do not replace the entropy.
- Requires a fresh user verification for owner-only operations. Freshness comes from the server-side session record, a stale owner session receives a distinct step-up-required response with no other data, and a cancelled or failed step-up changes nothing. Unauthenticated, uninvited and revoked requests keep receiving the generic response.
- Binds the step-up to the session: the challenge allows only `principal_session.credential_id`, and an assertion from any other registered credential is refused without updating the session's verification time.
- Keeps historical events/timeline under `recordings:view` and provides generic, non-branding denial for uninvited identities.
- Does not modify Tailscale ACLs/Grants, store Tailscale administrative credentials, or treat an agent identity as a human/admin identity.
- Separates general human/system access from Owner-only access. `require_owner_access` is an independent gate for Owner-only routes such as diagnostic export; an authorizer that implements no Owner check is denied rather than treated as the Owner.

## Current foundation

`store.py` persists application principals, independent viewer permissions,
opaque credential records, single-use enrollment authorization digests, and
opaque server-side session digests. It deliberately has no HTTP route, proxy
header adapter, cookie, WebAuthn parser, signature verifier, or browser
ceremony. A future ceremony verifies its input before calling enrollment/session
methods; every request integration must still validate current state and its
required permission.
