# ADR 0004: Shared Tailnet Account and Per-Person Application Credentials

Status: Proposed
Date: 2026-09-20

## What this status covers

This record is Proposed and awaits the Owner's decision. Its companion
[ADR-0003](0003-owner-authentication-and-trusted-proxy.md) for the same Issue #6
is already Accepted. The repository owner has stated the deployment constraint
this record is built on — the research room shares one Tailscale account — and
the direction that application authorization rests on per-person ServerSentinel
credentials; this record works that into a decision, selects WebAuthn/passkey,
and states the invariants below. ADR-0003 leaves the authoritative per-person
application credential to this separate decision.

Nothing here opens human access. ADR-0003 is already accepted, so the remaining
design decision is this ADR; after acceptance, human routes still stay closed
until Issue #10 implements and tests both records. Issue #6 stays Open until
those remaining gates are complete.

This record does not reopen ADR-0003's accepted parameters: session idle and
absolute lifetimes, the owner step-up freshness window, local bootstrap and
recovery mechanics, and exact identity-header handling. Where this record
mentions them, it applies or describes the accepted companion decision.

The division of labour: this ADR records the deployment constraint (one shared Tailscale account) and the resulting decision to authorize on a per-person credential; ADR-0003 works out the boundary around it (owner bootstrap and recovery, the trusted-proxy path, session and revocation mechanics). Where they overlap, a verified Tailscale/trusted-proxy identity is supplementary under this ADR and never sufficient on its own.

## Context

The target deployment is a research room. To reduce Tailscale cost, the room uses **one shared Tailscale account** for the whole group: several people sign in to the Tailnet with the same Tailscale login, and any of them can enroll additional devices.

Earlier documentation assumed that a verified Tailscale/trusted-proxy identity header names a person, and treated it as the external identity of an `access_principal`. That assumption does not hold here:

- the login names the shared account, not the person behind the request;
- everyone holding the shared account can reach the Main Server node and its listeners;
- an uninvited person in the room has exactly the same network position as an invited one.

ServerSentinel also does not manage Tailnet policy (ADR-0001, `SECURITY.md`), so it cannot fix this from the network side, and with unchanged Tailnet policy it cannot promise that the node itself is hidden from other Tailnet members.

Issue #6 requires an Owner-approved authorization/identity decision before human routes open. This ADR records that decision.

## Decision

### 1. Tailscale login is not the application principal

Tailscale login identity MUST NOT be the authoritative application principal and MUST NOT be the only check on any human route. A verified proxy identity header may be recorded, and may additionally be required, but never substitutes for the application credential check.

Where it is recorded, its lifecycle is defined rather than open-ended: the principal keeps at most the value last observed at authentication, overwritten each time, owner-visible only, cleared when the principal is revoked or deleted, and excluded from diagnostic exports. Longer history belongs to the audit log under its retention, and `PRIVACY.md` lists the field so nobody reads the credential inventory as the whole story.

The raw identity is not copied into sessions. Where ADR-0003 requires session
binding, the session retains only HMAC-SHA-256 over the canonical verified
identity under a deployment-local secret outside the database. Each request
recomputes and compares the binding in constant time. The binding is cleared
with session invalidation, never displayed, and excluded from diagnostics and
exports.

### 2. ServerSentinel issues a per-person credential

ServerSentinel issues and verifies its own per-person credential:

- created by an owner invitation carrying a short-lived, single-use enrollment code;
- stored as `principal_credential` bound to one `access_principal` (`SPECIFICATION.md` §11.4);
- revocable individually, and revoked as a whole with its principal.

**WebAuthn/passkey is the mechanism this record proposes.** Once the Owner accepts it, replacing it takes a superseding Owner-approved ADR.

Revocation is credential-scoped, not device-scoped. A synced passkey is a single credential that can exist on several of its owner's devices, so revoking it applies everywhere it synced and losing one device does not by itself isolate a credential. The product describes revocation and labels accordingly.

Whether a credential syncs is read rather than assumed: registration records the authenticator's backup-eligibility and backup-state flags, the owner UI shows them, and a deployment that needs device-scoped control refuses a backup-eligible registration on that signal. That is a deployment setting rather than a default promise.

Eligibility is fixed at registration. An assertion reporting a different value
is refused while the credential is atomically marked inconsistent with a fixed
owner-visible reason/timestamp and its sessions are revoked. It remains unusable
until replaced. A non-owner with no other usable credential is re-invited; an
Owner with none uses ADR-0003's privileged local bootstrap recovery. Backup
state is refreshed from every verified assertion, since a credential registered
before its first sync becomes backed up afterwards and a registration-time
snapshot would leave the owner looking at a stale answer.

### 3. The credential must be bound to a person, not to a workstation

A passkey alone does not separate people who share a machine. Therefore:

- authenticator user verification (local PIN, device unlock, or on-device biometric) is REQUIRED at registration and at every authentication;
- the authenticator MUST be one the invited person controls. On a machine whose OS account or device unlock is shared, a platform authenticator stored in that shared profile is a **shared** credential and does not satisfy this ADR; that deployment uses a per-person OS account or a portable authenticator the person carries;
- a session is bound to the credential that created it and ends on a bounded idle lifetime and a bounded absolute lifetime, with an explicit sign-out available for shared machines.

### 4. Bootstrap and enrollment are the only pre-credential paths

A credential check cannot apply to the request that creates the first credential, so exactly two HTTP routes may run without one and the pair is closed: invitation redemption against a valid short-lived single-use enrollment code, and the authentication/assertion route itself. Every other human/media route requires a verified credential and an active session.

Owner bootstrap is a privileged local administrative action on the Main Server that issues a single-use, short-lived enrollment authorization displayed only on the local console. The first owner redeems it once from a browser at the reserved origin through the same redemption path everyone else uses, so no owner-specific route and no remote first-visitor setup exist.

Redemption is rate-limited, registers exactly one credential for the named principal, returns no camera/recording/timeline/deployment data, and grants no application access on its own; the invited person authenticates afterwards like anyone else. An absent, unknown, expired or already-redeemed code gets the same generic response as an uninvited person, and logs never carry the raw code.

Both the invitation code and the bootstrap authorization are bearer authorizations on a path everyone holding the shared account can reach. They are therefore generated by a cryptographically secure random generator with at least 128 bits of entropy, stored only as a hash and compared in constant time. A readable encoding is allowed, but the floor applies to the value that is checked rather than to a shortened display form: a short code would let someone register their own passkey as the invitee, or as the first owner, before the intended recipient, and a lifetime limit with rate limiting does not repair that.

### 5. Owner operations need a fresh user verification

The AUTH-008 owner operations require a user verification newer than a bounded freshness window, so a long-lived or unattended owner session cannot revoke users, change retention/security settings or delete recordings by itself. A failed, cancelled or declined step-up leaves the operation unperformed, changes no state and returns only the generic failure. The exact freshness window is settled with ADR-0003.

The step-up is bound to the session's own credential, which matters here precisely because people share workstations: the challenge allows only the credential the session was created with, and an assertion from anyone else's passkey is refused and does not refresh the session. Without that binding, an invited non-owner who finds a stale owner session could verify with their own credential and run a privileged operation.

### 6. Device approval is not person identification

Device-scoped approval may be offered as an additional restriction, but the product MUST NOT describe approving a device as identifying a person.

### 7. Both access gates stay, with changed roles

The two-gate rule is unchanged: a network-level private/Tailscale permission path **and** ServerSentinel application authorization are both required. What the shared account changes is that the network gate no longer distinguishes individuals, so it MUST NOT be presented as the barrier that keeps an uninvited person out. Every human route therefore verifies the application credential and the requested permission server-side.

`live:view` and `recordings:view` remain independent, `recordings:view` keeps historical timeline/events, and non-owner recording access stays browser playback only. This ADR does not change them.

### 8. Pre-authentication disclosure

Before authentication succeeds, responses follow `REQUIREMENTS.md` AUTH-011: generic and non-branding, with no product/version string, camera names or counts, API schema, health detail, recording or timeline data, or other deployment metadata. The credential prompt itself carries none of them. An uninvited person and a revoked person receive the **same** response.

### 9. Credential data is not biometric data

Authenticator user verification runs on the viewer's own device and reaches the server as the authenticator's user-verification flag. ServerSentinel verifies the transient data a WebAuthn registration or assertion carries — its own challenge, client data, authenticator data, the attestation or assertion signature, the signature counter, the user-verification flag, and the relying-party id and origin — and persists only public credential material (credential id and public key), the last accepted signature counter, the authenticator's backup-eligibility and backup-state flags, and owner-visible metadata: label, created/last-used/revoked timestamps. A registration in the privacy-preserving `none` attestation format carries no attestation statement and is accepted on the strength of the other checks. The rest is discarded once verified. The counter and the backup flags are retained deliberately: the cloned-authenticator check has nothing to compare against without the counter, and the decision below about synced credentials cannot be shown or enforced without the flags.

No viewer fingerprint or face template reaches the server; it never leaves the authenticator. `principal_credential` is an access-control record; it is unrelated to the optional owner face verification and never becomes a non-owner identity or biometric database.

Relying-party verification assumes ServerSentinel owns its browser origin, so this ADR requires one: the dashboard is served from an origin reserved for it, with no other application sharing it, because a co-hosted application on that origin would put the credential within its reach.

Reserving the origin is a deployment obligation — a dedicated network identity, or a single-purpose node enforced outside the application — because a directly bound listener never appears in proxy configuration. [ADR-0003](0003-owner-authentication-and-trusted-proxy.md) states the reservation in full: the name serves ServerSentinel alone on every scheme and port, since path co-hosting shares one browser origin and another port of the same name still shares the cookie scope. ServerSentinel checks it at startup and at least daily by enumerating real listeners and proxy routes for the whole name, and closes human access and notifies the Owner on any other answer. That bounds the exposure window rather than preventing the bind: a process binding between two checks can receive credentials and cookies for that origin until the next check.

The origin must be a secure context — HTTPS, or `http://localhost` for a strictly local browser — because browsers expose WebAuthn only there. A private-network path that terminates plain HTTP on a non-loopback host would leave the owner and every invitee unable to register or authenticate at all.

## Alternatives

- **Keep Tailscale login as the principal.** Rejected: in this deployment it authorizes every holder of the shared account, including uninvited people.
- **Ask the room for per-person Tailscale accounts.** Rejected by the Owner on cost grounds; it is also outside what the application can require.
- **Tighten Tailnet ACLs/Grants instead.** Rejected: ServerSentinel does not modify Tailnet policy (ADR-0001), and with one shared account the policy cannot separate the people using it either.
- **Device-only approval.** Rejected: a shared lab machine is used by whoever sits at it, so device approval would be described as identifying a person when it does not.
- **Password/OTP credential.** Not selected as the default: WebAuthn/passkey with required user verification gives phishing-resistant, individually revocable, per-person credentials without a shared secret to leak. A superseding ADR may revisit this.

## Consequences

- Human routes stay closed until the credential check of Issue #10 exists; trusted-proxy identity plus invitation plus permission is no longer a sufficient acceptance contract.
- The data model gains `principal_credential` and enrollment/revocation flows, and the owner access UI gains per-credential listing and revocation.
- Shared lab machines need a per-person OS account or portable authenticators; this is a deployment/setup obligation recorded in `docs/SETUP.md` and `MANUAL_TEST.md`.
- ServerSentinel cannot detect a credential its holder deliberately lends, a session left unlocked on an unattended machine, or an authenticator registered into a shared profile against this ADR. These limits are documented, not claimed away.
- The dashboard needs an origin of its own, reserved by the deployment per ADR-0003 and served as a secure context: relying-party verification only means something while no other application shares the name, and WebAuthn is unavailable outside HTTPS or localhost. The startup and daily check closes access on any other answer but cannot prevent the bind.
- Revocation is credential-scoped, so neither the UI nor the documentation may offer "revoke this device"; a deployment that needs device-scoped control must register device-bound authenticators.
- Node-level concealment remains outside the application: with unchanged Tailnet policy the Main Server node and its listening service may stay visible and reachable to everyone holding the shared account, which is the expected state rather than an incident.

## Validation

- `MANUAL_TEST.md` "Shared Tailscale account" covers two people on the same Tailscale login, user verification, signed-out refusal, generic and identical responses for uninvited/revoked, per-credential versus per-principal revocation, session timeout and sign-out.
- Automated tests for Issue #10 must cover: no human route authorizing on a proxy identity header alone, credential verification on every human/media route, `live:view` / `recordings:view` isolation including historical timeline, prompt revocation at both levels, and identical generic pre-authentication responses.
- They must also cover the pre-credential paths and the step-up: enrollment succeeds once and only with a valid unexpired code; absent/unknown/expired/redeemed codes return the same generic response; enrollment alone returns no application data; an AUTH-008 owner operation is refused without a fresh user verification; and a failed or cancelled step-up performs nothing and leaks nothing.
- They must cover proxy session bindings without retained raw identities, binding
  mismatch, clearing and export exclusion, plus the inconsistent-credential
  transaction, session revocation and both non-owner and Owner recovery paths.

## Follow-up

- Issue #10 implements and tests the credential gate; `docs/INITIAL_ISSUES.md` Plan 17 acceptance carries it.
- WebAuthn library selection follows the dependency-license rules of `AGENTS.md` §13.
- Recovery when an owner loses every authenticator (local owner bootstrap) is specified with Issue #6 implementation and is not decided here.
