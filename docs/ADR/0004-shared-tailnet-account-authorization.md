# ADR 0004: Shared Tailnet Account and Per-Person Application Credentials

Status: Accepted
Date: 2026-09-20

Recorded for Issue #6 (Owner authorization / trusted Tailscale identity) and enforced by Issue #10 (human access enforcement). The shared research-room Tailscale account and the requirement for per-person application credentials are deployment constraints stated by the repository owner; this ADR takes effect when the owner merges the pull request that adds it. Issue #6 stays Open until its implementation and manual verification land, so this ADR records the decision only, not its enforcement.

Relationship to ADR-0003 (*Owner authentication and the trusted human-access boundary*, also Issue #6): this ADR records the deployment constraint — one shared Tailscale account — and the resulting decision to authorize on a per-person ServerSentinel credential, while ADR-0003 works out the implementation boundary around it (owner bootstrap and recovery, the trusted-proxy path, and session/revocation mechanics). Where the two overlap, a verified Tailscale/trusted-proxy identity is supplementary under this ADR and never sufficient on its own.

ADR-0003 arrives with a separate open pull request for Issue #6 and is therefore not in the repository yet; the number is reserved for it, which is why this record is 0004. ADR-0003 is `Proposed`, so the concrete parameters of that boundary — including session idle/absolute lifetimes and the exact identity-header handling — are settled there and in Issue #6, not here. Until it lands, treat the references to ADR-0003 below as pointing at that pending record.

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

### 2. ServerSentinel issues a per-person credential

ServerSentinel issues and verifies its own per-person credential:

- created by an owner invitation carrying a short-lived, single-use enrollment code;
- stored as `principal_credential` bound to one `access_principal` (`SPECIFICATION.md` §11.4);
- revocable individually, and revoked as a whole with its principal.

**WebAuthn/passkey is the selected mechanism.** Replacing it requires a superseding Owner-approved ADR.

Revocation is credential-scoped, not device-scoped. A synced passkey is a single credential that can exist on several of its owner's devices, so revoking it applies everywhere it synced and losing one device does not by itself isolate a credential. The product describes revocation and labels accordingly; a deployment that needs device-scoped control registers device-bound authenticators and refuses backup-eligible credentials, which is a deployment setting rather than a default promise.

### 3. The credential must be bound to a person, not to a workstation

A passkey alone does not separate people who share a machine. Therefore:

- authenticator user verification (local PIN, device unlock, or on-device biometric) is REQUIRED at registration and at every authentication;
- the authenticator MUST be one the invited person controls. On a machine whose OS account or device unlock is shared, a platform authenticator stored in that shared profile is a **shared** credential and does not satisfy this ADR; that deployment uses a per-person OS account or a portable authenticator the person carries;
- a session is bound to the credential that created it and ends on a bounded idle lifetime and a bounded absolute lifetime, with an explicit sign-out available for shared machines.

### 4. Bootstrap and enrollment are the only pre-credential paths

A credential check cannot apply to the request that creates the first credential, so the exceptions are enumerated and closed: the initial owner bootstrap (a privileged local administrative action on the Main Server, never a remote first-visitor route), invitation redemption against a valid short-lived single-use enrollment code, and the authentication/assertion route itself. Every other human/media route requires a verified credential and an active session.

Redemption is rate-limited, registers exactly one credential for the named principal, returns no camera/recording/timeline/deployment data, and grants no application access on its own; the invited person authenticates afterwards like anyone else. An absent, unknown, expired or already-redeemed code gets the same generic response as an uninvited person, and logs never carry the raw code.

### 5. Owner operations need a fresh user verification

The AUTH-008 owner operations require a user verification newer than a bounded freshness window, so a long-lived or unattended owner session cannot revoke users, change retention/security settings or delete recordings by itself. A failed, cancelled or declined step-up leaves the operation unperformed, changes no state and returns only the generic failure. The exact freshness window is a parameter of ADR-0003/Issue #6.

### 6. Device approval is not person identification

Device-scoped approval may be offered as an additional restriction, but the product MUST NOT describe approving a device as identifying a person.

### 7. Both access gates stay, with changed roles

The two-gate rule is unchanged: a network-level private/Tailscale permission path **and** ServerSentinel application authorization are both required. What the shared account changes is that the network gate no longer distinguishes individuals, so it MUST NOT be presented as the barrier that keeps an uninvited person out. Every human route therefore verifies the application credential and the requested permission server-side.

`live:view` and `recordings:view` remain independent, `recordings:view` keeps historical timeline/events, and non-owner recording access stays browser playback only. This ADR does not change them.

### 8. Pre-authentication disclosure

Before authentication succeeds, responses follow `REQUIREMENTS.md` AUTH-010: generic and non-branding, with no product/version string, camera names or counts, API schema, health detail, recording or timeline data, or other deployment metadata. The credential prompt itself carries none of them. An uninvited person and a revoked person receive the **same** response.

### 9. Credential data is not biometric data

Authenticator user verification runs on the viewer's own device and reaches the server as the authenticator's user-verification flag. ServerSentinel verifies the transient data a WebAuthn registration or assertion carries — its own challenge, client data, authenticator data, the attestation or assertion signature, the signature counter, the user-verification flag, and the relying-party id and origin — and persists only public credential material (credential id and public key) plus owner-visible metadata: label, created/last-used/revoked timestamps. The rest is discarded once verified.

No viewer fingerprint or face template reaches the server; it never leaves the authenticator. `principal_credential` is an access-control record; it is unrelated to the optional owner face verification and never becomes a non-owner identity or biometric database.

Relying-party verification assumes ServerSentinel owns its browser origin, so this ADR requires one: the dashboard is served from an origin reserved for it, with no other application sharing it, because a co-hosted application on that origin would put the credential within its reach. The pending ADR-0003 records the same reservation from the owner-authentication side; if it lands with a different arrangement, this decision is what has to be revisited with it.

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
- The dashboard needs an origin of its own: relying-party verification only means something while no other application shares it, which constrains how the deployment serves the UI.
- Revocation is credential-scoped, so neither the UI nor the documentation may offer "revoke this device"; a deployment that needs device-scoped control must register device-bound authenticators.
- Node-level concealment remains outside the application: with unchanged Tailnet policy the Main Server node and its listening service may stay visible and reachable to everyone holding the shared account, which is the expected state rather than an incident.

## Validation

- `MANUAL_TEST.md` "Shared Tailscale account" covers two people on the same Tailscale login, user verification, signed-out refusal, generic and identical responses for uninvited/revoked, per-credential versus per-principal revocation, session timeout and sign-out.
- Automated tests for Issue #10 must cover: no human route authorizing on a proxy identity header alone, credential verification on every human/media route, `live:view` / `recordings:view` isolation including historical timeline, prompt revocation at both levels, and identical generic pre-authentication responses.
- They must also cover the pre-credential paths and the step-up: enrollment succeeds once and only with a valid unexpired code; absent/unknown/expired/redeemed codes return the same generic response; enrollment alone returns no application data; an AUTH-008 owner operation is refused without a fresh user verification; and a failed or cancelled step-up performs nothing and leaks nothing.

## Follow-up

- Issue #10 implements and tests the credential gate; `docs/INITIAL_ISSUES.md` Plan 17 acceptance carries it.
- WebAuthn library selection follows the dependency-license rules of `AGENTS.md` §13.
- Recovery when an owner loses every authenticator (local owner bootstrap) is specified with Issue #6 implementation and is not decided here.
