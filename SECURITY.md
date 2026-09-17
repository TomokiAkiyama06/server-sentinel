# Security Policy

## Security philosophy

ServerSentinel handles private video streams, optional owner biometric verification, private-network identities, physical-security events, and persistent recordings.

Safe defaults:

- local/self-hosted;
- no developer cloud;
- no public Internet exposure by default;
- least privilege;
- explicit deployment-owner authorization;
- explicit capture-node pairing;
- restrictive human-viewer authorization;
- video-only MVP;
- no secrets or real monitoring media in source control.

## Threat model

Primary threats:

1. Unauthorized dashboard/live/recording access.
2. Tailnet member treated as automatically authorized.
3. Uninvited Tailnet member discovering/reaching the ServerSentinel node unnecessarily.
4. Capture-node impersonation or credential theft.
5. Different USB camera silently taking an old source identity.
6. Theft/tampering of the monitored server/cameras.
7. Secret leakage through logs/Git/diagnostics.
8. Malicious media upload/path traversal/resource exhaustion.
9. Recording filesystem exhaustion.
10. Network/capture-node failure being mistaken for healthy monitoring.
11. Biometric owner-template disclosure/misuse.
12. Vision false positive/negative creating false confidence.
13. Dependency/model/supply-chain compromise.

Out of scope as guaranteed prevention:

- physical destruction/removal of the main recorder/storage;
- compromise of the owner's trusted admin/browser endpoint;
- concealment from Tailnet Owners/Admins or infrastructure/network administrators;
- DRM-style prevention of screen recording by an authorized viewer;
- nation-state endpoint compromise;
- proving guilt/culpability from camera correlation.

## Development-repository trust boundary

Until Issue #4 establishes hardened repository-level enforcement:

- same-repository write access is a trusted-maintainer capability;
- external/untrusted contributors use fork PRs;
- Codex + Claude review of the current **HEAD and current base/diff context** is a mandatory operational merge policy;
- ordinary `GITHUB_TOKEN` statuses/check names are not treated as unforgeable against a malicious same-repository writer;
- any material HEAD or base change invalidates the prior review context;
- real monitoring media, biometric templates, secrets, and private deployment values never appear in PRs.

## Network boundaries

### Human dashboard path

Human browser traffic should use:

```text
invited browser
 -> Tailscale/private network
 -> trusted proxy / Tailscale Serve
 -> loopback-only ServerSentinel dashboard/API
```

Do not expose the same human backend listener directly to the research-room LAN when proxy-supplied Tailscale identity headers are used. Otherwise a LAN client could attempt to spoof those headers.

### Capture-agent path

`media-capture-agent` uses a **separate** LAN-facing ingest endpoint:

```text
capture node
 -> private LAN
 -> mTLS-authenticated ingest listener
```

The ingest listener:

- accepts only the capture-agent protocol;
- never serves dashboard/settings/recording-browser routes;
- requires revocable cryptographic node identity;
- is narrowly bound/firewalled;
- may additionally restrict known capture-node addresses when practical;
- never treats source IP as sufficient authentication;
- rate-limits/bounds media input and queues.

The capture machine does not need to join Tailscale merely to forward video over the same private LAN.

## Human authorization

### Two-gate rule

Tailnet membership is **not** ServerSentinel authorization.

A user must have both:

1. a Tailscale/private-network permission path to the main node; and
2. an active ServerSentinel principal/invitation with the required permission.

### Tailscale visibility objective

Configure restrictive Tailscale Grants/access policy so ordinary Tailnet members who are not intended ServerSentinel users receive no grant to the main node. Where Tailscale peer-map trimming applies, those users should not normally discover the node through peer/status visibility.

Do not claim this hides the machine from Tailnet Owners/Admins or infrastructure administrators.

MVP does not require ServerSentinel to hold Tailscale administrative credentials or automatically mutate Grants. Manual Tailnet-level membership/policy management is acceptable and preferred over introducing a powerful admin token without need.

### Application allowlist

Even when a network connection reaches the trusted human proxy/backend, ServerSentinel serves no deployment metadata until the external identity is matched to an active application principal.

Unauthorized identities must not receive:

- camera names/counts;
- thumbnails;
- live streams;
- recording metadata/playback;
- event/timeline details;
- storage/server configuration.

### Granular permissions

Initial invited-user permissions:

```text
live:view
recordings:view
```

They are independent.

Only the owner may manage invitations/permissions, cameras/capture nodes, owner biometric enrollment, destructive recording actions, retention/security settings, and other privileged configuration unless a future role model explicitly expands this.

### Recording playback

Non-owner invited users with `recordings:view` receive browser playback only in MVP. No official non-owner download/export endpoint/button is provided.

Playback segments/manifests remain authorization-protected; copying a URL does not make it public.

This is not DRM. An authorized viewer may still screen-record or use advanced client tools, and the product must not claim otherwise.

### Timeline

Historical timeline access is not implied by `live:view`. Whether `recordings:view` includes timeline/history or a separate `timeline:view` permission is required is a pending product decision.

### Revocation

Application permission revocation invalidates active application access promptly. Tailnet network access must also be revoked separately when applicable unless a future approved integration automates both layers.

## Trusted proxy identity

Do not trust arbitrary forwarded identity headers.

If Tailscale Serve/equivalent provides authenticated identity headers, the backend accepts them only on a non-bypassable local trusted-proxy path. Requests from LAN/other interfaces cannot directly set such headers and gain identity.

## Capture-node pairing

Pairing credentials:

- cryptographically random;
- short-lived;
- single-use;
- explicitly owner-approved;
- redacted from logs.

After pairing:

- each capture node has a unique revocable deployment-scoped credential/keypair;
- mTLS is the default long-lived design target;
- a capture-node credential authorizes only capture-node protocol actions, never dashboard/admin actions;
- certificate/key material is stored with restrictive filesystem permissions;
- revocation is auditable.

## `media-capture-agent` privilege boundary

Normal operation runs as a dedicated non-root account and has only:

- required UVC/video device access;
- agent config/credential access;
- bounded temp/buffer access if later enabled;
- outbound/agent network capability.

It has no reason to require the Docker socket or broad filesystem/root access.

The service name `media-capture-agent` is intentionally functional and non-deceptive. It may run without visible desktop UI/tray, but must not impersonate unrelated OS/vendor software.

## Local UVC/source substitution security

Discovery does not equal approval.

- prefer stable hardware identity over `/dev/videoN`;
- never pretend vendor/product/capability metadata is unique when identical non-serial devices cannot be distinguished;
- after ambiguous reconnect, fail to `manual_intervention_required` rather than selecting a candidate;
- explicit owner re-approval is required before healthy monitoring resumes;
- device metadata is untrusted for filenames/logging/display.

## Clock/timeline integrity

Capture-node and main-host clock offset is monitored. Large offset becomes a degraded state. Do not silently present misordered timestamps as trustworthy security chronology.

## Owner biometric security

Owner-only verification requirements:

- raw owner template/embedding never logged;
- normal settings/list APIs do not return raw biometric material;
- diagnostics exclude it by default;
- enrollment/replacement/deletion require owner authorization and are audited;
- non-owner persistent named biometric templates are prohibited;
- low-quality observation returns `unknown`, not a forced identity conclusion.

Model output is probabilistic and is not proof of identity or culpability.

## Video-only MVP

Do not open microphone/audio streams by default. `media-capture-agent` MVP is video-only. No event decision depends on audio.

## Secrets

Repository must never contain real:

- `.env` secrets;
- Slack webhook/token;
- Tailscale auth/admin key;
- private keys/certificates/credentials;
- private deployment IP/hostname/SSID/Tailnet values;
- owner biometric template;
- real monitoring footage or person images/audio.

Run secret scanning in CI.

## Media ingestion

For remote-agent media enforce:

- authenticated node/source/session;
- size/rate limits;
- bounded queues/backpressure;
- allowed codec/container policy;
- generated safe filenames;
- integrity/gap metadata where applicable;
- no client-controlled arbitrary output path;
- explicit degraded/offline state on known loss.

## Web/API

- typed validation;
- permission checks server-side for every media/API route;
- CSRF/session protections as applicable;
- safe CORS;
- no wildcard credential policy;
- rate limiting on pairing/auth-sensitive endpoints;
- strict path validation;
- no shell interpolation from request values;
- appropriate security headers;
- media URLs never become public bearer links with uncontrolled lifetime.

## Filesystem/storage

Recording root is configured by the owner; per-request arbitrary absolute paths are forbidden.

Preserve a hard filesystem safety reserve and enter explicit pressure/hard-stop states before unsafe writes.

## Vision/timeline interpretation

Allowed observations include:

- `Person observed at entrance 17:43`;
- `Server movement detected 17:55`;
- `Camera went offline 17:56`.

Do not convert temporal correlation into `suspect`, `attacker`, `thief`, guilt, or causal attribution.

Each detector must fail unknown when input quality is insufficient. A person detector that did not run reliably must never produce a trustworthy `no person` conclusion.

## Repository media policy

Repository/CI media fixtures are synthetic/generated only. Real-person or real-environment media is not committed or attached to GitHub, even if publicly licensed or consented. External real-person datasets may be used only locally under their terms and are not repository fixtures.

## Dependency security

See `docs/THIRD_PARTY_POLICY.md`. Computer-vision code and model/weight licenses are reviewed separately.

## Reporting a vulnerability

Before a public security contact process is established, use a private contact method defined by the repository owner rather than a public exploit-detail Issue.
