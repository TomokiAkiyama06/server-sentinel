# Security Policy

## Security philosophy

ServerSentinel handles camera/audio streams, biometric owner verification, private network endpoints, physical-security events, and persistent recordings.

Safe defaults:
- local/self-hosted;
- no developer cloud;
- no public Internet exposure by default;
- least privilege;
- explicit deployment-owner authorization;
- explicit Web Camera Node pairing;
- explicit local camera activation;
- no secrets or real monitoring media in source control.

## Threat model

Primary threats:

1. Unauthorized remote dashboard/media access.
2. Unauthorized Web Camera Node pairing or source registration.
3. Device/source substitution (a different USB camera silently taking an old source identity).
4. Theft/tampering of the monitored server or cameras.
5. Secret leakage through logs/Git/diagnostics.
6. Malicious media upload/path traversal/resource exhaustion.
7. Recording filesystem exhaustion.
8. Browser Camera Node suspension being mistaken for healthy monitoring.
9. Biometric owner-template disclosure or misuse.
10. False-positive/false-negative vision results creating false confidence.
11. Dependency/model/supply-chain compromise.
12. Slack/Tailscale credential disclosure.

Out of scope as guaranteed prevention:
- physical destruction/removal of the Ubuntu recorder/storage;
- guaranteed browser capture after screen lock/browser termination/device shutdown;
- compromise of the deployment owner's admin device/Tailnet/browser profile;
- nation-state endpoint compromise;
- proving guilt/culpability from camera correlation.

## Development-repository trust boundary

The product threat model is separate from GitHub development security.

Until Issue #4 establishes hardened repository-level enforcement:
- same-repository write access is a trusted-maintainer capability;
- external/untrusted contributors use fork PRs;
- Codex + Claude current-HEAD review is a mandatory operational merge policy enforced by the repository owner/merge agent;
- ordinary `GITHUB_TOKEN` statuses/check names are not treated as unforgeable against a malicious same-repository writer;
- the merge actor verifies both reviews cover the current PR HEAD;
- before additional write collaborators are granted access, Issue #4 must establish stronger Ruleset/required-workflow/dedicated-issuer enforcement.

Claude review receives PR diff/repository context. Contributors must never put user recordings, real-person media, biometric templates, secrets, or private deployment data in PR content.

## Network defaults

- Do not recommend router port forwarding as normal setup.
- Dashboard remote reachability should use Tailscale or equivalent private networking.
- Camera/server traffic should remain local/private where practical.
- Web Camera Node browser capture requires a secure context; normal setup must provide a legitimate HTTPS/private-origin path rather than telling users to bypass TLS warnings.
- Bind services to the smallest necessary interfaces.
- Document firewall requirements instead of disabling firewalls.

## Deployment-owner authorization

Tailscale/Tailnet membership provides reachability; it is **not** sufficient deployment-owner authorization.

Privileged operations require owner authorization, including:
- live media access;
- playback/deletion;
- camera-source add/remove/enable/disable;
- Web Camera Node pair/revoke;
- owner biometric enroll/delete;
- presence/security settings;
- retention/storage settings;
- Slack configuration.

The exact self-hosted authorization mechanism must be locked by ADR before implementation, support recovery/revocation, and require no developer-operated identity service.

Do not trust arbitrary forwarded identity headers. Proxy-derived identity is accepted only from an explicitly trusted/verifiable proxy path.

## Local UVC camera security

Local discovery is not equivalent to owner approval.

- only owner-authorized devices become active sources;
- prefer stable hardware identity over `/dev/videoN` ordering;
- after disconnect/reconnect, do not silently attach a different physical camera to an existing source merely because it inherited the same numeric device path;
- container/device access should be narrowly scoped;
- do not require privileged containers solely for webcam access.

## Web Camera Node pairing

Pairing tokens:
- cryptographically random;
- single-use;
- short-lived;
- owner-approved;
- redacted from logs.

Long-term browser-node identity:
- unique/revocable per node;
- deployment-scoped;
- should prefer browser-origin-bound/non-exportable key material through Web Crypto/IndexedDB where practical;
- must not be hard-coded;
- must not rely on a developer account.

Do not store long-lived privileged bearer credentials in plain browser `localStorage` when a safer browser-supported approach is practical.

## Browser lifecycle

A Web Camera Node can stop because of OS/browser behavior. Health state must fail visibly rather than implying continuous monitoring.

Track, where possible:
- heartbeat;
- media track ended/muted;
- connection state;
- page visibility/suspension state;
- reconnect attempts.

Wake Lock is best-effort, not a security boundary.

## Owner biometric security

Owner-only face verification processes sensitive biometric data.

Requirements:
- raw owner template/embedding is never logged;
- general settings/list APIs do not return raw biometric material;
- diagnostics exclude it by default;
- enrollment/replacement/deletion require owner authorization and are audited;
- storage/access is restricted to the verification/config path;
- non-owner persistent named biometric templates are prohibited in MVP;
- low-quality observations return unknown rather than a forced identity conclusion.

Model output is probabilistic and must not be presented as proof of identity or culpability.

## Secrets

Repository must never contain:
- `.env` with real values;
- Slack webhook/token;
- Tailscale auth key;
- private keys/certificates/credentials;
- real deployment IPs/hostnames/SSID/Tailnet values;
- raw owner biometric template;
- real monitoring footage or person images.

Run secret scanning in CI.

## Media ingestion

For remote uploads/streams enforce:
- authenticated node/source;
- expected session/source ID;
- size/rate limits;
- allowed format/container/codec policy;
- safe generated filenames;
- checksum/integrity metadata for durable chunks;
- no client-controlled arbitrary output path;
- bounded queues/backpressure.

For local UVC, treat device metadata as untrusted input for filenames/logging/display.

## Web/API

- typed validation;
- deployment-owner authorization for privileged actions;
- CSRF protection/considerations for cookie/browser sessions;
- safe CORS;
- no wildcard credential policy;
- rate limiting for pairing/auth-sensitive endpoints;
- strict path validation;
- no shell interpolation from request values;
- security headers appropriate to camera/dashboard routes;
- camera-node pages must not expose privileged dashboard actions merely because the node is paired.

## Filesystem/storage

Recording root is configured by the owner, but per-request arbitrary absolute paths are forbidden.

Resolve/validate all writes/deletes against configured roots.

Preserve a hard filesystem safety reserve and enter explicit pressure/hard-stop states before unsafe writes.

## Docker

Avoid privileged containers unless explicitly justified/approved.

Mount only required paths/devices. Do not mount the Docker socket into application containers.

## Vision/timeline interpretation

ServerSentinel separates observations from conclusions.

Allowed examples:
- `Person observed at entrance 17:43`;
- `Server movement detected 17:55`;
- `Camera went offline 17:56`.

Do not automatically transform temporal correlation into `suspect`, `attacker`, `thief`, or causal attribution.

## Dependency security

See `docs/THIRD_PARTY_POLICY.md`.

Computer-vision source code and model/weight licenses are reviewed separately. Vulnerability findings must be triaged rather than blindly upgrading security-sensitive dependencies.

## Reporting a vulnerability

Before a public release contact process is established, use a private contact method defined by the repository owner rather than opening a public Issue containing exploit details.

A public security contact address/process should be added before broad adoption.
