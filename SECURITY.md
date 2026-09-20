# Security Policy

The #8 dashboard is a development/test shell, denied by default. Before
production use, #10 must enforce the two access gates for every API and complete
asset namespace through the human listener. Do not expose its loopback-only
preview as a deployment server. Client permission visibility is not a security
boundary; `web/README.md` records the integration contract.

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

The internal compressed-recording store accepts no caller-controlled filenames or
public requests. It requires a private, deployment-approved existing media root,
an admission reservation and a trusted video-only codec validator. It rejects
path symlinks, substituted/missing roots and competing writers; publication and
recovery operate only on generated UUID files identified by its SQLite journal.
Mandatory adapters and human authorization remain unwired; this module adds no
recording playback/download route. See `server/app/media/recording/README.md`.

The current backend foundation denies every human HTTP/WebSocket route,
including system health, version, schema and framework documentation. Its
documented launcher accepts only loopback bind settings, disables proxy-header
parsing and access logs, and removes the server product header. The authorization
adapter remains deny-all until the #6/#10 gates are met. Newly created SQLite
files use mode `0600`; deployment operators must keep their parent data directory
private. This foundation does not yet implement trusted proxy/session handling
or Agent media-root mount enforcement. Details: `server/docs/FOUNDATION.md`.

Primary threats:

1. Unauthorized dashboard/live/recording access.
2. Tailnet member treated as automatically authorized.
3. Uninvited Tailnet member obtaining application information through a reachable Main Server node.
4. Capture-node impersonation or credential theft.
5. Different USB camera silently taking an old source identity.
6. Theft/tampering of the monitored server/cameras.
7. Secret leakage through logs/Git/diagnostics.
8. Malicious media upload/path traversal/resource exhaustion.
9. Recording filesystem exhaustion.
10. Network/capture-node failure being mistaken for healthy monitoring.
11. Biometric owner-template disclosure/misuse.
12. Vision false positive/negative creating false confidence.
13. Main-host CPU/RAM/GPU/NVMe/HDD changes or disappearance going unnoticed.
14. Recorder/storage pipeline silently failing while monitoring still appears healthy.
15. Dependency/model/supply-chain compromise.

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

The dedicated-App deployment proposal and offline policy validator are documented
in [`docs/REVIEW_GATE_SETUP.md`](docs/REVIEW_GATE_SETUP.md). They do not install
enforcement or authenticate supplied JSON. App credentials must remain outside
PR-controlled workflows/checkouts; the existing same-repository Claude workflow
is still limited to trusted writers. Actual issuer isolation and GitHub test-PR
acceptance remain open in #4.

## Main Server release and installer trust boundary

The stable Main Server deployment path is the native versioned release lifecycle
in ADR-0005 and [`server/docs/DEPLOYMENT.md`](server/docs/DEPLOYMENT.md). No
Docker Compose path is implemented or advertised.

Privilege assumptions:

- the installer is a one-shot administrator tool, deliberately invoked with root
  privileges; it is never a service, is never started by the application, and
  the running application cannot invoke it;
- it refuses to run without explicit root execution, refuses any unit path other
  than the single canonical `server-sentinel.service`, and refuses a service
  account of UID 0;
- before using an installation path it rejects ancestors that are symbolic
  links, not root-owned, or group/world-writable, so an untrusted directory
  cannot later have code substituted beneath the active release;
- release environments are built with a root-controlled absolute interpreter,
  from a fixed working directory, with a sanitized environment, so a hostile
  `PYTHONPATH` or shadowing module in the administrator's current directory is
  not executed;
- the non-root preflight runs as the dedicated account with no supplementary
  groups, and directory modes are normalized independently of the administrator
  umask so neither a restrictive nor a permissive umask changes the result;
- the generated unit is created with a restrictive mode at creation time, never
  widened and then narrowed, and every unit replacement is atomic and fsynced;
- one service-global advisory lock covers each whole install, update, and
  rollback transaction, so concurrent administrator invocations cannot interleave
  release pointers, unit replacement, and restart.

Supply-chain assumptions:

- the installer performs no network access. The release archive, its published
  SHA-256, the installer zipapp digest, and the offline wheelhouse are supplied
  by the administrator;
- trust comes from content hashes, not from a transport: the outer archive
  SHA-256, the manifest version, and every member digest are verified before any
  release code executes, the archive shape is bounded, and dependencies install
  with `--require-hashes --only-binary=:all: --no-index --no-deps`;
- verifying the published digests on the target host is therefore a required
  administrator step, and a release that fails any digest check is refused
  rather than installed.

Runtime-data assumptions:

- deployment configuration is administrator-owned and readable but not writable
  by the dedicated runtime account, is refused if it is world-readable,
  group-writable, inside the installation or release tree, inside the
  runtime-writable data tree, or under any directory path component the
  administrator does not control;
- the Owner-approved runtime filesystem is pinned by a stable filesystem UUID.
  Linux major/minor device numbers are reused by a replaced or reformatted disk,
  so they only corroborate that identity. A runtime mount that is missing,
  substituted, backed by the root filesystem device, or carrying a different
  filesystem is refused, and no root-filesystem fallback directory is created;
- the generated unit grants the runtime account write access to the state,
  recording, and audit directories only. The runtime root itself stays
  read-only, so a compromised service cannot replace or remove them;
- install, update, and rollback move release pointers and the unit only; they
  never delete, truncate, or rewrite state, recordings, or audit data. A failed
  transaction restores both release pointers and the previous unit and restarts
  the release that was running before the attempt.

Release trees accumulate under the installation root. Pruning an old release is
a deliberate administrator action on the installation filesystem only, and never
touches runtime data.

Deployed acceptance of this boundary — including the systemd activation, the
trusted-proxy boundary, real mount substitution, and the recording/audit content
comparison across update and rollback — remains the `MANUAL_TEST.md` section V
checks for Issue #47 and is not established by the synthetic tests.

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

### Tailscale policy boundary

ServerSentinel does **not** modify Tailscale ACLs/Grants or store Tailscale administrative credentials; policy administration remains outside the application. Existing Tailnet policy may remain unchanged.

Therefore ServerSentinel does not claim that the underlying Main Server Tailscale node is hidden from ordinary Tailnet members. Node/peer visibility is controlled by Tailscale policy outside the application.

Application authorization remains mandatory even when the network path is reachable. For an uninvited identity, use a generic/non-branding denial and avoid exposing ServerSentinel product/version strings, API schema, health details, camera/source counts, thumbnails, recordings, or timeline data.

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

Historical timeline/event access is included with `recordings:view`. A principal with only `live:view` receives current live/source state only and cannot access historical timeline/event data.

### Revocation

Application permission revocation invalidates active application access promptly. ServerSentinel does not mutate Tailnet ACL/Grant policy as part of revocation.

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

Before sending the pairing code:

- verify the intended Main Server using public trust information obtained/checked through an Owner-controlled trusted local or out-of-band channel;
- establish an encrypted exchange with authenticated Main Server identity and integrity protection;
- never treat private-LAN location or an unverified endpoint's own claimed identity as proof of trust;
- fail closed on missing/mismatched trust or certificate validation failure, without sending the code;
- do not offer plaintext or unverified-certificate fallback.

The concrete bootstrap trust/transport method requires PoC/ADR selection before implementation. A short-lived code and post-pairing mTLS do not replace confidentiality and intended-server authentication during initial enrollment. Pairing secrets are entered through a non-echoing prompt or protected automation input, never command arguments, environment variables, URLs, or logs.

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
- bounded temp/buffer access for the configured compressed-video ring buffer and protected incidents;
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
- owner biometric processing and template storage remain deployment-local; external biometric services are not an opt-in MVP option;
- all diagnostic exports exclude owner templates/embeddings, including explicit Owner-initiated exports;
- enrollment/replacement/deletion require owner authorization and are audited;
- persistent non-owner face-template/profile libraries are prohibited, whether named or anonymous; ordinary authorized recordings may still contain people and are not a separate biometric identity library;
- low-quality observation returns `unknown`, not a forced identity conclusion.

Model output is probabilistic and is not proof of identity or culpability.

The #25 internal singleton template store requires an existing private `0700` runtime directory and `0600` regular single-link database under the service UID, outside checkout. It rejects symlinks/FIFOs/shared permissions and root/file substitution, holds an exclusive directory lock, and confines operations to one worker. Every ancestor of that root must be owned by the service or root and must not be writable by other users unless sticky, because SQLite derives rollback-journal names from the canonical path; the connection itself is bound to the verified directory descriptor and re-verified before schema writes. Metadata reservations cover transactional enrollment/delete/audit; generation checks invalidate replacement/deletion races. The default Owner authorizer denies. No human listener/route is added before #6/#10. A separate local template DB is excluded from every diagnostic archive; normal recording exports cannot include it. Permissions do not claim encryption or protection from local administrators, and logical deletion does not promise forensic erasure from snapshots/backups. Audited local model adapters and 90-day audit-retention integration remain deployment prerequisites.

## Video-only MVP

The MVP does not open microphones/audio streams or capture, store, or forward monitoring audio. This applies to local capture, `media-capture-agent`, recordings, and viewer delivery; no audio opt-in is offered in MVP. No event decision depends on audio.

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

The `CI` workflow checks tracked files for known secret formats and sensitive paths before lint/tests, and checks deterministic synthetic fixture provenance. Findings never include matched values. This is a bounded scanner, not proof that unknown credentials or private values are absent; it does not scan Git history. CI runs PR code on GitHub-hosted runners without deployment secrets, persisted checkout credentials, or artifact uploads. See `docs/CI.md` for component onboarding and test limitations. Issue #4 continues to track enforcement of review provenance.

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

The internal Main policy holds configured metadata and media reservations on one
owning worker, including recorder startup recovery. It verifies the expected
private media root and private metadata file on the same filesystem. Provisioning
must separately reserve migration space before opening runtime data. State-audit
write failure remains visible. Its recording domain facade denies by default;
invited recording viewers cannot star/delete, and no human/download route is
introduced before #10.

The optional Slack adapter accepts only deployment-configured verified HTTPS
incoming webhooks, follows no redirect, ignores environment proxies and closes
error responses. Credential URLs, remote bodies and raw exceptions never enter
its result/log surface. Unset configuration constructs no transport. Current
payloads are fixed categories/validated aggregates, without media or arbitrary
event details. Tests use generated dummy components and intercepted transports.

The Agent's normal ring buffer is bounded by Owner-selected duration or capacity mode. Protected communication-loss/critical incidents are separate from normal overwrite and expire 60 days after completion by default. Storage pressure reclaims eligible ordinary ring data first and refuses unsafe writes; it does not silently delete unexpired protected incidents.

The Agent media root is deployment-configured outside the repository. Installer/startup and runtime admission check the expected mount/filesystem/device, dedicated-account writability, free space, and safety reserve. Missing or substituted media mounts produce a visible degraded/failed state and refused unsafe writes, never silent creation of a fallback media directory on the root filesystem.

## Main-host hardware integrity and recorder self-check

The Owner approves a baseline for CPU, RAM, NVMe/M.2, HDD/recording drives, and GPU using the strongest identifiers exposed by the platform.

Security rules:

- compare inventory at ServerSentinel startup and at least daily;
- never silently update the approved baseline;
- deliberate replacements require explicit Owner approval and audit;
- do not claim same-model physical replacement detection when no stable unique identifier is exposed;
- missing/changed approved hardware produces an immediate Owner alert;
- raw hardware serials/UUIDs stay deployment-local and are redacted or hashed in normal operational logs and general diagnostics.

At least daily, run a bounded recording-health self-test that checks source freshness, recorder/encoder state, expected recording filesystem identity, free-space/safety admission, and a temporary write + fsync + reopen/read/decode path. Where available, surface SMART/NVMe critical health indicators.

Delete only self-test-owned temporary/partial media on success, failure, and cancellation. At startup, verify the expected filesystem and clean interrupted-test leftovers before new self-test media writes; never delete ordinary recordings or protected incidents. Missing/read-only storage or another cleanup failure produces an explicit failure and blocks further self-test media writes until safe cleanup succeeds. Account for leftovers in storage admission/safety reserve. Do not fall back to another filesystem, upload the artifacts, or retain them as diagnostic media.

If the intended recording filesystem is missing or substituted, refuse recording and self-test media writes to that target. Never create or use a fallback directory on the root filesystem or another unintended filesystem, even while reporting degradation. A self-test failure or material recording-device mismatch is an immediate Owner-alert condition.

Hardware inventory/SMART collection must use least privilege. If a privileged helper is needed for a narrow probe, do not grant the whole application broad root access.

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
