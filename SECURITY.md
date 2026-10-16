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

The Agent ring core's configuration/early deletion and critical-preserve controls
use separate default-deny injected authorization boundaries; no human/control
listener is added. Its private SQLite ledger journals protection/deletion before
media mutation, and the approved media store validates mount identity for writes,
inventory and cleanup. Missing/uncertain media remains a visible gap; storage
pressure cannot remove unexpired protected incidents. Production authority and
transport integration remain pending. See `agent/docs/RING_BUFFER.md`.

The internal compressed-recording store accepts no caller-controlled filenames or
public requests. It requires a private, deployment-approved existing media root,
an admission reservation and a trusted video-only codec validator. It rejects
path symlinks, substituted/missing roots and competing writers; publication and
recovery operate only on generated UUID files identified by its SQLite journal.
Mandatory adapters and human authorization remain unwired; this module adds no
recording playback/download route. See `server/app/media/recording/README.md`.

The current backend foundation denies every human HTTP/WebSocket route,
including system health, version, schema and framework documentation. Issue
#10 phase 1 adds a human route foundation that only an explicitly enabled,
fully validated composition can open (passkey sign-in and the caller's own
session description), and phase 2 S1 adds gated authorization, a per-session
CSRF token and sign-out to it, S2 invitation redemption, S3 the Owner
step-up routes and S4b the Owner's access administration routes (see
`server/app/auth/README.md`); the
production launcher builds one only from an enabled `human_access` deployment
section (`server/app/auth/composition.py`; absent or disabled, every human path
stays closed, an incomplete section refuses startup, and a composition that
cannot be built keeps every human path closed and notifies the Owner), and even then access
opens only while the reservation check passes. Its
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
- Codex review of the current **HEAD and current base/diff context** is the mandatory operational merge policy while Claude review automation is temporarily disabled by Owner decision due to subscription quota;
- ordinary `GITHUB_TOKEN` statuses/check names are not treated as unforgeable against a malicious same-repository writer;
- any material HEAD or base change invalidates the prior review context;
- real monitoring media, biometric templates, secrets, and private deployment values never appear in PRs.

The dedicated-App deployment proposal and offline policy validator are documented
in [`docs/REVIEW_GATE_SETUP.md`](docs/REVIEW_GATE_SETUP.md). They do not install
enforcement or authenticate supplied JSON. App credentials must remain outside
PR-controlled workflows/checkouts; the former same-repository Claude workflow was limited to trusted writers and is currently disabled. Actual issuer isolation and GitHub test-PR
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
- installation, configuration, and unit paths must be absolute and free of
  `..` segments, because normalizing them away would validate a different
  location from the one the kernel later reaches through a symbolic link;
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
- the installation destination, the configuration, and the runtime root are
  refused under `/tmp` and `/var/tmp`, which the unit's `PrivateTmp=true`
  replaces with empty private trees, and under `/home`, `/root` and
  `/run/user`, which its `ProtectHome=true` makes empty or inaccessible. They
  would otherwise pass the installer's own preflight and fail only after
  staging and unit mutation;
- an existing `--destination` is adopted only when it is empty or already a
  ServerSentinel installation root, so a mistyped destination such as `/root`
  is never relaxed to mode `0755`;
- each runtime directory must be owned by the dedicated account and keep owner
  read, write and execute permission, so a runtime tree the service could not
  actually write is refused instead of being reported as ready;
- the runtime mount point must be configured as an absolute path, because a
  relative one would identify different mounts for the administrator and for
  the service;
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

Capture-network boundary (Owner decision 2026-10-07, Issue #150): capture enrollment and ingest are private-LAN only and never run over Tailscale. The Main refuses the Tailscale address ranges IPv4 `100.64.0.0/10` and IPv6 `fd7a:115c:a1e0::/48` (including IPv4-mapped spellings) for the enrollment bind, the ingest bind and the `export-bundle --endpoint` value (`enrollment_bind_requires_private_address`, `ingest_bind_tailscale_address_refused`, `trust_bundle_endpoint_tailscale_address_refused`). The Agent refuses a Main endpoint in those ranges, from the bundle, a `pair --endpoint` override or a DNS name's connected peer address, with `main_endpoint_tailscale_address_refused` (an IP literal before connecting; a DNS name after the TCP connect, before the TLS handshake and before any secret is sent). The refusal is by address range only: a private LAN that is not Tailscale but uses these ranges is refused too and must expose the Main on another private address. It refuses configured or connected destination addresses in those ranges; it does not inspect routing. On a capture host that optionally runs Tailscale, an accepted subnet route (`--accept-routes`) or an exit node can still carry LAN-addressed capture traffic over `tailscale0`, and the check does not detect that. It is a fail-closed configuration check, not an authentication or network-isolation mechanism (node admission still requires mTLS and the ledger's active record; confidentiality and integrity of capture traffic come from TLS 1.3, not from the path).

## Human authorization

### Two-gate rule

Tailnet membership is **not** ServerSentinel authorization.

A user must have both:

1. a Tailscale/private-network permission path to the main node; and
2. an active ServerSentinel principal/invitation, proved by that principal's own verified credential, with the required permission.

Both gates stay mandatory. In the shared-account deployment below the first gate no longer distinguishes individuals, which makes the second gate the only one that does.

### Tailscale policy boundary

ServerSentinel does **not** modify Tailscale ACLs/Grants or store Tailscale administrative credentials; policy administration remains outside the application. Existing Tailnet policy may remain unchanged.

Therefore ServerSentinel does not claim that the underlying Main Server Tailscale node is hidden from ordinary Tailnet members. Node/peer visibility is controlled by Tailscale policy outside the application.

Application authorization remains mandatory even when the network path is reachable. For an uninvited identity, use a generic/non-branding denial and avoid exposing ServerSentinel product/version strings, API schema, health details, camera/source counts, thumbnails, recordings, or timeline data.

### Application allowlist

Even when a network connection reaches the trusted human proxy/backend, ServerSentinel serves no deployment metadata until a credential-backed session of an active application principal is verified. The proxy identity never selects the principal: the shared Tailscale login is the same for every invited person.

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

The concrete Owner-bootstrap/session design is [ADR-0003](docs/ADR/0003-owner-authentication-and-trusted-proxy.md), which is **Accepted** (2026-09-21).
It states the trusted-host loopback limitation and upstream login-reuse risk,
and defines recovery/revocation transitions. The per-person authorization
decision for the shared Tailnet account is
[ADR-0004](docs/ADR/0004-shared-tailnet-account-authorization.md), **Accepted**
on 2026-09-30 (see [Shared Tailnet account](#shared-tailnet-account)).

Accepting the two records does not open human access by itself. Human routes
and dashboard assets stay closed — the backend shell denies them, including
application assets, health/version/schema and SPA/error fallbacks — until
Issue #10 implements and tests both records; the remaining work is listed in
`server/app/auth/README.md`. Phase 1 mounts only the authentication ceremony
and a session self-description behind an explicit composition, phase 2 S1
adds only sign-out, S2 invitation redemption, S3 the Owner step-up and S4b
the Owner's access administration; none makes any of the conditions below
optional.
Every session route commits its authorization inside the reservation gate
(`admit(epoch)`), every Owner mutation does too (Owner decision D6), and a
request already in flight when the composition stops or a periodic check
fails is refused at that commit (Issue #228). A mutating session route also
needs the exact `Origin` and an `X-CSRF-Token` equal to the session's
HMAC-derived token (Owner decision D2); the token is never stored, logged or
put in a URL. Sign-out invalidates the server-side session (the old cookie,
also through the Back button, is refused afterwards) and is audited with the
principal's logical UUID only (D7); it ends one session, not the credential,
which a synced passkey may hold on several devices. Revoking that credential
is what ends it everywhere. Once they are open, a human request receives
application data only when every one of these server-side conditions holds:

- **Network gate.** The request arrived over the Owner-managed private network
  / Tailscale path through the non-bypassable local trusted-proxy listener,
  never as a header an ordinary LAN client supplied. This gate is necessary but
  identifies nobody: the research room shares one Tailscale login, so the
  login and any approved device name the shared account or a machine, not the
  person using it. It is also not a barrier that keeps uninvited people out;
  every holder of the shared account can reach the listener.
- **Application gate: per-person credential.** The requester's own
  ServerSentinel-issued WebAuthn/passkey credential, created from an Owner
  invitation, was verified by the server — its challenge, client data,
  authenticator data, signature and counter, relying-party id and origin, and
  the user-verification flag, which is required at registration and at every
  authentication — and an active, unexpired server-side session created by
  that credential exists. The invitation and the permission the route needs
  (`live:view` or `recordings:view`, independently) are checked per route.
- **Proxy identity binding, where the deployment supplies one.** Where the
  deployment supplies a verified trusted-proxy identity, the session stores
  only a deployment-keyed HMAC binding of it, and every later request's
  identity must reproduce that binding, compared in constant time. A mismatch
  denies only that request generically. Per REQUIREMENTS AUTH-005 and
  SPECIFICATION §11.8 the identity is accepted only on the trusted local path
  and may be additionally required, and the Issue #10 acceptance criteria in
  `docs/INITIAL_ISSUES.md` require that no route demand one where the
  deployment supplies none.
  The current access-layer code requires one on every ceremony and session
  check (Owner decision, 2026-09-30). There is no strictly local
  `http://localhost` Owner route and none runs without a proxy identity
  (Owner decision, 2026-10-11, recorded in `server/app/auth/README.md`): the
  Owner signs in through the reserved `https` origin like every other person.
  The per-person credential above is always required, and the binding is a
  consistency signal, never an authorization input: a Tailscale login or
  proxy identity header alone authorizes nothing.
- **Reserved secure-context origin.** The dashboard is served from its
  reserved origin over a secure context, and the latest startup/daily
  reservation check passed. That check detects; it does not prevent (below).
- **Owner step-up.** Owner-only operations additionally require a fresh user
  verification bound to the session's own credential.

The only requests served without a credential are the enumerated
pre-credential routes (enrollment-code redemption and authentication), which
return no application data. Revocation stays credential-scoped: revoking a
synced passkey applies everywhere it synced, and nothing here is per-device
revocation. The ADR-0003 policy-model tests and the synthetic unit tests do not
validate a real Tailscale installation, LAN bypass resistance, browser
WebAuthn behaviour, or active stream cancellation.

ADR-0003 also requires a hostname reserved for the human listener on every
scheme and port. No other application, static tree, alias, port, or catch-all
may answer for that name: one sharing a path would run in the same browser
origin, and one on another HTTPS port would still receive the host-only session
cookie, because cookies are not port-scoped. The reservation is a deployment
obligation — a dedicated network identity for ServerSentinel, or a
single-purpose node enforced outside the application — because a local process
can bind another port on that address without appearing in any proxy
configuration. Startup and daily checks enumerate actual listeners and proxy
routes for the whole name and close human access on any other answer they can
see, which bounds rather than removes that exposure. The check sees only sockets in `/proc/net` and Serve status. Traffic the kernel redirects before it reaches a listening socket on the reserved address — nftables/iptables DNAT or REDIRECT (for example Docker with `userland-proxy=false`), TPROXY, eBPF `sk_lookup` or IPVS — is not visible to it, so it cannot claim that nothing else answers; the deployment isolation must exclude such forwarding, and the Owner verifies it manually. Even for
sockets it sees, the check bounds the exposure rather than preventing it: the
application cannot prevent a local process from binding.

The current contract for that check (Owner decisions 2026-09-30,
2026-10-01, 2026-10-05 and 2026-10-07; details in `server/app/auth/README.md`
and ADR-0003):

- Each check re-resolves the reserved name. A resolved address set that
  differs from the recorded one is treated as an exposure. A missing resolver
  or a resolution that fails or times out keeps human access closed but is not
  an exposure: access reopens without revocation once the name resolves to the
  recorded set again, unless an exposure was seen meanwhile.
- After any exposure (another listener or route, a changed address set, or
  a listener/route enumeration that fails or times out) access reopens only after every human
  session, the Owner's included, has been revoked by advancing the
  authorization generation, with its `system` audit record committed. The
  requirement is persisted as a marker before reopening; if the marker cannot
  be written, every human session is revoked at once instead. A check without
  a durable revoker never opens human access. The check and every commit that
  creates a human session, updates a session's user-verification time, or
  creates or redeems an enrollment authorization share one lock (Issue #144,
  Owner decision 2026-10-07): each such request takes the gate epoch before it
  verifies anything, and the commit re-checks inside the lock that access is
  open and has not closed since; the check closes access inside the lock and
  keeps the verdict closed until any required revocation has committed. So a
  request that saw access open before a check closed it cannot commit a
  session after that check's revocation, even if access has reopened in
  between. WebAuthn challenges are stored under the same lock and epoch, and a
  revocation deletes every pending one, so a challenge issued before a
  revocation cannot be used after it. The check also decides and revokes inside the lock as defense in
  depth. The idle-expiry touch of an existing session stays outside the lock;
  revocation advances the authorization generation, so a touch can never make
  a revoked session valid again.
- An Owner listener exception names a port together with its creating
  systemd unit (`.service` or `.socket`) and uid, never a port alone, and
  every check verifies the socket's creating unit and uid. The unprivileged
  backend asks the kernel's socket diagnostics (`NETLINK_SOCK_DIAG`) for each
  socket's uid and creating cgroup and maps the cgroup id to its
  `/sys/fs/cgroup` path; no helper, capability or root is used (Issue #126,
  Owner decision 2026-10-07). A socket created by another unit or uid, when
  an immediate second lookup confirms it, closes access as an exposure. The
  Main Server keeps `ssh.socket`; the exception is `tcp/22` created by
  `ssh.socket` as uid 0 (`server/docs/DEPLOYMENT.md`).
- An exception covers a wildcard bind only, with one exception (Owner
  decision D1, 2026-10-16; ADR-0003): `tailscaled.service` (uid 0) TCP
  listeners bound directly on a configured reserved address on a recorded
  port that is not the dashboard, upstream or proxy port, for `tailscaled`'s
  plain-HTTP peerAPI. The `Secure` `__Host-session` cookie is not sent to a
  plain-HTTP port; that the peerAPI stays plain HTTP is verified manually
  (`MANUAL_TEST.md`), not by the check, which still only detects.
- Every recorded proxy socket must be present and created by the recorded
  proxy unit and uid (for example `tailscaled.service`, uid 0), verified the
  same way. A confirmed other creator is an exposure; a missing recorded
  socket closes access without revocation until it returns.
- The loopback human upstream is created by systemd socket activation
  (`server-sentinel-upstream.socket`, uid 0, a loopback port below 1024) and
  passed to the unprivileged backend. It must be a socket the ServerSentinel
  process holds (its own `/proc/self/fd`), created by that socket unit, on a
  port below `ip_unprivileged_port_start`, and held by no other process of the
  ServerSentinel unit (a same-uid descriptor scan); a replacement bound by
  another process, a confirmed other creator, or the socket shared with
  another unit process is an exposure.
- Ownership that cannot be verified (no resolver; a sock_diag or cgroup
  lookup that is denied, fails, times out or fails its self-check; a socket
  missing from the lookup; a creating cgroup that is deleted, the root cgroup
  or `/init.scope` while the socket's uid is an expected one, or
  `/init.scope` with uid 0; an unconfirmed mismatch; an upstream holder not
  seen in all three scans; a kernel-owned socket; an upstream port that is
  not privileged; an unreadable descriptor table) keeps human access closed
  without revoking sessions, and access reopens once ownership verifies. An
  unresolved creating cgroup with a uid none of the expected identities has
  is an exposure once confirmed (Owner decision, 2026-10-07).
- Residual risk accepted by the Owner (2026-10-07): the kernel reports the
  socket's creator, not its current holder. If a legitimately created
  socket's process is compromised and hands the descriptor to another process
  (`fork`, `SCM_RIGHTS`), the check does not see it, except for the human
  upstream's sharing within the ServerSentinel unit. The backend needs
  `AF_NETLINK` and the host network namespace for this lookup; `AF_NETLINK`
  also lets a compromised backend use every other netlink protocol open to an
  unprivileged process, for example reading routes and addresses (largely
  readable from `/proc` already) or listening to kernel uevents
  (`NETLINK_KOBJECT_UEVENT`, device add/remove events). Narrowing this with a
  `SystemCallFilter=`/socket-protocol restriction is planned for when the
  check is wired into the running service.

## Shared Tailnet account

The research-room Tailnet uses one shared Tailscale account, so a verified identity header names the shared login rather than the person behind the request. Application authorization therefore rests on a ServerSentinel-issued per-person credential (WebAuthn/passkey, accepted in ADR-0004) created from an owner invitation and individually revocable.

Consequences to keep in mind while reviewing code:

- a route that authorizes on the proxy identity header alone grants access to everyone holding the shared account;
- network reachability is not a boundary in this deployment; assume an uninvited person can reach every listener the shared account can reach;
- the unauthenticated response, including the credential prompt, stays generic: no product/version strings, camera names or counts, recording or timeline data, or deployment metadata, and the same response for uninvited and revoked people;
- approving a device is not identifying a person; a shared lab machine is used by whoever sits at it;
- a credential is person-bound only when authenticator user verification is required at registration and at every authentication and the authenticator is not kept inside a shared OS account or behind a shared device unlock. A platform passkey sitting in a shared lab profile is a shared credential;
- sessions are server-side records bound to one principal and to the credential that created them. Sign-out, idle/absolute expiry and revocation invalidate the server-side record, so a retained cookie or token grants nothing afterwards; the check runs on every human/media route, never in the browser. Shared machines get an explicit sign-out control, and owner-only operations require a fresh user-verification step instead of an old session;
- the server verifies the transient WebAuthn data a registration or assertion carries — its own challenge, client data, authenticator data, the signature counter, the user-verification flag, and the relying-party id and origin — and persists only the credential id, its public key, the last accepted signature counter, the backup-eligibility and backup-state flags, and owner-visible metadata; the rest is discarded once verified. An assertion's signature is always verified against the stored public key; a registration carries an attestation statement only sometimes, so `none` attestation is accepted while a present-but-invalid statement fails. The current implementation (`server/app/auth/webauthn.py`) verifies only `packed` self attestation among present statements and refuses every other format rather than accepting it unverified; the registration options request `attestation: "none"`. A review that sees those fields skipped, or accepted from an unexpected origin, is looking at a broken check, not at data minimization;
- no fingerprint or face template reaches ServerSentinel: it never leaves the authenticator. Credential records are not an identity or biometric database;
- relying-party checks only hold if the dashboard owns its browser origin, with no other application sharing it, as AUTH-012 requires; a co-hosted application on that origin would put the credential within its reach;
- reserving the origin is a deployment obligation, described above and in ADR-0003. The startup and daily check closes human access and notifies the Owner when it sees anything else answering on that name (listening sockets and proxy routes only; kernel forwarding to the reserved address (nftables/iptables DNAT or REDIRECT, TPROXY, eBPF `sk_lookup`, IPVS) is verified by the operator), which bounds the exposure window rather than preventing the bind: a process binding between two checks collects credentials and cookies for that origin until the next one;
- the origin must be the reserved `https` origin, reachable by URL from viewer devices outside the Main Server (for example the tailnet hostname served through Tailscale Serve to Tailscale-joined viewer devices). It must be a secure context because browsers withhold WebAuthn otherwise, so plain HTTP on a non-loopback host is not a usable human path. `http://localhost` is not a human dashboard origin: the human composition accepts only the reserved `https` origin and no `http://localhost` Owner route exists (Owner decisions, 2026-10-11 and 2026-10-16). Reaching the URL identifies nobody; the invitation and per-person credential above are still required;
- the pending challenge lives server-side for one bounded, single-use ceremony and is then dropped;
- the signature counter persists as `principal_credential.sign_count` and advances only on an accepted assertion. The comparison applies whenever the stored or the received counter is non-zero, and the received value must be strictly greater: a received 0 after a stored non-zero is a regression, not an exemption. A regression refuses the assertion and notifies the Owner as a possible cloned authenticator. Only a stored-and-received 0 is exempt, which is the ordinary passkey case;
- a retained proxy identity is bounded: the principal keeps at most the last observed raw value, stored but never returned or shown, not even to the Owner (Owner decision D14), cleared on revocation or deletion and kept out of diagnostic exports, with longer history in the audit log. A session stores only a deployment-keyed HMAC binding for constant-time equality checks; it is cleared with session invalidation, never displayed and excluded from diagnostics/exports. The key is a 32-byte file in the data directory, created once with mode `0600`, refused (not replaced) when its ownership, mode, link count or size is wrong, and never logged, exported or stored in the database;
- ceremony material and enrollment codes stay out of logs, diagnostics and exports, and a failed verification is recorded as a typed outcome without the payload;
- revocation is credential-scoped, not device-scoped. A synced passkey is one credential across several of its owner's devices, so revoking it applies everywhere it synced; a deployment that needs device-scoped control registers device-bound authenticators and refuses backup-eligible credentials;
- backup eligibility is fixed at registration. A changed value atomically marks the credential inconsistent with a fixed reason/timestamp, revokes its sessions, refuses the assertion and notifies the Owner. The credential remains unusable until replaced; re-invitation recovers a non-owner with no usable credential, while an Owner with none uses privileged local bootstrap. Backup state is refreshed from every verified assertion, so a credential that syncs after registration stops being shown as not backed up.

Residual limits are documented, not claimed away: a credential its holder deliberately lends, and a session left unlocked on an unattended machine, are outside what the application can observe.

Enrollment codes and owner bootstrap authorizations are bearer authorizations reachable by everyone holding the shared account, so they are CSPRNG-generated with at least 128 bits of entropy, stored only as a hash, compared in constant time, short-lived, single-use and rate-limited per code and per source. Single use and the attempt counter are enforced in one conditional transaction, so racing redemptions of the same code cannot both register a credential and concurrent guesses cannot outrun the limit. A code short enough to guess is a finding regardless of the lifetime and rate limits around it. Issue #10 phase 2 S2 implements this with 160-bit codes valid for the deployment's `invitation_lifetime_hours` (default 24 hours, Owner decision D5; at most 7 days, Owner decision 2026-10-11), each also bound to the boot id and monotonic boot clock of its issuance so that a wall clock set back on the same boot refuses the code instead of extending it (after a reboot only the wall clock decides; see "Clock rollback across a reboot" below); a row located by a separate non-secret lookup key and its stored digest compared with `hmac.compare_digest`; a redemption limiter separate from sign-in (Owner decision D4: per verified proxy identity burst 5 and one per 12 seconds, with no global bucket, Owner decision 2026-10-11, so one source cannot stop another's redemption); refused redemptions counted and logged value-free (`invitation_redemption_refused` on the first and each doubling, never the code, identity or reason); the code only in the request body and never in a URL, log or audit record; and a local bootstrap/recovery command that runs as the service account and writes the code only to its controlling terminal. Under the shared account the per-source bucket is the room's, so one holder of the shared login can delay another's redemption (availability), never redeem without the code.

Clock rollback across a reboot (Issue #235 item 4, Owner decision 2026-10-14). The boot id and `CLOCK_BOOTTIME` pair is not comparable across boots, so the application does not detect a wall clock that is earlier after a reboot than before it: an expired invitation code can look valid again, and session idle and absolute limits are measured on that clock. The generated Main unit is ordered `After=time-sync.target`, so on a host where the Owner has persistently enabled a wait service (`chrony-wait.service` for chrony, the Ubuntu default since 25.10; `systemd-time-wait-sync.service` for systemd-timesyncd) the service waits after a boot until the clock is synchronized or until that wait service's own start limit ends (chrony-wait: `TimeoutStartSec=180`). This narrows the accidental case, a stale or flat RTC before NTP corrects it, to a host that does not synchronize within that limit; it does not close it: when no time source answers in time, the wait service fails, `time-sync.target` is still reached and the service starts on the unsynchronized clock, as before. It does not mitigate a clock set deliberately by root or an administrator (who can also write the database), a time source that answers with a wrong time (NTP spoofing, a misconfigured server: the wait ends when the daemon reports synchronized, to whatever time it was given), a clock step after the service has started (same-boot detection covers invitations and step-up), or a host without an enabled wait service, where `time-sync.target` does not wait. The installer only queries whether one of those two wait services is enabled (exactly `enabled`; `enabled-runtime` is gone at the next boot) and warns when neither is; it never changes host time configuration and does not refuse. While the service waits, it, local recording included, is not running; a wait service without a start limit would keep it down for as long as no time source is reachable (`server/docs/DEPLOYMENT.md`, "Clock synchronization before start"). A persisted wall-clock high-water mark was not chosen.

Two HTTP routes necessarily run before a credential exists, and the pair is closed: invitation redemption against a valid short-lived single-use enrollment code, and the authentication route. Owner bootstrap adds no third route — it is a privileged local action on the Main Server that issues a single-use, short-lived enrollment authorization shown only on the console, redeemed once from a browser at the reserved origin through that same redemption route, never a remote first-visitor route. They return no application data, redemption is rate-limited and succeeds at most once, an absent/unknown/expired/redeemed code gets the same generic response as an uninvited person, and enrollment codes never reach logs. Apart from the neutral sign-in markup, script and style those two routes need (the shell below, Owner decision D1), every other human route requires a verified credential and an active session.

The markup those two routes need is the neutral sign-in shell at `/` (`/s.js`, `/s.css`; Issue #10 phase 2 S5a, Owner decisions S5-1, S5-4, S5-5, `web/README.md`): Japanese only, no product, feature or version string, no favicon, fixed local messages only and never a server response; the invitation code stays in the JSON request body and never reaches a URL, history entry, browser storage or form submission. Accepted disclosure (S5-5): the shell's bytes are identical for every deployment of one release, so anyone reaching `/` can identify the software from them; they carry no version marker and nothing about the deployment, cameras or people. The dashboard under `/app/` is a separate build with its own policy and needs a session.

Accepted disclosure: the authentication options step (`POST /api/auth/authentication/options`) answers `200` with a fresh challenge and the `rpId` to any caller on the trusted proxy path while access is open, because discoverable-credential sign-in needs it before any credential is presented; it therefore differs from the generic denial and reveals that a relying party answers at the reserved name, but returns no principal, credential or application data. The origin, trusted-path, reservation and rate-limit checks bound who reaches it and how often; they do not hide it.

Accepted disclosure (Owner decisions D1 and S5-5, Issue #10 phase 2 S5b): the sign-in shell (`GET /`, `GET /s.js`, `GET /s.css`) is served before any credential, with the same bytes to every caller who passes the origin, trusted-path, reservation and serving gates. Those bytes and their hash identify the software (ServerSentinel, and which shell build) to anyone on the shared account who reaches the reserved name; the shell carries no version marker, no application data and nothing that names the deployment, a camera or a person, and its responses never vary with the caller (no cookie, no `ETag`/`Last-Modified`/`304`, `no-store`), so they reveal nothing about who is invited or signed in. The application assets (`/app/`, `/app/<name>`) need an active session and do not extend it. Every asset is served from a copy of the release build that the server verified against its manifest (exact file set, SHA-256, size, regular files only, extension allowlist) and froze in memory at startup; a mismatch keeps the human routes closed, and a later change on disk is never served. The loader also refuses a group- or world-writable directory or file and a file with a second hard link. Because the manifest is written by the same build, this verification guards against an accidental, partial or mixed deployment, not against someone who can write the directory (who can rewrite the manifest too); protection against the service account rests on ownership and modes: the release places the build root-owned and read-only (files `0444`, directories `0755`, never hard-linked), so the service account cannot write it (Issue #10 S5c). The release manifest copy the installer keeps in each release is unsigned and lives in the same root-owned tree; the installer compares the build with it only when it installs a release (confirming the bytes of the artifact whose published SHA-256 was verified were placed) and before a rollback switches to one (detecting accidental or partial changes and changed owners or modes). It is not compared at every start (the release's `--check` only loads the build against its own `manifest.json`), and it does not detect a change made by root, who can rewrite the copy too. Each response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy: same-origin`, a `Permissions-Policy` that denies camera, microphone and geolocation, and a `Content-Security-Policy` with `default-src 'none'`, same-origin scripts, styles and connections only and `frame-ancestors 'none'`. This is mock-verified only; browser enforcement of these headers is a manual check (`MANUAL_TEST.md`).

Owner-only operations additionally require a user verification newer than a bounded freshness window, so a stale or unattended owner session cannot revoke users, change retention/security settings or delete recordings; a failed or cancelled step-up performs nothing and reveals nothing.

The step-up is bound to the session's own credential: the challenge allows only `principal_session.credential_id`, and an assertion from any other registered credential is refused without touching the session's verification time. A route that accepts any valid passkey here lets whoever is standing at a shared workstation refresh someone else's stale owner session with their own credential, which is the attack this binding exists to stop.

Issue #10 phase 2 S3 implements this as `POST /api/auth/step-up/options` and `POST /api/auth/step-up`: both need an Owner session (`OWNER_READ`, so a stale Owner can refresh and a non-Owner gets the generic denial before anything is written), the exact `Origin` and the session's `X-CSRF-Token` (Owner decision 2026-10-12: they stay Owner-only), are charged before any body parse, gate or SQLite work to their own per-source rate limiter (Owner decision 2026-10-12: burst 5, one per 12 seconds, no global bucket, a `SourceRateLimiter` object `HumanAccess` refuses to share with sign-in or redemption, so a sign-in flood cannot stop the Owner's step-up and a step-up flood never spends the sign-in bucket), and commit under the same gate epoch as their authorization. The window is five minutes from the verification time read inside the commit transaction, measured on both the wall clock and the kernel's monotonic `CLOCK_BOOTTIME` of the same boot (migration 23): a wall clock stepped back after a verification makes the session stale rather than extending the window, and a reboot, a session without a recorded boot pair (established before migration 23) or an unreadable boot clock is stale (fail closed, Owner decision 2026-10-12). Any lag of the wall clock behind the monotonic clock beyond a one-second read allowance is stale too; slews should move both clocks together, and if a chrony slew back (default `maxslewrate` 83333 ppm) ever separated them, a just-verified session would need another step-up (availability only). Only a stale but otherwise valid Owner session on an Owner operation gets `403 {"detail":"step_up_required"}` (Owner decision D3); refused step-ups are counted and logged value-free (`owner_step_up_refused`). Step-up shows that whoever holds the session's credential passed its user verification just now; it cannot tell a deliberately lent credential from its holder, and a stale Owner session left open on an unattended machine keeps serving everything that is not an Owner operation until it expires or is signed out. The Owner operation routes mounted so far are the access administration routes of S4b (below); every mutation commits inside the gate epoch of its `OWNER_OP` authorization and re-checks the Owner session, freshness included, inside its own SQLite transaction, a `step_up_required` answer does not extend the session, and the Owner principal is never a target.

Issue #238 follow-ups to the step-up (synthetic/mock verified only, `server/tests/test_human_step_up.py` `FollowUpTests` and `StepUpFindingStoreTests`, with no browser or real authenticator). A refused step-up finish spends its challenge only when the challenge is bound to the refused request's own current session: a submission from another session, even another session of the same Owner that learned the challenge value, and a submission whose request has no current session at all (the session's proxy identity binding does not match, or the session expired or was signed out) is the generic denial and deletes nothing, so the challenge stays pending and is still usable only by the session it was issued to, until its normal expiry (or until a close that revokes sessions deletes it). This is an availability protection, not a weakening of single use: a challenge still verifies only for its own session and its own credential, and every refusal of the own session's request spends it as before (except a session-gate refusal, which leaves it pending, as before). A detected credential finding (changed backup eligibility or a signature counter that does not advance) whose write fails, for example a storage admission refused under `STORAGE_HARD_STOP`, has neither an audit record nor an Owner notification; it is counted in the value-free in-process counter `PasskeyCeremonies.unrecorded_findings` (not persisted; a session-gate refusal of the finding is not counted) and logged as the WARNING event `credential_finding_unrecorded` on the first failure and at each power of two (1, 2, 4, 8, ...), carrying only the event name, never a kind, principal, credential, challenge, token, identity or reason. The finding itself is not lost: the stored credential is unchanged, so the next assertion of that credential detects it again, and an operator who sees the event should treat it as a credential finding that could not be recorded and resolve the storage condition. A changed backup eligibility detected by two sessions' step-ups, or by a step-up and a sign-in, at the same time is recorded, audited and notified once: the first transaction to mark the credential writes the mark, its session invalidation and its audit record and is the only one that notifies the Owner; a later one finds the credential already marked, still spends its own challenge (a sign-in's was consumed before verification) and writes, audits and notifies nothing more.

Issue #10 phase 2 S4b mounts the Owner's access administration: `GET /api/admin/principals` (`OWNER_READ`, the inventory, which never returns a proxy identity, credential id, public key, counter, digest or session data) and five `OWNER_OP` changes — invite with one code, re-issue the code, grant or withdraw one of `live:view` / `recordings:view` as a delta, revoke a person, and revoke one credential by its random handle (credential-scoped: a synced passkey is revoked on all synced devices that hold it; it is not per-device revocation). Path ids match only the canonical lower-case UUID form with the raw path equal to the decoded one, bodies are strict bounded JSON checked before any session work, every change needs the exact `Origin` and `X-CSRF-Token`, and every refusal (a non-Owner, a revoked or Owner target, another principal's handle, a limit of S4-8, a gate change or a session that no longer holds at the commit) is the generic not-found response, except `403 step_up_required` for a stale Owner, decided before anything is written and without extending the session. An invitation code is shown only in the response that issued it and stored only as its digest and lookup key; no code, display name, handle, credential id or identity is logged, and audit records carry the principal's logical UUID only. The inventory re-checks the Owner session inside its own read transaction, so a local recover or revocation committed after the authorization (outside the gate) returns nothing. The changes are charged to their own per-session rate limiter (Owner decision 2026-10-13: burst 20, one per 3 seconds, a bounded table, keyed on a server-side digest of the session token after a read-only pre-check that the session is current and its principal the active Owner (so a non-Owner session is refused uncharged and cannot fill the table against the Owner, PR #242 review) and before any gate, SQLite or audit work, a `SourceRateLimiter` object `HumanAccess` refuses to share), so a fresh Owner session cannot grow the audit table without bound with repeated no-op or unknown-target changes, and another person's session cannot spend the Owner's bucket; over the limit nothing is written or audited. This is synthetic/mock verified only (`server/tests/test_human_admin_routes.py`), with no browser or real authenticator.

Issue #10 S7 mounts the interim live frame pull (Owner decision D10, pending #19): `GET /api/live/sources`, `POST /api/live/sessions`, `GET /api/live/sessions/<sid>/frame` and `POST /api/live/sessions/<sid>/close`. Every request needs `live:view` (or the Owner) server-side, except the close, which only releases a live session of the caller's own human session; `recordings:view` alone reaches none of them, and the source list returns only id, name and coarse health. A live session is bound to the human access session that opened it, so a live-session id copied to another person's browser, or to another sign-in of the same person, is refused; every frame read re-checks, inside the gate epoch, that the presented session is that human session (token digest and proxy-identity binding) and re-runs the `live:view` validator (current principal, credential, deployment generation, authorization revision). Nothing is written per frame: the idle expiry is extended at most once per 60 s per live session, and polls are admitted in memory against a per-(human session, live session) budget before any SQLite read, while opens are charged to a per-session limiter after a read-only check (a close reaches SQLite only for a live session held for the presented cookie, so closes are bounded by opens). Capacity (4 sessions in total, 2 per source, 2 per person) is the generic denial. Viewer demand ends after a 15 s lease without an authorized poll, on close and sign-out, at once after an Owner grant or revocation change, and for every session while access is closed; a revocation by the local CLI is caught by the next poll or the lease. Frames are served only as `image/jpeg` with `nosniff`, `no-store` and `Cross-Origin-Resource-Policy: same-origin`, never as an attachment; this is browser viewing, not a download, and it does not prevent screen capture by a viewer. Synthetic/mock verified only (`server/tests/test_live_frame_routes.py`).

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

ADR-0006 selects the bootstrap trust profile: a deployment-local CA public trust bundle moves through an independently trusted Owner channel; the local Main approval binds a 128-bit, five-minute, one-use code to the Agent public-key digest; and TLS 1.3 authenticates the intended Main before code submission. The Issue #13 CA, node-certificate and mTLS ingest adapters exist; the application starts no ingest listener. The bootstrap enrollment listener runs only inside the local Main approval CLI (`pairing_cli approve`), on an explicit private IP literal, for that run's approval, and closes when it completes or its five minutes end. It uses TLS 1.3 with a required ALPN protocol, bounded frames, one deadline per connection, per-source attempt limits and a refusal cap, and returns only a generic refusal to unauthenticated peers. The Agent pairing CLI authenticates the Main (bundle CA, server name, ALPN, deployment URI) before it prompts for the code, and the Main CLI shows the code only on its controlling terminal. Until #6, Owner authority in that CLI is the local administrator who can start it as root (`sudo`) plus a typed confirmation per approve/revoke. A short-lived code and post-pairing mTLS do not replace confidentiality and intended-server authentication during initial enrollment. Pairing secrets are entered through a non-echoing prompt or protected automation input, never command arguments, environment variables, URLs, or logs. The Main listener leaf is rotated in place (`pairing_cli rotate-listener`) without changing the CA.

CA key separation (Issue #109 PR1). The deployment CA private key is readable only by the static system account `serversentinel-ca` (CA directory 0700, files 0600) and is loaded only by a short-lived child of the pairing CLI running as that account: it holds no terminal, no database descriptor and no network socket, is non-dumpable with no_new_privs, signs at most one fixed-profile leaf (or records one revocation) per run, decides from its own CA-only issuance log rather than the application ledger, and exits before anything network-facing runs. The service account (application database, Main listener credential, public CA copy) never opens the CA directory: the launcher refuses to start if it can, and the CLI aborts if its dropped process can. The bootstrap enrollment listener runs as the service account with no capability, after the CA child has exited, and only activates a certificate signed before the code was shown; it has no signing capability. Consequently a compromise of the service, the listener or the enrollment process cannot read the CA key, issue a serverAuth certificate or obtain a certificate for a new node. Residual risks: a compromised service account can still impersonate the Main listener with its own listener key and could alter the public CA copy it exports (both already within that account's power); a pre-signed node certificate is public, useless without the Agent's private key and admits nothing until the ledger activates it on redemption; and a root compromise defeats the separation. The renewal path still uses an in-process signing primitive that nothing in the application calls yet; the renewal-only signer is Issue #109 PR2. Revocations are also recorded in the CA issuance log so the CA side refuses revoked nodes and their keys. Known limitation (Owner decision 2026-10-07): the issuance log has no hash chain, so an edit or truncation by the CA account or root is not detectable from the log itself; only those accounts can write it, and the CA directory backup is the reference copy.

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
- human enrollment codes and WebAuthn ceremony material (challenges, client/authenticator data, signatures);
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
event details. A failing hostname reservation check or human-access
composition, its recovery, and a committed WebAuthn credential finding are the
immediate fixed categories `human_access_fault`, `human_access_recovered` and
`credential_finding` (Issue #232 item 4): sent on the transition, not on every
check, rate-limited, and marking monitoring health degraded. They add Owner
visibility only; human access was already closed by the check, and the
notification carries no hostname, identity, principal, credential or reason. Tests use generated dummy components and intercepted transports.
The webhook is read only from the administrator-owned, non-world-readable
deployment configuration (`monitoring.slack_webhook_url`); it never enters
repr, validation messages or logs. The monitoring runtime binds the Main
storage policy only from explicit deployment thresholds and an Owner-declared
recording filesystem identity; missing thresholds leave writes refused, and a
missing, reformatted or substituted recording filesystem is refused without a
fallback directory. The runtime never approves or rewrites the hardware
baseline and adds no route; the human surface stays closed.

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

The Issue #23 foundation uses fixed read-only command arguments, bounded output
and time, a minimal environment, and no sudo or shell. Baseline approval denies by
default, checks the expected revision and audits the approved principal. Raw
inventory never enters the fixed-category fault outbox. Self-test I/O shares the
recorder worker's pinned root and reservations; only a journaled UUID artifact
can be cleaned. Domain interfaces do not enable a human API or replace pending
application authorization integration.

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
