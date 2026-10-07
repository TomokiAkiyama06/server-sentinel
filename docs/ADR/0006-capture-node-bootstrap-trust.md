# ADR-0006: Capture-node bootstrap trust and revocable enrollment

Status: Accepted 2026-09-21 — implementation remains staged; this ADR does not enable a listener by itself.

Related Issues: #13 (Plan 7), #6 (Owner authority), #12 (Agent foundation),
#14 (ingest isolation), #15 (media transport).

## Context

The existing requirements already require intended-Main authentication and
encryption **before** transmitting a pairing code, followed by a unique revocable
node identity. LAN reachability, a short-lived code, and later mTLS cannot establish
that initial trust. SPECIFICATION §5.4 deliberately leaves the exact method open.

This decision records the Owner-approved choice. It does not select the
media protocol in #15, introduce human authentication, or complete #13. Owner
authority still depends on #6; its proposed local administrative bootstrap is not
silently accepted here. There is no dashboard/UI implementation in this change.

## Decision

The Owner accepted a deployment-local CA public trust bundle transferred through an
Owner-controlled local/out-of-band channel. Use a local administrative Main CLI
for enrollment approval and a non-root Agent CLI for pairing. TLS 1.3 authenticates
the Main during bootstrap; deployment-scoped mTLS authenticates both endpoints
afterward. The code is 128 random bits, rendered as 26 Base32 characters, valid for five
minutes and one atomic redemption.

Fingerprint pinning remains documented as an alternative but is not selected. Bootstrap/ingest ports remain disabled until their separately scoped adapters are implemented and validated; unpaired Agent adapters remain unable to send network traffic.

| Trust method | Owner operation | Rotation and risk | Recommendation |
| --- | --- | --- | --- |
| Local CA public bundle | Export on the trusted Main, copy the public bundle to the intended Agent through an already trusted channel; verify its full SHA-256 digest independently if the copy channel is untrusted | Ordinary Main leaf renewal retains CA trust; CA replacement requires another explicit trusted transfer. The CA key becomes a protected deployment authority | Recommended |
| Exact Main certificate/public-key fingerprint | Copy a full SHA-256 fingerprint from the trusted local Main display and verify it before any enrollment bytes are sent | Exact certificate pins change on renewal; public-key pins survive renewal but need precise certificate/time/name validation and a separate key-rotation policy | Viable alternative; requires its own explicit protocol profile |
| First network connection supplies trust | Accept the first certificate or download its fingerprint from that same connection | An impersonator can supply both the endpoint and its supposed evidence | Rejected by current requirements |

A hash copied together with a bundle over the same unauthenticated channel does
not authenticate that bundle. Existing trusted physical/local administration or
an independently authenticated Owner channel supplies the trust. ServerSentinel
does not establish SSH access to the capture host, depend on developer services,
or change Tailscale policy to perform the transfer.

## Enrollment flow

1. On the intended capture host, the dedicated non-root Agent account creates a
   node key locally and a public enrollment request containing its public key and
   proof of possession. The private key never leaves that host. Pairing takes an
   exclusive runtime-state lock so it cannot overwrite an active service identity.
2. The Owner transfers the public request to the trusted Main through the approved
   channel. The local administrative CLI validates it and records explicit Owner
   approval bound to the request's public-key digest, a fresh enrollment ID and a
   Main-assigned node UUID. A CSR cannot choose human roles, its node UUID, SANs,
   certificate extensions, or permission scope.
3. The Main CLI exports a public trust bundle: format version, deployment UUID,
   deployment CA certificate, intended Main TLS server name, and explicit private
   bootstrap endpoint. It displays the bundle's full SHA-256 digest locally. No
   private key or pairing code is included in this bundle. Deployment names,
   addresses, public certificates and fingerprints still remain local deployment
   information; no real bundle is committed or uploaded as a test artifact.
4. The Owner copies the bundle to the Agent using the trusted channel. The Main
   CLI displays the single-use code once on its controlling terminal, outside
   normal stdout/log output. An unattended terminal is not a trusted delivery
   mechanism. The Agent command accepts only public file/endpoint selectors;
   neither CLI accepts a code through argv, environment, URL, or shell text.
5. The Agent establishes TLS 1.3 using **only** the imported deployment CA, with
   certificate-chain, validity and intended server-name verification. It checks
   the trusted deployment identity. Missing trust, wrong name/CA, expired
   certificate, protocol downgrade, redirect, or handshake failure aborts before
   requesting/transmitting the code. There is no plaintext or insecure switch.
6. After successful verification, the Agent reads the code from a non-echoing
   controlling-terminal prompt and submits it with the approved enrollment
   request over that connection. If input cannot be hidden, abort; a warning
   followed by echoing input is not acceptable. Reconnection repeats full server
   authentication. No automatic URL redirects, system proxies, TLS key logging,
   debug body dumps, or raw exception logging are enabled.
7. The Main validates the bounded request, proof of possession, matching approved
   public key, deployment, unexpired approval and code. It atomically consumes
   the approval and persists a pending node credential before signing. It issues
   only a node client certificate with the approved node identity and capture
   purpose. The Agent validates that the response matches its own key/identity,
   then writes private state atomically with owner-only permissions and fsync.
8. The Agent reconnects outbound through the separate mTLS ingest listener.
   Acceptance requires the current authoritative active-node record, correct
   deployment, issued serial/key digest, validity and capture-only scope.
   Enrollment success by itself does not grant source ownership or human rights.

The bootstrap endpoint is a separate, explicitly configured private listener
from both human routes and strict client-certificate ingest. It accepts only the
bounded enrollment exchange, opens only while approved enrollments are pending,
and closes after their completion/expiry. It cannot receive media or become a
human/API proxy. No network wildcard, public exposure or default port is assumed.

## Atomicity, persistence and revocation

- Generate codes with the OS cryptographic random source. Persist only a keyed
  digest in a protected SQLite ledger; keep its HMAC key separately protected.
  Compare digests in constant time. Do not retain the code in events or logs.
- Use a database transaction/uniqueness constraints to move an approval from
  pending to consumed exactly once. Concurrent redemption yields at most one
  credential. Server monotonic time bounds the five-minute lifetime; invalidate
  pending approvals on process restart, clock-integrity failure and backup
  restoration. UTC timestamps support audit and never extend a code's lifetime.
- Certificate signing and database commits are not one atomic operation. Persist
  consumption plus issuance intent first, activate the exact issued serial only
  after signing succeeds, and make ingest depend on that activation record.
  A crash leaves an unusable pending/orphan credential. Recovery cannot reactivate
  a consumed code. A lost enrollment response requires a fresh Owner approval;
  retries do not reissue credentials from the old code.
- Revocation first commits a durable status/generation change. All new handshakes
  and every media/control admission consult current authorization. Notify and
  close existing sessions; recheck before queued work commits. Resumed TLS sessions
  cannot reuse cached authorization. Database/cache/coordinator failure denies
  further work; certificate validation alone is insufficient revocation checking.
- A node cannot renew or replace its identity after revocation. Initial MVP
  replacement uses a fresh Owner-approved enrollment. CA replacement, credential
  validity periods and future unattended renewal need explicit policy before that
  capability ships; there is no infinite validity or insecure expiry bypass.
- Node certificates are not trusted on human/admin routes. Human cookies,
  invitations, Tailnet membership and trusted proxy headers do not authorize
  ingest. Authorize source actions against the node/source assignment separately.

Private state lives outside source/install/media trees, in dedicated private
directories (0700) and regular owner-controlled files (0600), without symlink
following or replacement of existing identities. Main issuer material is readable
only by the local authority that needs it; the network enrollment service receives
only its narrowly scoped issuance capability. Retained audit records contain fixed
operation/result codes and generated internal identifiers, not codes, keys, CSR or
certificate bodies, raw headers, URLs, addresses, or media.

Bounded request size, pending-enrollment count, connection count, timeout and
attempt-rate settings are required before listening; their measured deployment
limits and certificate-validity settings belong in the implementing PR. Failed
attempts cannot extend expiry. The high-entropy code and approved-key binding do
not remove the need for resource/denial-of-service limits.

## Threat model and negative validation plan

The attacker may observe/modify LAN traffic, impersonate endpoints, replay or race
requests, hold a revoked node key, or be a Tailnet member without app permission.
Compromise of Owner administration, the approved transfer channel, Main CA key or
the capture host's service account is outside protection by this pairing exchange;
revocation and recovery remain required. No claim hides activity from host/network
administrators. Tests generate all identities and media locally under temporary
directories; no real deployment material or packet/key logs are uploaded.

| Negative test | Required evidence |
| --- | --- |
| Missing/untrusted bundle, attacker CA, wrong server name, expired certificate, plaintext/downgrade, redirect | Real local TLS peers; enrollment spy receives zero code/request-secret bytes, and non-echo prompt is not invoked before verification |
| LAN observation of a successful pairing | Real TLS exchange with generated secrets; captured wire bytes contain no code/credential plaintext; never enable TLS key logging |
| Input has no safe terminal; inherited proxy/key-log variables; malicious exceptions | Abort unsafe input; fixed logs; subprocess argv/environment/URLs and captured stdout/stderr contain no test code/key; no network redirection or key-log file |
| Expired, reused, restarted, cancelled or concurrently redeemed approval | Fake monotonic clock plus real SQLite concurrent processes; at most one active identity; expiry/restart cannot restore approval |
| Stolen code with another public key, malformed CSR, chosen admin extension/source ID | Reject proof/key/scope mismatch; neither node activation nor human permissions created |
| Crash at consume/sign/activate/write/response boundaries | Fault injection and restart preserve single use; orphan certificate denied, no duplicate activation, existing identity never overwritten |
| Revoked node reconnect, existing stream, queued write or TLS resumption | Commit revocation while multiple local processes exchange generated messages; all later admissions/commits fail and sessions close |
| Human credential on ingest; node credential on human/admin routes; unpaired LAN node | Real listeners reject all cross-boundary credentials and expose no protected response or human-route dispatch |
| Inaccessible/readonly ledger, credential symlink, wrong UID/mode, competing pairing process | Fail closed without creating a replacement/fallback identity or partially active node |
| Resource saturation or malformed oversized input | Bounded allocations/work; fixed errors; pending approvals still expire and no unauthorized activation occurs |

These are planned tests, not test results. Issue #13 acceptance needs temporary-CA
multi-process real TLS tests; transport mocks alone cannot satisfy it. Actual LAN,
UVC and continuous-media interoperability remain #15/#28 acceptance. No actual
camera, mount, account or network policy is modified by this proposal.

## Implementation and license plan

1. Preserve the accepted trust channel/CLI flow and code parameters from this ADR,
   and finish the #6 authorization prerequisite before enabling behavior.
2. Implement internal ledger/issuer interfaces with default-deny listeners, then
   the separately authorized bootstrap and mTLS adapters. Keep protocol dispatch,
   node authorization and human authorization distinct. Integrate #12 only after
   the authenticated adapter has its own negative tests.
3. Reuse pinned, audited Python/backend foundations and stdlib `ssl`, `secrets`,
   `hmac`, `sqlite3`, `getpass`. Use an explicit TLS client context and deployment
   trust store; Python's convenience context may enable key logging from an
   environment variable. Treat non-echo fallback as an error. The official
   [Python TLS documentation](https://docs.python.org/3.12/library/ssl.html) and
   [getpass documentation](https://docs.python.org/3.12/library/getpass.html)
   describe these relevant defaults/fallbacks.
4. Certificate/CSR generation needs an independently reviewed implementation.
   `cryptography` is a candidate, not an approved dependency: inspect the exact
   selected release, wheel/source hashes, license files, bundled OpenSSL/Rust
   transitive obligations and notices before installation. Its
   [upstream license file](https://github.com/pyca/cryptography/blob/main/LICENSE)
   is a starting point, not an exact-version audit. An OS OpenSSL issuer helper is
   another candidate requiring exact package/source/license review and protected
   input handling; never place secrets in child command arguments/environment.
   This ADR adds no package, lockfile exception or cryptographic implementation.
5. Add the matrix above to CI with generated temporary credentials, bounded
   process lifetimes and secret-safe diagnostics; publish only counts/status.
   Update MANUAL_TEST for actual deployment interoperability and preserve #13 as
   open until its implementation acceptance criteria pass.

## Decision record

Accepted by the repository Owner on 2026-09-21: local-CA public bundle and trusted transfer, local privileged Main approval plus non-root Agent pairing, approved-public-key binding, TLS 1.3, and a 128-bit/five-minute/one-use code. The existing #6 Owner-authentication and #4 GitHub-App decisions remain separate; this ADR neither repeats nor resolves them.

## Follow-up notes (2026-09-30, Issue #13 mTLS adapters)

These notes record implementation progress; they do not change this ADR's
status or decision.

- **Dependency.** The Owner approved `cryptography` 50.0.1 on 2026-09-30
  (`docs/decisions/2026-09-30-cryptography-dependency.md`, the single approval
  shared with Issue #10), resolving item 4 of the implementation plan above. The
  exact release, wheel hashes, statically linked OpenSSL 4.0.2, Rust crate
  closure and notices are audited in `server/docs/DEPENDENCIES.md` (Main) and
  `agent/docs/DEPENDENCIES.md` (Agent lock). TLS remains stdlib `ssl`.
- **Main issuer** (`server/app/cameras/remote_agent/node_ca.py`): EC P-256
  deployment CA (`pathlen=0`) whose key lives in a 0700 directory with 0600
  write-once files; a separate directory holds the serverAuth-only Main ingest
  certificate/key, so the listener never needs the CA key. Node certificates are
  issued only for a redeemed `EnrollmentClaim`; the CSR is proof of possession of
  the approved key and its subject/extensions are ignored. The leaf carries
  `CA=false`, `digitalSignature`, EKU `clientAuth` only, and exactly the SAN URIs
  `urn:serversentinel:capture-node:<node UUID>` and
  `urn:serversentinel:deployment:<deployment UUID>`. Validity is an explicit,
  bounded parameter (at most 397 days for leaves, never beyond the CA). The
  Owner later set the default and renewal policy; see the renewal note below.
  Signing happens after ledger consumption; the ledger's
  `credential_serial_digest` stores the SHA-256 of the exact DER certificate, and
  activation happens only after signing succeeds.
- **Trust bundle.** `export_trust_bundle` emits format version, deployment UUID,
  CA certificate, Main server name and explicit endpoint, with its full SHA-256
  digest; the Agent refuses a bundle whose digest does not match the value the
  Owner verified independently.
- **Ingest adapter** (`server/app/cameras/remote_agent/ingest_tls.py`): TLS 1.3
  only, client certificate required, deployment CA as the only trust anchor,
  `VERIFY_X509_STRICT`, no session tickets. Admission re-parses the peer leaf and
  requires the ledger's current active record for node, key digest and
  certificate digest on every connection; `still_admitted()` re-checks before
  queued work commits and closes the session after revocation. Listener
  configuration refuses wildcard binds and the human listener's address/port.
  The application does not start this listener; it stays disabled until #14/#15
  wire it with their byte, connection and rate limits.
- **Agent** (`agent/media_capture_agent/node_tls.py`): non-root EC P-256 key
  generation into a write-once 0600 file under a 0700 runtime directory, CSR with
  an empty subject, trust-bundle parsing, issued-credential validation (own key,
  deployment CA, capture-only scope) before `NodeCredentialStore.install`, and a
  TLS 1.3 client context pinned to the deployment CA with hostname verification
  and no key-log support.
- **Evidence.** Real loopback TLS tests with temporary CAs cover mutual-auth
  success; wrong CA (both directions), expired client and server certificates,
  wrong server name, missing client certificate, plaintext, TLS 1.2 downgrade,
  orphan (unactivated) certificate, revocation of new and open sessions, role
  confusion between Main and node certificates, file modes, and absence of key
  material in logs, argv, environment and key-log files. A cross-process E2E
  (`tests/e2e/test_capture_mtls_scenarios.py`) runs the Agent side in separate
  processes.
- **Still open for #13 acceptance.** The bootstrap enrollment listener and wire
  protocol, the local Main approval CLI and Agent pairing CLI, crash-boundary
  fault injection, multi-process concurrent redemption over a real listener, and
  real LAN interoperability (MANUAL_TEST §B) are not implemented or verified by
  this change.
- **Validity and automatic renewal (Owner decision 2026-09-30).** This answers
  the "credential validity periods and future unattended renewal" policy that the
  Atomicity section above required before renewal could ship. Node leaves default to 397 days (still capped at
  397) and renew automatically; revocation and CA replacement rules above are
  unchanged. Implementation (`server/app/cameras/remote_agent/renewal.py`,
  `agent/media_capture_agent/node_tls.py`):
  - *Window and retries.* The Agent starts renewing 30 days before expiry and
    retries with exponential backoff from 1 hour, doubling to at most 24 hours.
    It reuses one fresh renewal key (0600, `pending-renewal/`) across retries.
  - *Eligibility.* The Main issues a renewal only for the node identity of the
    presenting mTLS session. That exact credential must still be the ledger's
    active, unexpired credential. The CSR must be for a new EC P-256 key that is
    not bound to any node, with an empty subject and no extensions. Revoked,
    expired or superseded credentials cannot renew; the node must re-pair with a
    fresh Owner approval.
  - *Supersession.* The renewed certificate is staged in the ledger (one per
    node; a retry replaces it; staging writes no audit record, so repeated
    requests cannot grow the audit table). The old certificate stays admitted
    until the renewed one is first presented. That admission atomically promotes
    it and appends an `activate_capture_node_credential` record (actor `system`).
    From then on only the new certificate is admitted, even though the old one
    has not expired. This keeps exactly one active credential per node, so
    revocation and audit stay per node. An Agent that never received or
    installed the response is not locked out: it keeps its old certificate and
    retries. Revocation deletes any staged renewal.
  - *Key uniqueness (Owner decision 2026-09-30).* A node public key is bound
    to at most one node, for good. `pairing_key_bindings` records every key
    the ledger approves, activates, stages or promotes and is never pruned. Approval,
    activation, renewal staging and promotion each refuse, in their own write
    transaction, a key that is bound to (or staged for) another node, whatever
    that node's credential state. Revocation marks all of the node's keys
    revoked, and a revoked key is never bound again, even to the same node.
    Main issues the renewed certificate before staging, so staging binds the
    new key permanently before the staged row is written. That binding
    survives a retry that replaces the staged row and a revocation before
    promotion (revocation marks it revoked like the node's other keys), so a
    key Main issued a certificate for is never bound to another node. Because
    each renewal retry with a fresh key adds a binding, a node may hold at most
    1024 bindings; beyond that, staging is refused (`renewal_not_eligible`,
    which raises the Owner signal below) and the node must re-pair. The Agent
    retries at most about 40 times per 30-day renewal window, so a legitimate
    node stays far below the cap. A key already bound to the node is
    accepted only as a retry of the currently staged renewal (same key as the
    staged row), without a new binding; a superseded key of the node, or an
    earlier staged key arriving after a newer one, is refused, so a superseded
    key is never re-staged and a newer staged renewal is never replaced by an
    older one. Migration 19 backfills the keys
    that existing enrollment and credential rows still record; if one legacy
    key digest appears under two node IDs (any state), the migration fails
    closed and blocks startup rather than silently picking one binding, and
    the Owner must remediate the conflicting rows first. It also fails closed
    when a key digest is revoked in one row yet still live in another (an
    active credential, or a pending or consumed enrollment, which the old
    schema allowed by re-approving a revoked key): recording a revoked binding
    would not stop the live credential, so the Owner must first revoke or
    remove the live use. Keys superseded
    before that migration are not recoverable.
  - *Agent rotation.* `NodeCredentialStore.rotate` atomically replaces the
    committed generation (rename over `current.json`) for the same node and
    deployment only, then removes the superseded files.
  - *Owner signal.* `CaptureCredentialMonitor` raises the local, Owner-visible
    `capture_credential_warning` notification through the injected notification
    hook in three cases: an active credential within 14 days of expiry (the
    Agent has retried for at least 16 days by then), an expired credential, or
    a refused renewal. Each is reported once per credential (or once per node,
    reason and day for refusals), counted only once the hook confirms it:
    the hook (`NotificationService.record`) must return a `DeliveryResult`, and
    only `suppressed`/`pending`/`sent`/`disabled` (written locally, or retained
    by the service for its own retry) confirm. `failed` (refused write with the
    retry buffer full, so the event was dropped), any other value or an
    exception leaves it unreported; the next check or refusal retries it with
    the same deterministic `event_id`, so the local sink upserts rather than
    duplicates. It is not an immediate Slack alert; changing
    that is a separate notification-policy decision.
  - *Not wired yet.* The renewal request and response travel over the ingest
    session that #14/#15 will carry. `ingest.py`/`continuity.py` are unchanged,
    and no scheduler or listener runs the renewal or the monitor yet.
  - The schema change is migration 19 (`pairing_credential_renewal`), after
    main's 17 (`human_access_webauthn`, PR #97) and 18
    (`human_access_shared_identity`, PR #107).

## Follow-up notes (2026-09-30, Issue #13 bootstrap enrollment and CLIs)

These notes record implementation progress; they do not change this ADR's
status or decision. They close the first item of "Still open for #13
acceptance" above except where listed at the end.

- **Main approval CLI** (`server/app/cameras/remote_agent/pairing_cli.py`,
  `python -m app.cameras.remote_agent.pairing_cli`): `init` (deployment CA plus
  the Main listener certificate in a separate private directory), `export-bundle`
  (public bundle; prints its full SHA-256 on the Main console; the server name
  is read from the listener certificate), `approve`, `list` and `revoke`.
  Creating a pairing and approving it are one step, as in the flow above:
  `approve` validates the Agent's public request file (the CSR must prove the key
  digest it names), shows that digest on the controlling terminal, requires the
  Owner to type `APPROVE`, calls `PairingLedger.approve` (new node UUID, key
  binding, code, audit row), writes the code **once to the controlling terminal
  only** (hyphen-grouped for reading), and then serves the bootstrap listener in
  the same process. Without a controlling terminal it refuses before touching any
  state. No command accepts a code. `revoke` requires typing `REVOKE`; `list`
  prints node UUIDs and state words only.
- **Owner authority in the CLI (pending #6).** The CLI's `OwnerAuthorizer` is
  local: the operating-system account that can open the owner-only issuer
  material and database, plus one typed confirmation on the controlling terminal
  per approve/revoke. Each confirmation authorizes exactly one ledger call, which
  writes the existing audit record. This is a stand-in for the #6
  Owner-authentication boundary, not a resolution of it.
- **Process epoch.** Approval and listener share one process because the ledger
  rejects pending approvals from any other process epoch. The HMAC verifier key is
  therefore generated in memory for each `approve` run and never stored; an
  interrupted run leaves only an unusable `pending` row.
- **Bootstrap listener** (`server/app/cameras/remote_agent/enrollment.py`):
  separate from the human and ingest listeners (explicit IP literal; wildcard,
  multicast and non-private addresses refused; must differ from the human
  listener and an optional ingest address). TLS 1.3 only, Main certificate, no
  client certificate, no session tickets, ALPN `serversentinel-capture-enroll/1`
  required. It opens only for the approvals of its own run and closes when they
  complete, when their five minutes end, after too many refused requests, or on
  interrupt. Limits (defaults): request frame 20 KiB, response frame 32 KiB,
  4 concurrent connections, one 10-second deadline per connection covering
  handshake, request and response, 6 connections per source address per minute,
  16 refused requests before the listener closes. The last limit is fail-closed:
  a LAN peer can force the Owner to approve again, but cannot extend a code's
  lifetime. These are initial values, not measured deployment limits.
- **Wire protocol v1.** One length-prefixed (4-byte big-endian) JSON frame each
  way. Request: exactly `version`, `deployment_id`, `code`, `csr`. Response:
  `{"status":"issued","certificate":PEM}` or the generic `{"status":"refused"}`,
  whatever the reason. The Main finds the approval by the CSR's proven key among
  its own run's approvals, then `PairingLedger.redeem` and
  `DeploymentAuthority.issue_and_activate`. A lost response needs a fresh
  approval. The TLS handshake necessarily shows any LAN peer the Main
  certificate (server name and deployment URI); nothing else is returned to an
  unauthenticated peer.
- **Agent pairing CLI** (`agent/media_capture_agent/enroll.py`,
  `python -m media_capture_agent.enroll`): `request` creates the node key (0600
  under a 0700 directory) and writes the public request file, printing the key
  digest; `pair` takes only the bundle file, its full SHA-256 and an optional
  endpoint override, refuses UID 0, and refuses before any network traffic if the
  digest differs. It then connects with TLS 1.3 pinned to the bundle CA, checks
  the server name, the ALPN protocol and that the Main certificate carries the
  bundle's deployment URI, and closes. Only then does it read the code from the
  non-echoing controlling-terminal prompt. It reconnects with the same full
  verification and sends one frame. It installs the result only after
  `validate_issued_credential`. The prompt accepts the grouped form and fixes a
  defect of the earlier primitive: it could not wrap a real (non-seekable)
  terminal.
- **Evidence (loopback, generated identities).** `tests/e2e/test_capture_enrollment_scenarios.py`
  runs both CLIs as separate processes, each with its own pseudo-terminal:
  enrollment through a recording relay followed by an admitted mTLS ingest
  connection; an Agent without a terminal refusing after verification without
  consuming the approval; the code absent from relay bytes, argv, environment,
  `/proc/<pid>/cmdline|environ`, stdout/stderr, every written file including the
  database and audit rows; no key-log file despite `SSLKEYLOGFILE`; revocation,
  refused ingest and refusal to approve the revoked key again. Impostor CA, a
  genuine certificate without the enrollment protocol, and a plaintext endpoint
  each receive zero application bytes and no prompt appears. A wrong bundle digest
  makes no connection. `server/tests/test_capture_enrollment.py` covers expired,
  reused, wrong-code, stolen-code/other-key, wrong-deployment and malformed
  requests, oversized frames, slow and silent peers, connection/source limits,
  the refusal cap, expiry, six concurrent redemptions yielding one credential,
  and bind validation. `agent/tests/test_enroll.py` covers the client against
  synthetic peers.
- **Still open.** Crash-boundary fault injection and concurrent redemption from
  separate processes (the concurrency test uses threads against the real
  listener); real LAN interoperability (MANUAL_TEST §B, unverified); a narrower
  issuance capability than the CLI process holding the CA key while it serves;
  Main listener-certificate renewal; the #6 Owner-authentication boundary.

## Follow-up notes (2026-10-07, Issues #116/#117 re-pairing and enrollment serialization)

These notes record the Owner decisions of 2026-10-01 and 2026-10-05 and their
implementation; they refine "A node cannot renew or replace its identity after
revocation" above without changing this ADR's status or bootstrap decision.
Every re-pair is a full bootstrap enrollment (same trust bundle, verified TLS
1.3 before the code, one-use code, typed local Owner approval) inside the
installed deployment; a different CA is a fresh install, never an in-place swap.

- **Expired, not revoked: same key, same node.** Allowed only once the installed
  certificate has expired; an unexpired credential renews automatically. The
  Main re-approves the key for the node it is already bound to after the Owner
  types `APPROVE`. The Agent accepts only a certificate for that node and
  deployment, for that key, outliving the expired one, and rotates it in
  atomically. Node UUID and camera-source assignments are unchanged.
- **Revoked: new key, new node.** A revoked key is never accepted again, even
  for its own node (the Main refuses it as `public_key_revoked` before the Owner
  prompt and inside the approval transaction). The Agent proves one fresh key
  kept in `pending-repair/` and accepts only a certificate for a different node
  of the same deployment, swapped in atomically. No camera source is carried
  over: the Owner approves the new node's sources again. The old node's ledger
  rows stay `revoked`; nothing is deleted, so its recordings stay attributed to
  the old node until normal retention.
- **Concurrent enrollment is refused immediately.** `request`, `pair` and the
  renewal steps hold one non-blocking runtime-wide `flock`
  (`<runtime_root>/node-enrollment.lock`, 0600, service account, no root):
  `pair` from the installed-identity check through install and pending-key
  cleanup, `request` through writing its public request file. A second run gets
  `enrollment_in_progress` before any network traffic or code prompt; it is
  never queued behind an interactive prompt.
- **Configuration stays a manual Owner edit; start fails closed.** After a
  revoked re-pair the CLI prints the exact `node_id` change. The Agent refuses to
  start (service and `--check`) with `node_identity_mismatch` while the
  configured `node_id` differs from the installed credential's node, and with
  `node_credential_unavailable` when the installed credential is damaged,
  unreadable, or its commit marker is lost after an identity was committed (a
  durable, never-removed `node-identity-installed` file records the first
  commit). Only a store without that evidence -- fresh, or a first install
  interrupted before its commit -- reads as unpaired.
- **Atomicity.** Both modes write and fsync the new generation, then atomically
  rename it over `current.json`; the old generation's files are deleted only
  after that commit. A renewal key staged for the old credential is discarded
  first (the Main drops staged renewals on activation). An interrupted revoked
  re-pair is completed by rerunning `pair --repair revoked` without a second
  exchange. The Agent's ring buffer and protected incidents are not touched.
- **Evidence.** Mock and loopback only (`agent/tests/test_enroll.py`,
  `agent/tests/test_pairing.py`, `agent/tests/test_check_reasons.py`,
  `server/tests/test_capture_enrollment.py`,
  `tests/e2e/test_capture_enrollment_scenarios.py`); real-host re-pairing is in
  `MANUAL_TEST.md` and unverified.
