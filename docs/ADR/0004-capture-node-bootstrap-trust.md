# ADR-0004: Capture-node bootstrap trust and revocable enrollment

Status: Proposed — explicit Owner decision required; no runtime behavior enabled.

Related Issues: #13 (Plan 7), #6 (Owner authority), #12 (Agent foundation),
#14 (ingest isolation), #15 (media transport).

## Context

The existing requirements already require intended-Main authentication and
encryption **before** transmitting a pairing code, followed by a unique revocable
node identity. LAN reachability, a short-lived code, and later mTLS cannot establish
that initial trust. SPECIFICATION §5.4 deliberately leaves the exact method open.

This proposal makes that choice reviewable. It does not approve itself, select the
media protocol in #15, introduce human authentication, or complete #13. Owner
authority still depends on #6; its proposed local administrative bootstrap is not
silently accepted here. There is no dashboard/UI implementation in this change.

## Proposed decision for Owner approval

Recommend a deployment-local CA public trust bundle transferred through an
Owner-controlled local/out-of-band channel. Use a local administrative Main CLI
for enrollment approval and a non-root Agent CLI for pairing. TLS 1.3 authenticates
the Main during bootstrap; deployment-scoped mTLS authenticates both endpoints
afterward. The proposed code is 128 random bits, rendered as 26 Base32 characters,
valid for five minutes and one atomic redemption. These are proposed settings,
not approved product defaults.

The Owner can approve this package or select fingerprint pinning below. Until the
decision is recorded as Accepted, bootstrap/ingest ports remain disabled and
unpaired Agent adapters remain unable to send network traffic.

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

## Proposed enrollment flow

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

1. Obtain Owner acceptance of the trust channel/CLI flow and proposed code
   parameters, and finish the #6 authorization prerequisite. Record the decision
   and sync REQUIREMENTS/SPECIFICATION/SECURITY before enabling behavior.
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

## Owner decision record

Pending: recommended local-CA public bundle and trusted transfer, local privileged
Main approval plus non-root Agent pairing, approved-public-key binding, TLS 1.3,
and 128-bit/five-minute/one-use code. An Owner response is required to move this ADR
to Accepted. The existing #6 Owner-authentication and #4 GitHub-App decisions remain
separate; this proposal neither repeats nor resolves them.
