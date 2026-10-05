# Remote Agent Adapter

Owns the Main Server side of capture-node registration, Owner-approved pairing/
revocation, authenticated LAN ingest, source/session validation, and separate
node/camera health reporting.

`pairing.py` is a dependency-free, listener-free domain ledger for the accepted
ADR-0006 flow. It creates a 128-bit, 26-character Base32 code with a five-minute
process-epoch lifetime, stores only an injected-verifier digest, binds redemption
to the approved Agent public-key digest, and makes activation and revocation
current durable admission state. It has no route, CLI, TLS socket, certificate
issuer, key generation, CSR parser, or credential-file writer. Those adapters
remain separately reviewed work; code input is never accepted by a command line,
environment, URL, or this module's logs.

The ledger requires an `AuditStore` on the same database. Approval, redemption,
activation and revocation commit together with their security audit record,
which names only the node's logical UUID; a refused Owner-only call records
`denied` and runs nothing, and unmatched redemption attempts record nothing.
See `server/app/audit/README.md`.

The deployment injects the verifier key from a protected secret boundary. A
restart gets a fresh epoch and rejects all old pending approvals rather than
reusing monotonic-clock state. The ledger's `admits` result is only a narrow
capture-node authorization primitive: it cannot authorize a human/API route.

## Capture-node CA and mTLS ingest adapter (Issue #13)

`node_ca.py` is the deployment-local issuer (uses the Owner-approved
`cryptography` dependency, see `server/docs/DEPENDENCIES.md`). It creates or
loads the EC P-256 deployment CA from an owner-only (0700) directory with
write-once 0600 files, writes the serverAuth-only Main ingest certificate/key to a
*different* private directory, exports the public trust bundle with its full
SHA-256 digest, and issues a capture-only client certificate for a redeemed
`EnrollmentClaim`. The CSR only proves possession of the approved key; the node
cannot choose its identity, SANs, key usage or scope. `issue_and_activate` signs
and then activates the exact certificate digest in the ledger, so a certificate
whose activation failed stays unusable. Validity is an explicit bounded
parameter that defaults to the Owner-decided 397 days.

`renewal.py` implements automatic renewal (Owner decision 2026-09-30).
`renew_node_credential` issues a certificate only for the presenting session's
own node. It requires that exact credential to still be the ledger's active,
unexpired one, and a fresh P-256 key whose CSR requests no subject or extension.
The result is staged with `PairingLedger.stage_renewal`: one per node, no audit
growth. The first admission of the renewed certificate promotes it atomically
and supersedes the old certificate, which stays admitted until then so a lost
response never locks the Agent out. Revocation discards staged renewals.
A node public key is bound to one node for good (`pairing_key_bindings`,
Owner decision 2026-09-30). Approval, activation, staging and promotion refuse
a key bound to or staged for another node, and a revoked key is never reused.
Staging binds the key permanently before the staged row is written, so a key
whose certificate Main issued stays bound even if a retry replaces the staged
row or the node is revoked first. Bindings per node are capped (1024); beyond
that renewal is refused and the node must re-pair. A key already bound to the
node is accepted only as a retry of the currently staged key; a superseded or
out-of-order earlier staged key is refused.
`CaptureCredentialMonitor` raises the local `capture_credential_warning`
notification through an injected hook in three cases: a credential within
14 days of expiry, an expired credential, or a refused renewal. A renewal
refused because the deployment CA expires before the requested leaf would is
reported as `renewal_ca_validity_insufficient` (not `renewal_request_invalid`)
and raises the deployment-wide `capture_trust_warning` once per day instead of
a per-node warning (#127). Given `ca_not_after` / `listener_not_after`, the
monitor also raises `capture_trust_warning` 30 days before the CA stops
covering a 397-day node leaf (`deployment_ca_expiring`), once it no longer
does, when the CA expired, and 30 days before / after expiry of the Main
listener certificate. The renewal exchange and the monitor are not yet run by
any listener or scheduler (#14/#15).

Listener credential lifecycle (#124/#125). `PrivateDirectory(owner_uid=...)`
may name another account than the process: new entries are then `fchown`-ed
to it before any content is written, which needs effective `CAP_CHOWN` and
`CAP_DAC_OVERRIDE` (reading needs `CAP_DAC_OVERRIDE` or
`CAP_DAC_READ_SEARCH`); without them every access refuses
(`OwnershipPrivilegeRequired`) before anything is created.
`DeploymentAuthority.initialize` locks both directories (`flock`, non-blocking,
`IssuerMaterialBusy` for the loser) and its rollback removes only entries this
run created (matched by device and inode). `rotate_main_server_credential`
replaces the listener key and certificate in place under the listener lock:
it verifies the current certificate was issued by this CA and matches its key,
keeps its server name, writes the new pair under `*.next` names, then renames
key and certificate over the current files. A run interrupted between the two
renames is completed by the next rotation; `listener_material` refuses a
mismatched pair (`ListenerMaterialInconsistent`) meanwhile. The CA is never
touched, so Agent trust bundles stay valid.

`ingest_tls.py` builds the ingest server `ssl.SSLContext` (TLS 1.3 only, client
certificate required, deployment CA only, strict X.509, no session tickets) and
turns an accepted TCP connection into an `AuthenticatedCaptureSession` whose
`CaptureNodeIdentity` carries a node UUID and digests only, never a human role.
Every connection re-reads the ledger's active record; `still_admitted()` must be
called before committing queued work and closes the session after revocation.
`IngestListenerConfig` refuses wildcard binds and the human listener's
address/port. Nothing starts this listener yet: the ingest core below and #14/#15
own wiring, per-connection byte limits and connection counts.

## Bootstrap enrollment listener and local approval CLI (Issue #13)

`enrollment.py` is the separate bootstrap listener of ADR-0006. It binds only an
explicit private IP literal (no wildcard, multicast or public address, never the
human or ingest socket address), speaks TLS 1.3 with the Main certificate and
the ALPN protocol `serversentinel-capture-enroll/1`, and carries exactly one
length-prefixed JSON request (`version`, `deployment_id`, `code`, `csr`) and one
response (`issued` with the certificate, or a generic `refused`). It opens only
for the approvals of the running `approve` command and closes when they
complete or expire, or after too many refused requests. Explicit
`EnrollmentLimits` bound frame sizes, concurrent connections, a single
per-connection deadline and attempts per source address. Logs carry fixed
reason words only.
Tailscale addresses (`100.64.0.0/10`, CGNAT) are also refused with
`enrollment_bind_requires_private_address`: capture enrollment and ingest are
designed for the private LAN and do not need Tailscale on either host.

`pairing_cli.py` (`python -m app.cameras.remote_agent.pairing_cli`) is the local
Owner CLI: `init`, `rotate-listener`, `export-bundle`, `approve`, `list`,
`revoke`. `--listener-owner` names the listener directory's account when it
differs from the CLI's (see `server/docs/DEPLOYMENT.md`). `rotate-listener`
replaces the Main listener leaf before it expires and keeps the CA and server
name; `export-bundle` and `approve` refuse `listener_authority_mismatch` when
the listener certificate was not issued by the selected CA directory (two
deployments' directories mixed up); `approve`, `list` and `revoke` require
`--database` to name the application's existing database (canonical path,
regular file with one link, owned by the account running the CLI, not group-
or other-writable) and refuse `database_not_found` / `database_rejected` /
`database_path_rejected` instead of creating one; `approve` refuses
`deployment_ca_validity_insufficient` before any
approval when the CA can no longer cover a 397-day node leaf. The bootstrap
listener sets `SO_REUSEADDR` (never `SO_REUSEPORT`) so a re-run binds while the
previous run's connections are in TIME_WAIT. `init` validates
the server name, both validity periods and both destination directories before
it writes the write-once CA, and removes what it created if listener issuance
still fails, so a corrected rerun works without manual secret-file cleanup.
`approve` shows
the request's key digest, requires a typed `APPROVE` on the controlling
terminal, creates the pairing through `PairingLedger.approve`, writes the code
once to the controlling terminal (never stdout, stderr, logs or files), and
serves the listener in the same process (the ledger's process epoch makes
approvals from other processes unusable; the HMAC key is per run and never
stored). It refuses before any state change when there is no controlling
terminal. `--human-host` (loopback IP) and `--human-port` name the dashboard
listener so the bootstrap listener can never take its socket. A key already
bound to a live node is re-approved for that same node (shown on the prompt),
so an interrupted, expired or unacknowledged enrollment can be retried; a
revoked key is refused. Until #6 lands, Owner authority in this CLI is the local account that
owns the issuer material and database plus one typed confirmation per
approve/revoke; see the ADR-0006 follow-up notes.

## Transport-neutral bounded ingest core

`ingest.py` is the in-process admission boundary used after a future dedicated
LAN listener has authenticated an Agent session. It exposes only typed
`heartbeat` and opaque `media` actions, requires injected node/source checks,
and defaults to rejection. Explicit deployment limits bound every queued
message, total queued bytes, and per-node message rate. Refusals report
`unauthorized`, size, rate, clock, or queue pressure without evicting accepted
messages or claiming camera/node health.

Per-node rate-window state is separately hard-bounded. Expired windows are
retired when capacity is needed; if every retained window is still active, a
new node fails closed with rate-window capacity pressure. The node lifecycle
should also call `forget_revoked_node` after durable revocation or node removal
to discard state promptly without exposing node identities in snapshots. A
mere transport disconnect must not reset a node's rate budget.

It opens no listener, parses no media/container, selects no transport, and
implements neither pairing nor mTLS. The eventual listener must independently
limit bytes before constructing an `AgentMessage`, remain separate from human
routes, and provide the revocable authenticated session required by Issue #13.

## Transport-neutral continuity core

`continuity.py` sits in front of `ingest.py` and implements the Proposed
ADR-0007 contract: Main-assigned session generations for an already
mTLS-authenticated node, the `(source_id, capture_epoch, sequence,
capture_time_ns)` media envelope (carried in full on each queued
`AgentMessage`), commit-after-admission so backpressure makes
the Agent retry rather than lose media, idempotent duplicate acknowledgement
(duplicates and other early refusals still consume the node's rate budget),
and bounded, coalescing gap events for skips and capture restarts (both
recorded when first observed, even on a refused unit, and never twice), clock
regressions and refused units.
After a Main Server restart each source resumes from the durable
`CommittedWatermark` supplied by the deployment, so already recorded units
are never reported as loss; while that lookup fails the source is reported
`degraded` (bounded, slot-limited) and nothing is committed. Known loss keeps a source flow `degraded` and a
closed or stale session makes it `interrupted`; after a reconnect each source
stays `interrupted` until it delivers media on the new session. Session generations are never
reissued (also after `forget_node` and re-enrollment), `forget_node` also
discards the node's ingest rate window under the tracker lock (so a
re-enrolled node UUID never inherits the old credential's rate/clock state),
and `forget_source`
releases a deactivated source's slot and returns its undrained gaps; while
that source's accepted units are still queued its committed position is kept
outside the slot limit, so a retry after reactivation stays a `duplicate`. The
node/source lifecycle commits a durable revocation or source deactivation
inside `authorization_change` (tracker, or queue for direct queue users), so
it is serialized with every grant, liveness refresh, charge and enqueue. On
success, before the lock is released, the block forgets a revoked node with
its sources and rate window and releases a deactivated source's slot, handing
undrained gaps back to the caller. Tracked node
sessions have their own hard bound, separate from the 1-4 active-source limit;
this is flow continuity, not
camera or node health. It opens no listener, selects no protocol and performs
no cryptography; tests are synthetic only.

Accept only narrow agent actions with bounded input. Agent credentials grant no
human/admin API rights; the ingest listener exposes no dashboard routes. Do not
require SSH access to capture nodes, change Tailscale policy, or route browser
viewers directly to agents.
