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
SHA-256 digest, and issues a capture-only client certificate for an
Owner-approved key. The CSR only proves possession of the approved key; the node
cannot choose its identity, SANs, key usage or scope. Validity is an explicit
bounded parameter that defaults to the Owner-decided 397 days.

Public and signing roles are separate (Issue #109). `DeploymentTrust` holds
only the CA certificate: CSR proof of possession, CA validity checks, listener
and node certificate verification (`verify_issued_node_certificate` /
`verify_issued_listener_certificate` check the direct issuer, the fixed leaf
profile, the URIs and the key), staged-renewal re-validation and the trust
bundle. `DeploymentAuthority` extends it with the CA private key and is
constructed only by the CA-account issuer (`issuer_process.py`) and by tests.
The listener directory keeps a public copy of the CA certificate
(`deployment-ca-certificate.pem`) so the service account can verify and export
without the CA directory.

`issuer_process.py` is the CA side of the pairing CLI. `ForkedIssuer.start`
forks, before any thread exists, a child that starts a new session, keeps only
its two pipe ends (stdin/stdout/stderr become `/dev/null`), drops to the
static `serversentinel-ca` account (`setgroups([])`, `setresgid`,
`setresuid`, no_new_privs, non-dumpable, parent-death signal) and verifies the
drop. `CaIssuer` answers `hello` with the public CA certificate and then
performs at most one of `sign_node`, `sign_listener`, `revoke` (or
`initialize` with a later `commit`/`abort`), deciding from its CA-only
issuance log (`issuance-log.jsonl`, 0600): a node revoked there, or a key bound
there to another or a revoked node, is refused, and every signature or
revocation is appended with fsync before it is answered (an unwritable log
means nothing is signed). Frames are length-prefixed JSON over the pipes;
every child failure is `issuer_unavailable` for the caller.

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
out-of-order earlier staged key is refused. Such a retry is
certificate-idempotent (Issue #123): the staged row keeps the issued
certificate's public PEM, bound to its digest, and the retry is answered with
that first certificate (re-verified as this CA's leaf for the node and key)
instead of a newly signed one. The staged certificate is looked up before
anything is signed, so a retry after the CA fell below the leaf validity still
receives it (#148). A connection that loses a concurrent promotion
of the same staged renewal is admitted if its exact key and certificate are by
then the active credential (Issue #121).
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
any listener or scheduler (#14/#15); meanwhile `pairing_cli` `init`,
`rotate-listener`, `export-bundle` and `approve` print the CA expiry and the
same warning words on stderr (`ca_expiry_reason` / `listener_expiry_reason`).
Interim (Issue #109): renewal signs through `renewal.RenewalIssuer`, which
today only an in-process `DeploymentAuthority` implements (tests); nothing in
the application calls it, and wiring it into a listener waits for the
renewal-only signer of Issue #109 PR2.

Listener credential lifecycle (#124/#125). `PrivateDirectory(owner_uid=...)`
may name another account than the process: new entries get their final 0600
mode and are then `fchown`-ed to it before any content is written (no mode
change after the ownership change, which would need `CAP_FOWNER`, #149),
which needs effective `CAP_CHOWN` and
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
renames -- or whose key rename took effect but could not be fsynced
(`ReplacementNotDurable`, which keeps the staged certificate) -- is completed
by the next rotation, before the new validity is checked against the CA
expiry (#148); `listener_material` refuses a
mismatched pair (`ListenerMaterialInconsistent`) meanwhile. The CA is never
touched, so Agent trust bundles stay valid.

`ingest_tls.py` builds the ingest server `ssl.SSLContext` (TLS 1.3 only, client
certificate required, deployment CA only, strict X.509, no session tickets) and
turns an accepted TCP connection into an `AuthenticatedCaptureSession` whose
`CaptureNodeIdentity` carries a node UUID and digests only, never a human role.
Every connection re-reads the ledger's active record; `still_admitted()` must be
called before committing queued work and closes the session after revocation.
`IngestListenerConfig` refuses wildcard binds, Tailscale addresses
(`ingest_bind_tailscale_address_refused`, same ranges as below) and the human
listener's address/port. Nothing starts this listener yet: the ingest core below and #14/#15
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
Tailscale addresses are also refused with
`enrollment_bind_requires_private_address`: IPv4 `100.64.0.0/10` (CGNAT) and
IPv6 `fd7a:115c:a1e0::/48` (a ULA, so being "private" does not exempt it), in
either spelling of an IPv4-mapped address (Issue #150). Capture enrollment and
ingest are designed for the private LAN and do not need Tailscale on either
host. `addresses.py` holds these ranges for both listeners; it classifies by
address only, so another network that reuses those ranges is refused too.
The same ranges are refused as a bundle endpoint (Owner decision 2026-10-07):
`export-bundle --endpoint` with an IP literal in them refuses
`trust_bundle_endpoint_tailscale_address_refused` and writes no bundle. A DNS
name is not resolved on the Main; the Agent refuses
`main_endpoint_tailscale_address_refused` for a Tailscale bundle endpoint,
`pair --endpoint` override or connected peer address (its copy of the ranges
lives in `agent/media_capture_agent/addresses.py`, kept equal by
`tests/unit/test_tailscale_ranges_match.py`).

`pairing_cli.py` (`python -m app.cameras.remote_agent.pairing_cli`) is the local
Owner CLI: `init`, `rotate-listener`, `export-bundle`, `approve`, `list`,
`revoke`. `init`, `rotate-listener`, `approve` and `revoke` start as root
(`sudo`), fork the CA child (above), and then drop to the service account
(`--service-user`, default `server-sentinel`; `--ca-user` defaults to
`serversentinel-ca`), verifying `CapEff==0` and `euid!=0` and that the CA
directory can no longer be opened, before they open the request file or the
database (`server/docs/DEPLOYMENT.md`). Listener keys are generated on the
service-account side and only their CSR goes to the CA child, so nothing
changes owner. `export-bundle` and `list` run as the service account and read
only public material and the database. `rotate-listener`
replaces the Main listener leaf before it expires and keeps the CA and server
name; `export-bundle` and `approve` refuse `listener_authority_mismatch` when
the listener certificate was not issued by the deployment CA (two
deployments' directories mixed up); `approve`, `list` and `revoke` require
`--database` to name the application's existing database (canonical path,
regular file with one link, owned by the service account the command runs as,
not group- or other-writable) and refuse `database_not_found` / `database_rejected` /
`database_path_rejected` instead of creating one, refuse
`database_schema_outdated` / `database_schema_unsupported` instead of
migrating (migrations run only at application startup), and keep the validated
file pinned so a later rename/replacement refuses `database_rejected` on every
connection and before every commit (SQLite `mode=rw`, never created; the
descriptor SQLite opened must be the pinned inode, checked via `/proc/self/fd`); `approve` refuses
`deployment_ca_validity_insufficient` before any
approval when the CA can no longer cover a 397-day node leaf. The bootstrap
listener sets `SO_REUSEADDR` (never `SO_REUSEPORT`) so a re-run binds while the
previous run's connections are in TIME_WAIT. `init` validates
the server name, both validity periods and both destination directories before
it writes the write-once CA, and removes what it created if listener issuance
still fails, so a corrected rerun works without manual secret-file cleanup.
`approve` shows
the request's key digest, requires a typed `APPROVE` on the controlling
terminal, creates the pairing through `PairingLedger.approve`, has the CA child
sign the node certificate (signed after approval and before redemption, valid
only after activation; ADR-0006 follow-up of 2026-10-07), verifies it against
the public CA and waits for the child to exit, then writes the code once to
the controlling terminal (never stdout, stderr, logs or files) and serves the
listener in the same process with no CA-key process alive (the ledger's
process epoch makes approvals from other processes unusable; the HMAC key is
per run and never stored). On redemption the listener, which holds only
`DeploymentTrust`, activates exactly that pre-signed certificate; any issuer
failure refuses `issuer_unavailable` without showing the code. `revoke`
revokes in the ledger, then records `node_revocation` in the CA issuance log
(`ca_revocation_unrecorded` and exit 1 if that fails; a rerun records it). It refuses before any state change when there is no controlling
terminal. `--human-host` (loopback IP) and `--human-port` name the dashboard
listener so the bootstrap listener can never take its socket. A key already
bound to a live node is re-approved for that same node (shown on the prompt),
so an interrupted, expired or unacknowledged enrollment can be retried, and a
node whose certificate expired without being revoked re-pairs with its same key
and node (#116). A key ever held by a revoked node is refused with
`public_key_revoked` before the Owner prompt or the listener opens
(`PairingLedger.key_revoked`; `approve` refuses it again inside its write
transaction). A revoked node re-pairs only as a new node with a new key: the
prompt says `new capture node`, no camera source is carried over from the old
node (the Owner approves the new node's sources again), and the old node's
ledger rows stay `revoked` -- nothing is deleted, so its recordings stay
attributed to the old node until normal retention removes them. Until #6 lands, Owner authority in this CLI is the local administrator who
can start it as root plus one typed confirmation per approve/revoke; see the
ADR-0006 follow-up notes.

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
releases a deactivated source's slot and returns its undrained gaps; its
continuity (committed position, attempted epoch, loss already recorded from a
refused unit) is kept outside the slot limit, hard-bounded by
`maximum_released_sources`, until the durable recording layer calls
`acknowledge_persisted` with a watermark covering it, so a retry after
reactivation stays a `duplicate` and the same loss is never reported twice
(leaving the ingest queue is not durability). A late unit behind loss already
recorded from a refused unit is acknowledged as `duplicate`, never admitted. The
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
