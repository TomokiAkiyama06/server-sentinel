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
`cryptography` dependency, see `server/docs/CRYPTOGRAPHY_AUDIT.md`). It creates or
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
`CaptureCredentialMonitor` raises the local `capture_credential_warning`
notification through an injected hook in three cases: a credential within
14 days of expiry, an expired credential, or a refused renewal. The renewal
exchange is not yet carried by any listener (#14/#15).

`ingest_tls.py` builds the ingest server `ssl.SSLContext` (TLS 1.3 only, client
certificate required, deployment CA only, strict X.509, no session tickets) and
turns an accepted TCP connection into an `AuthenticatedCaptureSession` whose
`CaptureNodeIdentity` carries a node UUID and digests only, never a human role.
Every connection re-reads the ledger's active record; `still_admitted()` must be
called before committing queued work and closes the session after revocation.
`IngestListenerConfig` refuses wildcard binds and the human listener's
address/port. Nothing starts this listener yet: the ingest core below and #14/#15
own wiring, per-connection byte limits and connection counts. The bootstrap
enrollment listener and the local approval CLI are not implemented.

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

Accept only narrow agent actions with bounded input. Agent credentials grant no
human/admin API rights; the ingest listener exposes no dashboard routes. Do not
require SSH access to capture nodes, change Tailscale policy, or route browser
viewers directly to agents.
