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
and bounded, coalescing gap events for skips, capture restarts (recorded when
first observed, even on a refused unit), clock regressions and refused units.
After a Main Server restart each source resumes from the durable
`CommittedWatermark` supplied by the deployment, so already recorded units
are never reported as loss. Known loss keeps a source flow `degraded` and a
closed or stale session makes it `interrupted`; after a reconnect each source
stays `interrupted` until it delivers media on the new session. Session generations are never
reissued (also after `forget_node` and re-enrollment), `forget_node` also
discards the node's ingest rate window under the tracker lock (so a
re-enrolled node UUID never inherits the old credential's rate/clock state),
and `forget_source`
releases a deactivated source's slot and returns its undrained gaps. The
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
