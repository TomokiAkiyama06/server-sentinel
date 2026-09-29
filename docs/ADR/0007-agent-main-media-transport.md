# ADR-0007: Agent-to-Main media transport selection and continuity contract

Status: Proposed — awaiting Owner decision. The transport protocol is **not
selected** by this ADR; selection requires the real-LAN measurements below.

Related Issues: #15 (Plan 9), #13/ADR-0006 (capture-node trust), #14 (ingest
boundary), #16 (Agent ring buffer), #17 (recording).

## Context

Issue #15 requires a PoC comparison of WebRTC, SRT, QUIC and authenticated
HTTP streaming, ranked by (1) stability, (2) reconnect, (3) accurate gap
reporting, (4) bounded buffering/backpressure, (5) authenticated encryption,
(6) resource usage, (7) latency. Authenticated encryption is a mandatory
invariant for every candidate regardless of its rank. Near-real-time is the
goal, but stability and reconnect take priority over any particular latency.

No Main Server, capture node or UVC camera has been available to this work.
Nothing in this ADR has been measured on real hardware or a real LAN, and no
candidate is claimed verified. Fixing a protocol before measurement is
explicitly forbidden by the Issue.

## Decision

### Accepted now (subject to Owner approval of this ADR)

1. **Transport-independent media envelope.** Every media unit carries
   `(source_id, capture_epoch, sequence, capture_time_ns)`, independent of any
   protocol's internal counters:
   - `capture_epoch` is an Agent-maintained, strictly increasing capture-process
     epoch (persisted by the Agent, e.g. with its ring ledger);
   - `sequence` counts units per source within one epoch and survives transport
     reconnects;
   - `capture_time_ns` is the Agent monotonic capture clock within that epoch.
     The Main Server does not compare it with its own clock; cross-host clock
     offset stays with SPECIFICATION §5.9 heartbeat timing.
   A lossless reconnect therefore yields no gap, a lossy reconnect yields an
   exact missing-unit count, and a capture restart yields a gap of explicitly
   unknown extent. Every candidate is evaluated by the same Main-side assertions.
   The complete envelope (including `capture_epoch` and `capture_time_ns`)
   travels with each admitted unit in the ingest queue, so a downstream
   consumer can distinguish units of different epochs and preserve the Agent
   capture timestamp (REQUIREMENTS MEDIA-007).
2. **Main-assigned session generation.** Each authenticated session open gets a
   new generation; a superseded session cannot deliver, heartbeat or close the
   newer one. Generations come from one tracker-wide counter that is never
   reset or reissued (also across node removal and re-enrollment of the same
   UUID), and each grant is bound to one Main process lifetime, so a revoked
   or pre-restart grant can never become current again. Every authorization
   that decides a session open, a heartbeat refresh, or a media outcome
   (including the ingest queue's recheck and charged early refusals) is
   evaluated while the lock guarding that state is held, so a call that waited
   across a revocation can neither issue a fresh grant, refresh liveness,
   acknowledge a revoked source, enqueue media, nor recreate a rate window.
   Because a durable revocation commits in its own database transaction, the
   node/source lifecycle commits it inside the tracker's (and, for direct
   queue users, the queue's) `authorization_change` block, which holds those
   locks for the commit: every check-then-act section runs entirely before or
   entirely after it. Before the block releases the tracker lock, a revoked
   node is forgotten with its sources (so a grant issued just before the
   commit is unusable) and its rate window is discarded, and a deactivated
   source releases its active-source slot; undrained gaps of released
   sources are handed back to the caller for persistence, never dropped.
3. **Commit only after bounded admission.** A unit advances continuity only
   after the #14 `AgentIngestQueue` accepts it. Backpressure/rate refusal
   leaves state unchanged so the Agent retries the same sequence from its disk
   ring buffer; a retry of a committed unit is an idempotent `duplicate`
   acknowledgement and is never enqueued twice. Every media attempt of an
   authorized node consumes its per-node ingest rate budget, including a
   `duplicate` and an early refusal that is never enqueued (stale session or
   capture epoch, source mismatch/capacity, unauthorized source); once the
   budget is spent such an attempt is reported `rate_limited` and changes no
   continuity state. The node is re-authorized before it is charged; a node
   revoked meanwhile is refused `unauthorized`, is not charged, and loses its
   session grant. Only a refusal that no retry
   of the same unit can satisfy (currently `message_too_large`) is committed
   past and recorded as known loss; any other ingest refusal (for example the
   ingest boundary's fail-closed Main clock regression) leaves continuity
   unchanged, keeps the flow `degraded`, and records no loss claim. A
   `duplicate` acknowledgement means "at or behind the committed head", not
   proof that that exact sequence was committed: a late unit behind an
   already-reported skip is also acknowledged as `duplicate`, so the Agent
   sends each source in order and keeps loss-window protection independent of
   Main acknowledgements.
4. **No silent healthy state.** Known loss, clock regression, or backpressure
   keeps the source flow `degraded`, including pressure or a transient refusal
   on a source's very first unit before anything is committed (reported with
   no committed sequence); a closed or stale session makes it
   `interrupted`. Pending gap events are hard-bounded per source and coalesce
   into an unknown-extent event rather than being dropped. Flow continuity is
   separate from camera health and from node health (SPECIFICATION §5.8).
5. **Security invariants for any candidate.** Mutual authentication with the
   ADR-0006 deployment-scoped mTLS identity before any media is accepted; a
   dedicated ingest listener separate from the human dashboard listener; the
   capture credential grants no human/admin API right; no Tailscale
   requirement on private LAN; no arbitrary paths/URLs from the Agent; bounded
   pre-read byte limits in the listener.

`server/app/cameras/remote_agent/continuity.py` implements items 1–4 as a
transport-neutral, listener-free domain object with synthetic tests only.

### Deferred to Owner decision after measurement

The concrete protocol, framing, codec/container carriage, and any new
dependency. The PoC must run each candidate through the same deterministic
impairment matrix and record the measurements in the table below.

## Alternatives

| Candidate | Expected strengths (unverified) | Concerns to measure | Dependency/licence notes (must be re-verified at pinning) |
| --- | --- | --- | --- |
| WebRTC (media + data channels) | Built-in congestion control, NAT handling not needed on LAN | Complexity, DTLS identity binding to ADR-0006 mTLS, jitter-buffer loss hiding, resource use | e.g. aiortc (reported BSD-3-Clause) or GStreamer webrtcbin (LGPL); verify exact licence and transitive codecs |
| SRT | Designed for contribution links, ARQ and latency window | Passphrase-based AES is not mutual certificate identity; would need mTLS wrapping or separate control channel | libsrt (reported MPL-2.0); verify obligations |
| QUIC (streams/datagrams) | TLS 1.3 mutual auth native, multiplexed per-source streams, connection migration | Library maturity, userspace CPU cost | e.g. aioquic (reported BSD-3-Clause); verify |
| Authenticated HTTP/2 or WebSocket streaming over mTLS | Simplest, reuses TLS 1.3 mTLS, explicit application acknowledgements | Head-of-line blocking over TCP, reconnect latency | Standard library TLS plus a reviewed server library |

Licence entries above are candidate notes, not a completed review. Any
selected dependency needs the full `docs/THIRD_PARTY_POLICY.md` review.

## Consequences

- The Agent must persist `capture_epoch` and keep per-source sequence across
  reconnects; the Agent-side sender is follow-up work.
- Backfill of lost units from the Agent ring buffer after reconnect is not
  admitted by this contract (older sequences are duplicates). A future
  backfill path needs its own ADR amendment.
- The transport adapter stays thin: authenticate, bound bytes, frame the
  envelope, map outcomes to acknowledgements.

## Validation

Synthetic (done, mock only): `server/tests/test_remote_agent_continuity.py`
covers deny-by-default, cross-node source spoofing, idempotent retries,
exact/unknown gaps, stale sessions, bounded backpressure and gap coalescing,
1–4 sources with a fifth refused, stale/clock-regression fail-closed,
revocation, concurrency, and a deterministic synthetic impairment run.

Real hardware (not done): MANUAL_TEST.md §G "Agent-to-Main transport PoC".
Record per candidate, for 1, 2, 3 and 4 sources (state real vs synthetic
inputs for each):

| Measurement | WebRTC | SRT | QUIC | HTTP/WS |
| --- | --- | --- | --- | --- |
| Reconnect time after 1–5 s link loss | | | | |
| Gap reported vs actual after reconnect | | | | |
| Max sender / receiver queue depth, slow consumer | | | | |
| Behaviour under sustained packet loss / added jitter | | | | |
| LAN glass-to-glass latency (informational) | | | | |
| CPU / GPU / VRAM, Main and Agent | | | | |
| Bitrate | | | | |
| Codec/container and recording-extraction impact | | | | |

## Follow-up

- Owner decision on this ADR and, after measurement, on the selected protocol.
- Agent-side envelope sender and `capture_epoch` persistence (#12/#16).
- Dedicated ingest listener with mTLS (ADR-0006 adapters, #13/#14).
- Durable consumer for drained gap events (timeline / recording health).
