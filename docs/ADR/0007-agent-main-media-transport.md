# ADR-0007: Agent-to-Main media transport selection and continuity contract

Status: Continuity contract accepted (Owner decision, 2026-11-02).
`a_framed` (TLS 1.3 mTLS framed stream) is the **provisionally** selected
transport (same decision), based on the real-LAN measurements below; it stays
provisional until the Owner's raw record review below is complete. It is a
harness candidate, not a product implementation: no product ingest path uses
it yet (#14).
Owner decision (2026-09-30): the transport is decided only after real-LAN
measurement with the capture host.

Related Issues: #15 (Plan 9), #13/ADR-0006 (capture-node trust), #14 (ingest
boundary), #16 (Agent ring buffer), #17 (recording).

## Context

Issue #15 requires a PoC comparison of WebRTC, SRT, QUIC and authenticated
HTTP streaming, ranked by (1) stability, (2) reconnect, (3) accurate gap
reporting, (4) bounded buffering/backpressure, (5) authenticated encryption,
(6) resource usage, (7) latency. (SRT was later dropped from the PoC candidate set by the
Owner on 2026-10-11; see the Measurement harness section.) Authenticated encryption is a mandatory
invariant for every candidate regardless of its rank. Near-real-time is the
goal, but stability and reconnect take priority over any particular latency.

When this ADR was first written no Main Server, capture node or UVC camera was
available. The measurements in the Validation section were taken on 2026-10-29
with the harness on the private LAN; they measure the harness candidates, not
a product ingest path. Fixing a protocol before measurement is explicitly
forbidden by the Issue.

## Decision

### Continuity contract (accepted by the Owner, 2026-11-02)

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
   unknown extent, even when the source's earlier-epoch unit was attempted but
   never committed (a lower epoch than one already attempted is refused as
   stale). A restart or skipped sequences are recorded when a refused unit
   first shows them, so that loss is not lost if the unit is never retried,
   and a retry never reports it twice. After a Main Server restart a
   source resumes from the durable recording layer's committed watermark, so
   units recorded by the earlier Main process are never reported as loss.
   That durable lookup happens only for an attempt that fits the node's rate
   budget, so an over-budget node cannot drive unbounded durable-store work.
   Every candidate is evaluated by the same Main-side assertions.
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
   The released source's continuity (committed position, attempted epoch,
   loss already recorded from a refused unit) is kept, hard-bounded, outside
   the slot table until the durable recording layer acknowledges a watermark
   covering it, not merely until its units leave the ingest queue, so a
   reactivated source neither enqueues a unit twice, accepts a stale epoch,
   nor reports the same loss twice (Issues #113, #118).
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
   already-reported skip is also acknowledged as `duplicate` (including a
   skip or restart recorded from a refused unit that is not committed yet,
   so media never contradicts the recorded gap), so the Agent
   sends each source in order and keeps loss-window protection independent of
   Main acknowledgements.
4. **No silent healthy state.** Known loss, clock regression, or backpressure
   keeps the source flow `degraded`, including pressure or a transient refusal
   on a source's very first unit before anything is committed (reported with
   no committed sequence); a closed or stale session makes it
   `interrupted`, and after a reconnect or superseding session each source
   stays `interrupted` until it delivers media on the new session (node
   connectivity alone never clears a camera's interruption). Pending gap events are hard-bounded per source and coalesce
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

### Transport selection (provisional, Owner decision 2026-11-02)

`a_framed`: length-prefixed frames over TLS 1.3 mTLS, stop-and-wait per
source, 1 s heartbeat, `TCP_NODELAY` set. Measured against `b_chunked` the
result does not separate them on gates or normal-run performance, so this is
a judgement, and these are its grounds:

- `b_chunked` carries the same frames inside a long-lived HTTP/1.1 chunked
  request, so the ingest listener would also have to parse HTTP. Item 5 asks
  for bounded pre-read limits there, and `a_framed` has less to parse. This is
  a design argument, not a measurement.
- Reconnect p95 is slightly lower (2.02 s against 2.23 s), in one `rst` run
  per candidate with three reconnects, so it is weak evidence.
- Against it: `a_framed` had more unprotected gap units than `b_chunked` (3904
  against 3584), and those counts differ mainly by run-to-run variation in
  impaired scenarios that are all exactly accounted (see the table).

`b_segment` is not selected: its latency is about 1 s by design, and it has a
recorded G3 fail (see below).

Still open, and not decided by this selection: codec/container carriage and
recording extraction (#313), and any dependency the product implementation
adds (`docs/THIRD_PARTY_POLICY.md`). The harness candidates use only the
Python standard library and the repository's own Agent and Main code.

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

Measurement harness (Issue #15): `scripts/manual/transport_poc/` runs the
same impairment matrix and G1–G6 gates for TLS 1.3 mTLS framed streaming and
mTLS HTTP/1.1 chunked / 1 s segment upload. It selects no candidate by itself;
its two-host results of 2026-10-29 are recorded below.

SRT is dropped from the PoC candidate set (Owner decision, 2026-10-11): its
passphrase-based encryption gives no mutual certificate identity (ADR-0006)
and cannot satisfy G1, so the harness has no SRT adapter and the table below
has no SRT column.

Real hardware: MANUAL_TEST.md §G "Agent-to-Main transport PoC". Recorded per
candidate, for 1, 2, 3 and 4 sources (real vs synthetic inputs stated in the
results below).

The harness candidates are `a_framed` (TLS 1.3 mTLS framed stream),
`b_chunked` (mTLS HTTP/1.1 chunked upload) and `b_segment` (mTLS HTTP/1.1
1 s segment upload); WebRTC and QUIC are not in the harness and SRT is dropped.

Transcribe only summaries in which every run has `fast: false` (full timing;
`fast_runs` 0 on the candidate row): `--fast` results are CI smoke durations,
not measurements. For two-host runs, state that the Main-side stop/restart
and Main stale-detection checks of G5 are matched by count only (no
cross-host clock comparison, so no per-window attribution).

Harness follow-ups of Issue #237 (used by the 2026-10-29 runs): the G4
reconnect after a Main-side stop/restart is measured from
the window end on two hosts as well, as a Main-clock (window end -> HELLO
received) plus an Agent-clock (TLS handshake done -> first accepted unit)
interval, which can only overstate the true value; Main's own stop time is no
longer counted (by the #237 record analysis, not a two-host measurement, it
would put about 55 s p95 on `slow_stop_60s`, a false FAIL).
Heartbeat-reply records are atomic with the receiver's stop, the first reply
after a pause always carries an echo (numbered heartbeat-reply frames and an
Agent received-frame count tell whether a repeated echo actually reached the
Agent), and the fast `slow_stop_10s` stop is 4 s
so the Agent detects it.

TCP_NODELAY (Issue #369): no run recorded before the harness set it is a
measurement of a candidate. The summarizer makes every run without
`tcp_nodelay: true` in its sender, receiver and proxy records `unmeasured`
(integrity and every gate, pass or fail) and leaves it out of the
candidate's secondary values (reconnect p95, latency, overhead, unprotected
gap units, `secondary_*`; counted in `nodelay_excluded_runs`); re-summarized, all 38 runs of
2026-10-26 (real and synthetic, 1–5 sources) are `unmeasured`. On that day
every 1-source real run (~150 KB MJPEG frames) showed an almost constant
per-unit RTT (p50 46 ms, p95 48 ms, per-second unit size uncorrelated with
time per unit), delivered about 27 of 30 fps and kept the sender pending at
its cap. The 2–5 source synthetic runs had a small p50 (7–10 ms), but they
were not unaffected: their tail latency can include the same stall (p95 up to
32 ms there; 33 ms for 2 sources on loopback without `TCP_NODELAY`).

A one-host loopback A/B in a CPU-limited container (1 source) reproduced a
stall: Nagle holds a small segment at the end of a unit while the receiver
delays its ACK (40 ms minimum on Linux). Whether a unit stalls depends on its
size, the sender's 64 KiB write split and the MSS (Linux's Minshall variant
of Nagle): with 125 KB and 147 KB units `a_framed` / `b_chunked` stalled on
almost every unit (RTT p50 41 ms); `b_segment` (one PUT per second) stalled
on some or all segments depending on the run (p50 5–42 ms, p95
5.7–44 ms, max 41–45 ms); 16 KB units did not stall, and with a 1448-byte MSS
(`TCP_MAXSEG`, closer to Ethernet) a fraction stalled (p50 0.4 ms, p95
41 ms). `TCP_NODELAY` removed it (p50 0.3 ms; `b_segment` max about
5.8 ms); a 5 ms
instead of 50 ms sender `select` timeout changed nothing. On loopback both
the sender and the proxy's upstream socket needed it; with the 1448-byte MSS
the Agent socket alone sufficed. Re-run on the LAN on 2026-10-29 with
`TCP_NODELAY`, the 1-source real `normal` run has RTT p50 3.9 ms and p95
5.5 ms (`a_framed`), 3.9 ms and 4.7 ms (`b_chunked`), with pending max 1. So
that mechanism fits, though the 46 ms itself was not reproduced by switching
only that one setting on the LAN. **Product follow-up (#14):** the Agent media
connection (after `connect_to_main`) and the Main ingest session socket must
set `TCP_NODELAY` (or otherwise never leave a unit's tail waiting for an ACK)
for any stop-and-wait or small-window acknowledgement design; the product
code does not set it today.

### Results of 2026-10-29 (two hosts, private LAN)

66 runs, all `fast: false`, all with `tcp_nodelay: true`: 60 matrix runs (20
per candidate), 3 reruns of `slow_stop_10s` for `b_segment`, and a 30-minute
`soak` per candidate. The harness is the tree of `f2b6142`; later changes to it
only remove the 3 h scheduler check (#372).

Inputs: 1 real camera (MJPEG 1280x720, 30 fps declared) for `normal`,
`outage_1s/8s/120s`, `rst`, `slow_stop_10s/60s`, `main_restart`,
`capture_restart`, `bandwidth_cap`, `slow_drain` and `soak`. Synthetic for
`sources_2`, `sources_3`, `capacity_4`, `fifth_refused` and every `auth_*` and
`route_probe` run, including `auth_revoked_live`. **So 2–4 sources were never
measured with real cameras.**

G5 on two hosts: the Main-side `interrupted` check is matched by count only
(no cross-host clock comparison, so no per-window attribution).

| Gate | a_framed | b_chunked | b_segment |
| --- | --- | --- | --- |
| G1 authentication | pass | pass | pass |
| G2 gap accounting | pass | pass | pass |
| G3 bounded memory and queues | pass | pass | **fail** |
| G4 reconnect | pass | pass | pass |
| G5 loss detection | pass | pass | pass |
| G6 capacity (4 sources, fifth refused) | pass | pass | pass |
| Secondary: soak (no unexpected disconnect) | pass | pass | pass |
| Secondary: overhead, Agent CPU | pass | pass | pass |
| Secondary: latency reference | pass | pass | fail |
| Secondary: packet loss, jitter | unmeasured | unmeasured | unmeasured |

`b_segment` G3: sender RSS growth of 16.09 MiB against the 16 MiB limit in
`slow_stop_10s` (`r20261029t054210`). The fail stands. Three reruns were 8.51,
15.95 and 8.92 MiB, which pass, but the values fall around two levels, about 9
and about 16 MiB, so this was not ruled out as chance. The highest values for
`a_framed` and `b_chunked` were 10.26 and 9.07 MiB, both in `outage_8s`.

| Measurement | a_framed | b_chunked | b_segment | WebRTC (not in harness) | QUIC (not in harness) |
| --- | --- | --- | --- | --- | --- |
| Reconnect after link loss, `outage_8s` p95 (the 1 s loss does not drop the connection; there is no 5 s scenario, #308) | 24 ms | 21 ms | 194 ms | not measured | not measured |
| Reconnect after TCP reset, `rst` p95 (the G4 candidate value) | 2.02 s | 2.23 s | 2.80 s | not measured | not measured |
| Gap reported / actual: `outage_8s` | 517 / 517 | 510 / 510 | 585 / 585 | not measured | not measured |
| Gap reported / actual: `outage_120s` | 3397 / 3397 | 3396 / 3396 | 3423 / 3423 | not measured | not measured |
| Gap reported / actual: `rst` | 1 / 1 | 6 / 6 | 29 / 29 | not measured | not measured |
| Gap reported / actual: `normal`, `outage_1s` | 0 / 0 | 0 / 0 | 0 / 0 | not measured | not measured |
| Unprotected gap units (gaps in non-loss scenarios, all accounted) | 3904 | 3584 | 3838 | not measured | not measured |
| Max pending at the sender, `slow_drain` (limit 60) | 60 | 60 | 60 | not measured | not measured |
| Max receiver queue, `slow_drain` (limit 240 units, 64 MiB) | 240, 38.1 MiB | 240, 30.9 MiB | 240, 34.5 MiB | not measured | not measured |
| Behaviour under sustained packet loss / added jitter | unmeasured (needs root `netem`) | unmeasured | unmeasured | not measured | not measured |
| Capture latency p95, 30 min `soak` (not glass-to-glass, which is unmeasured) | 6.1 ms | 6.0 ms | 1,019 ms (1 s segments) | not measured | not measured |
| RTT p50 / p95, `soak` | 3.8 / 5.8 ms | 3.9 / 5.7 ms | 69 / 78 ms | not measured | not measured |
| Max pending, `soak` | 2 | 2 | 31 | not measured | not measured |
| Units delivered, `soak`; missing | 51,848; 0 | 51,846; 0 | 51,798; 0 | not measured | not measured |
| Agent CPU per source, `soak` (share of one core, holder included) | 0.047 | 0.049 | 0.041 | not measured | not measured |
| Main receiver CPU, `soak` (share of one core) | 0.020 | 0.023 | 0.017 | not measured | not measured |
| GPU / VRAM | unmeasured (the harness uses neither) | unmeasured | unmeasured | not measured | not measured |
| Bitrate, `soak` (payload, overhead ≤ 0.19 %) | 34.1 Mbit/s | 34.2 Mbit/s | 33.9 Mbit/s | not measured | not measured |
| Codec/container and recording-extraction impact | unmeasured (MJPEG passthrough, payload discarded; #313) | unmeasured | unmeasured | not measured | not measured |

Real camera delivery was about 28.8 fps in every `soak`, against 30 declared;
the holder reported 0 capture restarts over its 33 matched matrix runs and
tolerated CS-800 padded buffers (#305). This run does not establish why
delivery is below 30 fps. The reconnect values differ by scenario because they
measure different things: `rst` includes the sender's retry backoff.

Unverified by these runs: product ingest (#14), including the product
human/admin API boundary (the harness `route_probe` shows only that its own
receiver serves no human route); real cameras at 2–4 sources; packet loss and
jitter; glass-to-glass latency.

### Raw record review (required by MANUAL_TEST.md §G before this table is final)

- **Claude, 2026-10-29 and 2026-11-02:** the raw JSONL of all 66 runs on both
  hosts. No broken JSON, missing record or mixed-in run; every process exited
  0; scenario, candidate, source count, inputs and `fast` agree across hosts.
  `capture_restart` for all 3 candidates has two holder sessions, no `refused`
  and no `producer_failed`. All 9 `sigstop` runs have `stopping` with
  `coordinated: true` and `stopped` after `sigstop`.
- Noted, judged not to affect a gate: in `r20261029t022330` one Main record is
  0.2 ms earlier than the previous one, where 4 refusals were written together;
  `tls_handshake_failed` appears in `outage_120s` (8) and `slow_stop_60s` (4)
  for all 3 candidates, as connection attempts time out during the window
  (it also appears 9 times per candidate in `auth_other_ca`, as that scenario
  intends).
- **Owner, 2026-11-02:** accepted the recommended selection and contract from
  the results Claude reported in chat. **The Owner has not reviewed the raw
  JSONL**, so MANUAL_TEST.md §G's review before transcription is incomplete and
  this table and the selection stay provisional.

## Follow-up

- Agent-side envelope sender and `capture_epoch` persistence (#12/#16).
- Dedicated ingest listener with mTLS (ADR-0006 adapters, #13/#14).
- Durable consumer for drained gap events (timeline / recording health).
- Owner raw record review of the 2026-10-29 runs, then confirm or change the
  selection (#15).
- Real camera delivery of about 28.8 fps against 30 declared: cause not
  established.
