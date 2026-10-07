# Presence and Timeline Core

This module persists neutral, attributed observations and projects the four
presence states: `PRESENT`, `PROBABLY_PRESENT`, `ABSENT`, and `UNKNOWN`.

It is deliberately an integration core, not a human-facing API or an
authentication implementation. `Access` is injected: the default denies every
Owner and historical-timeline operation. Until Issue #10 supplies the reviewed
application authorization boundary, no production timeline, override, or audit
route may be registered from this module.

Its integration ports keep the dependent stack explicit:

- Issue #24 supplies confirmed server-movement and camera-tamper observations,
  and optionally the `detection` health probe reported by the status snapshot.
- Issue #25 supplies quality-gated, confirmed Owner entry/exit observations;
  this module never compares biometric data or selects a confidence threshold.
- Issue #21 supplies storage admission, evidence preservation, and configured
  notification workers. The admission port is a callable returning a
  reservation context manager, such as `MainStoragePolicy.control`; presence
  holds it through the SQLite commit and releases it afterwards, so a presence
  write neither leaks a reservation nor writes without admission. Side effects
  are durably queued and dispatched outside the database write transaction.
- Issue #10 supplies Owner and `recordings:view` authorization before any
  future human route delegates here.

Owner control time is tracked in a marker separate from observation receipt
time. Receipt times arrive from capture sources, so a shared marker would let a
single far-future observation refuse every later Owner override, cancellation
and hint with no way back. Everything the Owner configures follows the control
marker: the mutations themselves, override expiry, the override projection and
configured hints. Observation-clock trust is reserved for inference from
observations, so a skewed source timestamp can no longer withhold the
suppression an accepted `PRESENT` override asks for. `clock_degraded` reports
the marker behind the state actually returned, and `observation_clock_degraded`
keeps source-time skew visible alongside it.

Manual overrides require an injected, audited Owner identity and take
precedence over observation and schedule hints. Only a trusted, confirmed,
quality-sufficient Owner entry can project `PRESENT`; untrusted timing and
insufficient quality remain `UNKNOWN`. An unusable owner observation stops an
earlier owner inference from applying, but it holds no projection of its own,
so a still valid configured hint keeps its documented precedence instead of
being masked by it. Critical movement/tamper observations
always queue evidence and configured notification work regardless of presence.
An unavailable action is not retried until that action's port recovers, so its
backlog cannot starve the other critical action. Any delivery that has not
completed its critical action keeps the affected path visibly unavailable:
`disabled`, `unavailable`, `failed` and `uncertain` outcomes, and also a
submission whose completion is unconfirmed (`submitting`, `queued`), which an
interrupted worker or a lost completion callback would otherwise strand while
the path still claimed to be armed. A claimed submission is never reclaimed by
a later cycle, because a concurrent or re-entrant dispatcher may still be inside
that port call; it stays visibly unresolved instead.

Automatic dispatch never retries an outcome it could not confirm, so stranded
work is recovered only through `requeue_action()`, an audited Owner decision
that accepts the risk of a duplicate preservation or notification. A requeued
job keeps its attempt count for diagnostics but is dispatched ahead of fresh
zero-attempt work, so a continuous stream of new events cannot starve the
action an Owner explicitly recovered. Each Owner recovery is audited with the
action and event identity it approved.

Every claim carries a generation, and a completion callback only resolves the
attempt it belongs to. A callback from a superseded attempt, including one that
arrives after an Owner requeue, is therefore ignored instead of cancelling the
approved resubmission or overwriting a newer attempt's outcome. An expired
degradation marker is cleared the same way, through `clear_expired_degradation()`,
never automatically.

`snapshot()` performs no authorization check. Critical-path health is Owner
information: a future route delegates to `owner_status()` and never exposes
this payload to a `live:view` identity. `complete_action()` is an internal
worker callback with no authorization or audit of its own, and an unscoped
call can return a degraded path to `armed`. It must never be registered as a
route; Owner-facing recovery goes through the audited `requeue_action()` and
`clear_expired_degradation()` and `clear_unresolved_critical_event()`, which
require an Owner identity. The latter is an audited, explicit resolution of a
retained event before the audit horizon: it releases its timeline payload and
pending delivery rows, preserves only action-level degradation markers, and
adds an identity tombstone so a delayed replay cannot recreate the work.

The status snapshot does not create a presence write, so a refused or exhausted
storage volume cannot hide presence state or unfinished critical work. It never
calls the admission port either: spending the deployment's bounded control
allowance on a read would contend with the writer that owns it and could drive
a storage state transition from a read path. Storage health in the status comes
from the read-only `storage_status` probe a deployment injects and from the
admission a write in the same snapshot actually observed; without that probe
the volume's health is reported as unknown rather than armed. Each critical path is reported as `armed`, `unavailable`,
or `unknown` from configured ports, that storage information, the durable
delivery outcomes, and the injected detection health probe; no path is
reported as healthy merely because nothing failed yet.
`armed` means configured and never disarmed by a presence state, not a
liveness guarantee for an external worker. An expired manual override stops
applying even when its durable retirement write is refused, and the snapshot
reports that retirement as still pending.

Owner-control audit records and presence timeline use the deployment's shared
`RetentionPeriods`; there is no independent presence default. Owner-control audit records use the main 90-day audit retention period. The
maintenance operation is bounded and deletes the oldest expired rows first.
Timeline observations use the main 20-day recording-retention period. Only a
confirmed movement/tamper event with unfinished critical delivery keeps its own
observation past that period, until the work resolves and at most until the
main audit-retention period, so a permanently unresolved action cannot keep
observations on disk without limit. No other observation is held back, and a
durably disabled delivery holds none either: disabling is a configuration
decision rather than pending work, so that observation expires on the ordinary
schedule while its per-action degradation marker keeps the path unavailable.
An event whose critical actions completed keeps an identity-only tombstone when
its payload expires, so a delayed replay of the same identity stays a duplicate
instead of preserving evidence and notifying a second time. Only events that
carried critical delivery are tombstoned, because replaying any other expired
observation queues no action. A critical action that never completed, such as a
durably disabled delivery, leaves a per-action degradation marker behind, so
expiry cannot report that path as armed again while the tombstone stops a
replay from re-queuing the work.

## Producer adapters

`adapters.py` connects the reviewed producers to `record()` without adding any
route, worker thread or default timing policy:

- `EntranceObservationAdapter` maps #25 `TrackUpdate` crossings for one
  entrance source (`source_id`; a crossing from another source is refused). A
  crossing is written only when the entrance quality gate was sufficient; an
  `UNKNOWN` update writes no crossing, because an empty crossing list is
  neither presence nor absence. Each change of the gate quality is written
  as a neutral `entrance_gate` fact instead (see "Entrance gate quality"
  below). An Owner crossing keeps its verification confidence and is
  `confirmed` only when the tracker confirmed it and its source latency and
  clock uncertainty stay within the explicit `maximum_source_latency`. Every
  Owner crossing carries the explicit `owner_presence_validity`, so an
  unconfirmed one makes the Owner-observation slot `UNKNOWN` instead of letting
  an earlier inference keep applying. Low-quality Owner verification reaches
  the adapter as an anonymous crossing, because the tracker never names it as
  the Owner. Anonymous crossings carry no confidence, no identifier beyond the
  event UUID, and no presence effect; nothing links crossings across cameras.
  Because `confirmed` also depends on receipt timing, a restamped replay
  ignores it when payloads are compared; the adapter therefore passes a
  SHA-256 digest of the crossing exactly as the tracker reported it
  (`record(..., source_fact=...)`), kept in `presence_source_facts` and
  removed with its observation. A replay of the same UUID with a different
  tracker confirmation, trust or timing, whether still staged or already
  written, is an identity conflict counted as rejected, never a silent
  duplicate.
- `CriticalTimelineRecorder` is the #24 `CriticalRecorder` for
  `CriticalDelivery`. It records synchronously and raises on failure so the
  staging retries the UUID. Receipt is stamped at write time from the shared
  `TimelineOutbox.receipt()`; a replay of an already recorded UUID (a retry
  after a write that committed and then failed, a repeated delivery, or a
  replay after a restart) is a duplicate by the durable row, via
  `record(..., restamped=True)`, never an identity conflict that would stay in
  the bounded `CriticalDelivery` staging forever. Critical confirmation comes
  from the detector rather than the receipt, so a confirmed delivery of a
  critical UUID first stored unconfirmed is confirmed in place (keeping the
  first receipt) and queues evidence and notification work exactly once; a
  later unconfirmed replay never withdraws it. It refuses an unconfirmed or
  insufficient-quality observation. Untrusted receipt clocks or excessive
  latency mark the timing untrusted but never withdraw confirmation, so
  evidence and notification work is queued in every presence and clock state.
- `HealthTimeline` stages UVC `HealthEvent`s, registry source and node health
  states, `MainStoragePolicy` transitions and `RecordingHealthService` results
  as `camera_health`, `node_health`, `storage` and `recording` facts. It copies
  only attribution and state, never free-form reasons, device evidence or
  storage figures.
- `TimelineOutbox` is the bounded staging those producers write to and the
  single main-host receipt clock. `record()` treats a receipt older than the
  newest one written as a clock step, which would make an Owner observation
  `UNKNOWN`, so receipt is stamped at write time under one lock held across
  the write and shared with `CriticalTimelineRecorder`; a staged crossing is
  never distrusted merely because another source's fact or a critical
  observation was written first. An Owner crossing therefore confirms only if
  it is still within `maximum_source_latency` when presence receives it, and
  its validity runs from that receipt. `stage()` never touches the database or
  the receipt lock, so it is safe inside the storage policy's transition
  audit, which runs while admission is being refused; the Main runtime drives
  `flush()` from the storage owner's worker, because
  `MainStoragePolicy.control` only admits writes from that thread. A flush
  keeps staging order and stops at the first storage, database or clock
  failure, including an unavailable database location and a naive or
  otherwise unusable receipt time from the clock port (`ClockUnavailable`,
  never `InvalidObservation`); a full outbox refuses
  the new fact, and only a fact presence rejects as `InvalidObservation` is
  removed. A UUID staged again while still pending is a duplicate only when
  its source fact (every field except the receipt fields, plus any producer
  source-fact digest) matches; a
  different fact under that UUID is refused at `stage()` as an identity
  conflict and counted as rejected. Both are counted and reported by `OutboxState.degraded`, never
  dropped silently.
- A staged fact's `build()` only constructs its observation from the receipt;
  it touches no storage, database or clock. When it raises anything other
  than `InvalidObservation` at flush time (it already passed the same check
  at `stage()`), that is a programming error a retry would repeat forever, so
  the flush moves the fact into a quarantine instead of treating it as
  transient: later facts are written, the quarantined fact still counts
  against the capacity and is deduplicated by UUID, `OutboxState.quarantined`
  and Owner `timeline_quarantined_count` report it (it is part of
  `timeline_gap`, because it will not be written without a fix), the event
  `timeline_fact_quarantined` is logged with no content, and a clean close
  records it as lost. Storage, database and clock failures stay transient and
  keep the head staged; `OutboxState.failures` and Owner
  `timeline_flush_failures` count consecutive failed flushes, and
  `timeline_flush_failing` is logged at the first failure of a streak and at
  every doubling, `timeline_flush_recovered` at the first later write, so a
  stuck outbox is visible to the runtime and the Owner without flooding logs.

### Entrance gate quality

An empty crossing list from an `UNKNOWN` gate and one from a sufficient gate
used to look the same in history, so a low-light period could not be told
apart from a period in which nothing crossed. The detection health in the
Owner status does not answer that: it is current, Owner-only and per
detector path, not historical and not per entrance source. The adapter
therefore records each change of the source's gate quality as an
`entrance_gate` fact in the ordinary timeline (`recordings:view`, like every
other historical fact): value `ready` with quality `sufficient`, or value
`unknown` with the reported quality (`unknown`, or `insufficient` for a
degraded or insufficient gate). The contract allows no other value, no
confidence and no confirmation, so the fact can never read as a detection,
a person or an absence. An interval runs from one fact to the next for that
source; crossings are only possible inside `ready` intervals. Only changes are
written, the first update after start always writes the current quality, and
a refused fact is retried by the next update and counted as a gap. A gate that
stops producing updates entirely (detector stop, source loss, shutdown) cannot
be seen from the updates themselves, so the runtime calls
`gate_unavailable()` then, which writes `unknown` once. Facts are dated by the
main-host clock, like other health facts, because a `TrackUpdate` carries no
frame time. Nothing here names a person, links sources or infers cause.

Timeline loss is durable (`presence_timeline_gap` migration 20). The runtime calls
`TimelineOutbox.open()` at startup, before it wires any producer, to open a
durable outbox session (`open_timeline_session()`); `stage()` refuses facts
until that succeeds, so no fact is held without a session row a restart would
find, and `open()` raises for the runtime to retry. Every flush adds its
refused and rejected counts to a singleton gap marker that holds counts and
times only, never observation content. `TimelineOutbox.close()` records any
still-staged fact as lost and ends the session; staging or flushing after close
raises, so the runtime stops its producers first; a repeated close is a
no-op. A process that exits without
a successful close leaves its session row behind, and the next start records
an interrupted gap: a restart is never assumed clean, and staged facts are not
recovered. A failed close reopens the outbox only when a read proves its
session row still in place. When the row is gone, the close committed before
failing, and the outbox stays closed with its session ended; when the row
cannot be read, the outbox stays closed with the session kept, and a retried
close records a missing row as interrupted. Either way no fact is accepted
without a session row a restart would find.
Only one outbox session per database can be open: `open()` takes an exclusive
advisory lock beside the database file, which the kernel releases when the
process dies, and a second outbox is refused while it is held. The lock file is
created and taken inside the same storage-admitted transaction as the session
row, so a refused volume gains nothing from an outbox start. Status, history,
audit and gap reads normally take no reservation and use a read-only SQLite
open (`mode=ro`), so they never create a missing or replaced database. A WAL
database is the exception: when its `-wal`/`-shm` sidecars are absent,
empty or truncated at the moment SQLite opens it, SQLite creates or resizes
them even for a `mode=ro` connection in a writable directory, and a read-only
connection cannot remove them again. Sidecars seen present beforehand prove
nothing, because the last other connection can close and delete them before
the open. Every read of a WAL database therefore runs under the storage
reservation, with a no-create read-write connection set to `query_only`, so
any sidecars are created inside the reservation and removed when it closes as
the last connection; a refused or missing reservation fails the read rather
than writing outside it. `immutable` is not used, because it would read a file
a live writer changes as if it could not change. The application never
switches its database to WAL, and a rollback-journal database never creates a
file on read, so those reads keep working during `STORAGE_HARD_STOP`. The WAL
header probe reads through a descriptor held for the process lifetime
(`app.storage.database`), never an `open`/`close` of the database file, which
would release the POSIX locks of this process's own SQLite connections. A session row
found once the lock is free therefore belongs to an outbox that is gone. Owner
status reports such rows as part of `timeline_gap`
(`timeline_gap_orphaned_sessions`) even before a replacement session opens, so
a restart whose `open()` is refused (for example `STORAGE_HARD_STOP` or a clock
fault) never looks healthy. A row held by a live session is not counted. For
a reader without its own session, that proof is a second, committed-session
lock, which `open()` takes only after its transaction committed (both lock
files are created inside that admitted transaction). A replacement whose open
is still in flight holds only the session mutex and has not yet converted the
stale rows, so they stay counted, and stay so if that open stalls or rolls
back. The probe opens the committed lock file read-only and never creates it,
and a lock that is free, missing or cannot be probed leaves the row counted. A
clock fault while a producer hands a fact over is counted as a refused fact,
because a one-shot producer callback will not re-emit it. A false positive is
cleared only by the Owner through the audited
`clear_timeline_gap()`, a domain operation with no route. `OutboxState.degraded`
stays true while facts are pending, counts are not yet persisted, the session
is not open, or the durable marker is set or unreadable; the Owner status
reports it as `timeline_gap` and `timeline_gap_detail`. Loss a live outbox has
counted but not yet written is part of `timeline_gap` too
(`timeline_gap_unpersisted`), and it refuses `clear_timeline_gap()` until the
outbox writes it, so a clear never makes Owner status look healthy while known
loss is pending. Facts still staged because a transient storage, database or
clock failure stopped the flush are not loss and are not counted in
`timeline_gap`; Owner status reports them separately as `timeline_pending` and
`timeline_pending_count`, which stay degraded until those facts are written
(or, at a clean close, recorded as lost in the gap marker). The outbox reports
its staged and unpersisted counts in one step, so a fact moving from staged to
counted loss is never missed, and an unreadable backlog is reported as both
pending and a gap. Live sessions are registered per database file for the
whole process, so Owner status and `clear_timeline_gap()` through any
`PresenceService` over the same database in the same process see the
owning outbox's counts. An outbox owned by another process cannot be read:
its session is proven live by the committed lock, so its row is not
orphaned, but its staged and unwritten counts are reported as unknown
(`timeline_backlog_visible: false`, counted as pending and as a gap) and
`clear_timeline_gap()` is refused there; the Owner clears it through the
owning process. Counts are only added,
so a retried write that had committed overstates the gap rather than hiding it.

### Rollback-journal read lock (#151)

Another process able to write the database file could switch it to WAL (or
replace it with a WAL database) between the header probe and the read. An
unadmitted read therefore re-reads the header through the held descriptor
after its open, then holds one read transaction, and so the SQLite SHARED
lock, for the whole read: a switch to WAL needs EXCLUSIVE, so the mode cannot
change between its statements. If the connection still reports WAL once it
holds the lock, the read is abandoned before the caller sees it and retried
under the storage reservation; a refused reservation fails the read (WAL
admission stays fail-closed).

A held SHARED lock makes a writer of the same file, such as a recording
append (busy timeout 5 s), wait until the read ends, so the work under it is
kept small and independent of the retained timeline:

- A history page with a cursor starts its index range at the cursor, not at
  the window start, so a late page reads about one page of rows.
- `audit()` copies its rows in one statement and builds the response after the
  read ends.
- Unadmitted reads of one process run one at a time. SQLite's unix VFS lets a
  connection of a process that already holds SHARED take it again without
  checking the PENDING lock a waiting writer in another process holds, so
  overlapping reads could keep the file read-locked indefinitely and starve
  that writer past its busy timeout. One at a time, the lock is released
  after each read and the writer's PENDING holds the next read back until the
  commit. Reads of other modules in the same process are not covered by this
  serialization.

`ReadLockBoundTests` guards these properties deterministically (SQLite VM
steps under the lock, and the order of a waiting writer and the next read)
and with a cross-process writer whose busy timeout is 1 s while two threads
run large reads.

Measured on the development host (32 threads, SQLite 3.46.1, Python 3.12,
database on tmpfs, so no disk latency), as the duration of each `_read()`
context, an upper bound on its SHARED lock. Synthetic data for 60 days of 4
sources (three times the default 20-day recording retention): *realistic* is
400 crossings, 400 gate-quality facts and 50 health facts per source per day,
5 critical events per day with 2 delivery rows each, and 20 audit rows per
day for the 90-day audit retention (204,300 observations, 135 MiB);
*stress* is 4,320 crossings and 4,320 gate facts per source per day (one fact
every 10 s per source), 500 critical events per day and 500 audit rows per day
(2,103,600 observations, 60,000 delivery rows, 45,000 audit rows, 1.4 GiB).
200 runs per read (50 for audit), longest single read transaction:

| Read | realistic p99 / max | stress p99 / max |
| --- | --- | --- |
| Owner status (`snapshot`) | 0.31 / 0.32 ms | 6.98 / 7.13 ms |
| history, 60-day window, first page, limit 500 | 0.42 / 0.52 ms | 0.37 / 0.40 ms |
| history, 60-day window, mid-window cursor, limit 500 | 0.57 / 0.61 ms | 0.40 / 0.43 ms |
| history, 1-hour window, limit 500 | 0.34 / 0.38 ms | 0.52 / 0.55 ms |
| `audit()` (all retained rows) | 1.16 / 1.42 ms | 21.07 / 21.32 ms |
| `timeline_gap()` | 0.31 / 0.35 ms | 0.24 / 0.26 ms |

Before the cursor bound, the mid-window history page held the lock for
p99 47 ms (stress) because it scanned every row from the window start. A
separate process committing small transactions (busy timeout 5 s) while two
threads read in a loop with no pause waited at most 8 ms (realistic) and
53 ms (stress); without the serialization above, the same stress run either
waited up to 1.3 s or exceeded the 5 s busy timeout and failed. The status
read scans `presence_deliveries` without an index on `state`, and `audit()`
returns every row inside the 90-day audit retention; both grow only with
critical deliveries and Owner control actions, not with the timeline.

Residual race: a switch to WAL after the post-open header re-read but before
the read's first lock lets SQLite open the WAL right after it reads page 1,
and SQLite offers no step in between where the read could stop. The read is
then retried under the reservation, whose closing connection removes the
sidecars. Only while the reservation is refused (`STORAGE_HARD_STOP`) the
read fails and leaves an empty `-wal` and one 32 KiB `-shm` region until the
next admitted connection closes; later reads during the same stop see the WAL
header first and are refused before they open the file, so nothing more is
created. When the switching process keeps its own WAL open, the sidecars are
that process's files and the read writes no WAL frame. The application never
switches its database to WAL, so only another process with write access to
the database can cause this, and removing the sidecars here is unsafe while
any other connection may still use them. This is accepted as a residual risk.

`owner_presence_validity` and `maximum_source_latency` have no default; they
are deployment decisions that need real-room and cross-host clock evaluation.

Timeline ordering uses main-host receipt order, with the durable sequence only
as a tie-break, as the single key for the SQL page, the cursor and the
response, so concatenated pages stay complete and in the advertised order. It
explicitly reports degraded timing if clock trust or source ordering is
unavailable. `ordering_degraded` describes the page it is returned with, so a
caller that concatenates pages treats the window as degraded when any page
reports it. Each source retains a trusted occurrence-time high-water mark, so
an out-of-order event cannot later regain trust merely because it is newer than
another untrusted delayed event. Only source-dated kinds (person, motion,
entry/exit and critical observations) use that mark; health, storage and
recording facts are dated by the main host and neither advance nor are checked
against it. Critical observations keep a separate per-source mark, because
they are recorded synchronously while other source facts wait in the outbox:
a later-occurring critical fact written first never makes a staged crossing
from the same camera look reordered, and order within each path is still
checked. An upgrade rebuilds both marks from the retained trusted observations
of their own kinds, because the earlier shared mark also held critical and
main-host dated health times and cannot be split. It reports observations and their temporal context only; it never
infers cause, guilt, or identity.
