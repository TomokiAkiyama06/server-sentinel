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
`clear_expired_degradation()`, which require an Owner identity.

The status snapshot does not create a presence write, so a refused or exhausted
storage volume cannot hide presence state or unfinished critical work. It never
calls the admission port either: spending the deployment's bounded control
allowance on a read would contend with the writer that owns it and could drive
a storage state transition from a read path. Storage health in the status comes
from the optional read-only `storage_status` probe a deployment injects and
from the admission a write in the same snapshot actually observed; without a
probe the report says only that the port is configured. Each critical path is reported as `armed`, `unavailable`,
or `unknown` from configured ports, that storage information, the durable
delivery outcomes, and the injected detection health probe; no path is
reported as healthy merely because nothing failed yet.
`armed` means configured and never disarmed by a presence state, not a
liveness guarantee for an external worker. An expired manual override stops
applying even when its durable retirement write is refused, and the snapshot
reports that retirement as still pending.

Owner-control audit records use the main 90-day audit retention period. The
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

Timeline ordering uses main-host receipt order, with the durable sequence only
as a tie-break, as the single key for the SQL page, the cursor and the
response, so concatenated pages stay complete and in the advertised order. It
explicitly reports degraded timing if clock trust or source ordering is
unavailable. `ordering_degraded` describes the page it is returned with, so a
caller that concatenates pages treats the window as degraded when any page
reports it. Each source retains a trusted occurrence-time high-water mark, so
an out-of-order event cannot later regain trust merely because it is newer than
another untrusted delayed event. It reports observations and their temporal context only; it never
infers cause, guilt, or identity.
