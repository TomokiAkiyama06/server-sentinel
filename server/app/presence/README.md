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
  notification workers. Side effects are durably queued and dispatched outside
  the database write transaction.
- Issue #10 supplies Owner and `recordings:view` authorization before any
  future human route delegates here.

Manual overrides require an injected, audited Owner identity and take
precedence over observation and schedule hints. Only a trusted, confirmed,
quality-sufficient Owner entry can project `PRESENT`; untrusted timing and
insufficient quality remain `UNKNOWN`. Critical movement/tamper observations
always queue evidence and configured notification work regardless of presence.

The status snapshot does not create a presence write, so a refused or exhausted
storage volume cannot hide presence state or unfinished critical work. It probes
the injected storage-admission guard and reports each
critical path as `armed`, `unavailable`, or `unknown` from configured ports,
the storage admission it actually observed, and the injected detection health
probe; no path is reported as healthy merely because nothing failed yet.
`armed` means configured and never disarmed by a presence state, not a
liveness guarantee for an external worker. An expired manual override stops
applying even when its durable retirement write is refused, and the snapshot
reports that retirement as still pending.

Timeline ordering uses main-host receipt order, with the durable sequence only
as a tie-break, as the single key for the SQL page, the cursor and the
response, so concatenated pages stay complete and in the advertised order. It
explicitly reports degraded timing if clock trust or source ordering is
unavailable. It reports observations and their temporal context only; it never
infers cause, guilt, or identity.
