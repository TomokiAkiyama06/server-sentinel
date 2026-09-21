# Recording-health self-test

`RecordingHealthService` coordinates startup and at-least-daily checks on the
existing serialized recorder worker. It adds no thread, route, codec choice,
fake source or public health endpoint. A missing adapter reports `UNAVAILABLE`.
The production launcher does not yet configure these callbacks.

The adapter verifies source freshness and recorder/encoder liveness, checks the
expected recording root and shared capacity admission, obtains a bounded sample
from the actual pipeline, writes/flushes/fsyncs it, reopens and validates size/
container/duration/decoded video, cleans up and reads available storage health.
Freshness thresholds and self-test byte/duration budgets are explicit integration
configuration, not new product defaults. Unknown sources cannot yield healthy.

`RecordingStore.self_test_probe(...)` supplies real disposable-file I/O using
the store's pinned root descriptor, expected identity, worker checks and shared
storage policy. Assign `recording_health_migration(version)` the next unused
schema slot. Supply actual-pipeline sample, liveness and storage-health callbacks.
The mandatory `SegmentValidator` must validate container/duration and bounded,
video-only decoding of reopened bytes. Generated test bytes do not constitute a
production codec or establish browser playability.

A committed single-artifact journal precedes file creation. Names are generated
UUIDs with `.selftest`, never caller input. Cleanup touches only that journaled
artifact, verifies the root, refuses symlinks/shared/non-regular files, fsyncs
deletion and removes the journal. Ordinary/protected recording references and
unjournaled files are untouched. Startup cleanup precedes new test media; failed
cleanup blocks another segment until recovery.

Storage policy reserves the configured maximum bytes and metadata/temp allowance
through validation and cleanup. Cleanup alone uses the worker's control reserve.
Leftovers remain actual filesystem usage after release/restart and stay in #21
free-space accounting. Missing/substituted roots fail without creating a fallback
directory. Tests cover disposable-file I/O, reopen/decode failure, cleanup retry,
interrupted recovery and substituted-directory refusal.

The injected `record_result(result, aware_time)` must durably retain fixed state/
stage codes locally and enqueue #21 `RECORDING_HEALTH_FAILURE` immediately for
`FAILED`. Unavailable SMART alone is a visible `UNAVAILABLE` warning, never a
clean health verdict. Results exclude raw exceptions, paths, hardware identifiers
and media. Local-recording failure propagates without completing the check.
Cancellation attempts cleanup, records failure, then propagates. Optional Slack
never determines local fault state.

Production codec/source/encoder wiring, verified mount/device mapping, durable
notification integration and physical acceptance remain open under #18/#21/#23/
#28. Run `MANUAL_TEST.md` S on the deployment; synthetic storage tests are not
actual playable media or hardware acceptance.
