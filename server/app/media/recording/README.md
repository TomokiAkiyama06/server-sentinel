# Durable compressed recording — Issue #18

`RecordingStore` persists trusted, independently decodable video segments and
SQLite manifests. It introduces no human HTTP route, recording download/export,
codec implementation, network client, automatic retention or decoded-frame
history. The application must leave this worker unavailable until the storage
policy, audited codec validator/muxer and authorization prerequisites are wired.

## Integration contract

- Supply a caller-owned SQLite connection, with no open transaction and at least
  `synchronous=FULL` plus a durable journal mode (in-memory/off are rejected). The final
  application migration aggregator must assign `recording_migration(version)` a
  contiguous slot after earlier migrations. This branch intentionally does not
  fork or renumber their history; isolated tests assign recording slot 2.
- Supply an already existing, private (`0700`), service-owned media directory
  outside a checkout and its deployment-approved `RootIdentity(device, inode)`.
  The constructor never creates that directory. It verifies every path component
  without symlinks and holds a directory descriptor and exclusive writer lock.
  Every filesystem operation rechecks that the visible path still names the
  approved directory. Unmount/substitution blocks writes; no fallback is created.
- Supply `StoragePolicy.admit(media_bytes, critical=...)` / `release()`. Admission
  is a reservation held through publication, fsync and spool cleanup. It must
  coordinate concurrent filesystem users, include SQLite/journal/container
  overhead and existing interrupted artifacts, enforce the configured hard
  reserve and reject ordinary/manual work during `STORAGE_PRESSURE`. Critical
  evidence receives only the allowance supplied by that policy and never bypasses
  `STORAGE_HARD_STOP`. This module invents no numeric reserve or retention rule.
- Supply a `SegmentValidator`. This is a mandatory trusted codec boundary, not
  a boolean supplied by a network peer. The adapter validates video-only content,
  allowed formats/configuration, bounded decode dimensions and independent
  decodability before storage. No production validator is shipped here. Tests
  use generated deflate bytes only and do **not** claim playable video.
- Call all methods on one owning worker thread; a competing store/process is
  rejected before recovery can alter the first worker's active recordings.
  Upstream must use its bounded media queue and surface every rejected append as
  degraded recording health. A required periodic `advance(now_ms)` closes record
  deadlines even when the source stops producing frames.

Issue #17 emits compressed packets with a source UUID, stream-generation UUID,
sequence, PTS/DTS and rational time base. An audited muxer implementing its
`PacketAdapter` must turn those packets into `Segment` objects, preserving source
and generation identity. It must convert timestamps through the upstream clock
mapping to UTC milliseconds, supply video-only codec/container identifiers and
start new independently decodable segments after a reset/discontinuity. Raw packet
concatenation or treating synthetic test bytes as a playable container does not
satisfy this contract. Registry/node authentication occurs before this adapter.

## Evidence and limits

Each media file has a generated UUID name, byte length and SHA-256 in SQLite.
Source/node UUIDs, stream generation/sequence and codec/container metadata remain
attached to each segment. No source role becomes a filename or schema column.
An event UUID links separate recordings for one through four sources; node health
does not substitute for source coverage.

The compressed pre-roll spool is bounded independently by duration, total bytes
and segment count. Each append is bounded in bytes and duration; active recording
count and segment count per recording are also admission limits. Callers supply
those operational budgets. A spool eviction unlinks only unreferenced files;
segments already linked to evidence survive. The last admitted stream cursor is
persistent even when the entire spool is evicted, so old packets cannot be
accepted as new evidence. `release_source()` releases a disabled source's spool
and active-source slot while preserving all recording links.

Event defaults are 30 seconds pre / 120 seconds post. The combined requested event
window and manual duration are capped at 20 minutes. Whole compressed segments
may overlap window boundaries; the manifest provides explicit clipped playback
intervals. A future playback adapter must obey those intervals, rather than
claiming that this storage layer performed frame-accurate trimming. Short buffers,
missing timestamps, generation/sequence discontinuities and missing/corrupt files
are reported. Future coverage for an active recording is `pending`; after its
deadline it becomes a gap. `complete` means the requested storage coverage and
byte integrity passed, not that a browser successfully decoded the media.

## Crash and integrity behavior

A pending SQLite journal row is committed before creating a media file. The
writer uses an exclusive generated `.part` file, fsyncs its contents, publishes a
generated `.seg` name without overwriting an existing file, fsyncs the directory,
then atomically marks the segment ready and links it to active recordings.
Failures poison that writer until reopening; the reservation is always released.

Startup removes only pending artifacts identified by this journal. Arbitrary
untracked files are never deleted. Failed cleanup blocks startup and leaves the
pending row for accounting/retry. Active recordings become `interrupted`; ready
segments survive and missing requested coverage remains visible. There is no
silent resumption of an old recording after restart. Manifests re-open bounded
regular files without following symlinks, reject extra hard links, compare hashes
and persist observed integrity degradation. They return metadata only, never
filesystem paths or file contents.

The owning service must treat the metadata database and media directory as one
deployment binding, use durable SQLite settings and supply its private database
location through the backend configuration. Sharing one media directory between
databases, replacing the database, migrations or manual file edits while a writer
is live are unsupported. The main application aggregator and worker lifecycle
integration remain pending the upstream issue merges.

## Verification

`python -m unittest tests.test_recording -v` covers generated compressed bytes,
multi-source manifests, time/byte/row limits, early stop, explicit critical
admission, mount substitution, symlink/hardlink attacks, independent writer/thread
rejection, reserve denial, short writes, crash recovery, failed cleanup,
corruption, missing segments and restart interruption. These are storage contract
tests on a temporary filesystem. Real codec playback, hardware performance and
phone/browser recording playback remain the separate acceptance work in
`MANUAL_TEST.md` K/R and Issues #19/#28.
