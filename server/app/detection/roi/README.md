# Calibrated ROI movement and camera-tamper core

This module processes transient, bounded grayscale `GrayFrame` values for one
immutable source/profile calibration. It stores no media, starts no capture,
opens no HTTP route, and makes no presence, identity, guilt, or notification
decision.

A calibration contains an Owner-selected polygon, reference frame digest,
source type, profile ID, explicit search/quality thresholds, version, and
timestamp. A policy is refused when a bounded search window cannot reach its
own displacement threshold, because such a configuration cannot express the
movement or camera shift it asks for and would report a matching geometry
instead. A calibration is refused for the same reason when its own support
leaves any axis direction without a *pure* translation at or beyond a
threshold above `minimum_coverage`, since the policy radius alone does not say
which candidates survive the coverage gate, a quarter turn does not register a
pixel shift even when it carries a translation of its own, and support against
one edge can register a shift one way while the opposite shift of the same
size has no eligible candidate at all.
A calibration whose reference already meets the obscured-scene threshold is
refused too: every unchanged sample would look obscured and confirm a tamper
that never happened. `CalibrationArchive` is a small append-only SQLite port: the Main
runtime must supply its already-open private database after application
migration (`roi_calibration_history`) has run. The table holds provenance
only — identities, polygon, policy, reference geometry and the reference
SHA-256 — so no decoded frame, crop, or other monitoring media is persisted
and the history cannot become retention-free image storage. `load()` therefore
returns a `CalibrationRecord` without pixels, separates a record it cannot
decode from an unavailable database so corrupt history is not hidden behind a
transient-looking failure, and refuses a record whose decoded provenance is not
the row that was looked up, so swapped history cannot bind a detector to
another source or profile; resuming detection needs
`CalibrationRecord.rehydrate(frame)`, which re-binds an Owner-supplied
transient frame and refuses any frame whose source, stream, sample, geometry
or digest differs. A history table carrying a media column is rejected at
construction. Where a deployment obtains that frame again is outside this core:
it comes from Owner-authorized media under ordinary recording authorization and
retention, or from a fresh Owner recalibration, never from a private image
store owned by this module. `OwnerCalibrationOperations` defaults to refusal;
authentication and API policy remain outside this core.

`SceneDetector` compares the background first to estimate bounded global
translation/quarter-turn transforms, then compares the ROI relative to that
transform. It only emits `server_movement` after the configured number and
duration of corroborating samples. An explicit ROI-occlusion signal, sampling
gap, stream restart, regression, mismatched frame, or insufficient movement
quality resets confirmation and yields `unknown`, never `no movement`. A
sample the detector refuses outright, such as a frame belonging to another
source, ends the episode too, so no later confirmation spans it. When only the
metadata of an identified sample is unusable, its stream, sequence and clock
are still recorded, and a refused source-loss report keeps a valid outage
clock, so a buffered earlier frame cannot start an episode behind either
refusal. Every stream
this source has replaced is remembered for the detector's lifetime, so a
delayed frame from a stream it already left is refused as stale imagery rather
than becoming current again, and no number of later replacements lets an old
identity age back into validity. The number of admitted transitions is bounded
instead: after `RETIRED_STREAM_LIMIT` of them the detector stops admitting new
streams and latches, reporting `stream_history_exhausted` for every later
sample and source-loss report, which a runtime resolves by binding a fresh
detector rather than by accepting stale imagery. Confirmation also starts from
the reference sample itself, so a frame the source captured before the Owner
calibrated cannot take part in it. Every accepted
sample records the observed stream, sequence and clock before any such
`unknown` result, so a buffered frame from a superseded geometry or stream
cannot pass the regression check afterwards. The calibration comparison budget
covers the costlier of the registered and unmatched paths, because the latter
trades ROI matching for a background scene-difference.
Ending an episode that way also clears its emitted latch: a condition that is
confirmed again after the interruption is new evidence and is reported again
rather than dropped as a duplicate. Person presence is deliberately not an
input.

Camera tamper has its own quality input and temporal confirmation. It can
report a bounded global scene shift, a persistent near-dark scene, or a scene
that stops registering while differing measurably from the calibrated
background — a covered or redirected camera. A registration whose best
transform is acceptable but ambiguous, as on a repetitive scene where several
bounded transforms score alike, stays `unknown` and confirms neither tamper
nor absence of tamper: its untransformed difference is large even when the
registered transform is small, so it is never treated as a changed scene. A trusted source-loss signal produces a
critical observation only if it closely follows a tracked global scene shift,
and at most once per tracked shift episode; source loss by itself stays
`unknown`, and a source-loss report this core cannot accept ends confirmation
before it is refused. The scene-difference measurement is a
bounded scalar over background support points; it never describes who or what
is in view. The core records neutral observation provenance and offers
`CriticalDelivery` for bounded, explicit local handoff; its staging holds at
least `MAXIMUM_BATCH` observations, because one confirmed sample can carry a
server movement and a camera tamper together and a batch that never fits could
not make progress by retrying. `app.presence.adapters.CriticalTimelineRecorder` is the reviewed recorder
that records each confirmed observation synchronously in presence, whose durable
evidence/notification queue takes it in every presence state; it is never
deferred through the timeline staging. A later
runtime owns recording preservation and configured notifications, which must
remain armed in every presence state.

## Main runtime wiring (Issue #205)

`runtime.py` provides `SceneMonitoringRuntime`, which `app.main.create_app()`
builds when the embedder passes `scene_monitoring` (a
`SceneMonitoringConfiguration` of 1 to 4 `SceneSourceBinding`s). Local UVC
frames reach it through the same frame and camera-state callbacks as the
preview hub; a source whose frames are decoded elsewhere (a future
remote-agent decoder) uses `offer_luma()` with the same pipeline. Capture
threads only make a sampling decision and hold at most one pending sample per
source; a newer sample replaces it and the replacement is counted. Decoding,
the two detector-specific `QualityGate`s (`server_roi` for movement,
`camera_tamper` for tamper) and `SceneDetector` run on one worker thread, and a
failure in one source makes only that source `unknown` (retried after the
calibration retry interval).

It fails closed:

- without an injected durable `CriticalRecorder` (in Main,
  `CriticalTimelineRecorder`) the runtime is `unavailable` and no detector runs;
- without a calibration provider, a stored record, or a re-bindable reference
  frame (`ArchiveCalibrationProvider` never re-bases a stored calibration on a
  live frame by itself; a new reference comes only from an explicit
  acquisition, see "Owner calibration and restart re-acquisition" below), the
  source stays inactive and `unknown`;
- a calibration whose source, type or profile differ, whose `maximum_gap_ns`
  does not exceed the sample interval, whose reference exceeds a quality pixel
  budget, or that the capture layout cannot decimate to, is refused;
- poor/unknown quality, an undecodable frame, critical backpressure (staging
  cannot take a full batch), a camera-state loss, or a conclusion older than the
  calibrated sampling gap is `unknown`, never "no movement" or "no tamper".

`capture_luma_layout()` picks the reader for the driver-negotiated format; when
it is wired to local UVC capture it must receive the negotiated profile, never
the requested one. Packed uncompressed `GREY`/`YUYV` is read by nearest-sample
luma decimation (byte slicing) to the reference size. `MJPG` is read by
`MjpgLumaLayout` (`mjpg.py`, Issue #217, Owner decision 2026-10-11: simplejpeg
1.9.0 with statically linked libjpeg-turbo 3.1.2 and numpy 2.3.5), only on the
scene worker, never on a capture thread, and the native decoder runs only in a
separate child process (Owner decision 2026-10-11 on PR #225), never in the Main
process:

- a pure-Python pre-check in Main runs before any native code sees the bytes:
  a flat byte buffer (a non-contiguous or multi-dimensional `memoryview` is
  refused), `SOI` first, a bounded marker count, a payload of at most
  2 bytes per negotiated pixel plus 256 KiB for marker segments and the
  trailing padding (never above 32 MiB; `frame_byte_budget`), exactly one
  baseline or extended-sequential Huffman `SOF` whose width/height equal the
  negotiated format and fit the 3840x2160 pixel budget (a decompression-bomb
  header is refused before the decoder allocates), one interleaved scan ending
  in a single `EOI`, and at most `maximum_trailing_bytes` (provisionally 8192)
  of padding after it with no further `SOI`/`EOI`. The entropy-coded data is
  checked with C-level `bytes.find` / `bytes.translate` in 1 MiB chunks, so
  even a frame at the budget made entirely of `FF 00` stuffing costs a few
  tens of milliseconds at 4K on the shared scene worker, never one Python
  iteration per byte. Only the validated bytes up to `EOI` are sent to the
  child;
- each MJPG source has its own resident decode child (`mjpg_worker.py`
  supervising `mjpg_child.py`), started with fork+exec of the service's
  interpreter (`python -I -B`, no `preexec_fn`) by that source's own
  supervisor thread (`mjpg-decoder`, kept until stop, so the child's
  parent-death signal is tied to a thread that outlives it), requested
  without waiting when the source is bound and started again by the
  supervisor itself as soon as the restart backoff after a failure ends (or
  by a frame, whichever comes first), with an explicit minimal environment (only
  `LC_ALL=C` and one BLAS/OpenMP thread), stdio on `/dev/null` and only one
  private `AF_UNIX` socketpair end inherited. Before importing simplejpeg or
  numpy the child sets `no_new_privs`, a parent-death `SIGKILL` (and checks
  that its parent is still the Main process), non-dumpable, nice 10, and equal
  soft/hard `RLIMIT_AS` (default 256 MiB), `RLIMIT_NOFILE` (16),
  `RLIMIT_NPROC=0`, `RLIMIT_CORE=0` and `RLIMIT_FSIZE=0`; it checks the
  imported simplejpeg/numpy versions against the pins and decodes one
  generated 32 x 32 warm-up frame (DCT scale 1/2), so every lazy initialisation
  (libjpeg-turbo SIMD detection, numpy first-use paths) happens before the
  sandbox. Then, before the ready message (Issue #269), it confines itself for
  good: a Landlock ruleset handling every filesystem right of the kernel's ABI
  with no rule (no path can be opened, created, executed or listed; TCP
  bind/connect denied at ABI >= 4; abstract UNIX socket / signal scoping at
  ABI >= 6), then a seccomp classic-BPF allowlist built in `mjpg_child.py`
  with no dependency, for x86-64 and aarch64 (`recvfrom`, `sendto`, `mmap` /
  `mprotect` without `PROT_EXEC`, `munmap`, `mremap`, `brk`, `madvise`,
  `futex`, `rt_sigreturn`, `rt_sigprocmask`, `restart_syscall`, `exit`,
  `exit_group`; the decode loop was traced with strace on CPython 3.12 and
  3.14 and uses only `recvfrom`, `sendto`, `brk`, `mmap`, `munmap`). Every
  other call, and every call through another architecture (i386, AArch32) or
  x32 numbering, kills the child with `SIGSYS` (a crash: `unknown`). Fail
  closed: when Landlock is unavailable (ABI 0), seccomp has no filter mode or
  kill-process action, the architecture is not one of the two, or the child is
  not single-threaded, the child sends `S` + a fixed code instead of ready and
  exits; the decoder counts a start failure, reports `failing` at once and
  `sandbox_refusal` (`landlock_unavailable`, `seccomp_unavailable`,
  `unsupported_architecture`, `sandbox_not_applied`); the source is `degraded`
  with `frame_decoder_sandbox_unavailable` and
  `scene_frame_decoder_sandbox_unavailable` is logged once (value-free; the
  scene worker polls the decoder on every pass, so the event appears even
  when the camera never delivers a frame, Issue #299). No
  setting decodes unconfined (keeping seccomp only on a kernel without
  Landlock is an open Owner decision). The child still runs as the same
  unprivileged service account inside the same systemd unit (same network
  namespace);
- the child decodes with simplejpeg `strict=True` (libjpeg warnings such as a
  premature end of data or extraneous bytes raise) to luma with the accurate
  integer IDCT and libjpeg DCT scaling to the smallest power of two (1/8 to 1)
  whose output decimates exactly to the reference, checks the decoded shape and
  type, refuses a decode whose trailing MCUs (one MCU row's worth, in scan
  order) are all exactly 128 — the band libjpeg leaves after stopping a scan
  early — and returns the nearest-sample-decimated luma at the reference size;
- Main checks the reply's type, request id and exact pixel count. Each
  exchange (frame transfer included) has a hard deadline (default 500 ms): a
  child that has not replied is killed. A crash, a kill (including an OOM
  kill), a non-zero exit, a timeout, or a malformed, oversized or mismatched
  reply kills and reaps the child and refuses that frame; a replacement starts
  only after an exponential backoff (1 s doubling to 30 s) and only once the
  killed child has been reaped. Starting a child (fork+exec and the ready
  handshake, bounded by a 5 s start timeout) and reaping a killed one (2 s
  bound, then `reap_failed` and periodic retries, never a second child
  alongside) run on the source's supervisor thread, never on the shared scene
  worker: frames while the child starts (`decoder_starting`), during the
  backoff, a reap or after a reap failure (`decoder_unavailable`) are refused
  at once, never waited on. The scene worker waits only for one exchange with
  a ready child, bounded by the 500 ms per-frame deadline.
  After 3 consecutive child failures the source is `degraded`
  (`frame_decoder_failing`, which also lowers the runtime) and
  `scene_frame_decoder_failing` is logged once (value-free);
  one successful exchange clears it (`scene_frame_decoder_recovered`). The
  restart after the backoff never gives up: a child that can never start
  (address-space cap too small, the reviewed pair not importable) is respawned
  as a fresh python + numpy process at most once per 30 s per source, for as
  long as the source is bound, while the source keeps reporting `degraded`
  (`frame_decoder_failing`). A
  refusal by a healthy child (strict decode error, shape mismatch, band) is not
  a child failure. One source's child failing, hanging, starting slowly or
  not being reaped never refuses another source's frames and never delays
  their evaluation by more than that source's own bounded exchange (at most
  the 500 ms per-frame deadline per cycle, and only while its child is
  ready).

Every refusal is `frame_undecodable` (counted in `unusable`, the episode ends,
movement and tamper are `unknown`), with value-free per-reason counts in the
source status (`undecodable_reasons`, the fixed `MjpgFrameRejected` reasons)
and child failures in `decoder_failures`. A missing or differently versioned
decoder (package metadata; Main never imports simplejpeg or numpy) keeps the
source inactive (`frame_decoder_unavailable`) and starts no child. `stop()`
lets a running child serve the final worker pass but starts no new one, kills
every child once the worker has ended (or its bound expired), and ends the
supervisor threads and reaps the children within a 1 s bound inside the usual
stop bounds (worker 5 s + delivery 5 s). A start in progress (even one hanging
until its 5 s start timeout) is interrupted within 50 ms, so it does not make
the stop wait or fail; a supervisor or child that cannot be ended within the
bound makes the stop `stop_failed`.

Decode success does not prove integrity. A corruption that keeps the
entropy-coded syntax decodable can give substantially wrong pixels, not only
locally wrong ones: in a synthetic mutation run during the PR #225 review
(entropy-segment byte insertions/deletions) about 10% of the mutants decoded without any refusal
while more than 5% of their pixels differed by more than 16 (worst cases 30–89%
of the frame), including a bottom band clamped to 0 by a DC desync that the
exactly-128 band check does not see. The band check is deliberately **not**
extended to 0 or 255: that would also refuse a covered or dark lens and hide
camera tamper. The quality gate and the detector's temporal confirmation still
apply, and the real-scene rate of such frames is a `MANUAL_TEST.md` item. The
band check is also a heuristic in the other direction: a real scene whose
trailing MCUs are exactly 128 (a uniform mid-grey area at the bottom right)
is refused as `undecoded_band` (fail-closed `unknown`).

A calibration reference for an `MJPG` source must be produced through the same
reader (same decoder, scale and decimation): `acquire_reference()` reads it on
the scene worker through the source's own reader, and the calibration records
the reader identity (`reader_identity()`, below). Real EMEET C960 frames (DHT presence, bytes
after `EOI`, decode time, refusal rates, the decode child inside the systemd
sandbox) are still to be checked (`MANUAL_TEST.md`).

A local `offline` or `manual_intervention_required`
camera state is a trusted source loss and can correlate with a just-tracked
scene shift; other states only end confirmation. A loss that arrives while
critical staging has no room is held (the source reports
`critical_backpressure`, samples after it are not evaluated ahead of it) and is
handed to the detector once staging drains, so a loss correlated with a scene
shift is never turned into a per-source fault that drops the tamper evidence.
A camera loss (every non-`online` state: `offline`,
`manual_intervention_required` and `degraded`) lowers the source to `degraded`
(`source_unavailable`) until a new evaluated sample establishes recovery; a
camera-state `online` alone is not a recovery. A source with no sample
evaluated within the calibration's `maximum_gap_ns` (frames stopped, or a bound
source that never received one) is also lowered to `degraded`
(`observation_stale`) and its conclusions are `unknown`, until a fresh
evaluated sample recovers it.

`offer_luma()` refuses a producer stream id that this source has already
replaced (`stale_rejected`): delayed frames of an old stream are stale imagery
and are never re-admitted under a fresh runtime stream identity, which would
defeat the detector's retired-stream refusal. The stream transition is
recorded before the sampling decision, so a replacement stream's first frame
retires the old stream even when that frame is itself sampled out. The retired
history holds at most `RETIRED_PRODUCER_LIMIT` (1024) ids per source and is
never evicted from; when it is full a further replacement stream is refused and
the source reports `stream_history_exhausted` until the runtime is restarted.
The refused replacement also shows that the current stream is stale, so from
then on no sample of that source is admitted at all (its pending sample is
dropped and counted in `stale_rejected`), and its conclusions are `unknown`
(`stream_history_exhausted`); `scene_stream_history_exhausted` is logged once,
value-free, when that happens. Because the detector never sees the refused
stream restart, a camera loss timestamped at or after exhaustion is handed to
it as untrusted and never confirms `source_loss_after_scene_shift`; a loss
timestamped before exhaustion keeps its trust and may still correlate (Owner
decision 2026-10-11). A sample still pending when its producer stream is
replaced (the worker has not taken it yet) is discarded as stale imagery
(`stale_rejected`), even when the replacement's first frame is sampled out.
Only a replacement producer stream consumes that history. For local UVC
capture (`on_uvc_frame`, which has no producer stream id) a camera loss or a
capture reopen mints a new runtime stream without adding a retired id, and a
calibration refresh binds a fresh detector for any source. For a decoded-sample
producer such as a future remote-agent decoder, every new producer
`stream_id` does use up the history: a remote agent capture restart (a new
`capture_epoch`) is a new stream. A capture restart loop (for example a
restart every 10 s) therefore reaches 1024 in about 2.8 hours; the source then
fails safe as above (`stream_history_exhausted`, `unknown` until restart, the
log event once), never as "no movement" or "no tamper". Such a producer
(Issue #224 review) should change `stream_id` only when the imagery itself
restarts (a new `capture_epoch`), not on every transport reconnect or session
generation, so that a flapping LAN alone does not use up the history.
A calibration refresh request (`request_calibration_refresh()`) is deferred
while a held loss or a loss just taken from the capture slot is still to be
handed to the current detector, so the refresh never discards the scene-shift
state a loss must be correlated with; it runs on the next pass. Under
sustained losses (a loss on every pass, or a loss held while staging has no
room) it can stay deferred; the source reports `refresh_pending` while it
waits. Once an explicit request has waited longer than
`calibration_refresh_defer_ns` (default 60 s, the calibration retry interval;
the bound runs from the first request still waiting, so repeated requests do
not postpone it), the source reports `refresh_deferred`, is `degraded`
(`calibration_refresh_deferred`) and its movement and tamper conclusions are
`unknown`, because they are judged against a calibration the Owner replaced
(Owner decision 2026-10-14). `scene_calibration_refresh_deferred` is logged
once per request. The refresh still waits for the loss, so no evidence is
dropped. A reason the source already reports is the cause and is kept, with
`refresh_deferred` alongside it: behind a held loss that is
`critical_backpressure` (its later samples are already dropped), and likewise
`source_unavailable`, `frame_decoder_failing`,
`frame_decoder_sandbox_unavailable`, `scene_evaluation_failed`,
`observation_stale` or an inactive source; only an otherwise active source takes
`calibration_refresh_deferred`. Either way its conclusions are `unknown`.
The state clears when the refresh runs. When the refresh runs, a pending
sample captured at or before the request is discarded (`refresh_discarded`),
so a frame of the scene before the new calibration never becomes a
temporal-confirmation sample of the refreshed detector.

The default sample interval
is a conservative 1 sample/s per source, evaluated by one worker thread for
all sources (`tick_seconds` must be between 0.01 and 60 s). Critical staging is bounded and in memory. The durable recorder is
called only on a dedicated `scene-critical-delivery` thread, one observation
at a time: the scene worker only stages a whole batch, so a recorder that
blocks (stalled storage) never stops sampling or detection on any source.
Staging then fills and further confirmations are explicit
`critical_backpressure`; a call in flight longer than `recorder_stall_ns`
(default 5 s) sets `recorder_stalled`, makes the runtime `degraded` and logs
`scene_critical_recorder_stalled` once for every distinct stalled call. At
shutdown the final worker
pass first hands every loss still queued in a capture slot to its detector
(after a sample captured before that loss, at most one of each per source; a
sample after the loss is dropped), then retries held losses; the delivery
thread then makes one final pass. The worker and the delivery thread are each
bounded by the stop timeout (default 5 s each, so a stop takes up to about
10 s): a recorder call still in flight is reported as `stop_failed` with
`critical_in_flight`, and no further recorder call starts after that. At stop,
`scene_critical_recorder_stalled` is logged only for a call that actually
exceeded `recorder_stall_ns`; a call merely in flight logs
`scene_critical_in_flight_at_stop`. Once stopped, staging refuses new
observations: a worker that outlived its stop bound cannot stage into it (each
refused observation is counted in `critical_refused` and logged) and cannot
republish a conclusion; every source stays `inactive` and `unknown`.
Observations the recorder has not accepted stay counted in
`critical_pending`, losses that still had no staging room in `losses_held`,
and losses lost to a per-source fault (while running or during the shutdown
drain) in `losses_failed`; a loss still in a capture slot, or already taken from
it but not yet handed to its detector, when the worker outlived its stop bound
is counted in `losses_cleared`. All are logged (`scene_critical_undelivered`);
the evidence itself is not persisted, but their total is handed to the injected
`undelivered` sink, a count-only durable record (Owner decision 2026-10-14).
Refusals are counted once: those before `stop()` fences the staging count are in
the stop total, and each batch a worker that outlived its bound confirms after
the fence is handed to the sink on its own. `undelivered_recorded` reports
whether the sink took every count (one failure keeps it `False`); a missing or
failing sink logs `scene_undelivered_unrecorded`. A count can be overstated (a
loss counted in `losses_cleared` whose outliving worker later confirms evidence
that is then refused), never hidden. A retried `stop()` (for example after
`stop_failed`) hands over only what no earlier stop or late batch recorded, and
resends a stop total whose record failed; concurrent `stop()` calls hand the
total over once. A late batch whose record failed is not resent, but
`undelivered_recorded` stays `False`, so the wiring below must not close the
outbox cleanly and the next start still records an interrupted gap. The sink is
called synchronously (from `stop()` and the delivery thread), so it must not
block and must do no I/O.

With `create_app(scene_timeline=...)` (`app.presence.runtime.SceneTimeline`,
#205) Main passes `CriticalTimelineRecorder.record_undelivered` as the sink and
the same `CriticalTimelineRecorder` as the durable recorder (an embedder-supplied
recorder or sink is then refused). It adds the count as lost facts to the
presence timeline gap marker through the open outbox session (no observation
content, identifier or source). The marker is written by the outbox's next
flush (the lifespan flushes at `flush_interval_seconds` and once more at
shutdown) or at its clean close. The lifespan opens the outbox before it starts
scene monitoring (a refused open keeps scene monitoring unstarted, `unknown`
and retried), stops scene monitoring before it ends the outbox, and calls
`close()` only when `stop()` returned `stopped` and `undelivered_recorded` is not
`False`; otherwise the session row stays, the next start records an interrupted
gap, and Owner status reports `timeline_gap` until the Owner clears it. Without
`scene_timeline` the count is only logged (`scene_undelivered_unrecorded`). A
direct Owner notification for an unclean stop is a follow-up.

After a worker failure the final pass still stages that
evidence, but every source stays withdrawn as `worker_failed`. The runtime is
`degraded` while evidence is undelivered, a loss is held, the recorder is
stalled, or any source is `degraded`. Because `critical_pending` counts every
staged observation until the recorder accepts it, the runtime briefly reports
`degraded` during normal delivery of each confirmation as well; that is
expected and returns to `running` once the recorder accepts it. The runtime
status itself reports `unavailable` when its worker or delivery thread is no
longer running (outside `stop()`, where both end by design); every source is
then reported `inactive` and `unknown` (`worker_unavailable` /
`delivery_unavailable`) without changing the stored results, and
`scene_monitoring_unavailable` is logged once by the runtime. If the worker
thread cannot be started after the delivery thread started, `start()` closes
the delivery thread within a bounded wait (5 s), keeps no unstarted thread,
reports `unavailable` (`worker_start_failed`) and raises; a later `stop()`
does not fail on it; a runtime without a durable recorder starts
`unavailable` (`critical_recorder_unavailable`). In both cases the caller
reports the outcome and `status()` does not log it again. A worker that
outlived its stop bound and then fails leaves the `stop_failed` state and the
`stopped` reasons unchanged (it logs `scene_source_failed`, not
`scene_monitoring_unavailable`). A delivery thread that had already died
before `stop()` has no call in flight, so the runtime ends `stopped`; what it
left staged stays counted in `critical_pending` and
`scene_critical_undelivered` is logged. The Main
application's `scene_monitoring_state` follows the
runtime status while it runs (those conditions are `degraded`; a failed or dead
worker or delivery thread, or an unreadable status, is `unavailable`). Only the
Owner's scene calibration status route reads it (below).

## Owner calibration and restart re-acquisition (Issue #205)

`calibration_service.py` (Owner decision 2026-10-22, option A) produces the
reference frames the provider re-binds; `app.main.create_app(scene_calibration=
SceneCalibrationConfiguration(...))` builds it, owns the runtime's provider
(`ArchiveCalibrationProvider` over a read-only connection with the in-memory
`TransientReferences`) and refuses an embedder-supplied provider. Nothing
derived from an image is written to disk: the history keeps provenance only,
and the frame lives in `TransientReferences` (and the bound `Calibration`)
for the process's lifetime.

- `SceneMonitoringRuntime.acquire_reference(source, width, height,
  timeout_ns)` is the only way a reference is taken from live frames. The
  worker reads the next samples captured after the request through the
  source's own luma reader at that size (packed decimation, the MJPG decode
  child, or a decoded producer's exact size) and assesses them with fresh
  quality gates of the source's two detector policies; the first frame both
  report `sufficient` (each policy's `recovery_frames` consecutive good
  samples of one stream) resolves the future. A camera loss or an unreadable
  sample restarts the count; the deadline is `no_frame` (nothing readable) or
  `quality_insufficient`; at most one acquisition per source (`busy`); a size
  the layout cannot decimate to, beyond a quality pixel budget, or without the
  reviewed decoder is `geometry_unsupported`; stop and `cancel_acquisition()`
  end it (`unavailable`, `cancelled`). Normal evaluation of the same sample
  continues. `calibration_refusal()` applies the same checks as binding
  (`_bind`), so a calibration is checked before it is stored.
- `reader_identity(binding)` names the reader without a device value:
  `packed:<format>:<w>x<h>`, `mjpg:simplejpeg=<pin>:numpy=<pin>:<w>x<h>` or
  `decoded:<source type>`. `Calibration.reader` / `CalibrationRecord.reader`
  carry it (`None` in a record written before #205).
- **Owner calibration** (`SceneCalibrationService.calibrate`): the
  deployment's `CalibrationTemplate` of the source (reference size,
  Owner-selected polygon, policy) plus the acquired frame make the next
  version (the identifier of the first version is kept). `commit(source,
  prepare, persist)` is the caller's audited transaction: the human surface
  passes `SceneCalibrationAdministration.calibrate` (an `OWNER_OP` request
  only), which runs `prepare` (the acquisition) after the authorization and
  `persist` (`calibration.append_on`, inside the caller's transaction) with
  the `calibrate_scene_source` record. The frame is staged in
  `TransientReferences` before the commit and dropped if it fails; on success
  older frames of the source are forgotten and a calibration refresh is
  requested. Refusals are `CalibrationRefused` with a fixed reason.
- **Restart re-acquisition** (`start()`, `pending_reacquisitions()`,
  `reacquire()`): after every start each source with a stored calibration is
  re-acquired with the stored size, polygon and policy, through the same
  reader only (`reader_changed` otherwise), and committed by Main's system
  commit (`reacquire_scene_reference`, actor `system`). Success queues a
  `scene_reference_reacquired` notice; a failure other than a not-yet-running
  runtime queues `scene_calibration_required` once per process and is
  retried by the application at `reacquire_retry_seconds`. `take_notices()` /
  `return_notices()` hand the fixed notices to Main, which submits them
  through the monitoring runtime's `NotificationService` (immediate kinds).
  The re-acquired reference is reported `restart_reacquired` (not confirmed by
  the Owner): a camera or server moved while Main was down is not detected
  against it.
- `status()` is value-free: origin, version, time, phase, last refusal,
  whether a template exists, and the runtime's own source state and reason.

Synthetic verification: `server/tests/test_scene_calibration.py` (runtime
acquisition, history, service, and the application lifespan with an
intercepted Slack transport) and `server/tests/test_scene_calibration_routes.py`
(the Owner routes). The production launcher does not build scene monitoring
yet (the deployment section, including the templates, is a follow-up).

`server/tests/test_detector_roi.py` generates all pixel inputs in memory for
local and remote-agent calibration, relative movement, global camera motion,
temporary ROI occlusion, dark-scene tamper, persistent unmatched scenes,
ambiguous and low-margin registration, refused foreign-source and
retired-stream samples,
frame-progression watermarks, the unmatched-path comparison budget,
source-loss correlation, quality isolation, media-free calibration history,
and failed critical delivery. `server/tests/test_scene_runtime.py` drives the
runtime with generated YUYV and grayscale samples, including the application
lifespan with a synthetic UVC capture. Hardware,
lighting, camera pose, and source-health integration are not verified here.
