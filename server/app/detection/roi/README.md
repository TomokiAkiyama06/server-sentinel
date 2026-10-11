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
  live frame; the Owner calibration route is #10), the source stays inactive
  and `unknown`;
- a calibration whose source, type or profile differ, whose `maximum_gap_ns`
  does not exceed the sample interval, whose reference exceeds a quality pixel
  budget, or that the capture layout cannot decimate to, is refused;
- poor/unknown quality, an undecodable frame, critical backpressure (staging
  cannot take a full batch), a camera-state loss, or a conclusion older than the
  calibrated sampling gap is `unknown`, never "no movement" or "no tamper".

`capture_luma_layout()` picks the reader for the driver-negotiated format.
Packed uncompressed `GREY`/`YUYV` is read by nearest-sample luma decimation
(byte slicing) to the reference size. `MJPG` is read by `MjpgLumaLayout`
(`mjpg.py`, Issue #217, Owner decision 2026-10-11: simplejpeg 1.9.0 with
statically linked libjpeg-turbo 3.1.2 and numpy 2.3.5), only on the scene
worker, never on a capture thread:

- a pure-Python pre-check runs before any native code sees the bytes: `SOI`
  first, a bounded marker count and payload size, exactly one baseline or
  extended-sequential Huffman `SOF` whose width/height equal the negotiated
  format and fit the 3840x2160 pixel budget (a decompression-bomb header is
  refused before the decoder allocates), one interleaved scan ending in a
  single `EOI`, and at most `maximum_trailing_bytes` (provisionally 8192) of
  padding after it with no further `SOI`/`EOI`;
- decoding uses simplejpeg `strict=True` (libjpeg warnings such as a premature
  end of data or extraneous bytes raise) to luma with the accurate integer IDCT
  and libjpeg DCT scaling to the smallest power of two (1/8 to 1) whose output
  decimates exactly to the reference, then nearest-sample decimation;
- the decoded shape and type are checked, a decode whose trailing MCUs (one
  MCU row's worth, in scan order) are all exactly 128 — the band libjpeg leaves
  after stopping a scan early — is refused, and so is a decode slower than
  250 ms.

Every refusal is `frame_undecodable` (counted in `unusable`, the episode ends,
movement and tamper are `unknown`), and a missing or differently versioned
decoder keeps the source inactive (`frame_decoder_unavailable`). Decode success
does not prove integrity: a bit flip that keeps the entropy-coded syntax valid
gives locally wrong pixels that no check here detects. A calibration reference
for an `MJPG` source must be produced through the same reader (same decoder,
scale and decimation); the Owner calibration route (#10) does not exist yet.
Real EMEET C960 frames (DHT presence, bytes after `EOI`, decode time, decoding
inside the systemd sandbox) are still to be checked (`MANUAL_TEST.md`).

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
(`stream_history_exhausted`). Because the detector never sees the refused
stream restart, a camera loss timestamped at or after exhaustion is handed to
it as untrusted and never confirms `source_loss_after_scene_shift`; a loss
timestamped before exhaustion keeps its trust and may still correlate (Owner
decision 2026-10-11). A sample still pending when its producer stream is
replaced (the worker has not taken it yet) is discarded as stale imagery
(`stale_rejected`), even when the replacement's first frame is sampled out.
A calibration refresh request (`request_calibration_refresh()`) is deferred
while a held loss or a loss just taken from the capture slot is still to be
handed to the current detector, so the refresh never discards the scene-shift
state a loss must be correlated with; it runs on the next pass. Under
sustained losses (a loss on every pass) it can stay deferred; the source
reports `refresh_pending` while it waits. When the refresh runs, a pending
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
drain) in `losses_failed`; all are logged (`scene_critical_undelivered`) and
are not persisted. After a worker failure the final pass still stages that
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
worker or delivery thread, or an unreadable status, is `unavailable`). No route
reads the runtime status before #10.

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
