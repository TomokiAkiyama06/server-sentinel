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
leaves no translating candidate at or beyond a threshold above
`minimum_coverage`, since the policy radius alone does not say which
candidates survive the coverage gate and a usable quarter turn does not
register a pixel shift.
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
source, ends the episode too, so no later confirmation spans it. A bounded
history of replaced streams is kept, so a delayed frame from a stream this
source already left is refused as stale imagery rather than becoming current
again through an A-to-B-to-A transition. Every accepted
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
not make progress by retrying. A later runtime owns
durable events, recording preservation, and configured notifications, which
must remain armed in every presence state.

`server/tests/test_detector_roi.py` generates all pixel inputs in memory for
local and remote-agent calibration, relative movement, global camera motion,
temporary ROI occlusion, dark-scene tamper, persistent unmatched scenes,
ambiguous and low-margin registration, refused foreign-source and
retired-stream samples,
frame-progression watermarks, the unmatched-path comparison budget,
source-loss correlation, quality isolation, media-free calibration history,
and failed critical delivery. Hardware,
lighting, camera pose, and source-health integration are not verified here.
