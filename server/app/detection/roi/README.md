# Calibrated ROI movement and camera-tamper core

This module processes transient, bounded grayscale `GrayFrame` values for one
immutable source/profile calibration. It stores no media, starts no capture,
opens no HTTP route, and makes no presence, identity, guilt, or notification
decision.

A calibration contains an Owner-selected polygon, reference frame digest,
source type, profile ID, explicit search/quality thresholds, version, and
timestamp. `CalibrationArchive` is a small append-only SQLite port: the Main
runtime must supply its already-open private database after application
migration 3 (`roi_calibration_history`) has run. The table holds provenance
only — identities, polygon, policy, reference geometry and the reference
SHA-256 — so no decoded frame, crop, or other monitoring media is persisted
and the history cannot become retention-free image storage. `load()` therefore
returns a `CalibrationRecord` without pixels; resuming detection needs
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
quality resets confirmation and yields `unknown`, never `no movement`.
Person presence is deliberately not an input.

Camera tamper has its own quality input and temporal confirmation. It can
report a bounded global scene shift, a persistent near-dark scene, or a scene
that stops registering while differing measurably from the calibrated
background — a covered or redirected camera. A registration that is merely
ambiguous on an otherwise unchanged scene stays `unknown` and confirms
neither tamper nor absence of tamper. A trusted source-loss signal produces a
critical observation only if it closely follows a tracked global scene shift;
source loss by itself stays `unknown`. The scene-difference measurement is a
bounded scalar over background support points; it never describes who or what
is in view. The core records neutral observation provenance and offers
`CriticalDelivery` for bounded, explicit local handoff. A later runtime owns
durable events, recording preservation, and configured notifications, which
must remain armed in every presence state.

`server/tests/test_detector_roi.py` generates all pixel inputs in memory for
local and remote-agent calibration, relative movement, global camera motion,
temporary ROI occlusion, dark-scene tamper, persistent unmatched scenes,
ambiguous registration, source-loss correlation, quality isolation,
media-free calibration history, and failed critical delivery. Hardware,
lighting, camera pose, and source-health integration are not verified here.
