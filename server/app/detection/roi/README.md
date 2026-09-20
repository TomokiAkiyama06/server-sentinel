# Calibrated ROI movement and camera-tamper core

This module processes transient, bounded grayscale `GrayFrame` values for one
immutable source/profile calibration. It stores no media, starts no capture,
opens no HTTP route, and makes no presence, identity, guilt, or notification
decision.

A calibration contains an Owner-selected polygon, reference frame digest,
source type, profile ID, explicit search/quality thresholds, version, and
timestamp. `CalibrationArchive` is a small append-only SQLite port: the Main
runtime must supply its already-open private database after application
migration 3 (`roi_calibration_history`) has run. `OwnerCalibrationOperations` defaults to refusal;
authentication and API policy remain outside this core.

`SceneDetector` compares the background first to estimate bounded global
translation/quarter-turn transforms, then compares the ROI relative to that
transform. It only emits `server_movement` after the configured number and
duration of corroborating samples. An explicit ROI-occlusion signal, sampling
gap, stream restart, regression, mismatched frame, or insufficient movement
quality resets confirmation and yields `unknown`, never `no movement`.
Person presence is deliberately not an input.

Camera tamper has its own quality input and temporal confirmation. It can
report a bounded global scene shift or persistent near-dark/changed scene. A
trusted source-loss signal produces a critical observation only if it closely
follows a tracked global scene shift; source loss by itself stays `unknown`.
The core records neutral observation provenance and offers `CriticalDelivery`
for bounded, explicit local handoff. A later runtime owns durable events,
recording preservation, and configured notifications, which must remain armed
in every presence state.

`server/tests/test_detector_roi.py` generates all pixel inputs in memory for
local and remote-agent calibration, relative movement, global camera motion,
temporary ROI occlusion, dark-scene tamper, source-loss correlation, quality
isolation, calibration history, and failed critical delivery. Hardware,
lighting, camera pose, and source-health integration are not verified here.
