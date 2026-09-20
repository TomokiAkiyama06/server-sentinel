# Spatial detector foundation

`spatial` contains in-memory, per-source analysis contracts for Issue #24. A
caller provides an explicit normalized ROI calibration, a reference frame,
bounded thresholds, the exact frame's detector-quality result, and an
occlusion estimate. There are no deployment thresholds, camera I/O, HTTP
routes, recording writes, event publication, biometric processing, or
calibration persistence here.

`RoiMovementAnalyzer` compares the calibrated ROI with the reference after an
optional, caller-supplied bounded translation. It does not estimate a camera
transform. Missing/insufficient quality or occlusion evidence, stream changes,
sequence gaps, geometry changes, and insufficient reference coverage return
`unknown`. Candidate server movement needs explicit consecutive-frame
confirmation. A temporary occlusion cannot become a movement or a trustworthy
no-movement result.

`CameraTamperAnalyzer` requires consecutive candidate frames before it reports
scene change or trusted lens occlusion. It only produces an observation; source
disconnect correlation, critical-event preservation, notifications, timeline
publication, persistent calibration, and physical acceptance remain separate
integration work.
