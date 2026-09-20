# Detection

Owns per-source motion, person, server-movement, camera-tamper, entrance, anonymous tracking, and optional owner-only 1:1 verification profiles on the Main Server. The calibrated local ROI/tamper core is in `roi/`; see `roi/README.md` for its bounded synthetic-only contract. Its calibration history keeps provenance and the reference digest only: no decoded frame is persisted by this package.

Apply detector-specific quality gates and motion/occlusion handling. Unreliable person inference and poor owner-verification input return `unknown`/unavailable. Do not infer movement from person presence, enroll named non-owners, perform cross-camera biometric re-identification, or claim guilt/causality. Dependencies and model weights require separate license review.
