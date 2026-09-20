# Detector-specific quality gate

This internal module measures transient decoded `GrayFrame`/`RgbFrame` values
and returns `QualityDecision` with a quality state, numerical metrics, fixed
reason codes, source/stream/sequence identity, detector name, policy version,
and recovery progress. It has no HTTP routes, network, image persistence,
biometric enrollment, capture/recording control, or production calibration.

Each source and detector/profile owns a separate `QualityGate`. Its immutable
`DetectorQualityPolicy` requires explicit metric ranges, recovery frame count,
and pixel budget. Every configured rule is a prerequisite for **both positive
and negative** conclusions. A missing required metric gives `UNKNOWN`; a metric
outside its usable range gives `INSUFFICIENT`; between the usable and sufficient
ranges it gives `DEGRADED`. Only `SUFFICIENT` allows either result direction.
No thresholds are copied between detectors or supplied as product defaults.

Measurements are local and bounded by the explicit pixel budget:

- normalized mean grayscale/weighted RGB luminance;
- mean squared neighboring luminance difference as a calibrated sharpness
  proxy (a textureless scene can also score low; this is not proof of defocus);
- fraction of pixels with a channel clipped at 255;
- decoded width and height;
- adapter-provided target/crop dimensions, calibrated obstruction fraction, and
  optional detector confidence, attributed to the exact assessed frame.

Target size and obstruction are never invented from a negative detection.
For a person-negative prerequisite, target dimensions describe the calibrated
smallest relevant person projection in the monitored region. For owner
verification, dimensions can describe the independently found candidate crop.
Missing calibration/candidates remain unavailable. `obstruction_fraction()`
measures an explicit binary mask within a caller-provided budget; it does not
claim to infer occlusion from arbitrary pixels. A producer of such masks owns
its calibration and frame attribution. This module does not implement owner
matching, entrance inference, presence automation, or a tamper detector.

Evaluate gates on the inference worker, separately from capture, recording,
and live delivery. Measurement takes O(pixels) time and O(width) temporary
memory. Gates retain only their latest numbers/identities and recovery count,
not a frame or decoded history. `maximum_pixels` must match the bounded input
profile; exceeding it yields unknown before scanning pixels.

Recovery requires the explicitly configured number (at least two) of
consecutive good frames. Bad/missing evidence has immediate effect. Stream
changes, sequence gaps/regressions/duplicates, geometry changes, unavailable
execution, and source/context mismatch reset recovery. A good frame during
recovery is `DEGRADED` with `quality_recovery_pending`, never trustworthy
negative evidence.

Integration sequence:

1. Continue capture/live/recording delivery independently when frames exist.
2. Assess quality for the particular detector with its current execution state
   and frame-bound context. A stopped/failed/skipped/unavailable detector yields
   unknown even if another detector can continue.
3. Pass `decision.quality` to that detector's `InferenceScheduler.offer`.
   The scheduler immediately invalidates preceding conclusions on bad quality,
   and enforces queue/evaluation/result age through `SourcePolicy`.
4. For dependent owner/entrance/presence adapters, propagate the scheduler's
   `UNKNOWN`; never substitute absent/no-match for skipped or failed inference.
   `gate.guard_result()` requires the gate's latest decision, the exact result
   frame identity, completed execution and an actual `Detection`. It also
   preserves any unknown detector result. An old assessment cannot authorize a
   late completion after a newer assessment has invalidated it.
5. Call `gate.invalidate(execution=...)` when a worker stops or fails without a
   new frame. On restart, quality recovery starts again. Result freshness still
   belongs to the scheduler; a gate does not replace its monotonic age policy.

A stricter owner-verification profile must not disable an unrelated critical
camera-tamper profile. Each profile lists its own prerequisites; for example a
near-black frame may be unusable for person inference while remaining evidence
for a separately evaluated tamper signal. Quality decisions never directly
change recording/live state or suppress critical monitoring.

`server/tests/test_detector_quality.py` generates geometric synthetic shapes,
darkness, severe box blur, clipped pixels and obstruction masks in memory. It
checks both positive/negative results, source/profile independence, hysteresis,
execution failure/stop, late-result rejection, and scheduler unknown propagation.
The calibration in tests is only for those synthetic fixtures. Real lighting,
physical camera/profile thresholds, and their acceptance remain `MANUAL_TEST.md`
section L and the hardware hardening Issues.
