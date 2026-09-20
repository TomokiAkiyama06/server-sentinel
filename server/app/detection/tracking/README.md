# Ephemeral same-camera entrance observations

`AnonymousEntranceTracker` associates normalized geometric `PersonPoint`s within
one source and stream/session. Configure a finite directed `EntranceLine`,
hysteresis, maximum association distance/gap and track limit explicitly; there
are no production geometry or matching-threshold defaults. It does not detect
people or faces, persist data, store images/embeddings, name people, or match
across cameras. Internal random track IDs are discarded on session/stream reset.

Each update requires the latest sufficient `entrance_crossing` QualityGate
assessment for the exact frame. Unknown/degraded quality returns
`TrackUpdate.quality=UNKNOWN`, clears continuity and emits no conclusion. Empty
crossings are never an absence/presence inference. Ambiguous nearest candidates,
occlusion/unmatched tracks and stream/time discontinuities discard continuity;
dropped frames or excessive time gaps cannot synthesize a crossing.

Only an observed intersection of the finite segment, with an explicit direction
and settled sides beyond hysteresis, emits an entry/exit. Returning across the
line inside the deadband or changing sign outside its endpoints cancels prior
intersection evidence. Geometry-only association is deliberately conservative
around nearby/occluding people and needs real-room calibration.

Owner entry/exit additionally requires an exact same-frame/candidate match receipt
accepted by the originating `OwnerVerificationService.is_current`. Forged,
deleted/replaced, stale-quality or other-session receipts remain anonymous.
Trusted timestamps are required for the Owner event's `confirmed` flag;
untrusted clock data remains explicit. Anonymous crossing never becomes Owner
identity or forces presence. Receipt checks are an internal trust boundary,
not human authentication.

`Crossing` exposes UUID event/source IDs, kind, aware timestamps, confidence,
clock trust/uncertainty and confirmed state, without any track/session/biometric
payload. The pending #26 adapter maps these factual observations to its typed
timeline, retains quality and validates time freshness; it must not invent guilt
or causal attribution. No timeline route, UI, presence suppression or inference
worker is enabled here. Synthetic geometry tests do not establish real-camera
identity, occlusion handling or room coverage.
