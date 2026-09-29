"""Bridge one SourcePipeline's inference sampler into an InferenceScheduler.

The decoder/resizer adapter calls `offer_decoded()` for each decoded frame in
presentation order. The pipeline's `InferenceSampler` decides which frames are
inference samples; only selected frames are rendered (at the sampled profile
dimensions) and offered to the scheduler. Offering never runs a detector.

Every input discontinuity the sampler reports (timestamp gap/reset, profile
change, new stream generation) and every render/validation failure replaces
the source's published conclusion with `unknown` at once through
`InferenceScheduler.invalidate`. A failure is never converted to `absent`.
No decoded pixels are retained after the offer.

A pipeline can become unusable (closed, admission expired, renegotiation
required) while no frame arrives, so the owning thread must also call
`poll()` right after every pipeline lifecycle action and on its periodic
tick; `poll()` invalidates at that transition instead of letting an earlier
conclusion stand until `maximum_observation_age_ns` expires.
"""

from dataclasses import dataclass
from fractions import Fraction
from typing import Callable
from uuid import UUID

from .contracts import GrayFrame, Quality, Reason, RgbFrame
from .scheduler import InferenceScheduler

# Pipeline states in which its sampler no longer describes a live input.
_BLOCKING_PIPELINE_REASONS = frozenset({
    "pipeline_closed", "admission_expired", "capture_renegotiation_required",
})
_DISCONTINUITIES = frozenset({"timestamp_gap", "timestamp_reset"})


@dataclass(frozen=True)
class FeedResult:
    offered: bool
    reason: str


@dataclass(frozen=True)
class FeedStatus:
    stream_id: UUID | None
    decoded: int
    sampled_out: int
    offered: int
    scheduler_rejected: int
    render_failures: int
    discontinuities: int
    blocked: int


class InferenceFeed:
    """One feed per (source, scheduler); runs on the decoder's owning thread."""

    def __init__(self, scheduler: InferenceScheduler, pipeline) -> None:
        if not isinstance(scheduler, InferenceScheduler):
            raise ValueError("invalid inference scheduler")
        self._scheduler = scheduler
        self.source_id: UUID = pipeline.source_id
        self._pipeline = pipeline
        self._profile = pipeline.profiles.inference
        self._stream_id: UUID | None = None
        self._sequence = -1
        self._decoded = self._sampled_out = self._offered = 0
        self._rejected = self._render_failures = self._discontinuities = 0
        self._blocked = 0
        self._unavailable = False

    def bind(self, pipeline) -> None:
        """Adopt a new stream generation for the same source."""
        if pipeline.source_id != self.source_id:
            raise ValueError("pipeline belongs to another source")
        self._pipeline = pipeline
        self._unavailable = False
        self._invalidate(Reason.DISCONTINUITY)

    def poll(self) -> bool:
        """Re-check the pipeline without a frame; True while it is unusable.

        Call on the pipeline's owning thread after close/renegotiation and
        periodically (an admission lease can expire asynchronously). The
        published conclusion is invalidated once, at the transition.
        """
        if self._pipeline_unavailable():
            if not self._unavailable:
                self._unavailable = True
                self._invalidate(Reason.DISCONTINUITY)
            return True
        self._unavailable = False
        return False

    def offer_decoded(self, *, stream_id: UUID, pts: int, time_base: Fraction,
                      quality: Quality, channels: int,
                      render: Callable[[int, int], bytes]) -> FeedResult:
        """Sample one decoded frame; `render(width, height)` returns pixels.

        `quality` is the detector-specific quality decision for this frame
        (#22); callers without one must pass `Quality.UNKNOWN`.
        """
        if not isinstance(quality, Quality) or channels not in (1, 3):
            self._invalidate(Reason.FAILURE)
            raise ValueError("invalid inference quality or channel count")
        self._decoded += 1
        pipeline = self._pipeline
        if self._pipeline_unavailable():
            self._blocked += 1
            self._unavailable = True
            self._invalidate(Reason.DISCONTINUITY)
            return FeedResult(False, "pipeline_unavailable")
        self._unavailable = False
        profile = pipeline.profiles.inference
        if profile != self._profile:
            # The sampler restarts its cadence; old temporal state is invalid.
            self._profile = profile
            self._invalidate(Reason.DISCONTINUITY)
        try:
            decision = pipeline.inference.select(stream_id, pts, time_base)
        except (TypeError, ValueError):
            self._invalidate(Reason.FAILURE)
            raise
        if not decision.emit:
            self._sampled_out += 1
            return FeedResult(False, decision.reason)
        if decision.reason in _DISCONTINUITIES:
            self._invalidate(Reason.DISCONTINUITY)
        if stream_id != self._stream_id:
            self._stream_id, self._sequence = stream_id, -1
        try:
            pixels = render(decision.width, decision.height)
            frame_type = RgbFrame if channels == 3 else GrayFrame
            frame = frame_type(self.source_id, stream_id, self._sequence + 1,
                               decision.width, decision.height, pixels)
        except Exception:
            # Decoder/resizer text can carry paths or device details; drop it.
            self._render_failures += 1
            self._invalidate(Reason.FAILURE)
            return FeedResult(False, "render_failed")
        self._sequence += 1
        if not self._scheduler.offer(frame, quality=quality):
            self._rejected += 1
            return FeedResult(False, "scheduler_rejected")
        self._offered += 1
        return FeedResult(True, decision.reason)

    def status(self) -> FeedStatus:
        return FeedStatus(self._stream_id, self._decoded, self._sampled_out, self._offered,
                          self._rejected, self._render_failures, self._discontinuities,
                          self._blocked)

    def _pipeline_unavailable(self) -> bool:
        try:
            reasons = self._pipeline.status.reasons
        except Exception:
            # An unreadable lifecycle state is treated as unusable, never live.
            return True
        return bool(_BLOCKING_PIPELINE_REASONS.intersection(reasons))

    def _invalidate(self, reason: Reason) -> None:
        if reason is Reason.DISCONTINUITY:
            self._discontinuities += 1
        self._scheduler.invalidate(self.source_id, reason=reason)
