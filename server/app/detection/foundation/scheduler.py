"""Bounded mailboxes and an explicit worker entry point for Main inference.

Capture calls offer(), which never calls a detector. A dedicated inference
worker calls run_one(); it must not run on capture/recording/health threads.
"""

from dataclasses import dataclass, field
import threading
import time
from typing import Callable
from uuid import UUID

from .contracts import (Detection, Detector, DetectorKind, GrayFrame, Health,
                        Observation, Quality, Reason, positive_integer)


@dataclass(frozen=True)
class SourcePolicy:
    cadence_ns: int
    maximum_cadence_ns: int
    maximum_queue_age_ns: int
    maximum_evaluation_ns: int
    maximum_observation_age_ns: int
    maximum_pixels: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            positive_integer(getattr(self, name), name)
        if self.maximum_cadence_ns < self.cadence_ns:
            raise ValueError("maximum cadence must allow configured cadence")


@dataclass(frozen=True)
class SourceSnapshot:
    source_id: UUID
    kind: DetectorKind
    implementation: str
    version: str
    health: Health
    result: Detection
    sequence: int | None
    stream_id: UUID | None
    received_at_ns: int | None
    evaluated_at_ns: int | None
    cadence_ns: int
    pending: bool
    dropped: int
    processed: int
    sampled_out: int


@dataclass
class _Pending:
    frame: GrayFrame
    quality: Quality
    received_ns: int


@dataclass
class _Source:
    detector: Detector
    policy: SourcePolicy
    cadence_ns: int
    pending: _Pending | None = None
    stream_id: UUID | None = None
    retired_stream_id: UUID | None = None
    sequence: int = -1
    result_sequence: int | None = None
    result: Detection = field(default_factory=lambda: Detection(Observation.UNKNOWN, Reason.NOT_STARTED))
    next_due: int = 0
    next_admission: int = 0
    result_ns: int | None = None
    evaluated_ns: int | None = None
    sampled_out: int = 0
    loss_unacknowledged: bool = False
    dropped: int = 0
    processed: int = 0
    epoch: int = 0
    reset_required: bool = True
    evaluating: bool = False


class InferenceScheduler:
    """At most one pending frame/source, plus one running frame globally.

    All thresholds/cadences are caller-provided. Overload doubles cadence up
    to its explicit limit. A recovered result never silently clears throttling;
    restore_cadence() is an explicit control-plane operation.
    """

    def __init__(self, *, clock_ns: Callable[[], int] = time.monotonic_ns,
                 maximum_sources: int = 4) -> None:
        positive_integer(maximum_sources, "maximum_sources")
        if maximum_sources > 4:
            raise ValueError("MVP supports at most four active sources")
        self._clock = clock_ns
        self._maximum_sources = maximum_sources
        self._sources: dict[UUID, _Source] = {}
        self._lock = threading.Lock()
        self._running = False
        self._last_clock = -1

    def register(self, source_id: UUID, detector: Detector, policy: SourcePolicy) -> None:
        if not isinstance(source_id, UUID) or not isinstance(policy, SourcePolicy):
            raise ValueError("invalid source registration")
        if not isinstance(detector.kind, DetectorKind):
            raise ValueError("invalid detector kind")
        if not isinstance(detector.implementation, str) or not detector.implementation:
            raise ValueError("detector implementation is required")
        if not isinstance(detector.version, str) or not detector.version:
            raise ValueError("detector version is required")
        with self._lock:
            if source_id in self._sources:
                raise ValueError("source is already registered")
            if len(self._sources) >= self._maximum_sources:
                raise ValueError("active inference source limit reached")
            if any(item.detector is detector for item in self._sources.values()):
                raise ValueError("each source requires its own detector instance")
            self._sources[source_id] = _Source(detector, policy, policy.cadence_ns)

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0:
            raise ValueError("clock must return nonnegative monotonic nanoseconds")
        if now < self._last_clock:
            for state in self._sources.values():
                state.pending = None
                state.next_due = now
                state.next_admission = now
                self._unknown(state, Reason.CLOCK)
        self._last_clock = now
        return now

    @staticmethod
    def _unknown(state: _Source, reason: Reason) -> None:
        state.result = Detection(Observation.UNKNOWN, reason)
        state.result_sequence = None
        state.result_ns = None
        state.evaluated_ns = None
        state.reset_required = True
        state.epoch += 1

    def _overload(self, state: _Source, reason: Reason, now: int) -> None:
        self._unknown(state, reason)
        state.loss_unacknowledged = True
        state.cadence_ns = min(state.cadence_ns * 2, state.policy.maximum_cadence_ns)
        state.next_admission = max(state.next_admission, now + state.cadence_ns)

    def offer(self, frame: GrayFrame, *, quality: Quality) -> bool:
        """Non-inferencing bounded admission; False means this frame was rejected."""
        if not isinstance(frame, GrayFrame) or not isinstance(quality, Quality):
            raise ValueError("invalid inference frame or quality")
        with self._lock:
            now = self._now()
            state = self._sources[frame.source_id]
            if state.stream_id != frame.stream_id:
                if frame.stream_id == state.retired_stream_id:
                    state.pending = None
                    state.dropped += 1
                    state.loss_unacknowledged = True
                    self._unknown(state, Reason.DISCONTINUITY)
                    return False
                state.pending = None
                state.retired_stream_id, state.stream_id, state.sequence = (
                    state.stream_id, frame.stream_id, -1)
                state.next_admission = now
                self._unknown(state, Reason.DISCONTINUITY)
            if frame.sequence <= state.sequence:
                state.pending = None
                state.dropped += 1
                state.loss_unacknowledged = True
                self._unknown(state, Reason.DISCONTINUITY)
                return False
            state.sequence = frame.sequence
            if frame.width * frame.height > state.policy.maximum_pixels:
                state.pending = None
                state.dropped += 1
                self._overload(state, Reason.RESOURCE_LIMIT, now)
                return False
            if quality is not Quality.SUFFICIENT:
                state.pending = None
                self._unknown(state, Reason.QUALITY)
                return False
            if now < state.next_admission:
                state.sampled_out += 1
                return False
            state.next_admission = now + state.cadence_ns
            if state.pending is not None:
                state.dropped += 1
                self._overload(state, Reason.DROPPED, now)
            state.pending = _Pending(frame, quality, now)
            return True

    def unregister(self, source_id: UUID) -> None:
        with self._lock:
            state = self._sources.pop(source_id)
            state.pending = None
            self._unknown(state, Reason.NOT_STARTED)

    def snapshot(self, source_id: UUID) -> SourceSnapshot:
        with self._lock:
            now = self._now()
            state = self._sources[source_id]
            if state.result_ns is not None and now - state.result_ns > state.policy.maximum_observation_age_ns:
                # Expire only the published old observation. A fresh in-flight
                # frame remains eligible unless its own input/quality changes.
                state.result = Detection(Observation.UNKNOWN, Reason.STALE)
                state.result_sequence = state.result_ns = state.evaluated_ns = None
                if not state.evaluating:
                    state.reset_required = True
            return self._snapshot(source_id, state)

    @staticmethod
    def _snapshot(source_id: UUID, state: _Source) -> SourceSnapshot:
        health = Health.HEALTHY
        if state.loss_unacknowledged or state.cadence_ns > state.policy.cadence_ns:
            health = Health.DEGRADED
        if state.result.observation is Observation.UNKNOWN:
            health = Health.UNAVAILABLE
        return SourceSnapshot(source_id, state.detector.kind, state.detector.implementation,
                              state.detector.version, health, state.result, state.result_sequence,
                              state.stream_id, state.result_ns, state.evaluated_ns, state.cadence_ns, state.pending is not None,
                              state.dropped, state.processed, state.sampled_out)

    def restore_cadence(self, source_id: UUID) -> None:
        with self._lock:
            state = self._sources[source_id]
            state.cadence_ns = state.policy.cadence_ns
            # Do not erase an outstanding error/unknown observation or loss.

    def acknowledge_recovery(self, source_id: UUID) -> None:
        with self._lock:
            state = self._sources[source_id]
            if state.result.observation is Observation.UNKNOWN:
                raise ValueError("cannot acknowledge unavailable inference")
            state.loss_unacknowledged = False

    def run_one(self) -> SourceSnapshot | None:
        with self._lock:
            now = self._now()
            if self._running:
                return None
            selected = next(((source_id, state) for source_id, state in self._sources.items()
                             if state.pending is not None and now >= state.next_due), None)
            if selected is None:
                return None
            source_id, state = selected
            # Round robin prevents one busy source starving the other sources.
            self._sources.pop(source_id)
            self._sources[source_id] = state
            pending, state.pending = state.pending, None
            state.next_due = now + state.cadence_ns
            if now - pending.received_ns > min(state.policy.maximum_queue_age_ns,
                                               state.policy.maximum_observation_age_ns):
                state.dropped += 1
                self._overload(state, Reason.STALE, now)
                return self._snapshot(source_id, state)
            if pending.quality is not Quality.SUFFICIENT:
                self._unknown(state, Reason.QUALITY)
                return self._snapshot(source_id, state)
            epoch, needs_reset = state.epoch, state.reset_required
            state.reset_required = False
            self._running = True
            state.evaluating = True
        try:
            if needs_reset:
                state.detector.reset()
            result = state.detector.evaluate(pending.frame)
            if not isinstance(result, Detection):
                raise ValueError("detector returned an invalid result")
        except Exception:
            # Never expose plugin exception text, pixels, model paths or secrets.
            result = Detection(Observation.UNKNOWN, Reason.FAILURE)
        except BaseException:
            with self._lock:
                self._running = False
                state.evaluating = False
            raise
        with self._lock:
            self._running = False
            state.evaluating = False
            finished = self._now()
            state.processed += 1
            if state.epoch != epoch:
                # A concurrent drop/discontinuity has already invalidated it.
                return self._snapshot(source_id, state)
            if finished - now > state.policy.maximum_evaluation_ns:
                self._overload(state, Reason.OVER_BUDGET, finished)
            elif finished - pending.received_ns > state.policy.maximum_observation_age_ns:
                self._overload(state, Reason.STALE, finished)
            else:
                state.result = result
                state.result_sequence = pending.frame.sequence
                state.result_ns = pending.received_ns
                state.evaluated_ns = finished
                if result.observation is Observation.UNKNOWN:
                    # Warmup intentionally retains the new background sample.
                    state.reset_required = result.reason is not Reason.WARMUP
            return self._snapshot(source_id, state)
