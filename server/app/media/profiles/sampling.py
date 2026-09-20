"""Constant-space cadence for presentation-ordered, already-decoded frames."""

from dataclasses import dataclass
from fractions import Fraction
from uuid import UUID

from .model import InferenceProfile, positive_fraction


@dataclass(frozen=True)
class SampleDecision:
    emit: bool
    reason: str
    width: int
    height: int


class InferenceSampler:
    """Select decoded frames; never discard reference packets before decode.

    The decoder calls this after reordering frames into presentation order.
    Every compressed packet must still reach its decoder. The decoder/resizer
    adapter owns producing an image at the returned dimensions. No decoded
    frame history or media payload is retained here.
    """

    def __init__(self, profile: InferenceProfile, stream_id: UUID):
        if not isinstance(stream_id, UUID):
            raise ValueError("stream_id must be a UUID")
        self.profile = profile
        self.stream_id = stream_id
        self._previous: Fraction | None = None
        self._next: Fraction | None = None

    def replace_profile(self, profile: InferenceProfile) -> None:
        self.profile = profile
        self._previous = None
        self._next = None

    def begin_stream(self, stream_id: UUID) -> None:
        if not isinstance(stream_id, UUID):
            raise ValueError("stream_id must be a UUID")
        self.stream_id = stream_id
        self._previous = None
        self._next = None

    def select(self, stream_id: UUID, pts: int, time_base: Fraction) -> SampleDecision:
        if type(pts) is not int:
            raise ValueError("PTS must be an integer")
        positive_fraction(time_base, "time_base")
        if stream_id != self.stream_id:
            return self._result(False, "stale_stream")
        timestamp = pts * time_base
        period = 1 / self.profile.fps
        if self._previous is None:
            self._previous = timestamp
            self._next = timestamp + period
            return self._result(True, "first_frame")
        if timestamp == self._previous:
            return self._result(False, "duplicate_timestamp")
        delta = timestamp - self._previous
        self._previous = timestamp
        if delta < 0 or delta > self.profile.maximum_timestamp_gap:
            self._next = timestamp + period
            return self._result(True, "timestamp_reset" if delta < 0 else "timestamp_gap")
        if timestamp < self._next:
            return self._result(False, "cadence")
        # Jump directly to the next deadline. Never iterate over missing frames.
        periods = (timestamp - self._next) // period + 1
        self._next += periods * period
        return self._result(True, "cadence")

    def _result(self, emit: bool, reason: str) -> SampleDecision:
        return SampleDecision(emit, reason, self.profile.width, self.profile.height)
