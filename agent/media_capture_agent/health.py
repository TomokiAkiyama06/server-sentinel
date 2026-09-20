"""Separate node/source health and bounded clock-exchange observations."""

from dataclasses import asdict, dataclass
import math
from uuid import UUID


SOURCE_STATES = frozenset({"online", "degraded", "offline", "manual_intervention_required"})
SOURCE_REASONS = frozenset({"video_ready", "camera_missing", "capture_failed",
                            "identity_ambiguous", "capture_unconfigured"})


@dataclass(frozen=True)
class SourceHealth:
    source_id: UUID
    state: str
    reason: str

    def __post_init__(self):
        if not isinstance(self.source_id, UUID) or self.state not in SOURCE_STATES:
            raise ValueError("invalid source health")
        if self.reason not in SOURCE_REASONS:
            raise ValueError("invalid source health reason")

    def public(self):
        return {"source_id": str(self.source_id), "state": self.state, "reason": self.reason}


@dataclass(frozen=True)
class ClockExchange:
    local_send_utc: float
    local_send_monotonic: float
    remote_receive_utc: float
    remote_send_utc: float
    local_receive_utc: float
    local_receive_monotonic: float


@dataclass(frozen=True)
class ClockHealth:
    state: str
    reason: str
    offset_seconds: float | None = None
    uncertainty_seconds: float | None = None


def assess_clock(exchange, settings):
    if exchange is None:
        return ClockHealth("unknown", "clock_unavailable")
    if not isinstance(exchange, ClockExchange) or any(
        type(value) not in (float, int) or not math.isfinite(value)
        for value in asdict(exchange).values()
    ):
        return ClockHealth("degraded", "clock_invalid")
    elapsed = exchange.local_receive_monotonic - exchange.local_send_monotonic
    wall = exchange.local_receive_utc - exchange.local_send_utc
    processing = exchange.remote_send_utc - exchange.remote_receive_utc
    if elapsed < 0 or processing < 0 or processing > elapsed:
        return ClockHealth("degraded", "clock_invalid")
    if abs(wall - elapsed) > settings.clock_step_limit_seconds:
        return ClockHealth("degraded", "clock_step")
    offset = ((exchange.remote_receive_utc - exchange.local_send_utc)
              + (exchange.remote_send_utc - exchange.local_receive_utc)) / 2
    uncertainty = (elapsed - processing) / 2
    if uncertainty > settings.clock_uncertainty_limit_seconds:
        return ClockHealth("degraded", "clock_uncertain", offset, uncertainty)
    # Even the optimistic end of the interval exceeds the configured limit.
    if abs(offset) - uncertainty > settings.clock_offset_limit_seconds:
        return ClockHealth("degraded", "clock_offset", offset, uncertainty)
    # An interval overlapping the limit is explicitly uncertain, not trustworthy.
    if abs(offset) + uncertainty > settings.clock_offset_limit_seconds:
        return ClockHealth("degraded", "clock_uncertain", offset, uncertainty)
    return ClockHealth("online", "clock_within_limit", offset, uncertainty)
