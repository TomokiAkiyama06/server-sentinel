"""Bounded compressed-segment contracts and owner-facing ring status values."""

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


SECOND = 1_000_000
PRE = POST = 600 * SECOND
RETENTION = 60 * 86400 * SECOND
MAX_INTEGER = (1 << 63) - 1


class RingRefused(RuntimeError):
    """Value-free failure codes; callers must surface refusal/degradation."""


def integer(value, *, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise RingRefused("invalid_numeric_value")
    return value


def round_up(value, unit):
    return ((value + unit - 1) // unit) * unit


@dataclass(frozen=True)
class SegmentProfile:
    source_id: UUID
    maximum_bitrate: int
    expected_bitrate: int
    segment_duration_us: int
    overhead_bytes: int

    def __post_init__(self):
        if not isinstance(self.source_id, UUID):
            raise RingRefused("invalid_source_identity")
        integer(self.maximum_bitrate, minimum=1)
        integer(self.expected_bitrate, minimum=1)
        integer(self.segment_duration_us, minimum=1)
        integer(self.overhead_bytes)
        if self.expected_bitrate > self.maximum_bitrate or self.segment_duration_us > PRE:
            raise RingRefused("invalid_profile_bound")
        integer(self.segment_bytes())

    def segment_bytes(self, *, expected=False):
        bitrate = self.expected_bitrate if expected else self.maximum_bitrate
        return (bitrate * self.segment_duration_us + 8 * SECOND - 1) // (8 * SECOND) + self.overhead_bytes

    def bytes_for(self, duration_us, allocation_unit, *, expected=False):
        # At most two complete boundary segments straddle an arbitrary window.
        count = (duration_us + self.segment_duration_us - 1) // self.segment_duration_us + 2
        return count * round_up(self.segment_bytes(expected=expected), allocation_unit)


@dataclass(frozen=True)
class RingConfig:
    mode: str
    value: int

    def __post_init__(self):
        if not isinstance(self.mode, str) or self.mode not in {"duration", "capacity"}:
            raise RingRefused("invalid_ring_mode")
        integer(self.value, minimum=1)
        if self.mode == "duration" and self.value < 600:
            raise RingRefused("insufficient_pre_loss_duration")


class ControlAuthority(Protocol):
    """Integration must authenticate/authorize before invoking controls."""

    def require_owner(self, operation: str) -> None:
        ...

    def require_preserve(self) -> None:
        ...


class DenyControls:
    def require_owner(self, operation):
        raise RingRefused("owner_authorization_required")

    def require_preserve(self):
        raise RingRefused("authenticated_preserve_required")


def intervals_and_gaps(intervals, start, end):
    """Union coverage for one source; adjacent segments are continuous."""
    merged = []
    for left, right in sorted(intervals):
        left, right = max(left, start), min(right, end)
        if left >= right:
            continue
        if merged and left <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(right, merged[-1][1]))
        else:
            merged.append((left, right))
    gaps, cursor = [], start
    for left, right in merged:
        if cursor < left:
            gaps.append((cursor, left))
        cursor = right
    if cursor < end:
        gaps.append((cursor, end))
    return merged, gaps
