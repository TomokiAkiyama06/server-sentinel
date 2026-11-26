"""Constant-rate frame slots for fixed-duration recording segments (Issue #16).

The ring stores segments of one fixed duration whose byte size is bounded by
the profile's maximum bitrate (``ring_models.SegmentProfile``). A camera does
not deliver frames on an exact grid: a USB camera's MJPG rate drifts, skips
and bunches. ``FramePacer`` maps the frames it is offered onto a fixed slot
grid (``origin_us + index * period_us``), the same way a ``videorate`` element
would: each slot gets the newest frame captured at or before the slot time,
so a missing frame repeats the previous one and surplus frames are dropped.
The encoder then sees exactly ``fps * segment seconds`` pictures per segment,
which fixes the segment's sample count and duration and lets every segment
start with an IDR picture (GOP size dividing the slot count).

A slot whose newest frame is older than ``max_hold_us`` is a gap: the pacer
never stretches one picture over a real interruption. Consecutive gap slots
are returned as one ``PacedGap`` range, so a clock jump or a long outage
yields a bounded result. Repeats and drops are counted for status reporting.

Times are integer microseconds of one monotonic clock and must not decrease.
A slot is decided only when a later frame or ``advance(now_us)`` proves that
no frame captured at or before the slot time can still arrive; the caller
passes ``now_us`` minus its delivery latency allowance to ``advance``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class PacedFrame(Generic[T]):
    index: int
    item: T = field(repr=False)
    repeated: bool


@dataclass(frozen=True)
class PacedGap:
    start: int  # first gap slot index
    stop: int   # one past the last gap slot index


def _microseconds(value, name):
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer number of microseconds")
    return value


class FramePacer(Generic[T]):
    def __init__(self, *, origin_us: int, period_us: int, max_hold_us: int):
        _microseconds(origin_us, "origin_us")
        if _microseconds(period_us, "period_us") < 1:
            raise ValueError("period_us must be positive")
        if _microseconds(max_hold_us, "max_hold_us") < 0:
            raise ValueError("max_hold_us must not be negative")
        self.origin_us = origin_us
        self.period_us = period_us
        self.max_hold_us = max_hold_us
        self.next_index = 0
        self._last: tuple[int, T] | None = None
        self._last_used = False
        self._latest_time: int | None = None
        self.repeated = 0
        self.dropped = 0

    def slot_time(self, index: int) -> int:
        return self.origin_us + index * self.period_us

    def offer(self, captured_us: int, item: T) -> list:
        """Offer one frame; return the slots this frame's time decides."""
        _microseconds(captured_us, "captured_us")
        if self._latest_time is not None and captured_us < self._latest_time:
            raise ValueError("frame times must not decrease")
        self._latest_time = captured_us
        out: list = []
        # Slots strictly before this frame take the previous frame.
        self._decide_through(captured_us - 1, out)
        if self._last is not None and not self._last_used:
            self.dropped += 1
        self._last, self._last_used = (captured_us, item), False
        # A slot at exactly this frame's time takes this frame.
        self._decide_through(captured_us, out)
        return out

    def advance(self, now_us: int) -> list:
        """Decide every slot at or before ``now_us`` with the frames seen so far.

        Slots before the newest offered frame are already decided, so an
        older ``now_us`` (for example ``now`` minus a latency allowance)
        decides nothing.
        """
        _microseconds(now_us, "now_us")
        out: list = []
        self._decide_through(now_us, out)
        return out

    def _decide_through(self, limit_us: int, out: list) -> None:
        if limit_us < self.slot_time(self.next_index):
            return
        last_slot = (limit_us - self.origin_us) // self.period_us
        # The held frame can fill slots up to ``held_until``; every later slot
        # up to ``last_slot`` is a gap until a newer frame is offered.
        held_until = (-1 if self._last is None
                      else (self._last[0] + self.max_hold_us - self.origin_us) // self.period_us)
        while self.next_index <= last_slot:
            index = self.next_index
            if index > held_until:
                out.append(PacedGap(index, last_slot + 1))
                self.next_index = last_slot + 1
                return
            repeated = self._last_used
            if repeated:
                self.repeated += 1
            self._last_used = True
            out.append(PacedFrame(index, self._last[1], repeated))
            self.next_index = index + 1
