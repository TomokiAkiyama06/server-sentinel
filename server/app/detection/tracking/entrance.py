"""Conservative geometric association and finite directed-line crossings.

There are no filesystem/network calls, images, embeddings or person names in
this state. Ambiguous associations start new tracks rather than transferring
an identity, and stream/quality discontinuities discard crossing continuity.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4
import math

from app.detection.foundation import Detection, Observation, Quality, Reason
from app.detection.owner.contracts import Verdict, Verification
from app.detection.quality import Execution, FrameIdentity, QualityDecision, QualityGate


def _fraction(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


@dataclass(frozen=True)
class Point:
    x: float
    y: float

    def __post_init__(self):
        if not _fraction(self.x) or not _fraction(self.y):
            raise ValueError("INVALID_TRACK_POINT")


@dataclass(frozen=True)
class PersonPoint:
    candidate_id: UUID
    point: Point

    def __post_init__(self):
        if not isinstance(self.candidate_id, UUID) or not isinstance(self.point, Point):
            raise ValueError("INVALID_TRACK_CANDIDATE")


@dataclass(frozen=True)
class TrackingPolicy:
    max_tracks: int
    max_gap_ms: int
    max_distance: float

    def __post_init__(self):
        if (type(self.max_tracks) is not int or not 1 <= self.max_tracks <= 256
                or type(self.max_gap_ms) is not int or self.max_gap_ms <= 0
                or not _fraction(self.max_distance) or self.max_distance <= 0):
            raise ValueError("INVALID_TRACKING_POLICY")


@dataclass(frozen=True)
class EntranceLine:
    start: Point
    end: Point
    entry_direction: int
    hysteresis_distance: float

    def __post_init__(self):
        if (not isinstance(self.start, Point) or not isinstance(self.end, Point) or self.start == self.end
                or type(self.entry_direction) is not int or self.entry_direction not in (-1, 1)
                or not _fraction(self.hysteresis_distance)):
            raise ValueError("INVALID_ENTRANCE_GEOMETRY")

    def distance(self, point):
        dx, dy = self.end.x - self.start.x, self.end.y - self.start.y
        return (dx * (point.y - self.start.y) - dy * (point.x - self.start.x)) / math.hypot(dx, dy)

    def settled_side(self, point):
        distance = self.distance(point)
        return (1 if distance > 0 else -1) if abs(distance) > self.hysteresis_distance else 0

    def intersects(self, previous, current):
        before, after = self.distance(previous), self.distance(current)
        if before == after or before * after > 0:
            return False
        ratio = before / (before - after)
        x = previous.x + ratio * (current.x - previous.x)
        y = previous.y + ratio * (current.y - previous.y)
        dx, dy = self.end.x - self.start.x, self.end.y - self.start.y
        projection = ((x - self.start.x) * dx + (y - self.start.y) * dy) / (dx * dx + dy * dy)
        return 0 <= ratio <= 1 and 0 <= projection <= 1


class CrossingKind(StrEnum):
    OWNER_ENTRY = "owner_entry"
    OWNER_EXIT = "owner_exit"
    ANONYMOUS_ENTRY = "anonymous_entry"
    ANONYMOUS_EXIT = "anonymous_exit"


@dataclass(frozen=True)
class Crossing:
    identifier: UUID
    kind: CrossingKind
    source_id: UUID
    occurred_at: datetime
    received_at: datetime
    confidence: float | None
    clock_trusted: bool
    uncertainty_us: int
    confirmed: bool


@dataclass
class _Track:
    identifier: UUID
    point: Point
    last_ms: int
    sequence: int
    side: int
    crossed: bool = False


@dataclass(frozen=True)
class TrackUpdate:
    # IDs are ephemeral internal correlation only, not exported to #26.
    assignments: tuple[tuple[UUID, UUID], ...] = field(repr=False)
    crossings: tuple[Crossing, ...]
    quality: Quality


class AnonymousEntranceTracker:
    def __init__(self, source_id: UUID, policy: TrackingPolicy, line: EntranceLine):
        if not isinstance(source_id, UUID):
            raise ValueError("INVALID_TRACK_SOURCE")
        if not isinstance(policy, TrackingPolicy) or not isinstance(line, EntranceLine):
            raise ValueError("INVALID_TRACK_CONFIGURATION")
        self._source_id = source_id
        self._policy = policy
        self._line = line
        self._tracks = {}
        self._stream = None
        self._sequence = -1
        self._last_ms = None

    @property
    def source_id(self):
        return self._source_id

    @property
    def policy(self):
        return self._policy

    @property
    def line(self):
        return self._line

    def close(self):
        self._tracks.clear()
        self._stream = None
        self._sequence = -1
        self._last_ms = None

    def update(self, frame: FrameIdentity, points: tuple[PersonPoint, ...], *, gate, decision,
               observed_ms: int, occurred_at: datetime, received_at: datetime,
               clock_trusted: bool, uncertainty_us: int, owner_results: tuple[Verification, ...] = (),
               owner_verifier=None) -> TrackUpdate:
        if (not isinstance(frame, FrameIdentity) or frame.source_id != self.source_id
                or type(observed_ms) is not int or observed_ms < 0
                or type(clock_trusted) is not bool or type(uncertainty_us) is not int or uncertainty_us < 0
                or any(not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None
                       for at in (occurred_at, received_at))
                or type(points) is not tuple or any(not isinstance(point, PersonPoint) for point in points)
                or len({point.candidate_id for point in points}) != len(points)):
            raise ValueError("INVALID_TRACK_OBSERVATION")
        if len(points) > self.policy.max_tracks:
            self.close()
            raise ValueError("TRACKING_RESOURCE_LIMIT")
        if (not isinstance(gate, QualityGate) or not isinstance(decision, QualityDecision)
                or gate.source_id != self.source_id or gate.policy.detector != "entrance_crossing"
                or gate.guard_result(decision, Detection(Observation.PRESENT, Reason.EVALUATED),
                                     execution=Execution.SUCCEEDED, frame=frame).observation is not Observation.PRESENT):
            self.close()
            return TrackUpdate((), (), Quality.UNKNOWN)
        if self._stream != frame.stream_id:
            self.close()
            self._stream = frame.stream_id
        if frame.sequence <= self._sequence or (self._last_ms is not None and observed_ms < self._last_ms):
            self.close()
            return TrackUpdate((), (), Quality.UNKNOWN)
        self._sequence, self._last_ms = frame.sequence, observed_ms
        self._tracks = {key: track for key, track in self._tracks.items()
                        if observed_ms - track.last_ms <= self.policy.max_gap_ms}
        possibilities = {}
        reverse = {}
        for index, point in enumerate(points):
            candidates = []
            for key, track in self._tracks.items():
                if math.hypot(point.point.x - track.point.x, point.point.y - track.point.y) <= self.policy.max_distance:
                    candidates.append(key)
                    reverse.setdefault(key, []).append(index)
            possibilities[index] = candidates
        assignments, crossings, next_tracks = [], [], {}
        for index, point in enumerate(points):
            candidates = possibilities[index]
            key = candidates[0] if len(candidates) == 1 and len(reverse[candidates[0]]) == 1 else None
            if key is None:
                key = uuid4()
                track = _Track(key, point.point, observed_ms, frame.sequence, self.line.settled_side(point.point))
            else:
                track = self._tracks[key]
                crossing = self._advance(track, point.point, observed_ms, frame.sequence)
                if crossing:
                    owner = self._owner(point, frame, owner_results, owner_verifier)
                    entry = crossing == self.line.entry_direction
                    kind = (CrossingKind.OWNER_ENTRY if entry else CrossingKind.OWNER_EXIT) if owner else (
                        CrossingKind.ANONYMOUS_ENTRY if entry else CrossingKind.ANONYMOUS_EXIT)
                    crossings.append(Crossing(uuid4(), kind, self.source_id, occurred_at, received_at,
                                              owner.confidence if owner else None, clock_trusted, uncertainty_us,
                                              bool(owner) and clock_trusted))
            next_tracks[key] = track
            assignments.append((point.candidate_id, key))
        # Unmatched/ambiguous tracks are immediately forgotten; this conservative
        # implementation does not extrapolate across unseen people or occlusion.
        self._tracks = next_tracks
        return TrackUpdate(tuple(assignments), tuple(crossings), Quality.SUFFICIENT)

    def _advance(self, track, point, observed_ms, sequence):
        side = self.line.settled_side(point)
        crossing = 0
        if sequence != track.sequence + 1:
            track.side, track.crossed = side, False
        else:
            before, after = self.line.distance(track.point), self.line.distance(point)
            if before != after and before * after <= 0 and after != 0:
                # Retain only the latest directed crossing. Reversing through
                # the deadband or crossing outside the finite segment cancels
                # prior evidence, even before a settled side is reached.
                track.crossed = self.line.intersects(track.point, point) and (1 if after > 0 else -1) != track.side
            if side and track.side and side != track.side:
                if track.crossed:
                    crossing = side
                track.side, track.crossed = side, False
            elif side and side == track.side:
                track.crossed = False
            elif side and not track.side:
                track.side, track.crossed = side, False
        track.point, track.last_ms, track.sequence = point, observed_ms, sequence
        return crossing

    @staticmethod
    def _owner(point, frame, results, verifier):
        if verifier is None:
            return None
        try:
            matches = [result for result in results if isinstance(result, Verification)
                       and result.candidate_id == point.candidate_id and result.frame == frame
                       and result.verdict is Verdict.MATCH and verifier.is_current(result)]
        except Exception:
            return None
        return matches[0] if len(matches) == 1 else None
