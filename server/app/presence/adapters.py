"""Adapters that feed reviewed detector and health facts into the timeline.

Each adapter maps an already-reviewed producer contract onto the neutral
presence `Observation`. None of them compares biometric data, chooses a
detector threshold, names a person, correlates people across cameras, or
infers cause or guilt. They register no route; the Main runtime wires them to
the producers and drives `TimelineOutbox.flush()` from its own worker.

Deployment timing policy is explicit. There is no default Owner presence
validity or source latency bound: both are Owner/deployment decisions made
after real-room and cross-host clock evaluation.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from typing import Callable
from uuid import UUID

from app.cameras.registry.models import NodeHealthState, SourceHealthState
from app.cameras.uvc.identity import CameraState, HealthEvent
from app.detection.foundation import Quality as DetectionQuality
from app.detection.roi.contracts import CriticalKind, CriticalObservation
from app.detection.tracking.entrance import CrossingKind, TrackUpdate
from app.media.health.service import HealthResult, HealthState
from app.storage.policy import StorageState, StorageTransition

from .models import InvalidObservation, Kind, Observation, Quality, Value, utc


# A main-host wall clock port: returns an aware receipt time and whether the
# deployment currently trusts it (for example, NTP synchronized). The adapters
# never assume a clock is trusted.
MainClock = Callable[[], tuple[datetime, bool]]

OWNER_KINDS = frozenset({CrossingKind.OWNER_ENTRY, CrossingKind.OWNER_EXIT})

_CAMERA = {
    CameraState.ONLINE: Value.ONLINE, CameraState.DEGRADED: Value.DEGRADED,
    CameraState.OFFLINE: Value.OFFLINE, CameraState.MANUAL: Value.MANUAL_INTERVENTION_REQUIRED,
}
_SOURCE = {
    SourceHealthState.ONLINE: Value.ONLINE, SourceHealthState.DEGRADED: Value.DEGRADED,
    SourceHealthState.OFFLINE: Value.OFFLINE,
    SourceHealthState.MANUAL_INTERVENTION_REQUIRED: Value.MANUAL_INTERVENTION_REQUIRED,
}
_NODE = {
    NodeHealthState.ONLINE: Value.ONLINE, NodeHealthState.DEGRADED: Value.DEGRADED,
    NodeHealthState.OFFLINE: Value.OFFLINE, NodeHealthState.REVOKED: Value.REVOKED,
}
_STORAGE = {
    StorageState.NORMAL: Value.READY, StorageState.PRESSURE: Value.DEGRADED,
    StorageState.HARD_STOP: Value.FAILED,
}
_RECORDING = {
    HealthState.OK: Value.READY, HealthState.FAILED: Value.FAILED,
    HealthState.UNAVAILABLE: Value.UNKNOWN,
}
_DETECTION_QUALITY = {
    DetectionQuality.SUFFICIENT: Quality.SUFFICIENT, DetectionQuality.DEGRADED: Quality.INSUFFICIENT,
    DetectionQuality.INSUFFICIENT: Quality.INSUFFICIENT, DetectionQuality.UNKNOWN: Quality.UNKNOWN,
}


def _positive(value, name):
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise ValueError(f"explicit positive {name} required")
    return value


def _stamp(clock):
    received, trusted = clock()
    utc(received)
    if type(trusted) is not bool:
        raise ValueError("explicit clock trust required")
    return received, trusted


def _timely(occurred, received, uncertainty_us, maximum_latency):
    """Deterministic source timing check; a replay reaches the same answer."""
    delay = utc(received) - utc(occurred)
    return (timedelta(0) <= delay <= maximum_latency
            and timedelta(microseconds=uncertainty_us) <= maximum_latency)


@dataclass(frozen=True)
class OutboxState:
    recorded: int
    pending: int
    refused: int
    rejected: int

    @property
    def degraded(self):
        """A refused or rejected fact is a visible gap in the timeline."""
        return bool(self.pending or self.refused or self.rejected)


class TimelineOutbox:
    """Bounded, write-deferred staging between producer callbacks and presence.

    `stage()` never touches the database, so it is safe inside a producer's
    own callback: the storage policy's transition audit runs while that policy
    is refusing admission, and a synchronous presence write from there would
    re-enter the same admission port. `flush()` is driven by the runtime's
    worker and keeps receipt order: the first storage/database failure stops
    the flush and keeps that fact and every later one staged, and a retry
    replays the identical observation, which presence treats as a duplicate.

    A full outbox refuses the new fact and counts it rather than displacing an
    already staged one. A fact the service rejects as a contract error is
    counted and removed so it cannot block every later fact. Both counters make
    the gap visible; neither is silent loss.
    """

    def __init__(self, service, *, capacity: int):
        if type(capacity) is not int or not 1 <= capacity <= 10_000:
            raise ValueError("bounded timeline staging required")
        self.service = service
        self.capacity = capacity
        self._pending = []
        self._lock = threading.Lock()
        self._flushing = threading.Lock()
        self._recorded = self._refused = self._rejected = 0

    def stage(self, observation, *, presence_valid_until=None):
        if not isinstance(observation, Observation):
            raise ValueError("typed observation required")
        if presence_valid_until is not None:
            if observation.kind not in {Kind.OWNER_ENTRY, Kind.OWNER_EXIT}:
                raise ValueError("presence validity applies to owner observations only")
            if utc(presence_valid_until) <= utc(observation.received_at):
                raise ValueError("presence validity must be explicit and future")
        with self._lock:
            if any(item.identifier == observation.identifier for item, _ in self._pending):
                return True
            if len(self._pending) >= self.capacity:
                self._refused += 1
                return False
            self._pending.append((observation, presence_valid_until))
            return True

    def flush(self, *, limit: int = 100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid flush limit")
        # One flusher at a time keeps receipt order; staging stays available.
        with self._flushing:
            for _ in range(limit):
                with self._lock:
                    if not self._pending:
                        break
                    observation, valid_until = self._pending[0]
                try:
                    self.service.record(observation, presence_valid_until=valid_until)
                except (InvalidObservation, ValueError):
                    outcome = "rejected"
                except Exception:
                    # Storage refusal or an unavailable database: keep it and
                    # everything after it for the next flush.
                    break
                else:
                    outcome = "recorded"
                with self._lock:
                    self._pending.pop(0)
                    if outcome == "recorded":
                        self._recorded += 1
                    else:
                        self._rejected += 1
        return self.state()

    def state(self):
        with self._lock:
            return OutboxState(self._recorded, len(self._pending), self._refused, self._rejected)


class EntranceObservationAdapter:
    """Maps #25 `TrackUpdate` crossings to neutral entry/exit observations.

    An Owner crossing keeps its verification confidence and is `confirmed`
    only when the tracker confirmed it and its timing passes the explicit
    latency bound. Every Owner crossing carries the explicit presence validity,
    so an unconfirmed one records the newest Owner evidence as unusable
    (`UNKNOWN`) rather than letting an earlier inference keep applying.
    Anonymous crossings carry no confidence, no identity and no presence
    effect. Low-quality Owner verification never reaches this adapter as an
    Owner crossing: the tracker already reports it as anonymous.
    """

    def __init__(self, outbox: TimelineOutbox, *, owner_presence_validity: timedelta,
                 maximum_source_latency: timedelta):
        self.outbox = outbox
        self.owner_presence_validity = _positive(owner_presence_validity, "owner presence validity")
        self.maximum_source_latency = _positive(maximum_source_latency, "source latency bound")

    def observations(self, update: TrackUpdate):
        if not isinstance(update, TrackUpdate):
            raise ValueError("typed track update required")
        if update.quality is not DetectionQuality.SUFFICIENT:
            if update.crossings:
                raise ValueError("crossings require a sufficient entrance gate")
            # No crossing and no quality is not an absence or presence fact.
            return ()
        result = []
        for crossing in update.crossings:
            if not isinstance(crossing.kind, CrossingKind) or not isinstance(crossing.source_id, UUID):
                raise ValueError("invalid crossing")
            owner = crossing.kind in OWNER_KINDS
            timely = crossing.clock_trusted and _timely(crossing.occurred_at, crossing.received_at,
                                                        crossing.uncertainty_us, self.maximum_source_latency)
            confidence = crossing.confidence if owner else None
            observation = Observation(
                Kind(crossing.kind.value), crossing.occurred_at, crossing.received_at,
                source_id=crossing.source_id, confidence=confidence, quality=Quality.SUFFICIENT,
                clock_trusted=timely, uncertainty_us=crossing.uncertainty_us,
                confirmed=owner and crossing.confirmed and timely and confidence is not None,
                identifier=crossing.identifier)
            valid_until = crossing.received_at + self.owner_presence_validity if owner else None
            result.append((observation, valid_until))
        return tuple(result)

    def submit(self, update: TrackUpdate):
        """Stage every crossing; returns False if the bounded outbox refused any."""
        staged = [self.outbox.stage(item, presence_valid_until=until)
                  for item, until in self.observations(update)]
        return all(staged)


class CriticalTimelineRecorder:
    """`CriticalRecorder` for #24 `CriticalDelivery`, backed by PresenceService.

    It records synchronously and raises on any failure, so the finite staging
    in `CriticalDelivery` keeps the UUID and retries it. The main-host receipt
    time is stamped once per UUID and reused on every retry, so a retried
    observation is byte-identical and presence reports it as a duplicate
    instead of an identity conflict. The stamps of the most recent accepted
    UUIDs are kept too (bounded by `capacity`), so a repeated delivery of an
    already accepted observation stays a duplicate; one older than that is
    refused as an identity conflict rather than queuing critical work twice.
    Clock distrust or excessive source latency
    marks the timing untrusted but never withdraws confirmation: critical
    evidence and notification work is queued in every presence and clock
    state.
    """

    def __init__(self, service, *, clock: MainClock, maximum_source_latency: timedelta,
                 capacity: int):
        if type(capacity) is not int or not 1 <= capacity <= 10_000:
            raise ValueError("bounded receipt memo required")
        self.service = service
        self.clock = clock
        self.maximum_source_latency = _positive(maximum_source_latency, "source latency bound")
        self.capacity = capacity
        self._receipts = {}
        self._accepted = {}
        self._lock = threading.Lock()

    def observation(self, item: CriticalObservation):
        if not isinstance(item, CriticalObservation) or not isinstance(item.kind, CriticalKind):
            raise ValueError("typed critical observation required")
        quality = _DETECTION_QUALITY.get(item.quality)
        if not item.confirmed or quality is not Quality.SUFFICIENT:
            raise ValueError("confirmed critical observation with sufficient quality required")
        with self._lock:
            receipt = self._receipts.get(item.identifier) or self._accepted.get(item.identifier)
            if receipt is None:
                if len(self._receipts) >= self.capacity:
                    raise BufferError("critical receipt memo is full")
                receipt = self._receipts[item.identifier] = _stamp(self.clock)
        received, trusted = receipt
        timely = trusted and _timely(item.observed_at, received, 0, self.maximum_source_latency)
        return Observation(Kind(item.kind.value), item.observed_at, received,
                           source_id=item.source_id, confidence=item.confidence, quality=quality,
                           clock_trusted=timely, confirmed=True, identifier=item.identifier)

    def __call__(self, item: CriticalObservation) -> None:
        self.service.record(self.observation(item))
        with self._lock:
            receipt = self._receipts.pop(item.identifier, None)
            if receipt is not None:
                self._accepted[item.identifier] = receipt
                while len(self._accepted) > self.capacity:
                    del self._accepted[next(iter(self._accepted))]


class HealthTimeline:
    """Source, node, storage and recording health producers as timeline facts.

    Every method only stages, so it can be passed directly as a producer
    callback: `camera` for the UVC `ReconnectController` emit, `storage` for
    the `MainStoragePolicy` transition audit and `recording` for a
    `RecordingHealthService` result recorder composed with the durable UI
    recorder. Health facts carry attribution and state only; free-form reasons,
    device evidence and storage figures are not copied into the timeline.
    """

    def __init__(self, outbox: TimelineOutbox, *, clock: MainClock):
        self.outbox = outbox
        self.clock = clock

    def _stage(self, kind, value, **attribution):
        received, trusted = _stamp(self.clock)
        return self.outbox.stage(Observation(kind, received, received, value=value,
                                             clock_trusted=trusted, **attribution))

    def camera(self, event: HealthEvent):
        if not isinstance(event, HealthEvent) or not isinstance(event.state, CameraState) \
                or event.state not in _CAMERA:
            raise ValueError("typed camera health event required")
        return self._stage(Kind.CAMERA_HEALTH, _CAMERA[event.state], source_id=event.source_id)

    def source(self, source_id: UUID, state: SourceHealthState, *, node_id: UUID | None = None):
        if not isinstance(state, SourceHealthState) or state not in _SOURCE:
            raise ValueError("typed source health state required")
        return self._stage(Kind.CAMERA_HEALTH, _SOURCE[state], source_id=source_id, node_id=node_id)

    def node(self, node_id: UUID, state: NodeHealthState):
        if not isinstance(state, NodeHealthState) or state not in _NODE:
            raise ValueError("typed node health state required")
        return self._stage(Kind.NODE_HEALTH, _NODE[state], node_id=node_id)

    def storage(self, transition: StorageTransition):
        # `at_ms` is the policy's monotonic clock, not wall time, so the
        # main-host receipt clock provides the timeline timestamp.
        if not isinstance(transition, StorageTransition) or not isinstance(transition.current, StorageState) \
                or transition.current not in _STORAGE:
            raise ValueError("typed storage transition required")
        return self._stage(Kind.STORAGE, _STORAGE[transition.current])

    def recording(self, result: HealthResult, at: datetime | None = None):
        # `at` keeps the `record_result(result, at)` signature; the timeline
        # uses the same main-host receipt clock as every other health fact.
        if not isinstance(result, HealthResult) or not isinstance(result.state, HealthState) \
                or result.state not in _RECORDING:
            raise ValueError("typed recording health result required")
        return self._stage(Kind.RECORDING, _RECORDING[result.state])
