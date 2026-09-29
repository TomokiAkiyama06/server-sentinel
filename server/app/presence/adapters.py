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

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from typing import Callable
from uuid import UUID, uuid4

from app.cameras.registry.models import NodeHealthState, SourceHealthState
from app.cameras.uvc.identity import CameraState, HealthEvent
from app.detection.foundation import Quality as DetectionQuality
from app.detection.roi.contracts import CriticalKind, CriticalObservation
from app.detection.tracking.entrance import Crossing, CrossingKind, TrackUpdate
from app.media.health.service import HealthResult, HealthState
from app.storage.policy import StorageState, StorageTransition

from .models import CRITICAL, InvalidObservation, Kind, Observation, Quality, Value, utc
from .service import RECEIPT_FIELDS


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


def _fact(observation):
    """The source fact of an observation, without the fields stamped at receipt."""
    return {key: value for key, value in observation.payload().items() if key not in RECEIPT_FIELDS}


def _positive(value, name):
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise ValueError(f"explicit positive {name} required")
    return value


class ClockUnavailable(RuntimeError):
    """The main-host clock port returned no usable receipt; retryable."""


def _stamp(clock):
    # A clock-port fault is infrastructure, never an observation contract
    # error, so it must not surface as `InvalidObservation` and be dropped.
    try:
        received, trusted = clock()
    except Exception:
        # A raising or malformed clock port is the same retryable fault.
        raise ClockUnavailable("main-host clock unavailable") from None
    try:
        utc(received)
    except InvalidObservation:
        raise ClockUnavailable("aware main-host receipt time required") from None
    if type(trusted) is not bool:
        raise ClockUnavailable("explicit clock trust required")
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
    # Refused or rejected facts counted in memory but not yet in the durable
    # timeline gap marker.
    unpersisted: int = 0
    # Whether this outbox holds an open durable session.
    session: bool = False
    # The durable gap marker as last read: True, False, or None when unknown.
    gap: bool | None = None

    @property
    def degraded(self):
        """Any pending, unpersisted, durable or unknown loss is a visible gap.

        The durable marker is the source of truth across restarts: it stays
        set until the Owner clears it, and an outbox with no open session or an
        unreadable marker never reports healthy.
        """
        # Persisted refused/rejected counts live in the durable marker, so
        # an Owner clear of that marker is what returns the outbox to healthy.
        return bool(self.pending or self.unpersisted or not self.session or self.gap is not False)


# Builds the observation for one staged fact from the main-host receipt taken
# at write time; returns it together with its Owner presence validity or None.
Build = Callable[[datetime, bool], tuple[Observation, datetime | None]]


class TimelineOutbox:
    """Bounded, write-deferred staging and the single main-host receipt clock.

    `PresenceService` treats a receipt time older than the newest one it has
    written as a clock step and marks it untrusted, which makes an Owner
    observation `UNKNOWN`. Receipt time is therefore stamped at write time,
    under one lock held across the write it dates, and that lock is shared
    with `CriticalTimelineRecorder`: a fact staged before a later-stamped fact
    was written, or before a critical observation was recorded directly, never
    looks like a clock step. Staging time is not receipt time; every producer
    keeps its own `occurred_at`.

    `stage()` never touches the database or the receipt lock, so it is safe
    inside a producer's own callback: the storage policy's transition audit
    runs while that policy is refusing admission, and a synchronous presence
    write from there would re-enter the same admission port. `flush()` is
    driven by the runtime's worker and keeps staging order: the first storage,
    database or clock failure stops the flush and keeps that fact and every
    later one staged. A retry is stamped again, which is safe because the
    failed write was rolled back; a write that committed before failing is a
    duplicate by its UUID (`restamped`).

    A full outbox refuses the new fact and counts it rather than displacing an
    already staged one. Only a fact presence rejects as a contract error
    (`InvalidObservation`) is counted and removed, so it cannot block every
    later fact; an unavailable database location stays staged. Staging a UUID
    that is already pending is a duplicate only when its source fact matches
    the staged one; a different fact under that UUID is an identity conflict,
    refused and counted as rejected just as presence would reject it. Both
    counters make the gap visible; neither is silent loss.

    Loss is also durable. `open()` establishes a durable outbox session at
    startup and `stage()` refuses facts until it has, so no fact is ever held
    without a session row that a restart would find. Every flush adds the
    refused and rejected counts to the presence timeline gap marker. `close()` records any still-staged facts as lost and ends the
    session; a process that exits without a successful close leaves the
    session row behind, so the next start records an interrupted gap. The
    session is exclusive per database (see `open_timeline_session()`), and a
    clock fault while a fact is handed over is counted as refused. The
    marker is cleared only by the Owner (`PresenceService.clear_timeline_gap`),
    and while it is set, or cannot be read, `OutboxState.degraded` stays true.
    Staged facts themselves are not recovered after a restart. The runtime
    stops its producers before `close()`; staging after close raises.
    """

    def __init__(self, service, *, clock: MainClock, capacity: int):
        if type(capacity) is not int or not 1 <= capacity <= 10_000:
            raise ValueError("bounded timeline staging required")
        if not callable(clock):
            raise ValueError("explicit main clock required")
        self.service = service
        self.clock = clock
        self.capacity = capacity
        self._pending = []
        self._lock = threading.Lock()
        self._flushing = threading.Lock()
        self._receipt = threading.RLock()
        self._recorded = self._refused = self._rejected = 0
        self._unpersisted_refused = self._unpersisted_rejected = 0
        self._session = False
        # The durable session and its lock, from `open_timeline_session()`.
        self._handle = None
        self._closed = False
        self._gap = None

    @contextmanager
    def receipt(self):
        """Stamp a main-host receipt and hold it across the write it dates."""
        with self._receipt:
            yield _stamp(self.clock)

    def stage(self, identifier: UUID, build: Build):
        """Stage one fact; its contract is checked now against the current clock."""
        if not isinstance(identifier, UUID) or not callable(build):
            raise ValueError("typed staged fact required")
        self._accepting()
        try:
            stamp = _stamp(self.clock)
        except ClockUnavailable:
            # The fact cannot be dated or checked now; count it as a refused
            # handoff so the loss reaches the durable gap marker.
            return self._refuse()
        observation, valid_until = build(*stamp)
        if not isinstance(observation, Observation) or observation.identifier != identifier:
            raise ValueError("typed observation required")
        if observation.kind in CRITICAL:
            # Critical work is recorded synchronously by CriticalTimelineRecorder.
            raise ValueError("critical observations are recorded, not staged")
        if valid_until is not None and observation.kind not in {Kind.OWNER_ENTRY, Kind.OWNER_EXIT}:
            raise ValueError("presence validity applies to owner observations only")
        fact = _fact(observation)
        with self._lock:
            self._accepting_locked()
            for item, _, staged in self._pending:
                if item == identifier:
                    if staged == fact:
                        return True
                    # Same UUID, different source fact: never deduplicated.
                    self._rejected += 1
                    self._unpersisted_rejected += 1
                    return False
            if len(self._pending) >= self.capacity:
                self._refused += 1
                self._unpersisted_refused += 1
                return False
            self._pending.append((identifier, build, fact))
            return True

    def flush(self, *, limit: int = 100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid flush limit")
        # One flusher at a time keeps staging order; staging stays available.
        with self._flushing:
            if self._closed:
                raise RuntimeError("timeline outbox closed")
            if not self._open():
                # Without a durable session a later loss could not be proven
                # on restart, so nothing is written and every fact stays staged.
                return self.state()
            for _ in range(limit):
                with self._lock:
                    if not self._pending:
                        break
                    _, build, _ = self._pending[0]
                try:
                    with self.receipt() as (received, trusted):
                        observation, valid_until = build(received, trusted)
                        self.service.record(observation, presence_valid_until=valid_until, restamped=True)
                except InvalidObservation:
                    outcome = "rejected"
                except Exception:
                    # Storage refusal, an unavailable database or clock: keep
                    # it and everything after it for the next flush.
                    break
                else:
                    outcome = "recorded"
                with self._lock:
                    self._pending.pop(0)
                    if outcome == "recorded":
                        self._recorded += 1
                    else:
                        self._rejected += 1
                        self._unpersisted_rejected += 1
            try:
                self._persist()
            except Exception:
                # Counts stay unpersisted and are retried by the next flush;
                # the open session row keeps a restart from looking clean.
                pass
        return self.state()

    def _accepting_locked(self):
        if self._closed:
            raise RuntimeError("timeline outbox closed")
        if not self._session:
            # Without a durable session a restart before the first write
            # would lose this fact with no trace, so nothing is accepted.
            raise RuntimeError("timeline outbox not open")

    def _accepting(self):
        with self._lock:
            self._accepting_locked()

    def _refuse(self):
        """Count a fact that could not be staged as a refused, visible gap."""
        with self._lock:
            self._accepting_locked()
            self._refused += 1
            self._unpersisted_refused += 1
        return False

    def open(self):
        """Open the durable session at startup, before any producer is wired.

        `stage()` refuses facts until this succeeds, so a fact is never held
        in memory without a session row that a restart would find. Raises when
        the session cannot be opened; the runtime retries before wiring
        producers. Opening an already open outbox is a no-op.
        """
        with self._flushing:
            if self._closed:
                raise RuntimeError("timeline outbox closed")
            self._open(strict=True)
        return self.state()

    def _open(self, *, strict=False):
        """Open the durable session once; False (retried later) on any failure."""
        if self._session:
            return True
        try:
            now, _ = _stamp(self.clock)
            session, gap = self.service.open_timeline_session(now=now)
        except Exception:
            if strict:
                raise
            return False
        session.unpersisted = self._unpersisted
        session.backlog = self._backlog
        with self._lock:
            self._handle = session
            self._session, self._gap = True, gap is not None
        return True

    def _unpersisted(self):
        """Counted loss not yet in the durable marker; read by Owner status."""
        with self._lock:
            return self._unpersisted_refused + self._unpersisted_rejected

    def _backlog(self):
        """Staged facts and unpersisted loss, read together for Owner status."""
        with self._lock:
            return len(self._pending), self._unpersisted_refused + self._unpersisted_rejected

    def _persist(self, *, lost=0, close=False):
        """Add unpersisted counts to the durable marker, or re-read it."""
        with self._lock:
            refused, rejected = self._unpersisted_refused, self._unpersisted_rejected
        if not (refused or rejected or lost or close):
            try:
                gap = self.service.timeline_gap() is not None
            except Exception:
                gap = None
            with self._lock:
                self._gap = gap
            return
        now, _ = _stamp(self.clock)
        gap = self.service.record_timeline_gap(now=now, refused=refused, rejected=rejected,
                                               lost=lost, close=self._handle if close else None)
        with self._lock:
            # Subtract what was written; facts refused meanwhile stay counted.
            # The durable marker is published in the same critical section,
            # so `state()` never sees the loss in neither place.
            self._unpersisted_refused -= refused
            self._unpersisted_rejected -= rejected
            self._gap = gap is not None

    def close(self):
        """End the durable session cleanly, recording still-staged facts as lost.

        Raises when the close cannot be persisted. The session row then stays,
        so the next start records an interrupted gap, and this outbox remains
        open for a retry.
        """
        with self._flushing:
            with self._lock:
                closed = self._closed
            if closed:
                # Repeated close is idempotent; `state()` takes the lock itself.
                return self.state()
            with self._lock:
                # Staging stops before the durable write; a producer staging
                # after this point gets an error rather than silent loss.
                self._closed = True
                lost = len(self._pending)
            try:
                if not self._open():
                    raise RuntimeError("timeline outbox session unavailable")
                self._persist(lost=lost, close=True)
            except BaseException:
                with self._lock:
                    self._closed = False
                raise
            self._session, self._handle = False, None
            return self.state()

    def state(self):
        with self._lock:
            return OutboxState(self._recorded, len(self._pending), self._refused, self._rejected,
                               self._unpersisted_refused + self._unpersisted_rejected,
                               self._session, self._gap)


class EntranceObservationAdapter:
    """Maps #25 `TrackUpdate` crossings to neutral entry/exit observations.

    An Owner crossing keeps its verification confidence and is `confirmed`
    only when the tracker confirmed it and its source timing stays within the
    explicit latency bound up to the main-host receipt at write time, so a
    crossing held back by a refused volume cannot confirm presence late. Every
    Owner crossing carries the explicit presence validity from that receipt,
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

    def crossings(self, update: TrackUpdate):
        """The crossings of a sufficient update; an `UNKNOWN` update has none."""
        if not isinstance(update, TrackUpdate):
            raise ValueError("typed track update required")
        if update.quality is not DetectionQuality.SUFFICIENT:
            if update.crossings:
                raise ValueError("crossings require a sufficient entrance gate")
            # No crossing and no quality is not an absence or presence fact.
            return ()
        for crossing in update.crossings:
            if (not isinstance(crossing, Crossing) or not isinstance(crossing.kind, CrossingKind)
                    or not isinstance(crossing.source_id, UUID)):
                raise ValueError("invalid crossing")
        return update.crossings

    def observation(self, crossing: Crossing, received: datetime, trusted: bool):
        owner = crossing.kind in OWNER_KINDS
        timely = (trusted and crossing.clock_trusted
                  and _timely(crossing.occurred_at, crossing.received_at, crossing.uncertainty_us,
                              self.maximum_source_latency)
                  and _timely(crossing.occurred_at, received, crossing.uncertainty_us,
                              self.maximum_source_latency))
        confidence = crossing.confidence if owner else None
        observation = Observation(
            Kind(crossing.kind.value), crossing.occurred_at, received,
            source_id=crossing.source_id, confidence=confidence, quality=Quality.SUFFICIENT,
            clock_trusted=timely, uncertainty_us=crossing.uncertainty_us,
            confirmed=owner and crossing.confirmed and timely and confidence is not None,
            identifier=crossing.identifier)
        return observation, (received + self.owner_presence_validity if owner else None)

    def submit(self, update: TrackUpdate):
        """Stage every crossing; returns False if the bounded outbox refused any."""
        staged = [self.outbox.stage(crossing.identifier,
                                    lambda received, trusted, crossing=crossing:
                                    self.observation(crossing, received, trusted))
                  for crossing in self.crossings(update)]
        return all(staged)


class CriticalTimelineRecorder:
    """`CriticalRecorder` for #24 `CriticalDelivery`, backed by PresenceService.

    It records synchronously and raises on any failure, so the finite staging
    in `CriticalDelivery` keeps the UUID and retries it. The main-host receipt
    comes from the shared `TimelineOutbox.receipt()` at write time. Replaying
    an already recorded UUID, whether a retry after a write that committed and
    then failed, a repeated delivery or a replay after a restart, is a
    duplicate by the durable row rather than by an in-memory cache
    (`restamped`), so it never queues critical work twice and never becomes a
    permanent identity conflict that would exhaust `CriticalDelivery`.
    Clock distrust or excessive source latency marks the timing untrusted but
    never withdraws confirmation: critical evidence and notification work is
    queued in every presence and clock state.
    """

    def __init__(self, outbox: TimelineOutbox, *, maximum_source_latency: timedelta):
        if not isinstance(outbox, TimelineOutbox):
            raise ValueError("shared timeline receipt clock required")
        self.outbox = outbox
        self.maximum_source_latency = _positive(maximum_source_latency, "source latency bound")

    @staticmethod
    def _quality(item):
        if not isinstance(item, CriticalObservation) or not isinstance(item.kind, CriticalKind):
            raise ValueError("typed critical observation required")
        quality = _DETECTION_QUALITY.get(item.quality)
        if not item.confirmed or quality is not Quality.SUFFICIENT:
            raise ValueError("confirmed critical observation with sufficient quality required")
        return quality

    def observation(self, item: CriticalObservation, received: datetime, trusted: bool):
        quality = self._quality(item)
        timely = trusted and _timely(item.observed_at, received, 0, self.maximum_source_latency)
        return Observation(Kind(item.kind.value), item.observed_at, received,
                           source_id=item.source_id, confidence=item.confidence, quality=quality,
                           clock_trusted=timely, confirmed=True, identifier=item.identifier)

    def __call__(self, item: CriticalObservation) -> None:
        self._quality(item)
        with self.outbox.receipt() as (received, trusted):
            self.outbox.service.record(self.observation(item, received, trusted), restamped=True)


class HealthTimeline:
    """Source, node, storage and recording health producers as timeline facts.

    Every method only stages, so it can be passed directly as a producer
    callback: `camera` for the UVC `ReconnectController` emit, `storage` for
    the `MainStoragePolicy` transition audit and `recording` for a
    `RecordingHealthService` result recorder composed with the durable UI
    recorder. A fact is dated by the main clock when its producer reports it
    and received by presence at write time. Health facts carry attribution and
    state only; free-form reasons, device evidence and storage figures are not
    copied into the timeline.
    """

    def __init__(self, outbox: TimelineOutbox):
        self.outbox = outbox

    def _stage(self, kind, value, **attribution):
        try:
            occurred, occurred_trusted = _stamp(self.outbox.clock)
        except ClockUnavailable:
            # A one-shot producer callback will not re-emit this transition,
            # so a clock fault here is a counted gap, never silent loss.
            return self.outbox._refuse()
        identifier = uuid4()

        def build(received, trusted):
            ordered = utc(occurred) <= utc(received)
            return Observation(kind, occurred, received, value=value, identifier=identifier,
                               clock_trusted=occurred_trusted and trusted and ordered,
                               **attribution), None
        return self.outbox.stage(identifier, build)

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
        # main-host clock provides the timeline timestamp.
        if not isinstance(transition, StorageTransition) or not isinstance(transition.current, StorageState) \
                or transition.current not in _STORAGE:
            raise ValueError("typed storage transition required")
        return self._stage(Kind.STORAGE, _STORAGE[transition.current])

    def recording(self, result: HealthResult, at: datetime | None = None):
        # `at` keeps the `record_result(result, at)` signature; the timeline
        # uses the same main-host clock as every other health fact.
        if not isinstance(result, HealthResult) or not isinstance(result.state, HealthState) \
                or result.state not in _RECORDING:
            raise ValueError("typed recording health result required")
        return self._stage(Kind.RECORDING, _RECORDING[result.state])
