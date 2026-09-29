"""Transport-neutral session and media-continuity tracking for Agent ingest.

This module opens no socket, performs no cryptography, and selects no media
transport (ADR-0007 keeps that decision open until real-LAN measurement).  A
future dedicated ingest listener must first authenticate the peer with the
revocable mTLS identity from ADR-0006 and only then call ``open_session`` with
that authenticated node identity.  Human/dashboard routes never use this
boundary and an Agent session grants no human or administrative right.

Every media unit carries a transport-independent header:
``(source_id, capture_epoch, sequence, capture_time_ns)``.  ``capture_epoch``
is an Agent-maintained, strictly increasing capture-process epoch; ``sequence``
counts units per source within one epoch; ``capture_time_ns`` is the Agent's
monotonic capture clock within that epoch.  The Main Server never compares the
Agent clock with its own clock here.  Because the sequence survives a transport
reconnect, a reconnect that lost media yields an exact missing-unit count, and
a reconnect that lost nothing yields no gap.

A unit is committed only after the bounded ingest queue accepts it.  A
backpressure/rate refusal leaves continuity unchanged so the Agent retries the
same sequence from its disk ring buffer; a retry of an already committed unit
is reported as ``duplicate`` and never enqueued twice.  Known loss is recorded
as a bounded gap event and keeps the source ``degraded`` until a consumer
drains it; it is never reported as a healthy flow.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Callable
from uuid import UUID

from app.cameras.remote_agent.ingest import (
    AgentAction, AgentIngestQueue, AgentMessage, IngestAuthorizer, IngestOutcome,
)

_MAXIMUM_COUNTER = 2 ** 63 - 1
# Only an ingest refusal that no retry of the same unit can ever satisfy is
# committed past as known loss.  Any other refusal (for example the ingest
# boundary's fail-closed Main clock regression) is transient: continuity is
# left unchanged so the Agent can retry from its ring buffer.
_PERMANENT_INGEST_REFUSALS = frozenset({"message_too_large"})


class DeliveryOutcome(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    BACKPRESSURED = "backpressured"
    RATE_LIMITED = "rate_limited"
    REJECTED = "rejected"


class GapReason(str, Enum):
    """Why continuity was broken; none of these names a cause or culprit."""

    SEQUENCE_SKIP = "sequence_skip"
    CAPTURE_RESTART = "capture_restart"
    CAPTURE_CLOCK_REGRESSION = "capture_clock_regression"
    INGEST_REFUSED = "ingest_refused"
    COALESCED = "coalesced"


class SourceFlow(str, Enum):
    """Media-flow continuity only; this is not camera or node health."""

    RECEIVING = "receiving"
    DEGRADED = "degraded"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class ContinuityLimits:
    """Deployment-selected bounds; this module supplies no network defaults."""

    maximum_sources: int
    maximum_pending_gaps_per_source: int
    stale_after_ns: int

    def __post_init__(self) -> None:
        values = (self.maximum_sources, self.maximum_pending_gaps_per_source,
                  self.stale_after_ns)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("continuity limits must be positive integers")


@dataclass(frozen=True)
class AgentSession:
    """A Main-assigned session grant for one authenticated capture node.

    ``generation`` increases on every ``open_session`` for the node; a newer
    grant supersedes older ones, whose in-flight units are then rejected.
    """

    node_id: UUID
    generation: int


@dataclass(frozen=True)
class MediaUnitHeader:
    source_id: UUID
    capture_epoch: int
    sequence: int
    capture_time_ns: int

    def __post_init__(self) -> None:
        counters = (self.capture_epoch, self.sequence, self.capture_time_ns)
        if (not isinstance(self.source_id, UUID)
                or any(type(value) is not int or not 0 <= value <= _MAXIMUM_COUNTER
                       for value in counters)):
            raise ValueError("invalid media unit header")


@dataclass(frozen=True)
class GapEvent:
    """A known discontinuity between two sequences of one source.

    Units strictly between ``after_sequence`` (None: start of epoch/unknown)
    and ``before_sequence`` are missing; ``missing_units`` is None when the
    extent is not knowable.  A clock regression reports zero missing units.
    """

    node_id: UUID
    source_id: UUID
    reason: GapReason
    capture_epoch: int
    after_sequence: int | None
    before_sequence: int
    missing_units: int | None


@dataclass(frozen=True)
class Delivery:
    outcome: DeliveryOutcome
    reason: str | None
    gaps: tuple[GapEvent, ...] = ()


@dataclass(frozen=True)
class SourceContinuity:
    node_id: UUID
    source_id: UUID
    flow: SourceFlow
    capture_epoch: int
    last_sequence: int | None
    pending_gaps: int
    backpressured: bool


@dataclass
class _Source:
    """Per-source state; ``last_sequence`` None means nothing committed yet.

    An uncommitted entry exists only so that pressure/refusal on a source's
    first unit is visible as ``degraded``; it occupies a bounded source slot.
    """

    node_id: UUID
    capture_epoch: int
    last_sequence: int | None
    last_capture_time_ns: int
    last_seen_ns: int
    backpressured: bool = False
    refused: bool = False
    gaps: deque = field(default_factory=deque)


@dataclass
class _Node:
    generation: int
    open: bool
    last_seen_ns: int


class ContinuityTracker:
    """Bounded per-source continuity in front of an ``AgentIngestQueue``.

    The number of tracked nodes and sources is capped by ``maximum_sources``
    (the MVP default active-source limit is four), so an authenticated but
    misbehaving node cannot grow Main Server memory by inventing sources.
    The ingest queue is called while this tracker's lock is held; neither the
    queue nor the injected authorizer may call back into the tracker.
    """

    def __init__(self, limits: ContinuityLimits, authorizer: IngestAuthorizer,
                 ingest: AgentIngestQueue, *, clock_ns: Callable[[], int]) -> None:
        if (not isinstance(limits, ContinuityLimits)
                or not callable(getattr(authorizer, "require_node", None))
                or not callable(getattr(authorizer, "require_source", None))
                or not isinstance(ingest, AgentIngestQueue)
                or not callable(clock_ns)):
            raise ValueError("invalid continuity dependencies")
        self.limits = limits
        self._authorizer = authorizer
        self._ingest = ingest
        self._clock_ns = clock_ns
        self._nodes: dict[UUID, _Node] = {}
        self._sources: dict[UUID, _Source] = {}
        self._lock = Lock()

    def _now(self) -> int:
        now = self._clock_ns()
        if type(now) is not int or now < 0:
            raise ValueError("continuity clock must return nonnegative integer nanoseconds")
        return now

    def open_session(self, node_id: UUID) -> AgentSession:
        """Grant a new session to an already mTLS-authenticated node identity.

        Raises ``PermissionError`` for an unauthorized/revoked node or when the
        bounded node table is full.  Continuity state survives the reconnect.
        """
        if not isinstance(node_id, UUID):
            raise ValueError("invalid agent node identity")
        self._authorizer.require_node(node_id)
        now = self._now()
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                if len(self._nodes) >= self.limits.maximum_sources:
                    raise PermissionError("agent node capacity reached")
                node = self._nodes[node_id] = _Node(0, False, now)
            node.generation += 1
            node.open = True
            node.last_seen_ns = now
            return AgentSession(node_id, node.generation)

    def _current(self, session: AgentSession) -> _Node | None:
        node = self._nodes.get(session.node_id)
        if node is None or not node.open or node.generation != session.generation:
            return None
        return node

    def close_session(self, session: AgentSession) -> None:
        """Mark the node's flows interrupted; a stale grant changes nothing."""
        if not isinstance(session, AgentSession):
            raise ValueError("invalid agent session")
        with self._lock:
            node = self._current(session)
            if node is not None:
                node.open = False

    def _invalidate(self, session: AgentSession) -> None:
        """Close the current grant after its node failed reauthorization."""
        with self._lock:
            node = self._current(session)
            if node is not None:
                node.open = False

    def heartbeat(self, session: AgentSession) -> bool:
        """Refresh liveness only for a current grant of a still-authorized node.

        Node authorization is rechecked on every heartbeat so a credential
        revoked while its session stays open cannot keep the node online; a
        failed check invalidates the grant and its flows become interrupted.
        """
        if not isinstance(session, AgentSession):
            raise ValueError("invalid agent session")
        try:
            self._authorizer.require_node(session.node_id)
        except PermissionError:
            self._invalidate(session)
            return False
        now = self._now()
        with self._lock:
            node = self._current(session)
            if node is None:
                return False
            node.last_seen_ns = now
            return True

    def _record(self, state: _Source, gap: GapEvent) -> None:
        """Append within the per-source bound, coalescing instead of dropping."""
        if len(state.gaps) < self.limits.maximum_pending_gaps_per_source:
            state.gaps.append(gap)
            return
        previous = state.gaps.pop()
        state.gaps.append(GapEvent(
            gap.node_id, gap.source_id, GapReason.COALESCED, gap.capture_epoch,
            previous.after_sequence if previous.capture_epoch == gap.capture_epoch
            else None,
            gap.before_sequence, None,
        ))

    def _pending(self, state: _Source | None, node_id: UUID,
                 header: MediaUnitHeader, now: int) -> _Source:
        """Return the source state, creating an uncommitted one if absent.

        Capacity was already checked by the caller, so this stays bounded.
        """
        if state is not None:
            return state
        state = self._sources[header.source_id] = _Source(
            node_id, header.capture_epoch, None, header.capture_time_ns, now)
        return state

    def _discontinuities(self, node_id: UUID, state: _Source | None,
                         header: MediaUnitHeader) -> tuple[GapEvent, ...] | str:
        """Pure check; returns gaps to record, or a refusal/duplicate reason."""
        source_id, epoch, sequence = header.source_id, header.capture_epoch, header.sequence
        if state is None or state.last_sequence is None or epoch > state.capture_epoch:
            gaps = []
            if state is not None and state.last_sequence is not None:
                # A new capture epoch means the Agent capture process
                # restarted; the extent of any loss is not knowable here.
                gaps.append(GapEvent(node_id, source_id, GapReason.CAPTURE_RESTART, epoch,
                                     None, sequence, None))
            elif sequence:
                gaps.append(GapEvent(node_id, source_id, GapReason.SEQUENCE_SKIP, epoch,
                                     None, sequence, sequence))
            return tuple(gaps)
        if epoch < state.capture_epoch:
            return "stale_capture_epoch"
        if sequence <= state.last_sequence:
            return "duplicate"
        gaps = []
        if sequence > state.last_sequence + 1:
            gaps.append(GapEvent(node_id, source_id, GapReason.SEQUENCE_SKIP, epoch,
                                 state.last_sequence, sequence,
                                 sequence - state.last_sequence - 1))
        if header.capture_time_ns < state.last_capture_time_ns:
            gaps.append(GapEvent(node_id, source_id, GapReason.CAPTURE_CLOCK_REGRESSION,
                                 epoch, state.last_sequence, sequence, 0))
        return tuple(gaps)

    def receive(self, session: AgentSession, header: MediaUnitHeader,
                payload: bytes) -> Delivery:
        if (not isinstance(session, AgentSession) or not isinstance(header, MediaUnitHeader)
                or type(payload) is not bytes):
            raise ValueError("invalid agent media unit")
        node_id, source_id = session.node_id, header.source_id
        try:
            self._authorizer.require_node(node_id)
        except PermissionError:
            # A revoked node loses its grant, not just this unit.
            self._invalidate(session)
            return Delivery(DeliveryOutcome.REJECTED, "unauthorized")
        try:
            self._authorizer.require_source(node_id, source_id)
        except PermissionError:
            return Delivery(DeliveryOutcome.REJECTED, "unauthorized")
        now = self._now()
        with self._lock:
            node = self._current(session)
            if node is None:
                return Delivery(DeliveryOutcome.REJECTED, "stale_session")
            state = self._sources.get(source_id)
            if state is not None and state.node_id != node_id:
                # Source identity is bound to the node that first delivered it;
                # the authorizer must also refuse this, but fail closed here.
                return Delivery(DeliveryOutcome.REJECTED, "source_identity_mismatch")
            if state is None and len(self._sources) >= self.limits.maximum_sources:
                return Delivery(DeliveryOutcome.REJECTED, "source_capacity")
            checked = self._discontinuities(node_id, state, header)
            if checked == "duplicate":
                # Idempotent acknowledgement: the Agent may release this unit.
                return Delivery(DeliveryOutcome.DUPLICATE, "already_committed")
            if isinstance(checked, str):
                return Delivery(DeliveryOutcome.REJECTED, checked)
            admission = self._ingest.submit(AgentMessage(
                node_id, source_id, AgentAction.MEDIA, header.sequence, payload,
                capture_epoch=header.capture_epoch,
                capture_time_ns=header.capture_time_ns))
            if admission.outcome in (IngestOutcome.BACKPRESSURED, IngestOutcome.RATE_LIMITED):
                self._pending(state, node_id, header, now).backpressured = True
                outcome = (DeliveryOutcome.BACKPRESSURED
                           if admission.outcome is IngestOutcome.BACKPRESSURED
                           else DeliveryOutcome.RATE_LIMITED)
                return Delivery(outcome, admission.reason)
            if (admission.outcome is IngestOutcome.REJECTED
                    and admission.reason == "unauthorized"):
                return Delivery(DeliveryOutcome.REJECTED, "unauthorized")
            if (admission.outcome is IngestOutcome.REJECTED
                    and admission.reason not in _PERMANENT_INGEST_REFUSALS):
                # Transient/unknown refusal: do not commit or claim loss, but
                # never let the flow look healthy while it persists.
                self._pending(state, node_id, header, now).refused = True
                return Delivery(DeliveryOutcome.REJECTED, admission.reason)
            if state is None:
                state = self._sources[source_id] = _Source(
                    node_id, header.capture_epoch, header.sequence,
                    header.capture_time_ns, now)
            gaps = list(checked)
            if admission.outcome is IngestOutcome.REJECTED:
                # A permanently refused unit (e.g. oversize) is known loss.
                # Commit past it so a retry cannot loop, and report it.
                gaps.append(GapEvent(node_id, source_id, GapReason.INGEST_REFUSED,
                                     header.capture_epoch, header.sequence - 1
                                     if header.sequence else None,
                                     header.sequence + 1, 1))
            for gap in gaps:
                self._record(state, gap)
            state.capture_epoch = header.capture_epoch
            state.last_sequence = header.sequence
            state.last_capture_time_ns = header.capture_time_ns
            state.last_seen_ns = node.last_seen_ns = now
            state.backpressured = state.refused = False
            if admission.outcome is IngestOutcome.REJECTED:
                return Delivery(DeliveryOutcome.REJECTED, admission.reason, tuple(gaps))
            return Delivery(DeliveryOutcome.ACCEPTED, None, tuple(gaps))

    def snapshot(self) -> tuple[SourceContinuity, ...]:
        now = self._now()
        with self._lock:
            result = []
            for source_id, state in self._sources.items():
                node = self._nodes[state.node_id]
                if (not node.open or now < state.last_seen_ns
                        or now - state.last_seen_ns > self.limits.stale_after_ns):
                    flow = SourceFlow.INTERRUPTED
                elif state.gaps or state.backpressured or state.refused:
                    flow = SourceFlow.DEGRADED
                else:
                    flow = SourceFlow.RECEIVING
                result.append(SourceContinuity(
                    state.node_id, source_id, flow, state.capture_epoch,
                    state.last_sequence, len(state.gaps), state.backpressured))
            return tuple(result)

    def drain_gaps(self, maximum_events: int) -> tuple[GapEvent, ...]:
        """Remove a bounded batch for the durable timeline/health consumer."""
        if type(maximum_events) is not int or maximum_events <= 0:
            raise ValueError("drain maximum must be a positive integer")
        with self._lock:
            result = []
            for state in self._sources.values():
                while state.gaps and len(result) < maximum_events:
                    result.append(state.gaps.popleft())
            return tuple(result)

    def forget_node(self, node_id: UUID) -> tuple[GapEvent, ...]:
        """Drop state after durable revocation/removal; returns undrained gaps."""
        if not isinstance(node_id, UUID):
            raise ValueError("invalid agent node identity")
        with self._lock:
            self._nodes.pop(node_id, None)
            owned = [source for source, state in self._sources.items()
                     if state.node_id == node_id]
            pending = []
            for source_id in owned:
                pending.extend(self._sources.pop(source_id).gaps)
            return tuple(pending)
