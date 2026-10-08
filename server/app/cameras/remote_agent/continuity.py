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
a reconnect that lost nothing yields no gap.  A Main Server restart loses the
in-memory tracker, so a source's continuity is restored from the durable
recording layer's committed watermark before its first post-restart unit is
checked; units that watermark already covers are never reported as loss.

A unit is committed only after the bounded ingest queue accepts it.  A
backpressure/rate refusal leaves continuity unchanged so the Agent retries the
same sequence from its disk ring buffer; a retry of an already committed unit
is reported as ``duplicate`` and never enqueued twice.  Every attempt of an
authorized node, including a duplicate or an early refusal that is never
enqueued, consumes that node's ingest rate budget.  Known loss is recorded
as a bounded gap event and keeps the source ``degraded`` until a consumer
drains it; it is never reported as a healthy flow.

Releasing (deactivating) a source keeps its continuity outside the active-slot
table until the durable recording layer acknowledges that it persisted that
position (``acknowledge_persisted``), so a reactivated source's retry is never
enqueued twice and loss already reported is never reported again.
"""

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Callable, Iterator
from uuid import UUID, uuid4

from app.cameras.remote_agent.ingest import (
    AgentAction, AgentIngestQueue, AgentMessage, IngestAuthorizer, IngestOutcome,
)

_MAXIMUM_COUNTER = 2 ** 63 - 1
# Only an ingest refusal that no retry of the same unit can ever satisfy is
# committed past as known loss.  Any other refusal (for example the ingest
# boundary's fail-closed Main clock regression) is transient: continuity is
# left unchanged so the Agent can retry from its ring buffer.
_PERMANENT_INGEST_REFUSALS = frozenset({"message_too_large"})
# A committed-watermark lookup that raised; distinct from "nothing recorded".
_UNAVAILABLE = object()
# Hard bound on the refused-attempt staircase kept per source (``_Source``).
_MAXIMUM_ATTEMPT_STEPS = 8


def _record_attempt(steps: tuple[tuple[int, int], ...], sequence: int,
                    at: int) -> tuple[tuple[int, int], ...]:
    """Add a refused ``(sequence, capture time)`` to a bounded staircase.

    ``steps`` is ordered by ascending sequence with strictly descending
    capture time: an attempt is kept only while no other attempt has both a
    sequence and a capture time at least as large, so the latest capture time
    after any sequence is that of the first step past it.  It grows only when
    a later refused sequence carries an earlier capture time.  Beyond
    ``_MAXIMUM_ATTEMPT_STEPS`` the two lowest steps are merged into the
    higher sequence with the later time: a watermark covering only the lower
    one then keeps the later time as baseline (a possible spurious regression
    report, never a hidden one).
    """
    if any(s >= sequence and t >= at for s, t in steps):
        return steps
    kept = [(s, t) for s, t in steps if not (s <= sequence and t <= at)]
    kept.append((sequence, at))
    kept.sort()
    if len(kept) > _MAXIMUM_ATTEMPT_STEPS:
        (_, later), (higher, _) = kept[0], kept[1]
        kept[:2] = [(higher, later)]
    return tuple(kept)


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
    """Deployment-selected bounds; this module supplies no network defaults.

    ``maximum_sources`` is the active-source limit (MVP default four) and
    bounds tracked sources only.  ``maximum_nodes`` separately hard-bounds
    tracked node sessions (memory only, like the ingest rate-window table),
    so live source-less node sessions never consume the active-source
    allowance.  ``maximum_released_sources`` hard-bounds the continuity kept
    for released (deactivated) sources that the durable layer has not yet
    acknowledged; when it is full the oldest such entry is evicted, and that
    source falls back to its durable watermark on reactivation.
    """

    maximum_sources: int
    maximum_pending_gaps_per_source: int
    stale_after_ns: int
    maximum_nodes: int = 64
    maximum_released_sources: int = 64

    def __post_init__(self) -> None:
        values = (self.maximum_sources, self.maximum_pending_gaps_per_source,
                  self.stale_after_ns, self.maximum_nodes,
                  self.maximum_released_sources)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("continuity limits must be positive integers")


@dataclass(frozen=True)
class AgentSession:
    """A Main-assigned session grant for one authenticated capture node.

    ``generation`` is drawn from one tracker-wide counter that never resets,
    so it increases on every ``open_session`` and is never reissued, even
    after ``forget_node`` and re-enrollment of the same node UUID.  A newer
    grant supersedes older ones, whose in-flight units are then rejected.
    ``instance`` binds the grant to one tracker lifetime, so a grant from
    before a Main Server restart can never match a post-restart session.
    """

    node_id: UUID
    generation: int
    instance: UUID | None = None


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
class CommittedWatermark:
    """The last unit of a source that the durable recording layer persisted.

    Supplied by the deployment's durable store after a Main Server restart so
    continuity resumes where it was durably recorded instead of treating an
    Agent that kept capturing as a new flow with leading loss.  Units at or
    below it are ``duplicate``; units after it and before the next delivered
    one are exact loss (for example queued units the restart discarded).
    """

    node_id: UUID
    capture_epoch: int
    sequence: int
    capture_time_ns: int

    def __post_init__(self) -> None:
        counters = (self.capture_epoch, self.sequence, self.capture_time_ns)
        if (not isinstance(self.node_id, UUID)
                or any(type(value) is not int or not 0 <= value <= _MAXIMUM_COUNTER
                       for value in counters)):
            raise ValueError("invalid committed watermark")


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
class AuthorizationChange:
    """Result of a fenced authorization change; filled only when it commits."""

    released_gaps: tuple[GapEvent, ...] = ()


@dataclass
class _Source:
    """Per-source state; ``last_sequence`` None means nothing committed yet.

    An uncommitted entry exists only so that pressure/refusal on a source's
    first unit is visible as ``degraded``; it occupies a bounded source slot.
    Its ``capture_epoch`` is that of the first attempted unit, so a later
    higher epoch is still a capture restart (known loss of the uncommitted
    unit) and a lower epoch is still stale, exactly as for committed state.
    ``session_generation`` is the node session that last delivered this
    source; a source not yet delivered on the node's current session stays
    ``interrupted`` even though the node itself reconnected.
    ``attempted_epoch`` is the highest epoch of a unit refused by pressure, a
    transient refusal or an unavailable watermark; a lower epoch is stale even
    before that unit commits, so a restart already observed is never lost to
    an older-epoch retry.  ``attempts`` keeps the ``(sequence, capture time)``
    of such refused units of ``attempted_epoch`` since the last commit (empty:
    none) as a bounded staircase (``_record_attempt``): ascending sequence,
    strictly descending capture time, so for any sequence it gives the latest
    capture time among the refused units after it (never earlier than the
    exact value).  Its latest capture time (``attempted_time_ns``) is the
    in-epoch clock baseline, so a capture clock regression is reported even
    before anything of that epoch is committed; a durable watermark resolved
    later supersedes only the attempts it covers (``_attempts_beyond``), like
    a commit does.
    ``noted_epoch``/``noted_before`` record known loss (a capture restart or
    skipped sequences) that was already reported when a refused unit of that
    epoch first showed it: every uncommitted unit of ``noted_epoch`` before
    sequence ``noted_before`` is already reported, so a retry never reports
    that loss twice; a retry that starts later than ``noted_before`` reports
    only the units in between, and a late unit before ``noted_before`` is a
    ``duplicate`` (it lies behind loss already reported and is never
    admitted).  ``noted_before`` None means nothing noted.
    ``unresolved`` marks an entry kept only because the durable watermark
    lookup failed for the source's first unit: it holds the source slot and
    reports ``degraded``, but carries no continuity, so the next attempt looks
    the watermark up again.
    ``durable_epoch``/``durable_sequence`` is the latest position the durable
    recording layer acknowledged as persisted (``durable_sequence`` None:
    nothing acknowledged yet).
    """

    node_id: UUID
    capture_epoch: int
    last_sequence: int | None
    last_capture_time_ns: int
    last_seen_ns: int
    backpressured: bool = False
    refused: bool = False
    gaps: deque = field(default_factory=deque)
    session_generation: int = 0
    attempted_epoch: int = 0
    attempts: tuple[tuple[int, int], ...] = ()
    noted_epoch: int = 0
    noted_before: int | None = None
    unresolved: bool = False
    durable_epoch: int = 0
    durable_sequence: int | None = None

    @property
    def attempted_time_ns(self) -> int | None:
        """Latest capture time of a refused attempt (None: none)."""
        return self.attempts[0][1] if self.attempts else None


@dataclass
class _Node:
    generation: int
    open: bool
    last_seen_ns: int


class ContinuityTracker:
    """Bounded per-source continuity in front of an ``AgentIngestQueue``.

    Tracked sources are capped by ``maximum_sources`` (the MVP default
    active-source limit is four), so an authenticated but misbehaving node
    cannot grow Main Server memory by inventing sources; tracked node
    sessions are separately capped by ``maximum_nodes``.
    The ingest queue and the injected authorizer are called while this
    tracker's lock is held; neither may call back into the tracker.

    Every node/source authorization that decides a grant, a liveness refresh
    or a media outcome is evaluated while this lock is held, immediately
    before the state it guards is read or changed.  A check made before
    waiting for the lock could otherwise be applied after a concurrent
    revocation (and ``_invalidate``/``forget_node``) that it never observed.

    Holding this lock does not by itself order a check with a revocation that
    commits elsewhere (``PairingLedger.revoke`` uses its own database
    transaction).  The node/source lifecycle therefore commits every durable
    revocation or source deactivation inside ``authorization_change``, which
    holds this tracker's lock and the ingest queue's lock for the commit, so
    no grant, liveness refresh, acknowledgement, charge or enqueue can rest on
    an authorization read before that commit.

    ``committed_watermark(source_id)`` returns the source's durably recorded
    ``CommittedWatermark`` or None when nothing was ever recorded.  It is
    consulted, under this tracker's lock, before the first unit of a source
    this tracker does not yet track, and must not call back into the tracker
    or its ingest queue.  An attempt that the node's rate budget (or its
    authorization) already refuses is refused before the lookup, so retries
    cannot drive unbounded durable-store work; the attempt is still charged
    exactly once.  A lookup that fails refuses the unit transiently
    (nothing is committed, so the Agent retries); it never falls back to
    reporting the durably recorded units as loss.  Until a lookup succeeds the
    source is kept as a bounded unresolved entry reported ``degraded``.

    Releasing a source (deactivation) frees its active-source slot.  Its
    continuity (committed position, attempted epoch and loss already reported
    on a refused unit) is kept outside the slot table, so a retry after
    reactivation is still a ``duplicate``, is never enqueued a second time,
    and never reports the same loss twice.  Leaving the ingest queue is not
    durability: that entry is dropped only once the durable recording layer
    has acknowledged (``acknowledge_persisted``) a watermark covering its
    committed position and the entry carries nothing else, after which the
    durable watermark is the source of truth.  These entries are hard-bounded
    by ``maximum_released_sources`` (oldest evicted first).
    """

    def __init__(self, limits: ContinuityLimits, authorizer: IngestAuthorizer,
                 ingest: AgentIngestQueue, *, clock_ns: Callable[[], int],
                 committed_watermark: Callable[[UUID], CommittedWatermark | None],
                 ) -> None:
        if (not isinstance(limits, ContinuityLimits)
                or not callable(getattr(authorizer, "require_node", None))
                or not callable(getattr(authorizer, "require_source", None))
                or not isinstance(ingest, AgentIngestQueue)
                or not callable(clock_ns)
                or not callable(committed_watermark)):
            raise ValueError("invalid continuity dependencies")
        self.limits = limits
        self._authorizer = authorizer
        self._ingest = ingest
        self._clock_ns = clock_ns
        self._committed_watermark = committed_watermark
        self._nodes: dict[UUID, _Node] = {}
        self._sources: dict[UUID, _Source] = {}
        # Continuity of released sources not yet covered by a durable
        # acknowledgement; bounded by ``maximum_released_sources`` and outside
        # the active-source slot limit.  Insertion order is eviction order.
        self._released: dict[UUID, _Source] = {}
        # Monotonic across forget/re-enrollment; never reused for any node.
        self._generation = 0
        self._instance = uuid4()
        self._lock = Lock()

    def _now(self) -> int:
        now = self._clock_ns()
        if type(now) is not int or now < 0:
            raise ValueError("continuity clock must return nonnegative integer nanoseconds")
        return now

    @contextmanager
    def authorization_change(self, *, revoked_node: UUID | None = None,
                             deactivated_source: UUID | None = None,
                             ) -> Iterator["AuthorizationChange"]:
        """Serialize a durable authorization change with every grant/commit.

        The caller commits the revocation or source deactivation inside the
        block and must not call back into this tracker or its ingest queue
        there.  Both locks are held (tracker, then queue: the same order as
        ``receive``), so every ``open_session``, ``heartbeat``, ``receive`` and
        direct queue ``submit`` authorizes and acts entirely before or
        entirely after the commit.

        When the block completes, and before this tracker's lock is released,
        ``revoked_node`` is forgotten with every source it owns (so a grant
        issued just before the commit is unusable afterwards) and its rate
        window is discarded, and ``deactivated_source`` releases its active
        source slot.  No waiting caller can therefore observe the committed
        change with the released state still present (for example a
        replacement source refused ``source_capacity``).  Undrained gaps of
        the released sources are not dropped: they are handed back in the
        yielded ``AuthorizationChange.released_gaps`` for the caller to
        persist.  If the commit raises, nothing is changed.
        """
        if ((revoked_node is not None and not isinstance(revoked_node, UUID))
                or (deactivated_source is not None
                    and not isinstance(deactivated_source, UUID))):
            raise ValueError("invalid agent authorization change")
        change = AuthorizationChange()
        with self._lock:
            with self._ingest.authorization_change(revoked_node=revoked_node):
                yield change
            released = []
            if revoked_node is not None:
                released.extend(self._forget_node_locked(revoked_node))
            if deactivated_source is not None:
                released.extend(self._forget_source_locked(deactivated_source))
            change.released_gaps = tuple(released)

    def open_session(self, node_id: UUID) -> AgentSession:
        """Grant a new session to an already mTLS-authenticated node identity.

        Raises ``PermissionError`` for an unauthorized/revoked node or when the
        bounded node table is full.  Continuity state survives the reconnect,
        but each of the node's sources stays ``interrupted`` until it delivers
        media on the new session: node connectivity alone never clears a
        camera's known interruption.
        """
        if not isinstance(node_id, UUID):
            raise ValueError("invalid agent node identity")
        with self._lock:
            # Authorized under the lock, right before the grant is issued: a
            # revocation that lands while this call waits for the lock must
            # refuse the grant instead of reopening an invalidated session.
            # A revocation committed inside ``authorization_change`` cannot
            # land between this check and the grant; one committed after the
            # grant forgets the node (and so the grant) when that block
            # completes.
            self._authorizer.require_node(node_id)
            # Liveness time is sampled under the lock so a delayed caller can
            # never apply an older ``now`` after a newer update (see _seen).
            now = self._now()
            node = self._nodes.get(node_id)
            if node is None:
                if len(self._nodes) >= self.limits.maximum_nodes:
                    self._retire_unused_nodes(now)
                if len(self._nodes) >= self.limits.maximum_nodes:
                    raise PermissionError("agent node capacity reached")
                node = self._nodes[node_id] = _Node(0, False, now)
            self._generation += 1
            node.generation = self._generation
            node.open = True
            self._seen(node, now)
            return AgentSession(node_id, node.generation, self._instance)

    def _retire_unused_nodes(self, now: int) -> None:
        """Free node slots held by nodes that own no tracked source.

        Only a node without sources whose session is closed, invalidated or
        stale is retired, so node records cannot exhaust the node-session
        bound after sources were deactivated.  A live session (fresh
        heartbeat) keeps its slot.  Generations are tracker-wide and never
        reissued, so a retired node's old grant can never become current.

        A clock that reads earlier than a node's last activity says nothing
        about that session being stale, so it never retires a node; the new
        session is refused instead (fail closed, the live session survives).
        """
        owners = {state.node_id for state in self._sources.values()}
        for node_id, node in tuple(self._nodes.items()):
            if node_id in owners:
                continue
            if not node.open or now - node.last_seen_ns > self.limits.stale_after_ns:
                del self._nodes[node_id]

    @staticmethod
    def _seen(state: _Node | _Source, now: int) -> None:
        """Advance activity time; an older sample never moves it backwards."""
        if now > state.last_seen_ns:
            state.last_seen_ns = now

    def _current(self, session: AgentSession) -> _Node | None:
        node = self._nodes.get(session.node_id)
        if (node is None or not node.open or session.instance != self._instance
                or node.generation != session.generation):
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

    def _invalidate_locked(self, session: AgentSession) -> None:
        """Close the current grant after its node failed reauthorization."""
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
        with self._lock:
            # Rechecked under the lock so a revocation that lands while this
            # call waits can never be followed by a liveness refresh.
            try:
                self._authorizer.require_node(session.node_id)
            except PermissionError:
                self._invalidate_locked(session)
                return False
            now = self._now()
            node = self._current(session)
            if node is None:
                return False
            self._seen(node, now)
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
        if state is not None and epoch < max(state.capture_epoch, state.attempted_epoch):
            # Also for an uncommitted state or an uncommitted higher epoch:
            # it was observed on a unit the Agent attempted, and capture
            # epochs only increase.
            return "stale_capture_epoch"
        if (state is not None and state.noted_before is not None
                and epoch == state.noted_epoch
                and (epoch > state.capture_epoch or state.last_sequence is None
                     or state.noted_before > state.last_sequence)):
            # Loss before ``noted_before`` was already reported when a refused
            # unit first showed it (a restart, or skipped sequences); only
            # units skipped past that first unit are new loss.
            if epoch == state.capture_epoch and state.last_sequence is not None \
                    and sequence <= state.last_sequence:
                return "duplicate"
            if sequence < state.noted_before:
                # A late unit behind loss already reported: admitting it would
                # contradict the recorded gap, so it is acknowledged instead.
                return "duplicate"
            gaps = []
            if sequence > state.noted_before:
                gaps.append(GapEvent(node_id, source_id, GapReason.SEQUENCE_SKIP, epoch,
                                     state.noted_before - 1 if state.noted_before else None,
                                     sequence, sequence - state.noted_before))
            gaps.extend(self._clock_regression(node_id, state, header))
            return tuple(gaps)
        if state is not None and epoch > state.capture_epoch:
            # A new capture epoch means the Agent capture process restarted;
            # the extent of any loss is not knowable here.  This holds for an
            # uncommitted state too: its attempted unit(s) of the older epoch
            # were never committed and are now known to be lost.  A unit of
            # this new epoch refused before (an unavailable watermark keeps
            # its capture time without noting loss) is still the in-epoch
            # baseline, so a capture clock regression is reported as well.
            return (GapEvent(node_id, source_id, GapReason.CAPTURE_RESTART, epoch,
                             None, sequence, None),
                    *self._clock_regression(node_id, state, header))
        if state is None or state.last_sequence is None:
            # Start of the flow in this epoch (absent, or seen but uncommitted
            # in the same epoch): leading units are reported as loss.
            gaps = []
            if sequence:
                gaps.append(GapEvent(node_id, source_id, GapReason.SEQUENCE_SKIP, epoch,
                                     None, sequence, sequence))
            if state is not None:
                gaps.extend(self._clock_regression(node_id, state, header))
            return tuple(gaps)
        if sequence <= state.last_sequence:
            return "duplicate"
        gaps = []
        if sequence > state.last_sequence + 1:
            gaps.append(GapEvent(node_id, source_id, GapReason.SEQUENCE_SKIP, epoch,
                                 state.last_sequence, sequence,
                                 sequence - state.last_sequence - 1))
        gaps.extend(self._clock_regression(node_id, state, header))
        return tuple(gaps)

    @staticmethod
    def _clock_regression(node_id: UUID, state: _Source,
                          header: MediaUnitHeader) -> tuple[GapEvent, ...]:
        """Report an in-epoch capture clock regression against what was seen.

        The baseline is the committed unit of this epoch and the latest
        capture time observed on a refused unit of this epoch since that
        commit, so a retry is compared even when nothing of the epoch is
        committed yet (a refused first unit, or a refused restart unit).
        """
        epoch = header.capture_epoch
        committed = state.last_sequence is not None and state.capture_epoch == epoch
        baseline = [state.last_capture_time_ns] if committed else []
        if state.attempted_time_ns is not None and state.attempted_epoch == epoch:
            baseline.append(state.attempted_time_ns)
        if not baseline or header.capture_time_ns >= max(baseline):
            return ()
        return (GapEvent(node_id, header.source_id, GapReason.CAPTURE_CLOCK_REGRESSION,
                         epoch, state.last_sequence if committed else None,
                         header.sequence, 0),)

    @staticmethod
    def _attempted(state: _Source, header: MediaUnitHeader) -> None:
        """Remember the epoch and capture time of a refused, uncommitted unit.

        Lower epochs are refused as stale before any attempt is recorded, so
        ``header.capture_epoch`` is never below ``attempted_epoch`` here; an
        older one is ignored defensively.
        """
        epoch = header.capture_epoch
        if epoch < state.attempted_epoch:
            return
        kept = state.attempts if epoch == state.attempted_epoch else ()
        state.attempts = _record_attempt(kept, header.sequence, header.capture_time_ns)
        state.attempted_epoch = epoch

    def _observe_loss(self, state: _Source, checked: tuple[GapEvent, ...],
                      header: MediaUnitHeader) -> tuple[GapEvent, ...]:
        """Record known loss (restart or skipped units) a refused unit first shows.

        The unit is not committed, but the units before it are already known
        loss: if the Agent never retries it (it disconnects for good, or the
        source is deactivated) that loss must still reach the durable
        consumer.  The loss is remembered so a retry never reports it a second
        time.  A capture-clock regression is not loss and is reported only
        when the unit commits.
        """
        losses = tuple(gap for gap in checked
                       if gap.reason in (GapReason.CAPTURE_RESTART, GapReason.SEQUENCE_SKIP))
        if not losses:
            return ()
        for gap in losses:
            self._record(state, gap)
        state.noted_epoch = header.capture_epoch
        state.noted_before = header.sequence
        return losses

    def _charged(self, session: AgentSession, outcome: DeliveryOutcome,
                 reason: str) -> Delivery:
        """Refuse/acknowledge an authorized node's attempt without enqueueing it.

        ``AgentIngestQueue.submit`` is otherwise the only place the per-node
        rate window is counted, so every early return for an authorized node
        (duplicate retry, stale session/epoch, source mismatch or capacity,
        unauthorized source) is charged here.  Over budget, the attempt is
        reported as the queue's rate/clock refusal, like ``submit`` reports a
        rate refusal before its other refusals.  Continuity is never changed.
        Session control (``open_session``/``heartbeat``) is not media and is
        not charged here; the future listener bounds connection attempts.

        Like ``submit``, ``charge_attempt`` re-authorizes the node under the
        queue lock first: a node revoked after the earlier checks (which may
        itself have caused a source refusal) is never charged and its grant
        is invalidated.  The caller holds this tracker's lock.
        """
        refusal = self._ingest.charge_attempt(session.node_id)
        if refusal is None:
            return Delivery(outcome, reason)
        return self._refused(session, refusal)

    def _refused(self, session: AgentSession, refusal) -> Delivery:
        """Report a queue rate/clock/authorization refusal of an attempt."""
        if refusal.reason == "unauthorized":
            self._invalidate_locked(session)
            return Delivery(DeliveryOutcome.REJECTED, "unauthorized")
        if refusal.outcome is IngestOutcome.RATE_LIMITED:
            return Delivery(DeliveryOutcome.RATE_LIMITED, refusal.reason)
        return Delivery(DeliveryOutcome.REJECTED, refusal.reason)

    def receive(self, session: AgentSession, header: MediaUnitHeader,
                payload: bytes) -> Delivery:
        if (not isinstance(session, AgentSession) or not isinstance(header, MediaUnitHeader)
                or type(payload) is not bytes):
            raise ValueError("invalid agent media unit")
        node_id, source_id = session.node_id, header.source_id
        with self._lock:
            # Node and source are authorized under the lock, so an outcome
            # decided below (duplicate acknowledgement, stale epoch, source
            # capacity, pending pressure) never rests on a check that a
            # revocation landing while this call waited did not observe.
            try:
                self._authorizer.require_node(node_id)
            except PermissionError:
                # A revoked node loses its grant, not just this unit.
                self._invalidate_locked(session)
                return Delivery(DeliveryOutcome.REJECTED, "unauthorized")
            try:
                self._authorizer.require_source(node_id, source_id)
            except PermissionError:
                # The source refusal may come from a node revocation that
                # landed after the node check; ``_charged`` rechecks the node,
                # invalidates the grant then, and charges only a source-only
                # refusal.
                return self._charged(session, DeliveryOutcome.REJECTED, "unauthorized")
            now = self._now()
            node = self._current(session)
            if node is None:
                return self._charged(session, DeliveryOutcome.REJECTED, "stale_session")
            # Never seed or refresh activity below the node's liveness
            # watermark: a regressed clock sample must not make a new source
            # look older than the session that is delivering it.
            now = max(now, node.last_seen_ns)
            state = self._sources.get(source_id)
            if state is not None and state.node_id != node_id:
                # Source identity is bound to the node that first delivered it;
                # the authorizer must also refuse this, but fail closed here.
                return self._charged(session, DeliveryOutcome.REJECTED,
                                     "source_identity_mismatch")
            if state is None and len(self._sources) >= self.limits.maximum_sources:
                return self._charged(session, DeliveryOutcome.REJECTED, "source_capacity")
            if state is None:
                released = self._released.get(source_id)
                if released is not None and released.node_id == node_id:
                    # Reactivated before the durable layer acknowledged
                    # covering it: this continuity is at least as new as the
                    # durable watermark and also carries loss already noted.
                    del self._released[source_id]
                    state = self._sources[source_id] = released
            if state is None or state.unresolved:
                # First unit this tracker sees (for example after a Main
                # Server restart): resume from the durable watermark so units
                # already recorded by an earlier process are not loss.
                # An over-budget or revoked node is refused before the lookup,
                # so retries can never drive unbounded durable-store work under
                # this lock; a fitting attempt is charged once, later.
                refusal = self._ingest.check_attempt(node_id)
                if refusal is not None:
                    delivery = self._refused(session, refusal)
                    if refusal.reason != "unauthorized":
                        # Still delivering: keep the refusal visible.
                        self._hold_unresolved(
                            session, node, state, header, now,
                            pressured=refusal.outcome is IngestOutcome.RATE_LIMITED)
                    return delivery
                try:
                    mark = self._committed_watermark(source_id)
                except Exception:
                    mark = _UNAVAILABLE
                # The durable lookup may block: re-sample so a unit admitted
                # or refused afterwards is never stamped with a time from
                # before the lookup (it would read as an interrupted flow).
                now = max(now, self._now())
                if mark is _UNAVAILABLE or (mark is not None
                                            and not isinstance(mark, CommittedWatermark)):
                    return self._unresolved(session, node, state, header, now)
                if mark is not None and mark.node_id != node_id:
                    return self._charged(session, DeliveryOutcome.REJECTED,
                                         "source_identity_mismatch")
                state = self._resolved(node_id, source_id, state, mark, header, now)
            checked = self._discontinuities(node_id, state, header)
            if checked == "duplicate":
                # Idempotent acknowledgement: the Agent may release this unit.
                # It is never enqueued again but still consumes rate budget.
                return self._charged(session, DeliveryOutcome.DUPLICATE,
                                     "already_committed")
            if isinstance(checked, str):
                return self._charged(session, DeliveryOutcome.REJECTED, checked)
            admission = self._ingest.submit(AgentMessage(
                node_id, source_id, AgentAction.MEDIA, header.sequence, payload,
                capture_epoch=header.capture_epoch,
                capture_time_ns=header.capture_time_ns))
            # Stamp the outcome with a time taken once admission completed.
            now = max(now, self._now())
            if admission.outcome in (IngestOutcome.BACKPRESSURED, IngestOutcome.RATE_LIMITED):
                pending = self._pending(state, node_id, header, now)
                pending.backpressured = True
                self._attempted(pending, header)
                observed = self._observe_loss(pending, checked, header)
                # The Agent is still delivering: refresh activity (not the
                # committed sequence) so sustained pressure stays ``degraded``
                # instead of decaying to ``interrupted``.
                self._seen(pending, now)
                pending.session_generation = node.generation
                self._seen(node, now)
                outcome = (DeliveryOutcome.BACKPRESSURED
                           if admission.outcome is IngestOutcome.BACKPRESSURED
                           else DeliveryOutcome.RATE_LIMITED)
                return Delivery(outcome, admission.reason, observed)
            if (admission.outcome is IngestOutcome.REJECTED
                    and admission.reason == "unauthorized"):
                # The queue re-authorizes node and source.  If the node was
                # revoked after the check above, the grant must be closed too;
                # a source-only revocation keeps the node session.  The
                # authorizer is already called under this lock by the queue.
                # The queue counts no rate for an authorization refusal, so a
                # still-authorized node is charged like the early source check.
                return self._charged(session, DeliveryOutcome.REJECTED, "unauthorized")
            if (admission.outcome is IngestOutcome.REJECTED
                    and admission.reason not in _PERMANENT_INGEST_REFUSALS):
                # Transient/unknown refusal: do not commit or claim loss, but
                # never let the flow look healthy while it persists.  Activity
                # is refreshed so a persisting refusal stays ``degraded``.
                pending = self._pending(state, node_id, header, now)
                pending.refused = True
                self._attempted(pending, header)
                observed = self._observe_loss(pending, checked, header)
                self._seen(pending, now)
                pending.session_generation = node.generation
                self._seen(node, now)
                return Delivery(DeliveryOutcome.REJECTED, admission.reason, observed)
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
            # Attempts up to this commit are superseded by the committed unit.
            state.attempts = ()
            self._seen(state, now)
            state.session_generation = node.generation
            self._seen(node, now)
            state.backpressured = state.refused = False
            if not (state.noted_before is not None
                    and state.noted_epoch == header.capture_epoch
                    and header.sequence < state.noted_before):
                # Committed at or past the noted loss: nothing noted remains.
                state.noted_epoch, state.noted_before = 0, None
            if admission.outcome is IngestOutcome.REJECTED:
                return Delivery(DeliveryOutcome.REJECTED, admission.reason, tuple(gaps))
            return Delivery(DeliveryOutcome.ACCEPTED, None, tuple(gaps))

    def _resolved(self, node_id: UUID, source_id: UUID, state: _Source | None,
                  mark: CommittedWatermark | None, header: MediaUnitHeader,
                  now: int) -> _Source | None:
        """Seed continuity from a successful durable-watermark lookup.

        An unresolved entry carries no continuity, but the epochs (and capture
        times) of the units it refused were attempted: they are kept, so a
        lower epoch is still stale and an in-epoch clock regression is still
        reported, whether or not the durable store recorded anything.
        A watermark of the attempted epoch supersedes, as a commit would, the
        refused units it covers (at or before its sequence) and those not
        later than its capture time: they are dropped, so a duplicate retry
        of a fully superseded attempt leaves the source durably covered and a
        release keeps no entry in the bounded released table.  A refused unit
        past the watermark with a later capture time stays the baseline (the
        latest such time only, never a covered unit's), so a genuine
        regression is still reported and a covered one is not.
        """
        attempted = state
        if attempted is not None:
            del self._sources[source_id]
        if mark is not None:
            # The watermark is itself the durable position: a source resumed
            # from it is covered there, so releasing it before anything newer
            # commits keeps no entry in the bounded released table.
            state = self._sources[source_id] = _Source(
                node_id, mark.capture_epoch, mark.sequence, mark.capture_time_ns, now,
                durable_epoch=mark.capture_epoch, durable_sequence=mark.sequence)
        elif attempted is not None:
            # Nothing durable: an uncommitted entry in the attempted epoch, as
            # if that refused unit had been refused by pressure.
            state = self._sources[source_id] = _Source(
                node_id, attempted.attempted_epoch, None, header.capture_time_ns, now)
        else:
            return None
        if attempted is not None and attempted.attempted_epoch >= state.capture_epoch:
            state.attempted_epoch = attempted.attempted_epoch
            state.attempts = self._attempts_beyond(mark, attempted)
        return state

    @staticmethod
    def _attempts_beyond(mark: CommittedWatermark | None,
                         attempted: _Source) -> tuple[tuple[int, int], ...]:
        """The refused attempts a resolved watermark does not supersede.

        Only a watermark of the attempted epoch supersedes any: those at or
        before its sequence are durably covered (their clock order the
        earlier process already checked when committing them), and those not
        later than its capture time add nothing to a baseline that already
        holds the mark's time, so dropping either changes no genuine
        regression report.  A higher attempted epoch keeps every attempt.
        """
        if mark is None or mark.capture_epoch != attempted.attempted_epoch:
            return attempted.attempts
        return tuple((sequence, at) for sequence, at in attempted.attempts
                     if sequence > mark.sequence and at > mark.capture_time_ns)

    def _unresolved(self, session: AgentSession, node: _Node, state: _Source | None,
                    header: MediaUnitHeader, now: int) -> Delivery:
        """Refuse a unit whose durable watermark could not be read.

        Nothing is committed and no loss is claimed, but the source keeps a
        bounded (slot-limited) unresolved entry so monitoring reports it
        ``degraded`` while the Agent retries.  An over-budget attempt or a
        revoked node changes nothing beyond what ``_charged`` reports.
        """
        delivery = self._charged(session, DeliveryOutcome.REJECTED, "watermark_unavailable")
        if delivery.reason != "watermark_unavailable":
            return delivery
        self._hold_unresolved(session, node, state, header, now, pressured=False)
        return delivery

    def _hold_unresolved(self, session: AgentSession, node: _Node, state: _Source | None,
                         header: MediaUnitHeader, now: int, *, pressured: bool) -> None:
        """Keep a bounded continuity-less entry so a refused source reads ``degraded``.

        Used for a source whose watermark is not resolved yet (``state`` is
        None or unresolved); capacity was already checked by the caller.
        """
        if state is None:
            state = self._sources[header.source_id] = _Source(
                session.node_id, header.capture_epoch, None, header.capture_time_ns, now,
                unresolved=True)
        # The attempt's epoch is kept so an older-epoch retry stays stale once
        # the watermark resolves (``_resolved``).
        self._attempted(state, header)
        if pressured:
            state.backpressured = True
        else:
            state.refused = True
        self._seen(state, now)
        state.session_generation = node.generation
        self._seen(node, now)

    def snapshot(self) -> tuple[SourceContinuity, ...]:
        with self._lock:
            # Sampled under the lock: an older ``now`` than a concurrent
            # update would otherwise misreport a live flow as interrupted.
            now = self._now()
            result = []
            for source_id, state in self._sources.items():
                node = self._nodes[state.node_id]
                if (not node.open or state.session_generation != node.generation
                        or now < state.last_seen_ns
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

    @staticmethod
    def _durably_covered(state: _Source) -> bool:
        """Whether the durable watermark alone restores this continuity.

        True only when the acknowledged durable position is at or past the
        committed one and nothing else is carried: no loss noted on a refused
        unit and no refused attempt since the last commit.  An unresolved or
        uncommitted entry is never covered.
        """
        return (not state.unresolved and state.last_sequence is not None
                and state.durable_sequence is not None
                and (state.durable_epoch, state.durable_sequence)
                >= (state.capture_epoch, state.last_sequence)
                and state.noted_before is None and state.attempted_time_ns is None
                and state.attempted_epoch <= state.capture_epoch)

    def _forget_source_locked(self, source_id: UUID) -> tuple[GapEvent, ...]:
        state = self._sources.pop(source_id, None)
        if state is None:
            return ()
        gaps = tuple(state.gaps)
        # Keep the continuity (gaps are handed back) until the durable layer
        # acknowledges covering it: leaving the ingest queue is not
        # durability, so a retry after reactivation can neither enqueue an
        # envelope again nor report noted loss twice.
        released = _Source(
            state.node_id, state.capture_epoch, state.last_sequence,
            state.last_capture_time_ns, state.last_seen_ns,
            attempted_epoch=state.attempted_epoch,
            attempts=state.attempts,
            noted_epoch=state.noted_epoch, noted_before=state.noted_before,
            unresolved=state.unresolved, durable_epoch=state.durable_epoch,
            durable_sequence=state.durable_sequence)
        self._released.pop(source_id, None)
        if not self._durably_covered(released):
            while len(self._released) >= self.limits.maximum_released_sources:
                # Hard bound: the oldest entry falls back to its durable
                # watermark (a possible duplicate envelope or repeated gap
                # report on reactivation, never unreported loss).
                del self._released[next(iter(self._released))]
            self._released[source_id] = released
        return gaps

    def acknowledge_persisted(self, source_id: UUID, mark: CommittedWatermark) -> None:
        """Record that the durable recording layer persisted ``mark``.

        The durable consumer calls this after it durably records a drained
        unit (the same watermark it will later return from
        ``committed_watermark``).  It changes no flow state or gap; it only
        lets a released source's kept continuity be dropped once the durable
        watermark covers it, because only then does a reactivated source
        resume from that watermark without enqueueing a unit twice.  An
        acknowledgement for another node or an unknown source is ignored.
        """
        if not isinstance(source_id, UUID) or not isinstance(mark, CommittedWatermark):
            raise ValueError("invalid durable persistence acknowledgement")
        with self._lock:
            state = self._sources.get(source_id) or self._released.get(source_id)
            if state is None or state.node_id != mark.node_id:
                return
            position = (mark.capture_epoch, mark.sequence)
            if (state.durable_sequence is None
                    or position > (state.durable_epoch, state.durable_sequence)):
                state.durable_epoch, state.durable_sequence = position
            if (self._released.get(source_id) is state
                    and self._durably_covered(state)):
                del self._released[source_id]

    def _forget_node_locked(self, node_id: UUID) -> tuple[GapEvent, ...]:
        self._nodes.pop(node_id, None)
        for source_id in [source for source, state in self._released.items()
                          if state.node_id == node_id]:
            del self._released[source_id]
        owned = [source for source, state in self._sources.items()
                 if state.node_id == node_id]
        pending = []
        for source_id in owned:
            pending.extend(self._sources.pop(source_id).gaps)
        return tuple(pending)

    def forget_source(self, source_id: UUID) -> tuple[GapEvent, ...]:
        """Release one source slot after durable deactivation/replacement.

        The active-source limit bounds *active* sources, not lifetime source
        identities, so a deactivated source must free its slot without
        discarding continuity of the node's other sources.  Undrained gaps
        are returned so the caller can persist them; nothing is dropped
        silently.  The authorizer must already refuse the source.  A
        deactivation committed through ``authorization_change`` releases the
        slot there, atomically with the commit.
        """
        if not isinstance(source_id, UUID):
            raise ValueError("invalid agent source identity")
        with self._lock:
            return self._forget_source_locked(source_id)

    def forget_node(self, node_id: UUID) -> tuple[GapEvent, ...]:
        """Drop state after durable revocation/removal; returns undrained gaps.

        Like a revocation committed through ``authorization_change``, this
        forgets the node's session grant, every source it owns (with their
        sequence/epoch/capture-clock watermarks) and the ingest queue's rate
        window for the node.  The rate window is discarded while this
        tracker's lock is held (tracker, then queue: the same lock order as
        ``receive``), so no waiting attempt can observe the forgotten node
        with its old rate/clock state still present, and a re-enrolled node
        with the same UUID is never refused ``rate_limit`` or
        ``clock_regression`` because of the previous credential's window.
        The authorizer must already refuse the node.
        """
        if not isinstance(node_id, UUID):
            raise ValueError("invalid agent node identity")
        with self._lock:
            self._ingest.forget_revoked_node(node_id)
            return self._forget_node_locked(node_id)
