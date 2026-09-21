"""Bounded, transport-neutral admission for authenticated agent ingest.

This module opens no socket and implements neither pairing nor cryptography.  A
future dedicated LAN listener must authenticate its session before passing only
narrow, opaque agent messages here.  Human/dashboard routes never use this
boundary.
"""

from collections import deque
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Callable, Protocol
from uuid import UUID


class AgentAction(str, Enum):
    """The only action categories the transport boundary may submit."""

    HEARTBEAT = "heartbeat"
    MEDIA = "media"


class IngestOutcome(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    BACKPRESSURED = "backpressured"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True)
class IngestLimits:
    """Deployment-selected bounds; this module supplies no network defaults."""

    maximum_message_bytes: int
    maximum_queued_messages: int
    maximum_queued_bytes: int
    maximum_messages_per_window: int
    rate_window_ns: int
    maximum_tracked_rate_windows: int = 1024

    def __post_init__(self) -> None:
        values = tuple(getattr(self, field) for field in self.__dataclass_fields__)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("ingest limits must be positive integers")
        if self.maximum_queued_bytes < self.maximum_message_bytes:
            raise ValueError("ingest byte queue must hold one maximum message")


@dataclass(frozen=True)
class AgentMessage:
    """An opaque, bounded agent action attributed to one node/source pair.

    The payload has no filesystem path, codec, URL, or human identity field.
    Frame/container parsing remains a transport/recording concern after
    authenticated bounded admission.
    """

    node_id: UUID
    source_id: UUID
    action: AgentAction
    sequence: int
    payload: bytes

    def __post_init__(self) -> None:
        if (not isinstance(self.node_id, UUID) or not isinstance(self.source_id, UUID)
                or not isinstance(self.action, AgentAction)
                or type(self.sequence) is not int or self.sequence < 0
                or type(self.payload) is not bytes):
            raise ValueError("invalid agent ingest message")


class IngestAuthorizer(Protocol):
    """Pairing/session integration must fail closed through these checks."""

    def require_node(self, node_id: UUID) -> None:
        ...

    def require_source(self, node_id: UUID, source_id: UUID) -> None:
        ...


class DenyIngestAuthorizer:
    """Explicit default for bootstrap/test composition before pairing exists."""

    def require_node(self, node_id: UUID) -> None:
        raise PermissionError("agent session is not authorized")

    def require_source(self, node_id: UUID, source_id: UUID) -> None:
        raise PermissionError("agent source is not authorized")


@dataclass(frozen=True)
class IngestAdmission:
    outcome: IngestOutcome
    reason: str | None
    queued_messages: int
    queued_bytes: int


@dataclass(frozen=True)
class IngestSnapshot:
    """Admission pressure only; it never represents camera or node health."""

    queued_messages: int
    queued_bytes: int
    rejected: int
    backpressured: int
    rate_limited: int
    tracked_rate_windows: int


class AgentIngestQueue:
    """Thread-safe bounded queue after injected node/source authorization.

    A refusal never evicts accepted media, silently reports success, or changes
    source/node health.  The future listener owns pre-read network byte limits;
    this domain object bounds what may remain in Main Server memory afterwards.
    """

    def __init__(self, limits: IngestLimits, authorizer: IngestAuthorizer,
                 *, clock_ns: Callable[[], int]) -> None:
        if (not isinstance(limits, IngestLimits)
                or not callable(getattr(authorizer, "require_node", None))
                or not callable(getattr(authorizer, "require_source", None))
                or not callable(clock_ns)):
            raise ValueError("invalid ingest boundary dependencies")
        self.limits = limits
        self._authorizer = authorizer
        self._clock_ns = clock_ns
        self._queue: deque[AgentMessage] = deque()
        self._queued_bytes = 0
        self._windows: dict[UUID, tuple[int, int]] = {}
        self._rejected = self._backpressured = self._rate_limited = 0
        self._lock = Lock()

    def _retire_expired_windows(self, now: int) -> None:
        """Drop inactive rate state when a new authenticated node needs room.

        The map is always hard-bounded.  Cleanup is deferred until capacity is
        needed so the ordinary per-message path does not scan all tracked
        nodes.  A start time ahead of ``now`` is retained and therefore fails
        closed if the injected monotonic clock regresses.
        """
        expired = tuple(
            node_id for node_id, (start, _) in self._windows.items()
            if now >= start and now - start >= self.limits.rate_window_ns
        )
        for node_id in expired:
            del self._windows[node_id]

    def _admission(self, outcome: IngestOutcome, reason: str | None) -> IngestAdmission:
        return IngestAdmission(outcome, reason, len(self._queue), self._queued_bytes)

    def submit(self, message: AgentMessage) -> IngestAdmission:
        if not isinstance(message, AgentMessage):
            raise ValueError("invalid agent ingest message")
        try:
            self._authorizer.require_node(message.node_id)
            self._authorizer.require_source(message.node_id, message.source_id)
        except PermissionError:
            with self._lock:
                self._rejected += 1
                return self._admission(IngestOutcome.REJECTED, "unauthorized")

        now = self._clock_ns()
        if type(now) is not int or now < 0:
            raise ValueError("ingest clock must return nonnegative integer nanoseconds")
        size = len(message.payload)
        with self._lock:
            window = self._windows.get(message.node_id)
            if window is None:
                if len(self._windows) >= self.limits.maximum_tracked_rate_windows:
                    self._retire_expired_windows(now)
                if len(self._windows) >= self.limits.maximum_tracked_rate_windows:
                    self._rate_limited += 1
                    return self._admission(IngestOutcome.RATE_LIMITED,
                                           "rate_window_capacity")
                start, count = now, 0
            else:
                start, count = window
            if now < start:
                self._rejected += 1
                return self._admission(IngestOutcome.REJECTED, "clock_regression")
            if now - start >= self.limits.rate_window_ns:
                start, count = now, 0
            if count >= self.limits.maximum_messages_per_window:
                self._windows[message.node_id] = (start, count)
                self._rate_limited += 1
                return self._admission(IngestOutcome.RATE_LIMITED, "rate_limit")
            # Every authenticated attempt consumes rate budget, including an
            # oversized message or a queue-pressure refusal. This prevents a
            # sender from repeatedly making bounded-admission work forever
            # while preserving the first refusal's specific reason.
            self._windows[message.node_id] = (start, count + 1)
            if size > self.limits.maximum_message_bytes:
                self._rejected += 1
                return self._admission(IngestOutcome.REJECTED, "message_too_large")
            if (len(self._queue) >= self.limits.maximum_queued_messages
                    or self._queued_bytes + size > self.limits.maximum_queued_bytes):
                self._backpressured += 1
                return self._admission(IngestOutcome.BACKPRESSURED, "queue_limit")
            self._queue.append(message)
            self._queued_bytes += size
            return self._admission(IngestOutcome.ACCEPTED, None)

    def forget_revoked_node(self, node_id: UUID) -> None:
        """Forget rate state after durable revocation or node removal."""
        if not isinstance(node_id, UUID):
            raise ValueError("invalid agent node identity")
        with self._lock:
            self._windows.pop(node_id, None)

    def drain(self, maximum_messages: int) -> tuple[AgentMessage, ...]:
        """Remove a bounded batch for one downstream consumer attempt."""
        if type(maximum_messages) is not int or maximum_messages <= 0:
            raise ValueError("drain maximum must be a positive integer")
        with self._lock:
            count = min(maximum_messages, len(self._queue))
            result = tuple(self._queue.popleft() for _ in range(count))
            self._queued_bytes -= sum(len(item.payload) for item in result)
            return result

    def snapshot(self) -> IngestSnapshot:
        with self._lock:
            return IngestSnapshot(len(self._queue), self._queued_bytes, self._rejected,
                                  self._backpressured, self._rate_limited,
                                  len(self._windows))
