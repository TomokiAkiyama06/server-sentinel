"""Authorization-bound demand lifecycle for future browser live transports.

This module deliberately owns no route, socket, manifest, codec, or protocol.
Like ``SourcePipeline``, one scheduler thread owns each manager and all sources
registered with it.  A future authorized human route must construct
``LiveAccess`` only after resolving the application principal and must validate
that access on every media request through the injected validator.
"""

from dataclasses import dataclass
from typing import Callable, Protocol
from uuid import UUID, uuid4


class LiveViewerSource(Protocol):
    """Narrow part of ``SourcePipeline`` required by live sessions."""

    source_id: UUID

    def add_viewer(self, subscriber_id: UUID) -> None:
        ...

    def remove_viewer(self, subscriber_id: UUID) -> bool:
        """Remove demand, returning false when cleanup remains incomplete."""
        ...


@dataclass(frozen=True)
class LiveAccess:
    """A route-authenticated application principal at one auth revision."""

    principal_id: UUID
    authorization_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, UUID):
            raise ValueError("principal_id must be a UUID")
        if (type(self.authorization_revision) is not int
                or self.authorization_revision < 0):
            raise ValueError("authorization_revision must be nonnegative")


LiveAccessValidator = Callable[[LiveAccess, UUID], bool]


@dataclass(frozen=True)
class LiveSessionLimits:
    maximum_total_viewers: int
    maximum_viewers_per_source: int

    def __post_init__(self) -> None:
        for name in ("maximum_total_viewers", "maximum_viewers_per_source"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.maximum_viewers_per_source > self.maximum_total_viewers:
            raise ValueError("per-source viewer limit cannot exceed total limit")


@dataclass(frozen=True)
class LiveSession:
    """Non-secret handle metadata safe for the authorized caller."""

    session_id: UUID
    source_id: UUID


@dataclass(frozen=True)
class LiveSessionStatus:
    """Aggregate operational status without principal or session identities."""

    active_viewers: int
    active_sources: int
    cleanup_failures: int


class LiveSessionUnavailable(Exception):
    """Generic denial which does not reveal whether a session exists."""


class LiveSessionCapacityExceeded(Exception):
    """The explicitly configured live viewer capacity is exhausted."""


@dataclass
class _Session:
    access: LiveAccess
    source: LiveViewerSource
    cleanup_failed: bool = False


class LiveViewerSessions:
    """Bind authenticated principals to bounded internal viewer demand.

    ``validator`` must consult current authorization state.  It is called when
    opening a session and again on every caller-facing lookup/close, so a grant
    or session identifier is never sufficient by itself.  Transport disconnect
    and principal revocation use their dedicated trusted cleanup methods.

    Methods are intentionally synchronous and lock-free because ``SourcePipeline``
    is scheduler-thread confined.  Network handlers must dispatch all calls to
    that owner rather than invoke this manager concurrently.
    """

    def __init__(self, limits: LiveSessionLimits, validator: LiveAccessValidator,
                 *, session_id_factory: Callable[[], UUID] = uuid4) -> None:
        if not isinstance(limits, LiveSessionLimits):
            raise ValueError("limits must be LiveSessionLimits")
        if not callable(validator) or not callable(session_id_factory):
            raise ValueError("validator and session_id_factory must be callable")
        self._limits = limits
        self._validator = validator
        self._session_id_factory = session_id_factory
        self._sessions: dict[UUID, _Session] = {}

    def open(self, access: LiveAccess, source: LiveViewerSource) -> LiveSession:
        source_id = self._source_id(source)
        self._require_current_access(access, source_id)
        if len(self._sessions) >= self._limits.maximum_total_viewers:
            raise LiveSessionCapacityExceeded("live viewer capacity exceeded")
        source_sessions = self._for_source(source_id)
        if len(source_sessions) >= self._limits.maximum_viewers_per_source:
            raise LiveSessionCapacityExceeded("live viewer capacity exceeded")
        if any(session.source is not source for session in source_sessions):
            # Do not attach a viewer to two generations for one logical source.
            raise LiveSessionUnavailable("live session unavailable")

        session_id = self._session_id_factory()
        if not isinstance(session_id, UUID) or session_id in self._sessions:
            raise RuntimeError("session identifier allocation failed")
        # SourcePipeline starts viewer-only work here.  Publish the session only
        # after that operation succeeds, so partial opens never consume capacity.
        source.add_viewer(session_id)
        self._sessions[session_id] = _Session(access, source)
        return LiveSession(session_id, source_id)

    def require(self, access: LiveAccess, session_id: UUID) -> LiveSession:
        session = self._sessions.get(session_id)
        if session is None or session.access != access:
            raise LiveSessionUnavailable("live session unavailable")
        if session.cleanup_failed:
            # A close/revocation already began. Never restore media access just
            # because cleanup failed; retry the idempotent source removal and
            # keep returning the same generic unavailable result.
            self._cleanup(session_id, session)
            raise LiveSessionUnavailable("live session unavailable")
        source_id = self._source_id(session.source)
        try:
            self._require_current_access(access, source_id)
        except LiveSessionUnavailable:
            # Prompt revocation also tears down demand.  Cleanup failures remain
            # visible and retryable without restoring access.
            self._cleanup(session_id, session)
            raise
        return LiveSession(session_id, source_id)

    def close(self, access: LiveAccess, session_id: UUID) -> None:
        self.require(access, session_id)
        session = self._sessions[session_id]
        if not self._cleanup(session_id, session):
            raise RuntimeError("live viewer cleanup failed")

    def disconnect(self, session_id: UUID) -> bool:
        """Release a session after a trusted transport disconnect notification."""
        session = self._sessions.get(session_id)
        return False if session is None else self._cleanup(session_id, session)

    def revoke_principal(self, principal_id: UUID) -> int:
        """Best-effort cleanup for all sessions of a newly revoked principal.

        Returns the number fully removed. Failed removals stay visible through
        ``status.cleanup_failures`` and may be retried with ``disconnect``.
        """
        if not isinstance(principal_id, UUID):
            raise ValueError("principal_id must be a UUID")
        targets = [(session_id, session) for session_id, session in self._sessions.items()
                   if session.access.principal_id == principal_id]
        return sum(self._cleanup(session_id, session)
                   for session_id, session in targets)

    @property
    def status(self) -> LiveSessionStatus:
        return LiveSessionStatus(
            active_viewers=len(self._sessions),
            active_sources=len({self._source_id(item.source)
                                for item in self._sessions.values()}),
            cleanup_failures=sum(item.cleanup_failed
                                 for item in self._sessions.values()),
        )

    def _require_current_access(self, access: LiveAccess, source_id: UUID) -> None:
        if not isinstance(access, LiveAccess):
            raise LiveSessionUnavailable("live session unavailable")
        try:
            allowed = self._validator(access, source_id)
        except Exception:
            allowed = False
        if allowed is not True:
            raise LiveSessionUnavailable("live session unavailable")

    @staticmethod
    def _source_id(source: LiveViewerSource) -> UUID:
        value = getattr(source, "source_id", None)
        if not isinstance(value, UUID):
            raise ValueError("source_id must be a UUID")
        return value

    def _for_source(self, source_id: UUID) -> list[_Session]:
        return [session for session in self._sessions.values()
                if self._source_id(session.source) == source_id]

    def _cleanup(self, session_id: UUID, session: _Session) -> bool:
        try:
            removed = session.source.remove_viewer(session_id)
        except Exception:
            session.cleanup_failed = True
            return False
        # ``SourcePipeline`` records adapter-close errors in its status rather
        # than raising. Treat every non-true result as incomplete so the
        # session remains unavailable, observable, and retryable.
        if removed is not True:
            session.cleanup_failed = True
            return False
        self._sessions.pop(session_id, None)
        return True
