"""Bounded local UVC preview frames behind authorized live viewer sessions.

``LocalPreviewHub.on_frame`` is the ``LocalUvcAdapter`` frame sink.  It runs on
per-source capture worker threads and keeps at most one latest frame per
source, and only while that source has live viewer demand: with zero viewers
the frame is dropped immediately, so no decoded-frame history exists.

``AuthorizedLocalPreview`` is the only way to read a frame.  Every open and
every read goes through ``LiveViewerSessions``, whose validator re-checks the
principal's current ``live:view`` grant, so possession of a session identifier
is never sufficient.  No route, socket, codec or media URL exists here; the
human surface stays closed until the authorized viewer route lands (#10/#19).
"""

from dataclasses import dataclass
import threading
from uuid import UUID

from .sessions import (
    LiveAccess, LiveAccessValidator, LiveSession, LiveSessionLimits,
    LiveSessionUnavailable, LiveViewerSessions,
)


DEFAULT_MAX_FRAME_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class PreviewFrame:
    """One captured video frame; carries no device or identity evidence."""

    sequence: int
    data: bytes


@dataclass(frozen=True)
class LocalPreviewStatus:
    sources: int
    viewers: int
    retained_bytes: int
    oversized_frames: int
    invalid_frames: int


class _PreviewSource:
    """The ``LiveViewerSource`` for one logical local source."""

    def __init__(self, hub: "LocalPreviewHub", source_id: UUID) -> None:
        self.source_id = source_id
        self._hub = hub
        self.viewers: set[UUID] = set()
        self.latest: PreviewFrame | None = None
        self.sequence = 0
        # Cleared by any non-online camera transition: a retained frame from
        # before a disconnect or capture failure is never served as live.
        self.live = True

    def add_viewer(self, subscriber_id: UUID) -> None:
        with self._hub._lock:
            self.viewers.add(subscriber_id)

    def remove_viewer(self, subscriber_id: UUID) -> bool:
        with self._hub._lock:
            self.viewers.discard(subscriber_id)
            if not self.viewers:
                # Zero subscribers: release the retained frame immediately.
                self.latest = None
        return True


class LocalPreviewHub:
    """Thread-safe latest-frame slots for the configured local sources."""

    def __init__(self, source_ids=(), *, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES):
        if type(max_frame_bytes) is not int or not 1 <= max_frame_bytes <= 64 * 1024 * 1024:
            raise ValueError("preview frame bound is invalid")
        self._lock = threading.Lock()
        self._max_frame_bytes = max_frame_bytes
        self._sources: dict[UUID, _PreviewSource] = {}
        self._oversized = 0
        self._invalid = 0
        for source_id in source_ids:
            if not isinstance(source_id, UUID):
                raise ValueError("preview source identity is invalid")
            self._sources[source_id] = _PreviewSource(self, source_id)

    def source(self, source_id: UUID) -> _PreviewSource:
        source = self._sources.get(source_id) if isinstance(source_id, UUID) else None
        if source is None:
            raise LiveSessionUnavailable("live session unavailable")
        return source

    def on_frame(self, source_id: UUID, frame) -> None:
        """Adapter frame sink; never raises into the capture worker."""
        source = self._sources.get(source_id) if isinstance(source_id, UUID) else None
        if source is None:
            return
        data = getattr(frame, "data", None)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            with self._lock:
                self._invalid += 1
            return
        with self._lock:
            if not source.viewers or not source.live:
                return
            if len(data) > self._max_frame_bytes:
                self._oversized += 1
                return
            source.sequence += 1
            source.latest = PreviewFrame(source.sequence, bytes(data))

    def on_health(self, event) -> None:
        """Camera health sink; never raises into the capture worker.

        Only an ``online`` transition accepts frames again. Every other state
        (offline, degraded, manual intervention, unknown) drops the retained
        frame at once, so a reader never receives a pre-loss image that it
        cannot distinguish from current live video.
        """
        source_id = getattr(event, "source_id", None)
        source = self._sources.get(source_id) if isinstance(source_id, UUID) else None
        if source is None:
            return
        online = getattr(getattr(event, "state", None), "value", None) == "online"
        with self._lock:
            source.live = online
            if not online:
                source.latest = None

    def latest(self, source_id: UUID, after_sequence: int = 0) -> PreviewFrame | None:
        with self._lock:
            frame = self.source(source_id).latest
            if frame is None or frame.sequence <= after_sequence:
                return None
            return frame

    def clear(self) -> None:
        """Drop retained frames, e.g. when capture stops."""
        with self._lock:
            for source in self._sources.values():
                source.latest = None

    @property
    def status(self) -> LocalPreviewStatus:
        with self._lock:
            return LocalPreviewStatus(
                len(self._sources),
                sum(len(source.viewers) for source in self._sources.values()),
                sum(len(source.latest.data) for source in self._sources.values()
                    if source.latest is not None),
                self._oversized, self._invalid,
            )


class AuthorizedLocalPreview:
    """Authorization-bound local preview; confined to one scheduler thread."""

    def __init__(self, hub: LocalPreviewHub, limits: LiveSessionLimits,
                 validator: LiveAccessValidator) -> None:
        if not isinstance(hub, LocalPreviewHub):
            raise ValueError("preview hub is required")
        self.hub = hub
        self.sessions = LiveViewerSessions(limits, validator)

    def open(self, access: LiveAccess, source_id: UUID) -> LiveSession:
        # An unknown source and a denied principal see the same generic refusal,
        # so the refusal does not reveal which local sources are configured.
        source = self.hub.source(source_id)
        return self.sessions.open(access, source)

    def read(self, access: LiveAccess, session_id: UUID,
             after_sequence: int = 0) -> PreviewFrame | None:
        """Return a newer frame only while the session's grant is current."""
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("after_sequence must be a nonnegative integer")
        session = self.sessions.require(access, session_id)
        return self.hub.latest(session.source_id, after_sequence)

    def close(self, access: LiveAccess, session_id: UUID) -> None:
        self.sessions.close(access, session_id)

    def disconnect(self, session_id: UUID) -> bool:
        return self.sessions.disconnect(session_id)

    def revoke_principal(self, principal_id: UUID) -> int:
        return self.sessions.revoke_principal(principal_id)
