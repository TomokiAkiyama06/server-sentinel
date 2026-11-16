"""Newest remote live preview frame per source, in memory only (Issue #14).

Owner decision 2026-11-12 ("option A"): before any Main-side recording of a
``remote_agent`` source exists, its Agent sends JPEG frames of each approved
camera over the capture ingest session (``LIVE_FRAME``, at most 5 per second
per source). The capture ingest listener (``ingest_server``) authorizes each
frame and hands it to ``RemotePreviewHub.publish``; the S7 frame pull
(``frame_pull.LiveFrameService``) serves it, through the same live sessions
and ``live:view`` checks as a local source. Nothing here is written to disk
or the database, and nothing is acknowledged to the Agent.

Retention (bounded, like ``LocalPreviewHub``):

* a frame is kept only while its source has live viewer demand, and only the
  newest one; with zero viewers a published frame is dropped at once, so no
  frame history exists;
* per ingest session (node and generation) only the sources it sent are
  tracked, at most ``maximum_sources_per_node`` (4) of them: for each, the
  receive time (no media) that makes the source ``online`` in the live list;
  a receive time older than ``fresh_seconds`` gives its place up to a new
  source of the node;
* a frame or receive time older than ``fresh_seconds`` (5 s, a little over
  ten frame intervals at the Agent's 5 fps and three at a 1 fps camera) is not
  live: it is never served and the source is listed ``offline``;
* when the node's session ends (closed, idle, revoked at the next frame,
  superseded by a newer session, the listener stopped) its frames and receive
  times are dropped at once (``close_node``); a newer session of the node
  replaces the older one's entirely (``open_node``).

Thread model: ``publish``/``open_node``/``close_node`` run on ingest session
threads, the viewer side on the frame pull's executor; one lock guards the
state, and nothing here calls back out while holding it.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Callable
from uuid import UUID

from .local_preview import PreviewFrame
from .sessions import LiveSessionUnavailable


DEFAULT_FRESH_SECONDS = 5.0
DEFAULT_MAXIMUM_SOURCES_PER_NODE = 4
DEFAULT_MAX_FRAME_BYTES = 1_048_576
# Viewer slots (sources with a live session) at once; the frame pull admits
# at most 4 sessions in total, so this is never reached in normal use.
DEFAULT_MAXIMUM_VIEWED_SOURCES = 16


@dataclass(frozen=True)
class RemotePreviewStatus:
    """Value-free counts only."""

    nodes: int
    tracked_sources: int
    viewed_sources: int
    viewers: int
    retained_bytes: int
    refused_frames: int


@dataclass
class _Received:
    node_id: UUID
    generation: int
    at: float


@dataclass
class _Retained:
    node_id: UUID
    generation: int
    at: float
    frame: PreviewFrame


class _RemoteSource:
    """The ``LiveViewerSource`` of one remote source (exists only while viewed)."""

    def __init__(self, hub: "RemotePreviewHub", source_id: UUID) -> None:
        self.source_id = source_id
        self._hub = hub
        self.viewers: set[UUID] = set()
        self.retained: _Retained | None = None
        # Never reset while the slot exists, so a viewer's ``after`` stays
        # meaningful across a dropped frame or a new ingest session.
        self.sequence = 0

    def add_viewer(self, subscriber_id: UUID) -> None:
        with self._hub._lock:
            if self._hub._closed:
                raise LiveSessionUnavailable("live session unavailable")
            self.viewers.add(subscriber_id)

    def remove_viewer(self, subscriber_id: UUID) -> bool:
        with self._hub._lock:
            self.viewers.discard(subscriber_id)
            if not self.viewers:
                # Zero subscribers: nothing is retained for this source.
                self.retained = None
                if self._hub._slots.get(self.source_id) is self:
                    del self._hub._slots[self.source_id]
        return True


class RemotePreviewHub:
    """Thread-safe newest-frame slots for remote ``remote_agent`` sources."""

    def __init__(self, *, fresh_seconds: float = DEFAULT_FRESH_SECONDS,
                 maximum_sources_per_node: int = DEFAULT_MAXIMUM_SOURCES_PER_NODE,
                 max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
                 maximum_viewed_sources: int = DEFAULT_MAXIMUM_VIEWED_SOURCES,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if (isinstance(fresh_seconds, bool) or not isinstance(fresh_seconds, (int, float))
                or not 0 < fresh_seconds <= 60
                or any(type(value) is not int or value <= 0
                       for value in (maximum_sources_per_node, max_frame_bytes,
                                     maximum_viewed_sources))
                or max_frame_bytes > 8 * 1024 * 1024 or not callable(monotonic)):
            raise ValueError("remote preview bounds are invalid")
        self._lock = threading.Lock()
        self._fresh = float(fresh_seconds)
        self._per_node = maximum_sources_per_node
        self._max_frame_bytes = max_frame_bytes
        self._maximum_viewed = maximum_viewed_sources
        self._monotonic = monotonic
        # node -> current ingest session generation.
        self._nodes: dict[UUID, int] = {}
        # source -> its latest receive (no media), for current sessions only.
        self._received: dict[UUID, _Received] = {}
        # source -> viewer slot (only while it has, or is getting, viewers).
        self._slots: dict[UUID, _RemoteSource] = {}
        self._refused = 0
        self._closed = False

    # -- ingest side (capture ingest session threads) ------------------------

    def open_node(self, node_id: UUID, generation: int) -> None:
        """A newer ingest session of ``node_id``: drop everything of older ones."""
        if not isinstance(node_id, UUID) or type(generation) is not int:
            return
        with self._lock:
            if self._closed:
                return
            current = self._nodes.get(node_id)
            if current is not None and current >= generation:
                return
            self._nodes[node_id] = generation
            self._drop_locked(node_id)

    def close_node(self, node_id: UUID, generation: int) -> None:
        """That session ended: its frames and receive times go at once."""
        if not isinstance(node_id, UUID):
            return
        with self._lock:
            if self._nodes.get(node_id) != generation:
                return
            del self._nodes[node_id]
            self._drop_locked(node_id)

    def publish(self, node_id: UUID, generation: int, source_id: UUID, jpeg: bytes) -> bool:
        """Keep ``jpeg`` as the newest frame of ``source_id``; never raises.

        The caller (the ingest listener) has authorized the source for this
        node. Refused (False): a session that is not the node's current one,
        a source beyond the node's ``maximum_sources_per_node``, or an
        oversized frame. Accepted without viewers, only the receive time is
        kept, never the bytes.
        """
        if (not isinstance(node_id, UUID) or not isinstance(source_id, UUID)
                or type(generation) is not int or not isinstance(jpeg, bytes)):
            return False
        now = self._monotonic()
        with self._lock:
            if (self._closed or self._nodes.get(node_id) != generation
                    or len(jpeg) > self._max_frame_bytes):
                self._refused += 1
                return False
            received = self._received.get(source_id)
            if received is None or received.node_id != node_id:
                # A source of this node that sent nothing within the
                # freshness bound no longer holds one of its places (PR #416
                # review): the count shrinks during a session too.
                for key in [key for key, item in self._received.items()
                            if item.node_id == node_id
                            and not self._current_locked(node_id, item.generation, item.at, now)]:
                    del self._received[key]
                tracked = sum(item.node_id == node_id for item in self._received.values())
                if tracked >= self._per_node:
                    self._refused += 1
                    return False
            self._received[source_id] = _Received(node_id, generation, now)
            slot = self._slots.get(source_id)
            if slot is not None and slot.viewers:
                slot.sequence += 1
                slot.retained = _Retained(node_id, generation, now,
                                          PreviewFrame(slot.sequence, jpeg))
            return True

    def clear(self) -> None:
        """The listener stopped: drop everything and accept nothing more."""
        with self._lock:
            self._closed = True
            self._nodes.clear()
            self._received.clear()
            for slot in self._slots.values():
                slot.retained = None

    def _drop_locked(self, node_id: UUID) -> None:
        for source_id in [source for source, item in self._received.items()
                          if item.node_id == node_id]:
            del self._received[source_id]
        for slot in self._slots.values():
            if slot.retained is not None and slot.retained.node_id == node_id:
                slot.retained = None

    def _current_locked(self, node_id: UUID, generation: int, at: float, now: float) -> bool:
        return (self._nodes.get(node_id) == generation
                and at <= now and now - at <= self._fresh)

    # -- viewer side (the frame pull's executor) -----------------------------

    def receiving(self, source_id: UUID, node_id: UUID) -> bool:
        """Whether ``node_id``'s current session sent a frame of ``source_id`` recently."""
        if not isinstance(source_id, UUID) or not isinstance(node_id, UUID):
            return False
        now = self._monotonic()
        with self._lock:
            received = self._received.get(source_id)
            return (not self._closed and received is not None and received.node_id == node_id
                    and self._current_locked(node_id, received.generation, received.at, now))

    def source(self, source_id: UUID) -> _RemoteSource:
        """The viewer slot of ``source_id``; the caller authorized the source."""
        if not isinstance(source_id, UUID):
            raise LiveSessionUnavailable("live session unavailable")
        with self._lock:
            if self._closed:
                raise LiveSessionUnavailable("live session unavailable")
            slot = self._slots.get(source_id)
            if slot is None:
                if len(self._slots) >= self._maximum_viewed:
                    # Reclaim slots left without viewers by a failed open.
                    for key in [key for key, item in self._slots.items() if not item.viewers]:
                        del self._slots[key]
                if len(self._slots) >= self._maximum_viewed:
                    raise LiveSessionUnavailable("live session unavailable")
                slot = self._slots[source_id] = _RemoteSource(self, source_id)
            return slot

    def latest(self, source_id: UUID, after_sequence: int = 0) -> PreviewFrame | None:
        """The newest frame after ``after_sequence``, only while it is live.

        Live: sent by the node's current ingest session within
        ``fresh_seconds``. An older frame is never served as live.
        """
        now = self._monotonic()
        with self._lock:
            slot = self._slots.get(source_id) if isinstance(source_id, UUID) else None
            retained = slot.retained if slot is not None else None
            if (self._closed or retained is None
                    or not self._current_locked(retained.node_id, retained.generation,
                                                retained.at, now)
                    or retained.frame.sequence <= after_sequence):
                return None
            return retained.frame

    @property
    def status(self) -> RemotePreviewStatus:
        with self._lock:
            return RemotePreviewStatus(
                len(self._nodes), len(self._received), len(self._slots),
                sum(len(slot.viewers) for slot in self._slots.values()),
                sum(len(slot.retained.frame.data) for slot in self._slots.values()
                    if slot.retained is not None),
                self._refused)
