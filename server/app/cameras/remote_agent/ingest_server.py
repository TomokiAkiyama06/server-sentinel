"""The dedicated capture ingest listener of the Main Server (Issue #14).

It serves only the capture ingest wire protocol (``ingest_wire``) on its own
socket, separate from the human dashboard listener: there is no HTTP parser,
no route and no dashboard handler behind it, so a capture credential can
reach nothing but this protocol (SPECIFICATION §5.7). Every connection is
authenticated by ``ingest_tls`` (TLS 1.3 mTLS against the deployment CA plus
the pairing ledger's current record) and must negotiate ``INGEST_ALPN``. An
IP address never authenticates; the per-address handshake limit below only
bounds what an unauthenticated LAN host can occupy.

Bounds (ADR-0007 item 5, Issue #14):

* ``maximum_connections`` sockets at once, handshakes included; one more is
  closed at accept. ``maximum_handshakes_per_address`` handshakes in progress
  per peer address, and each handshake ends within the acceptor's timeout.
* One live session per node: a newer admitted session of the same node
  supersedes the older, whose socket is shut down (ADR-0007 item 2).
* Every frame length is checked before its body is read
  (``maximum_frame_bytes``); a session without a frame for
  ``idle_timeout_seconds`` is closed; every frame is charged to the node's
  rate budget (``AgentIngestQueue.charge_attempt``) and re-checks the ledger
  (``still_admitted``) before it is acted on, so a revocation ends the session
  at the next frame.

Live preview frames (``LIVE_FRAME``; Issue #14, Owner decision 2026-11-12,
option A) have their own bounds (``live_frames``): a body limit of
``MAXIMUM_LIVE_FRAME_BODY_BYTES`` applied from the header, the ledger
re-check like any frame, the camera registry's authorization of the source
for this node (cached 1 s) and their own token buckets (never the heartbeat
budget). An accepted frame replaces the source's newest frame in the
in-memory ``RemotePreviewHub`` and gets **no reply**: it is not stored, so
it is never acknowledged. A frame of a source the registry does not
authorize, or beyond the buckets, is dropped and counted
(``CaptureIngestStatus.live_frames_unauthorized`` / ``live_frames_dropped``)
and the session goes on (PR #416 review: an Agent sends every camera it
approved, which the Owner may not have created or may have disabled on the
Main). Only a malformed body (``live_frame_invalid``) or a flood, more than
ten times the node refill rate sustained (``rate_limited``), closes the
session. The session's frames are dropped from the hub when it ends or is
superseded.

Nothing is written to the database or the disk here: the pairing ledger and
the camera registry are only read (a staged renewal's promotion is the
ledger's own admitted write), and node health and live frames are kept in
memory (``node_health``, ``RemotePreviewHub``). ``stop`` therefore waits
for nothing: it stops accepting and shuts every socket down, and the
connection threads end on their own (Issue #383: it adds no bounded wait to
the stop budget).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import logging
import socket
import ssl
import threading
import time
from typing import Callable
from uuid import UUID

from app.logging import Event

from .ingest import AgentIngestQueue, IngestLimits
from .ingest_config import CaptureIngestLimits
from .ingest_tls import CaptureIngestAcceptor, IngestTlsError
from .ingest_wire import (
    INGEST_ALPN, MAXIMUM_LIVE_FRAME_BODY_BYTES, FrameType, PeerClosed, WireRefused, encode_frame,
    parse_heartbeat, parse_live_frame, read_frame,
)
from .live_frames import CachedLiveSources, LiveFrameBudget
from .node_health import CaptureNodeHealthRegistry


LOGGER = logging.getLogger("serversentinel.capture_ingest")
ACCEPT_POLL_SECONDS = 0.25
_ORDINARY_ENDS = frozenset({"peer_closed", "stopping", "superseded", "idle_timeout", "closed"})
# Refused connections by fixed category (PR #401 review): each category has
# its own count and its own value-free, rate-limited log event.
_REFUSAL_CATEGORIES = {
    "connection_limit": "connection_limit",
    "tls_handshake_failed": "handshake", "tls_session_failed": "handshake",
    "tls_version_refused": "handshake",
    "capture_node_certificate_invalid": "not_admitted",
    "capture_node_certificate_missing": "not_admitted",
    "capture_node_not_admitted": "not_admitted",
    "alpn_refused": "alpn",
}
_REFUSAL_EVENTS = {
    "connection_limit": Event.CAPTURE_INGEST_REFUSED_LIMIT,
    "handshake": Event.CAPTURE_INGEST_REFUSED_HANDSHAKE,
    "not_admitted": Event.CAPTURE_INGEST_REFUSED_NOT_ADMITTED,
    "alpn": Event.CAPTURE_INGEST_REFUSED_ALPN,
}
# Rate-check refusals (`AgentIngestQueue.charge_attempt`) by reason: a node
# without a live session here was replaced meanwhile, not rate limited.
_RATE_ENDS = {"rate_limit": "rate_limited", "rate_window_capacity": "rate_limited",
              "unauthorized": "superseded", "clock_regression": "clock_regression"}


@dataclass(frozen=True)
class CaptureIngestStatus:
    """Value-free listener status: a state word and counts only."""

    state: str
    open_connections: int
    refused_connections: int
    closed_sessions: int
    # Refused connections per fixed category (`connection_limit`,
    # `handshake`, `not_admitted`, `alpn`).
    refused_by_category: tuple[tuple[str, int], ...] = ()
    # Live preview frames (Issue #14): kept, dropped as unauthorized, and
    # dropped beyond the buckets or the hub's bounds.
    live_frames_accepted: int = 0
    live_frames_unauthorized: int = 0
    live_frames_dropped: int = 0


class _LiveNodes:
    """The ingest queue's node authorizer: a node with a live session here."""

    def __init__(self, server: "CaptureIngestServer"):
        self._server = server

    def require_node(self, node_id: UUID) -> None:
        if not self._server._is_live(node_id):
            raise PermissionError("capture node has no live ingest session")

    def require_source(self, node_id: UUID, source_id: UUID) -> None:
        # Version 1 carries no media, so no source is ever authorized here.
        raise PermissionError("capture ingest accepts no media yet")


def _abort(connection) -> None:
    """Wake a thread blocked on ``connection`` without racing its close.

    ``socket.socket.shutdown`` acts on the descriptor below a TLS socket, so
    another thread's blocking ``recv``/``send``/handshake returns at once;
    only the owning thread closes the socket.
    """
    try:
        socket.socket.shutdown(connection, socket.SHUT_RDWR)
    except OSError:
        pass


def _close(connection) -> None:
    try:
        connection.close()
    except OSError:
        pass


class CaptureIngestServer:
    def __init__(self, listener: socket.socket, acceptor: CaptureIngestAcceptor, *,
                 limits: CaptureIngestLimits | None = None,
                 registry: CaptureNodeHealthRegistry | None = None,
                 utc: Callable[[], float] = time.time,
                 monotonic_ns: Callable[[], int] = time.monotonic_ns,
                 live_preview=None,
                 live_sources: Callable[[UUID, UUID], bool] | None = None):
        from app.media.live.remote_preview import RemotePreviewHub
        limits = limits or CaptureIngestLimits()
        if (not isinstance(listener, socket.socket) or not isinstance(acceptor, CaptureIngestAcceptor)
                or not isinstance(limits, CaptureIngestLimits) or not callable(utc)
                or (live_preview is not None and not isinstance(live_preview, RemotePreviewHub))
                or (live_sources is not None and not callable(live_sources))):
            raise ValueError("invalid capture ingest dependencies")
        self.limits = limits
        # Issue #14 (option A): without both, every live frame is refused
        # `source_not_authorized` (fail closed).
        self.live_preview = live_preview
        self._live_sources = (None if live_sources is None else CachedLiveSources(
            live_sources, maximum_nodes=limits.maximum_nodes, clock_ns=monotonic_ns))
        self._live_budget = LiveFrameBudget(maximum_nodes=limits.maximum_nodes,
                                            clock_ns=monotonic_ns)
        self._live_counts = {"accepted": 0, "unauthorized": 0, "dropped": 0}
        self._frame_limits = {FrameType.LIVE_FRAME: MAXIMUM_LIVE_FRAME_BODY_BYTES}
        self.registry = registry or CaptureNodeHealthRegistry(
            maximum_nodes=limits.maximum_nodes,
            stale_after_seconds=limits.idle_timeout_seconds)
        self._listener = listener
        self._acceptor = acceptor
        self._utc = utc
        self._rate = AgentIngestQueue(
            IngestLimits(maximum_message_bytes=limits.maximum_frame_bytes,
                         maximum_queued_messages=1,
                         maximum_queued_bytes=limits.maximum_frame_bytes,
                         maximum_messages_per_window=limits.frames_per_second,
                         rate_window_ns=1_000_000_000,
                         maximum_tracked_rate_windows=limits.maximum_nodes),
            _LiveNodes(self), clock_ns=monotonic_ns)
        self._lock = threading.Lock()
        self._state = "stopped"
        self._connections: set = set()
        self._handshakes: dict[str, int] = {}
        self._live: dict[UUID, tuple[int, object]] = {}
        self._generation = 0
        self._refused = 0
        self._refused_by: dict[str, int] = {}
        self._closed = 0
        # The latest session end reasons (fixed words), bounded.
        self._reasons: deque[str] = deque(maxlen=32)
        self._threads: set[threading.Thread] = set()
        self._accept_thread: threading.Thread | None = None

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._state != "stopped" or self._accept_thread is not None:
                raise RuntimeError("capture ingest listener already started")
            self._state = "running"
            self._listener.settimeout(ACCEPT_POLL_SECONDS)
            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True,
                                                   name="capture-ingest-accept")
            self._accept_thread.start()
        LOGGER.info(Event.CAPTURE_INGEST_STARTED)

    def stop(self) -> None:
        """Stop accepting and shut every connection down; waits for nothing."""
        with self._lock:
            if self._state != "running":
                return
            self._state = "stopping"
            connections = tuple(self._connections)
        _abort(self._listener)
        for connection in connections:
            _abort(connection)
        if self.live_preview is not None:
            # No live frame outlives the listener, nor is one accepted after.
            self.live_preview.clear()
        LOGGER.info(Event.CAPTURE_INGEST_STOPPED)

    def join(self, timeout: float) -> bool:
        """Tests and diagnostics: wait until every thread ended; True if they did."""
        deadline = time.monotonic() + timeout
        threads = [self._accept_thread] if self._accept_thread is not None else []
        with self._lock:
            threads += list(self._threads)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in threads)

    def status(self) -> CaptureIngestStatus:
        with self._lock:
            return CaptureIngestStatus(self._state, len(self._connections), self._refused,
                                       self._closed, tuple(sorted(self._refused_by.items())),
                                       self._live_counts["accepted"],
                                       self._live_counts["unauthorized"],
                                       self._live_counts["dropped"])

    def last_close_reasons(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._reasons)

    def _stopping(self) -> bool:
        with self._lock:
            return self._state != "running"

    def _is_live(self, node_id: UUID) -> bool:
        with self._lock:
            return node_id in self._live

    # -- accept --------------------------------------------------------------

    def _accept_loop(self) -> None:
        try:
            while not self._stopping():
                try:
                    connection, peer = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stopping():
                        break
                    time.sleep(ACCEPT_POLL_SECONDS)
                    continue
                address = str(peer[0]) if isinstance(peer, tuple) and peer else ""
                with self._lock:
                    admitted = (self._state == "running"
                                and len(self._connections) < self.limits.maximum_connections
                                and self._handshakes.get(address, 0)
                                < self.limits.maximum_handshakes_per_address)
                    if admitted:
                        self._connections.add(connection)
                        self._handshakes[address] = self._handshakes.get(address, 0) + 1
                if not admitted:
                    self._count_refusal("connection_limit")
                    _close(connection)
                    continue
                try:
                    # Stop-and-wait over small frames: without this, Nagle
                    # and delayed ACK add ~40 ms per reply (Issue #369,
                    # ADR-0007); the Agent sets it on its side too.
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                thread = threading.Thread(target=self._serve, args=(connection, address),
                                          daemon=True, name="capture-ingest-session")
                with self._lock:
                    self._threads.add(thread)
                thread.start()
        finally:
            _close(self._listener)
            with self._lock:
                self._state = "stopped"

    # -- one connection ------------------------------------------------------

    def _count_refusal(self, reason: str) -> None:
        """Count a refused connection by category; log the first and every power of two.

        An unauthenticated LAN host can open connections as fast as it likes,
        so one log line per refusal would let it flood the journal. The
        acceptor's own per-refusal log is off (`log_refusals=False`); each
        category has its own event and running count, so the reason is kept
        without any value (PR #401 review).
        """
        category = _REFUSAL_CATEGORIES.get(reason, "handshake")
        with self._lock:
            self._refused += 1
            count = self._refused_by.get(category, 0) + 1
            self._refused_by[category] = count
        if count & (count - 1) == 0:
            LOGGER.warning(_REFUSAL_EVENTS[category], extra={"count": count})

    def _handshake_done(self, address: str) -> None:
        with self._lock:
            count = self._handshakes.get(address, 0) - 1
            if count > 0:
                self._handshakes[address] = count
            else:
                self._handshakes.pop(address, None)

    def _serve(self, connection: socket.socket, address: str) -> None:
        tracked = [connection]

        def wrapped(tls) -> None:
            # `wrap_socket` detached `connection`: track the TLS socket, so
            # `stop` can wake this handshake (Issue #14).
            with self._lock:
                self._connections.discard(connection)
                self._connections.add(tls)
                tracked[0] = tls
                stopping = self._state != "running"
            if stopping:
                _abort(tls)

        try:
            try:
                session = self._acceptor.accept(connection, on_wrapped=wrapped)
            except IngestTlsError as refused:
                self._count_refusal(refused.reason)
                return
            finally:
                self._handshake_done(address)
            tls = session.connection
            if tls.selected_alpn_protocol() != INGEST_ALPN:
                # Defense in depth: the production acceptor already refuses
                # it before the ledger (`required_alpn`).
                self._close_with(tls, "alpn_refused")
                self._count_refusal("alpn_refused")
                return
            self._session(session, tls)
        except Exception:
            # Never let a connection thread's failure reach the process; the
            # connection is closed below and counted.
            LOGGER.error(Event.CAPTURE_INGEST_SESSION_REFUSED)
        finally:
            _close(tracked[0])
            with self._lock:
                self._connections.discard(tracked[0])
                self._connections.discard(connection)
                self._threads.discard(threading.current_thread())

    def _session(self, session, tls: ssl.SSLSocket) -> None:
        node = session.identity.node_id
        # The replacement and the health registration are one step under this
        # lock (PR #401 Codex review): a concurrent admission of the same node
        # can then never register an older generation after a newer one, so
        # the newer session always wins. Lock order: this lock, then the
        # registry's (the registry never calls back here).
        with self._lock:
            if self._state != "running":
                return
            self._generation += 1
            generation = self._generation
            if not self.registry.connected(node, generation):
                registered = False
                previous = None
            else:
                registered = True
                previous = self._live.get(node)
                self._live[node] = (generation, tls)
                if self.live_preview is not None:
                    # The older session's live frames go with it (lock
                    # order: this lock, then the hub's).
                    self.live_preview.open_node(node, generation)
        if not registered:
            self._close_with(tls, "node_capacity")
            return
        if previous is not None:
            # ADR-0007 item 2: the newer session wins; the older one's thread
            # sees its socket shut down and ends.
            _abort(previous[1])
        LOGGER.info(Event.CAPTURE_INGEST_SESSION_OPENED)
        reason = "closed"
        try:
            reason = self._frames(session, tls, node, generation)
        finally:
            self._end(node, generation)
            if reason not in ("not_admitted", "superseded") and not self._stopping():
                # A node revoked while it sent nothing more (it went quiet,
                # timed out or closed) is forgotten too, not kept as offline
                # (PR #401 review). One ledger read per ended session, on this
                # session's thread; never during the stop.
                try:
                    revoked = not session.still_admitted()
                except Exception:
                    revoked = False
                if revoked:
                    self._forget_revoked(node, generation)
            with self._lock:
                self._closed += 1
            # Value-free (`app.logging`): an ordinary end, or a refusal of
            # the peer's protocol, rate or credential. The reason word is
            # kept in `last_close_reasons` (bounded) for tests and status.
            LOGGER.info(Event.CAPTURE_INGEST_SESSION_CLOSED if reason in _ORDINARY_ENDS
                        else Event.CAPTURE_INGEST_SESSION_REFUSED)
            with self._lock:
                self._reasons.append(reason)

    def _forget_revoked(self, node: UUID, generation: int) -> None:
        """Forget this session's health entry after its credential stopped being admitted.

        Only this generation's entry, and only while no newer session of the
        node is live: a renewed certificate also makes the old one no longer
        admitted, and its newer session must keep its health (PR #401
        review). Done under this lock, where a newer session registers, so a
        registration cannot slip in between the check and the removal. The
        rate window is not dropped here: it belongs to the node, a newer
        session may be using it, and an unused window expires on its own and
        is reclaimed when the table needs room (`AgentIngestQueue`).
        """
        with self._lock:
            current = self._live.get(node)
            if current is not None and current[0] != generation:
                return
            self.registry.forget(node, generation)
        if self._live_sources is not None:
            self._live_sources.forget(node)

    def _end(self, node: UUID, generation: int) -> None:
        with self._lock:
            current = self._live.get(node)
            if current is not None and current[0] == generation:
                del self._live[node]
            if self.live_preview is not None:
                # Under this lock, so it is ordered with every publish of
                # this generation (`_live_frame`).
                self.live_preview.close_node(node, generation)
        self.registry.disconnected(node, generation)

    def _close_with(self, tls, reason: str) -> None:
        try:
            # `read_frame` leaves the socket at the rest of a frame deadline;
            # a send gets the whole idle timeout.
            tls.settimeout(self.limits.idle_timeout_seconds)
            tls.sendall(encode_frame(FrameType.CLOSE, {"reason": reason}))
        except (OSError, ValueError):
            pass

    def _frames(self, session, tls, node: UUID, generation: int) -> str:
        while True:
            # One deadline per frame, from the end of the previous one: the
            # whole next frame must arrive within the idle timeout, however
            # the peer splits it (PR #401 Codex review). A peer that trickles
            # bytes therefore cannot hold a session open, and a session that
            # never completes a frame is closed at that deadline, so neither
            # the per-frame ledger re-check nor the rate budget is skipped for
            # longer than the idle timeout.
            try:
                frame = read_frame(tls, self.limits.maximum_frame_bytes,
                                   deadline=time.monotonic() + self.limits.idle_timeout_seconds,
                                   type_limits=self._frame_limits)
            except WireRefused as refused:
                self._close_with(tls, refused.reason)
                return refused.reason
            except socket.timeout:
                self._close_with(tls, "idle_timeout")
                return "idle_timeout"
            except (PeerClosed, OSError, ssl.SSLError):
                return "superseded" if not self._current(node, generation) else (
                    "stopping" if self._stopping() else "peer_closed")
            # The Main's receive time for the Agent's clock estimate, taken
            # before the ledger and rate checks (PR #401 review).
            received = self._utc()
            if self._stopping():
                return "stopping"
            if not self._current(node, generation):
                return "superseded"
            # The ledger's current record decides every frame (Issue #13):
            # a revocation committed since the last frame ends the session.
            if not session.still_admitted():
                self._forget_revoked(node, generation)
                return "not_admitted"
            if frame.kind is FrameType.LIVE_FRAME:
                # Its own budget, never the heartbeat budget below, and no
                # reply (Issue #14, option A).
                ended = self._live_frame(node, generation, frame.body)
                if ended is None:
                    continue
                if ended != "superseded":
                    self._close_with(tls, ended)
                return ended
            refusal = self._rate.charge_attempt(node)
            if refusal is not None:
                ended = _RATE_ENDS.get(refusal.reason, "rate_refused")
                if ended != "superseded":
                    self._close_with(tls, ended)
                return ended
            if frame.kind is not FrameType.HEARTBEAT:
                self._close_with(tls, "frame_type_refused")
                return "frame_type_refused"
            try:
                heartbeat = parse_heartbeat(frame.body)
            except WireRefused as refused:
                self._close_with(tls, refused.reason)
                return refused.reason
            if heartbeat.node_id != node:
                self._close_with(tls, "node_identity_mismatch")
                return "node_identity_mismatch"
            if not self.registry.heartbeat(generation, heartbeat):
                return "superseded"
            try:
                tls.settimeout(self.limits.idle_timeout_seconds)
                tls.sendall(encode_frame(FrameType.HEARTBEAT_ACK, {
                    "sequence": heartbeat.sequence, "receive_utc": received,
                    "send_utc": self._utc()}))
            except socket.timeout:
                return "idle_timeout"
            except (OSError, ssl.SSLError):
                return "peer_closed"

    def _live_frame(self, node: UUID, generation: int, body: bytes) -> str | None:
        """Keep one live frame in memory; ``None``, or the session's end reason.

        Order: the body's form (malformed closes), the node's flood bound
        (closes), the registry's authorization of the source for this node
        (cached; unauthorized is dropped), the token buckets (dropped), then
        the publish under this lock while the session is the node's current
        one. Nothing is sent back to the Agent, whatever happens to a frame.
        """
        try:
            live = parse_live_frame(body)
        except WireRefused as refused:
            return refused.reason
        if self._live_budget.flooding(node):
            return "rate_limited"
        authorized = False
        if self.live_preview is not None and self._live_sources is not None:
            authorized = self._live_sources(node, live.source_id) is True
        if not authorized:
            self._count_live("unauthorized")
            return None
        if not self._live_budget.charge(node, live.source_id):
            self._count_live("dropped")
            return None
        with self._lock:
            if not self._current_locked(node, generation):
                return "superseded"
            kept = self.live_preview.publish(node, generation, live.source_id, live.jpeg)
            self._live_counts["accepted" if kept else "dropped"] += 1
        return None

    def _count_live(self, kind: str) -> None:
        with self._lock:
            self._live_counts[kind] += 1

    def _current_locked(self, node: UUID, generation: int) -> bool:
        current = self._live.get(node)
        return current is not None and current[0] == generation

    def _current(self, node: UUID, generation: int) -> bool:
        with self._lock:
            current = self._live.get(node)
            return current is not None and current[0] == generation
