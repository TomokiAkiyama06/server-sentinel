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
  supersedes the older, whose socket is shut down (ADR-0007 item 2). Each
  replacement is reported to the registry (``superseded``), which marks a node
  replaced 3 times within 10 min as ``contended`` for the Owner notice (Issue
  #407).
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
Main). Only a malformed body (``live_frame_invalid``) or a flood
(``rate_limited``: more than ten times the node refill rate in frames, or more
than about 50 MB/s with a 5 s burst in body bytes, twice the node refill of
maximum-size frames, sustained) closes the
session. The session's frames are dropped from the hub when it ends or is
superseded.

Certificate renewal (``RENEWAL_REQUEST`` / ``RENEWAL_REPLY``; Issue #109,
ADR-0007 addendum 2026-11-16). A request is a frame like a heartbeat: the
ledger re-check and the node's rate budget come first, and its form is
checked (``renewal_request_invalid`` closes). The node is the session's: the
injected ``renewal`` (``renewal.SessionRenewal``) receives the session's
identity and its presented certificate, never a node named by the Agent.
Since the signer can take up to its timeout, the renewal runs on its own
short-lived thread, never on the accept loop or a session thread, and at
most ``maximum_concurrent_renewals`` run at once, at most one per node; a
request beyond that is answered ``renewal_busy`` at once, and a listener
without ``renewal`` answers ``renewal_unavailable``. A session has at most
one request outstanding (until its reply is sent): a second closes it with
``renewal_in_flight``. The reply is sent by the session thread only, directly
before the next ``HEARTBEAT_ACK`` and in the same write, so one TLS socket is
never written from two threads and the Agent reads the reply inside a
heartbeat round trip. A reply whose session ended is dropped; the ledger
keeps the staged certificate, and the Agent's retry with the same key is
answered with it. Outcomes are counted in the status (value-free: counts and
the fixed refusal words) and logged at the first and every power of two per
category.

Nothing is written to the database or the disk here: the pairing ledger and
the camera registry are only read (a staged renewal's promotion and a
renewal's staging are the ledger's own admitted writes), and node health and
live frames are kept in memory (``node_health``, ``RemotePreviewHub``).
``stop`` therefore waits for nothing: it stops accepting and shuts every
socket down, and the connection and renewal threads end on their own (a
renewal within the signer's timeout; Issue #383: it adds no bounded wait to
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
    INGEST_ALPN, MAXIMUM_LIVE_FRAME_BODY_BYTES, MAXIMUM_RENEWAL_REQUEST_BODY_BYTES,
    RENEWAL_REFUSALS, FrameType, PeerClosed, WireRefused, encode_frame, encode_renewal_reply,
    parse_heartbeat, parse_live_frame, parse_renewal_request, read_frame,
)
from .live_frames import CachedLiveSources, LiveFrameBudget
from .node_health import CaptureNodeHealthRegistry
from .renewal import RenewalRefused


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
# Issue #109: renewals running at once (each holds one signer connection;
# the signer socket accepts 4), and the log event of each outcome category.
MAXIMUM_CONCURRENT_RENEWALS = 2
_RENEWAL_UNAVAILABLE = frozenset({"renewal_signer_unavailable", "renewal_unavailable",
                                  "renewal_busy"})
_RENEWAL_EVENTS = {
    "issued": Event.CAPTURE_INGEST_RENEWAL_ISSUED,
    "refused": Event.CAPTURE_INGEST_RENEWAL_REFUSED,
    "unavailable": Event.CAPTURE_INGEST_RENEWAL_UNAVAILABLE,
}


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
    # Certificate renewal (Issue #109): issued replies, refused replies, and
    # the refused replies per fixed word (`ingest_wire.RENEWAL_REFUSALS`).
    renewals_issued: int = 0
    renewals_refused: int = 0
    renewal_refusals: tuple[tuple[str, int], ...] = ()


class _RenewalSlot:
    """One session's renewal: whether a request is outstanding, and its reply.

    Guarded by the listener's lock. ``outstanding`` lasts from the request
    until its reply is sent (or the session ends); ``reply`` is the encoded
    ``RENEWAL_REPLY`` waiting for the next heartbeat acknowledgement.
    """

    __slots__ = ("outstanding", "reply")

    def __init__(self):
        self.outstanding = False
        self.reply: bytes | None = None


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
                 live_sources: Callable[[UUID, UUID], bool] | None = None,
                 renewal: Callable[..., bytes] | None = None,
                 maximum_concurrent_renewals: int = MAXIMUM_CONCURRENT_RENEWALS):
        from app.media.live.remote_preview import RemotePreviewHub
        limits = limits or CaptureIngestLimits()
        if (not isinstance(listener, socket.socket) or not isinstance(acceptor, CaptureIngestAcceptor)
                or not isinstance(limits, CaptureIngestLimits) or not callable(utc)
                or (live_preview is not None and not isinstance(live_preview, RemotePreviewHub))
                or (live_sources is not None and not callable(live_sources))
                or (renewal is not None and not callable(renewal))
                or type(maximum_concurrent_renewals) is not int
                or not 1 <= maximum_concurrent_renewals <= 4):
            raise ValueError("invalid capture ingest dependencies")
        self.limits = limits
        # Issue #109: `renewal.SessionRenewal`, or None (every request is
        # answered `renewal_unavailable`).
        self._renewal = renewal
        self._maximum_renewals = maximum_concurrent_renewals
        self._renewing: set[UUID] = set()
        self._renewal_counts = {"issued": 0, "refused": 0}
        self._renewal_refusals: dict[str, int] = {}
        self._renewal_logged = {"issued": 0, "refused": 0, "unavailable": 0}
        # Issue #14 (option A): without both, every live frame is dropped and
        # counted as `live_frames_unauthorized` (fail closed); the session
        # and its heartbeats go on.
        self.live_preview = live_preview
        self._live_sources = (None if live_sources is None else CachedLiveSources(
            live_sources, maximum_nodes=limits.maximum_nodes, clock_ns=monotonic_ns))
        self._live_budget = LiveFrameBudget(maximum_nodes=limits.maximum_nodes,
                                            clock_ns=monotonic_ns)
        self._live_counts = {"accepted": 0, "unauthorized": 0, "dropped": 0}
        self._frame_limits = {FrameType.LIVE_FRAME: MAXIMUM_LIVE_FRAME_BODY_BYTES,
                              FrameType.RENEWAL_REQUEST: MAXIMUM_RENEWAL_REQUEST_BODY_BYTES}
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
                                       self._live_counts["dropped"],
                                       self._renewal_counts["issued"],
                                       self._renewal_counts["refused"],
                                       tuple(sorted(self._renewal_refusals.items())))

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
                if previous is not None:
                    # Issue #407: counted per node; repeated replacement is
                    # notified by the monitoring worker (`capture_nodes.py`).
                    self.registry.superseded(node, generation)
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
            reason = self._frames(session, tls, node, generation, _RenewalSlot())
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

    def _frames(self, session, tls, node: UUID, generation: int, renewal: _RenewalSlot) -> str:
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
            if frame.kind is FrameType.RENEWAL_REQUEST:
                # Issue #109: answered before a later acknowledgement.
                ended = self._renewal_request(session, tls, node, renewal, frame.body)
                if ended is None:
                    continue
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
            with self._lock:
                # A finished renewal's reply goes first, in the same write
                # (Issue #109); only this thread writes to the socket.
                reply, renewal.reply = renewal.reply, None
                if reply is not None:
                    renewal.outstanding = False
            try:
                tls.settimeout(self.limits.idle_timeout_seconds)
                tls.sendall((reply or b"") + encode_frame(FrameType.HEARTBEAT_ACK, {
                    "sequence": heartbeat.sequence, "receive_utc": received,
                    "send_utc": self._utc()}))
            except socket.timeout:
                return "idle_timeout"
            except (OSError, ssl.SSLError):
                return "peer_closed"

    def _renewal_request(self, session, tls, node: UUID, slot: _RenewalSlot,
                         body: bytes) -> str | None:
        """Start one renewal off this thread; ``None``, or the session's end reason.

        The reply is left in ``slot`` for the next acknowledgement: at once
        for ``renewal_unavailable`` / ``renewal_busy``, otherwise when the
        renewal thread finishes.
        """
        try:
            csr = parse_renewal_request(body)
        except WireRefused as refused:
            return refused.reason
        with self._lock:
            if slot.outstanding:
                return "renewal_in_flight"
            slot.outstanding = True
            if self._renewal is None:
                immediate = "renewal_unavailable"
            elif node in self._renewing or len(self._renewing) >= self._maximum_renewals:
                immediate = "renewal_busy"
            else:
                immediate = None
                self._renewing.add(node)
        if immediate is not None:
            self._renewal_done(slot, None, immediate)
            return None
        # The exact certificate this session presented; its identity was
        # derived from it at admission (`SignerRenewalIssuer` checks that
        # both agree). Read here, while no other thread uses the socket.
        try:
            presented = tls.getpeercert(binary_form=True) or b""
        except (OSError, ValueError):
            presented = b""
        thread = threading.Thread(target=self._renew,
                                  args=(session.identity, presented, csr, node, slot),
                                  daemon=True, name="capture-ingest-renewal")
        with self._lock:
            self._threads.add(thread)
        try:
            thread.start()
        except RuntimeError:
            with self._lock:
                self._threads.discard(thread)
                self._renewing.discard(node)
            self._renewal_done(slot, None, "renewal_busy")
        return None

    def _renew(self, identity, presented: bytes, csr: bytes, node: UUID,
               slot: _RenewalSlot) -> None:
        certificate = None
        reason = None
        try:
            certificate = self._renewal(identity, presented, csr)
        except RenewalRefused as refused:
            reason = (refused.reason if refused.reason in RENEWAL_REFUSALS
                      else "renewal_unavailable")
        except Exception:
            # Never let a renewal thread's failure reach the process.
            reason = "renewal_unavailable"
        finally:
            with self._lock:
                self._renewing.discard(node)
        try:
            self._renewal_done(slot, certificate, reason)
        finally:
            with self._lock:
                self._threads.discard(threading.current_thread())

    def _renewal_done(self, slot: _RenewalSlot, certificate: bytes | None,
                      reason: str | None) -> None:
        """Leave the reply for the session's next acknowledgement; count and log it."""
        reply = None
        if certificate is not None:
            try:
                reply = encode_renewal_reply(certificate_pem=certificate)
            except ValueError:
                reason = "renewal_unavailable"
        if reply is not None:
            category = "issued"
        else:
            reason = reason if reason in RENEWAL_REFUSALS else "renewal_unavailable"
            reply = encode_renewal_reply(reason=reason)
            category = "unavailable" if reason in _RENEWAL_UNAVAILABLE else "refused"
        with self._lock:
            slot.reply = reply
            if category == "issued":
                self._renewal_counts["issued"] += 1
            else:
                # Bounded: the keys are words of `RENEWAL_REFUSALS`.
                self._renewal_counts["refused"] += 1
                self._renewal_refusals[reason] = self._renewal_refusals.get(reason, 0) + 1
            self._renewal_logged[category] += 1
            count = self._renewal_logged[category]
        # Value-free, the first and every power of two per category, so a
        # node cannot write one log line per request.
        if count & (count - 1) == 0:
            LOGGER.log(logging.INFO if category == "issued" else logging.WARNING,
                       _RENEWAL_EVENTS[category], extra={"count": count})

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
        if self._live_budget.flooding(node, len(body)):
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
