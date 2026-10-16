"""S7 interim live: authorized MJPEG frame-pull over the local preview hub.

Owner decision D10 (Issue #10, 2026-10-11): until Issue #19 selects the
browser live transport, live video is served as an *interim* frame pull. A
viewer opens a live session for one local source and then repeatedly asks for
"the newest frame after sequence ``n``"; each answer is one complete camera
JPEG (native MJPG passthrough, never transcoded) or nothing yet. This module
owns the server side of that contract, without any route: the human surface
(``app.auth.human_surface``) authenticates the request and calls in here.

Threading. ``LiveViewerSessions`` and ``AuthorizedLocalPreview`` are confined
to one scheduler thread. ``LiveFrameService`` therefore owns a single-thread
executor and runs every open, read, close, disconnect, revalidation and lease
sweep on it; request handlers only submit work and await the result. A small
lock guards the map of open live-session ids to the token digest of their
opening human session, which lets a request for an unknown id, or one
presented with another cookie, be refused before any SQLite read is made.

Authorization of a frame read (every poll):

1. the request passed the human surface gates (route, reserved origin,
   loopback trusted-proxy path, one well-formed proxy identity, open
   reservation verdict, serving composition);
2. the live-session id is one this service issued and still holds, presented
   with the cookie of the human session that opened it (a domain-separated
   token digest kept in memory, compared in constant time), and the poll is
   within that live session's poll budget (all in memory, no SQLite);
3. inside ``admit(epoch)`` of the request's gate epoch, on the executor:
   ``AccessStore.current_session`` (read-only: token digest, keyed
   proxy-identity binding, idle/absolute lifetime) must name exactly the
   human access session and principal the live session was opened under, so
   a live-session id copied to another person's browser is refused; then
   ``AuthorizedLocalPreview.read`` re-runs ``live_view_validator`` (current
   principal, credential, deployment generation, exact authorization
   revision, ``live:view`` or the Owner). ``recordings:view`` alone never
   passes.

Every refusal is the same ``LiveFrameUnavailable``; the surface turns it into
the generic not-found denial, capacity included.

Per-frame SQLite cost is two read-only transactions; nothing is written per
frame. The human session's idle expiry is extended by a live viewer at most
once per ``idle_extension_interval_seconds`` per live session (Owner default
D5: 60 s), through the normal gated ``authorize_request(..., touch=True)``
the surface performs when ``LivePoll.extend_idle`` is set, so a 5 fps viewer
does not turn into a 5 Hz stream of storage-admitted writes.

Demand and retention. A live session holds viewer demand on its hub source
only while its viewer keeps polling: a session with no authorized poll for
``lease_seconds`` (D5 default 15 s) is disconnected by the sweeper, which
releases the demand, and with zero viewers the hub retains no frame. The
sweeper also disconnects every session while human access is closed or the
composition is stopped. Principal and permission changes made through
``AccessAdministration`` and a sign-out re-check or end the affected sessions
at once; a change made elsewhere (the local CLI, a reservation revocation) is
caught by the next poll's validator or, without polls, by the lease.

Limits (D10 and the D5 defaults): at most 4 live sessions in total, 2 per
source and 2 per principal; at most one served frame per
``minimum_frame_interval_seconds`` (5 fps) per session; a frame that does not
start with a JPEG SOI marker or exceeds ``maximum_frame_bytes`` is never
served (counted, value-free). Nothing here logs an identity, token, session
id or media byte.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
import hashlib
import hmac
import math
import threading
import time
from typing import Callable, ContextManager
from uuid import UUID

from app.auth.live_access import BoundLiveAccess, live_view_validator
from app.auth.rate_limit import SourceRateLimiter
from .local_preview import AuthorizedLocalPreview, LocalPreviewHub, PreviewFrame
from .sessions import (
    LiveSession, LiveSessionCapacityExceeded, LiveSessionLimits, LiveSessionUnavailable,
)


_JPEG_SOI = b"\xff\xd8\xff"
_HOLDER_DOMAIN = b"ServerSentinel live session holder v1\x00"
_HEALTH = ("online", "degraded", "offline", "manual_intervention_required")


class LiveFrameUnavailable(Exception):
    """The one generic refusal of the frame-pull service (capacity included)."""

    def __init__(self) -> None:
        super().__init__("live is unavailable")


def _finite_positive(value, upper: float) -> bool:
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and 0 < value <= upper)


@dataclass(frozen=True)
class LiveFrameLimits:
    """D10 viewer limits and the D5 interim-transport defaults."""

    maximum_total_viewers: int = 4
    maximum_viewers_per_source: int = 2
    maximum_viewers_per_principal: int = 2
    lease_seconds: float = 15.0
    minimum_frame_interval_seconds: float = 0.2
    idle_extension_interval_seconds: float = 60.0
    sweep_interval_seconds: float = 1.0
    maximum_frame_bytes: int = 8 * 1024 * 1024
    # Poll budget per live session (its holder only): a burst of 20 and one
    # more every 0.1 s; the paced 5 fps viewer and its 204 waits stay well
    # inside it, a tight loop is refused before any SQLite read.
    poll_burst: int = 20
    poll_refill_seconds: float = 0.1

    def __post_init__(self) -> None:
        for name in ("maximum_total_viewers", "maximum_viewers_per_source",
                     "maximum_viewers_per_principal", "maximum_frame_bytes", "poll_burst"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError("live limits are invalid")
        if (self.maximum_viewers_per_source > self.maximum_total_viewers
                or self.maximum_viewers_per_principal > self.maximum_total_viewers
                or self.maximum_frame_bytes > 64 * 1024 * 1024):
            raise ValueError("live limits are invalid")
        for name, upper in (("lease_seconds", 300), ("minimum_frame_interval_seconds", 10),
                            ("idle_extension_interval_seconds", 3600), ("sweep_interval_seconds", 60),
                            ("poll_refill_seconds", 10)):
            if not _finite_positive(getattr(self, name), upper):
                raise ValueError("live limits are invalid")
        if self.sweep_interval_seconds > self.lease_seconds:
            raise ValueError("live limits are invalid")


@dataclass(frozen=True)
class LiveSourceView:
    """What a ``live:view`` caller learns about one source: nothing more."""

    source_id: UUID
    name: str
    health: str


@dataclass(frozen=True)
class LivePoll:
    """One authorized poll: a newer frame (or ``None``) and whether to touch."""

    frame: PreviewFrame | None
    extend_idle: bool


@dataclass(frozen=True)
class LiveFrameStatus:
    """Aggregate, value-free status (no principal, session or source identity)."""

    active_sessions: int
    served_frames: int
    unservable_frames: int
    lease_expiries: int
    running: bool


@dataclass
class _Entry:
    access: BoundLiveAccess
    source_id: UUID
    last_poll: float
    last_served: float | None
    last_extension: float


class LiveFrameService:
    """Executor-confined owner of ``AuthorizedLocalPreview`` for the frame pull."""

    def __init__(self, hub: LocalPreviewHub, access_store, *,
                 limits: LiveFrameLimits | None = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 validator=None) -> None:
        if not isinstance(hub, LocalPreviewHub):
            raise ValueError("preview hub is required")
        limits = LiveFrameLimits() if limits is None else limits
        if not isinstance(limits, LiveFrameLimits) or not callable(monotonic):
            raise ValueError("live configuration is invalid")
        current_session = getattr(access_store, "current_session", None)
        now = getattr(access_store, "now", None)
        database = getattr(access_store, "database", None)
        if not callable(current_session) or not callable(now) or database is None:
            raise ValueError("access store is required")
        self.hub = hub
        self.limits = limits
        self._store = access_store
        self._database = database
        self._monotonic = monotonic
        self.preview = AuthorizedLocalPreview(
            hub, LiveSessionLimits(limits.maximum_total_viewers, limits.maximum_viewers_per_source),
            validator if validator is not None else live_view_validator(database, clock=now))
        self._poll_limiter = SourceRateLimiter(
            per_source_capacity=limits.poll_burst, per_source_refill_seconds=limits.poll_refill_seconds,
            global_capacity=None, max_sources=8 * limits.maximum_total_viewers, monotonic=monotonic)
        # Executor-confined state.
        self._entries: dict[UUID, _Entry] = {}
        self._served = 0
        self._unservable = 0
        self._expiries = 0
        # Shared with request threads under ``_lock``.
        self._lock = threading.Lock()
        # Live-session id -> digest of the opening human session's token.
        self._holders: dict[UUID, bytes] = {}
        self._executor: ThreadPoolExecutor | None = None
        # A stopped executor whose final release may still be running; a
        # restart waits for it, so two threads never share the state above.
        self._retired: ThreadPoolExecutor | None = None
        self._sweeper: threading.Thread | None = None
        self._stop = threading.Event()
        self._closed: Callable[[], bool] = lambda: False

    @property
    def database(self):
        """The access database the validator and the source list read."""
        return self._database

    # -- lifecycle -------------------------------------------------------

    def bind_closed(self, closed: Callable[[], bool]) -> None:
        """While ``closed()`` is true (or raises) the sweeper ends every session."""
        if not callable(closed):
            raise ValueError("closed predicate is invalid")
        self._closed = closed

    @property
    def running(self) -> bool:
        with self._lock:
            return self._executor is not None

    def start(self) -> None:
        """Start the executor and the lease sweeper; idempotent."""
        with self._lock:
            if self._executor is not None:
                return
            retired, self._retired = self._retired, None
        if retired is not None:
            retired.shutdown(wait=True)
        with self._lock:
            if self._executor is not None:
                return
            self._stop = threading.Event()
            self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="live-frame")
            stop = self._stop
            self._sweeper = threading.Thread(target=self._sweep_loop, args=(stop,),
                                             name="live-frame-sweeper", daemon=True)
            self._sweeper.start()

    def stop(self, *, wait: bool = False) -> None:
        """Refuse every later call and release every session's demand.

        The release runs as the executor's last job; ``wait=True`` waits for
        it (tests, a synchronous embedder). Idempotent.
        """
        with self._lock:
            executor, self._executor = self._executor, None
            sweeper, self._sweeper = self._sweeper, None
            self._stop.set()
            self._holders.clear()
            if executor is not None:
                self._retired = executor
        if executor is None:
            return
        executor.submit(self._end_all)
        executor.shutdown(wait=wait)
        if wait and sweeper is not None:
            sweeper.join(timeout=10)

    def _submit(self, function, *args) -> Future:
        with self._lock:
            executor = self._executor
            if executor is None:
                raise LiveFrameUnavailable()
            try:
                return executor.submit(function, *args)
            except RuntimeError:
                raise LiveFrameUnavailable() from None

    def _sweep_loop(self, stop: threading.Event) -> None:
        while not stop.wait(self.limits.sweep_interval_seconds):
            try:
                self._submit(self._sweep)
            except LiveFrameUnavailable:
                return

    # -- request-thread entry points (return futures) ----------------------

    @staticmethod
    def _holder(token: bytes) -> bytes:
        return hashlib.sha256(_HOLDER_DOMAIN + token).digest()

    def holds(self, token: object, session_id: object) -> bool:
        """Whether ``session_id`` is held and was opened with this session token.

        In memory only (a digest compared in constant time): a live-session
        id presented with any other cookie, a copied id included, is refused
        here before any SQLite read or limiter slot.
        """
        if not isinstance(token, bytes) or not isinstance(session_id, UUID):
            return False
        with self._lock:
            holder = self._holders.get(session_id)
        return holder is not None and hmac.compare_digest(holder, self._holder(token))

    def charge_poll(self, token: bytes, session_id: UUID) -> bool:
        """In-memory admission of one poll: its holder, within its poll budget.

        Only the holder (``holds``) is charged, so the per-live-session
        budget cannot be spent by anyone else. No SQLite is read.
        """
        if not self.holds(token, session_id):
            return False
        return self._poll_limiter.allow(str(session_id))

    def open(self, access: BoundLiveAccess, source_id: UUID, token: bytes, *,
             admit: Callable[[], ContextManager]) -> Future:
        """Open for the human session ``access`` names, presented as ``token``."""
        if not isinstance(token, bytes):
            raise LiveFrameUnavailable()
        return self._submit(self._open, access, source_id, self._holder(token), admit)

    def poll(self, token: bytes, proxy_identity: str, session_id: UUID, after: int, *,
             admit: Callable[[], ContextManager]) -> Future:
        return self._submit(self._poll, token, proxy_identity, session_id, after, admit)

    def close(self, access_session_id: UUID, session_id: UUID) -> Future:
        """Close one live session of this human access session (trusted release)."""
        return self._submit(self._close, access_session_id, session_id)

    def sources(self, *, admit: Callable[[], ContextManager]) -> Future:
        return self._submit(self._sources, admit)

    def revalidate_principal(self, principal_id: UUID) -> None:
        """Re-check every live session of a changed principal; fire and forget."""
        if isinstance(principal_id, UUID):
            try:
                self._submit(self._revalidate, principal_id)
            except LiveFrameUnavailable:
                pass

    def end_access_session(self, access_session_id: UUID) -> None:
        """Release every live session of an ended human session; fire and forget."""
        if isinstance(access_session_id, UUID):
            try:
                self._submit(self._end_where, lambda entry: entry.access.access_session_id == access_session_id)
            except LiveFrameUnavailable:
                pass

    def status(self) -> Future:
        return self._submit(self._status)

    # -- executor jobs -----------------------------------------------------

    def _open(self, access: BoundLiveAccess, source_id: UUID, holder: bytes, admit) -> LiveSession:
        if not isinstance(access, BoundLiveAccess) or not isinstance(source_id, UUID):
            raise LiveFrameUnavailable()
        mine = sum(entry.access.principal_id == access.principal_id for entry in self._entries.values())
        if mine >= self.limits.maximum_viewers_per_principal:
            raise LiveFrameUnavailable()
        try:
            with admit():
                session = self.preview.open(access, source_id)
        except (LiveSessionUnavailable, LiveSessionCapacityExceeded):
            raise LiveFrameUnavailable() from None
        except Exception:
            raise LiveFrameUnavailable() from None
        now = self._monotonic()
        self._entries[session.session_id] = _Entry(access, session.source_id, now, None, now)
        with self._lock:
            self._holders[session.session_id] = holder
        return session

    def _poll(self, token, proxy_identity, session_id, after, admit) -> LivePoll:
        entry = self._entries.get(session_id)
        if entry is None or type(after) is not int or after < 0:
            raise LiveFrameUnavailable()
        try:
            with admit():
                view = self._store.current_session(token, proxy_identity, at=self._store.now())
                if (view is None or view.session_id != entry.access.access_session_id
                        or view.principal_id != entry.access.principal_id):
                    # Another person's browser (a copied id) or an ended human
                    # session: refused. The live session is kept only while
                    # its own grant still validates (a copied id must not end
                    # the owner's viewing); otherwise its demand ends now.
                    self._revalidate_one(session_id, entry)
                    raise LiveFrameUnavailable()
                try:
                    frame = self.preview.read(entry.access, session_id, after)
                except LiveSessionUnavailable:
                    # The validator refused (revoked, grant withdrawn, expired):
                    # the read already released the demand.
                    self._forget(session_id)
                    raise LiveFrameUnavailable() from None
        except LiveFrameUnavailable:
            raise
        except Exception:
            raise LiveFrameUnavailable() from None
        now = self._monotonic()
        entry.last_poll = now
        extend = now - entry.last_extension >= self.limits.idle_extension_interval_seconds
        if extend:
            entry.last_extension = now
        if (entry.last_served is not None
                and now - entry.last_served < self.limits.minimum_frame_interval_seconds):
            frame = None
        if frame is not None:
            if len(frame.data) > self.limits.maximum_frame_bytes or not frame.data.startswith(_JPEG_SOI):
                self._unservable += 1
                frame = None
            else:
                entry.last_served = now
                self._served += 1
        return LivePoll(frame, extend)

    def _close(self, access_session_id, session_id) -> None:
        entry = self._entries.get(session_id)
        if entry is None or entry.access.access_session_id != access_session_id:
            raise LiveFrameUnavailable()
        self._release(session_id)

    def _sources(self, admit) -> tuple[LiveSourceView, ...]:
        configured = set(self.hub.source_ids)
        try:
            with admit():
                if not configured:
                    return ()
                # Read-only and never creating: a lost or replaced filesystem
                # makes this a refusal, not a fallback database.
                with closing(self._database.connect_read_only()) as connection:
                    connection.execute("BEGIN")
                    rows = connection.execute(
                        "SELECT id, name, health_state FROM camera_sources"
                        " WHERE enabled=1 AND source_type='local_uvc' ORDER BY created_at, id").fetchall()
                    connection.execute("COMMIT")
        except Exception:
            raise LiveFrameUnavailable() from None
        views = []
        for row in rows:
            try:
                source_id = UUID(row[0])
            except (TypeError, ValueError):
                continue
            if source_id not in configured or not isinstance(row[1], str):
                continue
            health = row[2] if row[2] in _HEALTH else "offline"
            if health == "online" and not self.hub.accepting(source_id):
                # Never report a source as online while its frames are refused.
                health = "offline"
            views.append(LiveSourceView(source_id, row[1], health))
        return tuple(views)

    def _revalidate(self, principal_id: UUID) -> None:
        for session_id, entry in list(self._entries.items()):
            if entry.access.principal_id == principal_id:
                self._revalidate_one(session_id, entry)

    def _revalidate_one(self, session_id: UUID, entry: _Entry) -> None:
        try:
            self.preview.sessions.require(entry.access, session_id)
        except LiveSessionUnavailable:
            # ``require`` already released the demand.
            self._forget(session_id)

    def _sweep(self) -> None:
        try:
            closed = self._closed() is not False
        except Exception:
            closed = True
        if closed:
            self._end_all()
            return
        now = self._monotonic()
        for session_id, entry in list(self._entries.items()):
            if now - entry.last_poll > self.limits.lease_seconds or now < entry.last_poll:
                self._expiries += 1
                self._release(session_id)

    def _end_all(self) -> None:
        self._end_where(lambda entry: True)

    def _end_where(self, predicate) -> None:
        for session_id, entry in list(self._entries.items()):
            if predicate(entry):
                self._release(session_id)

    def _release(self, session_id: UUID) -> None:
        # The hub's demand removal cannot fail; a failed one would stay in
        # ``LiveViewerSessions`` (unusable, retried by its next lookup).
        self.preview.disconnect(session_id)
        self._forget(session_id)

    def _forget(self, session_id: UUID) -> None:
        self._entries.pop(session_id, None)
        with self._lock:
            self._holders.pop(session_id, None)

    def _status(self) -> LiveFrameStatus:
        return LiveFrameStatus(len(self._entries), self._served, self._unservable, self._expiries,
                               self.running)
