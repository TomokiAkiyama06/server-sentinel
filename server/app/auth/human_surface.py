"""Human route foundation (Issue #10, phase 1; ADR-0003, ADR-0004).

The human listener stays closed (``ClosedHumanSurface`` in ``app.main``)
unless the embedder passes a validated ``HumanAccess`` composition, which
requires an explicit ``HumanAccessConfiguration(enabled=True)`` and a fully
configured ``HostnameReservationCheck``. No deployment-file key enables it
yet, so the production entry points keep every human path closed.

When enabled, every HTTP request passes, server-side and in this order:

1. the dedicated, reserved, secure-context origin: exactly one ``Host`` equal
   to the reserved ``<hostname>[:<port>]`` and, when present, an ``Origin``
   exactly equal to the relying-party origin ``https://<hostname>[:<port>]``
   derived from the reservation; an absent ``Origin`` is accepted only for
   the non-mutating session read;
2. the trusted-proxy path: the actual transport peer and the local listener
   address are loopback (never a ``Forwarded``/``X-Forwarded-For`` value),
   and exactly one well-formed ``Tailscale-User-Login`` header is present.
   A request from any other peer is refused before its identity header is
   read, so a LAN client cannot spoof it;
3. the hostname reservation verdict (``access_open``, pid-guarded), and for
   every commit or authorization the gate epoch, re-checked by ``admit()``
   held around the commit itself (Issue #144/#181);
4. the per-person WebAuthn credential: a session established by a
   user-verified assertion of the person's own passkey. The proxy identity
   is supplementary (ADR-0004 §1): it must be present and reproduce the
   session's keyed binding, but it never selects or authorizes anyone.

Mounted routes (and nothing else; every other method, path, WebSocket and
error path gets the same generic denial):

- ``POST /api/auth/authentication/options``: begin a passkey sign-in;
- ``POST /api/auth/authentication``: finish it and set the ``__Host-`` cookie;
- ``GET /api/session``: the caller's own role and permissions.

The two ceremony routes run before a credential exists. They are
rate-limited per verified proxy identity and globally before the ceremony
takes any gate or SQLite lock (Issue #181). The session read is not
charged; a forged or stale cookie is refused by a read-only token lookup
before the gate or any SQLite write lock (see ``_session``). No live,
recording, timeline, event, administration, health or version route is
mounted here.

Every refusal is the generic, non-branding not-found response used by the
closed surface: no product/version header, no cookie, ``no-store``. Nothing
here logs a header, identity, token, challenge or body.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import ipaddress
import json
import logging
import re
from typing import Callable

from starlette.types import ASGIApp, Receive, Scope, Send

from app.completion import run_to_completion
from app.logging import Event
from app.storage.database import Database, PinnedDatabase
from .passkeys import PasskeyCeremonies, SessionGrant
from .rate_limit import SourceRateLimiter
from .reservation import HostnameReservationCheck
from .reservation_store import ListenerExceptionStore, ReservationSessionRevocation
from .session_binding import canonical_identity
from .store import AccessStore


PROXY_IDENTITY_HEADER = b"tailscale-user-login"
SESSION_COOKIE = "__Host-session"
AUTHENTICATION_OPTIONS_PATH = "/api/auth/authentication/options"
AUTHENTICATION_PATH = "/api/auth/authentication"
SESSION_PATH = "/api/session"
MAX_OPTIONS_BODY = 1024
MAX_ASSERTION_BODY = 64 * 1024
DEFAULT_TICK_SECONDS = 30.0

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_DENIAL_BODY = b'{"detail":"Not Found"}'


async def send_generic_denial(send: Send) -> None:
    """The one non-branding refusal for every human path (ADR-0003)."""
    await send({"type": "http.response.start", "status": 404, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(_DENIAL_BODY)).encode()),
        (b"cache-control", b"no-store"),
    ]})
    await send({"type": "http.response.body", "body": _DENIAL_BODY})


class HumanAccessUnavailable(ValueError):
    """The human surface cannot be composed; carries no configuration value."""

    def __init__(self) -> None:
        super().__init__("human access is unavailable")


@dataclass(frozen=True)
class HumanAccessConfiguration:
    """Explicit deployment switch; disabled unless stated."""

    enabled: bool = False


def reserved_origin(check: HostnameReservationCheck) -> tuple[str, str]:
    """``(origin, host header)`` for the reserved name; https only.

    The default port is omitted, as browsers serialize it. ``http://localhost``
    is not offered here: whether a strictly local Owner path may run without
    the trusted proxy is an open Owner decision, so it stays unavailable.
    """
    config = check.config
    authority = config.hostname if config.port == 443 else f"{config.hostname}:{config.port}"
    return f"https://{authority}", authority


class _Denied(Exception):
    pass


def _loopback(endpoint) -> bool:
    if not isinstance(endpoint, (tuple, list)) or len(endpoint) < 1 or not isinstance(endpoint[0], str):
        return False
    try:
        return ipaddress.ip_address(endpoint[0]).is_loopback
    except ValueError:
        return False


def _single(headers, name: bytes) -> bytes | None:
    """The value of a header that must occur at most once; raises if repeated."""
    values = [value for key, value in headers if key == name]
    if len(values) > 1:
        raise _Denied()
    return values[0] if values else None


def _ascii(value: bytes) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        raise _Denied() from None


def proxy_identity(headers) -> str:
    """Exactly one canonical, unambiguous trusted-proxy login (ADR-0003).

    Printable ASCII without spaces (``canonical_identity``), no comma-joined
    values and no RFC 2047 encoded word: those fail closed until a reviewed
    adapter exists. Never trimmed or case-folded.
    """
    raw = _single(headers, PROXY_IDENTITY_HEADER)
    if raw is None:
        raise _Denied()
    value = canonical_identity(_ascii(raw))
    if value is None or "," in value or "=?" in value:
        raise _Denied()
    return value


def session_token(headers) -> bytes:
    """The one ``__Host-session`` cookie value as 32 bytes; anything else denies."""
    values = []
    for key, raw in headers:
        if key != b"cookie":
            continue
        for part in _ascii(raw).split(";"):
            name, separator, value = part.strip().partition("=")
            if separator and name == SESSION_COOKIE:
                values.append(value)
    if len(values) != 1 or not _TOKEN.fullmatch(values[0]):
        raise _Denied()
    token = base64.urlsafe_b64decode(values[0] + "=")
    if len(token) != 32 or base64.urlsafe_b64encode(token).rstrip(b"=").decode() != values[0]:
        raise _Denied()
    return token


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite number")


class HumanAccess:
    """Validated composition of the human route foundation.

    Refuses construction unless the deployment explicitly enabled it, the
    session gate is a ``HostnameReservationCheck`` with every opening input
    configured (resolver, socket owners, own sockets, unprivileged port
    start, session revoker), the ceremonies use exactly that gate and this
    audited access store with a session-binding key, and the relying party
    is the reserved https origin. A missing or substituted gate is never
    accepted (Issue #181 item 3). The gate's session revoker must be a
    ``ReservationSessionRevocation`` of exactly this store, so a revocation
    after an exposure invalidates the sessions this surface authorizes and
    not another database's. A stored listener-exception source, when the
    gate has one, must be a ``ListenerExceptionStore`` on that same database:
    the exceptions the check applies are the ones the audited Owner path
    commits next to this store's sessions, never another database's.

    Every human-access write is admitted through the application's storage
    admission: ``create_app`` binds it with ``bind_storage_admission`` (the
    Main storage policy, or the embedder's injected reservation), and until
    it is bound every request is denied. An audit store already wired to a
    different reservation is refused rather than silently rebound.
    """

    def __init__(self, configuration: HumanAccessConfiguration, *, store: AccessStore,
                 ceremonies: PasskeyCeremonies, reservation: HostnameReservationCheck,
                 rate_limiter: SourceRateLimiter | None = None,
                 tick_seconds: float = DEFAULT_TICK_SECONDS):
        if not isinstance(configuration, HumanAccessConfiguration) or configuration.enabled is not True:
            raise HumanAccessUnavailable()
        if not isinstance(reservation, HostnameReservationCheck) or not reservation.opening_configured:
            raise HumanAccessUnavailable()
        if (not isinstance(store, AccessStore) or store.audit is None
                or not store.session_binding_configured):
            raise HumanAccessUnavailable()
        revoker = reservation.session_revoker
        if not isinstance(revoker, ReservationSessionRevocation) or revoker.access_store is not store:
            raise HumanAccessUnavailable()
        if (not isinstance(ceremonies, PasskeyCeremonies) or ceremonies.store is not store
                or ceremonies.session_gate is not reservation):
            raise HumanAccessUnavailable()
        exceptions = reservation.exception_store
        if exceptions is not None and not (
                isinstance(exceptions, ListenerExceptionStore)
                and isinstance(exceptions.database, (Database, PinnedDatabase))
                and exceptions.database.path == store.database.path):
            raise HumanAccessUnavailable()
        origin, host = reserved_origin(reservation)
        if ceremonies.rp.origin != origin or ceremonies.rp.rp_id != reservation.config.hostname:
            raise HumanAccessUnavailable()
        if rate_limiter is not None and not isinstance(rate_limiter, SourceRateLimiter):
            raise HumanAccessUnavailable()
        if (isinstance(tick_seconds, bool) or not isinstance(tick_seconds, (int, float))
                or not 0 < tick_seconds <= 300):
            raise HumanAccessUnavailable()
        self.configuration = configuration
        self.store = store
        self.ceremonies = ceremonies
        self.reservation = reservation
        self.rate_limiter = rate_limiter or SourceRateLimiter()
        self.origin = origin
        self.host = host
        self.tick_seconds = float(tick_seconds)
        self._storage_admission = None
        self._stopped = False

    def bind_storage_admission(self, admission: Callable, *, database: Database) -> None:
        """Admit every write of this composition through ``admission``.

        Binds the access store's audit store (shared with the session
        revoker) to the application's storage admission, the one that admits
        audit writes. ``database`` is the database that admission verifies
        (the application's own): an access store on any other database is
        refused, since that admission would check one filesystem's identity
        and reserve while the writes land on another. Also refuses a
        non-callable admission, an audit store already wired to another
        reservation, and rebinding to a different admission.
        """
        if not callable(admission) or not isinstance(database, Database):
            raise HumanAccessUnavailable()
        audit = self.store.audit
        if self.store.database != database or audit.database != database:
            raise HumanAccessUnavailable()
        if self._storage_admission is not None and self._storage_admission is not admission:
            raise HumanAccessUnavailable()
        if audit.reservation is not None and audit.reservation is not admission:
            raise HumanAccessUnavailable()
        audit.reservation = admission
        self._storage_admission = admission

    @property
    def storage_admitted(self) -> bool:
        """Whether writes go through the bound storage admission."""
        admission = self._storage_admission
        return admission is not None and self.store.audit.reservation is admission

    @property
    def stopped(self) -> bool:
        """Every request is denied while this is True.

        True from ``stop()``, and from the start of ``run()`` until its
        startup check has returned (Codex PR #219): a restarted lifespan never
        serves on the verdict a previous lifespan left behind.
        """
        return self._stopped

    def stop(self) -> None:
        """Deny every later request; called first by the application shutdown.

        The application then cancels ``run()`` and waits for it, before it
        unbinds the storage admission or stops the monitoring runtime.
        """
        self._stopped = True

    async def run(self, *, sleep: Callable = asyncio.sleep) -> None:
        """Startup check, then the periodic check tick and expiry sweep.

        ``tick()`` runs the daily check and the five-minute retries while
        closed; ``end_expired_sessions()`` clears expired rows even when no
        request arrives. A failure is logged without values and access stays
        as the check left it (closed on any doubt).

        Each of them runs on a worker thread that cancellation cannot stop,
        so a cancellation (application shutdown) is deferred until the
        in-flight call has returned and is re-raised afterwards: no verdict
        is published and no session-revocation, marker or expiry write
        happens after ``run()`` has ended, so after the shutdown has moved on
        to unbinding the storage admission. The wait is bounded by the call
        itself: every enumeration of the check runs under the check's
        enumeration timeout, and every SQLite write under the database busy
        timeout. Cancellation during the sleep between ticks ends at once.

        Requests stay denied (``stopped``) from the start of ``run()`` until
        ``startup()`` has returned, so a restarted lifespan never serves on
        the verdict the previous lifespan left behind while listeners or
        routes may have changed (Codex PR #219). ``startup()`` closes access
        before it re-evaluates; once it has returned, the verdict it
        published (open or closed) is current. A ``startup()`` that raises
        may have failed before it closed the old verdict, so requests stay
        denied and ``startup()`` (not ``tick()``) is retried on every tick
        until it returns.
        """
        self._stopped = True
        log = logging.getLogger(__name__)
        started = await self._startup(log)
        while True:
            await sleep(self.tick_seconds)
            if not started:
                started = await self._startup(log)
                continue
            try:
                await run_to_completion(asyncio.to_thread(self.reservation.tick))
            except Exception:
                log.error(Event.HUMAN_ACCESS_CHECK_FAILED)
            try:
                await run_to_completion(asyncio.to_thread(self.store.end_expired_sessions))
            except Exception:
                log.error(Event.HUMAN_ACCESS_CHECK_FAILED)

    async def _startup(self, log) -> bool:
        """Run the startup check; requests are served again only after it returned."""
        try:
            await run_to_completion(asyncio.to_thread(self.reservation.startup))
        except Exception:
            log.error(Event.HUMAN_ACCESS_CHECK_FAILED)
            return False
        self._stopped = False
        return True


class HumanSurface:
    """ASGI front of the human listener; see the module docstring for the order."""

    def __init__(self, app: ASGIApp, access: HumanAccess) -> None:
        if not isinstance(access, HumanAccess):
            raise HumanAccessUnavailable()
        self.app = app
        self.access = access

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            started = False

            async def tracked(message):
                nonlocal started
                started = True
                await send(message)

            try:
                await self._http(scope, receive, tracked)
            except Exception:
                # _Denied and any unexpected fault alike: never a framework
                # error page, traceback or distinguishable status.
                if not started:
                    await send_generic_denial(send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await self.app(scope, receive, send)

    # -- gates ---------------------------------------------------------

    def _origin(self, headers, *, mutating: bool) -> None:
        host = _single(headers, b"host")
        if host is None or _ascii(host) != self.access.host:
            raise _Denied()
        origin = _single(headers, b"origin")
        if origin is None:
            if mutating:
                raise _Denied()
        elif _ascii(origin) != self.access.origin:
            raise _Denied()

    @staticmethod
    def _trusted_peer(scope: Scope) -> None:
        # The actual transport peer and local address, never a forwarded
        # header. Checked before the identity header is read.
        if not _loopback(scope.get("client")) or not _loopback(scope.get("server")):
            raise _Denied()

    def _open(self) -> None:
        if (self.access.stopped or not self.access.storage_admitted
                or not self.access.reservation.access_open):
            raise _Denied()

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = scope.get("headers") or []
        method, path = scope.get("method"), scope.get("path")
        route = {
            ("POST", AUTHENTICATION_OPTIONS_PATH): self._begin_authentication,
            ("POST", AUTHENTICATION_PATH): self._finish_authentication,
            ("GET", SESSION_PATH): self._session,
        }.get((method, path))
        if scope.get("query_string"):
            route = None
        # 1. reserved secure-context origin
        self._origin(headers, mutating=method != "GET")
        # 2. trusted proxy path
        self._trusted_peer(scope)
        identity = proxy_identity(headers)
        # 3. reservation verdict
        self._open()
        if route is None:
            raise _Denied()
        await route(identity, headers, receive, send)

    # -- routes --------------------------------------------------------

    def _limit(self, identity: str) -> None:
        if not self.access.rate_limiter.allow(identity):
            raise _Denied()

    async def _body(self, headers, receive: Receive, limit: int, *, json_required: bool) -> bytes:
        content_type = _single(headers, b"content-type")
        if json_required and (content_type is None or _ascii(content_type).split(";")[0].strip().lower()
                              != "application/json"):
            raise _Denied()
        body = b""
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                raise _Denied()
            body += message.get("body", b"")
            if len(body) > limit:
                raise _Denied()
            if not message.get("more_body", False):
                return body

    async def _begin_authentication(self, identity, headers, receive, send) -> None:
        self._limit(identity)
        body = await self._body(headers, receive, MAX_OPTIONS_BODY, json_required=False)
        if body not in (b"", b"{}"):
            raise _Denied()
        try:
            options = await asyncio.to_thread(self.access.ceremonies.begin_authentication)
        except Exception:
            raise _Denied() from None
        await self._json(send, 200, options)

    async def _finish_authentication(self, identity, headers, receive, send) -> None:
        self._limit(identity)
        body = await self._body(headers, receive, MAX_ASSERTION_BODY, json_required=True)
        try:
            credential = json.loads(body, object_pairs_hook=_no_duplicates,
                                    parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            raise _Denied() from None
        if not isinstance(credential, dict):
            raise _Denied()
        try:
            grant = await asyncio.to_thread(self.access.ceremonies.finish_authentication,
                                            identity, credential)
        except Exception:
            raise _Denied() from None
        if not isinstance(grant, SessionGrant):
            raise _Denied()
        cookie = (f"{SESSION_COOKIE}={base64.urlsafe_b64encode(grant.token).rstrip(b'=').decode()}"
                  "; Path=/; Secure; HttpOnly; SameSite=Strict").encode()
        await send({"type": "http.response.start", "status": 204, "headers": [
            (b"cache-control", b"no-store"),
            (b"set-cookie", cookie),
        ]})
        await send({"type": "http.response.body", "body": b""})

    async def _session(self, identity, headers, receive, send) -> None:
        token = session_token(headers)
        reservation = self.access.reservation
        # A well-formed but unknown, invalidated or expired token is refused
        # by a read-only lookup before the gate lock or any SQLite write lock
        # is taken (Issue #181 item 4): only a token that names a live session
        # row pays for epoch -> authorize -> admit.
        try:
            known = await asyncio.to_thread(self.access.store.session_may_be_current, token)
        except Exception:
            raise _Denied() from None
        if known is not True:
            raise _Denied()
        try:
            # The epoch is taken before authorization, and the authorization
            # transaction, idle-session touch included, commits inside
            # admit(epoch): a close, revocation or reopen after the epoch
            # refuses the request before anything is read or written, so a
            # denied request never extends a session (Issue #144, Codex
            # PR #219). Lock order: gate -> storage admission -> SQLite write
            # lock; the denial bookkeeping runs after the gate is released.
            epoch = await asyncio.to_thread(reservation.epoch)
            if epoch is None:
                raise _Denied()
            principal, permissions = await asyncio.to_thread(
                self.access.store.authorize_session, token, identity,
                admit=lambda: reservation.admit(epoch))
        except Exception:
            raise _Denied() from None
        await self._json(send, 200, {
            "role": principal.role.value,
            "permissions": sorted(item.value for item in permissions),
        })

    @staticmethod
    async def _json(send: Send, status: int, value) -> None:
        body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ]})
        await send({"type": "http.response.body", "body": body})
