"""Human route foundation (Issue #10 phases 1 and 2; ADR-0003, ADR-0004).

The human listener stays closed (``ClosedHumanSurface`` in ``app.main``)
unless the embedder passes a validated ``HumanAccess`` composition, which
requires an explicit ``HumanAccessConfiguration(enabled=True)`` and a fully
configured ``HostnameReservationCheck``. No deployment-file key enables it
yet, so the production entry points keep every human path closed.

When enabled, every HTTP request passes, server-side and in this order:

1. the route table (``ROUTES``): an exact method, a strict path pattern over
   the decoded path (whose raw form must be present and the same, so no
   percent-encoded variant matches and a server that omits ``raw_path``
   matches nothing, Issue #232), and a strict per-route query allowlist; an unmatched
   request still passes the checks below before its denial, so a refusal
   never says which check failed;
2. the dedicated, reserved, secure-context origin: exactly one ``Host`` equal
   to the reserved ``<hostname>[:<port>]`` and, when present, an ``Origin``
   exactly equal to the relying-party origin ``https://<hostname>[:<port>]``
   derived from the reservation; a mutating route requires that ``Origin``;
3. the trusted-proxy path: the actual transport peer and the local listener
   address are loopback (never a ``Forwarded``/``X-Forwarded-For`` value),
   and exactly one well-formed ``Tailscale-User-Login`` header is present.
   A request from any other peer is refused before its identity header is
   read, so a LAN client cannot spoof it;
4. the hostname reservation verdict (``access_open``, pid-guarded) and this
   composition serving (``HumanAccess.stopped``);
5. for a route that needs a session, ``_authorize``: a read-only token
   pre-check, the gate epoch, then ``AccessStore.authorize_request``
   committed inside ``HumanAccess.admit(epoch)``, which re-checks under the
   gate lock that access is open, unchanged since the epoch, and that this
   composition has not stopped (Issue #144/#181/#228). A mutating session
   route also requires ``X-CSRF-Token`` equal to the session's token (Owner
   decision D2), compared inside the same transaction. Later writes of the
   request reuse ``admit(epoch)``;
6. the per-person WebAuthn credential: a session established by a
   user-verified assertion of the person's own passkey. The proxy identity
   is supplementary (ADR-0004 §1): it must be present and reproduce the
   session's keyed binding, but it never selects or authorizes anyone.

Mounted routes (and nothing else; every other method, path, query string,
WebSocket and error path gets the same generic denial):

- ``POST /api/auth/registration/options``: begin redeeming an invitation
  (body ``{"code"}``);
- ``POST /api/auth/registration``: finish it (body ``{"code", "credential",
  "label"?}``); ``204`` with no body and no cookie;
- ``POST /api/auth/authentication/options``: begin a passkey sign-in;
- ``POST /api/auth/authentication``: finish it and set the ``__Host-`` cookie;
- ``GET /api/session``: the caller's own role, permissions and CSRF token;
- ``POST /api/auth/sign-out``: end the caller's own session (CSRF);
- ``POST /api/auth/step-up/options``: an Owner session's step-up challenge
  (CSRF, Issue #10 phase 2 S3);
- ``POST /api/auth/step-up``: verify it and refresh the session's user
  verification (CSRF); ``204`` with no body.

The four ceremony routes run before a credential exists (AUTH-013). Each is
rate-limited per verified proxy identity before the request body is parsed
and before the ceremony takes any gate or SQLite lock (Issue #181); the
sign-in routes also globally; the two step-up routes are charged to the
sign-in limiter the same way (SPECIFICATION: repeated failed step-ups are
rate-limited). Redemption uses its own, stricter limiter with
no global bucket (Owner decisions D4 and 2026-10-11), so a redemption flood
never spends the sign-in buckets and one source cannot stop another's
redemption. A redemption refused after the limiter is counted, value-free
(``HumanAccess.refused_redemptions``, logged as
``invitation_redemption_refused`` on the first refusal and each time the
count doubles), never with the code, identity or reason; a refused step-up
finish is counted the same way (``HumanAccess.refused_step_ups``, logged as
``owner_step_up_refused``). An invitation code travels
only in the request body and is decoded strictly
(``invitation_code.parse_invitation_code``) before the gate; a code that does
not parse never reaches SQLite. Session routes are not charged; a forged or
stale cookie is refused by a read-only token lookup before the gate or any
SQLite write lock. No live, recording, timeline, event, administration,
health or version route is mounted here, and no ``OWNER_OP`` route yet (S4):
the step-up routes require ``OWNER_READ`` (an Owner session, fresh or stale),
so a non-Owner gets the generic denial inside the authorization transaction,
before any idle touch.

Every refusal is the generic, non-branding not-found response used by the
closed surface: no product/version header, no cookie, ``no-store``; an
absent, malformed, unknown, expired, redeemed, revoked or generation-stale
invitation code gets exactly that response. Two fixed exceptions exist: an
otherwise valid Owner session on an ``OWNER_OP`` route whose user
verification is stale gets ``403 {"detail":"step_up_required"}`` (Owner
decision D3), and the holder of a valid invitation whose verified
authenticator is backup eligible, in a deployment that requires device-bound
credentials, gets ``409 {"detail":"device_bound_credential_required"}``
(decided under the gate inside the redemption transaction, after the
invitation proved valid and bound to the consumed challenge,
``AccessStore.enroll_credential``). Nothing
here logs a header, identity, token, CSRF token, invitation code, challenge
or body.
"""

from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
import ipaddress
import json
import logging
import re
import threading
from typing import Callable, Iterator

from starlette.types import ASGIApp, Receive, Scope, Send

from app.completion import run_to_completion
from app.logging import Event
from app.storage.database import Database, PinnedDatabase
from .invitation_code import InvalidInvitationCode, parse_invitation_code
from .model import Credential
from .passkeys import DeviceBoundCredentialRequired, PasskeyCeremonies, SessionGrant
from .rate_limit import SourceRateLimiter, redemption_rate_limiter
from .reservation import HostnameReservationCheck, HumanAccessClosed
from .reservation_store import ListenerExceptionStore, ReservationSessionRevocation
from .session_binding import canonical_identity
from .store import AccessStore, Requirement, SessionView, StepUpRequired


PROXY_IDENTITY_HEADER = b"tailscale-user-login"
# Owner decision D2 (2026-10-11): the CSRF token travels in this header only.
CSRF_HEADER = b"x-csrf-token"
SESSION_COOKIE = "__Host-session"
AUTHENTICATION_OPTIONS_PATH = "/api/auth/authentication/options"
AUTHENTICATION_PATH = "/api/auth/authentication"
SESSION_PATH = "/api/session"
SIGN_OUT_PATH = "/api/auth/sign-out"
REGISTRATION_OPTIONS_PATH = "/api/auth/registration/options"
REGISTRATION_PATH = "/api/auth/registration"
STEP_UP_OPTIONS_PATH = "/api/auth/step-up/options"
STEP_UP_PATH = "/api/auth/step-up"
MAX_OPTIONS_BODY = 1024
MAX_ASSERTION_BODY = 64 * 1024
MAX_REGISTRATION_BODY = 64 * 1024
MAX_LABEL = 64
MAX_EMPTY_BODY = 2
MAX_QUERY_BYTES = 512
MAX_QUERY_VALUE = 128
DEFAULT_TICK_SECONDS = 30.0

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_DENIAL_BODY = b'{"detail":"Not Found"}'
_STEP_UP_BODY = b'{"detail":"step_up_required"}'
_DEVICE_BOUND_BODY = b'{"detail":"device_bound_credential_required"}'
# Clears the session cookie with the attributes it was set with.
_CLEARED_COOKIE = (SESSION_COOKIE + "=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict").encode()


async def _fixed_json(send: Send, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
    ]})
    await send({"type": "http.response.body", "body": body})


async def send_generic_denial(send: Send) -> None:
    """The one non-branding refusal for every human path (ADR-0003)."""
    await _fixed_json(send, 404, _DENIAL_BODY)


async def send_step_up_required(send: Send) -> None:
    """The fixed step-up response for a stale Owner on an ``OWNER_OP`` route (D3)."""
    await _fixed_json(send, 403, _STEP_UP_BODY)


async def send_device_bound_required(send: Send) -> None:
    """The fixed response to a valid invitation's backup-eligible registration."""
    await _fixed_json(send, 409, _DEVICE_BOUND_BODY)


class HumanAccessUnavailable(ValueError):
    """The human surface cannot be composed; carries no configuration value."""

    def __init__(self) -> None:
        super().__init__("human access is unavailable")


class HumanAccessAlreadyRunning(RuntimeError):
    """A second ``HumanAccess.run()`` while one is running (Issue #228 item 3)."""

    def __init__(self) -> None:
        super().__init__("human access is already running")


class HumanAccessState(StrEnum):
    """Value-free lifecycle of one composition (Issue #228 item 2).

    Readable by the embedder as ``HumanAccess.state`` (and through
    ``application.state.human_access``); it carries no reason, identity,
    path or exception text.
    """

    NOT_STARTED = "not_started"
    STARTING = "starting"
    SERVING = "serving"
    CHECK_FAILING = "check_failing"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True)
class HumanAccessConfiguration:
    """Explicit deployment switch; disabled unless stated."""

    enabled: bool = False


def reserved_origin(check: HostnameReservationCheck) -> tuple[str, str]:
    """``(origin, host header)`` for the reserved name; https only.

    The default port is omitted, as browsers serialize it. ``http://localhost``
    is never offered here: the Owner decision of 2026-10-11 rejected any
    strictly local ``http://localhost`` Owner route (and any path without a
    trusted-proxy identity), so the Owner signs in through this reserved
    ``https`` origin like every other person (``SECURITY.md``,
    ``server/app/auth/README.md``).
    """
    config = check.config
    authority = config.hostname if config.port == 443 else f"{config.hostname}:{config.port}"
    return f"https://{authority}", authority


class _Denied(Exception):
    pass


class _StepUp(Exception):
    """A stale, otherwise valid Owner session on an ``OWNER_OP`` route."""


@dataclass(frozen=True)
class Route:
    """One mounted human route (Issue #10 phase 2, S1).

    ``path`` is matched with ``fullmatch`` against the decoded request path.
    ``mutating`` routes require an exact ``Origin``; ``csrf`` routes also
    require ``X-CSRF-Token``. ``body_limit`` bounds the request body
    (``0``: the body is not read). ``query`` is the strict allowlist of
    query parameter names with the pattern each value must fully match; an
    unknown, repeated or over-long parameter is a denial.
    """

    method: str
    path: re.Pattern
    requirement: Requirement
    handler: str
    mutating: bool
    csrf: bool
    body_limit: int
    query: tuple[tuple[str, re.Pattern], ...] = ()

    def __post_init__(self) -> None:
        if self.mutating != (self.method != "GET"):
            raise ValueError("a route mutates exactly when its method is not GET")
        if self.csrf and (not self.mutating or self.requirement is Requirement.PRE_CREDENTIAL):
            raise ValueError("CSRF applies to session-bearing mutations")
        if self.mutating and self.requirement is not Requirement.PRE_CREDENTIAL and not self.csrf:
            raise ValueError("a session-bearing mutation requires CSRF")
        names = [name for name, _ in self.query]
        if len(set(names)) != len(names):
            raise ValueError("query parameter names must be unique")


def _exact(path: str) -> re.Pattern:
    return re.compile(re.escape(path))


ROUTES: tuple[Route, ...] = (
    Route("POST", _exact(REGISTRATION_OPTIONS_PATH), Requirement.PRE_CREDENTIAL, "_begin_registration",
          mutating=True, csrf=False, body_limit=MAX_OPTIONS_BODY),
    Route("POST", _exact(REGISTRATION_PATH), Requirement.PRE_CREDENTIAL, "_finish_registration",
          mutating=True, csrf=False, body_limit=MAX_REGISTRATION_BODY),
    Route("POST", _exact(AUTHENTICATION_OPTIONS_PATH), Requirement.PRE_CREDENTIAL, "_begin_authentication",
          mutating=True, csrf=False, body_limit=MAX_OPTIONS_BODY),
    Route("POST", _exact(AUTHENTICATION_PATH), Requirement.PRE_CREDENTIAL, "_finish_authentication",
          mutating=True, csrf=False, body_limit=MAX_ASSERTION_BODY),
    Route("GET", _exact(SESSION_PATH), Requirement.SESSION, "_session",
          mutating=False, csrf=False, body_limit=0),
    Route("POST", _exact(SIGN_OUT_PATH), Requirement.SESSION, "_sign_out",
          mutating=True, csrf=True, body_limit=MAX_EMPTY_BODY),
    # S3: OWNER_READ, not OWNER_OP, so a stale Owner can refresh, and not
    # SESSION, so a non-Owner is refused before the idle touch commits.
    Route("POST", _exact(STEP_UP_OPTIONS_PATH), Requirement.OWNER_READ, "_begin_step_up",
          mutating=True, csrf=True, body_limit=MAX_EMPTY_BODY),
    Route("POST", _exact(STEP_UP_PATH), Requirement.OWNER_READ, "_finish_step_up",
          mutating=True, csrf=True, body_limit=MAX_ASSERTION_BODY),
)


def match_route(scope: Scope, routes: tuple[Route, ...] = None) -> Route | None:
    """The route for this method and path, or ``None``.

    The raw path must be present and exactly the decoded path, so a
    percent-encoded or otherwise re-encoded spelling of a mounted path
    matches nothing. A server that does not supply ``raw_path`` matches
    nothing either (fail closed, Issue #232): the decoded path alone cannot
    show whether it was percent-encoded.
    """
    method, path = scope.get("method"), scope.get("path")
    if not isinstance(method, str) or not isinstance(path, str):
        return None
    raw = scope.get("raw_path")
    if not isinstance(raw, bytes):
        return None
    try:
        if raw != path.encode("ascii"):
            return None
    except UnicodeEncodeError:
        return None
    for route in ROUTES if routes is None else routes:
        if route.method == method and route.path.fullmatch(path):
            return route
    return None


def parse_query(route: Route, raw: object) -> dict[str, str]:
    """Strictly parse a query string against the route's allowlist.

    No percent-decoding and no ``+``: a value must fully match its pattern as
    sent. An empty string is no parameters. Anything unknown, repeated,
    valueless, over-long (whole string or one value) or not ASCII is a
    denial.
    """
    if raw in (None, b""):
        return {}
    if not isinstance(raw, bytes) or len(raw) > MAX_QUERY_BYTES:
        raise _Denied()
    text = _ascii(raw)
    allowed = dict(route.query)
    result: dict[str, str] = {}
    for part in text.split("&"):
        name, separator, value = part.partition("=")
        if (not separator or name not in allowed or name in result
                or len(value) > MAX_QUERY_VALUE or not allowed[name].fullmatch(value)):
            raise _Denied()
        result[name] = value
    return result


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


def csrf_header(headers) -> str:
    """Exactly one well-formed ``X-CSRF-Token`` value; anything else denies."""
    raw = _single(headers, CSRF_HEADER)
    if raw is None:
        raise _Denied()
    value = _ascii(raw)
    if not _TOKEN.fullmatch(value):
        raise _Denied()
    return value


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite number")


def _json_object(body: bytes) -> dict:
    """A strict JSON object: no duplicate member, no NaN/Infinity, else denial."""
    try:
        value = json.loads(body, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise _Denied() from None
    if not isinstance(value, dict):
        raise _Denied()
    return value


def _invitation_secret(value: object) -> bytes:
    """The invitation code's secret; a code that does not parse is a denial."""
    try:
        return parse_invitation_code(value)
    except InvalidInvitationCode:
        raise _Denied() from None


def _label(value: object) -> str | None:
    """An optional credential label, checked as ``Credential`` checks it (and no DEL)."""
    if value is None:
        return None
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_LABEL
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise _Denied()
    return value


class ServingGate:
    """The reservation session gate, also closed while the composition is stopped.

    Issue #228 item 1: ``HumanAccess.stopped`` used to be read only at the
    request entry, so a request already past it when ``stop()`` ran, or when
    a periodic check failed, could still be authorized. ``admit()`` now
    re-reads it after taking the gate lock, and ``epoch()`` is ``None`` while
    stopped. This is the gate every human commit uses: the routes'
    ``_authorize`` and later writes, and the ceremonies (installed through
    ``PasskeyCeremonies.guard_session_gate``). A commit admitted before
    ``stop()`` may still complete; none is admitted after it.
    """

    def __init__(self, access: "HumanAccess"):
        self._access = access
        self.reservation = access.reservation

    def epoch(self) -> int | None:
        if self._access.stopped:
            return None
        return self.reservation.epoch()

    @contextmanager
    def admit(self, epoch: int | None) -> Iterator[None]:
        with self.reservation.admit(epoch):
            if self._access.stopped:
                raise HumanAccessClosed()
            yield


class HumanAccess:
    """Validated composition of the human route foundation.

    Refuses construction unless the deployment explicitly enabled it, the
    session gate is a ``HostnameReservationCheck`` with every opening input
    configured (resolver, socket owners, own sockets, unprivileged port
    start, session revoker), the two rate limiters are distinct
    ``SourceRateLimiter`` objects (sign-in and, per Owner decision D4,
    invitation redemption), the ceremonies use exactly that gate and this
    audited access store with a session-binding key, and the relying party
    is the reserved https origin. A missing or substituted gate is never
    accepted (Issue #181 item 3). The gate's session revoker must be a
    ``ReservationSessionRevocation`` of exactly this store, so a revocation
    after an exposure invalidates the sessions this surface authorizes and
    not another database's. A stored listener-exception source, when the
    gate has one, must be a ``ListenerExceptionStore`` on that same database:
    the exceptions the check applies are the ones the audited Owner path
    commits next to this store's sessions, never another database's.

    On success the ceremonies' gate is replaced by this composition's
    ``ServingGate`` (Issue #228 item 1), so one ``PasskeyCeremonies`` serves
    exactly one composition; a second composition over the same ceremonies
    is refused.

    Every human-access write is admitted through the application's storage
    admission: ``create_app`` binds it with ``bind_storage_admission`` (the
    Main storage policy, or the embedder's injected reservation), and until
    it is bound every request is denied. An audit store already wired to a
    different reservation is refused rather than silently rebound.

    A new composition denies every request (``stopped``) until a ``run()``
    of the application lifespan has completed its startup check (Codex
    PR #219), so a composition whose lifespan never runs serves nothing.
    """

    def __init__(self, configuration: HumanAccessConfiguration, *, store: AccessStore,
                 ceremonies: PasskeyCeremonies, reservation: HostnameReservationCheck,
                 rate_limiter: SourceRateLimiter | None = None,
                 redemption_limiter: SourceRateLimiter | None = None,
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
        if redemption_limiter is not None and (not isinstance(redemption_limiter, SourceRateLimiter)
                                               or redemption_limiter is rate_limiter):
            # Separate buckets (D4): one shared object would let a redemption
            # flood starve sign-in.
            raise HumanAccessUnavailable()
        if (isinstance(tick_seconds, bool) or not isinstance(tick_seconds, (int, float))
                or not 0 < tick_seconds <= 300):
            raise HumanAccessUnavailable()
        self.configuration = configuration
        self.store = store
        self.ceremonies = ceremonies
        self.reservation = reservation
        self.rate_limiter = rate_limiter or SourceRateLimiter()
        self.redemption_limiter = redemption_limiter or redemption_rate_limiter()
        self.origin = origin
        self.host = host
        self.tick_seconds = float(tick_seconds)
        self._storage_admission = None
        # Denied until a run() of this lifespan has completed its startup
        # check (Codex PR #219): a composition that was never run, or whose
        # lifespan is disabled, serves nothing.
        self._serving = False
        self._halted = False
        self._running = False
        self._state = HumanAccessState.NOT_STARTED
        self._check_failures = 0
        self._sweep_failures = 0
        # Bounded, value-free health (AUTH-013, PR #234 review): how many
        # redemption requests that passed the limiter were refused. No code,
        # identity, invitation or reason is kept.
        self.refused_redemptions = 0
        # The same for refused step-up finishes (SPECIFICATION: logged
        # without credential material): a count only.
        self.refused_step_ups = 0
        self._refusal_lock = threading.Lock()
        self.gate = ServingGate(self)
        # Last: everything above validated, so a refused composition leaves
        # the ceremonies untouched.
        ceremonies.guard_session_gate(self.gate)

    def note_refused_redemption(self) -> None:
        """Count one refused redemption; log the value-free event at 1, 2, 4, 8, ..."""
        with self._refusal_lock:
            self.refused_redemptions += 1
            count = self.refused_redemptions
        if count & (count - 1) == 0:
            logging.getLogger(__name__).warning(Event.INVITATION_REDEMPTION_REFUSED)

    def note_refused_step_up(self) -> None:
        """Count one refused step-up finish; log the value-free event at 1, 2, 4, 8, ..."""
        with self._refusal_lock:
            self.refused_step_ups += 1
            count = self.refused_step_ups
        if count & (count - 1) == 0:
            logging.getLogger(__name__).warning(Event.OWNER_STEP_UP_REFUSED)

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

        True from construction until a ``run()`` has completed its startup
        check, from ``stop()``, after ``run()`` has ended, and from a failed
        periodic check until the retried startup check has returned (Codex
        PR #219): requests are served only on a verdict this lifespan's
        ``run()`` published and keeps checking. ``admit()`` re-reads it under
        the gate lock, so a request already in flight is refused as well
        (Issue #228 item 1).
        """
        return self._halted or not self._serving

    @property
    def state(self) -> HumanAccessState:
        """Value-free lifecycle state for the embedder (Issue #228 item 2)."""
        return self._state

    @property
    def check_failures(self) -> int:
        """Consecutive failed startup/periodic checks; ``0`` once one returned."""
        return self._check_failures

    def epoch(self) -> int | None:
        """The gate epoch for a request; ``None`` while closed or stopped."""
        return self.gate.epoch()

    def admit(self, epoch: int | None):
        """Hold the gate for one commit; see ``ServingGate.admit``."""
        return self.gate.admit(epoch)

    def stop(self) -> None:
        """Deny every later request; called first by the application shutdown.

        ``run()`` starts no further check or sweep after this, and a commit
        not yet admitted through ``admit()`` is refused. The application then
        cancels ``run()`` and waits for it, before it unbinds the storage
        admission or stops the monitoring runtime.
        """
        self._halted = True
        self._serving = False
        if self._state is not HumanAccessState.FAILED:
            self._state = HumanAccessState.STOPPED

    async def run(self, *, sleep: Callable = asyncio.sleep) -> None:
        """Startup check, then the periodic check tick and expiry sweep.

        ``tick()`` runs the daily check and the five-minute retries while
        closed; ``end_expired_sessions()`` clears expired rows even when no
        request arrives. A failure is logged without values: a failed check
        each time, a failed sweep when its streak starts and each time the
        streak doubles (Issue #228 item 4). ``state`` and ``check_failures``
        make a failing or ended ``run()`` visible to the embedder (Issue #228
        item 2). A second ``run()`` while one is running is refused with
        ``HumanAccessAlreadyRunning`` and changes nothing (item 3).

        Requests are served only while this lifespan's checks hold (Codex
        PR #219). They are denied (``stopped``) from the start of ``run()``
        until ``startup()`` has returned, so a restarted lifespan never serves
        on the verdict the previous lifespan left behind while listeners or
        routes may have changed: ``startup()`` closes access before it
        re-evaluates, and once it has returned the verdict it published (open
        or closed) is current. A ``startup()`` or ``tick()`` that raises may
        have failed before it closed the previous verdict, so requests are
        denied again and ``startup()`` (not ``tick()``) is retried on every
        tick until it returns. Requests are denied again once ``run()`` ends,
        since nothing re-checks the verdict after that.

        After ``stop()``, ``run()`` starts no further startup, tick or sweep
        and returns. Each of them runs on a worker thread that cancellation
        cannot stop, so a cancellation (application shutdown) is deferred
        until the in-flight call has returned and is re-raised afterwards: no
        verdict is published and no session-revocation, marker or expiry
        write happens after ``run()`` has ended, so after the shutdown has
        moved on to unbinding the storage admission. That wait is bounded by
        the one in-flight call: the check's enumeration timeout for each
        enumeration, plus, for a write, at most one in-flight monitoring job
        ahead of it in the storage admission (which waits for that job
        without a timeout of its own), plus the SQLite busy timeout.
        Cancellation during the sleep between ticks ends at once.
        """
        if self._running:
            raise HumanAccessAlreadyRunning()
        self._running = True
        self._halted = False
        self._serving = False
        self._state = HumanAccessState.STARTING
        log = logging.getLogger(__name__)
        failed = False
        try:
            started = await self._startup(log)
            while True:
                await sleep(self.tick_seconds)
                if self._halted:
                    return
                if not started:
                    started = await self._startup(log)
                    continue
                try:
                    await run_to_completion(asyncio.to_thread(self.reservation.tick))
                except Exception:
                    # The tick may have failed before it closed the gate (a
                    # raising clock, an unexpected fault): fail closed until
                    # a startup check has re-evaluated it (Codex PR #219).
                    self._serving = False
                    started = False
                    self._check_failed()
                    log.error(Event.HUMAN_ACCESS_CHECK_FAILED)
                else:
                    self._check_failures = 0
                if self._halted:
                    return
                try:
                    await run_to_completion(asyncio.to_thread(self.store.end_expired_sessions))
                except Exception:
                    self._sweep_failures += 1
                    if self._sweep_failures & (self._sweep_failures - 1) == 0:
                        log.error(Event.HUMAN_ACCESS_SWEEP_FAILED)
                else:
                    self._sweep_failures = 0
        except asyncio.CancelledError:
            raise
        except BaseException:
            failed = True
            log.error(Event.HUMAN_ACCESS_RUN_FAILED)
            raise
        finally:
            self._serving = False
            self._running = False
            self._state = HumanAccessState.FAILED if failed else HumanAccessState.STOPPED

    def _check_failed(self) -> None:
        self._check_failures += 1
        if not self._halted:
            self._state = HumanAccessState.CHECK_FAILING

    async def _startup(self, log) -> bool:
        """Run the startup check; requests are served again only after it returned."""
        try:
            await run_to_completion(asyncio.to_thread(self.reservation.startup))
        except Exception:
            self._check_failed()
            log.error(Event.HUMAN_ACCESS_CHECK_FAILED)
            return False
        self._check_failures = 0
        # Still denied after a stop() during the check (``stopped``).
        self._serving = True
        if not self._halted:
            self._state = HumanAccessState.SERVING
        return True


@dataclass(frozen=True)
class _Request:
    scope: Scope
    receive: Receive
    send: Send
    headers: list
    identity: str
    route: Route
    query: dict


@dataclass(frozen=True)
class _Authorized:
    """A request authorized inside the gate; later writes reuse ``epoch``."""

    session: SessionView
    epoch: int


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
            except _StepUp:
                if not started:
                    await send_step_up_required(send)
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
        route = match_route(scope)
        # 1. reserved secure-context origin; a POST without a mounted route
        # is held to the mutating rule as well.
        self._origin(headers, mutating=route.mutating if route is not None else scope.get("method") != "GET")
        # 2. trusted proxy path
        self._trusted_peer(scope)
        identity = proxy_identity(headers)
        # 3. reservation verdict and this composition serving
        self._open()
        if route is None:
            raise _Denied()
        query = parse_query(route, scope.get("query_string"))
        request = _Request(scope, receive, send, headers, identity, route, query)
        await getattr(self, route.handler)(request)

    async def _authorize(self, request: _Request, requirement: Requirement) -> _Authorized:
        """Authorize a session-bearing request inside the gate.

        Order: the cookie's form; a read-only token pre-check that takes no
        gate lock and no SQLite write lock (a forged or stale cookie stops
        here, Issue #181 item 4); the gate epoch; then
        ``AccessStore.authorize_request`` inside ``admit(epoch)``, with the
        CSRF header compared in that transaction for a CSRF route. Any
        refusal is ``_Denied``; only ``StepUpRequired`` on ``OWNER_OP`` is
        ``_StepUp``. The store releases the gate before its denial
        bookkeeping.
        """
        if requirement is Requirement.PRE_CREDENTIAL or requirement is not request.route.requirement:
            raise _Denied()
        token = session_token(request.headers)
        csrf = csrf_header(request.headers) if request.route.csrf else None
        access = self.access
        try:
            known = await asyncio.to_thread(access.store.session_may_be_current, token)
        except Exception:
            raise _Denied() from None
        if known is not True:
            raise _Denied()
        try:
            epoch = await asyncio.to_thread(access.epoch)
            if epoch is None:
                raise _Denied()
            session = await asyncio.to_thread(
                access.store.authorize_request, token, request.identity, requirement,
                admit=lambda: access.admit(epoch), csrf=csrf)
        except StepUpRequired:
            if requirement is Requirement.OWNER_OP:
                raise _StepUp() from None
            raise _Denied() from None
        except Exception:
            raise _Denied() from None
        if not isinstance(session, SessionView):
            raise _Denied()
        return _Authorized(session, epoch)

    # -- routes --------------------------------------------------------

    def _limit(self, identity: str) -> None:
        if not self.access.rate_limiter.allow(identity):
            raise _Denied()

    def _limit_redemption(self, identity: str) -> None:
        if not self.access.redemption_limiter.allow(identity):
            raise _Denied()

    async def _body(self, request: _Request, *, json_required: bool) -> bytes:
        limit = request.route.body_limit
        content_type = _single(request.headers, b"content-type")
        if json_required and (content_type is None or _ascii(content_type).split(";")[0].strip().lower()
                              != "application/json"):
            raise _Denied()
        body = b""
        while True:
            message = await request.receive()
            if message.get("type") != "http.request":
                raise _Denied()
            body += message.get("body", b"")
            if len(body) > limit:
                raise _Denied()
            if not message.get("more_body", False):
                return body

    async def _begin_authentication(self, request: _Request) -> None:
        self._limit(request.identity)
        body = await self._body(request, json_required=False)
        if body not in (b"", b"{}"):
            raise _Denied()
        try:
            options = await asyncio.to_thread(self.access.ceremonies.begin_authentication)
        except Exception:
            raise _Denied() from None
        await self._json(request.send, 200, options)

    async def _begin_registration(self, request: _Request) -> None:
        """Creation options for a valid invitation code (AUTH-013, D4, D5).

        Order: the redemption limiter (before the body is parsed and before
        any gate or SQLite work), the strict body ``{"code": <canonical
        code>}``, the code's strict decoding, then
        ``PasskeyCeremonies.begin_registration``, which binds a challenge to
        the invitation and counts the per-code attempt inside the gate. Every
        refusal is the generic denial.
        """
        self._limit_redemption(request.identity)
        try:
            body = _json_object(await self._body(request, json_required=True))
            if set(body) != {"code"}:
                raise _Denied()
            secret = _invitation_secret(body["code"])
            try:
                options = await asyncio.to_thread(self.access.ceremonies.begin_registration,
                                                  secret, request.identity)
            except Exception:
                raise _Denied() from None
        except _Denied:
            self.access.note_refused_redemption()
            raise
        await self._json(request.send, 200, options)

    async def _finish_registration(self, request: _Request) -> None:
        """Verify the registration and redeem the invitation (single use).

        Same order as ``_begin_registration``.
        ``PasskeyCeremonies.finish_registration`` consumes the challenge,
        verifies the registration (type, challenge, exact origin, rpId hash,
        UP and UV, attestation, algorithm, BE/BS) and commits the credential,
        the redemption and its audit record in one conditional transaction
        inside ``admit(epoch)``. Success is ``204`` with no body and no
        cookie: the invited person signs in afterwards like anyone else. Only
        ``DeviceBoundCredentialRequired`` has its own fixed ``409``.
        """
        self._limit_redemption(request.identity)
        try:
            body = _json_object(await self._body(request, json_required=True))
            if not {"code", "credential"} <= set(body) <= {"code", "credential", "label"}:
                raise _Denied()
            secret = _invitation_secret(body["code"])
            credential = body["credential"]
            if not isinstance(credential, dict):
                raise _Denied()
            label = _label(body.get("label"))
            try:
                enrolled = await asyncio.to_thread(self.access.ceremonies.finish_registration,
                                                   secret, request.identity, credential, label=label)
            except DeviceBoundCredentialRequired:
                # A refused redemption too (AUTH-013): counted and logged
                # value-free like every other refusal, then its own 409.
                self.access.note_refused_redemption()
                await send_device_bound_required(request.send)
                return
            except Exception:
                raise _Denied() from None
            if not isinstance(enrolled, Credential):
                raise _Denied()
        except _Denied:
            self.access.note_refused_redemption()
            raise
        await request.send({"type": "http.response.start", "status": 204, "headers": [
            (b"cache-control", b"no-store"),
        ]})
        await request.send({"type": "http.response.body", "body": b""})

    async def _finish_authentication(self, request: _Request) -> None:
        self._limit(request.identity)
        credential = _json_object(await self._body(request, json_required=True))
        try:
            grant = await asyncio.to_thread(self.access.ceremonies.finish_authentication,
                                            request.identity, credential)
        except Exception:
            raise _Denied() from None
        if not isinstance(grant, SessionGrant):
            raise _Denied()
        cookie = (f"{SESSION_COOKIE}={base64.urlsafe_b64encode(grant.token).rstrip(b'=').decode()}"
                  "; Path=/; Secure; HttpOnly; SameSite=Strict").encode()
        await request.send({"type": "http.response.start", "status": 204, "headers": [
            (b"cache-control", b"no-store"),
            (b"set-cookie", cookie),
        ]})
        await request.send({"type": "http.response.body", "body": b""})

    async def _session(self, request: _Request) -> None:
        # The epoch is taken before authorization, and the authorization
        # transaction, idle-session touch included, commits inside
        # admit(epoch): a close, revocation, reopen or stop() after the epoch
        # refuses the request before anything is read or written, so a denied
        # request never extends a session (Issue #144, Codex PR #219, #228).
        authorized = await self._authorize(request, Requirement.SESSION)
        session = authorized.session
        try:
            csrf = self.access.store.csrf_token(session.session_id)
        except Exception:
            raise _Denied() from None
        await self._json(request.send, 200, {
            "csrf": csrf,
            "role": session.role.value,
            "permissions": sorted(item.value for item in session.permissions),
        })

    async def _sign_out(self, request: _Request) -> None:
        """End the caller's own session (Owner decision D7).

        Exact ``Origin`` and ``X-CSRF-Token`` are required. Two separate
        gated commits run with the same epoch (Issue #232 item 3):
        ``_authorize`` commits the authorization and its idle touch inside
        one ``admit(epoch)``, then ``AccessStore.sign_out`` commits the
        invalidation together with its ``sign_out_principal`` audit record
        inside a second ``admit(epoch)``. A close, revocation or ``stop()``
        between the two refuses the second, and a change that ended the
        session in between makes it the generic denial; the race is harmless
        because sign-out only removes access. While access is closed or the
        composition is stopped the sign-out is the generic denial and changes
        nothing (accepted, D7). Success clears the cookie with ``Max-Age=0``
        and the attributes it was set with.
        """
        body = await self._body(request, json_required=False)
        if body not in (b"", b"{}"):
            raise _Denied()
        authorized = await self._authorize(request, Requirement.SESSION)
        access = self.access
        try:
            await asyncio.to_thread(access.store.sign_out, authorized.session,
                                    admit=lambda: access.admit(authorized.epoch))
        except Exception:
            raise _Denied() from None
        await request.send({"type": "http.response.start", "status": 204, "headers": [
            (b"cache-control", b"no-store"),
            (b"set-cookie", _CLEARED_COOKIE),
        ]})
        await request.send({"type": "http.response.body", "body": b""})

    async def _begin_step_up(self, request: _Request) -> None:
        """An Owner session's step-up challenge (Issue #10 phase 2 S3, AUTH-008).

        Order: the sign-in limiter (before the body is read), an empty body,
        ``_authorize`` with ``OWNER_READ`` and the CSRF header inside
        ``admit(epoch)``, then ``PasskeyCeremonies.begin_step_up`` with that
        same epoch, which stores the challenge (bound to this session, at most
        one per session) inside a second ``admit(epoch)``. The response is
        only the ceremony's request options: the challenge, the relying-party
        id, the timeout, ``userVerification: "required"`` and the session's
        own credential as the single allowed credential. A stale Owner is
        served (refreshing is the point); a non-Owner, a close, ``stop()`` or
        a failed tick in between is the generic denial.
        """
        self._limit(request.identity)
        body = await self._body(request, json_required=False)
        if body not in (b"", b"{}"):
            raise _Denied()
        authorized = await self._authorize(request, Requirement.OWNER_READ)
        token = session_token(request.headers)
        try:
            options = await asyncio.to_thread(self.access.ceremonies.begin_step_up, token, request.identity,
                                              epoch=authorized.epoch)
        except Exception:
            raise _Denied() from None
        await self._json(request.send, 200, options)

    async def _finish_step_up(self, request: _Request) -> None:
        """Verify the step-up assertion and refresh the session's verification.

        Same order as ``_begin_step_up``, with the strict JSON assertion as
        the body. ``PasskeyCeremonies.finish_step_up`` consumes the session's
        challenge, verifies type, challenge, exact origin, rpId hash, UP, UV,
        signature, counter and backup flags, refuses any credential other
        than the one that created this session (another person's passkey at
        the same workstation included), and commits the new verification
        time with its boot pair and a ``verify_principal_step_up`` audit
        record inside ``admit(epoch)``. Success is ``204`` with no body; the
        Owner operation is then retried by the client and re-checked
        server-side. Every refusal is the generic denial and changes no
        verification time, counter or audit record (the authorization's idle
        touch is the only write, as for any authenticated request); it is
        counted value-free (``note_refused_step_up``).
        """
        self._limit(request.identity)
        try:
            credential = _json_object(await self._body(request, json_required=True))
            authorized = await self._authorize(request, Requirement.OWNER_READ)
            token = session_token(request.headers)
            try:
                await asyncio.to_thread(self.access.ceremonies.finish_step_up, token, request.identity,
                                        credential, epoch=authorized.epoch)
            except Exception:
                raise _Denied() from None
        except _Denied:
            self.access.note_refused_step_up()
            raise
        await request.send({"type": "http.response.start", "status": 204, "headers": [
            (b"cache-control", b"no-store"),
        ]})
        await request.send({"type": "http.response.body", "body": b""})

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
