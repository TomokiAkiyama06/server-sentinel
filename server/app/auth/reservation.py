"""ADR-0003 dedicated-hostname reservation check: detection, not prevention.

The reserved hostname must serve this deployment alone on every scheme and
port. That is a deployment obligation met by the Owner-recorded isolation
(a dedicated network identity, or a single-purpose node enforced by OS/service
policy outside this application). This module only *verifies what it can
observe*: at startup and daily it enumerates the actual TCP listening sockets
that answer on the reserved addresses and the proxy (Tailscale Serve) routes,
and returns a closed verdict on any other answer, a missing mapping, an
unstated isolation mode, or an enumeration that fails or times out.

It cannot stop a local process from binding the reserved address, and a bind
between two checks is not seen until the next one: detection bounds the
exposure window; only the deployment isolation removes it.

Enumerators and the Owner fault sink are injected. Nothing here reads the host
implicitly, runs ``tailscale``, mounts a route, changes Tailscale ACLs/Grants,
or needs Tailscale administrative credentials. The Serve status parser follows
the ``tailscale serve status --json`` shape as understood from upstream
sources; the real installed output format is unverified (see MANUAL_TEST.md).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import json
import math
import re
import sys
import threading
import time
from typing import Callable, Iterable, Protocol


DAILY_SECONDS = 86400
RETRY_WHILE_CLOSED_SECONDS = 300
ENUMERATION_TIMEOUT_SECONDS = 10.0
MAX_PROC_NET_LINES = 1_000_000
MAX_SERVE_STATUS_BYTES = 1_048_576
TCP_LISTEN = "0A"

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
_HOSTNAME = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")


class ReservationEnumerationError(Exception):
    """An enumeration could not be performed or its output was not understood."""

    def __init__(self, code: str = "ENUMERATION_UNAVAILABLE"):
        super().__init__(code)


class IsolationMode(StrEnum):
    """How the Owner states the reservation is enforced outside the application."""

    DEDICATED_NETWORK_IDENTITY = "dedicated_network_identity"
    SINGLE_PURPOSE_NODE = "single_purpose_node"


class Reason(StrEnum):
    ISOLATION_UNSTATED = "ISOLATION_UNSTATED"
    LISTENER_ENUMERATION_UNAVAILABLE = "LISTENER_ENUMERATION_UNAVAILABLE"
    LISTENER_ENUMERATION_TIMEOUT = "LISTENER_ENUMERATION_TIMEOUT"
    ROUTE_ENUMERATION_UNAVAILABLE = "ROUTE_ENUMERATION_UNAVAILABLE"
    ROUTE_ENUMERATION_TIMEOUT = "ROUTE_ENUMERATION_TIMEOUT"
    UNEXPECTED_LISTENER = "UNEXPECTED_LISTENER"
    UNEXPECTED_ROUTE = "UNEXPECTED_ROUTE"
    MAPPING_MISSING = "MAPPING_MISSING"
    HUMAN_LISTENER_MISSING = "HUMAN_LISTENER_MISSING"


class CheckKind(StrEnum):
    STARTUP = "startup"
    DAILY = "daily"
    RETRY = "retry"
    CONFIGURATION = "configuration"


class TransportProtocol(StrEnum):
    TCP = "tcp"


class AddressFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class BindScope(StrEnum):
    # Only a wildcard bind may be excepted; a bind to a reserved address never is.
    WILDCARD = "wildcard"


MAX_LISTENER_EXCEPTIONS = 16


@dataclass(frozen=True)
class ListenerException:
    """One Owner-allowed wildcard system listener, for example ``sshd`` on 22.

    It matches only a wildcard (``0.0.0.0`` / ``::``) TCP bind on ``port`` in
    ``family`` (``None`` for both). A bind of the same port to a reserved
    address still closes access, as does every port not listed.
    """

    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    family: AddressFamily | None = None
    scope: BindScope = BindScope.WILDCARD

    def __post_init__(self):
        if (type(self.port) is not int or not 1 <= self.port <= 65535
                or not isinstance(self.protocol, TransportProtocol)
                or (self.family is not None and not isinstance(self.family, AddressFamily))
                or not isinstance(self.scope, BindScope)):
            raise ValueError("INVALID_LISTENER_EXCEPTION")

    def matches(self, listener: "Listener") -> bool:
        address = listener.address
        family = AddressFamily.IPV4 if address.version == 4 else AddressFamily.IPV6
        return (self.protocol is TransportProtocol.TCP and self.scope is BindScope.WILDCARD
                and address.is_unspecified and listener.port == self.port
                and (self.family is None or self.family is family))


@dataclass(frozen=True)
class Listener:
    """One TCP socket in LISTEN state within the enumerated network namespace."""

    address: Address
    port: int

    def __post_init__(self):
        if not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            raise ValueError("INVALID_LISTENER")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise ValueError("INVALID_LISTENER")


class RouteKind(StrEnum):
    PROXY = "proxy"
    PATH = "path"
    TEXT = "text"
    TCP_FORWARD = "tcp_forward"
    EMPTY_WEB_LISTENER = "empty_web_listener"
    FUNNEL = "funnel"


@dataclass(frozen=True)
class ProxyRoute:
    """One thing the proxy answers with on this node.

    ``host`` is None for routes that answer for every name on the port
    (raw TCP forwards, TLS/HTTP listeners without a Web handler).
    """

    kind: RouteKind
    scheme: str
    port: int
    host: str | None = None
    path: str | None = None
    target: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.kind, RouteKind) or not isinstance(self.scheme, str):
            raise ValueError("INVALID_ROUTE")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise ValueError("INVALID_ROUTE")


class ListenerEnumerator(Protocol):
    def listeners(self) -> Iterable[Listener]:
        """Return every TCP LISTEN socket; raise when that cannot be established."""


class ProxyRouteEnumerator(Protocol):
    def routes(self) -> Iterable[ProxyRoute]:
        """Return every proxy route on this node; raise when that cannot be established."""


class FaultSink(Protocol):
    def emit(self, fault: "ReservationFault") -> None:
        """Deliver an Owner fault event; must not block indefinitely."""


# -- /proc/net/tcp{,6} -------------------------------------------------------

def _decode_address(text: str, *, ipv6: bool, byteorder: str) -> Address:
    width = 32 if ipv6 else 8
    if len(text) != width or not re.fullmatch(r"[0-9A-Fa-f]+", text):
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    raw = bytes.fromhex(text)
    if byteorder == "little":
        # The kernel prints each 32-bit word in host byte order.
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    elif byteorder != "big":
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    return ipaddress.IPv6Address(raw) if ipv6 else ipaddress.IPv4Address(raw)


def parse_proc_net_tcp(text: str, *, ipv6: bool, byteorder: str = sys.byteorder) -> tuple[Listener, ...]:
    """Parse ``/proc/net/tcp`` (``ipv6=False``) or ``/proc/net/tcp6`` text.

    Only LISTEN sockets are returned. Anything not understood raises instead of
    being skipped, so a format change closes access rather than hiding a bind.
    """
    if not isinstance(text, str):
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    lines = text.splitlines()
    if not lines or len(lines) > MAX_PROC_NET_LINES:
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    header = lines[0].split()
    if header[:4] != ["sl", "local_address", "rem_address", "st"]:
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    result = []
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 4 or not re.fullmatch(r"\d+:", fields[0]):
            raise ReservationEnumerationError("MALFORMED_PROC_NET")
        local, state = fields[1], fields[3].upper()
        if not re.fullmatch(r"[0-9A-F]{2}", state) or local.count(":") != 1:
            raise ReservationEnumerationError("MALFORMED_PROC_NET")
        address, port = local.split(":")
        if not re.fullmatch(r"[0-9A-Fa-f]{4}", port):
            raise ReservationEnumerationError("MALFORMED_PROC_NET")
        decoded = _decode_address(address, ipv6=ipv6, byteorder=byteorder)
        if state == TCP_LISTEN:
            result.append(Listener(decoded, int(port, 16)))
    return tuple(result)


class ProcNetListeners:
    """Enumerate TCP listeners from an injected ``/proc/net`` reader.

    ``read`` receives ``"tcp"`` or ``"tcp6"`` and returns that file's text. It
    sees only the network namespace it runs in; with a dedicated network
    namespace the check must run inside the namespace holding the reserved
    address.
    """

    def __init__(self, read: Callable[[str], str], *, byteorder: str = sys.byteorder):
        if not callable(read):
            raise ValueError("INVALID_READER")
        self._read = read
        self._byteorder = byteorder

    def listeners(self) -> tuple[Listener, ...]:
        return (parse_proc_net_tcp(self._read("tcp"), ipv6=False, byteorder=self._byteorder)
                + parse_proc_net_tcp(self._read("tcp6"), ipv6=True, byteorder=self._byteorder))


# -- Tailscale Serve status -------------------------------------------------

def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    return dict(pairs)


def _port(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,4}", value) or int(value) > 65535:
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    return int(value)


def _host_port(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or value.count(":") != 1:
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    host, port = value.split(":")
    if not host:
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    return host.lower().rstrip("."), _port(port)


def _mapping(value) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    return value


_TCP_KEYS = {"HTTPS", "HTTP", "TCPForward", "TerminateTLS", "ProxyProtocol"}
_HANDLER_KINDS = {"Proxy": RouteKind.PROXY, "Path": RouteKind.PATH, "Text": RouteKind.TEXT}


def parse_serve_status(text: str) -> tuple[ProxyRoute, ...]:
    """Parse ``tailscale serve status --json`` text into every answering route.

    Assumed shape (unverified against the installed version)::

        {"TCP": {"443": {"HTTPS": true}},
         "Web": {"host.example.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}},
         "AllowFunnel": {"host.example.ts.net:443": true}}

    Unknown keys, handler types or non-empty unsupported sections raise, so an
    unrecognised configuration closes access instead of being ignored.
    """
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > MAX_SERVE_STATUS_BYTES:
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    try:
        document = json.loads(text, object_pairs_hook=_no_duplicates)
    except ReservationEnumerationError:
        raise
    except (ValueError, RecursionError):
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS") from None
    if not isinstance(document, dict):
        raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
    for key, value in document.items():
        if key not in {"TCP", "Web", "AllowFunnel"} and value not in (None, {}, [], False, ""):
            # e.g. Foreground/Services sessions: routes we cannot yet interpret.
            raise ReservationEnumerationError("UNRECOGNIZED_SERVE_STATUS")

    schemes: dict[int, str] = {}
    routes: list[ProxyRoute] = []
    for port_text, entry in _mapping(document.get("TCP")).items():
        port = _port(port_text)
        entry = _mapping(entry)
        if set(entry) - _TCP_KEYS:
            raise ReservationEnumerationError("UNRECOGNIZED_SERVE_STATUS")
        https, http = entry.get("HTTPS") is True, entry.get("HTTP") is True
        forward = entry.get("TCPForward")
        if forward not in (None, "") and not isinstance(forward, str):
            raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
        if forward:
            routes.append(ProxyRoute(RouteKind.TCP_FORWARD, "tcp", port, target=forward))
        if https and http:
            raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
        if https or http:
            schemes[port] = "https" if https else "http"
        elif not forward:
            # A port entry that answers with nothing we recognise.
            raise ReservationEnumerationError("UNRECOGNIZED_SERVE_STATUS")

    handled_ports: set[int] = set()
    for host_port, entry in _mapping(document.get("Web")).items():
        host, port = _host_port(host_port)
        entry = _mapping(entry)
        if set(entry) - {"Handlers"}:
            raise ReservationEnumerationError("UNRECOGNIZED_SERVE_STATUS")
        handlers = _mapping(entry.get("Handlers"))
        scheme = schemes.get(port, "unknown")
        for path, handler in handlers.items():
            handler = _mapping(handler)
            kinds = [key for key, value in handler.items() if value not in (None, "")]
            if len(kinds) != 1 or kinds[0] not in _HANDLER_KINDS or not isinstance(path, str):
                raise ReservationEnumerationError("UNRECOGNIZED_SERVE_STATUS")
            target = handler[kinds[0]]
            if not isinstance(target, str):
                raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
            routes.append(ProxyRoute(_HANDLER_KINDS[kinds[0]], scheme, port, host, path, target))
            handled_ports.add(port)
    for port, scheme in schemes.items():
        if port not in handled_ports:
            routes.append(ProxyRoute(RouteKind.EMPTY_WEB_LISTENER, scheme, port))

    for host_port, allowed in _mapping(document.get("AllowFunnel")).items():
        host, port = _host_port(host_port)
        if type(allowed) is not bool:
            raise ReservationEnumerationError("MALFORMED_SERVE_STATUS")
        if allowed:
            routes.append(ProxyRoute(RouteKind.FUNNEL, "https", port, host))
    return tuple(routes)


class ServeStatusRoutes:
    """Proxy routes from an injected source of Serve status JSON text.

    The composition supplies ``status`` (for example a bounded, read-only
    ``tailscale serve status --json`` runner). Reading local Serve status needs
    no Tailscale ACL/Grants change and no administrative credential.
    """

    def __init__(self, status: Callable[[], str]):
        if not callable(status):
            raise ValueError("INVALID_STATUS_SOURCE")
        self._status = status

    def routes(self) -> tuple[ProxyRoute, ...]:
        return parse_serve_status(self._status())


# -- Configuration and verdict ----------------------------------------------

def _normalize(address: Address) -> Address:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


@dataclass(frozen=True)
class ReservationConfig:
    """The Owner-recorded reservation for the human origin.

    ``hostname``/``port`` form the configured ``https://<host>[:<port>]``.
    ``reserved_addresses`` are every address the name resolves to on this node
    (IPv4 and IPv6). ``human_listener`` is the loopback upstream the proxy
    forwards to. ``proxy_listeners`` are sockets the proxy itself is expected
    to hold on a reserved address (empty when the proxy intercepts without a
    visible socket). ``isolation`` stays ``None`` until the Owner states it;
    ``None`` or any non-``IsolationMode`` value keeps access closed.
    """

    hostname: str
    port: int
    reserved_addresses: frozenset
    human_listener: Listener
    proxy_listeners: frozenset = frozenset()
    isolation: IsolationMode | None = None

    def __post_init__(self):
        if not isinstance(self.hostname, str) or not _HOSTNAME.fullmatch(self.hostname):
            raise ValueError("INVALID_RESERVATION_CONFIG")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("INVALID_RESERVATION_CONFIG")
        addresses = frozenset(self.reserved_addresses)
        if not addresses or any(
                not isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                or item.is_loopback or item.is_unspecified or item != _normalize(item)
                for item in addresses):
            raise ValueError("INVALID_RESERVATION_CONFIG")
        object.__setattr__(self, "reserved_addresses", addresses)
        if (not isinstance(self.human_listener, Listener) or not self.human_listener.address.is_loopback
                or self.human_listener.port == 0):
            # ADR-0003: the upstream binds an explicit loopback address.
            raise ValueError("INVALID_RESERVATION_CONFIG")
        proxies = frozenset(self.proxy_listeners)
        if any(not isinstance(item, Listener) or item.address not in addresses or item.port == 0
               for item in proxies):
            raise ValueError("INVALID_RESERVATION_CONFIG")
        object.__setattr__(self, "proxy_listeners", proxies)

    @property
    def upstream(self) -> str:
        address = self.human_listener.address
        host = f"[{address}]" if address.version == 6 else str(address)
        return f"http://{host}:{self.human_listener.port}"

    @property
    def expected_route(self) -> ProxyRoute:
        return ProxyRoute(RouteKind.PROXY, "https", self.port, self.hostname, "/", self.upstream)


@dataclass(frozen=True)
class ReservationVerdict:
    open: bool
    reasons: tuple[Reason, ...]
    checked_at: datetime | None
    check: CheckKind | None

    def __post_init__(self):
        if type(self.open) is not bool or (self.open and self.reasons):
            raise ValueError("INVALID_VERDICT")


@dataclass(frozen=True)
class ReservationFault:
    """Identifier-free Owner fault: reasons and counts, no addresses or targets."""

    reasons: tuple[Reason, ...]
    check: CheckKind
    observed_at: datetime
    unexpected_listeners: int = 0
    unexpected_routes: int = 0


CLOSED = ReservationVerdict(False, (), None, None)


def validate_listener_exceptions(config: ReservationConfig, exceptions) -> frozenset:
    """Typed, bounded exceptions that never cover the dashboard or human listener."""
    try:
        values = frozenset(exceptions)
    except TypeError:
        raise ValueError("INVALID_LISTENER_EXCEPTION") from None
    if len(values) > MAX_LISTENER_EXCEPTIONS:
        raise ValueError("INVALID_LISTENER_EXCEPTION")
    forbidden = {config.port, config.human_listener.port} | {item.port for item in config.proxy_listeners}
    for item in values:
        if not isinstance(item, ListenerException) or item.port in forbidden:
            raise ValueError("INVALID_LISTENER_EXCEPTION")
    return values


def evaluate(config: ReservationConfig, listeners, routes,
             exceptions: frozenset = frozenset()) -> tuple[tuple[Reason, ...], int, int]:
    """Pure comparison. ``listeners``/``routes`` are sequences or a ``Reason``."""
    exceptions = validate_listener_exceptions(config, exceptions)
    reasons: list[Reason] = []
    if not isinstance(config.isolation, IsolationMode):
        reasons.append(Reason.ISOLATION_UNSTATED)
    unexpected_listeners = unexpected_routes = 0
    if isinstance(listeners, Reason):
        reasons.append(listeners)
    else:
        seen_human = False
        for listener in listeners:
            address = _normalize(listener.address)
            if Listener(address, listener.port) == config.human_listener:
                seen_human = True
                continue
            normalized = Listener(address, listener.port)
            # A wildcard bind answers on every address, the reserved ones
            # included, unless the Owner explicitly allowed that port.
            if any(item.matches(normalized) for item in exceptions):
                continue
            if (address.is_unspecified or address in config.reserved_addresses) and \
                    normalized not in config.proxy_listeners:
                unexpected_listeners += 1
        if unexpected_listeners:
            reasons.append(Reason.UNEXPECTED_LISTENER)
        if not seen_human:
            reasons.append(Reason.HUMAN_LISTENER_MISSING)
    if isinstance(routes, Reason):
        reasons.append(routes)
    else:
        expected = config.expected_route
        matched = 0
        for route in routes:
            if route == expected:
                matched += 1
            else:
                unexpected_routes += 1
        # A duplicate of the expected mapping is still not a single mapping.
        unexpected_routes += max(0, matched - 1)
        if unexpected_routes:
            reasons.append(Reason.UNEXPECTED_ROUTE)
        if not matched:
            reasons.append(Reason.MAPPING_MISSING)
    return tuple(reasons), unexpected_listeners, unexpected_routes


class HostnameReservationCheck:
    """Startup/daily reservation verification that closes access on any doubt.

    ``access_open`` is False until a check passes and becomes False as soon as a
    check fails. Every failing startup/daily check emits a ``ReservationFault``
    to the injected sink after access is already closed; a failed delivery is
    retried on the next ``tick``. While closed, the check is retried every
    ``retry_seconds`` so a transient enumeration failure does not hold access
    closed for a day; retries re-notify only when the reasons change. A later
    passing check reopens access (the Owner has already been notified).
    """

    def __init__(self, config: ReservationConfig, listeners: ListenerEnumerator,
                 routes: ProxyRouteEnumerator, sink: FaultSink, *,
                 timeout: float = ENUMERATION_TIMEOUT_SECONDS,
                 retry_seconds: float = RETRY_WHILE_CLOSED_SECONDS,
                 monotonic: Callable[[], float] = time.monotonic,
                 utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        if not isinstance(config, ReservationConfig):
            raise ValueError("INVALID_RESERVATION_CONFIG")
        for value in (timeout, retry_seconds):
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not math.isfinite(value) or value <= 0:
                raise ValueError("INVALID_RESERVATION_TIMING")
        self.config = config
        self._listeners = listeners
        self._routes = routes
        self._sink = sink
        self._timeout = float(timeout)
        self._retry = float(retry_seconds)
        self._monotonic = monotonic
        self._utcnow = utcnow
        self._lock = threading.Lock()
        self._check_lock = threading.Lock()
        self._verdict = CLOSED
        self._last_check: float | None = None
        self._last_notified: tuple[Reason, ...] | None = None
        self._pending: ReservationFault | None = None
        self._inflight: dict[str, threading.Thread] = {}
        # Empty by default and never read from deployment configuration: only
        # the audited Owner path (``ReservationAdministration``) changes it.
        self._exceptions: frozenset = frozenset()
        self.undelivered_faults = 0

    @property
    def verdict(self) -> ReservationVerdict:
        return self._verdict

    @property
    def access_open(self) -> bool:
        """Precedes identity, session and permission evaluation (ADR-0003)."""
        return self._verdict.open

    @property
    def listener_exceptions(self) -> frozenset:
        return self._exceptions

    def stage_listener_exceptions(self, exceptions) -> "ListenerExceptionChange":
        """Validate a replacement set; changes nothing until applied."""
        return ListenerExceptionChange(self, validate_listener_exceptions(self.config, exceptions))

    def apply_audited_listener_exceptions(self, change: "ListenerExceptionChange") -> ReservationVerdict:
        """Apply a change whose Owner audit record has committed, then re-check.

        Reached at runtime only through ``app.audit.integration.ReservationAdministration``.
        Access closes during the immediate re-check, so narrowing the set takes
        effect now rather than at the next daily check.
        """
        if not isinstance(change, ListenerExceptionChange) or change.check is not self:
            raise ValueError("INVALID_LISTENER_EXCEPTION")
        with self._check_lock:
            self._exceptions = change.exceptions
            return self._check_locked(CheckKind.CONFIGURATION)

    def startup(self) -> ReservationVerdict:
        return self._check(CheckKind.STARTUP)

    def tick(self) -> ReservationVerdict | None:
        now = self._monotonic()
        if not math.isfinite(now):
            self._close()
            raise ValueError("INVALID_MONOTONIC_CLOCK")
        last = self._last_check
        if last is None or now < last or now - last >= DAILY_SECONDS:
            return self._check(CheckKind.DAILY)
        if not self._verdict.open and now - last >= self._retry:
            return self._check(CheckKind.RETRY)
        self._deliver()
        return None

    def _close(self) -> None:
        with self._lock:
            self._verdict = ReservationVerdict(False, self._verdict.reasons, self._verdict.checked_at,
                                               self._verdict.check)

    def _enumerate(self, name: str, call: Callable[[], Iterable], timeout_reason: Reason,
                   error_reason: Reason, item_type: type):
        previous = self._inflight.get(name)
        if previous is not None and previous.is_alive():
            # A hung enumeration is never stacked; it keeps the check closed.
            return timeout_reason
        box: dict[str, object] = {}

        def run():
            try:
                box["value"] = tuple(call())
            except BaseException:
                box["error"] = True

        worker = threading.Thread(target=run, name=f"reservation-{name}", daemon=True)
        self._inflight[name] = worker
        worker.start()
        worker.join(self._timeout)
        if worker.is_alive():
            return timeout_reason
        value = box.get("value")
        if "error" in box or not isinstance(value, tuple) or any(not isinstance(item, item_type) for item in value):
            return error_reason
        return value

    def _check(self, kind: CheckKind) -> ReservationVerdict:
        with self._check_lock:
            return self._check_locked(kind)

    def _check_locked(self, kind: CheckKind) -> ReservationVerdict:
        started = self._monotonic()
        # Close first: a check in progress never extends a previous pass.
        self._close()
        try:
            listeners = self._enumerate("listeners", lambda: self._listeners.listeners(),
                                        Reason.LISTENER_ENUMERATION_TIMEOUT,
                                        Reason.LISTENER_ENUMERATION_UNAVAILABLE, Listener)
            routes = self._enumerate("routes", lambda: self._routes.routes(),
                                     Reason.ROUTE_ENUMERATION_TIMEOUT,
                                     Reason.ROUTE_ENUMERATION_UNAVAILABLE, ProxyRoute)
            reasons, extra_listeners, extra_routes = evaluate(self.config, listeners, routes,
                                                              self._exceptions)
        except Exception:
            reasons, extra_listeners, extra_routes = (Reason.LISTENER_ENUMERATION_UNAVAILABLE,), 0, 0
        try:
            at = self._utcnow()
            if not isinstance(at, datetime) or at.tzinfo is None:
                raise ValueError
            at = at.astimezone(timezone.utc)
        except Exception:
            at = datetime.now(timezone.utc)
        verdict = ReservationVerdict(not reasons, reasons, at, kind)
        with self._lock:
            self._verdict = verdict
        self._last_check = started if math.isfinite(started) else None
        if reasons:
            if kind != CheckKind.RETRY or reasons != self._last_notified:
                self._pending = ReservationFault(reasons, kind, at, extra_listeners, extra_routes)
                self._last_notified = reasons
        else:
            self._last_notified = None
        self._deliver()
        return verdict

    def _deliver(self) -> None:
        fault = self._pending
        if fault is None:
            return
        try:
            self._sink.emit(fault)
        except Exception:
            self.undelivered_faults += 1
            return
        if self._pending is fault:
            self._pending = None


@dataclass(frozen=True)
class ListenerExceptionChange:
    """A validated, not yet applied replacement of the Owner's listener exceptions."""

    check: HostnameReservationCheck = field(repr=False)
    exceptions: frozenset
