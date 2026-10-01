"""ADR-0003 dedicated-hostname reservation check: detection, not prevention.

The reserved hostname must serve this deployment alone on every scheme and
port. That is a deployment obligation met by the Owner-recorded isolation
(a dedicated network identity, or a single-purpose node enforced by OS/service
policy outside this application). This module only *verifies what it can
observe*: at startup and daily it enumerates the actual TCP listening and
unconnected UDP sockets that answer on the reserved addresses and the proxy
(Tailscale Serve) routes,
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

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import json
import math
import os
import re
import socket
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
# An unconnected UDP socket shows the kernel's TCP_CLOSE state; it accepts
# datagrams from any peer (for example HTTP/3/QUIC). A connected one (01)
# answers only its peer and gets a concrete local address from connect().
UDP_UNCONNECTED = "07"

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
    LISTENER_EXCEPTIONS_UNREADABLE = "LISTENER_EXCEPTIONS_UNREADABLE"
    LISTENER_EXCEPTIONS_OUTDATED = "LISTENER_EXCEPTIONS_OUTDATED"
    LISTENER_OWNER_UNVERIFIED = "LISTENER_OWNER_UNVERIFIED"
    SESSION_REVOCATION_UNAVAILABLE = "SESSION_REVOCATION_UNAVAILABLE"
    SESSION_REVOCATION_FAILED = "SESSION_REVOCATION_FAILED"
    HOSTNAME_RESOLUTION_UNAVAILABLE = "HOSTNAME_RESOLUTION_UNAVAILABLE"
    HOSTNAME_RESOLUTION_TIMEOUT = "HOSTNAME_RESOLUTION_TIMEOUT"
    RESERVED_ADDRESSES_CHANGED = "RESERVED_ADDRESSES_CHANGED"


# Something other than this deployment answered, or may have answered unseen,
# for the reserved name, so a session cookie may have been exposed. Reopening
# after any of these first revokes every human session (Owner decision,
# 2026-09-30). An enumeration error or timeout is treated the same way: nothing
# shows an exposure, but nothing rules one out either. A resolved address set
# that differs from the configuration counts too: the name answered on an
# address the check did not cover until now. A failed or missing hostname
# resolution only keeps access closed (Owner decision, 2026-10-01): it reopens
# without revocation once the answer matches again, unless an exposure was
# seen meanwhile.
EXPOSURE_REASONS = frozenset({
    Reason.UNEXPECTED_LISTENER, Reason.UNEXPECTED_ROUTE,
    Reason.LISTENER_ENUMERATION_UNAVAILABLE, Reason.LISTENER_ENUMERATION_TIMEOUT,
    Reason.ROUTE_ENUMERATION_UNAVAILABLE, Reason.ROUTE_ENUMERATION_TIMEOUT,
    Reason.RESERVED_ADDRESSES_CHANGED, Reason.LISTENER_OWNER_UNVERIFIED,
})


class CheckKind(StrEnum):
    STARTUP = "startup"
    DAILY = "daily"
    RETRY = "retry"
    CONFIGURATION = "configuration"


class TransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class AddressFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class BindScope(StrEnum):
    # Only a wildcard bind may be excepted; a bind to a reserved address never is.
    WILDCARD = "wildcard"


MAX_LISTENER_EXCEPTIONS = 16
MAX_PENDING_FAULTS = 8
MAX_EXECUTABLE_PATH = 1024
_UNIT = re.compile(r"[A-Za-z0-9:_.\\@-]{1,250}\.(service|socket|scope)")


@dataclass(frozen=True)
class SocketOwner:
    """One process holding a socket: its executable path and systemd unit, when known."""

    executable: str | None
    unit: str | None


@dataclass(frozen=True)
class ListenerException:
    """One Owner-allowed wildcard system listener, for example ``sshd`` on 22.

    It matches only a wildcard (``0.0.0.0`` / ``::``) bind of ``protocol`` on
    ``port`` in ``family`` (``None`` for both). A bind of the same port to a
    reserved address still closes access, as does every port not listed.

    The port alone never exempts a socket (Owner decision, 2026-10-01): the
    exception names the owning process by exactly one of ``executable`` (the
    absolute path ``/proc/<pid>/exe`` resolves to, for example
    ``/usr/sbin/sshd``) or ``unit`` (the systemd unit in the process's cgroup,
    for example ``ssh.service``). Each check verifies that every process
    holding the socket matches; another process, or ownership that cannot be
    verified, closes access as a possible exposure.

    ``/proc/net/{tcp6,udp6}`` does not show ``IPV6_V6ONLY``, and a ``::``
    socket also accepts IPv4 unless that option is set, so a ``::`` bind is
    treated as dual-stack: only an exception without a family covers it. An
    IPv6-only exception could therefore never be verified and is rejected.
    """

    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    family: AddressFamily | None = None
    scope: BindScope = BindScope.WILDCARD
    executable: str | None = None
    unit: str | None = None

    def __post_init__(self):
        if (type(self.port) is not int or not 1 <= self.port <= 65535
                or not isinstance(self.protocol, TransportProtocol)
                or (self.family is not None and not isinstance(self.family, AddressFamily))
                or self.family is AddressFamily.IPV6
                or not isinstance(self.scope, BindScope)):
            raise ValueError("INVALID_LISTENER_EXCEPTION")
        if (self.executable is None) == (self.unit is None):
            # Exactly one owner identity; a port-only exception is refused.
            raise ValueError("INVALID_LISTENER_EXCEPTION")
        if self.executable is not None and (
                not isinstance(self.executable, str) or not self.executable.startswith("/")
                or len(self.executable) > MAX_EXECUTABLE_PATH or "\0" in self.executable
                or os.path.normpath(self.executable) != self.executable
                or self.executable.endswith(" (deleted)")):
            raise ValueError("INVALID_LISTENER_EXCEPTION")
        if self.unit is not None and (not isinstance(self.unit, str) or not _UNIT.fullmatch(self.unit)):
            raise ValueError("INVALID_LISTENER_EXCEPTION")

    def owned_by(self, owner: SocketOwner) -> bool:
        if self.executable is not None:
            return owner.executable == self.executable
        return owner.unit == self.unit

    def matches(self, listener: "Listener") -> bool:
        address = listener.address
        # A ``::`` bind may be dual-stack, so only an unrestricted exception covers it.
        family = AddressFamily.IPV4 if address.version == 4 else None
        return (self.protocol is listener.protocol and self.scope is BindScope.WILDCARD
                and address.is_unspecified and listener.port == self.port
                and (self.family is None or self.family is family))


@dataclass(frozen=True)
class Listener:
    """One TCP LISTEN or unconnected UDP socket in the enumerated network namespace."""

    address: Address
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    # The socket inode from ``/proc/net`` (0 or None: unknown); it identifies
    # the owning processes and is not part of the endpoint's identity.
    inode: int | None = field(default=None, compare=False)

    def __post_init__(self):
        if not isinstance(self.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
                or not isinstance(self.protocol, TransportProtocol):
            raise ValueError("INVALID_LISTENER")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise ValueError("INVALID_LISTENER")
        if self.inode is not None and (type(self.inode) is not int or self.inode < 0):
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
        """Return every TCP LISTEN and unconnected UDP socket; raise when that cannot be established."""


class ProxyRouteEnumerator(Protocol):
    def routes(self) -> Iterable[ProxyRoute]:
        """Return every proxy route on this node; raise when that cannot be established."""


class AddressResolver(Protocol):
    def resolve(self, hostname: str) -> Iterable[Address]:
        """Return every address ``hostname`` resolves to on this node; raise when unknown."""


class SocketOwnerResolver(Protocol):
    def owners(self, inodes: frozenset) -> dict:
        """Map each socket inode to the ``SocketOwner``s holding it; raise when unknown."""


class ListenerExceptionSource(Protocol):
    def load(self) -> Iterable["ListenerException"]:
        """Return the persisted Owner exceptions; raise when unreadable or corrupt."""


class ListenerExceptionsOutdated(Exception):
    """The stored exceptions predate owner binding (port-only); the Owner must re-enter them."""


class SessionRevoker(Protocol):
    def record_exposure(self) -> None:
        """Durably note that sessions must be revoked before access reopens."""

    def exposure_pending(self) -> bool:
        """Whether a recorded exposure still awaits revocation; raise when unreadable."""

    def revoke_all_human_sessions(self) -> None:
        """Invalidate every human session with its audit record committed; raise on failure."""


class FaultSink(Protocol):
    def emit(self, fault: "ReservationFault") -> None:
        """Deliver an Owner fault event; must not block indefinitely."""


# -- /proc/net/{tcp,udp}{,6} -------------------------------------------------

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
    return _parse_proc_net(text, ipv6=ipv6, byteorder=byteorder, protocol=TransportProtocol.TCP)


def parse_proc_net_udp(text: str, *, ipv6: bool, byteorder: str = sys.byteorder) -> tuple[Listener, ...]:
    """Parse ``/proc/net/udp`` (``ipv6=False``) or ``/proc/net/udp6`` text.

    Only unconnected sockets, which accept datagrams from any peer, are
    returned; the same strictness as ``parse_proc_net_tcp`` applies.
    """
    return _parse_proc_net(text, ipv6=ipv6, byteorder=byteorder, protocol=TransportProtocol.UDP)


def _parse_proc_net(text: str, *, ipv6: bool, byteorder: str, protocol: TransportProtocol) -> tuple[Listener, ...]:
    listening = TCP_LISTEN if protocol is TransportProtocol.TCP else UDP_UNCONNECTED
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
        if len(fields) < 10 or not re.fullmatch(r"\d+:", fields[0]) or not re.fullmatch(r"\d{1,20}", fields[9]):
            raise ReservationEnumerationError("MALFORMED_PROC_NET")
        local, state = fields[1], fields[3].upper()
        if not re.fullmatch(r"[0-9A-F]{2}", state) or local.count(":") != 1:
            raise ReservationEnumerationError("MALFORMED_PROC_NET")
        address, port = local.split(":")
        if not re.fullmatch(r"[0-9A-Fa-f]{4}", port):
            raise ReservationEnumerationError("MALFORMED_PROC_NET")
        decoded = _decode_address(address, ipv6=ipv6, byteorder=byteorder)
        if state == listening:
            result.append(Listener(decoded, int(port, 16), protocol, int(fields[9])))
    return tuple(result)


class ProcNetListeners:
    """Enumerate TCP and UDP listeners from an injected ``/proc/net`` reader.

    ``read`` receives ``"tcp"``, ``"tcp6"``, ``"udp"`` or ``"udp6"`` and
    returns that file's text. It
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
                + parse_proc_net_tcp(self._read("tcp6"), ipv6=True, byteorder=self._byteorder)
                + parse_proc_net_udp(self._read("udp"), ipv6=False, byteorder=self._byteorder)
                + parse_proc_net_udp(self._read("udp6"), ipv6=True, byteorder=self._byteorder))


def _unit_from_cgroup(text: str) -> str | None:
    """The systemd unit named by a cgroup v2 ``0::/...`` line, if any."""
    for line in text.splitlines():
        if line.startswith("0::"):
            for component in reversed(line[3:].split("/")):
                if _UNIT.fullmatch(component):
                    return component
            return None
    return None


class ProcSocketOwners:
    """Find the processes holding socket inodes by walking ``/proc/<pid>/fd``.

    ``proc`` is the ``/proc`` root (a synthetic tree in tests). Reading another
    account's ``fd``/``exe`` needs privilege (for example root or
    ``CAP_DAC_READ_SEARCH`` + ``CAP_SYS_PTRACE``); a process that cannot be
    read leaves its sockets without a verified owner, which closes access.
    """

    def __init__(self, proc: str = "/proc"):
        if not isinstance(proc, str) or not proc.startswith("/"):
            raise ValueError("INVALID_PROC_ROOT")
        self._proc = proc

    def owners(self, inodes: frozenset) -> dict:
        wanted = {f"socket:[{inode}]": inode for inode in inodes}
        found: dict[int, set[SocketOwner]] = {}
        for pid in os.listdir(self._proc):
            if not pid.isdigit():
                continue
            base = os.path.join(self._proc, pid)
            held = set()
            try:
                for fd in os.listdir(os.path.join(base, "fd")):
                    try:
                        target = os.readlink(os.path.join(base, "fd", fd))
                    except OSError:
                        continue
                    if target in wanted:
                        held.add(wanted[target])
            except OSError:
                # Unreadable or exited: its sockets stay unverified.
                continue
            if not held:
                continue
            try:
                executable = os.readlink(os.path.join(base, "exe"))
            except OSError:
                executable = None
            try:
                with open(os.path.join(base, "cgroup"), encoding="utf-8") as handle:
                    unit = _unit_from_cgroup(handle.read(65536))
            except (OSError, ValueError):
                unit = None
            for inode in held:
                found.setdefault(inode, set()).add(SocketOwner(executable, unit))
        return {inode: frozenset(owners) for inode, owners in found.items()}


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


class GetaddrinfoResolver:
    """Resolve through the node's resolver (``getaddrinfo``, injectable for tests).

    It sees what this node's name service answers now (for example MagicDNS);
    an empty answer or any error raises, so the check fails closed.
    """

    def __init__(self, getaddrinfo: Callable = socket.getaddrinfo):
        if not callable(getaddrinfo):
            raise ValueError("INVALID_RESOLVER")
        self._getaddrinfo = getaddrinfo

    def resolve(self, hostname: str) -> tuple[Address, ...]:
        try:
            answers = self._getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
            addresses = {_normalize(ipaddress.ip_address(item[4][0].split("%", 1)[0])) for item in answers}
        except Exception:
            raise ReservationEnumerationError("HOSTNAME_RESOLUTION_UNAVAILABLE") from None
        if not addresses:
            raise ReservationEnumerationError("HOSTNAME_RESOLUTION_UNAVAILABLE")
        return tuple(addresses)


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
    (IPv4 and IPv6); each check re-resolves the name and closes access when the
    answer differs. ``human_listener`` is the loopback TCP upstream the proxy
    forwards to. ``proxy_listeners`` are TCP sockets the proxy itself is
    expected to hold on a reserved address at the configured ``port`` (empty
    when the proxy intercepts without a visible socket); any other port on the
    reserved name is another answer for its cookies, so it is never exempted. ``isolation`` stays ``None`` until the Owner states it;
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
                or self.human_listener.port == 0 or self.human_listener.protocol is not TransportProtocol.TCP):
            # ADR-0003: the upstream binds an explicit loopback address.
            raise ValueError("INVALID_RESERVATION_CONFIG")
        proxies = frozenset(self.proxy_listeners)
        if any(not isinstance(item, Listener) or item.address not in addresses or item.port != self.port
               or item.protocol is not TransportProtocol.TCP
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


def excepted_inodes(config: ReservationConfig, listeners, exceptions: frozenset) -> frozenset:
    """Inodes of listeners whose endpoint an exception covers (ownership still unverified)."""
    if isinstance(listeners, Reason):
        return frozenset()
    return frozenset(
        listener.inode for listener in listeners
        if listener.inode and any(item.matches(Listener(_normalize(listener.address), listener.port,
                                                        listener.protocol)) for item in exceptions))


def evaluate(config: ReservationConfig, listeners, routes,
             exceptions: frozenset = frozenset(),
             resolved=None, owners=None) -> tuple[tuple[Reason, ...], int, int]:
    """Pure comparison. ``listeners``/``routes``/``resolved``/``owners`` are values or a ``Reason``.

    ``owners`` maps socket inodes to their ``SocketOwner``s; an excepted
    endpoint passes only when its socket has a known inode and every owner
    matches the exception (``None`` or a ``Reason``: none verified).

    ``resolved`` is the hostname's current address set (``None``: the
    configured set). Listeners are checked against the union with the
    configured set, so a bind to an address the name gained is still seen.
    """
    exceptions = validate_listener_exceptions(config, exceptions)
    reasons: list[Reason] = []
    if not isinstance(config.isolation, IsolationMode):
        reasons.append(Reason.ISOLATION_UNSTATED)
    reserved = config.reserved_addresses
    if isinstance(resolved, Reason):
        reasons.append(resolved)
    elif resolved is not None:
        current = frozenset(_normalize(item) for item in resolved)
        if current != reserved:
            reasons.append(Reason.RESERVED_ADDRESSES_CHANGED)
        reserved = reserved | current
    unexpected_listeners = unexpected_routes = 0
    if isinstance(listeners, Reason):
        reasons.append(listeners)
    else:
        seen_human = False
        seen_proxies: set[Listener] = set()
        seen_excepted: set[Listener] = set()
        unverified = 0
        known = owners if isinstance(owners, dict) else {}
        for listener in listeners:
            address = _normalize(listener.address)
            normalized = Listener(address, listener.port, listener.protocol)
            # Each expected endpoint is one socket. Independent SO_REUSEPORT
            # sockets show as identical rows, and every extra copy is another
            # process sharing the upstream or proxy endpoint (and its cookies).
            if normalized == config.human_listener:
                if seen_human:
                    unexpected_listeners += 1
                seen_human = True
                continue
            # A wildcard bind answers on every address, the reserved ones
            # included, unless the Owner explicitly allowed that port. The
            # exception allows one socket per covered endpoint (for example
            # both ``0.0.0.0`` and ``::``); an identical extra row is another
            # SO_REUSEPORT socket sharing the port and is unexpected.
            covering = [item for item in exceptions if item.matches(normalized)]
            if covering:
                holders = known.get(listener.inode) if listener.inode else None
                if not holders:
                    # No verified owner: it may be any process answering here.
                    unverified += 1
                    continue
                if not any(all(item.owned_by(owner) for owner in holders) for item in covering):
                    unexpected_listeners += 1
                    continue
                if normalized in seen_excepted:
                    unexpected_listeners += 1
                seen_excepted.add(normalized)
                continue
            if address.is_unspecified or address in reserved:
                if normalized in config.proxy_listeners and normalized not in seen_proxies:
                    seen_proxies.add(normalized)
                    continue
                unexpected_listeners += 1
        if unexpected_listeners:
            reasons.append(Reason.UNEXPECTED_LISTENER)
        if unverified:
            reasons.append(Reason.LISTENER_OWNER_UNVERIFIED)
            unexpected_listeners += unverified
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
    passing check reopens access (the Owner has already been notified), except
    after an ``EXPOSURE_REASONS`` close: then it reopens only once the injected
    ``session_revoker`` has revoked every human session and committed its audit
    record. Without a revoker, or when revocation fails, access stays closed
    with a ``SESSION_REVOCATION_*`` fault. The requirement is made durable when
    the exposure is seen: the revoker's marker, or, when that write fails, an
    immediate revocation; until one commits, every check retries it and keeps
    ``SESSION_REVOCATION_FAILED``. If both keep failing and the process
    restarts, only the delivered Owner fault records the requirement.

    Every check also re-resolves the hostname through ``resolver``; a missing
    resolver or a failed or timed-out resolution keeps access closed without
    requiring revocation; an answer that differs from ``reserved_addresses``
    keeps it closed as an exposure reason.
    """

    def __init__(self, config: ReservationConfig, listeners: ListenerEnumerator,
                 routes: ProxyRouteEnumerator, sink: FaultSink, *,
                 exception_store: ListenerExceptionSource | None = None,
                 session_revoker: SessionRevoker | None = None,
                 resolver: AddressResolver | None = None,
                 socket_owners: SocketOwnerResolver | None = None,
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
        # Held by ``ReservationAdministration`` across stage, audited commit and
        # apply, so the applied set always follows the durable commit order.
        # Startup/daily/retry checks also hold it (always acquired before
        # ``_check_lock``), so no verdict computed from a superseded set can be
        # published after a change has durably committed.
        self.exception_change_lock = threading.Lock()
        self._verdict = CLOSED
        self._last_check: float | None = None
        self._last_notified: tuple[Reason, ...] | None = None
        self._pending: deque[ReservationFault] = deque(maxlen=MAX_PENDING_FAULTS)
        self._inflight: dict[str, threading.Thread] = {}
        # Empty by default and never read from deployment configuration: only
        # the audited Owner path (``ReservationAdministration``) changes it,
        # persisting it in ``exception_store``, which ``startup`` loads.
        self.exception_store = exception_store
        self._exceptions: frozenset = frozenset()
        # False until the stored set loads; a check first (re)tries the load.
        self._exceptions_loaded = False
        self.session_revoker = session_revoker
        # Without a resolver every check fails closed: the frozen configured
        # set alone cannot show an address the name gained.
        self._resolver = resolver
        # Without it no excepted listener's owner can be verified, so any
        # listener an exception would cover closes access.
        self._socket_owners = socket_owners
        self._exceptions_reason = Reason.LISTENER_EXCEPTIONS_UNREADABLE
        self._revocation_required = False
        # True once the requirement is durable: the marker was written, or the
        # revocation already committed while access was closed.
        self._revocation_durable = True
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
            # The audited change has just rewritten the stored set.
            self._exceptions_loaded = True
            return self._check_locked(CheckKind.CONFIGURATION)

    def startup(self) -> ReservationVerdict:
        """Load the persisted exceptions, then run the first check.

        An unreadable, corrupt or no longer valid stored set fails closed: the
        check runs with no exceptions and ``LISTENER_EXCEPTIONS_UNREADABLE``
        stays in every verdict (so the Owner receives a fault) until the store
        loads again on a later check or an audited Owner change rewrites it,
        whether or not any listener needs an exception. It is never widened to
        allow everything.
        """
        with self.exception_change_lock, self._check_lock:
            self._exceptions = frozenset()
            self._exceptions_loaded = False
            self._load_revocation_state()
            return self._check_locked(CheckKind.STARTUP)

    def _load_revocation_state(self) -> None:
        if self.session_revoker is None:
            return
        try:
            pending = self.session_revoker.exposure_pending() is not False
        except Exception:
            # Unknown: revoking is the safe answer.
            pending = True
        self._revocation_required = self._revocation_required or pending

    def _make_durable(self) -> bool:
        """Ensure a restart cannot reopen without the required revocation.

        Write the marker; when that fails, revoke now instead (access is closed,
        so no session is issued until reopening revokes again). Retried on every
        check until one of them commits.
        """
        try:
            self.session_revoker.record_exposure()
            return True
        except Exception:
            pass
        try:
            self.session_revoker.revoke_all_human_sessions()
            return True
        except Exception:
            return False

    def _after_evaluation(self, reasons: tuple[Reason, ...]) -> tuple[Reason, ...]:
        if self.session_revoker is None:
            # Nothing durable could carry a revocation requirement across a
            # restart, so access never opens without a revoker.
            return reasons + (Reason.SESSION_REVOCATION_UNAVAILABLE,)
        if any(reason in EXPOSURE_REASONS for reason in reasons):
            self._revocation_required = True
            self._revocation_durable = self._make_durable()
        elif self._revocation_required and not self._revocation_durable:
            self._revocation_durable = self._make_durable()
        if not self._revocation_durable:
            # Only memory holds the requirement; a restart could lose it.
            return reasons + (Reason.SESSION_REVOCATION_FAILED,)
        if reasons or not self._revocation_required:
            return reasons
        try:
            self.session_revoker.revoke_all_human_sessions()
        except Exception:
            return (Reason.SESSION_REVOCATION_FAILED,)
        self._revocation_required = False
        self._revocation_durable = True
        return ()

    def _load_exceptions(self) -> None:
        self._exceptions = frozenset()
        if self.exception_store is not None:
            try:
                self._exceptions = validate_listener_exceptions(self.config, self.exception_store.load())
            except ListenerExceptionsOutdated:
                self._exceptions_reason = Reason.LISTENER_EXCEPTIONS_OUTDATED
                return
            except Exception:
                self._exceptions_reason = Reason.LISTENER_EXCEPTIONS_UNREADABLE
                return
        self._exceptions_loaded = True

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
                   error_reason: Reason, item_type: type | tuple[type, ...]):
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

    def _enumerate_owners(self, inodes: frozenset):
        previous = self._inflight.get("owners")
        if previous is not None and previous.is_alive():
            return None
        box: dict[str, object] = {}

        def run():
            try:
                box["value"] = self._socket_owners.owners(inodes)
            except BaseException:
                box["error"] = True

        worker = threading.Thread(target=run, name="reservation-owners", daemon=True)
        self._inflight["owners"] = worker
        worker.start()
        worker.join(self._timeout)
        value = box.get("value")
        if worker.is_alive() or "error" in box or not isinstance(value, dict) or any(
                type(inode) is not int or not isinstance(holders, frozenset)
                or any(not isinstance(owner, SocketOwner) for owner in holders)
                for inode, holders in value.items()):
            # Unknown ownership: every excepted listener stays unverified.
            return None
        return value

    def _check(self, kind: CheckKind) -> ReservationVerdict:
        with self.exception_change_lock, self._check_lock:
            return self._check_locked(kind)

    def _check_locked(self, kind: CheckKind) -> ReservationVerdict:
        started = self._monotonic()
        # Close first: a check in progress never extends a previous pass.
        self._close()
        if not self._exceptions_loaded:
            # Load (or retry) the stored set; until it loads, access stays closed.
            self._load_exceptions()
        try:
            if self._resolver is None:
                resolved = Reason.HOSTNAME_RESOLUTION_UNAVAILABLE
            else:
                resolved = self._enumerate("addresses", lambda: self._resolver.resolve(self.config.hostname),
                                           Reason.HOSTNAME_RESOLUTION_TIMEOUT,
                                           Reason.HOSTNAME_RESOLUTION_UNAVAILABLE,
                                           (ipaddress.IPv4Address, ipaddress.IPv6Address))
                if not isinstance(resolved, Reason) and not resolved:
                    resolved = Reason.HOSTNAME_RESOLUTION_UNAVAILABLE
            listeners = self._enumerate("listeners", lambda: self._listeners.listeners(),
                                        Reason.LISTENER_ENUMERATION_TIMEOUT,
                                        Reason.LISTENER_ENUMERATION_UNAVAILABLE, Listener)
            routes = self._enumerate("routes", lambda: self._routes.routes(),
                                     Reason.ROUTE_ENUMERATION_TIMEOUT,
                                     Reason.ROUTE_ENUMERATION_UNAVAILABLE, ProxyRoute)
            owners = None
            inodes = excepted_inodes(self.config, listeners, self._exceptions)
            if inodes and self._socket_owners is not None:
                owners = self._enumerate_owners(inodes)
            reasons, extra_listeners, extra_routes = evaluate(self.config, listeners, routes,
                                                              self._exceptions, resolved, owners)
        except Exception:
            reasons, extra_listeners, extra_routes = (Reason.LISTENER_ENUMERATION_UNAVAILABLE,), 0, 0
        if not self._exceptions_loaded:
            reasons = (self._exceptions_reason,) + reasons
        # Access is still closed here: reopening waits for any required revocation.
        reasons = self._after_evaluation(reasons)
        at = self._now()
        verdict = ReservationVerdict(not reasons, reasons, at, kind)
        with self._lock:
            self._verdict = verdict
        self._last_check = started if math.isfinite(started) else None
        if reasons:
            if kind != CheckKind.RETRY or reasons != self._last_notified:
                self._pending.append(ReservationFault(reasons, kind, at, extra_listeners, extra_routes))
                self._last_notified = reasons
        else:
            self._last_notified = None
        self._deliver()
        return verdict

    def _now(self) -> datetime:
        try:
            at = self._utcnow()
            if not isinstance(at, datetime) or at.tzinfo is None:
                raise ValueError
            return at.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def _deliver(self) -> None:
        # Oldest first; stop at the first failure and retry on the next tick.
        # The bounded queue drops the oldest undelivered fault when full.
        while self._pending:
            fault = self._pending[0]
            try:
                self._sink.emit(fault)
            except Exception:
                self.undelivered_faults += 1
                return
            if self._pending and self._pending[0] is fault:
                self._pending.popleft()


@dataclass(frozen=True)
class ListenerExceptionChange:
    """A validated, not yet applied replacement of the Owner's listener exceptions."""

    check: HostnameReservationCheck = field(repr=False)
    exceptions: frozenset
