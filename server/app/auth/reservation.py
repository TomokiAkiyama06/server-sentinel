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
It sees only sockets and proxy routes: kernel forwarding to the reserved
address (nftables/iptables DNAT or REDIRECT, TPROXY, eBPF ``sk_lookup``, IPVS)
is invisible to it and is verified by the operator (MANUAL_TEST.md).

Which systemd unit and uid created an excepted, proxy or upstream socket is
answered by an injected ``SocketOwnerResolver``; production uses the
unprivileged sock_diag lookup in ``sock_diag.py`` (Issue #126). It reports a
socket's creator, not its current holder.

Enumerators and the Owner fault sink are injected. Apart from the overridable
defaults for this process's own ``/proc/self/fd`` and
``/proc/sys/net/ipv4/ip_unprivileged_port_start``, nothing here reads the host
implicitly, runs ``tailscale``, mounts a route, changes Tailscale ACLs/Grants,
or needs Tailscale administrative credentials. The Serve status parser follows
the ``tailscale serve status --json`` shape as understood from upstream
sources; the real installed output format is unverified (see MANUAL_TEST.md).
"""

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import json
import logging
import math
import os
import re
import socket
import sys
import threading
import time
from typing import Callable, Iterable, Iterator, Protocol

from app.logging import Event


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


class HumanAccessClosed(Exception):
    """A session or enrollment commit refused because human access is closed.

    Carries no reason: callers map it to their own generic denial.
    """

    def __init__(self) -> None:
        super().__init__("access is unavailable")


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
    PROXY_LISTENER_MISSING = "PROXY_LISTENER_MISSING"
    # The human upstream was created in ``/init.scope`` by uid 0: systemd
    # listened from PID 1 instead of the socket unit's cgroup, which it does
    # when the host has no cgroup-BPF (BPF firewall) support (Issue #157).
    # Closed without revocation, like ``LISTENER_OWNER_UNVERIFIED``.
    UPSTREAM_CREATED_IN_INIT_SCOPE = "UPSTREAM_CREATED_IN_INIT_SCOPE"
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
# seen meanwhile. Ownership that cannot be verified (``LISTENER_OWNER_UNVERIFIED``:
# no socket owner resolver, a sock_diag or cgroup lookup that fails, times out
# or fails its self-check, a socket missing from the dump, a creator cgroup
# that cannot be resolved, an unconfirmed mismatch, or a human upstream port
# that is not privileged) likewise only keeps access closed (Owner decisions,
# 2026-10-05 and 2026-10-07): only an observed other creator or holder
# (``UNEXPECTED_LISTENER``) is an exposure.
EXPOSURE_REASONS = frozenset({
    Reason.UNEXPECTED_LISTENER, Reason.UNEXPECTED_ROUTE,
    Reason.LISTENER_ENUMERATION_UNAVAILABLE, Reason.LISTENER_ENUMERATION_TIMEOUT,
    Reason.ROUTE_ENUMERATION_UNAVAILABLE, Reason.ROUTE_ENUMERATION_TIMEOUT,
    Reason.RESERVED_ADDRESSES_CHANGED,
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
MAX_UID = 0xFFFFFFFE  # (uid_t)-1 is never a real account
_UNIT = re.compile(r"[A-Za-z0-9:_.\\@-]{1,250}\.(service|socket|scope)")
# Owner decision 2026-10-07: exceptions and proxy owners name a service or
# socket unit; a transient scope is not an identity.
_IDENTITY_UNIT = re.compile(r"[A-Za-z0-9:_.\\@-]{1,250}\.(service|socket)")
_SLICE = re.compile(r"[A-Za-z0-9:_.\\@-]{1,250}\.slice")
# A socket created in the root cgroup or PID 1's own scope names no unit: it
# keeps the owner unverified rather than counting as another unit
# (Owner decision, 2026-10-07).
UNRESOLVED_CGROUPS = frozenset({"/", "/init.scope"})
UPSTREAM_SOCKET_UNIT = "server-sentinel-upstream.socket"


def unit_from_cgroup(path: str | None) -> str | None:
    """The system unit whose own cgroup v2 path this is, else None.

    Only a socket created directly in a system unit's cgroup names a unit:
    ``/system.slice/<unit>``, or the same below nested system slices
    (``/system.slice/system-cups.slice/cups.service``), where every component
    between ``system.slice`` and the unit is itself a ``.slice``. A unit name
    is unique on the host and its slice is fixed, so the leaf names it. A path
    under ``user.slice`` is controlled by that user's own service manager,
    which can create a unit of any name (``.../user@1000.service/app.slice/
    ssh.service``), and a sub-cgroup of a unit or another top-level slice is
    not the unit itself, so none of them names one; an exception or proxy
    identity then does not match.
    """
    if not isinstance(path, str) or not path.startswith("/system.slice/"):
        return None
    parts = path.split("/")[2:]
    if not parts or any(not _SLICE.fullmatch(part) for part in parts[:-1]):
        return None
    return parts[-1] if _UNIT.fullmatch(parts[-1]) else None


@dataclass(frozen=True)
class SocketCreator:
    """Where a socket was created: its cgroup v2 path and owning uid (sock_diag).

    ``cgroup`` is None when the kernel reported no cgroup id or the id names no
    existing cgroup (for example a deleted one). This is the creator, not the
    current holder: a descriptor inherited or passed (``SCM_RIGHTS``) later
    keeps the creator's cgroup.
    """

    cgroup: str | None
    uid: int

    @property
    def resolved(self) -> bool:
        return isinstance(self.cgroup, str) and self.cgroup not in UNRESOLVED_CGROUPS


def _valid_unit_identity(unit, uid) -> bool:
    return (isinstance(unit, str) and _IDENTITY_UNIT.fullmatch(unit) is not None
            and type(uid) is int and 0 <= uid <= MAX_UID)


@dataclass(frozen=True)
class ProcessIdentity:
    """The expected creator of a socket: a systemd system unit and uid.

    It matches a socket created in the cgroup ``/system.slice/<unit>`` by
    ``uid``. A ``.socket`` unit's sockets are created by systemd (uid 0) in the
    socket unit's cgroup (for example ``ssh.socket``); a service's own sockets
    in the service's cgroup with its ``User=`` (Owner decision, 2026-10-07,
    replacing the executable-path identity).
    """

    unit: str
    uid: int

    def __post_init__(self):
        if not _valid_unit_identity(self.unit, self.uid):
            raise ValueError("INVALID_PROCESS_IDENTITY")

    def created(self, creator: "SocketCreator") -> bool:
        return (isinstance(creator, SocketCreator) and creator.resolved
                and unit_from_cgroup(creator.cgroup) == self.unit and creator.uid == self.uid)


@dataclass(frozen=True)
class ListenerException:
    """One Owner-allowed wildcard system listener, for example ``ssh.socket`` on 22.

    It matches only a wildcard (``0.0.0.0`` / ``::``) bind of ``protocol`` on
    ``port`` in ``family`` (``None`` for both). A bind of the same port to a
    reserved address still closes access, as does every port not listed.

    The port alone never exempts a socket (Owner decision, 2026-10-01): the
    exception names the creating systemd system ``unit`` and ``uid`` (Owner
    decision, 2026-10-07: a ``.service`` or ``.socket`` unit, for example
    ``ssh.socket`` with uid 0). Each check verifies, through sock_diag, that
    the socket was created in ``/system.slice/<unit>`` by ``uid``; a socket
    created elsewhere, confirmed by an immediate second dump, closes access as
    a possible exposure, and a creator that cannot be resolved closes it
    without revocation.

    ``/proc/net/{tcp6,udp6}`` does not show ``IPV6_V6ONLY``, and a ``::``
    socket also accepts IPv4 unless that option is set, so a ``::`` bind is
    treated as dual-stack: only an exception without a family covers it. An
    IPv6-only exception could therefore never be verified and is rejected.
    """

    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    family: AddressFamily | None = None
    scope: BindScope = BindScope.WILDCARD
    unit: str | None = None
    uid: int | None = None

    def __post_init__(self):
        if (type(self.port) is not int or not 1 <= self.port <= 65535
                or not isinstance(self.protocol, TransportProtocol)
                or (self.family is not None and not isinstance(self.family, AddressFamily))
                or self.family is AddressFamily.IPV6
                or not isinstance(self.scope, BindScope)):
            raise ValueError("INVALID_LISTENER_EXCEPTION")
        if not _valid_unit_identity(self.unit, self.uid):
            # A creator identity is required; a port-only exception is refused.
            raise ValueError("INVALID_LISTENER_EXCEPTION")

    @property
    def owner(self) -> ProcessIdentity:
        return ProcessIdentity(self.unit, self.uid)

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
    """Resolves socket creators and the human upstream's holders (Issue #126).

    Production uses ``app.auth.sock_diag.SockDiagOwners``; tests inject fakes.
    """

    def creators(self, inodes: frozenset) -> dict:
        """Map each socket inode to its ``SocketCreator``; raise when the lookup fails.

        An inode left out (not in the dump) is unverified.
        """

    def held_only_by_requester(self, inodes: frozenset) -> dict:
        """Map each socket inode to whether no other process of the ServerSentinel
        unit(s) also holds it; raise when a process there cannot be read.

        ``False`` is a forked child or a process that received the descriptor
        (``SCM_RIGHTS``) within the scanned cgroups. An inode left out is
        unverified.
        """


class ListenerExceptionSource(Protocol):
    def load(self) -> Iterable["ListenerException"]:
        """Return the persisted Owner exceptions; raise when unreadable or corrupt."""


class ListenerExceptionsOutdated(Exception):
    """The stored exceptions predate the current owner identity (port-only, or
    executable-path); the Owner must re-enter them."""


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


_PROC_NET_HEADER_V4 = ["sl", "local_address", "rem_address", "st"]
_PROC_NET_HEADER_V6 = ["sl", "local_address", "remote_address", "st"]


def _parse_proc_net(text: str, *, ipv6: bool, byteorder: str, protocol: TransportProtocol) -> tuple[Listener, ...]:
    listening = TCP_LISTEN if protocol is TransportProtocol.TCP else UDP_UNCONNECTED
    if not isinstance(text, str):
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    lines = text.splitlines()
    if not lines or len(lines) > MAX_PROC_NET_LINES:
        raise ReservationEnumerationError("MALFORMED_PROC_NET")
    # The kernel names the peer column per family: tcp4/udp4 print
    # ``rem_address`` (net/ipv4/tcp_ipv4.c, udp.c) and tcp6/udp6 print
    # ``remote_address`` (net/ipv6/tcp_ipv6.c, datagram.c). Only the spelling
    # of the file's own family is accepted; any other header fails closed.
    header = lines[0].split()
    expected = _PROC_NET_HEADER_V6 if ipv6 else _PROC_NET_HEADER_V4
    if header[:4] != expected:
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


UNPRIVILEGED_PORT_START = "/proc/sys/net/ipv4/ip_unprivileged_port_start"


def read_unprivileged_port_start(path: str = UNPRIVILEGED_PORT_START) -> int:
    """The first port a process without ``CAP_NET_BIND_SERVICE`` may bind.

    Readable without privilege; the sysctl belongs to the reader's network
    namespace and covers IPv4 and IPv6 binds. Raises when unreadable or not
    understood.
    """
    with open(path, encoding="ascii") as handle:
        text = handle.read(16)
    value = text.strip()
    if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65536:
        raise ReservationEnumerationError("UNPRIVILEGED_PORT_START_UNREADABLE")
    return int(value)




class OwnSocketInodes:
    """Socket inodes this process holds, from ``/proc/self/fd``.

    A process can always read its own fd table, so this part of the human
    upstream check needs no privilege. A socket on the upstream endpoint that
    is not among these is another process's, whoever created it. Python
    creates non-inheritable descriptors, and the launcher marks the
    socket-activated upstream descriptor non-inheritable as well
    (``app.systemd.activated_listener``); the resolver's
    ``held_only_by_requester`` checks the unit's other processes anyway.
    """

    def __init__(self, proc_self: str = "/proc/self"):
        if not isinstance(proc_self, str) or not proc_self.startswith("/"):
            raise ValueError("INVALID_PROC_ROOT")
        self._fd = os.path.join(proc_self, "fd")

    def __call__(self) -> frozenset:
        inodes = set()
        for fd in os.listdir(self._fd):
            try:
                target = os.readlink(os.path.join(self._fd, fd))
            except FileNotFoundError:
                continue  # closed since the listing (including the listing's own)
            match = re.fullmatch(r"socket:\[(\d{1,20})\]", target)
            if match:
                inodes.add(int(match.group(1)))
        return frozenset(inodes)


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
    reserved name is another answer for its cookies, so it is never exempted.
    Every recorded proxy socket must be present (``PROXY_LISTENER_MISSING``
    otherwise, closed without revocation), and ``proxy_owner`` (required
    with ``proxy_listeners``, a systemd unit and uid) must be its creator on
    every check: a confirmed other creator is ``UNEXPECTED_LISTENER``, an
    unverifiable one ``LISTENER_OWNER_UNVERIFIED``. ``upstream_owner`` is the
    systemd ``.socket`` unit that creates the human upstream as uid 0 and
    passes it to the backend (socket activation, the production requirement;
    Owner decision, 2026-10-07). ``isolation`` stays ``None`` until the Owner
    states it; ``None`` or any non-``IsolationMode`` value keeps access closed.
    """

    hostname: str
    port: int
    reserved_addresses: frozenset
    human_listener: Listener
    proxy_listeners: frozenset = frozenset()
    isolation: IsolationMode | None = None
    proxy_owner: ProcessIdentity | None = None
    upstream_owner: ProcessIdentity = ProcessIdentity(UPSTREAM_SOCKET_UNIT, 0)

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
        if bool(proxies) != isinstance(self.proxy_owner, ProcessIdentity) or (
                not proxies and self.proxy_owner is not None):
            raise ValueError("INVALID_RESERVATION_CONFIG")
        if (not isinstance(self.upstream_owner, ProcessIdentity) or self.upstream_owner.uid != 0
                or not self.upstream_owner.unit.endswith(".socket")):
            # Only a socket created by systemd for the backend satisfies this.
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


def expected_creators(config: ReservationConfig, listeners, exceptions: frozenset) -> dict:
    """The creator identities a check verifies, by inode.

    Excepted endpoints expect the identity of any covering exception, recorded
    proxy sockets ``proxy_owner``, and the human upstream ``upstream_owner``.
    """
    if isinstance(listeners, Reason):
        return {}
    expected: dict[int, set[ProcessIdentity]] = {}
    for listener in listeners:
        if not listener.inode:
            continue
        normalized = Listener(_normalize(listener.address), listener.port, listener.protocol)
        identities = set()
        if normalized == config.human_listener:
            identities.add(config.upstream_owner)
        if normalized in config.proxy_listeners:
            identities.add(config.proxy_owner)
        identities.update(item.owner for item in exceptions if item.matches(normalized))
        if identities:
            expected.setdefault(listener.inode, set()).update(identities)
    return {inode: frozenset(identities) for inode, identities in expected.items()}


def human_inodes(config: ReservationConfig, listeners, own_inodes) -> frozenset:
    """Inodes of human upstream rows this process holds, whose other holders a check looks for."""
    if isinstance(listeners, Reason) or not isinstance(own_inodes, frozenset):
        return frozenset()
    return frozenset(
        listener.inode for listener in listeners
        if listener.inode and listener.inode in own_inodes
        and Listener(_normalize(listener.address), listener.port, listener.protocol) == config.human_listener)


_PASS, _UNVERIFIED, _UNEXPECTED = 0, 1, 2
PID1_CREATOR = SocketCreator("/init.scope", 0)


def _creator_status(identities, creator) -> int:
    """How a socket's creator compares with the identities expected for it.

    A resolved creator passes only as one of them (unit and uid); another unit
    or uid is unexpected. An unresolved creator (no cgroup attribute, a
    deleted cgroup, the root cgroup or ``/init.scope``) is unverified while its
    uid is one of the expected uids, and always for ``/init.scope`` with uid 0
    (PID 1's own sockets); with a uid none of them has it is unexpected (Owner
    decision, 2026-10-07). A socket not in the dump is unverified.
    """
    if not isinstance(creator, SocketCreator):
        return _UNVERIFIED
    if creator.resolved:
        return _PASS if any(identity.created(creator) for identity in identities) else _UNEXPECTED
    if creator.cgroup == "/init.scope" and creator.uid == 0:
        return _UNVERIFIED
    if any(identity.uid == creator.uid for identity in identities):
        return _UNVERIFIED
    return _UNEXPECTED


def mismatched_creators(expected: dict, creators: dict) -> frozenset:
    """Inodes whose creator is unexpected for the identities expected for it.

    A check confirms each of them with an immediate second dump before
    treating it as another creator (Owner decision, 2026-10-07).
    """
    return frozenset(
        inode for inode, creator in creators.items()
        if _creator_status(expected.get(inode, ()), creator) == _UNEXPECTED)


def _human_status(config, listener, own_inodes, known, owners, sole_holders,
                  upstream_privileged) -> tuple[int, bool]:
    """The upstream's status, and whether its creator is PID 1's ``/init.scope``.

    A creator in ``/init.scope`` with uid 0 is reported apart (Issue #157): it
    stays closed without revocation, as an unverified creator does, but with
    its own reason, because it shows the host lacks the cgroup-BPF support
    that makes systemd create a socket unit's sockets in the unit's cgroup.
    """
    if isinstance(own_inodes, Reason) or not listener.inode:
        return _UNVERIFIED, False
    if listener.inode not in own_inodes:
        # A single replacement: another process's socket on the upstream.
        return _UNEXPECTED, False
    statuses = [_PASS]
    init_scope = False
    if upstream_privileged is not None and upstream_privileged is not True:
        # Any account may bind an unprivileged port, so its creator proves
        # nothing: a configuration error (for example no socket activation)
        # that only keeps access closed.
        statuses.append(_UNVERIFIED)
    elif owners is not None:
        creator = known.get(listener.inode)
        if creator == PID1_CREATOR:
            init_scope = True
        else:
            statuses.append(_creator_status([config.upstream_owner], creator))
    if sole_holders is not None:
        sole = sole_holders.get(listener.inode) if isinstance(sole_holders, dict) else None
        if sole is None:
            statuses.append(_UNVERIFIED)
        elif sole is not True:
            # The same socket is also held by another process of the unit.
            statuses.append(_UNEXPECTED)
    status = max(statuses)
    return status, init_scope and status != _UNEXPECTED


def evaluate(config: ReservationConfig, listeners, routes,
             exceptions: frozenset = frozenset(),
             resolved=None, owners=None, own_inodes=None,
             sole_holders=None, upstream_privileged=None) -> tuple[tuple[Reason, ...], int, int]:
    """Pure comparison. ``listeners``/``routes``/``resolved``/``owners`` are values or a ``Reason``.

    ``owners`` maps socket inodes to their ``SocketCreator`` (sock_diag); an
    excepted endpoint or recorded proxy socket passes only when its socket has
    a known inode whose creator matches the expected unit and uid (``None`` or
    a ``Reason``: none verified). A mismatch here is one the check has
    already confirmed with a second dump; unconfirmed ones are left out.
    ``own_inodes`` are the sockets this process holds: the human upstream
    passes only as one of them (a ``Reason``: unverifiable; ``None`` skips the
    ownership comparison, for pure endpoint evaluation only). With ``owners``
    given (not ``None``), the upstream's creator must also be
    ``config.upstream_owner``.
    ``sole_holders`` maps the upstream's inode to whether no other process of
    the ServerSentinel unit(s) holds it (Issue #126): ``False`` is another
    holder sharing the socket (a forked child or a descriptor passed with
    ``SCM_RIGHTS``), and a ``Reason`` or a missing inode is unverifiable.
    ``upstream_privileged`` is whether the upstream port is below
    ``ip_unprivileged_port_start`` (``False`` or a ``Reason``: a configuration
    error that only keeps access closed; the creator is then not compared).
    ``None`` skips either, for pure endpoint evaluation only: a check without
    a socket owner resolver passes a ``Reason`` (the resolver is mandatory,
    Owner decision 2026-10-05).

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
        init_scope = False
        # Whether the upstream is already counted as unverified, so an
        # ``/init.scope`` upstream is counted once (Issue #172).
        human_unverified = False
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
                elif own_inodes is not None:
                    status, init_scope = _human_status(config, listener, own_inodes, known, owners,
                                                       sole_holders, upstream_privileged)
                    if status == _UNEXPECTED:
                        unexpected_listeners += 1
                    elif status == _UNVERIFIED:
                        unverified += 1
                        human_unverified = True
                seen_human = True
                continue
            # A wildcard bind answers on every address, the reserved ones
            # included, unless the Owner explicitly allowed that port. The
            # exception allows one socket per covered endpoint (for example
            # both ``0.0.0.0`` and ``::``); an identical extra row is another
            # SO_REUSEPORT socket sharing the port and is unexpected.
            covering = [item for item in exceptions if item.matches(normalized)]
            if covering:
                creator = known.get(listener.inode) if listener.inode else None
                status = _creator_status([item.owner for item in covering], creator)
                if status == _UNVERIFIED:
                    # No verified creator: it may be any process answering here.
                    unverified += 1
                    continue
                if status == _UNEXPECTED:
                    unexpected_listeners += 1
                    continue
                if normalized in seen_excepted:
                    unexpected_listeners += 1
                seen_excepted.add(normalized)
                continue
            if address.is_unspecified or address in reserved:
                if normalized in config.proxy_listeners and normalized not in seen_proxies:
                    seen_proxies.add(normalized)
                    creator = known.get(listener.inode) if listener.inode else None
                    status = _creator_status([config.proxy_owner], creator)
                    if status == _UNVERIFIED:
                        unverified += 1
                    elif status == _UNEXPECTED:
                        unexpected_listeners += 1
                    continue
                unexpected_listeners += 1
        if unexpected_listeners:
            reasons.append(Reason.UNEXPECTED_LISTENER)
        if unverified:
            reasons.append(Reason.LISTENER_OWNER_UNVERIFIED)
            unexpected_listeners += unverified
        if init_scope:
            reasons.append(Reason.UPSTREAM_CREATED_IN_INIT_SCOPE)
            if not human_unverified:
                unexpected_listeners += 1
        if config.proxy_listeners - seen_proxies:
            # Proxy drift or failure; nothing else seen answering, so no revocation.
            reasons.append(Reason.PROXY_LISTENER_MISSING)
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
    immediate revocation; until one commits, every check retries both and keeps
    ``SESSION_REVOCATION_FAILED``. After the immediate revocation commits, the
    retries of the same closed period do not repeat it, but keep retrying the
    marker until it commits (PR #134), logging a marker that stays unsaved
    when the streak starts and each time it doubles. If both keep failing
    and the process restarts, only the delivered Owner fault records the
    requirement. A fallback revocation that commits in the same check that
    would reopen access, while access has never been open in this process
    (a clean startup), counts as the reopening revocation (Issue #145); a
    failed marker rewrite after the marker is already stored for the closed
    period does not revoke (Issue #144).

    Session gate (Issue #144, Owner decision 2026-10-07: serialize). A
    request that may create a human session, update a session's
    user-verification time, or create or redeem an enrollment authorization
    first takes ``epoch()``, before it reads or verifies anything the commit
    relies on, and then commits inside ``admit(epoch)``, which holds
    ``_session_gate_lock`` and re-checks right before the commit that access
    is open and that the epoch is unchanged. The epoch advances on every
    close of an open verdict, under the same lock, and ``epoch()`` returns
    ``None`` while access is closed. The check closes access (at its start)
    under the lock and keeps the verdict closed until any required
    revocation has committed; that is the essential property. A request
    therefore commits only if access stayed open from its start to its
    commit, so no revocation ran in between: either it committed before the
    close, and every later revocation covers it, or it is refused with
    ``HumanAccessClosed``, also when a whole close -> revoke -> reopen cycle
    completed while it was verifying (PR #174 review). Taking the lock again for decide +
    commit (``_after_evaluation`` with the marker, fallback and reopening
    revocations, together with publishing the verdict) is defense in depth.
    The idle-expiry touch in ``AccessStore.authorize()`` /
    ``authorize_owner()`` stays outside the gate: revocation advances the
    authorization generation, so a touch never makes a revoked session valid.

    Lock order (outermost first): ``exception_change_lock`` ->
    ``_check_lock`` -> ``_session_gate_lock`` -> the SQLite write lock
    (``BEGIN IMMEDIATE``). Session paths take only the last two, in that
    order, and never take the gate lock while already inside a write
    transaction. Enumeration, resolution and Owner fault delivery run outside
    the gate lock; under it run only local SQLite write transactions, their
    storage admission and the marker log event. The verdict lives
    in this object's memory, so the gate and every session-establishing path
    must share one process.

    Every check also re-resolves the hostname through ``resolver``; a missing
    resolver or a failed or timed-out resolution keeps access closed without
    requiring revocation; an answer that differs from ``reserved_addresses``
    keeps it closed as an exposure reason.

    Listener owners (Issue #126, Owner decision 2026-10-07): ``socket_owners``
    (mandatory; ``app.auth.sock_diag.SockDiagOwners`` in production) reports
    the creating cgroup and uid of every excepted, proxy and human upstream
    socket. A creator that matches no expected unit and uid is re-dumped at
    once and counts as ``UNEXPECTED_LISTENER`` only when the second dump
    reports the same creator; otherwise, and for any lookup failure or
    unresolvable creator, the listener stays ``LISTENER_OWNER_UNVERIFIED``
    (closed, no revocation). ``unprivileged_port_start`` must show the human
    upstream port as privileged, or the upstream is unverified.
    """

    def __init__(self, config: ReservationConfig, listeners: ListenerEnumerator,
                 routes: ProxyRouteEnumerator, sink: FaultSink, *,
                 exception_store: ListenerExceptionSource | None = None,
                 session_revoker: SessionRevoker | None = None,
                 resolver: AddressResolver | None = None,
                 socket_owners: SocketOwnerResolver | None = None,
                 own_sockets: Callable[[], frozenset] | None = OwnSocketInodes(),
                 unprivileged_port_start: Callable[[], int] | None = read_unprivileged_port_start,
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
        # The session gate (Issue #144): held to close access, to decide and
        # commit a verdict, and by every ``admit()`` commit. Innermost of the
        # check's locks; see the class docstring for the lock order.
        self._session_gate_lock = threading.Lock()
        # Advanced (under the gate lock) every time an open verdict closes;
        # ``admit()`` refuses a request whose epoch changed (PR #174 review).
        self._epoch = 0
        self._check_lock = threading.Lock()
        # Held by ``ReservationAdministration`` across stage, audited commit and
        # apply, so the applied set always follows the durable commit order.
        # Startup/daily/retry checks also hold it (always acquired before
        # ``_check_lock``), so no verdict computed from a superseded set can be
        # published after a change has durably committed.
        self.exception_change_lock = threading.RLock()
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
        # Mandatory (Owner decision, 2026-10-05): without it neither an
        # excepted listener's, a proxy socket's nor the human upstream's
        # creator can be verified, so access stays closed
        # (``LISTENER_OWNER_UNVERIFIED``, without revocation). Production
        # passes ``app.auth.sock_diag.SockDiagOwners`` (Issue #126).
        self._socket_owners = socket_owners
        # Without it the human upstream's owner is unverifiable and access stays closed.
        self._own_sockets = own_sockets
        # Without it the upstream port cannot be shown to be privileged.
        self._port_start = unprivileged_port_start
        self._exceptions_reason = Reason.LISTENER_EXCEPTIONS_UNREADABLE
        self._revocation_required = False
        # True once the requirement is durable: the marker was written, or the
        # revocation already committed while access was closed.
        self._revocation_durable = True
        # True once the marker-failure fallback revocation has committed during
        # the current closed period; cleared when access reopens.
        self._revoked_while_closed = False
        # True once the marker is known to be stored for the current closed
        # period; cleared when access reopens.
        self._exposure_recorded = False
        # True when the fallback revocation committed during the check now
        # being evaluated (Issue #145).
        self._revoked_in_check = False
        # True once any check has opened access in this process.
        self._ever_opened = False
        # Consecutive marker write failures while the marker is not stored;
        # logged when the streak starts and each time it doubles.
        self._marker_failures = 0
        self.undelivered_faults = 0

    @property
    def verdict(self) -> ReservationVerdict:
        return self._verdict

    @property
    def access_open(self) -> bool:
        """Precedes identity, session and permission evaluation (ADR-0003).

        A request-time read only: a commit that creates a session, updates its
        user-verification time, or creates or redeems an enrollment
        authorization goes through ``admit()`` instead, which
        re-checks under the gate lock (Issue #144).
        """
        return self._verdict.open

    def epoch(self) -> int | None:
        """The gate epoch at the start of a request; ``None`` while access is closed.

        Taken before the request reads or verifies anything its commit relies
        on (a challenge, a credential, an Owner authorization), so a close
        anywhere between that point and the commit is seen by ``admit()``.
        """
        with self._session_gate_lock:
            return self._epoch if self._verdict.open else None

    @contextmanager
    def admit(self, epoch: int | None) -> Iterator[None]:
        """Run one session or enrollment commit while access is still open since ``epoch``.

        Holds the session gate lock for the whole block and raises
        ``HumanAccessClosed`` when the published verdict is closed, when
        ``epoch`` is ``None`` (closed at the start) or when it differs from
        the current epoch (access closed at least once since the request
        started, even if it has reopened), so the block cannot interleave
        with, or follow, a check closing access or revoking sessions. The
        caller enters it before opening its SQLite write transaction and
        keeps only that local commit inside: no network I/O, no WebAuthn
        verification and no other lock of this check.
        """
        with self._session_gate_lock:
            if (not self._verdict.open or type(epoch) is not int or epoch != self._epoch):
                raise HumanAccessClosed()
            yield

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
        effect now rather than at the next daily check. It takes the
        (reentrant) ``exception_change_lock`` itself, so a direct caller is
        serialized with other changes and checks as well.
        """
        if not isinstance(change, ListenerExceptionChange) or change.check is not self:
            raise ValueError("INVALID_LISTENER_EXCEPTION")
        with self.exception_change_lock, self._check_lock:
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
            stored = self.session_revoker.exposure_pending()
        except Exception:
            # Unknown: revoking is the safe answer.
            stored = None
        pending = stored is not False
        self._revocation_required = self._revocation_required or pending
        self._exposure_recorded = self._exposure_recorded or stored is True

    def _make_durable(self) -> bool:
        """Ensure a restart cannot reopen without the required revocation.

        Write the marker; when that fails, revoke now instead (access is closed,
        so no later request is admitted until reopening revokes again). Retried
        on every check until one of them commits. Once that immediate revocation has
        committed, later checks of the same closed period do not repeat it
        (Issue #120): every repeat would advance the authorization generation
        again, add an audit record and void the enrollment authorizations
        issued during the outage. The revocation before reopening still runs.

        The marker itself is still retried on every check until it commits
        (PR #134). Since the session gate (Issue #144) no gated commit can land
        after the close, so the immediate revocation already covers every
        session and enrollment authorization a restart could otherwise keep;
        the stored marker remains the durable record of the requirement, and a
        marker that stays unsaved is logged (``_marker_failed``).

        Once the marker is known to be stored for the current closed period, a
        failed rewrite neither revokes nor counts as undurable (Issue #144):
        the stored marker already carries the requirement across a restart.
        """
        try:
            self.session_revoker.record_exposure()
        except Exception:
            self._marker_failed()
        else:
            self._marker_saved()
            self._exposure_recorded = True
            return True
        if self._exposure_recorded or self._revoked_while_closed:
            # The marker is already stored for this closed period (Issue #144):
            # a transient rewrite failure loses nothing a restart needs.
            return True
        try:
            self.session_revoker.revoke_all_human_sessions()
        except Exception:
            return False
        self._revoked_while_closed = True
        self._revoked_in_check = True
        return True

    def _marker_failed(self) -> None:
        """Log a marker that stays unsaved: the first failure and every doubling.

        Only while the marker is not known to be stored; a failed rewrite of a
        stored marker loses nothing a restart needs (Issue #144).
        """
        if self._exposure_recorded:
            return
        self._marker_failures += 1
        if self._marker_failures & (self._marker_failures - 1) == 0:
            logging.getLogger(__name__).warning(Event.SESSION_REVOCATION_MARKER_UNSAVED)

    def _marker_saved(self) -> None:
        if self._marker_failures:
            self._marker_failures = 0
            logging.getLogger(__name__).warning(Event.SESSION_REVOCATION_MARKER_SAVED)

    def _after_evaluation(self, reasons: tuple[Reason, ...]) -> tuple[Reason, ...]:
        if self.session_revoker is None:
            # Nothing durable could carry a revocation requirement across a
            # restart, so access never opens without a revoker.
            return reasons + (Reason.SESSION_REVOCATION_UNAVAILABLE,)
        self._revoked_in_check = False
        if any(reason in EXPOSURE_REASONS for reason in reasons):
            self._revocation_required = True
            self._revocation_durable = self._make_durable()
        elif self._revocation_required and (not self._revocation_durable
                                            or not self._exposure_recorded):
            # Also retry the marker after a committed immediate revocation
            # (PR #134), kept with the session gate as the durable record.
            self._revocation_durable = self._make_durable()
        if not self._revocation_durable:
            # Only memory holds the requirement; a restart could lose it.
            return reasons + (Reason.SESSION_REVOCATION_FAILED,)
        if reasons or not self._revocation_required:
            return reasons
        if not (self._revoked_in_check and not self._ever_opened):
            # Issue #145: the fallback revocation committed in this very check
            # already satisfies the reopening one when access has never been
            # open in this process (a clean startup), since no request can
            # have seen it open and committed a session after that
            # revocation. Otherwise (PR #134) reopening revokes again; with
            # the session gate (Issue #144) that is defense in depth for a
            # commit that bypassed ``admit()``.
            try:
                self.session_revoker.revoke_all_human_sessions()
            except Exception:
                return (Reason.SESSION_REVOCATION_FAILED,)
        self._revocation_required = False
        self._revocation_durable = True
        self._revoked_while_closed = False
        self._exposure_recorded = False
        self._marker_failures = 0
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
        # Under the gate lock: once this returns, no ``admit()`` block that
        # saw the earlier open verdict is still committing (Issue #144).
        with self._session_gate_lock:
            self._publish(ReservationVerdict(False, self._verdict.reasons, self._verdict.checked_at,
                                             self._verdict.check))

    def _publish(self, verdict: ReservationVerdict) -> None:
        """Replace the verdict; the caller holds the gate lock."""
        if self._verdict.open and not verdict.open:
            self._epoch += 1
        self._verdict = verdict

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

    def _enumerate_own(self):
        if not callable(self._own_sockets):
            return Reason.LISTENER_OWNER_UNVERIFIED
        value = self._enumerate("own-sockets", lambda: tuple(self._own_sockets()),
                                Reason.LISTENER_OWNER_UNVERIFIED, Reason.LISTENER_OWNER_UNVERIFIED, int)
        return value if isinstance(value, Reason) else frozenset(value)

    def _enumerate_mapping(self, name: str, call: Callable[[], dict], valid: Callable[[object], bool]):
        """A bounded ``dict`` lookup on a worker thread; ``None`` when unknown."""
        previous = self._inflight.get(name)
        if previous is not None and previous.is_alive():
            return None
        box: dict[str, object] = {}

        def run():
            try:
                box["value"] = call()
            except BaseException:
                box["error"] = True

        worker = threading.Thread(target=run, name=f"reservation-{name}", daemon=True)
        self._inflight[name] = worker
        worker.start()
        worker.join(self._timeout)
        value = box.get("value")
        if worker.is_alive() or "error" in box or not isinstance(value, dict) or any(
                type(key) is not int or not valid(item) for key, item in value.items()):
            return None
        return value

    def _enumerate_creators(self, inodes: frozenset):
        # Unknown creators (None): every listener they would verify stays unverified.
        return self._enumerate_mapping(
            "owners", lambda: self._socket_owners.creators(inodes),
            lambda creator: isinstance(creator, SocketCreator)
            and (creator.cgroup is None or isinstance(creator.cgroup, str))
            and type(creator.uid) is int)

    def _confirmed_creators(self, expected: dict):
        """Creators by inode, keeping a mismatch only when a second dump repeats it.

        A mismatch the immediate re-dump does not reproduce exactly (the
        socket went away, its creator changed, or the dump failed) is dropped,
        which leaves that listener unverified rather than an exposure (Owner
        decision, 2026-10-07).
        """
        first = self._enumerate_creators(frozenset(expected))
        if first is None:
            return Reason.LISTENER_OWNER_UNVERIFIED
        first = {inode: creator for inode, creator in first.items() if inode in expected}
        mismatched = mismatched_creators(expected, first)
        if not mismatched:
            return first
        second = self._enumerate_creators(mismatched) or {}
        return {inode: creator for inode, creator in first.items()
                if inode not in mismatched or second.get(inode) == creator}

    def _enumerate_sole_holders(self, inodes: frozenset):
        lookup = getattr(self._socket_owners, "held_only_by_requester", None)
        if not callable(lookup):
            return Reason.LISTENER_OWNER_UNVERIFIED
        value = self._enumerate_mapping("sole-holders", lambda: lookup(inodes),
                                        lambda sole: type(sole) is bool)
        return Reason.LISTENER_OWNER_UNVERIFIED if value is None else value

    def _upstream_privileged(self):
        """Whether the upstream port is below ``ip_unprivileged_port_start``; a ``Reason`` when unknown."""
        if not callable(self._port_start):
            return Reason.LISTENER_OWNER_UNVERIFIED
        try:
            start = self._port_start()
        except Exception:
            return Reason.LISTENER_OWNER_UNVERIFIED
        if type(start) is not int or not 0 <= start <= 65536:
            return Reason.LISTENER_OWNER_UNVERIFIED
        return self.config.human_listener.port < start

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
            own = self._enumerate_own()
            if self._socket_owners is None:
                # The resolver is mandatory: no creator or holder can be verified.
                owners = sole = Reason.LISTENER_OWNER_UNVERIFIED
            else:
                expected = expected_creators(self.config, listeners, self._exceptions)
                owners = self._confirmed_creators(expected) if expected else {}
                # No other process of the ServerSentinel unit(s) may hold the
                # upstream (Issue #126); a failed lookup is unverified.
                human = human_inodes(self.config, listeners, own)
                sole = self._enumerate_sole_holders(human) if human else {}
            reasons, extra_listeners, extra_routes = evaluate(
                self.config, listeners, routes, self._exceptions, resolved, owners, own,
                sole, self._upstream_privileged())
        except Exception:
            reasons, extra_listeners, extra_routes = (Reason.LISTENER_ENUMERATION_UNAVAILABLE,), 0, 0
        if not self._exceptions_loaded:
            reasons = (self._exceptions_reason,) + reasons
        # Decide + commit under the session gate (Issue #144): the marker,
        # fallback and reopening revocations and the published verdict.
        # Access is still closed here: reopening waits for any required
        # revocation, and no session commit can interleave with either.
        with self._session_gate_lock:
            reasons = self._after_evaluation(reasons)
            at = self._now()
            verdict = ReservationVerdict(not reasons, reasons, at, kind)
            if verdict.open:
                self._ever_opened = True
            self._publish(verdict)
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
