"""Unprivileged listener-creator lookup through ``NETLINK_SOCK_DIAG`` (Issue #126).

The hostname reservation check (``reservation.py``) asks which systemd unit and
uid *created* each socket it must verify: an excepted wildcard system
listener, a recorded proxy socket and the human upstream. Reading another
account's ``/proc/<pid>/fd`` needs ptrace-level privilege, so the non-root
backend does not ask which processes *hold* a socket. It asks the kernel's
socket diagnostics instead (Owner decision, 2026-10-07): an unprivileged
``inet_diag`` dump of the TCP and UDP tables (IPv4 and IPv6) of the caller's
network namespace reports each socket's inode, owning uid and the cgroup v2 id
it was created in (``INET_DIAG_CGROUP_ID``). A cgroup v2 id is the inode
number of that cgroup's directory under ``/sys/fs/cgroup`` on a 64-bit
kernel, which any account can ``stat``.

systemd creates a ``.socket`` unit's sockets in that unit's own cgroup
(``/system.slice/ssh.socket``), and a service's own sockets in the service's
cgroup (``/system.slice/tailscaled.service``). Only root can move a process
into a ``system.slice`` cgroup.

What this cannot show (accepted residual risk, Owner decision 2026-10-07): the
cgroup is the *creator's*, recorded when the socket was made; it does not
change when the descriptor is inherited across ``fork`` or passed with
``SCM_RIGHTS``. A legitimate creator that is compromised and hands its
listening socket to another process is not detected. The human upstream adds
a same-uid descriptor scan of the ServerSentinel unit's own processes
(``held_only_by_requester``) for the inheritance case it can see.

This module only reads: it sends dump requests, ``stat``s and lists
``/sys/fs/cgroup``, reads ``cgroup.procs`` and ``/proc/<pid>/fd`` links of
processes in the ServerSentinel unit's cgroups. It needs no capability, no
helper process and no root. Every failure raises, and the reservation check
turns any failure into ``LISTENER_OWNER_UNVERIFIED`` (closed, no revocation).
"""

from dataclasses import dataclass
import os
import re
import socket
import struct
import time
from typing import Callable

from .reservation import UPSTREAM_SOCKET_UNIT, ReservationEnumerationError, SocketCreator


# <linux/netlink.h>, <linux/sock_diag.h>, <linux/inet_diag.h>
NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST = 0x01
NLM_F_MULTI = 0x02
NLM_F_DUMP_INTR = 0x10
NLM_F_DUMP = 0x300  # NLM_F_ROOT | NLM_F_MATCH
NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSG_OVERRUN = 4
# enum { INET_DIAG_NONE, ..., INET_DIAG_SK_BPF_STORAGES = 20, INET_DIAG_CGROUP_ID = 21 }
# (checked against the installed linux/inet_diag.h). The kernel adds it to
# every inet socket it reports when built with CONFIG_SOCK_CGROUP_DATA, with
# no request extension bit.
INET_DIAG_CGROUP_ID = 21
NLA_TYPE_MASK = 0x3FFF
TCP_LISTEN = 10
# An unconnected UDP socket is in TCP_CLOSE (``/proc/net/udp`` state 07).
TCP_CLOSE = 7

NLMSG_HEADER = struct.Struct("=IHHII")
INET_DIAG_REQ_V2 = struct.Struct("=BBBBI48s")
# family, state, timer, retrans, sockid (sport, dport, src[16], dst[16],
# if, cookie[2]), expires, rqueue, wqueue, uid, inode
INET_DIAG_MSG = struct.Struct("=BBBB48sIIIII")
RTATTR = struct.Struct("=HH")

# The four tables ``/proc/net/{tcp,tcp6,udp,udp6}`` show, with the state the
# reservation check enumerates in each.
TABLES = (
    (socket.AF_INET, socket.IPPROTO_TCP, TCP_LISTEN),
    (socket.AF_INET6, socket.IPPROTO_TCP, TCP_LISTEN),
    (socket.AF_INET, socket.IPPROTO_UDP, TCP_CLOSE),
    (socket.AF_INET6, socket.IPPROTO_UDP, TCP_CLOSE),
)

RECEIVE_BYTES = 262_144
MAX_DUMP_BYTES = 64 * 1024 * 1024
MAX_DUMP_SOCKETS = 1_000_000
DUMP_TIMEOUT_SECONDS = 5.0
MAX_CGROUPS = 65_536
MAX_CGROUP_PROCS_BYTES = 1_048_576
MAX_SCANNED_PROCESSES = 4096
# Gap between consecutive holder scans of one check, and the number of scans
# another holder must appear in. A child between fork and exec still has every
# descriptor (close-on-exec closes them only at exec); it is usually gone or
# past exec well within one gap, and a third scan gives a loaded host another
# gap before a holder is confirmed (Issue #160).
HOLDER_CONFIRM_SECONDS = 0.1
HOLDER_CONFIRM_SCANS = 3
CGROUP_ROOT = "/sys/fs/cgroup"


class SockDiagError(ReservationEnumerationError):
    """The dump failed, was refused, timed out or was not understood."""


@dataclass(frozen=True)
class DiagSocket:
    """One socket from an ``inet_diag`` dump; ``cgroup_id`` None: attribute absent."""

    family: int
    protocol: int
    state: int
    inode: int
    uid: int
    cgroup_id: int | None


def build_request(family: int, protocol: int, state: int, sequence: int) -> bytes:
    """One ``SOCK_DIAG_BY_FAMILY`` dump request for sockets in ``state``."""
    body = INET_DIAG_REQ_V2.pack(family, protocol, 0, 0, 1 << state, bytes(48))
    return NLMSG_HEADER.pack(NLMSG_HEADER.size + len(body), SOCK_DIAG_BY_FAMILY,
                             NLM_F_REQUEST | NLM_F_DUMP, sequence, 0) + body


def _align(length: int) -> int:
    return (length + 3) & ~3


def _parse_attributes(data: bytes, start: int, end: int) -> int | None:
    cgroup_id = None
    offset = start
    while offset < end:
        if end - offset < RTATTR.size:
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        length, kind = RTATTR.unpack_from(data, offset)
        if length < RTATTR.size or offset + length > end:
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        if kind & NLA_TYPE_MASK == INET_DIAG_CGROUP_ID:
            if cgroup_id is not None or length != RTATTR.size + 8:
                raise SockDiagError("MALFORMED_SOCK_DIAG")
            cgroup_id = struct.unpack_from("=Q", data, offset + RTATTR.size)[0]
        offset += _align(length)
    return cgroup_id


def parse_messages(data: bytes, *, family: int, protocol: int, state: int, sequence: int,
                   port_id: int) -> tuple[list[DiagSocket], bool]:
    """Parse one received datagram of a dump; returns its sockets and whether it ended.

    Anything not understood raises: a short or overlong header, a message for
    another request, an error, an interrupted (inconsistent) dump, another
    message type, a socket of another family or state, or a malformed
    attribute. The caller turns that into an unverified owner.
    """
    sockets: list[DiagSocket] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < NLMSG_HEADER.size:
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        length, kind, flags, seq, pid = NLMSG_HEADER.unpack_from(data, offset)
        if length < NLMSG_HEADER.size or offset + length > len(data):
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        if seq != sequence or pid != port_id:
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        if flags & NLM_F_DUMP_INTR:
            # The table changed during the dump; its content is not consistent.
            raise SockDiagError("SOCK_DIAG_INTERRUPTED")
        body = offset + NLMSG_HEADER.size
        if kind == NLMSG_DONE:
            if length >= NLMSG_HEADER.size + 4 and struct.unpack_from("=i", data, body)[0] < 0:
                raise SockDiagError("SOCK_DIAG_FAILED")
            return sockets, True
        if kind == NLMSG_ERROR:
            # Includes EPERM, ENOENT (no diag module for the protocol) and an
            # unexpected acknowledgement (error 0): a dump never ends that way.
            raise SockDiagError("SOCK_DIAG_FAILED")
        if kind == NLMSG_NOOP:
            offset += _align(length)
            continue
        if kind != SOCK_DIAG_BY_FAMILY or length < NLMSG_HEADER.size + INET_DIAG_MSG.size:
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        (msg_family, msg_state, _timer, _retrans, _id, _expires, _rqueue, _wqueue,
         uid, inode) = INET_DIAG_MSG.unpack_from(data, body)
        if msg_family != family or msg_state != state:
            raise SockDiagError("MALFORMED_SOCK_DIAG")
        cgroup_id = _parse_attributes(data, body + INET_DIAG_MSG.size, offset + length)
        sockets.append(DiagSocket(family, protocol, msg_state, inode, uid, cgroup_id))
        offset += _align(length)
    return sockets, False


class NetlinkSockDiag:
    """Bounded ``inet_diag`` dumps over an unprivileged ``NETLINK_SOCK_DIAG`` socket.

    It sees the network namespace of the calling process only, so the backend
    must run in the host network namespace that holds the reserved addresses
    (no ``PrivateNetwork=``), with ``AF_NETLINK`` in its
    ``RestrictAddressFamilies=``.
    """

    def __init__(self, *, socket_factory: Callable = socket.socket,
                 monotonic: Callable[[], float] = time.monotonic,
                 timeout: float = DUMP_TIMEOUT_SECONDS):
        self._socket = socket_factory
        self._monotonic = monotonic
        self._timeout = float(timeout)
        self._sequence = 0

    def dump(self) -> tuple[DiagSocket, ...]:
        """Every TCP LISTEN and unconnected UDP socket, IPv4 and IPv6; raise on any doubt."""
        deadline = self._monotonic() + self._timeout
        result: list[DiagSocket] = []
        budget = [MAX_DUMP_BYTES]
        try:
            channel = self._socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC,
                                   NETLINK_SOCK_DIAG)
        except OSError:
            # EAFNOSUPPORT (RestrictAddressFamilies), EPROTONOSUPPORT, ...
            raise SockDiagError("SOCK_DIAG_UNAVAILABLE") from None
        with channel:
            for family, protocol, state in TABLES:
                result.extend(self._dump_one(channel, family, protocol, state, deadline, budget))
                if len(result) > MAX_DUMP_SOCKETS:
                    raise SockDiagError("SOCK_DIAG_TOO_LARGE")
        return tuple(result)

    def _dump_one(self, channel, family, protocol, state, deadline, budget) -> list[DiagSocket]:
        self._sequence = self._sequence % 0x7FFFFFFF + 1
        sequence = self._sequence
        try:
            channel.sendto(build_request(family, protocol, state, sequence), (0, 0))
            port_id = channel.getsockname()[0]
        except OSError:
            raise SockDiagError("SOCK_DIAG_UNAVAILABLE") from None
        sockets: list[DiagSocket] = []
        while True:
            remaining = deadline - self._monotonic()
            if not remaining > 0:
                raise SockDiagError("SOCK_DIAG_TIMEOUT")
            try:
                channel.settimeout(remaining)
                data, _ancillary, flags, address = channel.recvmsg(RECEIVE_BYTES)
            except socket.timeout:
                raise SockDiagError("SOCK_DIAG_TIMEOUT") from None
            except OSError:
                raise SockDiagError("SOCK_DIAG_UNAVAILABLE") from None
            if flags & socket.MSG_TRUNC or not data:
                raise SockDiagError("MALFORMED_SOCK_DIAG")
            if not isinstance(address, tuple) or not address or address[0] != 0:
                # Only the kernel (port id 0) answers a dump.
                raise SockDiagError("MALFORMED_SOCK_DIAG")
            budget[0] -= len(data)
            if budget[0] < 0:
                raise SockDiagError("SOCK_DIAG_TOO_LARGE")
            batch, done = parse_messages(data, family=family, protocol=protocol, state=state,
                                         sequence=sequence, port_id=port_id)
            sockets.extend(batch)
            if len(sockets) > MAX_DUMP_SOCKETS:
                raise SockDiagError("SOCK_DIAG_TOO_LARGE")
            if done:
                return sockets


def cgroup_paths(root: str = CGROUP_ROOT, *, max_entries: int = MAX_CGROUPS) -> dict[int, str]:
    """Map each cgroup v2 directory's inode (its cgroup id) to its path, ``"/"`` for the root.

    A subtree that cannot be listed is left out, so a socket created there
    stays unresolved (unverified, never mistaken for another unit); a
    directory removed during the walk is skipped the same way.
    """
    try:
        if not os.path.isfile(os.path.join(root, "cgroup.controllers")):
            # Not a cgroup v2 (unified) hierarchy.
            raise SockDiagError("CGROUP_UNAVAILABLE")
        paths = {os.stat(root, follow_symlinks=False).st_ino: "/"}
    except OSError:
        raise SockDiagError("CGROUP_UNAVAILABLE") from None
    pending = [(root, "")]
    while pending:
        directory, relative = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                inode = entry.stat(follow_symlinks=False).st_ino
            except OSError:
                continue
            path = relative + "/" + entry.name
            if inode in paths:
                raise SockDiagError("CGROUP_UNAVAILABLE")
            paths[inode] = path
            if len(paths) > max_entries:
                raise SockDiagError("CGROUP_UNAVAILABLE")
            pending.append((entry.path, path))
    return paths


def own_cgroup(proc_self: str = "/proc/self") -> str:
    """This process's cgroup v2 path from ``/proc/self/cgroup`` (``0::<path>``)."""
    try:
        with open(os.path.join(proc_self, "cgroup"), encoding="utf-8") as handle:
            text = handle.read(65536)
    except (OSError, ValueError):
        raise SockDiagError("CGROUP_UNAVAILABLE") from None
    found = [line[3:] for line in text.splitlines() if line.startswith("0::")]
    if len(found) != 1 or not found[0].startswith("/") or "\0" in found[0]:
        raise SockDiagError("CGROUP_UNAVAILABLE")
    return found[0]


def _probe_listener() -> socket.socket:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        probe.listen(1)
    except OSError:
        probe.close()
        raise
    return probe


class SockDiagOwners:
    """The production ``SocketOwnerResolver``: creators via sock_diag, holders via own-unit fds.

    ``creators`` first opens a loopback probe listener of its own and requires
    the same dump to report it with this process's cgroup and effective uid:
    a kernel without the cgroup attribute, a denied or filtered netlink socket,
    a cgroup namespace or a ``/sys/fs/cgroup`` view that does not map ids to
    paths, or any other mismatch raises before any listener is judged (the
    startup self-check, repeated on every check).

    ``held_only_by_requester`` lists the processes in this process's own
    cgroup subtree and in ``extra_units`` (``/system.slice/<unit>``, by
    default the upstream ``.socket`` unit), and reads their ``/proc/<pid>/fd``
    links, which needs no privilege for processes of the same uid. Any process
    there whose descriptors cannot be read raises.
    """

    def __init__(self, *, diag: NetlinkSockDiag | None = None, cgroup_root: str = CGROUP_ROOT,
                 proc: str = "/proc", proc_self: str = "/proc/self",
                 extra_units: tuple[str, ...] = (UPSTREAM_SOCKET_UNIT,),
                 probe: Callable[[], socket.socket] | None = _probe_listener,
                 getpid: Callable[[], int] = os.getpid, geteuid: Callable[[], int] = os.geteuid,
                 confirm_seconds: float = HOLDER_CONFIRM_SECONDS,
                 sleep: Callable[[float], None] = time.sleep):
        if not isinstance(cgroup_root, str) or not cgroup_root.startswith("/") \
                or not isinstance(proc, str) or not proc.startswith("/"):
            raise ValueError("INVALID_PROC_ROOT")
        for unit in extra_units:
            if not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9:_.\\@-]{1,250}\.(service|socket)", unit):
                raise ValueError("INVALID_UNIT")
        self._diag = diag or NetlinkSockDiag()
        self._cgroup_root = cgroup_root
        self._proc = proc
        self._proc_self = proc_self
        self._extra_units = tuple(extra_units)
        self._probe = probe
        self._getpid = getpid
        self._geteuid = geteuid
        self._confirm_seconds = float(confirm_seconds)
        self._sleep = sleep

    def creators(self, inodes: frozenset) -> dict:
        probe = self._probe() if self._probe is not None else None
        try:
            probe_inode = os.fstat(probe.fileno()).st_ino if probe is not None else None
            sockets = self._diag.dump()
            paths = cgroup_paths(self._cgroup_root)
            mine = own_cgroup(self._proc_self)
        finally:
            if probe is not None:
                probe.close()
        found: dict[int, SocketCreator] = {}
        for item in sockets:
            if not item.inode:
                continue
            path = None if item.cgroup_id is None else paths.get(item.cgroup_id)
            creator = SocketCreator(path, item.uid)
            if found.setdefault(item.inode, creator) != creator:
                raise SockDiagError("MALFORMED_SOCK_DIAG")
        if probe_inode is not None and found.get(probe_inode) != SocketCreator(mine, self._geteuid()):
            raise SockDiagError("SOCK_DIAG_SELF_CHECK_FAILED")
        return {inode: found[inode] for inode in inodes if inode in found}

    def held_only_by_requester(self, inodes: frozenset) -> dict:
        """``True`` when no other unit process holds the inode; ``False`` only when confirmed.

        Another holder counts only when the same process (pid and start time)
        still holds the inode in every one of ``HOLDER_CONFIRM_SCANS`` scans
        ``confirm_seconds`` apart (Issue #160: three scans, so a child that is
        slow to exec on a loaded host gets two gaps, not one). A child between
        ``fork`` and ``exec`` briefly shows every descriptor of the backend
        (close-on-exec acts only at exec), and its descriptors can be briefly
        unreadable while it execs, so a holder or an unreadable process that is
        gone or changed in any later scan leaves the inode out (unverified),
        never shared. A process whose descriptors stay unreadable in every scan
        raises. Whatever executable the holder runs does not matter: a process
        that keeps the descriptor through every scan shares the socket.
        """
        first, first_unreadable = self._holders(inodes)
        if not any(first.values()) and not first_unreadable:
            return {inode: True for inode in inodes}
        confirmed = {inode: set(first[inode]) for inode in inodes}
        seen = {inode: bool(first[inode]) for inode in inodes}
        unreadable = set(first_unreadable)
        last_unreadable = first_unreadable
        for _ in range(HOLDER_CONFIRM_SCANS - 1):
            self._sleep(self._confirm_seconds)
            holders, last_unreadable = self._holders(inodes)
            unreadable &= last_unreadable
            for inode in inodes:
                confirmed[inode] &= holders[inode]
                seen[inode] = seen[inode] or bool(holders[inode])
        if unreadable:
            raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE")
        result = {}
        for inode in inodes:
            # A start time that could not be read never confirms a holder.
            if any(start is not None for _, start in confirmed[inode]):
                result[inode] = False
            elif not seen[inode] and not last_unreadable:
                result[inode] = True
            # else: not in every scan, or not readable now: unverified (left out)
        return result

    def _holders(self, inodes: frozenset) -> tuple[dict, set]:
        """Each inode's other holders and the unreadable processes, as ``(pid, start time)``."""
        wanted = {f"socket:[{inode}]": inode for inode in inodes}
        me = self._getpid()
        holders: dict[int, set] = {inode: set() for inode in inodes}
        unreadable: set = set()
        for pid in self._unit_processes():
            if pid == me:
                continue
            base = os.path.join(self._proc, str(pid), "fd")
            try:
                descriptors = os.listdir(base)
            except (FileNotFoundError, ProcessLookupError):
                continue  # exited
            except OSError:
                unreadable.add((pid, self._start_time(pid)))
                continue
            held = set()
            for fd in descriptors:
                try:
                    target = os.readlink(os.path.join(base, fd))
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except OSError:
                    unreadable.add((pid, self._start_time(pid)))
                    break
                if target in wanted:
                    held.add(wanted[target])
            if held:
                identity = (pid, self._start_time(pid))
                for inode in held:
                    holders[inode].add(identity)
        return holders, unreadable

    def _start_time(self, pid: int):
        """The process start time (``/proc/<pid>/stat`` field 22), or None when unreadable."""
        try:
            with open(os.path.join(self._proc, str(pid), "stat"), "rb") as handle:
                text = handle.read(4096)
            fields = text[text.rindex(b")") + 2:].split()
            value = fields[19]
            if value.isdigit():
                return int(value)
        except (OSError, ValueError, IndexError):
            pass
        return None

    def _unit_processes(self) -> set[int]:
        roots = [(own_cgroup(self._proc_self), True)]
        roots += [("/system.slice/" + unit, False) for unit in self._extra_units]
        pids: set[int] = set()
        for path, required in roots:
            top = os.path.normpath(self._cgroup_root + path)
            if not top.startswith(self._cgroup_root.rstrip("/") + "/") and top != self._cgroup_root:
                raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE")
            if not os.path.isdir(top):
                if required:
                    raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE")
                continue  # an inactive extra unit has no cgroup and no process
            # os.walk does not follow symbolic links.
            for directory, _, _ in os.walk(top, onerror=self._walk_error):
                pids |= self._procs(os.path.join(directory, "cgroup.procs"))
                if len(pids) > MAX_SCANNED_PROCESSES:
                    raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE")
        return pids

    @staticmethod
    def _walk_error(error: OSError) -> None:
        if isinstance(error, FileNotFoundError):
            return  # a child cgroup removed during the walk has no process left
        # A sub-cgroup that cannot be listed may hide a process holding the socket.
        raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE")

    @staticmethod
    def _procs(path: str) -> set[int]:
        try:
            with open(path, "rb") as handle:
                text = handle.read(MAX_CGROUP_PROCS_BYTES + 1)
        except FileNotFoundError:
            return set()  # removed during the walk
        except OSError:
            raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE") from None
        if len(text) > MAX_CGROUP_PROCS_BYTES or not re.fullmatch(rb"(?:[0-9]{1,10}\n)*", text):
            raise ReservationEnumerationError("SOCKET_HOLDERS_UNREADABLE")
        return {int(line) for line in text.split()}
