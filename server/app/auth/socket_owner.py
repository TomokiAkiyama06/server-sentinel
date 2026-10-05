"""Privileged listener socket-owner helper and its client (Issue #126).

ServerSentinel runs as a dedicated non-root account and cannot read another
account's ``/proc/<pid>/fd`` or ``exe``, so it cannot tell who holds a
root-owned listener such as ``sshd`` on 22 (Owner decision, 2026-10-01). This
module is a small separate service that does only that lookup for it:

- it runs as its own systemd service (``infra/systemd/``), as a transient
  non-root account holding exactly ``CAP_SYS_PTRACE`` (the kernel's
  ``ptrace_may_access`` check for another account's ``fd`` links and ``exe``)
  and ``CAP_DAC_READ_SEARCH`` (listing another account's ``/proc/<pid>/fd``);
  ServerSentinel itself stays without capabilities;
- it answers on a socket-activated unix stream socket that systemd creates
  ``root:server-sentinel-socket-owner`` mode ``0660`` in a root-owned
  directory, and it answers only a peer whose kernel-reported ``SO_PEERCRED``
  UID is the ServerSentinel service UID from the administrator-owned
  deployment configuration (every other peer is closed unread and audited);
- it answers only about sockets that are TCP LISTEN or unconnected UDP sockets
  in the requesting process's own network namespace (the rows ServerSentinel
  already sees in ``/proc/net``), and only with each holder's executable path
  and system unit, or with one bit: whether the requester alone holds it. No
  PID, command line, account, other descriptor or other process is returned;
- requests are bounded in size, inode count and rate, and every answer or
  refusal is written to the journal as an identifier-light audit line
  (refusals coalesced);
- any failure (a missing or slow helper, an incomplete scan, a malformed
  answer, a rate limit) raises in the client, so the reservation check keeps
  the listener ``LISTENER_OWNER_UNVERIFIED`` and access closed.

The helper imports only the standard library and ``app.auth.reservation``
(itself standard-library only). It never changes a socket, a process or a
file; it reads ``/proc`` and the deployment configuration only.
"""

import argparse
from dataclasses import dataclass
import json
import math
import os
import re
import socket
import stat
import struct
import sys
import time
from typing import Callable

from app.auth.reservation import (
    MAX_EXECUTABLE_PATH, ProcSocketOwners, ReservationEnumerationError, SocketOwner, _UNIT,
    parse_proc_net_tcp, parse_proc_net_udp,
)


PROTOCOL_VERSION = 1
DEFAULT_SOCKET = "/run/server-sentinel-socket-owner/socket"
OP_OWNERS = "owners"
OP_REQUESTER_ONLY = "requester_only"
OPERATIONS = frozenset({OP_OWNERS, OP_REQUESTER_ONLY})
MAX_REQUEST_BYTES = 4096
# 16 exceptions on both families, the recorded proxy sockets and the upstream.
MAX_REQUEST_INODES = 64
MAX_HOLDERS_PER_SOCKET = 64
MAX_RESPONSE_BYTES = 262_144
MAX_PROC_FILE_BYTES = 256 * 1024 * 1024
MAX_CONFIGURATION_BYTES = 16 * 1024
CLIENT_TIMEOUT_SECONDS = 5.0
CONNECTION_TIMEOUT_SECONDS = 2.0
# A check asks at most twice; checks run at startup, daily, every five minutes
# while closed, and after an Owner exception change.
RATE_BURST = 20
RATE_PER_SECOND = 1 / 3
AUDIT_COALESCE_SECONDS = 60.0
ADMINISTRATOR_UID = 0
SYSTEMD_FIRST_FD = 3
# CapEff bits: CAP_DAC_READ_SEARCH (2) and CAP_SYS_PTRACE (19).
REQUIRED_CAPABILITIES = (1 << 2) | (1 << 19)
_PEERCRED = struct.Struct("3i")
_INODE = re.compile(r"[1-9][0-9]{0,19}")


class SocketOwnerProtocolError(Exception):
    """A request or answer that does not follow the helper protocol."""


# -- Protocol -----------------------------------------------------------------

def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise SocketOwnerProtocolError("DUPLICATE_KEY")
    return dict(pairs)


def _load(data: bytes, limit: int) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise SocketOwnerProtocolError("BAD_SIZE")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except SocketOwnerProtocolError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SocketOwnerProtocolError("BAD_JSON") from None
    if not isinstance(document, dict) or document.get("version") != PROTOCOL_VERSION \
            or type(document.get("version")) is not int:
        raise SocketOwnerProtocolError("BAD_VERSION")
    return document


def _inode(value) -> int:
    if type(value) is not int or not _INODE.fullmatch(str(value)):
        raise SocketOwnerProtocolError("BAD_INODE")
    return value


def encode_request(op: str, inodes) -> bytes:
    values = sorted(frozenset(inodes))
    if op not in OPERATIONS or not values or len(values) > MAX_REQUEST_INODES:
        raise SocketOwnerProtocolError("BAD_REQUEST")
    for value in values:
        _inode(value)
    data = json.dumps({"version": PROTOCOL_VERSION, "op": op, "inodes": values},
                      separators=(",", ":")).encode()
    if len(data) > MAX_REQUEST_BYTES:
        raise SocketOwnerProtocolError("BAD_REQUEST")
    return data


def decode_request(data: bytes) -> tuple[str, frozenset]:
    document = _load(data, MAX_REQUEST_BYTES)
    if set(document) != {"version", "op", "inodes"} or document["op"] not in OPERATIONS:
        raise SocketOwnerProtocolError("BAD_REQUEST")
    inodes = document["inodes"]
    if not isinstance(inodes, list) or not inodes or len(inodes) > MAX_REQUEST_INODES:
        raise SocketOwnerProtocolError("BAD_REQUEST")
    values = frozenset(_inode(value) for value in inodes)
    if len(values) != len(inodes):
        raise SocketOwnerProtocolError("BAD_REQUEST")
    return document["op"], values


def _executable(value) -> str | None:
    """The reported executable path, or ``None`` when it cannot be stated safely."""
    if value is None:
        return None
    if (not isinstance(value, str) or not value.startswith("/") or "\0" in value
            or len(value) > MAX_EXECUTABLE_PATH):
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return value


def encode_owners(answer: dict) -> bytes:
    """``answer`` maps inodes to the set of ``SocketOwner``s holding them."""
    sockets = []
    for inode in sorted(answer):
        holders = sorted({(_executable(owner.executable), owner.unit) for owner in answer[inode]},
                         key=lambda item: (item[0] or "", item[1] or ""))
        sockets.append({"inode": inode, "holders": [
            {"executable": executable, "unit": unit} for executable, unit in holders]})
    return json.dumps({"version": PROTOCOL_VERSION, "sockets": sockets}, separators=(",", ":")).encode()


def encode_requester_only(answer: dict) -> bytes:
    sockets = [{"inode": inode, "requester_only": answer[inode] is True} for inode in sorted(answer)]
    return json.dumps({"version": PROTOCOL_VERSION, "sockets": sockets}, separators=(",", ":")).encode()


def encode_error(code: str) -> bytes:
    return json.dumps({"version": PROTOCOL_VERSION, "error": code}, separators=(",", ":")).encode()


def _sockets(data: bytes, requested: frozenset) -> list:
    document = _load(data, MAX_RESPONSE_BYTES)
    if set(document) == {"version", "error"}:
        code = document["error"]
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z_]{1,64}", code):
            raise SocketOwnerProtocolError("BAD_RESPONSE")
        raise ReservationEnumerationError(code)
    if set(document) != {"version", "sockets"} or not isinstance(document["sockets"], list) \
            or len(document["sockets"]) > len(requested):
        raise SocketOwnerProtocolError("BAD_RESPONSE")
    seen = set()
    for entry in document["sockets"]:
        if not isinstance(entry, dict):
            raise SocketOwnerProtocolError("BAD_RESPONSE")
        inode = _inode(entry.get("inode"))
        if inode not in requested or inode in seen:
            raise SocketOwnerProtocolError("BAD_RESPONSE")
        seen.add(inode)
    return document["sockets"]


def decode_owners(data: bytes, requested: frozenset) -> dict:
    result = {}
    for entry in _sockets(data, requested):
        holders = entry.get("holders")
        if set(entry) != {"inode", "holders"} or not isinstance(holders, list) \
                or not holders or len(holders) > MAX_HOLDERS_PER_SOCKET:
            raise SocketOwnerProtocolError("BAD_RESPONSE")
        owners = set()
        for holder in holders:
            if not isinstance(holder, dict) or set(holder) != {"executable", "unit"}:
                raise SocketOwnerProtocolError("BAD_RESPONSE")
            executable, unit = holder["executable"], holder["unit"]
            if executable is not None and _executable(executable) != executable:
                raise SocketOwnerProtocolError("BAD_RESPONSE")
            if unit is not None and (not isinstance(unit, str) or not _UNIT.fullmatch(unit)):
                raise SocketOwnerProtocolError("BAD_RESPONSE")
            owners.add(SocketOwner(executable, unit))
        result[entry["inode"]] = frozenset(owners)
    return result


def decode_requester_only(data: bytes, requested: frozenset) -> dict:
    result = {}
    for entry in _sockets(data, requested):
        if set(entry) != {"inode", "requester_only"} or type(entry["requester_only"]) is not bool:
            raise SocketOwnerProtocolError("BAD_RESPONSE")
        result[entry["inode"]] = entry["requester_only"]
    return result


# -- Client (ServerSentinel side, no privilege) ---------------------------------

class SocketOwnerHelperClient:
    """``SocketOwnerResolver`` that asks the privileged helper over its unix socket.

    Before each request the socket must be a socket owned by
    ``trusted_uid`` (root: systemd creates it), not writable by others, in a
    directory owned by ``trusted_uid`` that nobody else can write, so another
    local account cannot stand in for the helper. Any failure raises, which the
    reservation check treats as ``LISTENER_OWNER_UNVERIFIED``.
    """

    def __init__(self, path: str = DEFAULT_SOCKET, *, timeout: float = CLIENT_TIMEOUT_SECONDS,
                 trusted_uid: int = ADMINISTRATOR_UID,
                 socket_factory: Callable[..., socket.socket] = socket.socket):
        if not isinstance(path, str) or not path.startswith("/") or os.path.normpath(path) != path \
                or len(path.encode()) > 107:
            raise ValueError("INVALID_HELPER_SOCKET")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("INVALID_HELPER_TIMEOUT")
        if type(trusted_uid) is not int or trusted_uid < 0:
            raise ValueError("INVALID_HELPER_OWNER")
        self._path = path
        self._timeout = float(timeout)
        self._trusted_uid = trusted_uid
        self._socket_factory = socket_factory

    def owners(self, inodes: frozenset) -> dict:
        requested = frozenset(inodes)
        if not requested:
            return {}
        return self._decode(decode_owners, self._request(OP_OWNERS, requested), requested)

    def held_only_by_requester(self, inodes: frozenset) -> dict:
        requested = frozenset(inodes)
        if not requested:
            return {}
        return self._decode(decode_requester_only, self._request(OP_REQUESTER_ONLY, requested), requested)

    @staticmethod
    def _decode(decode, data: bytes, requested: frozenset) -> dict:
        try:
            return decode(data, requested)
        except SocketOwnerProtocolError:
            # Includes an empty answer: the helper closed without replying.
            raise ReservationEnumerationError("HELPER_RESPONSE_INVALID") from None

    def _trusted_endpoint(self) -> None:
        try:
            directory = os.lstat(os.path.dirname(self._path))
            endpoint = os.lstat(self._path)
        except OSError:
            raise ReservationEnumerationError("HELPER_UNAVAILABLE") from None
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != self._trusted_uid
                or directory.st_mode & 0o022 or not stat.S_ISSOCK(endpoint.st_mode)
                or endpoint.st_uid != self._trusted_uid or endpoint.st_mode & 0o002):
            raise ReservationEnumerationError("HELPER_UNTRUSTED")

    def _request(self, op: str, inodes: frozenset) -> bytes:
        request = encode_request(op, inodes)
        self._trusted_endpoint()
        deadline = time.monotonic() + self._timeout
        try:
            with self._socket_factory(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout)
                connection.connect(self._path)
                connection.sendall(request + b"\n")
                connection.shutdown(socket.SHUT_WR)
                chunks, size = [], 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReservationEnumerationError("HELPER_TIMEOUT")
                    connection.settimeout(remaining)
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ReservationEnumerationError("HELPER_RESPONSE_TOO_LARGE")
                    chunks.append(chunk)
        except socket.timeout:
            raise ReservationEnumerationError("HELPER_TIMEOUT") from None
        except OSError:
            raise ReservationEnumerationError("HELPER_UNAVAILABLE") from None
        return b"".join(chunks)


# -- Helper (privileged side) ---------------------------------------------------

def _read_proc(path: str, *, dir_fd: int | None = None, limit: int = MAX_PROC_FILE_BYTES) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ReservationEnumerationError("PROC_FILE_TOO_LARGE")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    # A process name in ``status`` may hold any bytes; the parsed fields are ASCII.
    return b"".join(chunks).decode("utf-8", "replace")


def _status_uids(text: str) -> tuple[int, ...]:
    for line in text.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()[1:]
            if len(fields) == 4 and all(field.isdigit() for field in fields):
                return tuple(int(field) for field in fields)
    raise ReservationEnumerationError("PEER_UNVERIFIED")


def _audit_stderr(event: str, **fields) -> None:
    values = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    print(f"server-sentinel-socket-owner event={event}" + (" " + values if values else ""),
          file=sys.stderr, flush=True)


@dataclass
class _Coalesced:
    count: int = 0
    last: float | None = None


class SocketOwnerHelper:
    """Answer ownership questions from the ServerSentinel service account only."""

    def __init__(self, service_uid: int, *, proc: str = "/proc",
                 monotonic: Callable[[], float] = time.monotonic,
                 audit: Callable[..., None] = _audit_stderr,
                 burst: int = RATE_BURST, rate: float = RATE_PER_SECOND,
                 connection_timeout: float = CONNECTION_TIMEOUT_SECONDS):
        if type(service_uid) is not int or service_uid <= 0:
            raise ValueError("INVALID_SERVICE_UID")
        if not isinstance(proc, str) or not proc.startswith("/"):
            raise ValueError("INVALID_PROC_ROOT")
        if type(burst) is not int or burst < 1 or not isinstance(rate, (int, float)) \
                or isinstance(rate, bool) or not math.isfinite(rate) or rate <= 0:
            raise ValueError("INVALID_RATE")
        self.service_uid = service_uid
        self._proc = proc
        self._owners = ProcSocketOwners(proc)
        self._monotonic = monotonic
        self._audit = audit
        self._burst = burst
        self._rate = float(rate)
        self._tokens = float(burst)
        self._refilled: float | None = None
        self._timeout = float(connection_timeout)
        self._refused: dict[str, _Coalesced] = {}

    # Refusals are coalesced so an unauthorized local process cannot flood the journal.
    def _refuse(self, reason: str, **fields) -> None:
        now = self._monotonic()
        entry = self._refused.setdefault(reason, _Coalesced())
        entry.count += 1
        if entry.last is None or now - entry.last >= AUDIT_COALESCE_SECONDS or now < entry.last:
            self._audit("refused", reason=reason, count=entry.count, **fields)
            entry.count = 0
            entry.last = now

    def _admit(self) -> bool:
        now = self._monotonic()
        if self._refilled is not None and now > self._refilled:
            self._tokens = min(float(self._burst), self._tokens + (now - self._refilled) * self._rate)
        self._refilled = now
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True

    def _peer_listening_inodes(self, pid: int) -> frozenset:
        """Listening socket inodes in the peer's own network namespace.

        The peer is re-identified through its ``/proc/<pid>`` directory: a PID
        reused by a process of another account fails the ``Uid`` comparison.
        """
        try:
            directory = os.open(os.path.join(self._proc, str(pid)),
                                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError:
            raise ReservationEnumerationError("PEER_UNVERIFIED") from None
        try:
            uids = _status_uids(_read_proc("status", dir_fd=directory, limit=65536))
            if uids[0] != self.service_uid or uids[1] != self.service_uid:
                raise ReservationEnumerationError("PEER_UNVERIFIED")
            inodes = set()
            for name, parse, ipv6 in (("net/tcp", parse_proc_net_tcp, False),
                                      ("net/tcp6", parse_proc_net_tcp, True),
                                      ("net/udp", parse_proc_net_udp, False),
                                      ("net/udp6", parse_proc_net_udp, True)):
                inodes.update(listener.inode for listener in parse(_read_proc(name, dir_fd=directory), ipv6=ipv6)
                              if listener.inode)
        except ReservationEnumerationError:
            raise
        except (OSError, UnicodeDecodeError):
            raise ReservationEnumerationError("PEER_UNVERIFIED") from None
        finally:
            os.close(directory)
        return frozenset(inodes)

    def answer(self, request: bytes, peer_pid: int) -> bytes:
        """The response for one admitted request from the verified peer ``peer_pid``."""
        try:
            op, inodes = decode_request(request)
        except SocketOwnerProtocolError:
            self._refuse("bad_request", peer_pid=peer_pid)
            return encode_error("BAD_REQUEST")
        try:
            # Only sockets the peer already sees as listening in /proc/net.
            wanted = inodes & self._peer_listening_inodes(peer_pid)
            scan = self._owners.scan(wanted) if wanted else {}
        except ReservationEnumerationError as error:
            code = str(error) if re.fullmatch(r"[A-Z_]{1,64}", str(error)) else "OWNERS_UNAVAILABLE"
            self._audit("failed", op=op, inodes=len(inodes), code=code)
            return encode_error(code)
        except Exception:
            self._audit("failed", op=op, inodes=len(inodes), code="OWNERS_UNAVAILABLE")
            return encode_error("OWNERS_UNAVAILABLE")
        if any(len(holders) > MAX_HOLDERS_PER_SOCKET for holders in scan.values()):
            self._audit("failed", op=op, inodes=len(inodes), code="TOO_MANY_HOLDERS")
            return encode_error("TOO_MANY_HOLDERS")
        if op == OP_OWNERS:
            response = encode_owners({inode: frozenset(holders.values()) for inode, holders in scan.items()})
        else:
            response = encode_requester_only({inode: set(holders) == {peer_pid} for inode, holders in scan.items()})
        self._audit("answered", op=op, inodes=len(inodes), answered=len(scan))
        return response

    def handle(self, connection: socket.socket) -> None:
        """Serve one connection; never raises for a peer's behaviour."""
        with connection:
            try:
                pid, uid, _ = _PEERCRED.unpack(
                    connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size))
            except OSError:
                self._refuse("peer_credentials_unavailable")
                return
            if uid != self.service_uid or pid <= 0:
                # Closed before a single byte is read from it.
                self._refuse("peer_uid", peer_uid=uid, peer_pid=pid)
                return
            try:
                connection.settimeout(self._timeout)
                if not self._admit():
                    self._refuse("rate_limited", peer_pid=pid)
                    connection.sendall(encode_error("RATE_LIMITED"))
                    return
                request = self._read_request(connection)
                if request is None:
                    self._refuse("bad_request", peer_pid=pid)
                    connection.sendall(encode_error("BAD_REQUEST"))
                    return
                connection.sendall(self.answer(request, pid))
            except OSError:
                self._refuse("connection_failed", peer_pid=pid)

    def _read_request(self, connection: socket.socket) -> bytes | None:
        deadline = self._monotonic() + self._timeout
        data = b""
        while b"\n" not in data:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return None
            connection.settimeout(remaining)
            try:
                chunk = connection.recv(MAX_REQUEST_BYTES + 2 - len(data))
            except socket.timeout:
                return None
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_REQUEST_BYTES + 1:
                return None
        line, separator, rest = data.partition(b"\n")
        if not separator or rest or not line:
            return None
        return line

    def serve(self, listener: socket.socket) -> None:
        """Accept and answer connections one at a time until the service stops."""
        while True:
            try:
                connection, _ = listener.accept()
            except InterruptedError:
                continue
            except OSError:
                self._refuse("accept_failed")
                time.sleep(0.1)
                continue
            self.handle(connection)


def read_service_uid(path: str, *, administrator_uid: int = ADMINISTRATOR_UID) -> int:
    """``service_uid`` from the administrator-owned deployment configuration.

    The file must be owned by the administrator and every directory above it
    by root or the administrator, none writable by anyone else (a sticky
    directory excepted), so the ServerSentinel account cannot change which UID
    the helper answers.
    """
    if not isinstance(path, str) or not path.startswith("/") or os.path.normpath(path) != path:
        raise ValueError("INVALID_CONFIGURATION_PATH")
    current = "/"
    for part in path.split("/")[1:-1]:
        current = os.path.join(current, part)
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) \
                or info.st_uid not in {0, administrator_uid} \
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise ValueError("CONFIGURATION_NOT_ADMINISTRATOR_CONTROLLED")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != administrator_uid or info.st_mode & 0o022 \
                or info.st_size > MAX_CONFIGURATION_BYTES:
            raise ValueError("CONFIGURATION_NOT_ADMINISTRATOR_CONTROLLED")
        data = os.read(descriptor, MAX_CONFIGURATION_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_CONFIGURATION_BYTES:
        raise ValueError("INVALID_CONFIGURATION")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("INVALID_CONFIGURATION") from None
    uid = document.get("service_uid") if isinstance(document, dict) else None
    if type(uid) is not int or uid <= 0 or uid == administrator_uid:
        raise ValueError("INVALID_CONFIGURATION")
    return uid


def systemd_listener(environ=None, *, fileno: int = SYSTEMD_FIRST_FD) -> socket.socket:
    """The single unix stream socket passed by socket activation (``LISTEN_FDS``)."""
    values = os.environ if environ is None else environ
    if values.get("LISTEN_PID") != str(os.getpid()) or values.get("LISTEN_FDS") != "1":
        raise ValueError("SOCKET_ACTIVATION_REQUIRED")
    listener = socket.socket(fileno=fileno)
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        listener.detach()
        raise ValueError("SOCKET_ACTIVATION_REQUIRED")
    if environ is None:
        # Not inherited by anything this process might start.
        for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            os.environ.pop(name, None)
    return listener


def effective_capabilities(proc_self: str = "/proc/self") -> int:
    for line in _read_proc(os.path.join(proc_self, "status"), limit=65536).splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16)
    raise ValueError("CAPABILITIES_UNKNOWN")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ServerSentinel listener socket-owner helper (Issue #126)")
    parser.add_argument("--config", required=True, help="administrator-owned deployment configuration")
    arguments = parser.parse_args(argv)
    try:
        service_uid = read_service_uid(arguments.config)
        listener = systemd_listener()
    except (OSError, ValueError) as error:
        code = str(error) if re.fullmatch(r"[A-Z_]{1,64}", str(error)) else "STARTUP_FAILED"
        _audit_stderr("startup_failed", code=code)
        return 1
    if service_uid == os.geteuid():
        _audit_stderr("startup_failed", code="HELPER_RUNS_AS_SERVICE_ACCOUNT")
        return 1
    try:
        missing = REQUIRED_CAPABILITIES & ~effective_capabilities()
    except (OSError, ValueError):
        missing = REQUIRED_CAPABILITIES
    # Without them every scan is incomplete and answers OWNERS_UNAVAILABLE (fail closed).
    _audit_stderr("started", capabilities="complete" if not missing else "missing")
    SocketOwnerHelper(service_uid).serve(listener)
    return 0


if __name__ == "__main__":
    sys.exit(main())
