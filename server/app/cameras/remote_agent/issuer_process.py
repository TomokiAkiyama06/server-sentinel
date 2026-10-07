"""CA-account issuer process for the local pairing CLI (ADR-0006, Issue #109).

The deployment CA private key is only ever loaded by a short-lived child
process running as the static system account ``serversentinel-ca``. The
administrative commands that need a signature (``init``, ``rotate-listener``,
``approve``) and ``revoke`` start as root (``sudo serversentinel-pairing ...``)
and, before any thread exists:

1. fork the CA child. The child starts a new session (no controlling
   terminal), closes every descriptor except its two pipe ends, points
   stdin/stdout/stderr at ``/dev/null``, drops to the CA account with
   ``setgroups([])``, ``setresgid`` and ``setresuid``, sets
   ``PR_SET_NO_NEW_PRIVS``, ``PR_SET_DUMPABLE=0`` and a parent-death signal,
   verifies the drop (all uids/gids, no supplementary group, no capability)
   and only then opens the CA directory. It never holds the terminal or a
   database descriptor;
2. the parent drops to the service account in the same way (it owns the
   application database and the Main listener directory) before it opens
   the database or the Agent's request file.

Parent and child talk over two pipes with length-prefixed JSON frames. The
child answers ``hello`` with the public CA certificate and then performs at
most one state-changing operation (sign one node leaf, sign one listener
leaf, create the CA, or record one revocation) and exits. Every signature and
every revocation is appended (fsync) to the CA-only issuance log
(``issuance-log.jsonl`` in the CA directory, 0600, CA account) before the
certificate is returned; when the log cannot be written nothing is signed.
The child decides with that log and the certificate chain, never with the
application ledger: it refuses a node recorded as revoked and a key recorded
for another node.

The parent verifies every returned certificate against the public CA
certificate before using it. Any child failure (refusal, crash, malformed
frame, non-zero exit, deadline) is ``issuer_unavailable`` for the caller.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import ctypes
import datetime
import hmac
import json
import os
from pathlib import Path
import select
import signal
import struct
import threading
import time
from typing import Callable, Protocol
from uuid import UUID

from .node_ca import (
    DEFAULT_NODE_VALIDITY, MAX_CA_VALIDITY, MAX_LEAF_VALIDITY, CaptureAuthorityError,
    DeploymentAuthority, IssuanceLogUnavailable, IssuerRefusedRequest, PrivateDirectory,
    _CA_CERTIFICATE, _CA_KEY, _certificate_pem, _single_server_name, certificate_digest,
    deployment_id_of, public_key_digest, valid_server_name,
)


ISSUANCE_LOG = "issuance-log.jsonl"
ISSUANCE_LOG_FORMAT = 1
# Bounded so a damaged or hostile log cannot exhaust the issuer's memory; at
# a few hundred bytes per record this is tens of thousands of issuances.
MAX_ISSUANCE_LOG_BYTES = 8 * 1024 * 1024
MAX_FRAME_BYTES = 64 * 1024
FRAME_HEADER = struct.Struct(">I")
# The CA child exits by itself after this long, whatever the parent does
# (for example an Owner who never answers the APPROVE prompt).
CHILD_LIFETIME_SECONDS = 15 * 60
# How long the parent waits for one child answer and for the child to exit.
REPLY_TIMEOUT_SECONDS = 60.0
EXIT_TIMEOUT_SECONDS = 10.0
DEFAULT_CA_ACCOUNT = "serversentinel-ca"
DEFAULT_SERVICE_ACCOUNT = "server-sentinel"

_PR_SET_PDEATHSIG = 1
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39


class IssuerUnavailable(CaptureAuthorityError):
    """The CA-account issuer failed or its answer did not verify; nothing is shown."""

    reason = "issuer_unavailable"
    detail: str | None = None


class PrivilegeSeparationError(CaptureAuthorityError):
    """The account split could not be established; the command aborts first."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Account:
    """A resolved OS account: numeric uid and primary gid only."""

    uid: int
    gid: int


# ---------------------------------------------------------------------------
# Privileges


def _prctl(option: int, argument: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(ctypes.c_int(option), ctypes.c_ulong(argument), ctypes.c_ulong(0),
                        ctypes.c_ulong(0), ctypes.c_ulong(0))
    if result < 0:
        raise OSError(ctypes.get_errno(), "prctl failed")
    return result


def _status_mask(field: bytes) -> int | None:
    try:
        with open("/proc/self/status", "rb") as status:
            for line in status:
                if line.startswith(field + b":"):
                    return int(line.split(b":", 1)[1].strip(), 16)
    except (OSError, ValueError):
        return None
    return None


class Privileges(Protocol):
    """Seam for the root start and the two account drops (fakes in tests)."""

    def require_start(self) -> None:
        ...

    def account(self, name: str) -> Account:
        ...

    def check_accounts(self, ca: Account, service: Account) -> None:
        ...

    def drop(self, account: Account) -> None:
        ...

    def harden_child(self) -> None:
        ...

    def require_ca_directory_closed(self, path: Path) -> None:
        ...


class OsPrivileges:
    """The real root start, account drop and post-drop verification."""

    def require_start(self) -> None:
        if os.getresuid() != (0, 0, 0):
            raise PrivilegeSeparationError("privilege_separation_requires_root")

    def account(self, name: str) -> Account:
        import pwd
        try:
            if isinstance(name, str) and name.isascii() and name.isdecimal():
                entry = pwd.getpwuid(int(name))
            else:
                entry = pwd.getpwnam(name)
        except (KeyError, ValueError, OverflowError, TypeError):
            raise PrivilegeSeparationError("account_unknown") from None
        return Account(entry.pw_uid, entry.pw_gid)

    def check_accounts(self, ca: Account, service: Account) -> None:
        if 0 in (ca.uid, ca.gid, service.uid, service.gid):
            raise PrivilegeSeparationError("account_must_not_be_root")
        if ca.uid == service.uid or ca.gid == service.gid:
            raise PrivilegeSeparationError("ca_account_must_differ_from_service_account")

    def drop(self, account: Account) -> None:
        try:
            os.setgroups([])
            os.setresgid(account.gid, account.gid, account.gid)
            os.setresuid(account.uid, account.uid, account.uid)
            _prctl(_PR_SET_NO_NEW_PRIVS, 1)
            _prctl(_PR_SET_DUMPABLE, 0)
        except OSError:
            raise PrivilegeSeparationError("privilege_drop_failed") from None
        verify_dropped(account)

    def harden_child(self) -> None:
        parent = os.getppid()
        try:
            _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        except OSError:
            raise PrivilegeSeparationError("privilege_drop_failed") from None
        if os.getppid() != parent:
            raise PrivilegeSeparationError("privilege_drop_failed")

    def require_ca_directory_closed(self, path: Path) -> None:
        """After the drop the service account must not be able to open the CA directory.

        A CA directory that does not exist (as seen by this unprivileged
        process) holds no CA material to expose, so it is not refused here:
        ``revoke`` must still revoke in the ledger when the CA directory was
        lost (the CA child then reports it unavailable on its own).
        """
        if ca_directory_exposed(path):
            raise PrivilegeSeparationError("ca_directory_exposed")


def verify_dropped(account: Account) -> None:
    """Abort unless this process is exactly ``account`` with no capability left."""
    effective = _status_mask(b"CapEff")
    permitted = _status_mask(b"CapPrm")
    try:
        dumpable = _prctl(_PR_GET_DUMPABLE)
        no_new_privs = _prctl(_PR_GET_NO_NEW_PRIVS)
    except OSError:
        raise PrivilegeSeparationError("privilege_drop_failed") from None
    if (os.getresuid() != (account.uid,) * 3 or os.getresgid() != (account.gid,) * 3
            or os.getgroups() not in ([], [account.gid]) or os.geteuid() == 0
            or effective != 0 or permitted != 0 or dumpable != 0 or no_new_privs != 1):
        raise PrivilegeSeparationError("privilege_drop_failed")


def ca_directory_accessible(path: Path) -> bool:
    """Whether this process can open the CA directory or its key (fail closed).

    The same probe the application launcher runs at start (``app.deployment``).
    """
    from app.deployment import capture_ca_directory_accessible
    return capture_ca_directory_accessible(Path(path))


def ca_directory_exposed(path: Path) -> bool:
    """Whether CA material at ``path`` is reachable by this (dropped) process.

    Unlike the launcher's ``ca_directory_accessible``, a missing directory is
    not exposure: ``ENOENT``/``ENOTDIR`` -- the path or one of its parents
    does not exist, which this process can only learn because it may search
    every existing parent -- means there is nothing there to read. A
    permission refusal is closed. Anything else (an openable directory or key,
    a symbolic link, any other error) counts as exposed (fail closed).
    """
    import errno
    for target, flags in ((Path(path), os.O_RDONLY | os.O_DIRECTORY),
                          (Path(path) / _CA_KEY, os.O_RDONLY | os.O_NONBLOCK)):
        try:
            descriptor = os.open(target, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
        except PermissionError:
            continue
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ENOTDIR):
                continue
            return True
        os.close(descriptor)
        return True
    return False


# ---------------------------------------------------------------------------
# Frames


def write_frame(descriptor: int, message: dict) -> None:
    body = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(body) > MAX_FRAME_BYTES:
        raise IssuerUnavailable("issuer frame is too large")
    data = memoryview(FRAME_HEADER.pack(len(body)) + body)
    try:
        while data:
            written = os.write(descriptor, data)
            if written <= 0:
                raise OSError("short write")
            data = data[written:]
    except OSError:
        raise IssuerUnavailable("issuer channel failed") from None


def _read_exact(descriptor: int, size: int, deadline: float | None) -> bytes | None:
    chunks = []
    remaining = size
    while remaining:
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise IssuerUnavailable("issuer did not answer in time")
            try:
                ready, _, _ = select.select([descriptor], [], [], left)
            except (OSError, ValueError):
                raise IssuerUnavailable("issuer channel failed") from None
            if not ready:
                continue
        try:
            chunk = os.read(descriptor, min(remaining, 65536))
        except OSError:
            raise IssuerUnavailable("issuer channel failed") from None
        if not chunk:
            if remaining == size:
                return None
            raise IssuerUnavailable("issuer channel closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(descriptor: int, *, timeout: float | None = None) -> dict | None:
    """One frame, or ``None`` on a clean end of stream before a header."""
    deadline = None if timeout is None else time.monotonic() + timeout
    header = _read_exact(descriptor, FRAME_HEADER.size, deadline)
    if header is None:
        return None
    (length,) = FRAME_HEADER.unpack(header)
    if not 0 < length <= MAX_FRAME_BYTES:
        raise IssuerUnavailable("issuer frame is invalid")
    body = _read_exact(descriptor, length, deadline)
    if body is None:
        raise IssuerUnavailable("issuer channel closed mid-frame")
    try:
        value = json.loads(body.decode("ascii"))
    except (UnicodeError, ValueError, RecursionError):
        raise IssuerUnavailable("issuer frame is invalid") from None
    if not isinstance(value, dict):
        raise IssuerUnavailable("issuer frame is invalid")
    return value


# ---------------------------------------------------------------------------
# CA-only issuance log


def _now_text(clock: Callable[[], datetime.datetime]) -> str:
    return clock().astimezone(datetime.timezone.utc).isoformat(timespec="seconds")


class IssuanceLog:
    """Append-only, CA-account-only record of every issuance and revocation.

    One JSON object per line with ``format``, ``type`` and fixed fields:
    ``deployment_ca`` (``deployment_id``, ``credential_digest``,
    ``not_after``), ``listener`` (``server_name``, ``public_key_digest``,
    ``credential_digest``, ``not_after``), ``node`` (``node_id``,
    ``public_key_digest``, ``credential_digest``, ``not_after``) and
    ``node_revocation`` (``node_id``). Every record carries ``at`` (UTC).
    Public digests and UUIDs only: no key, CSR, code or certificate body.
    A record that does not parse makes the whole log invalid, and the issuer
    then refuses to sign (fail closed).
    """

    def __init__(self, directory: PrivateDirectory, *,
                 clock: Callable[[], datetime.datetime]):
        self._directory = directory
        self._clock = clock

    def records(self) -> list[dict]:
        try:
            content = self._directory.read_optional(ISSUANCE_LOG, maximum=MAX_ISSUANCE_LOG_BYTES)
        except CaptureAuthorityError:
            raise IssuanceLogUnavailable("issuer log is unavailable") from None
        if content is None:
            return []
        if not content.endswith(b"\n"):
            raise IssuanceLogUnavailable("issuer log is invalid")
        records = []
        for line in content.split(b"\n")[:-1]:
            try:
                value = json.loads(line.decode("ascii"))
            except (UnicodeError, ValueError, RecursionError):
                raise IssuanceLogUnavailable("issuer log is invalid") from None
            if (not isinstance(value, dict) or value.get("format") != ISSUANCE_LOG_FORMAT
                    or value.get("type") not in ("deployment_ca", "listener", "node",
                                                 "node_revocation")):
                raise IssuanceLogUnavailable("issuer log is invalid")
            if value["type"] in ("node", "node_revocation"):
                try:
                    if str(UUID(value["node_id"])) != value["node_id"]:
                        raise ValueError
                except (KeyError, TypeError, ValueError, AttributeError):
                    raise IssuanceLogUnavailable("issuer log is invalid") from None
            if value["type"] == "node" and not isinstance(value.get("public_key_digest"), str):
                raise IssuanceLogUnavailable("issuer log is invalid")
            records.append(value)
        return records

    def append(self, record: dict) -> None:
        line = json.dumps({"format": ISSUANCE_LOG_FORMAT, "at": _now_text(self._clock), **record},
                          sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        self._directory.append(ISSUANCE_LOG, line, maximum=MAX_ISSUANCE_LOG_BYTES)

    def require_node_eligible(self, node_id: UUID, key_digest: str) -> None:
        """Refuse a node revoked in this log, or a key bound to another or a revoked node."""
        node = str(node_id)
        records = self.records()
        revoked = {record["node_id"] for record in records if record["type"] == "node_revocation"}
        if node in revoked:
            raise IssuerRefusedRequest("node is revoked at the issuer")
        for record in records:
            if (record["type"] == "node"
                    and hmac.compare_digest(record["public_key_digest"], key_digest)
                    and (record["node_id"] != node or record["node_id"] in revoked)):
                raise IssuerRefusedRequest("key is bound to another node at the issuer")


# ---------------------------------------------------------------------------
# CA side


def _uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise IssuerRefusedRequest("issuer request is invalid")
    try:
        parsed = UUID(value)
    except ValueError:
        raise IssuerRefusedRequest("issuer request is invalid") from None
    if str(parsed) != value:
        raise IssuerRefusedRequest("issuer request is invalid")
    return parsed


def _text(value: object, *, maximum: int = MAX_FRAME_BYTES) -> bytes:
    if not isinstance(value, str) or not value.isascii() or not 0 < len(value) <= maximum:
        raise IssuerRefusedRequest("issuer request is invalid")
    return value.encode("ascii")


def _days(value: object, maximum: datetime.timedelta) -> datetime.timedelta:
    if type(value) is not int or not 0 < value <= maximum.days:
        raise IssuerRefusedRequest("issuer request is invalid")
    return datetime.timedelta(days=value)


def _digest(value: object) -> str:
    if (not isinstance(value, str) or len(value) != 64 or value != value.lower()
            or any(character not in "0123456789abcdef" for character in value)):
        raise IssuerRefusedRequest("issuer request is invalid")
    return value


class CaIssuer:
    """The CA child's request handler; holds the CA key, decides from its own log.

    ``hello`` loads and validates the CA (key and certificate) and returns
    only the public certificate. Afterwards exactly one of ``sign_node``,
    ``sign_listener`` or ``revoke`` is accepted, then the issuer is done.
    ``initialize`` (only as the first request) creates the CA and signs the
    first listener leaf; the CA files stay provisional until ``commit``, and
    ``abort`` or a lost parent removes exactly the files this run created.
    """

    def __init__(self, directory: PrivateDirectory, *,
                 clock: Callable[[], datetime.datetime] | None = None):
        self._directory = directory
        self._clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self._log = IssuanceLog(directory, clock=self._clock)
        self._authority: DeploymentAuthority | None = None
        self._resources = ExitStack()
        self._provisional = False
        self.done = False

    def handle(self, message: object) -> dict:
        try:
            if self.done or not isinstance(message, dict):
                raise IssuerRefusedRequest("issuer request is invalid")
            operation = message.get("op")
            if operation == "hello":
                return self._hello()
            if operation == "initialize":
                return self._initialize(message)
            if operation == "commit":
                return self._finish(commit=True)
            if operation == "abort":
                return self._finish(commit=False)
            if self._authority is None or self._provisional:
                raise IssuerRefusedRequest("issuer request is invalid")
            if operation == "sign_node":
                return self._sign_node(message)
            if operation == "sign_listener":
                return self._sign_listener(message)
            if operation == "revoke":
                return self._revoke(message)
            raise IssuerRefusedRequest("issuer request is invalid")
        except CaptureAuthorityError as error:
            if not self._provisional:
                self.done = True
            return {"status": "refused", "reason": error.reason}
        except Exception:
            if not self._provisional:
                self.done = True
            return {"status": "refused", "reason": IssuerUnavailable.reason}

    def _hello(self) -> dict:
        if self._authority is not None:
            raise IssuerRefusedRequest("issuer request is invalid")
        deployment = deployment_id_of(self._directory)
        self._authority = DeploymentAuthority.load(self._directory, deployment, clock=self._clock)
        # A damaged log is reported now, before any Owner prompt.
        self._log.records()
        return {"status": "ok", "ca_certificate": self._authority.ca_certificate_pem().decode("ascii"),
                "deployment_id": str(deployment)}

    def _sign_node(self, message: dict) -> dict:
        node = _uuid(message.get("node_id"))
        approved = _digest(message.get("public_key_digest"))
        csr = _text(message.get("csr"))
        self._log.require_node_eligible(node, approved)
        issued = self._authority.issue_approved_node_certificate(
            node, csr, approved, validity=DEFAULT_NODE_VALIDITY)
        self._log.append({"type": "node", "node_id": str(node),
                          "public_key_digest": issued.public_key_digest,
                          "credential_digest": issued.credential_digest,
                          "not_after": issued.not_after.isoformat(timespec="seconds")})
        self.done = True
        return {"status": "ok", "certificate": issued.certificate_pem.decode("ascii")}

    def _sign_listener(self, message: dict) -> dict:
        certificate = self._authority.sign_listener_request(
            _text(message.get("csr")), server_name=self._server_name(message),
            validity=_days(message.get("validity_days"), MAX_LEAF_VALIDITY))
        self._record_listener(certificate)
        self.done = True
        return {"status": "ok", "certificate": _certificate_pem(certificate).decode("ascii")}

    @staticmethod
    def _server_name(message: dict) -> str:
        name = message.get("server_name")
        if not valid_server_name(name):
            raise IssuerRefusedRequest("issuer request is invalid")
        return name

    def _record_listener(self, certificate) -> None:
        self._log.append({"type": "listener",
                          "server_name": _single_server_name(certificate),
                          "public_key_digest": public_key_digest(certificate.public_key()),
                          "credential_digest": certificate_digest(certificate),
                          "not_after": certificate.not_valid_after_utc.isoformat(timespec="seconds")})

    def _revoke(self, message: dict) -> dict:
        node = _uuid(message.get("node_id"))
        self._log.records()
        self._log.append({"type": "node_revocation", "node_id": str(node)})
        self.done = True
        return {"status": "ok"}

    def _initialize(self, message: dict) -> dict:
        if self._authority is not None or self._provisional:
            raise IssuerRefusedRequest("issuer request is invalid")
        csr = _text(message.get("csr"))
        server_name = self._server_name(message)
        ca_validity = _days(message.get("ca_validity_days"), MAX_CA_VALIDITY)
        server_validity = _days(message.get("server_validity_days"), MAX_LEAF_VALIDITY)
        deployment = _uuid(message.get("deployment_id"))
        self._directory.ensure()
        self._resources.enter_context(self._directory.locked())
        if any(self._directory.exists(name) for name in (_CA_KEY, _CA_CERTIFICATE)):
            return self._initialize_existing(csr, server_name, server_validity)
        if self._directory.exists(ISSUANCE_LOG):
            raise CaptureAuthorityError("issuer material already exists")
        self._provisional = True
        try:
            authority = DeploymentAuthority.create(self._directory, deployment,
                                                   validity=ca_validity, clock=self._clock)
            certificate = authority.sign_listener_request(csr, server_name=server_name,
                                                          validity=server_validity)
            self._log.append({"type": "deployment_ca", "deployment_id": str(deployment),
                              "credential_digest": certificate_digest(authority.certificate),
                              "not_after": authority.not_valid_after.isoformat(timespec="seconds")})
            self._record_listener(certificate)
        except BaseException:
            self._discard()
            raise
        self._authority = authority
        return {"status": "ok", "ca_certificate": authority.ca_certificate_pem().decode("ascii"),
                "certificate": _certificate_pem(certificate).decode("ascii"),
                "deployment_id": str(deployment)}

    def _initialize_existing(self, csr: bytes, server_name: str, server_validity) -> dict:
        """Recover an ``init`` whose CA already exists (Issue #109).

        For example the ``commit`` reply was lost, or the run stopped after
        the CA was committed, so the listener side removed its files. The CA
        is never replaced or removed: it must load and validate as a whole,
        and only a new listener leaf is signed for it -- for the same server
        name as the last listener this log recorded, if any. The caller sends
        this only for an empty listener directory.
        """
        deployment = deployment_id_of(self._directory)
        authority = DeploymentAuthority.load(self._directory, deployment, clock=self._clock)
        recorded = [record.get("server_name") for record in self._log.records()
                    if record["type"] == "listener"]
        if recorded and recorded[-1] != server_name:
            raise IssuerRefusedRequest("server name differs from the recorded listener")
        certificate = authority.sign_listener_request(csr, server_name=server_name,
                                                      validity=server_validity)
        self._record_listener(certificate)
        self._authority = authority
        self.done = True
        return {"status": "ok", "existing": True,
                "ca_certificate": authority.ca_certificate_pem().decode("ascii"),
                "certificate": _certificate_pem(certificate).decode("ascii"),
                "deployment_id": str(deployment)}

    def _finish(self, *, commit: bool) -> dict:
        if not self._provisional:
            raise IssuerRefusedRequest("issuer request is invalid")
        if not commit:
            self._discard()
        self._provisional = False
        self.done = True
        return {"status": "ok"}

    def _discard(self) -> None:
        for name in (ISSUANCE_LOG, _CA_CERTIFICATE, _CA_KEY):
            try:
                self._directory.discard_created(name)
            except CaptureAuthorityError:
                pass
        self._provisional = False
        self.done = True

    def close(self) -> None:
        """End of the conversation: a CA never committed is removed."""
        if self._provisional:
            self._discard()
        self._authority = None
        self._resources.close()
        self.done = True


# ---------------------------------------------------------------------------
# Parent side


class IssuerChannel(Protocol):
    def request(self, message: dict) -> dict:
        ...

    def finish(self) -> None:
        ...

    def close(self) -> None:
        ...


def checked_reply(channel: IssuerChannel, message: dict) -> dict:
    """Send one request; a refusal or broken channel raises a fixed reason.

    The issuer's own refusal word (always a fixed ``CaptureAuthorityError``
    reason) is kept as ``detail``; the reason is ``issuer_unavailable``
    except for the refusals an Owner acts on directly.
    """
    reply = channel.request(message)
    if isinstance(reply, dict) and reply.get("status") == "ok":
        return reply
    reason = reply.get("reason") if isinstance(reply, dict) else None
    detail = (reason if isinstance(reason, str) and 0 < len(reason) <= 64 and reason.isascii()
              and reason.replace("_", "").isalpha() and reason.islower() else None)
    error = IssuerUnavailable("issuer refused the request")
    error.detail = detail
    if detail in _OWNER_ACTIONABLE:
        error.reason = detail
    raise error


# Refusals reported under their own word: the Owner fixes them differently
# from a broken issuer (busy directory, expiring CA, existing CA, log state).
_OWNER_ACTIONABLE = frozenset({
    "deployment_ca_validity_insufficient", "issuer_material_busy", "issuer_material_rejected",
    "issuance_log_unavailable", "issuer_refused_request",
})


def _isolate_descriptors(keep: set[int]) -> None:
    """Close every descriptor but ``keep``; stdin/stdout/stderr become /dev/null."""
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        names = [str(number) for number in range(3, 1024)]
    for name in names:
        number = int(name)
        if number > 2 and number not in keep:
            try:
                os.close(number)
            except OSError:
                pass
    null = os.open("/dev/null", os.O_RDWR)
    for number in (0, 1, 2):
        os.dup2(null, number)
    if null > 2:
        os.close(null)


def _child_main(requests: int, replies: int, authority_path: Path, ca: Account,
                privileges: Privileges) -> int:
    os.setsid()
    _isolate_descriptors({requests, replies})
    privileges.drop(ca)
    privileges.harden_child()
    signal.alarm(CHILD_LIFETIME_SECONDS)
    issuer = CaIssuer(PrivateDirectory(authority_path))
    try:
        while not issuer.done:
            message = read_frame(requests)
            if message is None:
                break
            write_frame(replies, issuer.handle(message))
        # After a provisional ``initialize`` the child waits for commit/abort
        # above; anything else ends the conversation here.
    finally:
        issuer.close()
    return 0


class ForkedIssuer:
    """Parent end of the CA child: two pipes and the child's pid."""

    def __init__(self, pid: int, requests: int, replies: int):
        self.pid = pid
        self._requests = requests
        self._replies = replies
        self._status: int | None = None

    @classmethod
    def start(cls, authority_path: Path, ca: Account, privileges: Privileges) -> "ForkedIssuer":
        """Fork the CA child; refused unless this process has exactly one thread."""
        if threading.active_count() != 1:
            raise IssuerUnavailable("issuer must be started before any thread")
        to_child, requests = os.pipe()
        replies, from_child = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - exercised by subprocess tests
            status = 1
            try:
                os.close(requests)
                os.close(replies)
                status = _child_main(to_child, from_child, Path(authority_path), ca, privileges)
            except BaseException:
                status = 1
            finally:
                os._exit(status)
        os.close(to_child)
        os.close(from_child)
        return cls(pid, requests, replies)

    def request(self, message: dict) -> dict:
        if self._requests < 0:
            raise IssuerUnavailable("issuer channel is closed")
        write_frame(self._requests, message)
        reply = read_frame(self._replies, timeout=REPLY_TIMEOUT_SECONDS)
        if reply is None:
            raise IssuerUnavailable("issuer exited")
        return reply

    def finish(self) -> None:
        """Close the channel and require the child to exit with status 0.

        The parent may already run as another account than the child, so it
        never signals the child: end of stream makes the child exit, and its
        own deadline bounds the rest.
        """
        self._close_pipes()
        status = self._wait(EXIT_TIMEOUT_SECONDS)
        if status != 0:
            raise IssuerUnavailable("issuer did not exit cleanly")

    def close(self) -> None:
        self._close_pipes()
        if self._status is None:
            self._wait(EXIT_TIMEOUT_SECONDS)

    def alive(self) -> bool:
        if self._status is not None:
            return False
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self._status = -1
            return False
        if pid == 0:
            return True
        self._status = os.waitstatus_to_exitcode(status)
        return False

    def _close_pipes(self) -> None:
        for name in ("_requests", "_replies"):
            descriptor = getattr(self, name)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, -1)

    def _wait(self, timeout: float) -> int | None:
        deadline = time.monotonic() + timeout
        while self.alive():
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.01)
        return self._status
