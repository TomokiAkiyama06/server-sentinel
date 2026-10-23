"""Which UVC session markers the running service issued in its current run (Issue #317).

``ApprovalStore.start_session`` arms a fresh ``uuid4`` session marker in
``uvc_approvals.session_token`` for every session it starts. A crash leaves
the marker behind, and the next start turns it into "approval required". The
local administration command (``admin_cli sources``) must tell such a left
marker from one the running service armed in its current run, also while the
restarted service has not (yet) started local UVC capture: the database is
then held by a live service process, but the marker is still the crashed
run's.

The service therefore records, in this ledger, the markers it issued and has
not released in its current run, together with the identity of the process
that wrote it. The command trusts the ledger only while that very process is
still alive and holds the database; any other ledger is stale (left by an
earlier process, or by an earlier boot) and every marker it would vouch for
is a left one.

The file. ``uvc-session-ledger.json`` next to the database, in the service's
private state directory on the approved runtime filesystem (``Deployment``
validates that directory as owned by the service account, mode ``0700``). It
is mode ``0600``, owned by the service account, with one link, and replaced
atomically (staging file in the same directory, ``rename``), so a reader sees
either the previous or the next complete version. It holds:

- ``boot_id`` (``/proc/sys/kernel/random/boot_id``), ``pid`` and
  ``start_time`` (field 22 of ``/proc/<pid>/stat``, clock ticks since boot)
  of the writing process. A PID is reused, but not together with the same
  start time in the same boot, so the triple names one process instance;
- per source UUID, at most ``MAX_DIGESTS_PER_SOURCE`` SHA-256 digests of
  session markers (domain-separated), never the markers themselves. A
  marker is an unguessable ``uuid4`` with no meaning outside this database,
  so the digest reveals nothing; it is enough to compare.

There is no schema change and the ledger is never a source of approval: the
service never reads it back, and ``sources`` can only show *fewer* sources
as ``approved_in_use`` because of it (a missing or stale ledger shows
``approval_required``). Writes are made under the same storage admission as
the marker itself (``ApprovalStore``).

Best effort (Owner decision 2026-10-23). The ledger only serves a display,
so a publication that fails never stops a session: ``issue`` keeps the
digest in this process's entries (and still raises, for the caller to log)
and the next successful publication includes it; ``pending`` stays set
until then, and the source polls retry it (``ApprovalStore.retry_ledger``,
at most every ``RETRY_SECONDS``). Until then the file lacks it and
``sources`` shows the marker as ``approval_required``, never a false
``approved_in_use``. A release drops its digest from the entries before
its storage admission (``forget``) and removes the file (``discard``) when
the admission is refused.

Bounds. The writer keeps at most ``MAX_SOURCES`` sources of
``MAX_DIGESTS_PER_SOURCE`` digests each, the bounds the reader enforces, and
``MAX_LEDGER_BYTES`` is derived from them (the largest file they allow), so
the writer never produces a file the reader refuses.

Ordering. A marker's digest is published *before* the marker is committed to
the database, and withdrawn *before* the marker is cleared (or the file is
removed if that withdrawal cannot be published), so a listed digest matches
a database marker only while the current run holds it, and every marker it
holds is listed once a publication succeeds (best effort, above). A digest of
a marker that never committed, or one that was later superseded, matches no
row and is harmless. The command reads the database first and the ledger
after it.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Callable, Mapping
from uuid import UUID


LEDGER_NAME = "uvc-session-ledger.json"
FORMAT = "serversentinel-uvc-session-ledger-v1"
# Supervisors start at most one session per source at a time, and every start
# supersedes the previous marker; keeping the last few covers an overlap.
MAX_DIGESTS_PER_SOURCE = 4
MAX_SOURCES = 64
# A failed publication is retried by the source workers' polls, at most this
# often (``SessionLedger.retry_due``).
RETRY_SECONDS = 30.0
_DOMAIN = b"serversentinel-uvc-session-marker-v1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STAGING = re.compile(re.escape(f".{LEDGER_NAME}.") + r"[0-9a-f]{16}\.tmp")
_KEYS = {"format", "boot_id", "pid", "start_time", "sessions"}


class SessionLedgerError(RuntimeError):
    """A fixed safe error, without paths, process details or file contents."""


def ledger_path(database_path: Path) -> Path:
    """The ledger of the database at ``database_path`` (the same directory)."""
    return Path(database_path).with_name(LEDGER_NAME)


def marker_digest(session_token: str) -> str:
    """The digest the ledger stores for one session marker."""
    if not isinstance(session_token, str) or not session_token.isascii():
        raise SessionLedgerError("UVC session marker is invalid")
    return hashlib.sha256(_DOMAIN + session_token.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class ProcessIdentity:
    boot_id: str
    pid: int
    start_time: int


def boot_id(proc_root: Path = Path("/proc")) -> str:
    """This boot's identity; refuses when it cannot be read."""
    try:
        with open(proc_root / "sys/kernel/random/boot_id", "rb") as stream:
            value = stream.read(64).decode("ascii").strip()
    except (OSError, UnicodeError):
        raise SessionLedgerError("boot identity is unavailable") from None
    if not _BOOT_ID.fullmatch(value):
        raise SessionLedgerError("boot identity is unavailable")
    return value


def process_start_time(pid: int, proc_root: Path = Path("/proc")) -> int | None:
    """Field 22 of ``/proc/<pid>/stat``, or ``None`` if the process is gone.

    The command name (field 2) may contain spaces and parentheses, so the
    fields are counted after its last ``)``.
    """
    try:
        with open(proc_root / str(pid) / "stat", "rb") as stream:
            text = stream.read(4096).decode("ascii", "replace")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError:
        raise SessionLedgerError("process state is unavailable") from None
    fields = text.rpartition(")")[2].split()
    # fields[0] is field 3 (state), so field 22 is fields[19].
    if len(fields) < 20 or not fields[19].isdecimal():
        raise SessionLedgerError("process state is unavailable")
    return int(fields[19])


def current_process_identity(proc_root: Path = Path("/proc")) -> ProcessIdentity:
    pid = os.getpid()
    start = process_start_time(pid, proc_root)
    if start is None:
        raise SessionLedgerError("process state is unavailable")
    return ProcessIdentity(boot_id(proc_root), pid, start)


def _encode(identity: ProcessIdentity, sessions: Mapping[str, list[str]]) -> bytes:
    return json.dumps({
        "format": FORMAT, "boot_id": identity.boot_id, "pid": identity.pid,
        "start_time": identity.start_time,
        "sessions": {source: sorted(digests) for source, digests in sorted(sessions.items())},
    }, sort_keys=True, separators=(",", ":")).encode("ascii")


# The largest file the writer's bounds allow: the widest identity (a 64-bit
# PID and start time; the kernel's are smaller) and every source holding the
# most digests.
MAX_LEDGER_BYTES = len(_encode(
    ProcessIdentity("0" * 36, 2 ** 64 - 1, 2 ** 64 - 1),
    {str(UUID(int=number)): ["0" * 64] * MAX_DIGESTS_PER_SOURCE for number in range(MAX_SOURCES)}))


@dataclass(frozen=True)
class LedgerContents:
    writer: ProcessIdentity
    sessions: Mapping[str, frozenset[str]]


def _parse(content: bytes) -> LedgerContents:
    try:
        value = json.loads(content.decode("ascii"))
    except (UnicodeError, ValueError):
        raise SessionLedgerError("UVC session ledger is malformed") from None
    if (not isinstance(value, dict) or set(value) != _KEYS or value["format"] != FORMAT
            or not isinstance(value["boot_id"], str) or not _BOOT_ID.fullmatch(value["boot_id"])
            or type(value["pid"]) is not int or value["pid"] <= 0
            or type(value["start_time"]) is not int or value["start_time"] < 0
            or not isinstance(value["sessions"], dict) or len(value["sessions"]) > MAX_SOURCES):
        raise SessionLedgerError("UVC session ledger is malformed")
    sessions = {}
    for source, digests in value["sessions"].items():
        try:
            canonical = str(UUID(source)) == source
        except (TypeError, ValueError):
            canonical = False
        if (not canonical or not isinstance(digests, list)
                or len(digests) > MAX_DIGESTS_PER_SOURCE
                or not all(isinstance(item, str) and _DIGEST.fullmatch(item) for item in digests)):
            raise SessionLedgerError("UVC session ledger is malformed")
        sessions[source] = frozenset(digests)
    return LedgerContents(ProcessIdentity(value["boot_id"], value["pid"], value["start_time"]),
                          sessions)


def read_ledger(path: Path, *, account: int) -> LedgerContents | None:
    """The ledger at ``path``, or ``None`` when there is none.

    Refuses (``SessionLedgerError``) a ledger that cannot be read or that is
    not a private regular file of ``account`` with one link (a symbolic
    link, a group- or world-accessible file, another account's file), and a
    malformed one: the caller must not guess either way then.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise SessionLedgerError("UVC session ledger is unavailable") from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != account or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_LEDGER_BYTES):
            raise SessionLedgerError("UVC session ledger failed ownership checks")
        content = b""
        while len(content) <= MAX_LEDGER_BYTES:
            chunk = os.read(descriptor, MAX_LEDGER_BYTES + 1 - len(content))
            if not chunk:
                break
            content += chunk
    except OSError:
        raise SessionLedgerError("UVC session ledger is unavailable") from None
    finally:
        os.close(descriptor)
    if len(content) > MAX_LEDGER_BYTES:
        raise SessionLedgerError("UVC session ledger is malformed")
    return _parse(content)


class SessionLedger:
    """The service side: publishes the markers this process issued and holds.

    One instance per ledger file and process (``for_database``), shared by
    every ``ApprovalStore`` of that database, so two adapters of one process
    never overwrite each other's entries. Thread-safe. ``identity`` is read
    from ``/proc`` on the first publication unless given.
    """

    _instances: dict[Path, "SessionLedger"] = {}
    _instances_lock = threading.Lock()

    def __init__(self, path: Path, *,
                 identity: Callable[[], ProcessIdentity] = current_process_identity):
        path = Path(path)
        if not path.is_absolute() or path.name != LEDGER_NAME:
            raise SessionLedgerError("UVC session ledger location is invalid")
        self.path = path
        self._identity_source = identity
        self._identity: ProcessIdentity | None = None
        self._sessions: dict[str, list[str]] = {}
        self._lock = threading.Lock()
        self._swept = False
        # Set when the file may lack (or still list) an entry, cleared by a
        # successful publication; ``retry`` republishes it.
        self._pending = False
        self._retried_at: float | None = None

    @classmethod
    def for_database(cls, database) -> "SessionLedger":
        path = ledger_path(database.path)
        with cls._instances_lock:
            ledger = cls._instances.get(path)
            if ledger is None:
                ledger = cls._instances[path] = cls(path)
            return ledger

    def issue(self, source_id, session_token: str) -> None:
        """Publish a marker before it is committed.

        Raises ``SessionLedgerError`` when it cannot be published, for the
        caller to log; the session goes on (best effort). The digest is kept
        in this process's entries all the same, so the next successful
        publication includes it; until then ``sources`` shows the marker as
        ``approval_required``. A new source beyond ``MAX_SOURCES`` is not
        recorded at all (the same display), so the file stays readable.
        """
        source, digest = str(source_id), marker_digest(session_token)
        with self._lock:
            previous = self._sessions.get(source)
            if previous is None and len(self._sessions) >= MAX_SOURCES:
                raise SessionLedgerError("UVC session ledger is full")
            digests = [item for item in previous or () if item != digest] + [digest]
            self._sessions[source] = digests[-MAX_DIGESTS_PER_SOURCE:]
            self._pending = True
            self._publish()

    def withdraw(self, source_id, session_token: str) -> None:
        """Drop a marker before it is cleared (or after it failed to commit).

        Best effort: a digest that stays published matches no marker once
        the marker is cleared or superseded. If the publication fails, the
        ledger file is removed instead where that still works, because the
        marker's release may fail too and leave the marker in the database:
        until the next successful publication every marker then shows as
        ``approval_required``, never a false ``approved_in_use``.
        """
        with self._lock:
            self._forget(source_id, session_token)
            try:
                self._publish()
            except SessionLedgerError:
                self._discard()

    def forget(self, source_id, session_token: str) -> None:
        """Drop a marker from this process's entries only, without writing.

        For a caller that cannot write yet (``ApprovalStore.save`` before its
        storage admission): the digest can then never be published again,
        and the next publication (or ``discard``) removes it from the file.
        """
        with self._lock:
            self._forget(source_id, session_token)

    def discard(self) -> None:
        """Remove the ledger file (no space needed); it vouches for nothing until republished."""
        with self._lock:
            self._discard()

    @property
    def pending(self) -> bool:
        """Whether the file may differ from this process's entries."""
        return self._pending

    def retry_due(self, now: float) -> bool:
        """Whether a pending publication should be retried now (at most every ``RETRY_SECONDS``)."""
        with self._lock:
            if not self._pending:
                return False
            if self._retried_at is not None and now - self._retried_at < RETRY_SECONDS:
                return False
            self._retried_at = now
            return True

    def retry(self) -> bool:
        """Publish a pending state again; whether the file is now up to date. Never raises."""
        with self._lock:
            if not self._pending:
                return True
            try:
                self._publish()
            except SessionLedgerError:
                return False
            return True

    def _forget(self, source_id, session_token: str) -> None:
        source, digest = str(source_id), marker_digest(session_token)
        digests = [item for item in self._sessions.get(source, ()) if item != digest]
        if digests:
            self._sessions[source] = digests
        else:
            self._sessions.pop(source, None)
        self._pending = True

    def _discard(self) -> None:
        self._pending = True
        try:
            directory = os.open(self.path.parent,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return
        try:
            os.unlink(LEDGER_NAME, dir_fd=directory)
        except OSError:
            pass
        finally:
            os.close(directory)

    def _publish(self) -> None:
        """Atomically replace the ledger with this process's current entries."""
        try:
            if self._identity is None:
                self._identity = self._identity_source()
            identity = self._identity
            content = _encode(identity, self._sessions)
        except SessionLedgerError:
            raise
        except Exception:
            raise SessionLedgerError("UVC session ledger could not be written") from None
        if len(self._sessions) > MAX_SOURCES or len(content) > MAX_LEDGER_BYTES:
            # Unreachable within the bounds ``issue`` keeps; never write a
            # file the reader would refuse.
            raise SessionLedgerError("UVC session ledger could not be written")
        try:
            directory = os.open(self.path.parent,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise SessionLedgerError("UVC session ledger could not be written") from None
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise SessionLedgerError("UVC session ledger could not be written")
            if not self._swept:
                self._sweep(directory)
                self._swept = True
            staging = f".{LEDGER_NAME}.{secrets.token_hex(8)}.tmp"
            descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                 | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                try:
                    os.fchmod(descriptor, 0o600)
                    written = 0
                    while written < len(content):
                        written += os.write(descriptor, content[written:])
                    # A torn file after a power loss would make every later
                    # listing refuse until the next publication; a complete
                    # one of the previous boot is merely stale.
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.replace(staging, LEDGER_NAME, src_dir_fd=directory, dst_dir_fd=directory)
                self._pending = False
            except BaseException:
                try:
                    os.unlink(staging, dir_fd=directory)
                except OSError:
                    pass
                raise
        except SessionLedgerError:
            raise
        except OSError:
            raise SessionLedgerError("UVC session ledger could not be written") from None
        finally:
            os.close(directory)

    @staticmethod
    def _sweep(directory: int) -> None:
        """Remove staging files a crashed process left (regular files only)."""
        for entry in os.listdir(directory):
            if not _STAGING.fullmatch(entry):
                continue
            try:
                info = os.stat(entry, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                    os.unlink(entry, dir_fd=directory)
            except FileNotFoundError:
                pass
