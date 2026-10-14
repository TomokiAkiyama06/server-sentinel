"""Small SQLite connection factory. Callers own connection lifetimes."""

from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
import os
import sqlite3
import stat
import threading
from urllib.parse import quote


# POSIX record locks belong to a process and an inode, not to a descriptor:
# closing *any* descriptor this process holds on a file releases every fcntl
# lock the process holds on it, including the SHARED/RESERVED/PENDING locks of
# this process's own open SQLite connections. SQLite defers its own closes for
# that reason, but a plain ``os.open`` + ``os.close`` of a database file by
# application code would silently drop those locks and let another process
# write concurrently, which can corrupt the database.
#
# Application code therefore never closes a descriptor it opened on a
# database file. Each is kept here for the life of the process and reused:
# one read-only descriptor per distinct (device, inode) this process has
# opened or created through this module, never closed, not even once the
# file is unlinked or replaced, because a connection may still be using the
# old inode. The set is bounded by the database files the process uses; a
# replaced database file costs one more descriptor and keeps the old file's
# blocks allocated until the process restarts.
_HELD_LOCK = threading.Lock()
_HELD: dict[tuple[int, int], int] = {}
# Descriptors that duplicate a held file (the path was swapped back to it
# between stat and open). They are kept open too, never read from.
_DUPLICATES: list[int] = []
_HOLD_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _adopt_locked(descriptor: int) -> tuple[int, int]:
    """Keep ``descriptor`` for the process lifetime; returns its file identity."""
    identity = _identity(os.fstat(descriptor))
    if identity in _HELD:
        _DUPLICATES.append(descriptor)
    else:
        _HELD[identity] = descriptor
    return identity


def _hold_locked(path: Path) -> tuple[int, tuple[int, int]]:
    """The held read descriptor and identity of the regular file at ``path``.

    Raises ``FileNotFoundError`` for a missing file and ``ValueError`` for
    anything else unusable. A file already held is never opened again.
    """
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError:
        raise ValueError("database location is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("database location is unavailable")
    descriptor = _HELD.get(_identity(info))
    if descriptor is not None:
        return descriptor, _identity(info)
    try:
        opened = os.open(path, _HOLD_FLAGS)
    except FileNotFoundError:
        raise
    except OSError:
        raise ValueError("database location is unavailable") from None
    identity = _adopt_locked(opened)
    descriptor = _HELD[identity]
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError("database location is unavailable")
    return descriptor, identity


def read_database_prefix(path: Path, size: int) -> bytes | None:
    """The first ``size`` bytes of the database file, or ``None`` if missing.

    Read through a held descriptor, so this process's SQLite locks on the
    file survive. Raises ``ValueError`` when the location is unusable.
    """
    with _HELD_LOCK:
        try:
            descriptor, _held_identity = _hold_locked(path)
        except FileNotFoundError:
            return None
    try:
        return os.pread(descriptor, size, 0)
    except OSError:
        raise ValueError("database location is unavailable") from None


def hold_database_file(path: Path) -> tuple[int, tuple[int, int]]:
    """The process-held read descriptor and identity of the file at ``path``.

    For callers outside this module that must pin an existing database file
    (the pairing CLI's ledger). The descriptor belongs to the process-wide
    holder above: callers must never close it, and it stays open after their
    use ends. Raises ``FileNotFoundError`` for a missing file and
    ``ValueError`` for anything else unusable; nothing is ever created.
    """
    with _HELD_LOCK:
        return _hold_locked(path)


def held_descriptors() -> frozenset[int]:
    """Every descriptor the process-wide holder keeps open (never SQLite's)."""
    with _HELD_LOCK:
        return frozenset(_HELD.values()) | frozenset(_DUPLICATES)


def _process_descriptors() -> list[int] | None:
    """Every descriptor number this process has open, or ``None`` if unknown."""
    for listing in ("/proc/self/fd", "/dev/fd"):
        try:
            return [int(name) for name in os.listdir(listing)]
        except (OSError, ValueError):
            continue
    return None


def _release_unlinked_held_files_for_tests() -> tuple[int, int]:
    """TEST-ONLY: close held descriptors whose file is gone and unused.

    Application code must never call this (``tests`` enforces it); the
    production rule above stays: a held descriptor lives for the process.
    A test suite, however, creates and deletes one temporary database per
    test, and each would keep one descriptor open until the test process
    exits (Issue #248).

    Only an identity that is safe to close is released: every holder
    descriptor on it (held and duplicates) refers to a file that is no longer
    linked anywhere (``st_nlink == 0``, so no path can open it again), and no
    other descriptor in the process refers to the same inode. SQLite opens
    its own descriptor for each connection and defers closing it while this
    process holds locks on the inode, so an open (or leaked) connection, or a
    pending SQLite close, leaves the identity held. With no other descriptor
    on the inode the process holds no POSIX lock on it that a close could
    drop. If the descriptors cannot be listed nothing is released.

    A ``PinnedDatabase`` or the local admin ledger may still remember a
    released descriptor number; they already refuse an unlinked file, and a
    reused number names another file, which they refuse too.

    Returns ``(released, kept)``: identities closed and unlinked identities
    left held because something else still uses them.
    """
    released = kept = 0
    with _HELD_LOCK:
        candidates: dict[tuple[int, int], list[int]] = {}
        for identity, descriptor in _HELD.items():
            candidates[identity] = [descriptor]
        for descriptor in _DUPLICATES:
            try:
                identity = _identity(os.fstat(descriptor))
            except OSError:
                continue
            candidates.setdefault(identity, []).append(descriptor)
        unlinked = {}
        for identity, descriptors in candidates.items():
            try:
                infos = [os.fstat(descriptor) for descriptor in descriptors]
            except OSError:
                continue
            if all(_identity(info) == identity and info.st_nlink == 0 for info in infos):
                unlinked[identity] = descriptors
        if not unlinked:
            return 0, 0
        listed = _process_descriptors()
        if listed is None:
            return 0, len(unlinked)
        holder = {descriptor for descriptors in unlinked.values() for descriptor in descriptors}
        in_use = set()
        for descriptor in listed:
            if descriptor in holder:
                continue
            try:
                identity = _identity(os.fstat(descriptor))
            except OSError:
                continue
            if identity in unlinked:
                in_use.add(identity)
        for identity, descriptors in unlinked.items():
            if identity in in_use:
                kept += 1
                continue
            if _HELD.get(identity) in descriptors:
                del _HELD[identity]
            for descriptor in descriptors:
                if descriptor in _DUPLICATES:
                    _DUPLICATES.remove(descriptor)
                os.close(descriptor)
            released += 1
    return released, kept


def _hold_file(path: Path) -> tuple[int, tuple[int, int]]:
    with _HELD_LOCK:
        try:
            return _hold_locked(path)
        except FileNotFoundError:
            raise ValueError("database location is unavailable") from None


@dataclass(frozen=True)
class Database:
    path: Path = field(repr=False)

    def connect(self) -> sqlite3.Connection:
        # The explicit parent must exist; never create a fallback directory.
        if not self.path.is_absolute() or not self.path.parent.is_dir() or self.path.is_symlink():
            raise ValueError("database location is unavailable")
        # New database contents must not inherit a permissive deployment umask.
        # The creating descriptor is kept, not closed: another thread may
        # already have opened the new file and taken SQLite locks on it.
        with _HELD_LOCK:
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | _HOLD_FLAGS, 0o600)
            except FileExistsError:
                pass
            else:
                _adopt_locked(descriptor)
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def connect_read_only(self) -> sqlite3.Connection:
        """A ``mode=ro`` connection that never creates the database file.

        ``connect()`` creates a missing file, so a read reached by an
        unauthenticated request after the verified filesystem disappeared
        (the mount-point directory left behind on the root filesystem) would
        create a fallback database there without any storage admission.
        SQLite's ``mode=ro`` opens an existing file or fails; there is no
        check-then-create window. A rollback-journal read creates no file
        beside the database.

        A WAL database is refused (the application never enables WAL): SQLite
        could create ``-wal``/``-shm`` sidecars for it even read-only. Two
        checks, on two different objects:

        - before any statement, the header of the file the *path* names now,
          read through the process-held descriptor; this refuses a WAL file
          before SQLite reads it, so no sidecar is created for it;
        - after a first read transaction on the connection itself,
          ``PRAGMA journal_mode`` of the file the *connection* actually opened
          (as ``app.presence.service`` does). The path is resolved separately
          by ``sqlite3.connect`` and by the header read, so a file swapped in
          between them is caught here; that read of a swapped-in WAL file may
          already have created its sidecars before the refusal.

        The returned connection is outside any transaction.
        """
        if not self.path.is_absolute() or not self.path.parent.is_dir() or self.path.is_symlink():
            raise ValueError("database location is unavailable")
        connection = sqlite3.connect(
            "file:" + quote(str(self.path)) + "?mode=ro", uri=True,
            timeout=5, isolation_level=None,
        )
        try:
            header = read_database_prefix(self.path, 20)
            if header is None or (len(header) == 20 and header[:16] == b"SQLite format 3\x00"
                                  and 2 in (header[18], header[19])):
                raise ValueError("database location is unavailable")
            connection.execute("BEGIN")
            try:
                connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
                mode = connection.execute("PRAGMA journal_mode").fetchone()
            finally:
                connection.execute("ROLLBACK")
            if mode is None or str(mode[0]).lower() == "wal":
                raise ValueError("database location is unavailable")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
        except BaseException:
            connection.close()
            raise
        return connection


class PinnedDatabase:
    """Open only the database file pinned under a storage admission.

    ``Database.connect()`` creates a missing file. A long-running reader that
    keeps opening connections after startup (the local UVC capture workers)
    must not create or open a database on whatever filesystem is at the path
    once the verified recording filesystem disappears or is replaced. ``pin()``
    therefore opens and holds a read-only descriptor to the admitted regular
    file. While that descriptor is held the file's inode cannot be freed, so an
    unlinked-and-recreated replacement can never reuse the pinned (device,
    inode) pair. Every connection requires the pinned file to still be linked
    and the path to still name that same file, opens it without create (SQLite
    ``mode=rw``), and re-checks both after the open. Until ``pin()`` succeeds
    every connection is refused.
    """

    def __init__(self, database: Database) -> None:
        if not isinstance(database, Database):
            raise ValueError("database is required")
        self._database = database
        self._lock = threading.Lock()
        self._pinned: tuple[int, int] | None = None
        self._descriptor: int | None = None

    @property
    def path(self) -> Path:
        return self._database.path

    @property
    def pinned(self) -> bool:
        with self._lock:
            return self._pinned is not None

    def _path_identity(self) -> tuple[int, int]:
        path = self.path
        try:
            if not path.is_absolute():
                raise ValueError()
            info = os.stat(path, follow_symlinks=False)
        except (OSError, ValueError):
            raise ValueError("database location is unavailable") from None
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("database location is unavailable")
        return info.st_dev, info.st_ino

    @staticmethod
    def _held_identity(descriptor: int) -> tuple[int, int]:
        try:
            info = os.fstat(descriptor)
        except OSError:
            raise ValueError("database location is unavailable") from None
        # An unlinked pinned file (lost or replaced mount/file) is refused even
        # if the path now names some other file.
        if not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
            raise ValueError("database location is unavailable")
        return info.st_dev, info.st_ino

    def pin(self, admission=None) -> None:
        """Hold the admitted file open; ``admission`` verifies storage."""
        with (admission() if admission is not None else nullcontext()):
            if not self.path.is_absolute():
                raise ValueError("database location is unavailable")
            # The descriptor comes from the process-wide holder and is never
            # closed here: closing it would drop the POSIX locks of this
            # process's open connections to the same file.
            descriptor, identity = _hold_file(self.path)
            if self._held_identity(descriptor) != identity or self._path_identity() != identity:
                raise ValueError("database location is unavailable")
        with self._lock:
            self._pinned, self._descriptor = identity, descriptor

    def release(self) -> None:
        """Drop the pin; later connections are refused until pinned again.

        The held descriptor itself stays open for the process lifetime (see
        ``_HELD``), so a pin ending never releases the locks of other
        connections in this process.
        """
        with self._lock:
            self._pinned = self._descriptor = None

    def _verify(self) -> tuple[int, int]:
        with self._lock:
            pinned, descriptor = self._pinned, self._descriptor
            if pinned is None or descriptor is None:
                raise ValueError("database location is unavailable")
            # Checked under the lock so a concurrent release() cannot close
            # (and the process reuse) the descriptor number mid-check.
            held = self._held_identity(descriptor)
        if held != pinned or self._path_identity() != pinned:
            raise ValueError("database location is unavailable")
        return pinned

    def connect(self) -> sqlite3.Connection:
        return self._open("rw")

    def connect_read_only(self) -> sqlite3.Connection:
        """A ``mode=ro`` connection with the same pin checks as ``connect()``."""
        return self._open("ro")

    def _open(self, mode: str) -> sqlite3.Connection:
        self._verify()
        connection = sqlite3.connect(
            "file:" + quote(str(self.path)) + "?mode=" + mode, uri=True,
            timeout=5, isolation_level=None,
        )
        try:
            # The path could have been swapped between the check and the open.
            self._verify()
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
        except BaseException:
            connection.close()
            raise
        return connection
