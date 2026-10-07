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
# Application code therefore never closes a descriptor on a database file
# that may be in use. Every such descriptor is kept here, at most one per
# (device, inode), for the life of the process, and reused. An entry is
# closed only once its file is unlinked and no `PinnedDatabase` pins it: no
# new connection can reach an unlinked file by its path, and its contents are
# discarded once its last descriptor closes. The cost is one read-only
# descriptor per live database file for the process lifetime.
_HELD_LOCK = threading.Lock()
_HELD: dict[tuple[int, int], "_HeldFile"] = {}
_HOLD_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK


class _HeldFile:
    def __init__(self, descriptor: int) -> None:
        # The first descriptor is read from; any further one (a path swapped
        # back to a held file between stat and open) is only kept open.
        self.descriptors = [descriptor]
        self.pins = 0


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _adopt_locked(descriptor: int) -> tuple[int, int]:
    """Keep ``descriptor`` for the process lifetime; returns its file identity."""
    identity = _identity(os.fstat(descriptor))
    held = _HELD.get(identity)
    if held is None:
        _HELD[identity] = _HeldFile(descriptor)
    else:
        held.descriptors.append(descriptor)
    return identity


def _evict_unlinked_locked() -> None:
    for identity, held in list(_HELD.items()):
        if held.pins:
            continue
        try:
            linked = os.fstat(held.descriptors[0]).st_nlink > 0
        except OSError:
            linked = True
        if not linked:
            del _HELD[identity]
            for descriptor in held.descriptors:
                os.close(descriptor)


def _hold_locked(path: Path) -> tuple[int, tuple[int, int]]:
    """The held read descriptor and identity of the regular file at ``path``.

    Raises ``FileNotFoundError`` for a missing file and ``ValueError`` for
    anything else unusable. A file already held is never opened again.
    """
    _evict_unlinked_locked()
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError:
        raise ValueError("database location is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("database location is unavailable")
    held = _HELD.get(_identity(info))
    if held is not None:
        return held.descriptors[0], _identity(info)
    try:
        descriptor = os.open(path, _HOLD_FLAGS)
    except FileNotFoundError:
        raise
    except OSError:
        raise ValueError("database location is unavailable") from None
    identity = _adopt_locked(descriptor)
    held = _HELD[identity]
    if not stat.S_ISREG(os.fstat(held.descriptors[0]).st_mode):
        raise ValueError("database location is unavailable")
    return held.descriptors[0], identity


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


def _pin_file(path: Path) -> tuple[int, tuple[int, int]]:
    with _HELD_LOCK:
        try:
            descriptor, identity = _hold_locked(path)
        except FileNotFoundError:
            raise ValueError("database location is unavailable") from None
        _HELD[identity].pins += 1
        return descriptor, identity


def _unpin_file(identity: tuple[int, int]) -> None:
    with _HELD_LOCK:
        held = _HELD.get(identity)
        if held is not None and held.pins:
            held.pins -= 1


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
            descriptor, identity = _pin_file(self.path)
            try:
                if self._held_identity(descriptor) != identity or self._path_identity() != identity:
                    raise ValueError("database location is unavailable")
            except BaseException:
                _unpin_file(identity)
                raise
        with self._lock:
            previous = self._pinned
            self._pinned, self._descriptor = identity, descriptor
        if previous is not None:
            _unpin_file(previous)

    def release(self) -> None:
        """Drop the pin; later connections are refused until pinned again.

        The held descriptor itself stays open (see ``_HELD``) until the file
        is unlinked, so the locks of other connections in this process are
        never released by a pin ending.
        """
        with self._lock:
            pinned = self._pinned
            self._pinned = self._descriptor = None
        if pinned is not None:
            _unpin_file(pinned)

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
