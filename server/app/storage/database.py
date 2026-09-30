"""Small SQLite connection factory. Callers own connection lifetimes."""

from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
import os
import sqlite3
import stat
import threading
from urllib.parse import quote


@dataclass(frozen=True)
class Database:
    path: Path = field(repr=False)

    def connect(self) -> sqlite3.Connection:
        # The explicit parent must exist; never create a fallback directory.
        if not self.path.is_absolute() or not self.path.parent.is_dir() or self.path.is_symlink():
            raise ValueError("database location is unavailable")
        # New database contents must not inherit a permissive deployment umask.
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
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
            try:
                descriptor = os.open(
                    self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY,
                )
            except OSError:
                raise ValueError("database location is unavailable") from None
            try:
                identity = self._held_identity(descriptor)
                if self._path_identity() != identity:
                    raise ValueError("database location is unavailable")
            except BaseException:
                os.close(descriptor)
                raise
        with self._lock:
            previous = self._descriptor
            self._pinned, self._descriptor = identity, descriptor
        if previous is not None:
            os.close(previous)

    def release(self) -> None:
        """Drop the pin; later connections are refused until pinned again."""
        with self._lock:
            descriptor = self._descriptor
            self._pinned = self._descriptor = None
        if descriptor is not None:
            os.close(descriptor)

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
        self._verify()
        connection = sqlite3.connect(
            "file:" + quote(str(self.path)) + "?mode=rw", uri=True,
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
