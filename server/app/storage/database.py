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
    once the verified recording filesystem disappears or is replaced. Every
    connection therefore requires the path to still be the same regular file
    (device and inode) observed by ``pin()`` inside a storage admission, opens
    it without create (SQLite ``mode=rw``), and re-checks the identity after
    the open. Until ``pin()`` succeeds every connection is refused.
    """

    def __init__(self, database: Database) -> None:
        if not isinstance(database, Database):
            raise ValueError("database is required")
        self._database = database
        self._lock = threading.Lock()
        self._pinned: tuple[int, int] | None = None

    @property
    def path(self) -> Path:
        return self._database.path

    @property
    def pinned(self) -> bool:
        with self._lock:
            return self._pinned is not None

    def _identity(self) -> tuple[int, int]:
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

    def pin(self, admission=None) -> None:
        """Record the admitted file identity; ``admission`` verifies storage."""
        with (admission() if admission is not None else nullcontext()):
            identity = self._identity()
        with self._lock:
            self._pinned = identity

    def _require(self) -> tuple[int, int]:
        with self._lock:
            pinned = self._pinned
        if pinned is None or self._identity() != pinned:
            raise ValueError("database location is unavailable")
        return pinned

    def connect(self) -> sqlite3.Connection:
        pinned = self._require()
        connection = sqlite3.connect(
            "file:" + quote(str(self.path)) + "?mode=rw", uri=True,
            timeout=5, isolation_level=None,
        )
        try:
            # The path could have been swapped between the check and the open.
            if self._identity() != pinned:
                raise ValueError("database location is unavailable")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
        except BaseException:
            connection.close()
            raise
        return connection
