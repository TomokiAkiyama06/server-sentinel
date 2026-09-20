"""Small SQLite connection factory. Callers own connection lifetimes."""

from dataclasses import dataclass, field
from pathlib import Path
import os
import sqlite3


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
