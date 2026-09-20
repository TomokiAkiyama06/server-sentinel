"""Private SQLite ledger with serialized ownership and durable transitions."""

from contextlib import contextmanager
import fcntl
import os
import sqlite3
import stat

from .ring_models import RingRefused
from .storage import open_directory


SCHEMA = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE segments (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, start INTEGER NOT NULL,
  end INTEGER NOT NULL, length INTEGER NOT NULL, allocated INTEGER NOT NULL,
  checksum TEXT NOT NULL, state TEXT NOT NULL, clock_trusted INTEGER NOT NULL
);
CREATE INDEX segment_time ON segments(source, end);
CREATE TABLE incidents (
  id TEXT PRIMARY KEY, reason TEXT NOT NULL, start INTEGER NOT NULL,
  end INTEGER NOT NULL, completed INTEGER, expires INTEGER, state TEXT NOT NULL,
  clock_uncertain INTEGER NOT NULL DEFAULT 0, sources TEXT NOT NULL
);
CREATE TABLE protection (
  incident TEXT REFERENCES incidents(id), segment TEXT REFERENCES segments(id),
  PRIMARY KEY(incident, segment)
);
PRAGMA user_version = 1;
"""


class Ledger:
    def __init__(self, settings):
        self.settings = settings
        self.fd = None
        self.connection = None
        try:
            self.fd = open_directory(settings.runtime_root)
            info = os.fstat(self.fd)
            if info.st_uid != settings.service_uid or info.st_mode & 0o077:
                raise RingRefused("ledger_root_ownership")
            # Lifetime lock: independent agents must not write one ring ledger.
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptor = os.open("ring.sqlite3", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=self.fd)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != settings.service_uid
                        or info.st_mode & 0o077 or info.st_nlink != 1):
                    raise RingRefused("ledger_file_ownership")
                self.identity = (info.st_dev, info.st_ino)
            finally:
                os.close(descriptor)
            self.connection = sqlite3.connect(f"/proc/self/fd/{self.fd}/ring.sqlite3",
                                              isolation_level=None, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA synchronous = FULL")
            self.connection.execute("PRAGMA journal_mode = DELETE")
            self.connection.execute("PRAGMA temp_store = MEMORY")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                    raise RingRefused("unrecognized_ledger")
                self.connection.executescript("BEGIN IMMEDIATE;" + SCHEMA + "COMMIT;")
                os.fsync(self.fd)
            elif version != 1:
                raise RingRefused("unsupported_ledger_version")
            if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RingRefused("ledger_integrity_failure")
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise RingRefused("ledger_unavailable") from exc
        except Exception:
            self.close()
            raise

    def check(self):
        descriptor = open_directory(self.settings.runtime_root)
        try:
            actual, expected = os.fstat(descriptor), os.fstat(self.fd)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise RingRefused("ledger_root_replaced")
            if actual.st_uid != self.settings.service_uid or actual.st_mode & 0o077:
                raise RingRefused("ledger_root_ownership")
            info = os.stat("ring.sqlite3", dir_fd=self.fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != self.identity or not stat.S_ISREG(info.st_mode):
                raise RingRefused("ledger_file_replaced")
            if info.st_uid != self.settings.service_uid or info.st_mode & 0o077 or info.st_nlink != 1:
                raise RingRefused("ledger_file_ownership")
        finally:
            os.close(descriptor)

    @contextmanager
    def transaction(self):
        self.check()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
