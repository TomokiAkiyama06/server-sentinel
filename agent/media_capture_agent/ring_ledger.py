"""Private SQLite ledger with serialized ownership and durable transitions."""

from contextlib import contextmanager
import fcntl
import os
import sqlite3
import stat

from .ring_models import RingRefused, integer, round_up
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


# SQLite pager.c caps assumed sectors at 64 KiB. Budget one header and
# alignment padding per original page, even though real journals are smaller.
PAGE_BYTES = 4096
MAX_SECTOR_BYTES = 65536


class Ledger:
    def __init__(self, settings, *, maximum_bytes, space=os.fstatvfs):
        integer(maximum_bytes, minimum=PAGE_BYTES)
        self.maximum_bytes = maximum_bytes // PAGE_BYTES * PAGE_BYTES
        self.maximum_pages = self.maximum_bytes // PAGE_BYTES
        self.settings, self.space = settings, space
        self.fd = None
        self.connection = None
        try:
            self.fd = open_directory(settings.runtime_root)
            info = os.fstat(self.fd)
            if info.st_uid != settings.service_uid or info.st_mode & 0o077:
                raise RingRefused("ledger_root_ownership")
            # Lifetime lock: independent agents must not write one ring ledger.
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            allocation = self.space(self.fd).f_frsize
            self.journal_bound = (self.maximum_pages * (PAGE_BYTES + 8 + 2 * MAX_SECTOR_BYTES)
                                  + MAX_SECTOR_BYTES)
            self.headroom = (round_up(self.maximum_bytes, allocation)
                             + round_up(self.journal_bound, allocation) + 2 * allocation)
            # Before file creation, PRAGMAs or hot-journal recovery can write.
            self.check_space()
            self._check_sidecars()
            descriptor = os.open("ring.sqlite3", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=self.fd)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != settings.service_uid
                        or info.st_mode & 0o077 or info.st_nlink != 1):
                    raise RingRefused("ledger_file_ownership")
                if info.st_size > self.maximum_bytes:
                    raise RingRefused("ledger_size_limit")
                header = os.pread(descriptor, 100, 0)
                if header and (len(header) != 100 or header[:16] != b"SQLite format 3\x00"
                               or int.from_bytes(header[16:18], "big") != PAGE_BYTES
                               or header[18:20] != b"\x01\x01"):
                    raise RingRefused("unsupported_ledger_format")
                self.identity = (info.st_dev, info.st_ino)
            finally:
                os.close(descriptor)
            self.connection = sqlite3.connect(f"/proc/self/fd/{self.fd}/ring.sqlite3",
                                              isolation_level=None, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA page_size = 4096")
            if self.connection.execute("PRAGMA auto_vacuum").fetchone()[0] != 0 or (header and header[20] != 0):
                raise RingRefused("unsupported_ledger_format")
            if self.connection.execute(f"PRAGMA max_page_count = {self.maximum_pages}").fetchone()[0] != self.maximum_pages:
                raise RingRefused("ledger_size_limit")
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA synchronous = FULL")
            self.connection.execute("PRAGMA journal_mode = DELETE")
            self.connection.execute("PRAGMA temp_store = MEMORY")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                    raise RingRefused("unrecognized_ledger")
                with self.transaction():
                    for statement in SCHEMA.split(";"):
                        if statement.strip():
                            self.connection.execute(statement)
                os.fsync(self.fd)
            elif version != 1:
                raise RingRefused("unsupported_ledger_version")
            if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RingRefused("ledger_integrity_failure")
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise RingRefused("ledger_unavailable") from exc
        except BaseException:
            self.close()
            raise

    def check_space(self):
        space = self.space(self.fd)
        if space.f_flag & os.ST_RDONLY:
            raise RingRefused("ledger_readonly")
        if space.f_bavail * space.f_frsize < self.settings.safety_reserve_bytes + self.headroom:
            raise RingRefused("ledger_reserve_unavailable")

    def require_rows(self, *, segments, incidents, protections):
        # Bounded UUID/numeric records fit without overflow in schema v1.
        # Each B-tree needs at most two pages per entry (leaf + interior).
        # segments have three trees; incidents/protection each have two.
        # 74 extra pages cover schema/settings roots and transient split work;
        # this deliberately does not depend on average UUID insertion packing.
        required = PAGE_BYTES * (74 + 6 * integer(segments) + 4 * integer(incidents)
                                 + 4 * integer(protections))
        if required > self.maximum_bytes:
            raise RingRefused("insufficient_ledger_capacity")
        return required

    def _check_sidecars(self):
        for name in ("ring.sqlite3-wal", "ring.sqlite3-shm", "ring.sqlite3-journal"):
            try:
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (name != "ring.sqlite3-journal" or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != self.settings.service_uid or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_size > self.journal_bound):
                raise RingRefused("ledger_sidecar_refused")

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
        self.check_space()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
