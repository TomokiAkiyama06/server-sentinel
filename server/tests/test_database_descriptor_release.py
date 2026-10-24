"""Issue #248: the test-only release of held database descriptors."""

import errno
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import TestCase
from unittest.mock import patch

from app import local_admin
from app.storage import database as storage_database
from app.storage.database import Database, PinnedDatabase, held_descriptors, read_database_prefix
import tests
from tests import release_unlinked_test_databases


SERVER_ROOT = Path(__file__).resolve().parents[1]
RELEASE_NAME = "_release_unlinked_held_files_for_tests"


def open_descriptor_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def held_identities() -> set[tuple[int, int]]:
    with storage_database._HELD_LOCK:
        return set(storage_database._HELD)


PosixLock = tuple[str, str, int, str, str]


def posix_locks_of_this_process(identity: tuple[int, int]) -> list[PosixLock]:
    """This process's held POSIX locks on ``identity``'s file, sorted.

    Each lock is ``(mandatory, mode, pid, start, end)`` parsed from a
    ``/proc/locks`` line. The leading ordinal is dropped: it is numbered
    across the whole host, so it shifts whenever another process takes or
    drops a lock between two reads (Issue #350). Waiters (``->``) are not
    held locks and are skipped. The file is matched by device and inode,
    which the kernel prints as ``MAJOR:MINOR:INODE`` (major/minor in hex).
    """
    with open("/proc/locks", encoding="ascii") as stream:
        lines = stream.read().splitlines()
    device, inode = identity
    target = (os.major(device), os.minor(device), inode)
    pid = os.getpid()
    locks: list[PosixLock] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 8 or fields[1] != "POSIX":
            continue
        major, minor, number = fields[5].split(":")
        if (int(major, 16), int(minor, 16), int(number)) != target or int(fields[4]) != pid:
            continue
        locks.append((fields[2], fields[3], int(fields[4]), fields[6], fields[7]))
    return sorted(locks)


def second_process_writer(path: Path) -> str:
    """``locked`` if another process cannot take a write lock on ``path``."""
    code = (
        "import sqlite3, sys\n"
        "c = sqlite3.connect(sys.argv[1], timeout=0, isolation_level=None)\n"
        "try:\n"
        "    c.execute('BEGIN IMMEDIATE')\n"
        "except sqlite3.OperationalError:\n"
        "    print('locked')\n"
        "else:\n"
        "    c.execute('ROLLBACK')\n"
        "    print('acquired')\n"
    )
    completed = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True,
                               text=True, timeout=30, check=True)
    return completed.stdout.strip()


class ReleaseTests(TestCase):
    def setUp(self):
        # Start from a clean holder so counts below are this test's own.
        release_unlinked_test_databases()

    def make_database(self) -> tuple[tempfile.TemporaryDirectory, Database]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = Database(Path(directory.name) / "main.sqlite3")
        with database.connect() as connection:
            connection.execute("CREATE TABLE probe (value INTEGER)")
        connection.close()
        return directory, database

    def identity(self, database: Database) -> tuple[int, int]:
        info = os.stat(database.path)
        return info.st_dev, info.st_ino

    def test_descriptors_do_not_grow_across_many_temporary_databases(self):
        before = open_descriptor_count()
        for _ in range(300):
            with tempfile.TemporaryDirectory() as directory:
                database = Database(Path(directory) / "main.sqlite3")
                connection = database.connect()
                connection.execute("CREATE TABLE probe (value INTEGER)")
                connection.close()
                self.assertIsNotNone(read_database_prefix(database.path, 16))
                reader = database.connect_read_only()
                reader.close()
                pinned = PinnedDatabase(database)
                pinned.pin()
                pinned.connect().close()
                pinned.release()
                identity = self.identity(database)
                self.assertIn(identity, held_identities())
            self.assertEqual((1, 0), release_unlinked_test_databases())
            self.assertNotIn(identity, held_identities())
        self.assertLessEqual(open_descriptor_count(), before + 2)

    def test_without_the_release_each_temporary_database_keeps_a_descriptor(self):
        before = len(held_descriptors())
        for _ in range(5):
            with tempfile.TemporaryDirectory() as directory:
                Database(Path(directory) / "main.sqlite3").connect().close()
        self.assertEqual(before + 5, len(held_descriptors()))
        self.assertEqual((5, 0), release_unlinked_test_databases())
        self.assertEqual(before, len(held_descriptors()))

    def test_a_linked_database_is_never_released(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        self.assertEqual((0, 0), release_unlinked_test_databases())
        self.assertIn(identity, held_identities())

    def test_a_live_connection_keeps_the_held_descriptor_and_its_locks(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        holder = database.connect()
        self.addCleanup(holder.close)
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("INSERT INTO probe VALUES (1)")
        self.assertEqual("locked", second_process_writer(database.path))
        try:
            locks = posix_locks_of_this_process(identity)
        except OSError:
            locks = None
        if locks is not None:
            self.assertTrue(locks)
        with storage_database._HELD_LOCK:
            descriptor = storage_database._HELD[identity]
        # Unlink the file while the connection is open: the release must
        # still refuse, because SQLite's own descriptor is on the inode.
        os.unlink(database.path)
        self.assertEqual((0, 1), release_unlinked_test_databases())
        self.assertIn(identity, held_identities())
        self.assertIn(descriptor, held_descriptors())
        self.assertEqual(identity, (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino))
        if locks:
            self.assertEqual(locks, posix_locks_of_this_process(identity))
        holder.execute("COMMIT")
        self.assertEqual(1, holder.execute("SELECT COUNT(*) FROM probe").fetchone()[0])
        holder.close()
        self.assertEqual((1, 0), release_unlinked_test_databases())
        self.assertNotIn(identity, held_identities())

    def test_a_pending_sqlite_close_keeps_the_held_descriptor(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        first = database.connect()
        self.addCleanup(first.close)
        first.execute("BEGIN")
        first.execute("SELECT COUNT(*) FROM probe").fetchone()
        second = database.connect()
        second.execute("SELECT COUNT(*) FROM probe").fetchone()
        second.close()
        os.unlink(database.path)
        self.assertEqual((0, 1), release_unlinked_test_databases())
        first.execute("ROLLBACK")
        first.close()
        self.assertEqual((1, 0), release_unlinked_test_databases())
        self.assertNotIn(identity, held_identities())

    def test_a_still_linked_hard_link_keeps_the_file_held(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        other = Path(directory.name) / "other.sqlite3"
        os.link(database.path, other)
        os.unlink(database.path)
        self.assertEqual((0, 0), release_unlinked_test_databases())
        self.assertIn(identity, held_identities())

    def test_duplicates_of_a_released_file_are_closed_too(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        duplicate = os.open(database.path, os.O_RDONLY | os.O_CLOEXEC)
        with storage_database._HELD_LOCK:
            self.assertEqual(identity, storage_database._adopt_locked(duplicate))
        self.assertIn(duplicate, held_descriptors())
        os.unlink(database.path)
        self.assertEqual((1, 0), release_unlinked_test_databases())
        self.assertNotIn(duplicate, held_descriptors())
        self.assertNotIn(identity, held_identities())

    def test_nothing_is_released_when_descriptors_cannot_be_listed(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        os.unlink(database.path)
        original = storage_database._process_descriptors
        storage_database._process_descriptors = lambda: None
        try:
            self.assertEqual((0, 1), release_unlinked_test_databases())
        finally:
            storage_database._process_descriptors = original
        self.assertIn(identity, held_identities())

    def test_a_pinned_database_on_a_released_file_is_refused(self):
        directory, database = self.make_database()
        pinned = PinnedDatabase(database)
        pinned.pin()
        os.unlink(database.path)
        self.assertEqual((1, 0), release_unlinked_test_databases())
        with self.assertRaises(ValueError):
            pinned.connect()

    def stale_after_recreation(self, database: Database) -> tuple[int, tuple[int, int]]:
        """Release the unlinked file, recreate one at the same path; its hold."""
        os.unlink(database.path)
        self.assertEqual((1, 0), release_unlinked_test_databases())
        with database.connect() as connection:
            connection.execute("CREATE TABLE probe (value INTEGER)")
        connection.close()
        identity = self.identity(database)
        with storage_database._HELD_LOCK:
            return storage_database._HELD[identity], identity

    def test_a_stale_pin_refuses_a_database_recreated_at_the_same_path(self):
        directory, database = self.make_database()
        pinned = PinnedDatabase(database)
        pinned.pin()
        self.stale_after_recreation(database)
        with self.assertRaises(ValueError):
            pinned.connect()
        with self.assertRaises(ValueError):
            pinned.connect_read_only()

    def test_a_stale_pin_refuses_even_a_reused_number_and_inode(self):
        # The worst case Linux allows: the recreated file got the freed inode
        # and the freed descriptor number. Simulated by pointing the stale
        # pin at the new hold; only the adoption serial tells them apart.
        directory, database = self.make_database()
        pinned = PinnedDatabase(database)
        pinned.pin()
        descriptor, identity = self.stale_after_recreation(database)
        pinned._pinned, pinned._descriptor = identity, descriptor
        with self.assertRaises(ValueError):
            pinned.connect()
        # A fresh pin of the recreated file works.
        fresh = PinnedDatabase(database)
        fresh.pin()
        fresh.connect().close()

    def test_a_stale_ledger_pin_refuses_a_reused_number_and_inode(self):
        directory, database = self.make_database()
        ledger = local_admin._existing_database(database.path)
        ledger.verify()
        descriptor, identity = self.stale_after_recreation(database)
        object.__setattr__(ledger, "_descriptor", descriptor)
        object.__setattr__(ledger, "_identity", identity)
        with self.assertRaises(sqlite3.DatabaseError):
            ledger.verify()
        self.assertTrue(ledger.rejected)
        local_admin._existing_database(database.path).verify()

    def reused_by_a_non_holder(self, database: Database, descriptor: int) -> tuple[int, int]:
        """Release the unlinked file, recreate one at the same path, and reopen
        ``descriptor``'s number on it outside the holder; the new identity.

        The released number is first taken by a descriptor the holder never
        adopted (standing in for a SQLite connection's), so no new adoption
        overwrites the released number's serial.
        """
        os.unlink(database.path)
        self.assertEqual((1, 0), release_unlinked_test_databases())
        connection = sqlite3.connect(database.path, isolation_level=None)
        connection.execute("CREATE TABLE probe (value INTEGER)")
        connection.close()
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptor)
        self.assertEqual(errno.EBADF, closed.exception.errno)
        opened = os.open(database.path, os.O_RDONLY | os.O_CLOEXEC)
        if opened != descriptor:  # usually the lowest free number already
            try:
                os.dup2(opened, descriptor, inheritable=False)
            finally:
                os.close(opened)
        self.addCleanup(os.close, descriptor)
        self.assertNotIn(descriptor, held_descriptors())
        return self.identity(database)

    def test_a_stale_pin_refuses_a_number_reused_by_a_non_holder(self):
        # Without the release forgetting the serial, the released number
        # would still carry the pin's serial: a non-holder descriptor on a
        # recreated file with the reused inode would then pass every check.
        directory, database = self.make_database()
        pinned = PinnedDatabase(database)
        pinned.pin()
        descriptor, serial = pinned._descriptor, pinned._serial
        identity = self.reused_by_a_non_holder(database, descriptor)
        self.assertFalse(storage_database.held_descriptor_is_current(descriptor, serial))
        pinned._pinned = identity
        with self.assertRaises(ValueError):
            pinned.connect()
        with self.assertRaises(ValueError):
            pinned.connect_read_only()

    def test_a_stale_ledger_pin_refuses_a_number_reused_by_a_non_holder(self):
        directory, database = self.make_database()
        ledger = local_admin._existing_database(database.path)
        ledger.verify()
        identity = self.reused_by_a_non_holder(database, ledger._descriptor)
        object.__setattr__(ledger, "_identity", identity)
        with self.assertRaises(sqlite3.DatabaseError):
            ledger.verify()
        self.assertTrue(ledger.rejected)

    def test_the_ledger_takes_the_serial_with_its_hold(self):
        directory, database = self.make_database()
        descriptor, identity, serial = storage_database.hold_database_file(database.path)
        self.assertEqual(self.identity(database), identity)
        self.assertTrue(storage_database.held_descriptor_is_current(descriptor, serial))
        ledger = local_admin._existing_database(database.path)
        self.assertEqual((descriptor, identity, serial),
                         (ledger._descriptor, ledger._identity, ledger._serial))

    def test_an_unexaminable_descriptor_keeps_the_file_held(self):
        directory, database = self.make_database()
        identity = self.identity(database)
        os.unlink(database.path)
        unrelated = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, unrelated)
        real_fstat = os.fstat

        def failing_fstat(descriptor):
            if descriptor == unrelated:
                raise OSError(errno.EIO, "synthetic I/O error")
            return real_fstat(descriptor)

        with patch.object(storage_database.os, "fstat", failing_fstat):
            self.assertEqual((0, 1), release_unlinked_test_databases())
        self.assertIn(identity, held_identities())
        # A descriptor closed since it was listed (EBADF) does not block.

        def closed_fstat(descriptor):
            if descriptor == unrelated:
                raise OSError(errno.EBADF, "closed")
            return real_fstat(descriptor)

        with patch.object(storage_database.os, "fstat", closed_fstat):
            self.assertEqual((1, 0), release_unlinked_test_databases())
        self.assertNotIn(identity, held_identities())


class WiringTests(TestCase):
    def test_every_test_releases_after_its_cleanups(self):
        self.assertTrue(getattr(unittest.TestCase.run, "_releases_test_databases", False))
        self.assertIs(tests.release_unlinked_test_databases, release_unlinked_test_databases)

    def test_application_code_never_calls_the_release(self):
        offenders = []
        paths = list((SERVER_ROOT / "app").rglob("*.py")) + list(SERVER_ROOT.glob("*.py"))
        for path in sorted(paths):
            text = path.read_text(encoding="utf-8")
            count = text.count(RELEASE_NAME)
            allowed = 1 if path == SERVER_ROOT / "app/storage/database.py" else 0
            if count != allowed:
                offenders.append(str(path.relative_to(SERVER_ROOT)))
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
