from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest

from app.storage.database import Database
from app.storage.migrations import BUILTIN_MIGRATIONS, Migration, MigrationError, migrate


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "test.sqlite3")

    def test_fresh_database_upgrade_and_restart_persist_data(self):
        with closing(self.database.connect()) as connection:
            migrate(connection)
            connection.execute("INSERT INTO application_metadata VALUES ('synthetic', 'kept')")
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        extension = Migration(2, "synthetic_extension", ("CREATE TABLE extension (id INTEGER)",))
        with closing(self.database.connect()) as connection:
            migrate(connection, BUILTIN_MIGRATIONS + (extension,))
            migrate(connection, BUILTIN_MIGRATIONS + (extension,))
            self.assertEqual(connection.execute("SELECT value FROM application_metadata").fetchone()[0], "kept")
            self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0], 2)

    def test_failed_upgrade_rolls_back_all_pending_schema_and_history(self):
        with closing(self.database.connect()) as connection:
            migrate(connection)
            pending = (
                Migration(2, "second", ("CREATE TABLE pending (id INTEGER)",)),
                Migration(3, "broken", ("NOT VALID SYNTHETIC_PRIVATE_VALUE",)),
            )
            with self.assertRaises(MigrationError) as caught:
                migrate(connection, BUILTIN_MIGRATIONS + pending)
            self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", str(caught.exception))
            self.assertFalse(connection.in_transaction)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='pending'").fetchone())
            self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0], 1)

    def test_edited_history_or_future_schema_blocks_startup(self):
        with closing(self.database.connect()) as connection:
            migrate(connection)
            with self.assertRaises(MigrationError):
                migrate(connection, (Migration(1, "edited", ("SELECT 1",)),))
            connection.execute("INSERT INTO schema_migrations VALUES (2, 'future', 'synthetic')")
            with self.assertRaises(MigrationError):
                migrate(connection)

    def test_invalid_sequence_and_in_progress_transaction_refused(self):
        with closing(self.database.connect()) as connection:
            with self.assertRaises(MigrationError):
                migrate(connection, (Migration(2, "gap", ("SELECT 1",)),))
            connection.execute("BEGIN")
            with self.assertRaises(MigrationError):
                migrate(connection)
            self.assertTrue(connection.in_transaction)
            connection.rollback()

    def test_competing_startups_are_serialized(self):
        def start():
            with closing(self.database.connect()) as connection:
                migrate(connection)
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(lambda _: start(), range(4)))
        with closing(self.database.connect()) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0], 1)

    def test_foreign_keys_are_enforced(self):
        with closing(self.database.connect()) as connection:
            connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            connection.execute("CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO child VALUES (1)")

    def test_new_database_is_private(self):
        with closing(self.database.connect()):
            self.assertEqual(stat.S_IMODE(self.database.path.stat().st_mode), 0o600)

    def test_database_factory_does_not_create_missing_directory_or_follow_file_link(self):
        missing = self.database.path.parent / "missing"
        with self.assertRaises(ValueError):
            Database(missing / "test.sqlite3").connect()
        self.assertFalse(missing.exists())
        self.database.path.symlink_to(self.database.path.parent / "target.sqlite3")
        with self.assertRaises(ValueError):
            self.database.connect()
