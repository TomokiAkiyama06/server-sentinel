"""Issue #396: the SQLite lock waits of the stop's settle polls share one bound.

Synthetic SQLite files in a temporary directory only; no deployment, camera or
network. On the rollback journal a write can wait for a lock more than once
(SHARED and RESERVED at ``BEGIN IMMEDIATE``, EXCLUSIVE at ``COMMIT``) and
SQLite's busy timeout restarts for each, so a completion callback could run
several busy timeouts past a settle's deadline.
"""

from contextlib import closing, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from zoneinfo import ZoneInfo
import sqlite3
import threading
import time
import unittest
from uuid import uuid4

from app.notifications.schedule import DailySummaryScheduler
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.presence.delivery import ActionResult
from app.presence.service import PresenceService
from app.storage import database as database_module
from app.storage.database import (BUSY_TIMEOUT_SECONDS, Database, bounded_lock_waits,
                                  bounded_transaction, lock_waits_bounded)
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_storage_notifications import Transport, endpoint

DEFAULT_BUSY_MS = int(BUSY_TIMEOUT_SECONDS * 1000)
# Scheduling slack on a loaded runner; far below the 5 s busy timeout the
# bounds replace, so a missing bound still fails.
MARGIN = 1.0


class _Locks:
    """Another writer holding RESERVED, then a reader holding SHARED."""

    def __init__(self, test, path, *, reserved_for: float):
        self.other = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.reader = sqlite3.connect(path, isolation_level=None)
        test.addCleanup(self.other.close)
        test.addCleanup(self.reader.close)
        # The reader keeps SHARED, so a COMMIT waits for EXCLUSIVE.
        self.reader.execute("BEGIN")
        self.reader.execute("SELECT count(*) FROM sqlite_master").fetchall()
        # The other writer keeps RESERVED, so BEGIN IMMEDIATE waits.
        self.other.execute("BEGIN IMMEDIATE")
        self.release = threading.Timer(reserved_for, lambda: self.other.execute("ROLLBACK"))
        self.release.start()
        test.addCleanup(self.release.cancel)

    def close(self):
        self.release.join()
        if self.reader.in_transaction:
            self.reader.execute("ROLLBACK")


class BoundedTransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="sentinel-lock-waits-")
        self.addCleanup(temporary.cleanup)
        self.path = str(Path(temporary.name) / "state.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE t (v INTEGER)")

    def busy_ms(self):
        return self.db.execute("PRAGMA busy_timeout").fetchone()[0]

    def test_all_lock_waits_of_one_write_end_by_the_context_end(self):
        locks = _Locks(self, self.path, reserved_for=0.3)
        started = time.monotonic()
        with bounded_lock_waits(started + 0.5), self.assertRaises(sqlite3.OperationalError):
            with bounded_transaction(self.db):
                self.db.execute("INSERT INTO t VALUES (1)")
        elapsed = time.monotonic() - started
        locks.close()
        # BEGIN got RESERVED after 0.3 s; COMMIT then waited only until the
        # end (0.5 s), never a busy timeout of its own (5 s more).
        self.assertGreater(elapsed, 0.3)
        self.assertLess(elapsed, 0.5 + MARGIN)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(DEFAULT_BUSY_MS, self.busy_ms())
        self.assertEqual([], self.db.execute("SELECT v FROM t").fetchall())

    def test_one_write_gets_at_most_one_busy_timeout_from_its_start(self):
        # A far context end does not lengthen a write beyond one busy timeout.
        locks = _Locks(self, self.path, reserved_for=0.2)
        started = time.monotonic()
        with mock.patch.object(database_module, "BUSY_TIMEOUT_SECONDS", 0.4), \
                bounded_lock_waits(started + 60), self.assertRaises(sqlite3.OperationalError):
            with bounded_transaction(self.db):
                self.db.execute("INSERT INTO t VALUES (1)")
        elapsed = time.monotonic() - started
        locks.close()
        self.assertLess(elapsed, 0.4 + MARGIN)

    def test_a_write_that_gets_its_locks_in_time_commits(self):
        locks = _Locks(self, self.path, reserved_for=0.1)
        locks.reader.execute("ROLLBACK")
        with bounded_lock_waits(time.monotonic() + 2):
            self.assertTrue(lock_waits_bounded())
            with bounded_transaction(self.db):
                self.db.execute("INSERT INTO t VALUES (1)")
        locks.close()
        self.assertFalse(lock_waits_bounded())
        self.assertEqual([(1,)], self.db.execute("SELECT v FROM t").fetchall())
        self.assertEqual(DEFAULT_BUSY_MS, self.busy_ms())

    def test_outside_a_bound_it_is_the_plain_transaction(self):
        with mock.patch.object(database_module, "_retry_busy") as retried:
            with bounded_transaction(self.db):
                self.db.execute("INSERT INTO t VALUES (2)")
        retried.assert_not_called()
        self.assertEqual([(2,)], self.db.execute("SELECT v FROM t").fetchall())
        self.assertEqual(DEFAULT_BUSY_MS, self.busy_ms())
        with self.assertRaises(ValueError):
            with bounded_transaction(self.db):
                self.db.execute("INSERT INTO t VALUES (3)")
                raise ValueError("synthetic")
        self.assertFalse(self.db.in_transaction)
        self.assertEqual([(2,)], self.db.execute("SELECT v FROM t").fetchall())

    def test_the_connections_own_busy_timeout_is_restored(self):
        # PR #400 review: the timeout the connection had, not the default.
        self.db.execute("PRAGMA busy_timeout=1234")
        with bounded_lock_waits(time.monotonic() + 1):
            with bounded_transaction(self.db):
                # The statements inside get what is left of the budget.
                self.assertGreater(self.busy_ms(), 500)
                self.assertLessEqual(self.busy_ms(), 1000)
                self.db.execute("INSERT INTO t VALUES (4)")
        self.assertEqual(1234, self.busy_ms())

    def test_an_inner_bound_never_extends_an_outer_one(self):
        outer = time.monotonic() + 1
        with bounded_lock_waits(outer):
            with bounded_lock_waits(outer + 60):
                self.assertEqual(outer, database_module._LOCK_WAIT_END.get())
            with bounded_lock_waits(outer - 0.5):
                self.assertEqual(outer - 0.5, database_module._LOCK_WAIT_END.get())
            self.assertEqual(outer, database_module._LOCK_WAIT_END.get())
        self.assertIsNone(database_module._LOCK_WAIT_END.get())


class CallbackWriteTests(unittest.TestCase):
    """The completion callbacks' own writes follow the bound."""

    def setUp(self):
        temporary = TemporaryDirectory(prefix="sentinel-callback-locks-")
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "state.sqlite3")
        with closing(self.database.connect()) as db:
            migrate(db, APPLICATION_MIGRATIONS)

    def held(self, reserved_for=30.0):
        locks = _Locks(self, str(self.database.path), reserved_for=reserved_for)
        self.addCleanup(lambda: locks.other.in_transaction and locks.other.execute("ROLLBACK"))
        return locks

    def test_a_presence_transaction_fails_by_the_bound(self):
        service = PresenceService(self.database, reservation=nullcontext)
        self.held()
        started = time.monotonic()
        with bounded_lock_waits(started + 0.3), self.assertRaises(sqlite3.OperationalError):
            with service._transaction() as db:
                db.execute("SELECT 1")
        self.assertLess(time.monotonic() - started, 0.3 + MARGIN)

    def test_the_daily_summary_schedule_row_fails_by_the_bound(self):
        connection = self.database.connect()
        self.addCleanup(connection.close)
        service = NotificationService(lambda event: None)
        scheduler = DailySummaryScheduler(connection, ZoneInfo("UTC"), service, nullcontext)
        self.held()
        started = time.monotonic()
        with bounded_lock_waits(started + 0.3), self.assertRaises(sqlite3.OperationalError):
            scheduler._complete("2026-01-01", DeliveryResult.SENT)
        self.assertLess(time.monotonic() - started, 0.3 + MARGIN)
        self.assertEqual(DEFAULT_BUSY_MS, connection.execute("PRAGMA busy_timeout").fetchone()[0])


class SettlePollTests(unittest.TestCase):
    """`NotificationService.poll(deadline)` ends by its overshoot past the deadline."""

    def setUp(self):
        temporary = TemporaryDirectory(prefix="sentinel-settle-locks-")
        self.addCleanup(temporary.cleanup)
        self.path = str(Path(temporary.name) / "state.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE claims (v INTEGER)")
        self.stopping = False
        self.service = NotificationService(
            lambda event: None, SlackDelivery(endpoint(), opener=Transport()),
            stopping=lambda: self.stopping, settle_overshoot_seconds=0.3)
        self.addCleanup(self.service.close)
        self.calls = []

    def callback(self, result):
        # A callback whose transaction waits for two locks (a presence claim).
        self.calls.append(result)
        with bounded_transaction(self.db):
            self.db.execute("INSERT INTO claims VALUES (1)")

    def submit_and_finish(self):
        self.assertEqual(DeliveryResult.PENDING, self.service.record(
            NotificationKind.RECORDING_HEALTH_FAILURE, at=datetime.now(timezone.utc),
            on_complete=self.callback))
        until = time.monotonic() + 5
        while not any(entry[2] for entry in self.service._pending.values()):
            for identifier, result in self.service._worker.results():
                self.service._pending[identifier][2] = result
            self.assertLess(time.monotonic(), until)
            time.sleep(0.01)

    def test_a_callback_with_two_lock_waits_ends_by_the_overshoot(self):
        self.submit_and_finish()
        locks = _Locks(self, self.path, reserved_for=0.2)
        deadline = time.monotonic() + 0.1
        self.service.poll(deadline)
        elapsed_past = time.monotonic() - deadline
        locks.close()
        self.assertEqual([DeliveryResult.SENT], self.calls)
        # Its BEGIN waited 0.2 s, its COMMIT until deadline + 0.3 s, then it
        # failed: never a busy timeout of 5 s for each lock.
        self.assertLess(elapsed_past, 0.3 + MARGIN)
        # The callback failed and is retried by the next poll.
        self.assertEqual(1, self.service.pending_count)
        self.assertTrue(self.service.local_delivery_failed)
        self.assertEqual(DEFAULT_BUSY_MS, self.db.execute("PRAGMA busy_timeout").fetchone()[0])
        self.service.poll(time.monotonic() + 1)
        self.assertEqual(0, self.service.pending_count)
        self.assertEqual([(1,)], self.db.execute("SELECT v FROM claims").fetchall())

    def test_once_stopping_a_poll_without_deadline_does_nothing(self):
        self.submit_and_finish()
        self.stopping = True
        self.assertEqual((), self.service.poll())
        self.assertEqual([], self.calls)
        self.assertEqual(1, self.service.pending_count)
        # The settles poll with their deadline.
        self.assertEqual(1, len(self.service.poll(time.monotonic() + 1)))
        self.assertEqual([DeliveryResult.SENT], self.calls)

    def test_a_failed_submission_once_stopping_is_not_left_in_flight(self):
        # `_enqueue`'s own poll after a failed submission is gated the same
        # way; the refused delivery then moves to the bounded retry buffer
        # (PR #400 review), so it is not taken as in flight, and the stop's
        # last write records it as `failed`.
        self.stopping = True
        written = []
        service = NotificationService(
            written.append, SlackDelivery(endpoint(), opener=Transport()),
            stopping=lambda: self.stopping, local_batch_sink=lambda events: written.extend(events))
        self.addCleanup(service.close)
        event_id = uuid4()
        with mock.patch.object(service, "_poll", wraps=service._poll) as work, \
                mock.patch.object(service._worker, "submit", side_effect=RuntimeError):
            self.assertEqual(DeliveryResult.FAILED, service.record(
                NotificationKind.RECORDING_HEALTH_FAILURE, at=datetime.now(timezone.utc),
                event_id=event_id))
        work.assert_not_called()
        self.assertFalse(service.in_flight(event_id))
        self.assertTrue(service.retained(event_id))
        self.assertEqual(0, service.pending_count)
        written.clear()
        self.assertEqual(1, service.persist_completed())
        self.assertEqual([(event_id, DeliveryResult.FAILED)],
                         [(event.event_id, event.delivery) for event in written])
        # Before the stop the submission failure is written at once, as before.
        self.stopping = False
        written.clear()
        with mock.patch.object(service._worker, "submit", side_effect=RuntimeError):
            other = uuid4()
            service.record(NotificationKind.RECORDING_HEALTH_FAILURE,
                           at=datetime.now(timezone.utc), event_id=other)
        self.assertFalse(service.in_flight(other))
        self.assertFalse(service.retained(other))
        self.assertEqual(DeliveryResult.FAILED, written[-1].delivery)

    def test_without_a_stop_a_poll_without_deadline_is_unbounded_as_before(self):
        self.submit_and_finish()
        with mock.patch("app.notifications.service.bounded_lock_waits") as bound:
            self.service.poll()
        bound.assert_not_called()
        self.assertEqual([DeliveryResult.SENT], self.calls)

    def test_the_overshoot_must_be_valid(self):
        for value in (-1, 61, "5", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                NotificationService(lambda event: None, settle_overshoot_seconds=value)
        with self.assertRaises(ValueError):
            NotificationService(lambda event: None, stopping=True)


class PresenceCallbackPathTests(unittest.TestCase):
    """The real presence completion runs through the bounded transaction."""

    def test_complete_action_uses_the_bounded_transaction(self):
        with TemporaryDirectory(prefix="sentinel-presence-bound-") as directory:
            database = Database(Path(directory) / "state.sqlite3")
            with closing(database.connect()) as db:
                migrate(db, APPLICATION_MIGRATIONS)
            service = PresenceService(database, reservation=nullcontext)
            with mock.patch("app.presence.service.bounded_transaction",
                            wraps=bounded_transaction) as bounded:
                service.complete_action(uuid4(), "notification", ActionResult.DELIVERED)
            bounded.assert_called_once()


if __name__ == "__main__":
    unittest.main()
