"""Real RecordingStore integration; every database/media root is disposable."""

from pathlib import Path
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from uuid import uuid4
import sqlite3
import threading
import unittest
import zlib

from app.audit import AuditAction, AuditOutcome, AuditStore, OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.audit.schema import audit_migration
from app.cameras.registry import CameraRegistry
from app.media.recording import Limits, RecordingError, RecordingStore, RootIdentity, Segment
from app.media.recording.schema import recording_migration
from app.storage.database import Database
from app.storage.migrations import BUILTIN_MIGRATIONS, migrate
from app.storage.policy import (
    ExpectedFilesystem, FilesystemSpace, MainStoragePolicy, StorageLimits, StorageState, StorageTransition,
)
from app.storage.retention import (
    Action, DAY_MS, RecordingBrowser, RetentionPeriods, RetentionService, StorageAudit,
    storage_audit_migration,
)
from app.notifications.schedule import DailySummaryScheduler, notification_migration
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from zoneinfo import ZoneInfo
from tests.test_recording import SyntheticValidator
from tests.test_storage_notifications import Transport, drain, endpoint, summary


class RealRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="sentinel-storage-integration-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "media"
        self.root.mkdir(mode=0o700)
        info = self.root.stat()
        identity = RootIdentity(info.st_dev, info.st_ino)
        self.db = sqlite3.connect(base / "metadata.sqlite", isolation_level=None)
        (base / "metadata.sqlite").chmod(0o600)
        self.addCleanup(self.db.close)
        migrate(self.db, BUILTIN_MIGRATIONS + (recording_migration(len(BUILTIN_MIGRATIONS) + 1), storage_audit_migration(len(BUILTIN_MIGRATIONS) + 2), audit_migration(len(BUILTIN_MIGRATIONS) + 3)))
        self.metadata = Database(base / "metadata.sqlite")
        self.now = 5 * DAY_MS
        self.audit = StorageAudit(self.db, reservation=lambda: self.policy.control())
        self.policy = MainStoragePolicy(
            StorageLimits(recording_limit_bytes=100_000, critical_allowance_bytes=10_000,
                          hard_reserve_bytes=4096, pressure_free_bytes=8192,
                          recovery_free_bytes=16_384, recovery_allocation_bytes=90_000,
                          write_overhead_bytes=4096, max_request_bytes=1024,
                          cleanup_batch_size=10),
            ExpectedFilesystem(self.root, identity, base / "metadata.sqlite").snapshot, lambda: self.now, self.audit.append,
        )
        self.store = RecordingStore(
            self.db, self.root, identity,
            Limits(pre_roll_bytes=4096, max_segment_bytes=512, max_segment_ms=30_000,
                   max_active_recordings=8, max_spool_segments=16, max_segments_per_recording=100),
            self.policy, SyntheticValidator(),
        )
        self.addCleanup(self.store.close)
        self.retention = RetentionService(self.store)
        self.policy.bind(self.store, self.retention)

    def completed(self, at_ms=DAY_MS):
        source, stream = uuid4(), uuid4()
        recording = self.store.start_manual(source, at_ms, duration_ms=1000)
        segment = Segment(source, stream, 0, at_ms, at_ms + 1000, "synthetic", "deflate",
                          zlib.compress(b"generated geometric test payload" * 4))
        self.store.append(segment)
        self.store.finish(recording)
        self.store.release_source(source)
        return recording

    def test_real_retention_expires_unstarred_but_preserves_starred_and_agent_data(self):
        expired, starred = self.completed(), self.completed()
        self.store.set_starred(starred, True)
        self.db.execute("CREATE TABLE synthetic_agent_incidents (id TEXT PRIMARY KEY, expiry_ms INTEGER)")
        self.db.execute("INSERT INTO synthetic_agent_incidents VALUES ('synthetic-agent', ?)",
                        (61 * DAY_MS,))
        used = self.store.usage_bytes()
        self.assertEqual(1, self.retention.expired(22 * DAY_MS, 10))
        self.assertEqual([str(starred)], [row["id"] for row in self.store.list_recordings(limit=10)])
        self.assertLess(self.store.usage_bytes(), used)
        self.assertEqual(1, self.db.execute("SELECT COUNT(*) FROM synthetic_agent_incidents").fetchone()[0])
        with self.assertRaisesRegex(RecordingError, "NOT_FOUND"):
            self.store.manifest(expired)
        self.assertTrue(self.store.manifest(starred)["segments"])

    def test_default_retention_boundary_and_audit_90_days_are_independent(self):
        recording = self.completed()
        self.assertEqual((20, 90), (RetentionPeriods().recording_days, RetentionPeriods().audit_days))
        self.assertEqual(0, self.retention.expired(21 * DAY_MS, 10))
        self.assertEqual(1, self.retention.expired(21 * DAY_MS + 1000, 10))
        self.audit.append(StorageTransition(StorageState.NORMAL, StorageState.PRESSURE, DAY_MS))
        self.audit.append(StorageTransition(StorageState.PRESSURE, StorageState.NORMAL, 30 * DAY_MS))
        self.assertEqual(1, self.audit.expire(100 * DAY_MS))
        self.assertEqual(30 * DAY_MS, self.db.execute("SELECT at_ms FROM storage_state_audit").fetchone()[0])
        with self.assertRaises(RecordingError):
            self.store.manifest(recording)

    def test_policy_reclaims_actual_expired_segments_before_new_write(self):
        recording = self.completed()
        self.assertGreater(self.store.usage_bytes(), 0)
        self.now = 30 * DAY_MS
        self.policy.admit(1, critical=False)
        try:
            self.assertEqual(0, self.store.usage_bytes())
            self.assertEqual(4097, self.policy.status().reserved_bytes)
        finally:
            self.policy.release()
        self.assertFalse(list(self.root.glob('*.seg')))
        with self.assertRaises(RecordingError):
            self.store.manifest(recording)

    def test_domain_browser_denies_by_default_and_live_only_reveals_no_history(self):
        recording = self.completed()
        default = RecordingBrowser(self.store)
        for operation in [lambda: default.list(), lambda: default.manifest(recording),
                          lambda: default.star(recording, True), lambda: default.delete(recording)]:
            with self.assertRaisesRegex(RecordingError, "ACCESS_DENIED"):
                operation()
        checked = []
        def live_only(action):
            checked.append(action)
            raise RecordingError("RECORDING_ACCESS_DENIED")
        with self.assertRaises(RecordingError):
            RecordingBrowser(self.store, live_only).list()
        self.assertEqual([Action.READ], checked)
        self.assertEqual(1, len(self.store.list_recordings(limit=10)))

    def test_recordings_view_is_read_only_owner_can_star_unstar_delete(self):
        recording = self.completed()
        def viewer(action):
            if action != Action.READ:
                raise RecordingError("RECORDING_ACCESS_DENIED")
        browser = RecordingBrowser(self.store, viewer, self.policy.guard_metadata)
        self.assertEqual(str(recording), browser.list()[0]["id"])
        self.assertTrue(browser.manifest(recording)["segments"])
        for operation in [lambda: browser.star(recording, True), lambda: browser.delete(recording)]:
            with self.assertRaises(RecordingError):
                operation()
        security_audit = self.security_audit()
        owner = RecordingBrowser(self.store, lambda _: None, self.policy.guard_metadata,
                                 administration=self.administration(security_audit))
        owner.star(recording, True, actor_context="synthetic-owner")
        self.assertEqual(0, self.retention.oldest(10))
        owner.star(recording, False, actor_context="synthetic-owner")
        owner.star(recording, True, actor_context="synthetic-owner")
        self.assertGreater(owner.delete(recording, actor_context="synthetic-owner"), 0)
        self.assertEqual((), owner.list())
        # Every Owner recording change carries its security/admin record.
        records = security_audit.list_records()
        self.assertEqual(
            [AuditAction.DELETE_RECORDING, AuditAction.UPDATE_RECORDING,
             AuditAction.UPDATE_RECORDING, AuditAction.UPDATE_RECORDING],
            [record.action for record in records],
        )
        self.assertEqual({AuditOutcome.SUCCEEDED},
                         {record.outcome for record in records})

    def security_audit(self):
        return AuditStore(self.metadata, reservation=self.store.control_reservation)

    def administration(self, security_audit, actor="synthetic-owner"):
        class SyntheticOwner:
            def require_owner(self, actor_context):
                if actor_context != actor:
                    raise PermissionError("not the deployment owner")

        return OwnerAdministration(
            OwnerAuditService(security_audit, SyntheticOwner()),
            CameraRegistry(self.metadata),
        )

    def test_owner_recording_mutation_requires_the_audited_boundary(self):
        recording = self.completed()
        unaudited = RecordingBrowser(self.store, lambda _: None, self.policy.guard_metadata)
        for operation in (lambda: unaudited.star(recording, True),
                          lambda: unaudited.delete(recording)):
            with self.assertRaisesRegex(RecordingError, "RECORDING_AUDIT_UNAVAILABLE"):
                operation()
        self.assertEqual(0, self.store.list_recordings(limit=1)[0]["starred"])

        security_audit = self.security_audit()
        denied = RecordingBrowser(self.store, lambda _: None, self.policy.guard_metadata,
                                  administration=self.administration(security_audit))
        # The facade's own permission check is not Owner authentication: the
        # audited boundary re-authorizes and records the denial.
        with self.assertRaises(PermissionError):
            denied.star(recording, True, actor_context={"synthetic": "not-owner"})
        self.assertEqual(0, self.store.list_recordings(limit=1)[0]["starred"])
        self.assertEqual([AuditOutcome.DENIED],
                         [record.outcome for record in security_audit.list_records()])

    def test_write_guard_denies_owner_mutation_and_audit_before_writing(self):
        recording = self.completed()
        owner_without_storage = RecordingBrowser(self.store, lambda _: None)
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            owner_without_storage.star(recording, True)
        self.assertEqual(0, self.store.list_recordings(limit=1)[0]["starred"])
        guarded = StorageAudit(self.db)
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            guarded.append(StorageTransition(StorageState.NORMAL, StorageState.PRESSURE, self.now))
        self.assertEqual(0, self.db.execute("SELECT COUNT(*) FROM storage_state_audit").fetchone()[0])

    def test_constructor_recovery_reserves_before_inventory_binding_and_commit(self):
        self.store.close()
        policy = MainStoragePolicy(self.policy.limits, self.policy._space, lambda: self.now,
                                   lambda _: None)
        seen = []
        def trace(statement):
            if statement.startswith(("BEGIN", "UPDATE", "DELETE", "COMMIT")):
                seen.append(policy._reserved_total)
        self.db.set_trace_callback(trace)
        reopened = RecordingStore(self.db, self.root, self.store.expected_root,
                                  self.store.limits, policy, SyntheticValidator())
        self.addCleanup(reopened.close)
        self.db.set_trace_callback(None)
        self.assertTrue(seen)
        self.assertTrue(all(value == policy.limits.write_overhead_bytes for value in seen))
        self.assertIsNone(policy._inventory)
        self.assertFalse(policy._reservation)

    def test_hard_stop_constructor_does_not_begin_or_mutate_and_audit_failure_is_visible(self):
        self.store.close()
        policy = MainStoragePolicy(self.policy.limits, lambda: FilesystemSpace(4096, 100_000),
                                   lambda: self.now, lambda event: audit.append(event))
        audit = StorageAudit(self.db, reservation=policy.control)
        statements = []
        self.db.set_trace_callback(statements.append)
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            RecordingStore(self.db, self.root, self.store.expected_root,
                           self.store.limits, policy, SyntheticValidator())
        self.db.set_trace_callback(None)
        self.assertFalse(any(s.startswith(("BEGIN", "UPDATE", "INSERT", "DELETE")) for s in statements))
        self.assertEqual(StorageState.HARD_STOP, policy.state)
        self.assertTrue(policy.audit_delivery_failed)
        self.assertFalse(policy._reservation)

    def test_audit_retention_is_bounded_and_oldest_first(self):
        for at in (3 * DAY_MS, DAY_MS, 2 * DAY_MS):
            self.audit.append(StorageTransition(StorageState.NORMAL, StorageState.PRESSURE, at))
        self.assertEqual(1, self.audit.expire(100 * DAY_MS, limit=1))
        self.assertEqual([2 * DAY_MS, 3 * DAY_MS], [row[0] for row in self.db.execute(
            'SELECT at_ms FROM storage_state_audit ORDER BY at_ms')])
        with self.assertRaises(RecordingError):
            self.audit.expire(100 * DAY_MS, limit=1001)

    def test_slow_slack_critical_and_daily_never_block_real_recording_or_write_from_worker(self):
        migrate(self.db, BUILTIN_MIGRATIONS + (recording_migration(len(BUILTIN_MIGRATIONS) + 1), storage_audit_migration(len(BUILTIN_MIGRATIONS) + 2), audit_migration(len(BUILTIN_MIGRATIONS) + 3), notification_migration(len(BUILTIN_MIGRATIONS) + 4)))
        self.db.execute('CREATE TABLE synthetic_notifications (id TEXT PRIMARY KEY, delivery TEXT)')
        entered, release = threading.Event(), threading.Event()
        owner = threading.get_ident()
        def local(event):
            self.assertEqual(owner, threading.get_ident())
            with self.policy.control():
                self.db.execute('INSERT INTO synthetic_notifications VALUES (?,?) ON CONFLICT(id) '
                                'DO UPDATE SET delivery=excluded.delivery', (str(event.event_id), event.delivery.value))
        class SlowTransport(Transport):
            def open(self, request, *, timeout):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test release missing')
                return super().open(request, timeout=timeout)
        service = NotificationService(local, SlackDelivery(endpoint(), opener=SlowTransport()), queue_capacity=2)
        self.addCleanup(release.set)
        self.addCleanup(service.close)
        now = datetime(2026, 1, 1, 23, tzinfo=timezone.utc)
        self.assertEqual(DeliveryResult.PENDING, service.record(NotificationKind.RECORDING_HEALTH_FAILURE, at=now))
        self.assertTrue(entered.wait(2))
        scheduler = DailySummaryScheduler(self.db, ZoneInfo('UTC'), service, self.policy.control)
        self.assertEqual(DeliveryResult.PENDING, scheduler.tick(now, summary()))
        recording = self.completed()
        self.assertTrue(self.store.manifest(recording)['segments'])
        self.assertFalse(release.is_set())
        self.assertEqual('pending', scheduler.status()['result'])
        release.set()
        drain(self, service)
        self.assertEqual('sent', scheduler.status()['result'])
        self.assertEqual(['sent', 'sent'], [row[0] for row in self.db.execute('SELECT delivery FROM synthetic_notifications')])
