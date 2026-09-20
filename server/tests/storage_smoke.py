"""Real disposable recording/policy path under the smoke's network audit hook."""

from datetime import datetime, timezone
from uuid import uuid4
from zoneinfo import ZoneInfo
import zlib

from app.media.recording import Limits, RecordingError, RecordingStore, RootIdentity, Segment
from app.media.recording.schema import recording_migration
from app.notifications.schedule import DailySummaryScheduler, notification_migration
from app.notifications.service import NotificationKind, NotificationService
from app.notifications.slack import DeliveryResult, SlackDelivery
from app.storage.database import Database
from app.storage.migrations import BUILTIN_MIGRATIONS, migrate
from app.storage.policy import ExpectedFilesystem, MainStoragePolicy, StorageLimits, StorageState
from app.storage.retention import RecordingBrowser, RetentionService, StorageAudit, storage_audit_migration
from tests.test_recording import SyntheticValidator
from tests.test_storage_notifications import Transport, endpoint, summary


def run_storage_smoke(base, scenario):
    root = base / 'policy-media'
    root.mkdir(mode=0o700)
    metadata = base / 'policy-metadata.sqlite'
    db = Database(metadata).connect()
    try:
        migrate(db, BUILTIN_MIGRATIONS + (recording_migration(len(BUILTIN_MIGRATIONS) + 1), storage_audit_migration(len(BUILTIN_MIGRATIONS) + 2), notification_migration(len(BUILTIN_MIGRATIONS) + 3)))
        identity = RootIdentity(root.stat().st_dev, root.stat().st_ino)
        checker = ExpectedFilesystem(root, identity, metadata)
        policy = MainStoragePolicy(StorageLimits(100_000, 10_000, 4096, 8192, 16_384, 90_000,
                                                4096, 1024, 10),
                                   checker.snapshot, lambda: 30_000, lambda event: audit.append(event))
        audit = StorageAudit(db, reservation=policy.control)
        limits = Limits(pre_roll_bytes=4096, max_segment_bytes=512, max_segment_ms=30_000,
                        max_active_recordings=4, max_spool_segments=16, max_segments_per_recording=100)
        with RecordingStore(db, root, identity, limits, policy, SyntheticValidator()) as store:
            policy.bind(store, RetentionService(store))
            source = uuid4()
            recording = store.start_manual(source, 30_000, duration_ms=1000)
            store.append(Segment(source, uuid4(), 0, 30_000, 31_000, 'synthetic', 'deflate',
                                 zlib.compress(b'generated geometric test payload' * 4)))
            store.finish(recording)
            store.release_source(source)
            browser = RecordingBrowser(store, lambda _: None, policy.guard_metadata)
            if scenario == 'normal':
                browser.star(recording, True)
                assert RetentionService(store).oldest(10) == 0
                assert browser.list()[0]['starred']
                assert browser.delete(recording) > 0
                assert browser.list() == ()
            else:
                root.rename(base / 'policy-detached')
                try:
                    policy.admit(1, critical=True)
                except RecordingError as error:
                    assert str(error) == 'STORAGE_HARD_STOP'
                else:
                    raise AssertionError('missing policy filesystem accepted')
                assert policy.state == StorageState.HARD_STOP
                assert policy.audit_delivery_failed
                assert not root.exists()
                # Restore only this synthetic directory so scheduling can write.
                (base / 'policy-detached').rename(root)
            transport = Transport(error=RuntimeError('generated private error') if scenario == 'error' else None)
            local = []
            service = NotificationService(local.append, SlackDelivery(endpoint(), opener=transport))
            now = datetime(2026, 1, 1, 23, tzinfo=timezone.utc)
            assert service.record(NotificationKind.PERSON, at=now) == DeliveryResult.SUPPRESSED
            scheduler = DailySummaryScheduler(db, ZoneInfo('UTC'), service, policy.control)
            expected = DeliveryResult.FAILED if scenario == 'error' else DeliveryResult.SENT
            assert scheduler.tick(now, summary()) == DeliveryResult.PENDING
            assert service._worker.ready.wait(2)
            service.poll()
            assert service.last_delivery == expected
            assert scheduler.tick(now, summary()) == DeliveryResult.SUPPRESSED
            assert len(transport.requests) == 1
            assert len(local) == 3
            service.close()
    finally:
        db.close()
