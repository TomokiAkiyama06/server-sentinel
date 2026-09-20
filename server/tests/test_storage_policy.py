"""Main-host quota/reserve behavior on synthetic inventories and disposable roots."""

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4
import threading
import unittest

from app.media.recording.model import RecordingError
from app.media.recording.store import RootIdentity
from app.storage.policy import (
    ExpectedFilesystem, FilesystemSpace, MainStoragePolicy, StorageLimits, StorageState,
)
from app.storage.retention import DAY_MS, RetentionService


LIMITS = StorageLimits(recording_limit_bytes=1000, critical_allowance_bytes=300,
                       hard_reserve_bytes=100, pressure_free_bytes=300,
                       recovery_free_bytes=500, recovery_allocation_bytes=800,
                       write_overhead_bytes=20, max_request_bytes=500,
                       cleanup_batch_size=10)


class SyntheticInventory:
    def __init__(self):
        self.rows = []
        self.free = 10_000
        self.deleted = []
        self.before_delete = None

    def add(self, size, ended_ms, *, starred=False, critical=False, active=False):
        row = dict(id=str(uuid4()), size=size, ended_ms=ended_ms, starred=starred,
                   critical=critical, active=active)
        self.rows.append(row)
        return row

    def usage_bytes(self, *, starred_only=False, critical_only=False):
        return sum(row["size"] for row in self.rows
                   if (not starred_only or row["starred"])
                   and (not critical_only or row["critical"]))

    def retention_candidates(self, *, before_ms, limit):
        return sorted((row for row in self.rows if not row["starred"] and not row["active"]
                       and (before_ms is None or row["ended_ms"] <= before_ms)),
                      key=lambda row: (row["ended_ms"], row["id"]))[:limit]

    def delete_recording(self, recording_id, *, owner_requested=False):
        row = next(row for row in self.rows if row["id"] == str(recording_id))
        if self.before_delete:
            self.before_delete(row)
        if row["active"] or row["starred"] and not owner_requested:
            raise RecordingError("RECORDING_DELETE_REFUSED")
        self.rows.remove(row)
        self.deleted.append(row["id"])
        self.free += row["size"]
        return row["size"]

    def space(self):
        return FilesystemSpace(self.free, 100_000)


class StoragePolicyTests(unittest.TestCase):
    def setUp(self):
        self.inventory = SyntheticInventory()
        self.events = []
        self.policy = self.make_policy()

    def make_policy(self):
        policy = MainStoragePolicy(LIMITS, self.inventory.space,
                                   lambda: 90 * DAY_MS, self.events.append)
        policy.bind(self.inventory, RetentionService(self.inventory))
        return policy

    def test_no_unconfigured_thresholds_and_invalid_hysteresis(self):
        for field in LIMITS.__dataclass_fields__:
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(LIMITS, **{field: True})
        for change in [dict(hard_reserve_bytes=300), dict(recovery_free_bytes=299),
                       dict(recovery_allocation_bytes=1000), dict(cleanup_batch_size=1001)]:
            with self.assertRaises(ValueError):
                replace(LIMITS, **change)

    def test_reservation_covers_media_and_overhead_until_release(self):
        self.policy.admit(100, critical=False)
        self.assertEqual(120, self.policy.status().reserved_bytes)
        with self.assertRaisesRegex(RecordingError, "INVALID_RESERVATION"):
            self.policy.admit(1, critical=False)
        self.assertEqual(120, self.policy.status().reserved_bytes)
        self.policy.release()
        self.assertEqual(0, self.policy.status().reserved_bytes)
        with self.assertRaisesRegex(RecordingError, "INVALID_RESERVATION"):
            self.policy.release()

    def test_other_process_consumption_is_resampled_and_reserve_never_admitted(self):
        self.policy.admit(100, critical=False)
        self.policy.release()
        self.inventory.free = 119
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            self.policy.admit(1, critical=True)
        self.assertEqual(StorageState.HARD_STOP, self.policy.state)
        self.assertEqual([], self.inventory.deleted)
        self.assertEqual(StorageState.HARD_STOP, self.events[-1].current)

    def test_pending_media_cannot_consume_hard_reserve_in_status(self):
        self.policy.admit(100, critical=False)
        self.inventory.free = 210
        self.assertEqual(StorageState.HARD_STOP, self.policy.status().state)
        self.policy.release()

    def test_expired_before_oldest_and_never_starred_or_active(self):
        starred = self.inventory.add(400, DAY_MS, starred=True)
        active = self.inventory.add(100, DAY_MS, active=True)
        fresh = self.inventory.add(400, 85 * DAY_MS)
        expired = self.inventory.add(300, 60 * DAY_MS)
        self.policy.admit(200, critical=False)
        self.assertEqual([expired["id"], fresh["id"]], self.inventory.deleted)
        self.assertEqual({starred["id"], active["id"]}, {row["id"] for row in self.inventory.rows})
        self.policy.release()

    def test_ordinary_and_manual_metadata_work_denied_in_pressure(self):
        self.inventory.add(1000, DAY_MS, starred=True)
        for size in (0, 1, 100):
            with self.assertRaisesRegex(RecordingError, "STORAGE_PRESSURE"):
                self.policy.admit(size, critical=False)
        self.assertEqual(StorageState.PRESSURE, self.policy.state)

    def test_critical_allowance_is_bounded_across_calls_and_policy_restart(self):
        self.inventory.add(1000, DAY_MS, starred=True)
        for _ in range(2):
            self.policy.admit(100, critical=True)
            self.inventory.add(100, 90 * DAY_MS, starred=True, critical=True)
            self.policy.release()
        self.policy = self.make_policy()
        with self.assertRaisesRegex(RecordingError, "STORAGE_PRESSURE"):
            self.policy.admit(100, critical=True)
        self.assertEqual(1200, self.inventory.usage_bytes())

    def test_critical_allowance_never_overrides_physical_reserve(self):
        self.inventory.free = 200
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            self.policy.admit(100, critical=True)

    def test_transition_audit_shares_the_admitted_metadata_budget(self):
        self.inventory.free = 220
        reserved_during_audit = []
        def audit(_):
            with policy.control():
                reserved_during_audit.append(policy._reserved_total)
                self.inventory.free -= LIMITS.write_overhead_bytes
        policy = MainStoragePolicy(LIMITS, self.inventory.space, lambda: 0, audit)
        policy.bind(self.inventory, RetentionService(self.inventory))
        policy.admit(100, critical=True)
        self.assertEqual([120], reserved_during_audit)
        # Audit consumed the metadata part of this same reservation; writing
        # admitted media still leaves the hard reserve, with no second budget.
        self.assertEqual(LIMITS.hard_reserve_bytes, self.inventory.free - 100)
        policy.release()

    def test_recovery_hysteresis_prevents_threshold_oscillation(self):
        self.inventory.free = 299
        self.assertEqual(StorageState.PRESSURE, self.policy.status().state)
        for available in (301, 499, 302, 490):
            self.inventory.free = available
            self.assertEqual(StorageState.PRESSURE, self.policy.status().state)
        self.inventory.free = 500
        self.assertEqual(StorageState.NORMAL, self.policy.status().state)
        self.assertEqual(2, len(self.events))

    def test_pressure_cleanup_reclaims_through_recovery_thresholds(self):
        oldest = self.inventory.add(300, 80 * DAY_MS)
        next_oldest = self.inventory.add(200, 81 * DAY_MS)
        retained = self.inventory.add(700, 82 * DAY_MS)
        self.assertEqual(StorageState.PRESSURE, self.policy.status().state)

        self.policy.admit(100, critical=False)

        self.assertEqual([oldest["id"], next_oldest["id"]], self.inventory.deleted)
        self.assertEqual([retained], self.inventory.rows)
        self.assertEqual(StorageState.NORMAL, self.policy.status().state)
        self.policy.release()

    def test_hard_stop_cleanup_reclaims_through_recovery_thresholds(self):
        oldest = self.inventory.add(250, 80 * DAY_MS)
        next_oldest = self.inventory.add(200, 81 * DAY_MS)
        self.inventory.free = 99
        self.assertEqual(StorageState.HARD_STOP, self.policy.status().state)
        self.inventory.free = 221

        self.policy.admit(100, critical=False)

        self.assertEqual([oldest["id"], next_oldest["id"]], self.inventory.deleted)
        self.assertEqual(StorageState.NORMAL, self.policy.status().state)
        self.policy.release()

    def test_cleanup_reclaims_below_pressure_allocation_boundary(self):
        row = self.inventory.add(900, 80 * DAY_MS)

        self.policy.admit(100, critical=False)

        self.assertEqual([row["id"]], self.inventory.deleted)
        self.assertEqual(StorageState.NORMAL, self.policy.status().state)
        self.policy.release()

    def test_star_race_rechecks_before_delete_and_stops_admission(self):
        row = self.inventory.add(1000, DAY_MS)
        self.inventory.before_delete = lambda item: item.update(starred=True)
        with self.assertRaisesRegex(RecordingError, "STORAGE_PRESSURE"):
            self.policy.admit(100, critical=True)
        self.assertEqual([row], self.inventory.rows)
        self.assertTrue(self.policy.status().cleanup_failed)

    def test_policy_rejects_cross_worker_use(self):
        errors = []
        def run():
            try:
                self.policy.admit(100, critical=False)
            except RecordingError as error:
                errors.append(str(error))
        worker = threading.Thread(target=run)
        worker.start()
        worker.join()
        self.assertEqual(["STORAGE_POLICY_UNAVAILABLE"], errors)

    def test_audit_failure_is_visible_without_raw_exception(self):
        def failed(_):
            raise RuntimeError("synthetic private detail")
        policy = MainStoragePolicy(LIMITS, self.inventory.space, lambda: 0, failed)
        policy.bind(self.inventory, RetentionService(self.inventory))
        self.inventory.free = 0
        status = policy.status()
        self.assertEqual(StorageState.HARD_STOP, status.state)
        self.assertTrue(status.audit_delivery_failed)
        self.assertNotIn("synthetic private detail", repr(status))

    def test_invalid_snapshot_fails_closed(self):
        policy = MainStoragePolicy(LIMITS, lambda: FilesystemSpace(-1, 100),
                                   lambda: 0, self.events.append)
        policy.bind(self.inventory, RetentionService(self.inventory))
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            policy.admit(1, critical=False)


class ExpectedFilesystemTests(unittest.TestCase):
    def test_real_disposable_filesystem_and_missing_substituted_symlink_roots(self):
        with TemporaryDirectory(prefix="sentinel-storage-root-") as temp:
            root = Path(temp) / "media"
            root.mkdir(mode=0o700)
            info = root.stat()
            metadata = Path(temp) / 'metadata.sqlite'
            metadata.touch(mode=0o600)
            checker = ExpectedFilesystem(root, RootIdentity(info.st_dev, info.st_ino), metadata)
            self.assertGreater(checker.snapshot().available_bytes, 0)
            root.chmod(0o500)
            with self.assertRaises(RecordingError):
                checker.snapshot()
            root.chmod(0o700)
            metadata.chmod(0o400)
            with self.assertRaises(RecordingError):
                checker.snapshot()
            metadata.chmod(0o600)
            metadata.chmod(0o644)
            with self.assertRaises(RecordingError):
                checker.snapshot()
            metadata.chmod(0o600)
            metadata.rename(Path(temp) / 'saved.sqlite')
            metadata.symlink_to(Path(temp) / 'saved.sqlite')
            with self.assertRaises(RecordingError):
                checker.snapshot()
            metadata.unlink()
            (Path(temp) / 'saved.sqlite').rename(metadata)
            root.rename(Path(temp) / "saved")
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                checker.snapshot()
            self.assertFalse(root.exists())
            root.mkdir(mode=0o700)
            with self.assertRaises(RecordingError):
                checker.snapshot()
            root.rmdir()
            root.symlink_to(Path(temp) / "saved", target_is_directory=True)
            with self.assertRaises(RecordingError):
                checker.snapshot()
