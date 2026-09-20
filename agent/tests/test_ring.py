"""Temporary-filesystem segments with synthetic compressed bytes and fake quotas."""

import hashlib
import json
import os
import random
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4
import zlib

from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_ledger import Ledger
from media_capture_agent.ring_models import (POST, PRE, RETENTION, SECOND, RingConfig,
                                            RingRefused, SegmentProfile)
from media_capture_agent.storage import MediaStore, StorageRefused
from tests.support import SOURCE, settings


PAYLOAD = zlib.compress(b"generated-pattern-0001" * 8)
T0 = 3600 * SECOND
LEDGER_BYTES = 16 * 1024 * 1024


class AllowControls:
    def require_owner(self, operation):
        pass

    def require_preserve(self):
        pass


class Quota:
    def __init__(self, root, capacity=2 * 1024 * 1024 * 1024):
        self.root, self.capacity, self.other = root, capacity, 0

    def used(self):
        return sum(path.stat().st_blocks * 512 for path in self.root.glob("*.segment"))

    def __call__(self, descriptor):
        actual = os.fstatvfs(descriptor)
        values = list(actual)
        values[4] = max(0, (self.capacity - self.used() - self.other) // actual.f_frsize)
        return os.statvfs_result(values)


class RingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.settings = settings(Path(self.temporary.name))
        self.quota = Quota(self.settings.media_root)
        self.store = MediaStore(self.settings, space=self.quota,
                                stable_device=lambda _expected: True)
        self.addCleanup(self.store.close)
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=LEDGER_BYTES, authority=AllowControls())
        self.addCleanup(lambda: self.ring.close())
        self.profile = SegmentProfile(SOURCE, 800, 400, 60 * SECOND, 100)

    def configure(self, mode="duration", value=600, profiles=None):
        return self.ring.configure(RingConfig(mode, value), profiles or (self.profile,), now_us=T0,
                                   clock_trusted=True)

    def append(self, start, *, source=SOURCE, trusted=True):
        return self.ring.append(source, start, start + 60 * SECOND, PAYLOAD,
                                now_us=start + 60 * SECOND, clock_trusted=trusted)

    def warm(self, *, profiles=None):
        self.configure(profiles=profiles)
        for start in range(T0 - PRE, T0, 60 * SECOND):
            for profile in profiles or (self.profile,):
                self.append(start, source=profile.source_id)

    def loss(self):
        self.ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                     now_us=T0, clock_trusted=True)
        return self.ring.observe_connection(authenticated=True, connected=False, unexpected=True,
                                            now_us=T0, clock_trusted=True)

    def finish(self):
        for start in range(T0, T0 + POST, 60 * SECOND):
            self.append(start)

    def restart(self):
        maximum = self.ring.ledger.maximum_bytes
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=maximum, authority=AllowControls())

    def test_owner_controls_and_preserve_commands_default_deny(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=LEDGER_BYTES)
        with self.assertRaisesRegex(RingRefused, "owner_authorization_required"):
            self.configure()
        with self.assertRaisesRegex(RingRefused, "authenticated_preserve_required"):
            self.ring.preserve("camera_tamper", T0 - PRE, T0 + POST, now_us=T0, clock_trusted=True)
        with self.assertRaisesRegex(RingRefused, "owner_authorization_required"):
            self.ring.delete_incident(uuid4(), now_us=T0, clock_trusted=True)

    def test_duration_and_capacity_reject_less_than_pre_window(self):
        with self.assertRaises(RingRefused):
            RingConfig("duration", 599)
        with self.assertRaisesRegex(RingRefused, "insufficient_pre_loss_capacity"):
            self.configure("capacity", self.profile.bytes_for(PRE, self.store.allocation_unit) - 1)

    def test_pre_only_filesystem_and_post_headroom_consumed_elsewhere_rejected(self):
        pre = self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.quota.capacity = pre + self.settings.safety_reserve_bytes
        with self.assertRaisesRegex(RingRefused, "insufficient_simultaneous_pre_post_budget"):
            self.configure()
        self.quota.capacity *= 3
        self.quota.other = self.quota.capacity - pre - self.settings.safety_reserve_bytes
        with self.assertRaisesRegex(RingRefused, "insufficient_simultaneous_pre_post_budget"):
            self.configure("capacity", pre)

    def test_exact_conservative_twenty_minute_budget_is_accepted(self):
        self.quota.capacity = (self.profile.bytes_for(PRE + POST, self.store.allocation_unit)
                               + self.settings.safety_reserve_bytes + self.ring.ledger_headroom)
        status = self.configure()
        self.assertEqual(status["state"], "degraded")
        self.assertEqual(status["reason"], "pre_loss_coverage_gap")

    def test_complete_pre_and_post_survive_main_loss_and_reconnect(self):
        self.warm()
        identifier = self.loss()
        self.finish()
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(result["has_gaps"])
        self.assertEqual(result["coverage"][str(SOURCE)]["intervals_us"], [(T0 - PRE, T0 + POST)])
        self.assertEqual(result["expires_at_us"], T0 + POST + RETENTION)
        self.ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                     now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(self.ring.incident(identifier, now_us=T0 + POST)["state"], "complete")
        self.restart()
        self.assertFalse(self.ring.incident(identifier, now_us=T0 + POST)["has_gaps"])

    def test_loss_is_once_per_authenticated_transition(self):
        self.configure()
        self.assertIsNone(self.ring.observe_connection(authenticated=False, connected=False,
                                                       unexpected=True, now_us=T0, clock_trusted=True))
        identifier = self.loss()
        self.assertIsInstance(identifier, UUID)
        for _ in range(10):
            self.assertIsNone(self.ring.observe_connection(authenticated=True, connected=False,
                                                           unexpected=True, now_us=T0, clock_trusted=True))
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 1)

    def test_critical_preserve_and_shared_files_count_once(self):
        self.warm()
        first = self.loss()
        second = self.ring.preserve("camera_tamper", T0 - PRE, T0 + POST, now_us=T0, clock_trusted=True)
        self.finish()
        one = self.ring.incident(first, now_us=T0 + POST)
        two = self.ring.incident(second, now_us=T0 + POST)
        status = self.ring.status(now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(one["allocated_bytes"], two["allocated_bytes"])
        self.assertEqual(status["protected_allocated_bytes"], one["allocated_bytes"])
        self.ring.delete_incident(first, now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(self.quota.used(), two["allocated_bytes"])
        self.ring.delete_incident(second, now_us=T0 + POST, clock_trusted=True)
        self.assertGreater(self.quota.used(), 0)
        self.assertFalse(self.ring.status(now_us=T0 + POST, clock_trusted=True)["pre_loss_coverage"][str(SOURCE)]["gaps_us"])
        self.ring.tick(now_us=T0 + POST + PRE, clock_trusted=True)
        self.assertEqual(self.quota.used(), 0)

    def test_expiry_is_sixty_days_after_completion_and_requires_trusted_clock(self):
        self.warm()
        identifier = self.loss()
        self.finish()
        expiry = T0 + POST + RETENTION
        self.ring.tick(now_us=expiry - 1, clock_trusted=True)
        self.assertEqual(self.ring.incident(identifier, now_us=expiry)["state"], "complete")
        self.ring.tick(now_us=expiry, clock_trusted=False)
        self.assertGreater(self.quota.used(), 0)
        self.ring.tick(now_us=expiry, clock_trusted=True)
        self.assertEqual(self.ring.incident(identifier, now_us=expiry)["state"], "deleted")
        self.assertEqual(self.quota.used(), 0)

    def test_gap_and_clock_uncertainty_never_report_complete_protection(self):
        self.configure()
        for start in range(T0 - PRE + 60 * SECOND, T0, 60 * SECOND):
            self.append(start, trusted=start != T0 - 120 * SECOND)
        identifier = self.loss()
        self.finish()
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["coverage"][str(SOURCE)]["gaps_us"], [
            (T0 - PRE, T0 - PRE + 60 * SECOND), (T0 - 120 * SECOND, T0 - 60 * SECOND),
        ])

    def test_storage_loss_preserves_existing_incident_and_reports_post_gap(self):
        self.warm()
        identifier = self.loss()
        before = self.quota.used()
        self.quota.other = self.quota.capacity - before - self.settings.safety_reserve_bytes
        with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
            self.append(T0)
        self.assertEqual(self.quota.used(), before)
        self.assertEqual(self.ring.status(now_us=T0, clock_trusted=True)["state"], "STORAGE_PRESSURE")
        self.ring.tick(now_us=T0 + POST, clock_trusted=True)
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["coverage"][str(SOURCE)]["gaps_us"], [(T0, T0 + POST)])

    def test_capacity_fifo_never_exceeds_selected_ordinary_bytes(self):
        limit = self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.configure("capacity", limit)
        for index in range(50):
            self.append(T0 + index * 60 * SECOND)
            status = self.ring.status(now_us=T0 + (index + 1) * 60 * SECOND, clock_trusted=True)
            self.assertLessEqual(status["ordinary_allocated_bytes"], limit)
        self.assertGreater(status["estimated_duration_us"], 0)

    def test_duration_fifo_and_projected_equivalent_are_reported(self):
        self.configure()
        for index in range(30):
            self.append(T0 + index * 60 * SECOND)
        status = self.ring.status(now_us=T0 + 1800 * SECOND, clock_trusted=True)
        self.assertEqual(status["mode"], "duration")
        self.assertEqual(status["selected_value"], 600)
        self.assertLessEqual(status["ordinary_allocated_bytes"], status["projected_maximum_bytes"])
        self.assertLessEqual(status["projected_expected_bytes"], status["projected_maximum_bytes"])
        self.assertEqual(len(self.store.list_segments()), 10)

    def test_write_pressure_never_shortens_selected_duration(self):
        self.configure(value=1200)
        for start in range(T0 - 1200 * SECOND, T0, 60 * SECOND):
            self.append(start)
        selected = UUID(self.ring._rows()[1]["id"])
        self.quota.other = self.quota.capacity - self.quota.used()
        with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
            self.append(T0)
        self.assertIn(selected, self.store.list_segments())
        status = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertIn(status["state"], {"STORAGE_PRESSURE", "STORAGE_HARD_STOP"})

    def test_existing_protected_incident_can_exhaust_next_incident_admission(self):
        self.warm()
        self.loss()
        self.finish()
        self.quota.capacity = self.quota.used() + self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.quota.other = 0
        with self.assertRaisesRegex(RingRefused, "insufficient_simultaneous_pre_post_budget"):
            self.ring.configure(RingConfig("duration", 600), (self.profile,), now_us=T0 + POST + PRE,
                                clock_trusted=True)

    def test_profile_cadence_and_bitrate_violation_refused_before_file_write(self):
        self.configure()
        with self.assertRaisesRegex(RingRefused, "profile_bound_violation"):
            self.ring.append(SOURCE, T0, T0 + SECOND, PAYLOAD, now_us=T0 + SECOND, clock_trusted=True)
        with self.assertRaisesRegex(RingRefused, "profile_bound_violation"):
            self.ring.append(SOURCE, T0, T0 + 60 * SECOND, b"x" * (self.profile.segment_bytes() + 1),
                             now_us=T0 + 60 * SECOND, clock_trusted=True)
        self.assertEqual(self.store.list_segments(), {})

    def test_restart_recovers_committed_file_after_interrupted_ledger_finalization(self):
        self.configure()
        identifier = self.append(T0)
        self.ring.db.execute("UPDATE segments SET state='writing' WHERE id=?", (str(identifier),))
        self.restart()
        self.assertEqual(self.ring.db.execute("SELECT state FROM segments").fetchone()[0], "stored")

    def test_restart_detects_missing_or_corrupt_protected_media_as_gaps(self):
        self.warm()
        identifier = self.loss()
        rows = self.ring._rows()
        missing, corrupt = UUID(rows[0]["id"]), UUID(rows[1]["id"])
        self.store.delete_segment(missing)
        (self.settings.media_root / (str(corrupt) + ".segment")).write_bytes(b"x" * len(PAYLOAD))
        self.restart()
        self.finish()
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["has_gaps"])
        self.assertIn(corrupt, self.store.list_segments())

    def test_missing_mount_never_creates_fallback_segment_directory(self):
        self.configure()
        self.store.mounts = lambda: []
        with self.assertRaises(RingRefused):
            self.append(T0)
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_ledger_is_private_single_writer_and_durable(self):
        self.configure()
        with self.assertRaises(RingRefused):
            DiskRing(self.settings, self.store, ledger_maximum_bytes=128 * 1024)
        self.assertEqual((self.settings.runtime_root / "ring.sqlite3").stat().st_mode & 0o777, 0o600)
        self.restart()
        self.assertEqual(self.ring.config, RingConfig("duration", 600))

    def test_four_source_loss_coverage_is_independent(self):
        profiles = tuple(SegmentProfile(UUID(int=100 + index), 800, 400, 60 * SECOND, 100)
                         for index in range(4))
        self.warm(profiles=profiles)
        identifier = self.loss()
        for start in range(T0, T0 + POST, 60 * SECOND):
            for profile in profiles:
                self.append(start, source=profile.source_id)
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(len(result["coverage"]), 4)
        self.assertFalse(result["has_gaps"])
        self.assertEqual(result["state"], "complete")

    def test_orphan_files_are_not_silently_deleted_or_credited_as_reclaimable(self):
        self.configure()
        orphan = uuid4()
        self.store.write_segment(orphan, PAYLOAD)
        self.restart()
        self.assertIn(orphan, self.store.list_segments())
        self.assertEqual(self.ring._budget(self.ring.profiles, T0)["reclaimable_allocated"], 0)

    def test_pending_corrupt_file_never_recovers_as_complete_after_fallocate(self):
        self.configure()
        identifier = uuid4()
        self.ring.db.execute("INSERT INTO segments VALUES (?,?,?,?,?,?,?,'writing',1)",
                             (str(identifier), str(SOURCE), T0, T0 + 60 * SECOND, len(PAYLOAD), 0,
                              hashlib.sha256(PAYLOAD).hexdigest()))
        self.store.write_segment(identifier, b"\0" * len(PAYLOAD))
        self.restart()
        self.assertEqual(self.ring.db.execute("SELECT state FROM segments").fetchone()[0], "uncertain")

    def test_clock_rollback_is_degraded_even_when_caller_marks_sample_trusted(self):
        self.warm()
        identifier = self.loss()
        status = self.ring.tick(now_us=T0 - SECOND, clock_trusted=True)
        self.assertEqual(status["reason"], "clock_uncertain")
        self.finish()
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["clock_uncertain"])

    def test_clock_uncertain_reconfiguration_never_trims_by_timestamp(self):
        self.configure(value=1200)
        for start in range(T0 - 1200 * SECOND, T0, 60 * SECOND):
            self.append(start)
        before = set(self.store.list_segments())
        status = self.ring.configure(RingConfig("duration", 600), (self.profile,),
                                     now_us=T0 - SECOND, clock_trusted=True)
        self.assertEqual(status["reason"], "clock_uncertain")
        self.assertEqual(set(self.store.list_segments()), before)

    def test_untrusted_forward_jump_does_not_poison_trusted_clock_after_restart(self):
        self.warm()
        incident = self.loss()
        before = self.store.segment_allocations()
        status = self.ring.tick(now_us=T0 + RETENTION, clock_trusted=False)
        self.assertEqual(status["reason"], "clock_uncertain")
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(int(self.ring.db.execute(
            "SELECT value FROM settings WHERE key='latest_clock'"
        ).fetchone()[0]), T0)
        self.restart()
        self.finish()
        result = self.ring.incident(incident, now_us=T0 + POST)
        # The uncertain interval stays visible, but trusted time can complete
        # and eventually expire it without waiting for the rejected jump.
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["completed_at_us"], T0 + POST)
        self.assertEqual(result["expires_at_us"], T0 + POST + RETENTION)
        self.ring.tick(now_us=T0 + POST + RETENTION, clock_trusted=True)
        self.assertEqual(self.ring.incident(incident, now_us=T0 + POST + RETENTION)["state"], "deleted")

    def test_untrusted_forward_segment_is_refused_without_blocking_corrected_capture(self):
        self.warm()
        incident = self.loss()
        before = self.store.segment_allocations()
        with self.assertRaisesRegex(RingRefused, "clock_uncertain"):
            self.append(T0 + RETENTION, trusted=False)
        self.assertEqual(self.store.segment_allocations(), before)
        self.restart()
        self.finish()
        result = self.ring.incident(incident, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["clock_uncertain"])
        self.assertFalse(result["has_gaps"])

    def test_legacy_untrusted_future_segment_is_not_a_trusted_source_watermark(self):
        self.warm()
        identifier = self.append(T0, trusted=False)
        # Model a row persisted by the pre-fix version, in this private fixture.
        with self.ring.ledger.transaction():
            self.ring.db.execute("UPDATE segments SET start=?,end=? WHERE id=?",
                                 (T0 + RETENTION, T0 + RETENTION + 60 * SECOND, str(identifier)))
        self.restart()
        corrected = self.append(T0)
        self.assertNotEqual(corrected, identifier)
        self.assertEqual(self.ring.db.execute("SELECT clock_trusted FROM segments WHERE id=?",
                                              (str(corrected),)).fetchone()[0], 1)

    def test_untrusted_time_cannot_establish_initial_capture_chronology(self):
        self.configure()
        with self.assertRaisesRegex(RingRefused, "clock_uncertain"):
            self.append(T0, trusted=False)
        self.assertEqual(self.store.list_segments(), {})
        self.append(T0)

    def test_untrusted_post_cannot_spend_reserved_corrected_capture_rows(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=370 * 4096,
                             authority=AllowControls())
        self.warm()
        incident = self.loss()
        before = self.store.segment_allocations()
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.append(T0, trusted=False)
        self.assertEqual(self.store.segment_allocations(), before)
        self.restart()
        self.finish()
        self.assertEqual(self.ring.incident(incident, now_us=T0 + POST)["state"], "complete")

    def test_untrusted_post_with_extra_capacity_allows_corrected_capture_after_restart(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=470 * 4096,
                             authority=AllowControls())
        self.warm()
        incident = self.loss()
        for start in range(T0, T0 + POST, 60 * SECOND):
            self.append(start, trusted=False)
        self.restart()
        self.finish()
        result = self.ring.incident(incident, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["clock_uncertain"])
        self.assertFalse(result["has_gaps"])

    def test_preserve_does_not_credit_untrusted_rows_as_future_trusted_coverage(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=370 * 4096,
                             authority=AllowControls())
        self.warm()
        for start in range(T0, T0 + POST, 60 * SECOND):
            self.append(start, trusted=False)
        before = self.store.segment_allocations()
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.loss()
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 0)

    def test_late_trusted_capture_reserves_reactivated_incident_before_mutation(self):
        self.warm()
        incident = self.loss()
        self.ring.tick(now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(self.ring.incident(incident, now_us=T0 + POST)["state"], "partial")
        self.ring.close()
        # Existing ordinary target, ten protected rows/references and one
        # incident fit, but reactivating its future reservation does not.
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=250 * 4096,
                             authority=AllowControls())
        before = self.store.segment_allocations()
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.ring.append(SOURCE, T0, T0 + 60 * SECOND, PAYLOAD,
                             now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(self.ring.db.execute("SELECT state FROM incidents WHERE id=?",
                                              (str(incident),)).fetchone()[0], "partial")

    def test_late_trusted_capture_with_room_completes_partial_incident(self):
        self.warm()
        incident = self.loss()
        self.ring.tick(now_us=T0 + POST, clock_trusted=True)
        for start in range(T0, T0 + POST, 60 * SECOND):
            self.ring.append(SOURCE, start, start + 60 * SECOND, PAYLOAD,
                             now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(self.ring.incident(incident, now_us=T0 + POST)["state"], "complete")

    def test_delayed_completion_and_late_media_keep_original_end_based_expiry(self):
        self.warm()
        incident = self.loss()
        delayed = T0 + POST + 24 * 3600 * SECOND
        self.restart()
        self.ring.tick(now_us=delayed, clock_trusted=True)
        initial = self.ring.incident(incident, now_us=delayed)
        self.assertEqual(initial["completed_at_us"], T0 + POST)
        self.assertEqual(initial["expires_at_us"], T0 + POST + RETENTION)
        for start in range(T0, T0 + POST, 60 * SECOND):
            self.ring.append(SOURCE, start, start + 60 * SECOND, PAYLOAD,
                             now_us=delayed, clock_trusted=True)
        final = self.ring.incident(incident, now_us=delayed)
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["expires_at_us"], initial["expires_at_us"])

    def test_first_trusted_tick_after_retention_expires_delayed_active_incident(self):
        self.warm()
        incident = self.loss()
        delayed = T0 + POST + RETENTION + 15 * 24 * 3600 * SECOND
        self.restart()
        self.ring.tick(now_us=delayed, clock_trusted=False)
        self.assertEqual(len(self.store.list_segments()), 10)
        self.assertEqual(self.ring.incident(incident, now_us=delayed)["state"], "active")
        self.ring.tick(now_us=delayed, clock_trusted=True)
        self.assertEqual(self.ring.incident(incident, now_us=delayed)["state"], "deleted")
        self.assertEqual(self.store.list_segments(), {})

    def test_preserve_refuses_end_based_expiry_overflow_before_creating_incident(self):
        self.configure()
        end = 2**63 - 1 - RETENTION + 1
        with self.assertRaises(RingRefused):
            self.ring.preserve("camera_tamper", end - PRE, end, now_us=T0, clock_trusted=True)
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 0)

    def test_interrupted_deletion_resumes_and_preserves_shared_incident(self):
        self.warm()
        first = self.loss()
        shared = self.ring.preserve("server_movement", T0 - PRE, T0, now_us=T0, clock_trusted=True)
        self.finish()
        with patch.object(self.store, "delete_segment", side_effect=StorageRefused("storage_unavailable")):
            with self.assertRaises(RingRefused):
                self.ring.delete_incident(first, now_us=T0 + POST + PRE, clock_trusted=True)
        self.restart()
        self.assertEqual(self.ring.incident(first, now_us=T0 + POST)["state"], "deleted")
        result = self.ring.incident(shared, now_us=T0 + POST)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(result["has_gaps"])
        self.assertGreater(result["allocated_bytes"], 0)

    def test_reclaimed_blocks_must_actually_become_free_before_config_acceptance(self):
        self.configure(value=1200)
        for start in range(T0 - 1200 * SECOND, T0, 60 * SECOND):
            self.append(start)
        before = self.store.segment_allocations()
        budget = self.ring._budget(self.ring.profiles, T0)
        self.assertGreater(budget["reclaimable_allocated"], 0)
        self.quota.capacity = (self.quota.used() + budget["required_additional"]
                               + budget["safety_reserve"] - budget["reclaimable_allocated"])
        original = self.store.delete_segment

        def kept_open(identifier):
            allocation = self.store.segment_allocations()[identifier]
            result = original(identifier)
            self.quota.other += allocation  # Models blocks retained by an open reader.
            return result

        with patch.object(self.store, "delete_segment", side_effect=kept_open):
            with self.assertRaises(RingRefused):
                self.configure(value=600)
        self.assertEqual(self.ring.config.value, 1200)
        self.assertEqual(self.store.segment_allocations(), before)
        self.quota.capacity += budget["reclaimable_allocated"]
        self.restart()
        self.assertEqual(self.ring.config.value, 1200)
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(self.ring.status(now_us=T0, clock_trusted=True)["state"], "healthy")

    def test_successful_duration_reconfiguration_trims_only_after_commit(self):
        self.configure(value=1200)
        for start in range(T0 - 1200 * SECOND, T0, 60 * SECOND):
            self.append(start)
        original = self.store.delete_segment
        def after_commit(identifier):
            self.assertEqual(self.ring.config.value, 600)
            return original(identifier)
        with patch.object(self.store, "delete_segment", side_effect=after_commit):
            self.configure(value=600)
        self.assertEqual(len(self.store.list_segments()), 10)

    def test_reconfiguration_rechecks_blocks_only_from_expired_current_media(self):
        self.configure(value=1200)
        # Model interrupted FIFO work, leaving older ordinary files that may
        # expire under the current, longer configuration after recovery.
        with patch.object(self.ring, "_trim"):
            for start in range(T0 - 1800 * SECOND, T0, 60 * SECOND):
                self.append(start)
        current = {UUID(row["id"]) for row in self.ring._rows() if row["end"] > T0 - 1200 * SECOND}
        eligible = self.ring._configuration_reclaimable(T0, RingConfig("duration", 600))
        allocations = self.store.segment_allocations()
        credit = sum(allocations[UUID(row["id"])] for row in eligible)
        budget = self.ring._budget(self.ring.profiles, T0)
        self.quota.capacity = (self.quota.used() + budget["required_additional"]
                               + budget["safety_reserve"] - credit)
        original = self.store.delete_segment
        def kept_open(identifier):
            allocation = self.store.segment_allocations()[identifier]
            original(identifier)
            self.quota.other += allocation
        with patch.object(self.store, "delete_segment", side_effect=kept_open):
            with self.assertRaises(RingRefused):
                self.configure(value=600)
        self.assertEqual(self.ring.config.value, 1200)
        self.assertEqual(set(self.store.list_segments()), current)

    def test_failed_capacity_reconfiguration_retains_current_ordinary_limit(self):
        minimum = self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.configure("capacity", 2 * minimum)
        for start in range(T0 - 1800 * SECOND, T0, 60 * SECOND):
            self.append(start)
        before = self.store.segment_allocations()
        budget = self.ring._budget(self.ring.profiles, T0)
        self.quota.capacity = (self.quota.used() + budget["required_additional"]
                               + budget["safety_reserve"] - self.store.allocation_unit)
        with self.assertRaises(RingRefused):
            self.configure("capacity", minimum)
        self.assertEqual(self.ring.config.value, 2 * minimum)
        self.assertEqual(self.store.segment_allocations(), before)

    def test_capacity_shrink_rejects_legacy_rollover_peak_and_preserves_configuration(self):
        high = SegmentProfile(SOURCE, 2000, 1000, 60 * SECOND, 100)
        high_limit = high.bytes_for(PRE, self.store.allocation_unit)
        low_limit = self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.configure("capacity", high_limit, profiles=(high,))
        large = zlib.compress(random.Random(16).randbytes(12000))
        for index, start in enumerate(range(T0 - PRE, T0, 60 * SECOND)):
            self.ring.append(SOURCE, start, start + 60 * SECOND, PAYLOAD if index < 4 else large,
                             now_us=start + 60 * SECOND, clock_trusted=True)
        before = self.store.segment_allocations()
        configuration = self.ring.db.execute("SELECT value FROM settings WHERE key='configuration'").fetchone()[0]
        # One new batch fits, but a later batch would exceed the smaller limit
        # while older large segments still belong to the required pre-window.
        self.assertLess(sum(before.values()), low_limit)
        with self.assertRaisesRegex(RingRefused, "capacity_transition_exceeds_limit"):
            self.configure("capacity", low_limit)
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(self.ring.profiles[SOURCE], high)
        self.assertEqual(self.ring.db.execute("SELECT value FROM settings WHERE key='configuration'").fetchone()[0],
                         configuration)
        self.ring.tick(now_us=T0 + PRE, clock_trusted=True)
        self.ring.configure(RingConfig("capacity", low_limit), (self.profile,), now_us=T0 + PRE, clock_trusted=True)
        self.append(T0 + PRE)

    def test_capacity_reconfiguration_accepts_unchanged_compatible_pre_window(self):
        minimum = self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.configure("capacity", minimum)
        for start in range(T0 - PRE, T0, 60 * SECOND):
            self.append(start)
        self.assertEqual(self.configure("capacity", minimum)["state"], "healthy")
        self.append(T0)

    def test_capacity_transition_counts_four_sources_removed_source_and_untrusted_time(self):
        self.ring.close()
        self.quota.capacity = 4 * 1024 * 1024 * 1024
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=64 * 1024 * 1024,
                             authority=AllowControls())
        high = tuple(SegmentProfile(UUID(int=100 + index), 2000, 1000, 60 * SECOND, 100) for index in range(4))
        low = tuple(SegmentProfile(profile.source_id, 800, 400, 60 * SECOND, 100) for profile in high)
        limit = sum(profile.bytes_for(PRE, self.store.allocation_unit) for profile in high)
        self.configure("capacity", limit, profiles=high)
        large = zlib.compress(random.Random(16).randbytes(12000))
        for start in range(T0 - PRE, T0, 60 * SECOND):
            for profile in high:
                self.ring.append(profile.source_id, start, start + 60 * SECOND, large,
                                 now_us=start + 60 * SECOND, clock_trusted=True)
        before = self.store.segment_allocations()
        for profiles in (low, low[:3]):
            target = sum(profile.bytes_for(PRE, self.store.allocation_unit) for profile in profiles)
            for trusted in (True, False):
                with self.subTest(sources=len(profiles), trusted=trusted):
                    with self.assertRaisesRegex(RingRefused, "capacity_transition_exceeds_limit"):
                        self.ring.configure(RingConfig("capacity", target), profiles, now_us=T0, clock_trusted=trusted)
                    self.assertEqual(self.store.segment_allocations(), before)
                    self.assertEqual(self.ring.config.value, limit)

    def test_legacy_overlimit_capacity_reports_pressure_after_restart(self):
        high = SegmentProfile(SOURCE, 2000, 1000, 60 * SECOND, 100)
        self.configure("capacity", high.bytes_for(PRE, self.store.allocation_unit), profiles=(high,))
        large = zlib.compress(random.Random(16).randbytes(12000))
        for start in range(T0 - PRE, T0, 60 * SECOND):
            self.ring.append(SOURCE, start, start + 60 * SECOND, large, now_us=start + 60 * SECOND, clock_trusted=True)
        value = json.loads(self.ring.db.execute("SELECT value FROM settings WHERE key='configuration'").fetchone()[0])
        value["config"]["value"] = self.profile.bytes_for(PRE, self.store.allocation_unit)
        value["profiles"][0].update(maximum_bitrate=800, expected_bitrate=400)
        with self.ring.ledger.transaction():
            self.ring.db.execute("UPDATE settings SET value=? WHERE key='configuration'", (json.dumps(value),))
        self.restart()
        result = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertEqual(result["state"], "STORAGE_PRESSURE")
        self.assertEqual(result["reason"], "ordinary_capacity_exhausted")

    def test_hard_stop_status_does_not_claim_free_space_when_mount_missing(self):
        self.configure()
        self.store.mounts = lambda: []
        result = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertEqual(result["state"], "STORAGE_HARD_STOP")
        self.assertIsNone(result["filesystem_free"])

    def test_unknown_orphan_bytes_are_visible_and_not_reclaim_credit(self):
        self.warm()
        orphan = uuid4()
        self.store.write_segment(orphan, PAYLOAD)
        status = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertEqual(status["reason"], "orphan_media_present")
        self.assertGreater(status["orphan_allocated_bytes"], 0)
        self.assertEqual(status["reclaimable_allocated"], 0)

    def test_configuration_refuses_profile_change_during_active_post_capture(self):
        self.warm()
        self.loss()
        with self.assertRaisesRegex(RingRefused, "protection_configuration_busy"):
            self.configure()

    def test_completed_incident_losing_media_after_restart_is_partial(self):
        self.warm()
        identifier = self.loss()
        self.finish()
        self.store.delete_segment(UUID(self.ring._rows()[0]["id"]))
        self.restart()
        result = self.ring.incident(identifier, now_us=T0 + POST)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["has_gaps"])

    def test_current_media_disappearance_is_not_hidden_by_stale_ledger_coverage(self):
        self.warm()
        identifier = UUID(self.ring._rows()[0]["id"])
        self.store.delete_segment(identifier)
        result = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["reason"], "pre_loss_coverage_gap")

    def test_selected_target_larger_than_filesystem_is_rejected_even_if_twenty_minutes_fit(self):
        with self.assertRaisesRegex(RingRefused, "selected_target_exceeds_safe_filesystem"):
            self.configure("capacity", self.quota.capacity * 2)
        with self.assertRaisesRegex(RingRefused, "selected_target_exceeds_safe_filesystem"):
            self.configure("duration", 86400 * 1000)

    def test_small_ledger_rejects_one_second_cadence_before_configuration(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=128 * 1024, authority=AllowControls())
        profile = SegmentProfile(SOURCE, 800, 400, SECOND, 100)
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure(profiles=(profile,))
        self.assertIsNone(self.ring.config)
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM settings").fetchone()[0], 0)
        self.assertEqual(self.ring._rows(), [])
        self.assertEqual(self.store.list_segments(), {})

    def test_capacity_admission_counts_512_byte_allocations_before_capture(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=1792 * 1024,
                             authority=AllowControls())
        minimum = self.profile.bytes_for(PRE, self.store.allocation_unit)
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure("capacity", minimum)
        self.assertIsNone(self.ring.config)
        self.assertEqual(self.store.list_segments(), {})

    def test_sufficient_ledger_completes_one_second_pre_and_post_through_restart(self):
        self.ring.close()
        self.quota.capacity = 4 * 1024 * 1024 * 1024
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=64 * 1024 * 1024,
                             authority=AllowControls())
        profile = SegmentProfile(SOURCE, 800, 400, SECOND, 100)
        self.configure(profiles=(profile,))
        for start in range(T0 - PRE, T0, SECOND):
            self.ring.append(SOURCE, start, start + SECOND, PAYLOAD, now_us=start + SECOND, clock_trusted=True)
        incident = self.loss()
        self.restart()
        for start in range(T0, T0 + POST, SECOND):
            self.ring.append(SOURCE, start, start + SECOND, PAYLOAD, now_us=start + SECOND, clock_trusted=True)
        result = self.ring.incident(incident, now_us=T0 + POST)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(result["has_gaps"])
        self.assertEqual(len(self.ring._rows()), 1200)

    def test_metadata_budget_counts_selected_horizon_and_every_source_cadence(self):
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure("duration", 86400)
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure("capacity", 20 * self.profile.bytes_for(PRE, self.store.allocation_unit))
        profiles = tuple(SegmentProfile(UUID(int=100 + index), 800, 400,
                                        SECOND if index == 3 else 60 * SECOND, 100)
                         for index in range(4))
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure(profiles=profiles)
        self.assertIsNone(self.ring.config)

    def test_ledger_reservation_rejects_overlapping_preserve_without_harming_active_post(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=2 * 1024 * 1024,
                             authority=AllowControls())
        self.warm()
        incident = self.loss()
        before = self.store.segment_allocations()
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.ring.preserve("camera_tamper", T0 - PRE, T0 + POST, now_us=T0, clock_trusted=True)
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 1)
        self.assertEqual(self.store.segment_allocations(), before)
        self.restart()
        self.finish()
        self.assertEqual(self.ring.incident(incident, now_us=T0 + POST)["state"], "complete")

    def test_existing_tombstones_are_counted_without_reset_or_deletion(self):
        with self.ring.ledger.transaction():
            self.ring.db.executemany("INSERT INTO incidents VALUES (?, 'camera_tamper', ?, ?, ?, ?, 'deleted', 0, ?)",
                                    ((str(UUID(int=index + 1)), T0 - PRE, T0, T0, T0 + RETENTION,
                                      '["' + str(SOURCE) + '"]') for index in range(1200)))
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure()
        self.assertIsNone(self.ring.config)
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 1200)

    def test_missing_ordinary_rows_do_not_substitute_for_future_capacity_rows(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=6 * 1024 * 1024,
                             authority=AllowControls())
        minimum = self.profile.bytes_for(PRE, self.store.allocation_unit)
        self.configure("capacity", minimum)
        with self.ring.ledger.transaction():
            self.ring.db.executemany("INSERT INTO segments VALUES (?,?,?,?,?,0,?,'missing',1)",
                                    ((str(UUID(int=index + 1)), str(SOURCE), index * 60 * SECOND,
                                      (index + 1) * 60 * SECOND, len(PAYLOAD), hashlib.sha256(PAYLOAD).hexdigest())
                                     for index in range(100)))
        with self.assertRaisesRegex(RingRefused, "insufficient_ledger_capacity"):
            self.configure("capacity", minimum)
        self.assertEqual(len(self.ring._rows()), 100)

    def test_zero_allocation_cannot_enter_capacity_accounting_or_healthy_recovery(self):
        self.configure()
        allocation = self.store.segment_allocations
        with patch.object(self.store, "segment_allocations", side_effect=lambda: dict.fromkeys(allocation(), 0)):
            with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
                self.append(T0)
        self.assertEqual(self.store.list_segments(), {})
        identifier = self.append(T0 + 60 * SECOND)
        with patch.object(self.store, "segment_allocations", side_effect=lambda: dict.fromkeys(allocation(), 0)):
            self.restart()
            self.assertEqual(self.ring.db.execute("SELECT state FROM segments WHERE id=?", (str(identifier),)).fetchone()[0],
                             "uncertain")

    def test_replaced_ledger_is_a_hard_stop_and_never_recreated(self):
        self.configure()
        original = self.settings.runtime_root / "ring.sqlite3"
        original.rename(self.settings.runtime_root / "moved.sqlite3")
        original.write_bytes(b"synthetic-replacement")
        result = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertEqual(result["state"], "STORAGE_HARD_STOP")
        self.assertEqual(result["reason"], "ledger_file_replaced")
        self.assertEqual(original.read_bytes(), b"synthetic-replacement")


    def test_authentication_loss_protects_even_when_socket_stays_connected(self):
        self.warm()
        self.ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                     now_us=T0, clock_trusted=True)
        incident = self.ring.observe_connection(authenticated=False, connected=True, unexpected=True,
                                                now_us=T0, clock_trusted=True)
        self.assertIsInstance(incident, UUID)
        self.assertIsNone(self.ring.observe_connection(authenticated=False, connected=False, unexpected=True,
                                                       now_us=T0, clock_trusted=True))
        self.finish()
        self.assertEqual(self.ring.incident(incident, now_us=T0 + POST)["state"], "complete")
        self.assertEqual(self.ring.db.execute("SELECT count(*) FROM incidents").fetchone()[0], 1)

    def test_old_protected_integrity_loss_remains_degraded_with_complete_current_pre(self):
        self.warm()
        self.loss()
        self.finish()
        for start in range(T0 + POST, T0 + POST + PRE, 60 * SECOND):
            self.append(start)
        now = T0 + POST + PRE
        old = self.ring._rows()[0]
        self.store.delete_segment(UUID(old["id"]))
        status = self.ring.status(now_us=now, clock_trusted=True)
        self.assertFalse(status["pre_loss_coverage"][str(SOURCE)]["gaps_us"])
        self.assertEqual(status["reason"], "protected_evidence_integrity_gap")
        self.restart()
        self.assertEqual(self.ring.status(now_us=now, clock_trusted=True)["state"], "degraded")

    def test_ledger_transaction_rolls_back_process_interruptions(self):
        for exception in (KeyboardInterrupt, SystemExit):
            with self.assertRaises(exception):
                with self.ring.ledger.transaction():
                    self.ring.db.execute("INSERT INTO settings VALUES ('interrupted','synthetic')")
                    raise exception()
            self.assertFalse(self.ring.db.in_transaction)
            self.assertIsNone(self.ring.db.execute("SELECT value FROM settings WHERE key='interrupted'").fetchone())
        self.configure()

    def test_ledger_startup_refuses_before_database_creation_at_reserve(self):
        self.ring.close()
        database = self.settings.runtime_root / "ring.sqlite3"
        database.unlink()  # Only this test's generated temporary database.
        def shortage(descriptor):
            values = list(os.fstatvfs(descriptor))
            values[4] = self.settings.safety_reserve_bytes // values[1]
            return os.statvfs_result(values)
        with self.assertRaisesRegex(RingRefused, "ledger_reserve_unavailable"):
            Ledger(self.settings, maximum_bytes=128 * 1024, space=shortage)
        self.assertFalse(database.exists())

    def test_separate_runtime_pressure_blocks_ledger_mutation_and_reports_hard_stop(self):
        self.warm()
        incident = self.loss()
        before = self.store.segment_allocations()
        def shortage(descriptor):
            values = list(os.fstatvfs(descriptor))
            values[4] = 0
            return os.statvfs_result(values)
        self.ring.ledger.space = shortage
        with self.assertRaisesRegex(RingRefused, "ledger_reserve_unavailable"):
            self.ring.tick(now_us=T0 + POST, clock_trusted=True)
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(self.ring.db.execute("SELECT state FROM incidents WHERE id=?", (str(incident),)).fetchone()[0], "active")
        self.assertEqual(self.ring.status(now_us=T0, clock_trusted=True)["reason"], "ledger_reserve_unavailable")

    def test_sqlite_growth_is_bounded_and_rolls_back_at_explicit_page_limit(self):
        self.ring.close()
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=128 * 1024, authority=AllowControls())
        before = self.settings.runtime_root.joinpath("ring.sqlite3").stat().st_size
        with self.assertRaises(sqlite3.Error):
            with self.ring.ledger.transaction():
                self.ring.db.execute("INSERT INTO settings VALUES ('oversize',?)", ("x" * 256 * 1024,))
        self.assertFalse(self.ring.db.in_transaction)
        self.assertIsNone(self.ring.db.execute("SELECT value FROM settings WHERE key='oversize'").fetchone())
        self.assertLessEqual(self.settings.runtime_root.joinpath("ring.sqlite3").stat().st_size, 128 * 1024)
        self.assertGreater(before, 0)

    def test_media_write_retains_shared_filesystem_ledger_headroom(self):
        self.warm()
        self.loss()
        before = self.store.segment_allocations()
        # There is space above the hard reserve for compressed bytes, but not
        # above the additional metadata completion budget on the same device.
        self.quota.other = (self.quota.capacity - self.quota.used() - self.settings.safety_reserve_bytes
                            - self.ring.ledger_headroom + self.store.allocation_unit)
        with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
            self.append(T0)
        self.assertEqual(self.store.segment_allocations(), before)

    def test_unsafe_journal_sidecar_is_rejected_before_sqlite_recovery(self):
        self.ring.close()
        sidecar = self.settings.runtime_root / "ring.sqlite3-journal"
        target = self.settings.runtime_root / "synthetic-target"
        target.write_bytes(b"generated")
        sidecar.symlink_to(target)
        with self.assertRaisesRegex(RingRefused, "ledger_sidecar_refused"):
            Ledger(self.settings, maximum_bytes=128 * 1024)
        self.assertEqual(target.read_bytes(), b"generated")


    def test_missing_ordinary_media_inside_selected_duration_stays_degraded(self):
        self.configure("duration", 1800)
        for start in range(T0 - 1800 * SECOND, T0, 60 * SECOND):
            self.append(start)
        old = UUID(self.ring._rows()[0]["id"])
        self.store.delete_segment(old)
        status = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertFalse(status["pre_loss_coverage"][str(SOURCE)]["gaps_us"])
        self.assertEqual(status["reason"], "ordinary_ring_integrity_gap")
        self.restart()
        self.assertEqual(self.ring.status(now_us=T0, clock_trusted=True)["state"], "degraded")

    def test_owner_incident_deletion_retains_independent_ordinary_pre_ownership(self):
        self.warm()
        incident = self.loss()
        before = self.store.segment_allocations()
        self.ring.delete_incident(incident, now_us=T0, clock_trusted=True)
        self.assertEqual(self.store.segment_allocations(), before)
        self.assertEqual(self.ring.incident(incident, now_us=T0)["state"], "deleted")
        self.restart()
        status = self.ring.status(now_us=T0, clock_trusted=True)
        self.assertFalse(status["pre_loss_coverage"][str(SOURCE)]["gaps_us"])
        self.assertEqual(status["protected_allocated_bytes"], 0)
        self.ring.tick(now_us=T0 + PRE, clock_trusted=True)
        self.assertEqual(self.store.segment_allocations(), {})

    def test_uncertain_future_clock_cannot_fifo_delete_current_ordinary_media(self):
        self.warm()
        before = self.store.segment_allocations()
        self.ring.tick(now_us=T0 + RETENTION, clock_trusted=False)
        self.assertEqual(self.store.segment_allocations(), before)
