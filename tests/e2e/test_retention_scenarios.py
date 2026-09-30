"""Main 20-day / Audit 90-day / Agent 60-day retention on independent clocks.

The Main RecordingStore, storage policy and audit table run on a disposable
SQLite database and media root. The Agent ring runs in its own directory with
its own synthetic clock; neither side reads the other's clock or storage.
"""

import os
import sqlite3
import unittest
from uuid import uuid4
import zlib

from app.media.recording import Limits, RecordingError, RecordingStore, RootIdentity, Segment
from app.media.recording.schema import recording_migration
from app.storage.migrations import BUILTIN_MIGRATIONS, migrate
from app.storage.policy import (ExpectedFilesystem, FilesystemSpace, MainStoragePolicy,
                                StorageLimits, StorageState, StorageTransition)
from app.storage.retention import (DAY_MS, RetentionPeriods, RetentionService, StorageAudit,
                                   storage_audit_migration)
from media_capture_agent.ring_models import POST, PRE, RETENTION, SECOND

from tests.e2e.test_agent_ring_scenarios import RingScenario


FIXTURE = b"generated geometric test payload" * 4


class SyntheticValidator:
    """Accepts only the generated deflate fixture; never real media."""

    def validate(self, segment):
        if segment.codec != "synthetic" or segment.container != "deflate":
            raise ValueError("unvalidated codec")
        if zlib.decompress(segment.data) != FIXTURE:
            raise ValueError("invalid generated fixture")


class RetentionScenarios(RingScenario):
    source_count = 1

    def setUp(self):
        super().setUp()
        base = self.root / "main"
        base.mkdir(mode=0o700)
        self.media = base / "media"
        self.media.mkdir(mode=0o700)
        info = self.media.stat()
        identity = RootIdentity(info.st_dev, info.st_ino)
        metadata = base / "metadata.sqlite"
        self.db = sqlite3.connect(metadata, isolation_level=None)
        metadata.chmod(0o600)
        self.addCleanup(self.db.close)
        count = len(BUILTIN_MIGRATIONS)
        migrate(self.db, BUILTIN_MIGRATIONS + (recording_migration(count + 1),
                                               storage_audit_migration(count + 2)))
        # Main wall clock in UTC milliseconds, independent of the Agent clock.
        self.main_now = 5 * DAY_MS
        self.main_free = None
        filesystem = ExpectedFilesystem(self.media, identity, metadata)

        def space():
            real = filesystem.snapshot()
            if self.main_free is None:
                return real
            return FilesystemSpace(min(real.available_bytes, self.main_free), real.total_bytes)

        self.audit = StorageAudit(self.db, reservation=lambda: self.policy.control())
        self.policy = MainStoragePolicy(
            StorageLimits(recording_limit_bytes=100_000, critical_allowance_bytes=10_000,
                          hard_reserve_bytes=4096, pressure_free_bytes=8192,
                          recovery_free_bytes=16_384, recovery_allocation_bytes=90_000,
                          write_overhead_bytes=4096, max_request_bytes=1024,
                          cleanup_batch_size=10),
            space, lambda: self.main_now, self.audit.append,
        )
        self.recordings = RecordingStore(
            self.db, self.media, identity,
            Limits(pre_roll_bytes=4096, max_segment_bytes=512, max_segment_ms=30_000,
                   max_active_recordings=8, max_spool_segments=16, max_segments_per_recording=100),
            self.policy, SyntheticValidator(),
        )
        self.addCleanup(self.recordings.close)
        self.retention = RetentionService(self.recordings)
        self.policy.bind(self.recordings, self.retention)

    def recording(self, at_ms, *, starred=False):
        source = uuid4()
        identifier = self.recordings.start_manual(source, at_ms, duration_ms=1000)
        self.recordings.append(Segment(source, uuid4(), 0, at_ms, at_ms + 1000, "synthetic",
                                       "deflate", zlib.compress(FIXTURE)))
        self.recordings.finish(identifier)
        self.recordings.release_source(source)
        if starred:
            self.recordings.set_starred(identifier, True)
        return identifier

    def listed(self):
        return {row["id"] for row in self.recordings.list_recordings(limit=100)}

    def audit_rows(self):
        return [tuple(row) for row in self.db.execute(
            "SELECT at_ms,previous_state,current_state FROM storage_state_audit ORDER BY id")]

    def agent_incident(self):
        t0 = self.t0
        self.configure()
        self.capture(t0 - PRE, t0)
        self.connect(t0)
        incident = self.lose(t0)
        self.capture(t0, t0 + POST)
        return incident

    def agent_state(self, incident, at):
        self.ring.tick(now_us=at, clock_trusted=True)
        return self.ring.incident(incident, now_us=at)["state"]

    def test_default_periods_run_on_independent_main_and_agent_clocks(self):
        self.assertEqual((20, 90), (RetentionPeriods().recording_days, RetentionPeriods().audit_days))
        self.assertEqual(60 * 86400 * SECOND, RETENTION)
        early, starred = self.recording(DAY_MS), self.recording(DAY_MS, starred=True)
        later = self.recording(10 * DAY_MS)
        self.audit.append(StorageTransition(StorageState.NORMAL, StorageState.PRESSURE, DAY_MS))
        self.audit.append(StorageTransition(StorageState.PRESSURE, StorageState.NORMAL, 30 * DAY_MS))
        incident = self.agent_incident()
        agent_complete = self.t0 + POST

        # Main day 21 + 1 s: only the unstarred day-1 recording expires.
        self.main_now = 21 * DAY_MS + 1000
        self.assertEqual(0, self.retention.expired(21 * DAY_MS, 10))
        self.assertEqual(1, self.retention.expired(self.main_now, 10))
        self.assertEqual({str(starred), str(later)}, self.listed())
        with self.assertRaisesRegex(RecordingError, "NOT_FOUND"):
            self.recordings.manifest(early)
        self.assertEqual(0, self.audit.expire(self.main_now))
        # The Agent clock has barely moved; its incident is untouched.
        self.assertEqual("complete", self.agent_state(incident, agent_complete + SECOND))

        # Main day 31: the day-10 recording expires; starred never does,
        # neither by age nor by oldest-first reclamation.
        self.main_now = 31 * DAY_MS
        self.assertEqual(1, self.retention.expired(self.main_now, 10))
        self.assertEqual(0, self.retention.oldest(10))
        self.assertEqual({str(starred)}, self.listed())
        self.assertEqual(2, len(self.audit_rows()))

        # Main day 91 + 1 s: the day-1 audit row expires, the day-30 one stays.
        self.main_now = 91 * DAY_MS + 1000
        self.assertEqual(0, self.retention.expired(self.main_now, 10))
        self.assertEqual(1, self.audit.expire(self.main_now))
        self.assertEqual([(30 * DAY_MS, "STORAGE_PRESSURE", "NORMAL")], self.audit_rows())
        # Main is 91 days on, but the Agent still counts from its own completion.
        self.assertEqual("complete", self.agent_state(incident, agent_complete + RETENTION - 1))
        self.assertEqual("deleted", self.agent_state(incident, agent_complete + RETENTION))
        self.assertEqual({str(starred)}, self.listed())
        self.assertTrue(self.recordings.manifest(starred)["segments"])
        self.assertEqual(1, len(self.audit_rows()))

    def test_pressure_and_hard_stop_are_audited_and_never_reclaim_starred(self):
        starred = self.recording(DAY_MS, starred=True)
        ordinary = self.recording(2 * DAY_MS)
        limits = self.policy.limits

        # Free space just above the hard reserve but below the pressure line.
        self.main_free = limits.hard_reserve_bytes + limits.write_overhead_bytes + 512
        with self.assertRaisesRegex(RecordingError, "STORAGE_PRESSURE"):
            self.recordings.start_manual(uuid4(), self.main_now, duration_ms=1000)
        self.assertEqual(StorageState.PRESSURE, self.policy.status().state)
        # Pressure cleanup reclaimed the unstarred recording, never the starred one.
        self.assertEqual({str(starred)}, self.listed())
        with self.assertRaisesRegex(RecordingError, "NOT_FOUND"):
            self.recordings.manifest(ordinary)
        # Critical evidence is still admitted within its bounded allowance.
        self.recordings.start_event(uuid4(), (uuid4(),), self.main_now, pre_ms=0,
                                    post_ms=1000, critical=True)

        self.main_free = limits.hard_reserve_bytes - 1
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            self.recordings.start_event(uuid4(), (uuid4(),), self.main_now, pre_ms=0,
                                        post_ms=1000, critical=True)
        stopped = self.policy.status()
        self.assertEqual(StorageState.HARD_STOP, stopped.state)
        # No room even for the audit row: the failure itself stays visible.
        self.assertTrue(stopped.audit_delivery_failed)
        self.assertIn(str(starred), self.listed())

        self.main_free = None
        self.main_now += 1000
        self.recording(self.main_now)
        self.assertEqual(StorageState.NORMAL, self.policy.status().state)
        self.assertEqual(
            [("NORMAL", "STORAGE_PRESSURE"), ("STORAGE_HARD_STOP", "NORMAL")],
            [row[1:] for row in self.audit_rows()])
        self.assertTrue(self.recordings.manifest(starred)["segments"])
        self.assertTrue(self.policy.status().audit_delivery_failed)

    def test_substituted_main_media_root_is_a_hard_stop_without_fallback(self):
        starred = self.recording(DAY_MS, starred=True)
        moved = self.media.with_name("media-moved")
        os.rename(self.media, moved)
        self.media.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(RecordingError, "RECORDING_ROOT_UNAVAILABLE|STORAGE_HARD_STOP"):
                self.recordings.start_manual(uuid4(), self.main_now, duration_ms=1000)
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                self.policy.status()
            self.assertEqual(StorageState.HARD_STOP, self.policy.state)
            self.assertTrue(self.policy.audit_delivery_failed)
            self.assertEqual([], list(self.media.iterdir()))
        finally:
            self.media.rmdir()
            os.rename(moved, self.media)
        self.assertIn(str(starred), self.listed())


if __name__ == "__main__":
    unittest.main()
