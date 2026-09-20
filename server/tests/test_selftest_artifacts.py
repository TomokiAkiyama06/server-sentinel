"""Real disposable filesystem I/O with generated non-playable test bytes."""

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4
import os
import sqlite3
import threading
import zlib

from app.media.health.artifacts import recording_health_migration
from app.media.health.service import HealthState, PipelineStatus, RecordingHealthService
from app.media.recording import Limits, RecordingError, RecordingStore, RootIdentity, Segment
from app.media.recording.schema import recording_migration
from app.storage.migrations import BUILTIN_MIGRATIONS, migrate
from tests.test_recording import Reservation, SyntheticValidator


class ArtifactTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "media"
        self.root.mkdir(mode=0o700)
        info = self.root.stat()
        self.identity = RootIdentity(info.st_dev, info.st_ino)
        self.db = sqlite3.connect(self.base / "metadata.sqlite", isolation_level=None)
        self.addCleanup(self.db.close)
        migrate(self.db, BUILTIN_MIGRATIONS + (recording_migration(2), recording_health_migration(3)))
        self.policy = Reservation()
        self.validator = SyntheticValidator()
        self.limits = Limits(4096, 512, 30000, 8, 16, 100)
        self.store = self.open_store()
        self.addCleanup(lambda: self.store.close())
        self.sample = Segment(uuid4(), uuid4(), 0, 1000, 2000, "synthetic", "deflate",
                              zlib.compress(b"generated geometric test payload" * 4))
        self.results = []
        self.adapter = self.make_adapter()
        self.service = RecordingHealthService(self.adapter, lambda *args: self.results.append(args))

    def open_store(self):
        return RecordingStore(self.db, self.root, self.identity, self.limits, self.policy, self.validator)

    def make_adapter(self):
        return self.store.self_test_probe(lambda: PipelineStatus((True,), True, True),
                                          lambda: self.sample, lambda: ("OK",), max_bytes=512, max_duration_ms=1000)

    def test_real_write_read_cleanup_and_shared_reservation(self):
        fsync = os.fsync
        observed = []
        def check_reservation(descriptor):
            observed.append(self.policy.reserved)
            fsync(descriptor)
        with patch("app.media.health.artifacts.os.fsync", side_effect=check_reservation):
            self.assertEqual(self.service.startup().state, HealthState.OK)
        self.assertTrue(observed)
        self.assertTrue(all(observed))
        self.assertFalse(self.policy.reserved)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM recording_selftest").fetchone()[0], 0)

    def test_normal_recording_and_unowned_files_never_cleaned(self):
        self.store.append(self.sample)
        original = {path.name: path.read_bytes() for path in self.root.iterdir()}
        unknown = self.root / (uuid4().hex + ".selftest")
        unknown.write_bytes(b"synthetic-unowned-file")
        self.service.startup()
        for name, value in original.items():
            self.assertEqual((self.root / name).read_bytes(), value)
        self.assertEqual(unknown.read_bytes(), b"synthetic-unowned-file")

    def test_reopen_corruption_fails_and_cleans(self):
        write = self.adapter.write_test_segment
        def corrupt():
            write()
            next(self.root.glob("*.selftest")).write_bytes(b"corrupt")
        self.adapter.write_test_segment = corrupt
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(self.policy.reserved)

    def test_decode_failure_of_reopened_media_fails(self):
        validate = self.validator.validate
        calls = []
        def fail_reopen(segment):
            calls.append(1)
            if len(calls) == 2:
                raise ValueError("synthetic-decode-failure")
            validate(segment)
        self.validator.validate = fail_reopen
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.assertEqual(len(calls), 2)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cleanup_failure_blocks_next_write_and_recovery_removes_only_owned(self):
        unlink = os.unlink
        with patch("app.media.health.artifacts.os.unlink", side_effect=OSError("synthetic-readonly")):
            self.assertEqual(self.service.startup().state, HealthState.FAILED)
            names = list(self.root.iterdir())
            self.assertEqual(len(names), 1)
            self.assertEqual(self.service.startup().state, HealthState.FAILED)
            self.assertEqual(list(self.root.iterdir()), names)
        self.assertIs(os.unlink, unlink)
        self.assertEqual(self.service.startup().state, HealthState.OK)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_restart_cleans_journaled_partial_before_next_test(self):
        self.adapter.cleanup()
        self.adapter.check_storage()
        self.adapter.write_test_segment()
        self.assertEqual(len(list(self.root.iterdir())), 1)
        self.store.close()
        # A killed process loses its in-memory reservation; physical bytes
        # remain in the filesystem free-space accounting used by the policy.
        self.policy = Reservation()
        self.store = self.open_store()
        self.adapter = self.make_adapter()
        self.adapter.cleanup()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertIsNone(self.db.execute("SELECT 1 FROM recording_selftest").fetchone())

    def test_substituted_root_never_creates_fallback(self):
        self.root.rename(self.base / "approved-media")
        self.root.mkdir(mode=0o700)
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(list((self.base / "approved-media").iterdir()), [])

    def test_hard_reserve_denial_creates_no_artifact(self):
        self.policy.denial = "STORAGE_HARD_STOP"
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_oversized_or_too_long_sample_is_rejected(self):
        self.sample = replace(self.sample, end_ms=3000)
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(self.policy.reserved)

    def test_different_worker_cannot_write(self):
        results = []
        def wrong_worker():
            try:
                self.adapter.check_storage()
            except RecordingError as exc:
                results.append(str(exc))
        thread = threading.Thread(target=wrong_worker)
        thread.start()
        thread.join()
        self.assertEqual(results, ["RECORDING_WRITER_UNAVAILABLE"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_different_worker_cannot_release_owned_reservation(self):
        self.adapter.check_storage()
        results = []
        def wrong_worker():
            try:
                self.adapter.cleanup()
            except RecordingError:
                results.append("rejected")
        thread = threading.Thread(target=wrong_worker)
        thread.start()
        thread.join()
        self.assertEqual(results, ["rejected"])
        self.assertTrue(self.policy.reserved)
        self.adapter.cleanup()
        self.assertFalse(self.policy.reserved)
