"""Generated compressed bytes test storage only, never real/playable video."""

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4
import os
import sqlite3
import threading
import unittest
import zlib

from app.media.recording import Limits, RecordingError, RecordingStore, RootIdentity, Segment
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


class SyntheticValidator:
    def validate(self, segment):
        if segment.codec != "synthetic" or segment.container != "deflate":
            raise ValueError("unvalidated codec")
        if zlib.decompress(segment.data) != b"generated geometric test payload" * 4:
            raise ValueError("invalid generated fixture")


class Reservation:
    def __init__(self):
        self.denial = None
        self.reserved = False
        self.calls = []

    def admit_control(self):
        self.admit(0, critical=False)

    def admit(self, media_bytes, *, critical):
        self.calls.append((media_bytes, critical))
        if self.denial:
            raise RecordingError(self.denial)
        if self.reserved:
            raise AssertionError("overlapping reservation")
        self.reserved = True

    def release(self):
        if not self.reserved:
            raise AssertionError("unowned reservation")
        self.reserved = False


class RecordingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory(prefix="sentinel-generated-recording-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "media"
        self.root.mkdir(mode=0o700)
        info = self.root.stat()
        self.identity = RootIdentity(info.st_dev, info.st_ino)
        self.db = sqlite3.connect(self.base / "metadata.sqlite", isolation_level=None)
        self.addCleanup(self.db.close)
        migrate(self.db, APPLICATION_MIGRATIONS)
        self.assertEqual(
            self.db.execute("SELECT version, name FROM schema_migrations ORDER BY version").fetchall(),
            [(1, "foundation"), (2, "camera_registry"), (3, "uvc_identity"),
             (4, "durable_recording"), (5, "security_admin_audit")],
        )
        self.policy = Reservation()
        self.validator = SyntheticValidator()
        self.limits = Limits(pre_roll_bytes=4096, max_segment_bytes=512,
                             max_segment_ms=30_000, max_active_recordings=8,
                             max_spool_segments=16, max_segments_per_recording=100)
        self.source = uuid4()
        self.stream = uuid4()
        self.store = self.open_store()
        self.policy.calls.clear()
        self.addCleanup(lambda: self.store.close())

    def open_store(self, **kwargs):
        return RecordingStore(self.db, kwargs.get("root", self.root),
                              kwargs.get("expected_root", self.identity), self.limits,
                              self.policy, self.validator)

    def segment(self, start=30_000, end=40_000, sequence=0, **kwargs):
        return Segment(source_id=kwargs.get("source_id", self.source),
                       stream_id=kwargs.get("stream_id", self.stream),
                       sequence=sequence, start_ms=start, end_ms=end,
                       codec="synthetic", container="deflate",
                       data=zlib.compress(b"generated geometric test payload" * 4),
                       capture_node_id=kwargs.get("capture_node_id"))

    def reopen(self):
        self.store.close()
        self.store = self.open_store()

    def test_default_multi_source_event_and_source_based_manifest(self):
        remote_source, node, event = uuid4(), uuid4(), uuid4()
        for source in (self.source, remote_source):
            self.store.append(self.segment(source_id=source,
                                          capture_node_id=node if source == remote_source else None))
        recordings = self.store.start_event(event, (self.source, remote_source), 60_000)
        for index, start in enumerate(range(40_000, 180_000, 10_000), 1):
            for source in (self.source, remote_source):
                self.store.append(self.segment(start, start + 10_000, index, source_id=source,
                                              capture_node_id=node if source == remote_source else None))
        self.store.advance(180_000 + self.limits.max_segment_ms)
        manifest = self.store.event_manifest(event)
        self.assertEqual(2, len(manifest["recordings"]))
        self.assertEqual({str(value) for value in recordings},
                         {item["id"] for item in manifest["recordings"]})
        for recording in manifest["recordings"]:
            self.assertEqual("complete", recording["status"])
            self.assertEqual((30_000, 180_000),
                             (recording["start_ms"], recording["target_end_ms"]))
            self.assertEqual([], recording["gaps"])
            self.assertTrue(all(item["integrity"] == "verified" for item in recording["segments"]))
            expected_node = str(node) if recording["source_id"] == str(remote_source) else None
            self.assertEqual({expected_node}, {item["capture_node_id"] for item in recording["segments"]})
        self.assertTrue(all(len(file.stem) == 32 and file.suffix == ".seg"
                            for file in self.root.iterdir()))

    def test_byte_budget_evicts_spool_without_deleting_linked_evidence(self):
        size = len(self.segment().data)
        self.store.close()
        self.limits = replace(self.limits, pre_roll_bytes=size)
        self.store = self.open_store()
        first = self.store.append(self.segment())
        recording = self.store.start_manual(self.source, 30_000, duration_ms=30_000)
        self.store.append(self.segment(40_000, 50_000, 1))
        self.store.append(self.segment(50_000, 60_000, 2))
        result = self.store.finish(recording)
        self.assertEqual("complete", result["status"])
        self.assertEqual(3, len(result["segments"]))
        self.assertTrue((self.root / (first.hex + ".seg")).exists())
        self.assertEqual(size, self.db.execute(
            "SELECT SUM(byte_length) FROM recording_segments WHERE spool=1").fetchone()[0])

    def test_time_budget_evicts_unreferenced_files_and_reports_missing_pre_roll(self):
        first = self.store.append(self.segment(0, 10_000))
        self.store.append(self.segment(40_000, 50_000, 1))
        self.assertFalse((self.root / (first.hex + ".seg")).exists())
        recording = self.store.start_event(uuid4(), (self.source,), 50_000, post_ms=10_000)[0]
        self.store.append(self.segment(50_000, 60_000, 2))
        result = self.store.finish(recording)
        self.assertEqual("gapped", result["status"])
        self.assertIn({"start_ms": 20_000, "end_ms": 40_000, "reason": "unavailable"}, result["gaps"])

    def test_timer_finishes_without_incoming_media_and_future_is_pending(self):
        recording = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        active = self.store.manifest(recording)
        self.assertEqual([], active["gaps"])
        self.assertEqual("awaiting_media", active["pending"][0]["reason"])
        self.store.advance(40_000 + self.limits.max_segment_ms)
        result = self.store.manifest(recording)
        self.assertEqual("gapped", result["status"])
        self.assertEqual("unavailable", result["gaps"][0]["reason"])

    def test_timer_keeps_boundary_segment_linkable_until_bounded_close(self):
        recording = self.store.start_manual(self.source, 30_000, duration_ms=15_000)
        self.store.append(self.segment(30_000, 40_000))
        self.store.advance(45_000)
        self.assertEqual("active", self.store.manifest(recording)["status"])
        boundary = self.store.append(self.segment(40_000, 50_000, 1))
        self.store.advance(45_000 + self.limits.max_segment_ms)
        result = self.store.manifest(recording)
        self.assertEqual("complete", result["status"])
        self.assertEqual([str(boundary)], [item["id"] for item in result["segments"]
                                            if item["clip_end_ms"] == 45_000])

    def test_manual_and_event_limits_and_invalid_identifiers(self):
        recording = self.store.start_manual(self.source, 30_000)
        self.assertEqual(1_200_000, self.store.manifest(recording)["target_end_ms"] - 30_000)
        for duration in (1_200_001, 0, -1, True):
            with self.assertRaises(ValueError):
                self.store.start_manual(self.source, 0, duration_ms=duration)
        with self.assertRaises(ValueError):
            self.store.start_event(uuid4(), (self.source,), 30_000, post_ms=1_200_000)
        with self.assertRaises(ValueError):
            self.store.start_event(uuid4(), (self.source, self.source), 30_000)
        with self.assertRaises(ValueError):
            self.store.start_manual("../../untrusted", 30_000)

    def test_manifest_clips_boundary_segments_and_early_stop(self):
        self.store.append(self.segment(20_000, 40_000))
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        self.store.append(self.segment(40_000, 60_000, 1))
        result = self.store.finish(recording, stop_ms=45_000)
        self.assertEqual("complete", result["status"])
        self.assertEqual([(30_000, 40_000), (40_000, 45_000)],
                         [(item["clip_start_ms"], item["clip_end_ms"]) for item in result["segments"]])

    def test_manual_stop_keeps_open_boundary_segment_linkable(self):
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        self.store.append(self.segment(30_000, 40_000))
        pending = self.store.finish(recording, stop_ms=45_000)
        self.assertEqual("active", pending["status"])
        boundary = self.store.append(self.segment(40_000, 50_000, 1))
        self.store.advance(45_000 + self.limits.max_segment_ms)
        result = self.store.manifest(recording)
        self.assertEqual("complete", result["status"])
        self.assertEqual([str(boundary)], [item["id"] for item in result["segments"]
                                            if item["clip_end_ms"] == 45_000])

    def test_queued_stop_releases_post_stop_links_and_discontinuities(self):
        recording = self.store.start_manual(self.source, 30_000, duration_ms=40_000)
        self.store.append(self.segment())
        boundary = self.store.append(self.segment(40_000, 50_000, 1))
        after_stop = self.store.append(self.segment(50_000, 60_000, 0, stream_id=uuid4()))
        result = self.store.finish(recording, stop_ms=45_000)
        self.assertEqual("complete", result["status"])
        self.assertEqual([], result["discontinuities"])
        self.assertEqual(2, len(result["segments"]))
        self.assertEqual(2, self.db.execute(
            "SELECT COUNT(*) FROM recording_links WHERE recording_id=?", (str(recording),)
        ).fetchone()[0])
        self.store.release_source(self.source)
        self.assertTrue((self.root / (boundary.hex + ".seg")).exists())
        self.assertFalse((self.root / (after_stop.hex + ".seg")).exists())
        self.assertEqual(result["byte_length"], self.store.usage_bytes())

    def test_corruption_and_missing_segment_never_report_complete(self):
        first = self.store.append(self.segment())
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        second = self.store.append(self.segment(40_000, 50_000, 1))
        self.store.finish(recording)
        (self.root / (first.hex + ".seg")).write_bytes(b"corrupted")
        (self.root / (second.hex + ".seg")).unlink()
        result = self.store.manifest(recording)
        self.assertEqual("gapped", result["status"])
        self.assertEqual({"corrupt", "missing"}, {gap["reason"] for gap in result["gaps"]})

    def test_restart_preserves_segments_and_marks_active_recording_interrupted(self):
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        self.store.append(self.segment())
        self.reopen()
        result = self.store.manifest(recording)
        self.assertEqual("interrupted", result["status"])
        self.assertEqual(40_000, result["ended_ms"])
        self.assertEqual({"start_ms": 40_000, "end_ms": 50_000, "reason": "unavailable"}, result["gaps"][0])
        self.assertEqual("verified", result["segments"][0]["integrity"])

    def test_crash_between_file_and_metadata_commit_recovers_only_journaled_files(self):
        unrelated = self.root / (uuid4().hex + ".seg")
        unrelated.write_bytes(b"not owned by this journal")
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        with patch.object(self.store, "_publish", side_effect=sqlite3.OperationalError("synthetic failure")):
            with self.assertRaisesRegex(RecordingError, "RECORDING_WRITE_FAILED"):
                self.store.append(self.segment())
        self.assertFalse(self.policy.reserved)
        with self.assertRaisesRegex(RecordingError, "WRITER_UNAVAILABLE"):
            self.store.append(self.segment())
        self.assertEqual(2, len(list(self.root.iterdir())))
        self.reopen()
        self.assertEqual([unrelated], list(self.root.iterdir()))
        self.assertEqual("interrupted", self.store.manifest(recording)["status"])
        self.assertEqual(0, self.db.execute("SELECT COUNT(*) FROM recording_segments").fetchone()[0])

    def test_short_write_failure_has_recoverable_pending_row(self):
        with patch("app.media.recording.store.os.write", return_value=0):
            with self.assertRaisesRegex(RecordingError, "WRITE_FAILED"):
                self.store.append(self.segment())
        self.assertEqual(1, len(list(self.root.glob("*.part"))))
        self.reopen()
        self.assertEqual([], list(self.root.iterdir()))

    def test_cancelled_publication_blocks_all_mutation_until_recovery(self):
        with patch.object(self.store, "_write", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.store.append(self.segment())
        self.assertFalse(self.policy.reserved)
        with self.assertRaisesRegex(RecordingError, "WRITER_UNAVAILABLE"):
            self.store.start_manual(self.source, 30_000)
        self.reopen()
        self.store.append(self.segment())

    def test_failed_cleanup_blocks_reopening_and_keeps_pending_accounting(self):
        with patch.object(self.store, "_publish", side_effect=sqlite3.OperationalError("synthetic")):
            with self.assertRaises(RecordingError):
                self.store.append(self.segment())
        self.store.close()
        with patch("app.media.recording.store.os.unlink", side_effect=PermissionError):
            with self.assertRaisesRegex(RecordingError, "STORAGE_UNAVAILABLE"):
                self.open_store()
        self.assertEqual(1, self.db.execute(
            "SELECT COUNT(*) FROM recording_segments WHERE state='pending'").fetchone()[0])
        self.store = self.open_store()

    def test_expected_root_substitution_and_missing_mount_never_create_fallback(self):
        original = self.base / "old-media"
        self.root.rename(original)
        with self.assertRaisesRegex(RecordingError, "ROOT_UNAVAILABLE"):
            self.store.append(self.segment())
        self.assertFalse(self.root.exists())
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(RecordingError, "ROOT_UNAVAILABLE"):
            self.store.append(self.segment())
        self.assertEqual([], list(self.root.iterdir()))
        self.assertEqual([], list(original.iterdir()))

    def test_symlink_parent_and_repository_media_root_refused(self):
        link = self.base / "alias"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(RecordingError, "STORAGE_UNAVAILABLE"):
            self.open_store(root=link / "media")
        repository = self.base / "checkout"
        repository.mkdir()
        (repository / ".git").write_text("synthetic worktree marker")
        with self.assertRaisesRegex(RecordingError, "INSIDE_CHECKOUT"):
            self.open_store(root=repository / "media")

    def test_packaged_layout_does_not_treat_filesystem_root_as_checkout(self):
        self.store.close()
        with patch("app.media.recording.store.__file__", "/app/app/media/recording/store.py"):
            self.store = self.open_store()
            self.store.append(self.segment())
        self.assertEqual(1, len(list(self.root.iterdir())))

    def test_symlink_and_hardlink_media_fail_integrity_without_following_target(self):
        first = self.store.append(self.segment())
        recording = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        file = self.root / (first.hex + ".seg")
        outside = self.base / "outside"
        outside.write_bytes(b"unrelated sensitive content")
        file.unlink()
        file.symlink_to(outside)
        self.assertEqual("unreadable", self.store.finish(recording)["segments"][0]["integrity"])
        file.unlink()
        os.link(outside, file)
        self.assertEqual("corrupt", self.store.manifest(recording)["segments"][0]["integrity"])
        self.assertEqual(b"unrelated sensitive content", outside.read_bytes())

    def test_second_writer_cannot_interrupt_first_writer_and_thread_is_rejected(self):
        recording = self.store.start_manual(self.source, 30_000)
        with self.assertRaisesRegex(RecordingError, "WRITER_BUSY"):
            self.open_store()
        self.assertEqual("active", self.store.manifest(recording)["status"])
        errors = []

        def cross_thread_call():
            try:
                self.store.append(self.segment())
            except RecordingError as exc:
                errors.append(str(exc))

        thread = threading.Thread(target=cross_thread_call)
        thread.start()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(["RECORDING_WRITER_UNAVAILABLE"], errors)

    def test_non_durable_database_connection_is_refused(self):
        self.store.close()
        self.db.execute("PRAGMA synchronous=OFF")
        with self.assertRaisesRegex(RecordingError, "DATABASE_NOT_DURABLE"):
            self.open_store()
        self.db.execute("PRAGMA synchronous=FULL")
        self.store = self.open_store()

    def test_explicit_transactions_close_with_python_sqlite_autocommit(self):
        if not hasattr(self.db, "autocommit"):
            self.skipTest("Python sqlite3 has no autocommit mode")
        original = self.db.autocommit
        self.addCleanup(setattr, self.db, "autocommit", original)
        self.db.autocommit = True
        self.store.append(self.segment())
        self.assertFalse(self.db.in_transaction)
        self.assertFalse(self.policy.reserved)

    def test_denied_reserve_or_pressure_does_not_write_or_delete(self):
        existing = self.store.append(self.segment())
        for reason in ("STORAGE_PRESSURE", "STORAGE_HARD_STOP"):
            self.policy.denial = reason
            with self.assertRaisesRegex(RecordingError, reason):
                self.store.append(self.segment(40_000, 50_000, 1))
            with self.assertRaisesRegex(RecordingError, reason):
                self.store.start_manual(self.source, 40_000)
            self.assertEqual([self.root / (existing.hex + ".seg")], list(self.root.iterdir()))
            self.assertFalse(self.policy.reserved)

    def test_critical_admission_is_explicit_and_still_obeys_guard(self):
        self.store.start_event(uuid4(), (self.source,), 30_000, pre_ms=0, critical=True)
        self.store.append(self.segment())
        self.assertTrue(self.policy.calls[-1][1])
        self.policy.denial = "STORAGE_HARD_STOP"
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            self.store.append(self.segment(40_000, 50_000, 1))

    def test_sequence_or_generation_discontinuity_reported_even_without_time_gap(self):
        self.store.append(self.segment())
        self.store.append(self.segment(40_000, 50_000, 2))
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        result = self.store.finish(recording)
        self.assertEqual("gapped", result["status"])
        self.assertEqual([], result["gaps"])
        self.assertEqual("stream_discontinuity", result["discontinuities"][0]["reason"])
        self.assertEqual((40_000, 40_000),
                         (result["discontinuities"][0]["start_ms"],
                          result["discontinuities"][0]["end_ms"]))
        next_recording = self.store.start_manual(self.source, 50_000, duration_ms=10_000)
        self.store.append(self.segment(50_000, 60_000, 0, stream_id=uuid4()))
        # The new recording begins at this independently decodable generation;
        # the previous generation ends outside its half-open clip interval.
        next_result = self.store.finish(next_recording)
        self.assertEqual("complete", next_result["status"])
        self.assertEqual([], next_result["discontinuities"])
        self.assertEqual(0, self.db.execute(
            "SELECT COUNT(*) FROM recording_discontinuities WHERE recording_id=?",
            (str(next_recording),),
        ).fetchone()[0])

    def test_pre_roll_start_preserves_prior_stream_discontinuity(self):
        self.store.append(self.segment(10_000, 20_000, 0))
        self.store.append(self.segment(40_000, 50_000, 2))
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        result = self.store.finish(recording)
        self.assertEqual("gapped", result["status"])
        self.assertEqual([{"start_ms": 30_000, "end_ms": 40_000,
                           "reason": "stream_discontinuity"}], result["discontinuities"])

    def test_release_source_drops_bounded_source_discontinuities(self):
        self.store.append(self.segment(10_000, 20_000, 0))
        self.store.append(self.segment(40_000, 50_000, 2))
        self.assertEqual(1, self.db.execute(
            "SELECT COUNT(*) FROM recording_source_discontinuities").fetchone()[0])
        self.store.release_source(self.source)
        self.assertEqual(0, self.db.execute(
            "SELECT COUNT(*) FROM recording_source_discontinuities").fetchone()[0])

    def test_cursor_survives_eviction_and_rejects_replays(self):
        self.store.close()
        self.limits = replace(self.limits, pre_roll_bytes=1)
        self.store = self.open_store()
        self.store.append(self.segment())
        self.assertEqual([], list(self.root.iterdir()))
        with self.assertRaisesRegex(RecordingError, "TIMELINE_REGRESSION"):
            self.store.append(self.segment())
        self.reopen()
        with self.assertRaisesRegex(RecordingError, "TIMELINE_REGRESSION"):
            self.store.append(self.segment())

    def test_discontinuity_crossing_start_is_clipped_to_recording_window(self):
        self.store.append(self.segment(10_000, 20_000))
        recording = self.store.start_manual(self.source, 30_000, duration_ms=20_000)
        self.store.append(self.segment(40_000, 50_000, 2))
        result = self.store.finish(recording)
        self.assertEqual("gapped", result["status"])
        self.assertEqual([{"start_ms": 30_000, "end_ms": 40_000,
                           "reason": "stream_discontinuity"}], result["discontinuities"])
        self.assertEqual((30_000, 40_000),
                         (result["gaps"][0]["start_ms"], result["gaps"][0]["end_ms"]))

    def test_source_limit_and_explicit_release_preserve_recordings(self):
        sources = [self.source, uuid4(), uuid4(), uuid4()]
        for source in sources:
            self.store.append(self.segment(source_id=source))
        recording = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        with self.assertRaisesRegex(RecordingError, "SOURCE_LIMIT"):
            self.store.append(self.segment(source_id=uuid4()))
        self.store.release_source(self.source)
        self.store.append(self.segment(source_id=uuid4()))
        self.assertEqual("complete", self.store.finish(recording)["status"])

    def test_late_stop_clips_discontinuity_crossing_both_window_boundaries(self):
        self.store.append(self.segment(10_000, 20_000))
        recording = self.store.start_manual(self.source, 30_000, duration_ms=70_000)
        self.store.append(self.segment(90_000, 100_000, 2))
        result = self.store.finish(recording, stop_ms=50_000)
        self.assertEqual([], result["segments"])
        self.assertEqual([{"start_ms": 30_000, "end_ms": 50_000,
                           "reason": "stream_discontinuity"}], result["discontinuities"])

    def test_row_and_active_recording_limits(self):
        self.store.close()
        self.limits = replace(self.limits, max_spool_segments=1, max_segments_per_recording=1,
                              max_active_recordings=1)
        self.store = self.open_store()
        self.store.append(self.segment())
        self.store.append(self.segment(40_000, 50_000, 1))
        self.assertEqual(1, self.db.execute("SELECT COUNT(*) FROM recording_segments WHERE spool=1").fetchone()[0])
        recording = self.store.start_manual(self.source, 40_000, duration_ms=20_000)
        with self.assertRaisesRegex(RecordingError, "ACTIVE_LIMIT"):
            self.store.start_manual(self.source, 40_000)
        with self.assertRaisesRegex(RecordingError, "SEGMENT_LIMIT"):
            self.store.append(self.segment(50_000, 60_000, 2))
        self.assertFalse(self.policy.reserved)
        self.assertEqual("gapped", self.store.finish(recording)["status"])

    def test_unvalidated_payload_and_oversize_rejected_before_storage(self):
        for segment in (replace(self.segment(), codec="h264"),
                        replace(self.segment(), data=b"x" * 513),
                        replace(self.segment(), data=b"not compressed"),
                        replace(self.segment(), sequence=True),
                        replace(self.segment(), end_ms=2**63)):
            with self.assertRaises((ValueError, zlib.error)):
                self.store.append(segment)
        self.assertEqual([], list(self.root.iterdir()))
        self.assertEqual([], self.policy.calls)

    def test_duplicate_event_is_atomic_and_does_not_allocate_partial_recordings(self):
        event = uuid4()
        self.store.start_event(event, (self.source,), 30_000)
        with self.assertRaisesRegex(RecordingError, "EVENT_EXISTS"):
            self.store.start_event(event, (uuid4(),), 30_000)
        self.assertEqual(1, len(self.store.event_manifest(event)["recordings"]))
        self.assertFalse(self.policy.reserved)

    def test_starred_deletion_and_shared_segment_accounting(self):
        self.store.append(self.segment())
        first = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        second = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        self.store.finish(first)
        self.store.finish(second)
        self.store.release_source(self.source)
        size = len(self.segment().data)
        self.assertEqual(size, self.store.usage_bytes())
        self.store.set_starred(first, True)
        self.assertEqual(size, self.store.usage_bytes(starred_only=True))
        self.assertEqual(0, self.store.delete_recording(second))
        with self.assertRaisesRegex(RecordingError, "DELETE_REFUSED"):
            self.store.delete_recording(first)
        self.assertEqual(size, self.store.delete_recording(first, owner_requested=True))
        self.assertEqual(0, self.store.usage_bytes())
        self.assertEqual([], list(self.root.iterdir()))

    def test_active_recording_cannot_be_deleted_even_by_owner(self):
        recording = self.store.start_manual(self.source, 30_000)
        for owner in (False, True):
            with self.assertRaisesRegex(RecordingError, "DELETE_REFUSED"):
                self.store.delete_recording(recording, owner_requested=owner)
        self.assertEqual("active", self.store.manifest(recording)["status"])

    def test_retention_candidates_order_filter_and_bounded_summaries(self):
        oldest = self.store.start_manual(self.source, 10_000, duration_ms=10_000)
        self.store.finish(oldest)
        newer = self.store.start_manual(self.source, 20_000, duration_ms=10_000)
        self.store.finish(newer)
        self.store.start_manual(self.source, 30_000)
        self.assertEqual([str(oldest)], [item["id"] for item in self.store.retention_candidates(
            before_ms=20_000, limit=10)])
        self.assertEqual([str(oldest)], [item["id"] for item in self.store.retention_candidates(
            before_ms=None, limit=1)])
        self.store.set_starred(oldest, True)
        self.assertEqual([str(newer)], [item["id"] for item in self.store.retention_candidates(
            before_ms=None, limit=10)])
        self.assertEqual(str(newer), self.store.list_recordings(limit=1, offset=1)[0]["id"])
        with self.assertRaises(ValueError):
            self.store.retention_candidates(before_ms=None, limit=1001)

    def test_failed_deletion_preserves_journal_and_recovery_finishes_cleanup(self):
        self.store.append(self.segment())
        recording = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        self.store.finish(recording)
        self.store.release_source(self.source)
        with patch("app.media.recording.store.os.unlink", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                self.store.delete_recording(recording)
        self.assertEqual("deleting", self.db.execute("SELECT status FROM recordings").fetchone()[0])
        self.assertEqual(len(self.segment().data), self.store.usage_bytes())
        self.reopen()
        self.assertEqual(0, self.store.usage_bytes())
        self.assertEqual((), self.store.list_recordings(limit=1))
        self.assertEqual([], list(self.root.iterdir()))

    def test_release_source_cleanup_failure_blocks_later_mutation(self):
        self.store.append(self.segment())
        with patch("app.media.recording.store.os.unlink", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                self.store.release_source(self.source)
        with self.assertRaisesRegex(RecordingError, "WRITER_UNAVAILABLE"):
            self.store.start_manual(self.source, 30_000)

    def test_recovery_refuses_inconsistent_deletion_journal_with_evidence_links(self):
        segment = self.store.append(self.segment())
        recording = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        self.store.finish(recording)
        self.db.execute("UPDATE recordings SET status='deleting' WHERE id=?", (str(recording),))
        self.store.close()
        with self.assertRaisesRegex(RecordingError, "RECORDING_RECOVERY_REQUIRED"):
            self.open_store()
        self.assertTrue((self.root / (segment.hex + ".seg")).exists())
        self.assertEqual(1, self.db.execute("SELECT COUNT(*) FROM recording_links").fetchone()[0])

    def test_critical_usage_counts_shared_and_interrupted_pending_bytes_once(self):
        self.store.append(self.segment())
        first = self.store.start_event(uuid4(), (self.source,), 30_000, pre_ms=0,
                                       post_ms=20_000, critical=True)[0]
        self.store.start_event(uuid4(), (self.source,), 30_000, pre_ms=0,
                               post_ms=20_000, critical=True)
        size = len(self.segment().data)
        self.assertEqual(size, self.store.usage_bytes(critical_only=True))
        self.assertEqual(0, self.store.usage_bytes(starred_only=True, critical_only=True))
        self.store.set_starred(first, True)
        self.assertEqual(size, self.store.usage_bytes(starred_only=True, critical_only=True))
        with patch.object(self.store, "_write", side_effect=OSError):
            with self.assertRaises(RecordingError):
                self.store.append(self.segment(40_000, 50_000, 1))
        self.assertEqual(size * 2, self.store.usage_bytes(critical_only=True))
        self.assertEqual(size * 2, self.store.usage_bytes())

    def test_hard_stop_blocks_metadata_before_any_sql_write_and_keeps_reads(self):
        self.store.append(self.segment())
        completed = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        self.store.finish(completed)
        active = self.store.start_manual(self.source, 40_000, duration_ms=10_000)
        statements = []
        self.db.set_trace_callback(statements.append)
        self.policy.denial = "STORAGE_HARD_STOP"
        for mutation in (lambda: self.store.set_starred(completed, True),
                         lambda: self.store.finish(active),
                         lambda: self.store.delete_recording(completed),
                         lambda: self.store.release_source(self.source)):
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                mutation()
        result = self.store.manifest(completed)
        self.assertEqual("verified", result["segments"][0]["integrity"])
        self.assertFalse(result["integrity_persisted"])
        writes = [sql for sql in statements if sql.split()[0] in
                  {"BEGIN", "COMMIT", "UPDATE", "INSERT", "DELETE"}]
        self.assertEqual([], writes)
        self.db.set_trace_callback(None)

    def test_startup_recovery_requires_control_admission_before_mutation(self):
        self.store.start_manual(self.source, 30_000)
        self.store.close()
        self.policy.denial = "STORAGE_HARD_STOP"
        statements = []
        self.db.set_trace_callback(statements.append)
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            self.open_store()
        self.assertEqual([], [sql for sql in statements if sql.split()[0] in
                              {"BEGIN", "COMMIT", "UPDATE", "INSERT", "DELETE"}])
        self.assertEqual("active", self.db.execute("SELECT status FROM recordings").fetchone()[0])
        self.db.set_trace_callback(None)
        self.policy.denial = None
        self.store = self.open_store()
        self.assertEqual("interrupted", self.db.execute("SELECT status FROM recordings").fetchone()[0])

    def test_control_reservation_survives_cleanup_fsync_and_nested_transactions(self):
        self.store.append(self.segment())
        recording = self.store.start_manual(self.source, 30_000, duration_ms=10_000)
        self.store.finish(recording)
        self.store.release_source(self.source)
        original_fsync = os.fsync
        observed = []

        def reserved_fsync(descriptor):
            observed.append(self.policy.reserved)
            self.assertTrue(self.policy.reserved)
            return original_fsync(descriptor)

        with patch("app.media.recording.store.os.fsync", side_effect=reserved_fsync):
            self.store.delete_recording(recording)
        self.assertTrue(observed)
        self.assertFalse(self.policy.reserved)


if __name__ == "__main__":
    unittest.main()
