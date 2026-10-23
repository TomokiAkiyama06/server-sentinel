"""Issue #317: the UVC session ledger and its process fencing.

Synthetic only: temporary SQLite databases and invented source UUIDs. The
ledger's writer is this test process (or an invented earlier process); the
fencing reads the real ``/proc`` of this test process and of a short-lived
child, or a fake ``/proc`` tree. No camera or service is used; mock only.
"""

from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from app.cameras.registry import CameraRegistry, CaptureProfile, SourceType
from app.cameras.uvc import admin_cli
from app.cameras.uvc import session_ledger
from app.cameras.uvc.identity import DeviceEvidence, ReconnectController
from app.cameras.uvc.persistence import ApprovalStorageError, ApprovalStore
from app.cameras.uvc.session_ledger import (
    LEDGER_NAME, ProcessIdentity, SessionLedger, SessionLedgerError, current_process_identity,
    ledger_path, marker_digest, process_start_time, read_ledger,
)
from app.local_admin import CliRefused
from app.logging import Event
from app.media.recording.model import RecordingError
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


SOURCE = UUID("00000000-0000-4000-8000-000000000001")
OTHER = UUID("00000000-0000-4000-8000-000000000002")


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.path = self.root / "state.sqlite3"
        self.database = Database(self.path)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        info = os.stat(self.path)
        self.identity = (info.st_dev, info.st_ino)
        self.ledger_file = ledger_path(self.path)

    def contents(self):
        return read_ledger(self.ledger_file, account=os.geteuid())


class SessionLedgerTests(Fixture):
    def test_publishes_digests_with_the_writer_identity_privately_and_atomically(self):
        ledger = SessionLedger(self.ledger_file)
        tokens = [str(uuid4()) for _ in range(6)]
        for token in tokens:
            ledger.issue(SOURCE, token)
        ledger.issue(OTHER, tokens[0])
        info = self.ledger_file.stat()
        self.assertEqual((0o600, 1, os.geteuid()), (info.st_mode & 0o777, info.st_nlink, info.st_uid))
        contents = self.contents()
        self.assertEqual(current_process_identity(), contents.writer)
        # Bounded per source: the newest ones (older markers are superseded).
        self.assertEqual({marker_digest(token) for token in tokens[-4:]},
                         contents.sessions[str(SOURCE)])
        raw = self.ledger_file.read_text()
        self.assertFalse(any(token in raw for token in tokens))
        ledger.withdraw(SOURCE, tokens[-1])
        ledger.withdraw(OTHER, tokens[0])
        contents = self.contents()
        self.assertNotIn(marker_digest(tokens[-1]), contents.sessions[str(SOURCE)])
        self.assertNotIn(str(OTHER), contents.sessions)
        # No staging file is left behind.
        self.assertEqual(["state.sqlite3", LEDGER_NAME], sorted(os.listdir(self.root)))

    def test_a_crashed_writer_staging_file_is_removed_on_the_first_publication(self):
        left = self.root / f".{LEDGER_NAME}.0123456789abcdef.tmp"
        left.write_bytes(b"partial")
        unrelated = self.root / ".other.0123456789abcdef.tmp"
        unrelated.write_bytes(b"kept")
        SessionLedger(self.ledger_file).issue(SOURCE, str(uuid4()))
        self.assertFalse(left.exists())
        self.assertTrue(unrelated.exists())

    def test_a_failed_publication_keeps_the_file_and_retains_the_digest_for_the_next(self):
        ledger = SessionLedger(self.ledger_file)
        first, second = str(uuid4()), str(uuid4())
        ledger.issue(SOURCE, first)
        with patch.object(session_ledger.os, "replace", side_effect=OSError(28, "synthetic")):
            with self.assertRaises(SessionLedgerError):  # reported, for the caller to log
                ledger.issue(SOURCE, second)
            # The file is the last complete publication; no staging file is left.
            self.assertEqual({str(SOURCE): frozenset({marker_digest(first)})},
                             self.contents().sessions)
            self.assertEqual(["state.sqlite3", LEDGER_NAME], sorted(os.listdir(self.root)))
            # A withdrawal that cannot publish removes the file instead (its
            # release may fail too): it vouches for nothing until the next
            # publication. Best effort: it does not raise.
            ledger.withdraw(SOURCE, first)
        self.assertIsNone(self.contents())
        self.assertEqual(["state.sqlite3"], sorted(os.listdir(self.root)))
        # The next successful publication (here another source's issue)
        # includes the retained digest, and not the withdrawn one.
        ledger.issue(OTHER, str(uuid4()))
        self.assertEqual(frozenset({marker_digest(second)}), self.contents().sessions[str(SOURCE)])

    def test_the_writer_keeps_the_bounds_the_reader_enforces(self):
        ledger = SessionLedger(self.ledger_file, identity=lambda: ProcessIdentity(
            current_process_identity().boot_id, 2 ** 64 - 1, 2 ** 64 - 1))
        sources = [UUID(int=number) for number in range(1, session_ledger.MAX_SOURCES + 1)]
        for source in sources:
            for _ in range(session_ledger.MAX_DIGESTS_PER_SOURCE + 1):
                ledger.issue(source, str(uuid4()))
        self.assertLessEqual(self.ledger_file.stat().st_size, session_ledger.MAX_LEDGER_BYTES)
        self.assertEqual(session_ledger.MAX_SOURCES, len(self.contents().sessions))
        # One source more is not recorded at all; the file stays readable.
        extra = UUID(int=session_ledger.MAX_SOURCES + 1)
        with self.assertRaises(SessionLedgerError):
            ledger.issue(extra, str(uuid4()))
        ledger.withdraw(sources[0], str(uuid4()))  # publishes again
        contents = self.contents()
        self.assertNotIn(str(extra), contents.sessions)
        self.assertEqual(session_ledger.MAX_SOURCES, len(contents.sessions))
        # The size bound is derived from the source and digest bounds.
        self.assertGreater(session_ledger.MAX_LEDGER_BYTES,
                           session_ledger.MAX_SOURCES * session_ledger.MAX_DIGESTS_PER_SOURCE * 64)

    def test_a_shared_directory_is_refused(self):
        os.chmod(self.root, 0o777)
        self.addCleanup(os.chmod, self.root, 0o700)
        with self.assertRaises(SessionLedgerError):
            SessionLedger(self.ledger_file).issue(SOURCE, str(uuid4()))

    def test_one_ledger_per_database_and_process(self):
        self.assertIs(SessionLedger.for_database(self.database),
                      SessionLedger.for_database(Database(self.path)))
        self.assertEqual(self.ledger_file, SessionLedger.for_database(self.database).path)

    def test_malformed_ledgers_are_refused(self):
        valid = {"format": session_ledger.FORMAT, "boot_id": current_process_identity().boot_id,
                 "pid": 1, "start_time": 0, "sessions": {}}
        cases = [
            b"\xff", b"[]", json.dumps({**valid, "extra": 1}).encode(),
            json.dumps({**valid, "format": "v0"}).encode(),
            json.dumps({**valid, "pid": 0}).encode(),
            json.dumps({**valid, "pid": True}).encode(),
            json.dumps({**valid, "sessions": {"not-a-uuid": []}}).encode(),
            json.dumps({**valid, "sessions": {str(SOURCE): ["A" * 64]}}).encode(),
            json.dumps({**valid, "sessions": {str(SOURCE): ["0" * 64] * 5}}).encode(),
            b" " * (session_ledger.MAX_LEDGER_BYTES + 1),
        ]
        for content in cases:
            self.ledger_file.write_bytes(content)
            os.chmod(self.ledger_file, 0o600)
            with self.subTest(content=content[:40]), self.assertRaises(SessionLedgerError):
                self.contents()
        self.ledger_file.write_bytes(json.dumps(valid).encode())
        self.assertEqual({}, self.contents().sessions)
        self.ledger_file.unlink()
        self.assertIsNone(self.contents())

    def test_process_start_time_counts_fields_after_the_command_name(self):
        proc = self.root / "proc"
        (proc / "42").mkdir(parents=True)
        fields = " ".join(str(number) for number in range(3, 30))
        (proc / "42" / "stat").write_text(f"42 (a) b (c) {fields}\n")
        self.assertEqual(22, process_start_time(42, proc))
        self.assertIsNone(process_start_time(43, proc))
        (proc / "42" / "stat").write_text("42 (truncated) S 1\n")
        with self.assertRaises(SessionLedgerError):
            process_start_time(42, proc)


class CurrentRunMarkerTests(Fixture):
    """``admin_cli._current_run_markers``: a ledger counts only for its live writer."""

    def markers(self, **kwargs):
        return admin_cli._current_run_markers(self.identity, self.path, **kwargs)

    def write(self, identity, token):
        SessionLedger(self.ledger_file, identity=lambda: identity).issue(SOURCE, token)

    def test_the_live_writer_holding_the_database_is_trusted(self):
        token = str(uuid4())
        self.write(current_process_identity(), token)
        self.assertEqual({str(SOURCE): frozenset({marker_digest(token)})}, self.markers())

    def test_a_writer_whose_start_time_changes_during_the_check_is_stale(self):
        # The PID was reused while its descriptors were read: the first
        # check saw the writer, the re-check another process.
        own = current_process_identity()
        self.write(own, str(uuid4()))
        with patch.object(admin_cli, "process_start_time",
                          side_effect=[own.start_time, own.start_time + 1]) as start:
            self.assertEqual({}, self.markers())
        self.assertEqual(2, start.call_count)
        with patch.object(admin_cli, "process_start_time",
                          side_effect=[own.start_time, SessionLedgerError("synthetic")]), \
                self.assertRaises(CliRefused):
            self.markers()

    def test_a_missing_ledger_vouches_for_nothing(self):
        self.assertEqual({}, self.markers())

    def test_a_ledger_of_an_earlier_process_or_boot_is_stale(self):
        own = current_process_identity()
        other_boot = "00000000-0000-4000-8000-000000000000"
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()  # reaped: its PID names no process (barring reuse)
        for identity in (ProcessIdentity(own.boot_id, own.pid, own.start_time + 1),
                         ProcessIdentity(other_boot, own.pid, own.start_time),
                         ProcessIdentity(own.boot_id, child.pid, 0)):
            with self.subTest(identity=identity):
                self.write(identity, str(uuid4()))
                self.assertEqual({}, self.markers())

    def test_a_live_writer_that_does_not_hold_the_database_is_stale(self):
        # Same boot, same PID and start time, but not the service: the
        # database is not among its descriptors.
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys, time\nprint('up', flush=True)\ntime.sleep(60)\n"],
            stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertEqual("up", child.stdout.readline().strip())
        child.stdout.close()
        own = current_process_identity()
        start = process_start_time(child.pid)
        self.write(ProcessIdentity(own.boot_id, child.pid, start), str(uuid4()))
        self.assertEqual({}, self.markers())
        # Another account's ledger is refused before any process is looked at.
        with self.assertRaises(CliRefused):
            self.markers(account=os.geteuid() + 1)

    def test_an_unreadable_boot_or_process_state_refuses(self):
        self.write(current_process_identity(), str(uuid4()))
        proc = self.root / "proc"
        proc.mkdir()
        with self.assertRaises(CliRefused) as refused:  # no boot_id
            self.markers(proc_root=proc)
        self.assertEqual("service_state_unavailable", refused.exception.reason)
        (proc / "sys/kernel/random").mkdir(parents=True)
        (proc / "sys/kernel/random/boot_id").write_text(current_process_identity().boot_id + "\n")
        (proc / str(os.getpid())).mkdir()
        (proc / str(os.getpid()) / "stat").write_text("garbage")
        with self.assertRaises(CliRefused):
            self.markers(proc_root=proc)


class ServiceStoreTests(Fixture):
    """``ApprovalStore`` with the service's ledger: publish before commit, withdraw before release."""

    def setUp(self):
        super().setUp()
        self.source = CameraRegistry(self.database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic source", enabled=True,
            desired_capture_profile=CaptureProfile(640, 480, 10, "MJPG"))
        self.camera = DeviceEvidence("/dev/video0", "synthetic", "model", "serial")
        self.ledger = SessionLedger(self.ledger_file)
        self.store = ApprovalStore(self.database, ledger=self.ledger)

    def listed(self):
        contents = self.contents()
        return set() if contents is None else set(contents.sessions.get(str(self.source.id), ()))

    def test_markers_are_listed_while_held_and_withdrawn_on_release(self):
        started = self.store.start_session(self.source.id, self.camera)
        self.assertEqual({marker_digest(started.session_token)}, self.listed())
        self.store.save(self.source.id, self.camera, started.requires_approval,
                        session_token=started.session_token, serial_ambiguous=False, release=True)
        self.assertIsNone(self.store.load(self.source.id).session_token)
        self.assertEqual(set(), self.listed())

    def test_a_marker_is_published_before_it_is_committed(self):
        seen = []
        real_issue = self.ledger.issue

        def issue(source_id, token):
            real_issue(source_id, token)
            row = self.store.load(source_id)
            seen.append((row.session_token if row else None) != token
                        and marker_digest(token) in self.listed())
        self.ledger.issue = issue
        self.store.start_session(self.source.id, self.camera)
        self.assertEqual([True], seen)

    def approved_start_without_ledger(self):
        """An approved source whose session starts while the ledger cannot be written."""
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, self.source.id, self.camera, serial_ambiguous=False)
            connection.execute("COMMIT")
        with patch.object(session_ledger.os, "replace", side_effect=OSError(28, "synthetic")), \
                self.assertLogs("app.cameras.uvc.persistence", "WARNING") as logs:
            started = self.store.start_session(self.source.id, self.camera)
        self.assertEqual([Event.LOCAL_UVC_SESSION_LEDGER_UNPUBLISHED.value],
                         [record.getMessage() for record in logs.records])
        # A fixed event: no path, marker or digest.
        self.assertNotIn(str(self.root), logs.output[0])
        self.assertNotIn(started.session_token, logs.output[0])
        return started

    def listing(self):
        lines = admin_cli.source_lines(
            CameraRegistry(self.database, unaudited_writes=True), ApprovalStore(self.database),
            {self.source.id}, lambda: admin_cli._current_run_markers(self.identity, self.path))
        return "\n".join(lines)

    def test_a_ledger_that_cannot_be_written_never_stops_the_session(self):
        # Owner decision 2026-10-23: the ledger only serves a display.
        started = self.approved_start_without_ledger()
        self.assertFalse(started.requires_approval)
        self.assertEqual(started.session_token, self.store.load(self.source.id).session_token)
        self.assertNotIn(marker_digest(started.session_token), self.listed())
        # The display falls toward approval_required, never a false in-use.
        self.assertIn("approval=approval_required configured=yes", self.listing())
        self.assertNotIn("approved_in_use", self.listing())

    def test_a_later_successful_publication_includes_the_retained_digest(self):
        started = self.approved_start_without_ledger()
        other = CameraRegistry(self.database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Other source", enabled=True,
            desired_capture_profile=CaptureProfile(640, 480, 10, "MJPG"))
        self.store.start_session(other.id, DeviceEvidence("/dev/video2", "synthetic", "model", "s2"))
        self.assertEqual({marker_digest(started.session_token)}, self.listed())
        self.assertIn("approval=approved_in_use configured=yes", self.listing())
        # Released as usual: withdrawn before the marker is cleared.
        self.store.save(self.source.id, self.camera, False, session_token=started.session_token,
                        serial_ambiguous=False, release=True)
        self.assertEqual(set(), self.listed())

    def test_a_release_that_fails_with_its_withdrawal_never_shows_in_use(self):
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, self.source.id, self.camera, serial_ambiguous=False)
            connection.execute("COMMIT")
        started = self.store.start_session(self.source.id, self.camera)
        self.assertIn("approval=approved_in_use", self.listing())

        class Failing:
            path = self.path

            def connect(self):
                raise __import__("sqlite3").OperationalError("synthetic")
        with patch.object(session_ledger.os, "replace", side_effect=OSError(28, "synthetic")), \
                patch.object(self.store, "database", Failing()), \
                self.assertRaises(ApprovalStorageError):
            self.store.save(self.source.id, self.camera, False, session_token=started.session_token,
                            serial_ambiguous=False, release=True)
        self.assertEqual(started.session_token, self.store.load(self.source.id).session_token)
        self.assertIn("approval=approval_required configured=yes", self.listing())

    def test_a_start_that_fails_to_commit_withdraws_its_marker(self):
        class Failing:
            path = self.path

            def connect(self):
                raise __import__("sqlite3").OperationalError("synthetic")
        store = ApprovalStore(Failing(), ledger=self.ledger)
        with self.assertRaises(ApprovalStorageError):
            store.start_session(self.source.id, self.camera)
        self.assertEqual(set(), self.listed())

    def approve(self):
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, self.source.id, self.camera, serial_ambiguous=False)
            connection.execute("COMMIT")

    def gated_store(self):
        """A store whose storage admission can be refused (a storage hard stop)."""
        gate = {"refused": False}

        @contextmanager
        def reservation():
            if gate["refused"]:
                raise RecordingError("STORAGE_HARD_STOP")
            yield
        return ApprovalStore(self.database, reservation=reservation, ledger=self.ledger), gate

    def test_a_release_the_storage_admission_refuses_never_shows_in_use(self):
        # Review of bfac895: the release never reached its withdrawal, so a
        # marker of an ended session kept showing as approved_in_use.
        self.approve()
        store, gate = self.gated_store()
        started = store.start_session(self.source.id, self.camera)
        self.assertIn("approval=approved_in_use", self.listing())
        gate["refused"] = True
        with self.assertRaises(RecordingError):
            store.save(self.source.id, self.camera, False, session_token=started.session_token,
                       serial_ambiguous=False, release=True)
        self.assertEqual(started.session_token, self.store.load(self.source.id).session_token)
        self.assertNotIn(marker_digest(started.session_token), self.listed())
        self.assertIn("approval=approval_required configured=yes", self.listing())
        # Once the storage recovers, the republished ledger still lacks it.
        gate["refused"] = False
        store.retry_ledger(lambda: 0.0)
        self.assertIsNotNone(self.contents())
        self.assertNotIn(marker_digest(started.session_token), self.listed())
        self.assertIn("approval=approval_required configured=yes", self.listing())

    def test_a_failed_publication_is_retried_by_the_polls(self):
        self.approve()
        with patch.object(session_ledger.os, "replace", side_effect=OSError(28, "synthetic")), \
                self.assertLogs("app.cameras.uvc.persistence", "WARNING"):
            started = self.store.start_session(self.source.id, self.camera)
        self.assertTrue(self.ledger.pending)
        self.assertIn("approval=approval_required", self.listing())
        now = [100.0]
        with patch.object(session_ledger.os, "replace", side_effect=OSError(28, "synthetic")):
            self.store.retry_ledger(lambda: now[0])  # still failing: no raise, still pending
        self.assertTrue(self.ledger.pending)
        now[0] += session_ledger.RETRY_SECONDS - 1
        with patch.object(session_ledger.os, "replace") as replace:
            self.store.retry_ledger(lambda: now[0])  # throttled: no write
        replace.assert_not_called()
        now[0] += 1
        with self.assertLogs("app.cameras.uvc.persistence", "INFO") as logs:
            self.store.retry_ledger(lambda: now[0])
        self.assertEqual([Event.LOCAL_UVC_SESSION_LEDGER_REPUBLISHED.value],
                         [record.getMessage() for record in logs.records])
        self.assertFalse(self.ledger.pending)
        self.assertEqual({marker_digest(started.session_token)}, self.listed())
        self.assertIn("approval=approved_in_use", self.listing())
        # Nothing pending: the poll neither reads the clock nor writes.
        self.store.retry_ledger(lambda: self.fail("clock read without a pending publication"))

    def test_a_controller_that_cannot_be_built_withdraws_its_marker(self):
        # Review of bfac895, proposal 2: start_session committed the marker,
        # then the controller refused; no session runs.
        self.approve()
        other = DeviceEvidence("/dev/video1", "synthetic", "model", "other")
        with self.assertRaises(ValueError):
            ReconnectController(self.source.id, self.camera, lambda event: None,
                                store=self.store, explicit_candidate=other)
        self.assertIsNotNone(self.store.load(self.source.id).session_token)
        self.assertEqual(set(), self.listed())
        self.assertIn("approval=approval_required configured=yes", self.listing())

    def test_withdrawing_a_session_that_never_ran_under_a_refused_admission(self):
        self.approve()
        store, gate = self.gated_store()
        started = store.start_session(self.source.id, self.camera)
        gate["refused"] = True
        store.withdraw_session(self.source.id, started.session_token)  # never raises
        self.assertIsNone(self.contents())
        self.assertTrue(self.ledger.pending)
        self.assertIn("approval=approval_required configured=yes", self.listing())


if __name__ == "__main__":
    unittest.main()
