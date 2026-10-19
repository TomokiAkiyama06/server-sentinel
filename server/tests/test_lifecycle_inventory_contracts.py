"""Section contracts of the split lifecycle inventory (Issue #256).

Each section module re-implements the read-side semantics of one service.
These tests drive that service's real transitions inside the record ->
verify window and pin the section's verdict, so a later change to a
section module (or to the service) that drifts from the other fails here,
next to the module it concerns. All media is generated; nothing here is
real-person or surveillance content.
"""

from __future__ import annotations

import ast
from contextlib import closing, nullcontext
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
from uuid import UUID, uuid4
import zlib

import app
from app import lifecycle_inventory as inventory
from app.audit.store import AuditStore
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.lifecycle_inventory import _common as inventory_common, output as inventory_output
from app.presence.service import PresenceService
from app.storage.database import Database
from tests.test_lifecycle_inventory import Runtime, run


PACKAGE = Path(inventory.__file__).resolve().parent
PAYLOAD = zlib.compress(b"generated geometric test payload" * 4)


class SectionContractTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        patcher = mock.patch.object(inventory_common, "_utcnow", lambda: self.now)
        patcher.start()
        self.addCleanup(patcher.stop)
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.runtime = Runtime(self.base)
        self.notes = self.base / "notes"
        self.notes.mkdir(mode=0o700)

    def record(self) -> Path:
        output = self.notes / f"baseline-{uuid4().hex}.json"
        code, _, stderr = run("record", "--runtime-root", str(self.runtime.root),
                              "--output", str(output))
        self.assertIn(code, (inventory.EXIT_PRESERVED, inventory.EXIT_EMPTY), stderr)
        return output

    def verify(self, baseline: Path) -> tuple[int, dict]:
        report = self.notes / f"report-{uuid4().hex}.json"
        code, _, _ = run("verify", "--runtime-root", str(self.runtime.root),
                         "--baseline", str(baseline), "--report", str(report))
        return code, json.loads(report.read_text())

    def section(self, report: dict, name: str) -> dict:
        return report["sections"][name]

    # -- recordings: RecordingStore -------------------------------------

    def recording_store(self):
        from app.media.recording import RecordingStore, RootIdentity
        from app.media.recording.model import Limits
        from tests.test_recording import Reservation, SyntheticValidator
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        media = self.runtime.root / "recordings"
        info = media.stat()
        store = RecordingStore(connection, media, RootIdentity(info.st_dev, info.st_ino),
                               Limits(pre_roll_bytes=4096, max_segment_bytes=512,
                                      max_segment_ms=30_000, max_active_recordings=8,
                                      max_spool_segments=16, max_segments_per_recording=100),
                               Reservation(), SyntheticValidator())
        self.addCleanup(store.close)
        return store

    def publisher(self, base_ms: int):
        from app.media.recording import Segment
        streams: dict = {}

        def put(store, source, sequence, start, end):
            stream_id = streams.setdefault(source, uuid4())
            return store.append(Segment(source, stream_id, sequence, base_ms + start,
                                        base_ms + end, "synthetic", "deflate", PAYLOAD))
        return put

    def test_recordings_follow_the_real_store_across_stop_and_restart(self):
        # Recordings active at record time grow, one stops early (its later
        # segment trimmed from it), and a restart interrupts the other: the
        # section accepts each as the store's own transition.
        self.runtime.seed()
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        put = self.publisher(base)
        store = self.recording_store()
        manual_source, event_source = uuid4(), uuid4()
        put(store, manual_source, 0, 0, 10_000)
        put(store, event_source, 0, 0, 10_000)
        manual = store.start_manual(manual_source, base + 10_000, duration_ms=40_000)
        event, = store.start_event(uuid4(), (event_source,), base + 20_000,
                                   pre_ms=10_000, post_ms=30_000, critical=True)
        put(store, manual_source, 1, 10_000, 20_000)
        put(store, event_source, 1, 10_000, 20_000)
        baseline = self.record()
        trimmed = put(store, manual_source, 2, 20_000, 30_000)
        store.finish(manual, stop_ms=base + 20_000)
        put(store, event_source, 2, 20_000, 30_000)
        store.close()
        self.recording_store()  # startup recovery interrupts the event
        with closing(sqlite3.connect(self.runtime.database)) as db:
            self.assertEqual(
                db.execute("SELECT status FROM recordings WHERE id IN (?, ?) ORDER BY id = ?",
                           (str(manual), str(event), str(event))).fetchall(),
                [("complete",), ("interrupted",)])
            self.assertIsNone(db.execute("SELECT 1 FROM recording_links WHERE segment_id=?",
                                         (str(trimmed),)).fetchone())
        code, report = self.verify(baseline)
        recordings = self.section(report, "recordings")
        self.assertEqual(code, inventory.EXIT_PRESERVED, json.dumps(recordings)[:2000])
        self.assertEqual(recordings["in_progress_at_record"], sorted([str(manual), str(event)]))
        self.assertLessEqual({str(manual), str(event)}, set(recordings["preserved"]))

    def test_a_lost_link_of_an_active_recording_fails_the_recordings_section(self):
        self.runtime.seed()
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        put = self.publisher(base)
        store = self.recording_store()
        source = uuid4()
        put(store, source, 0, 0, 10_000)
        recording = store.start_manual(source, base + 10_000, duration_ms=40_000)
        baseline = self.record()
        lost = put(store, source, 1, 10_000, 20_000)
        self.runtime.execute("DELETE FROM recording_links WHERE segment_id=?", (str(lost),))
        code, report = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": str(recording), "reason": "changed"},
                      self.section(report, "recordings")["failed"])

    def test_a_critical_unlinked_segment_does_not_prove_a_lost_link(self):
        # #256 item 1: append() records segment critical=1 while an
        # overlapping active recording is critical, so a link lost before a
        # restart leaves a critical=1 unlinked segment behind an interrupted
        # critical recording. The real store reaches the same catalog
        # without any loss: a critical recording started after the restart
        # links the publication (critical=1) and then loses that link to an
        # Owner deletion or to its own early stop. A rule "an unlinked
        # critical=1 segment overlapping an interrupted critical recording
        # is a lost link" would fail these normal operations, so the
        # section keeps judging neither (server/docs/DEPLOYMENT.md).
        for variant in ("owner_deleted", "stopped_early"):
            with self.subTest(variant):
                self.runtime = Runtime(self.base / variant)
                self.runtime.seed()
                base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
                put = self.publisher(base)
                store = self.recording_store()
                source = uuid4()
                put(store, source, 0, 0, 10_000)
                # Window base + 10,000 to base + 50,000.
                interrupted, = store.start_event(uuid4(), (source,), base + 20_000,
                                                 pre_ms=10_000, post_ms=30_000, critical=True)
                put(store, source, 1, 10_000, 20_000)
                baseline = self.record()
                put(store, source, 2, 20_000, 30_000)
                store.close()
                restarted = self.recording_store()
                # A later critical event of the same source: window base +
                # 30,000 to base + 60,000, overlapping the interrupted one.
                later, = restarted.start_event(uuid4(), (source,), base + 40_000,
                                               pre_ms=10_000, post_ms=20_000, critical=True)
                if variant == "owner_deleted":
                    unlinked = put(restarted, source, 3, 30_000, 40_000)
                    restarted.finish(later)
                    restarted.delete_recording(later, owner_requested=True)
                else:
                    put(restarted, source, 3, 30_000, 40_000)
                    unlinked = put(restarted, source, 4, 40_000, 50_000)
                    restarted.finish(later, stop_ms=base + 35_000)
                with closing(sqlite3.connect(self.runtime.database)) as db:
                    self.assertEqual(db.execute(
                        "SELECT status FROM recordings WHERE id=?",
                        (str(interrupted),)).fetchone(), ("interrupted",))
                    # Ready, critical, unlinked from every recording, and
                    # inside the interrupted recording's window.
                    self.assertEqual(db.execute(
                        "SELECT state, critical, start_ms - ? < 50000, "
                        "(SELECT COUNT(*) FROM recording_links WHERE segment_id = s.id) "
                        "FROM recording_segments s WHERE id=?",
                        (base, str(unlinked))).fetchone(), ("ready", 1, 1, 0))
                code, report = self.verify(baseline)
                recordings = self.section(report, "recordings")
                self.assertEqual(code, inventory.EXIT_PRESERVED, json.dumps(recordings)[:2000])
                self.assertIn(str(interrupted), recordings["preserved"])

    # -- pairing: PairingLedger -----------------------------------------

    def test_pairing_follows_the_real_ledger_and_never_reverses(self):
        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32), audit=AuditStore(database),
                               clock=lambda: 100.0, process_epoch=uuid4())
        nodes = [uuid4(), uuid4()]
        for index, node in enumerate(nodes):
            key = hashlib.sha256(f"synthetic-key-{index}".encode()).hexdigest()
            approval, code = ledger.approve(Owner(), "owner", node_id=node,
                                            public_key_digest=key)
            claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                                  public_key_digest=key, code=code.value)
            ledger.activate(claim, not_after=50.0, credential_serial_digest=hashlib.sha256(
                f"synthetic-serial-{index}".encode()).hexdigest())
        baseline = self.record()
        ledger.revoke(Owner(), "owner", node_id=nodes[0])
        code, report = self.verify(baseline)
        self.assertEqual(self.section(report, "security_state")["status"], "preserved",
                         json.dumps(self.section(report, "security_state"))[:2000])
        # A revocation the ledger never reverses, reversed.
        revoked = self.record()
        self.runtime.execute("UPDATE pairing_node_credentials SET state='active' "
                             "WHERE node_id=?", (str(nodes[0]),))
        code, report = self.verify(revoked)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(self.section(report, "security_state")["status"], "failed")

    # -- presence: PresenceService --------------------------------------

    def test_presence_follows_the_real_service_owner_clear(self):
        seeded = self.runtime.seed()
        released, kept = uuid4(), uuid4()
        for identifier in (released, kept):
            self.runtime.observation(identifier, (self.now - timedelta(days=1)).isoformat(
                timespec="microseconds"))
            self.runtime.execute("INSERT INTO presence_deliveries (observation, action, state, "
                                 "attempts) VALUES (?, 'notification', 'pending', 0)",
                                 (str(identifier),))
        baseline = self.record()

        class Owner:
            def require_owner(self, context):
                return UUID(seeded["owner"])
        PresenceService(Database(self.runtime.database), access=Owner(),
                        reservation=nullcontext).clear_unresolved_critical_event(
            "owner", released, now=self.now, clock_trusted=True)
        code, report = self.verify(baseline)
        presence = self.section(report, "presence")
        self.assertEqual(code, inventory.EXIT_PRESERVED, json.dumps(presence)[:2000])
        self.assertEqual(presence["released"], [str(released)])
        # The same removal without the service's Owner clear (no tombstone).
        self.runtime.execute("DELETE FROM presence_deliveries WHERE observation=?", (str(kept),))
        self.runtime.execute("DELETE FROM presence_observations WHERE id=?", (str(kept),))
        code, report = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(self.section(report, "presence")["status"], "failed")

    # -- access: AccessStore --------------------------------------------

    def test_access_follows_the_real_store_sign_in(self):
        from app.auth.session_binding import SessionBindingKey
        from app.auth.store import AccessStore
        database = Database(self.runtime.database)
        clock = [self.now - timedelta(days=1)]

        def tick(**delta):
            clock[0] += timedelta(**delta)
        access = AccessStore(database, clock=lambda: clock[0],
                             audit=AuditStore(database, clock=lambda: clock[0]),
                             unaudited_writes=True, session_binding=SessionBindingKey.generate())
        identity = "shared-tailnet-login@example.invalid"

        def material(label):
            return hashlib.sha256(f"synthetic-{label}".encode()).digest()
        owner = access.bootstrap_owner("Synthetic Owner")
        secret = material("enrollment-secret")
        tick(minutes=1)
        access.issue_enrollment(owner.id, secret, clock[0] + timedelta(minutes=15))
        tick(seconds=20)
        subject = access.begin_registration(secret, identity, material("registration"),
                                            at=clock[0], lifetime=timedelta(minutes=5))
        tick(seconds=5)
        access.consume_challenge(material("registration"), "registration", at=clock[0])
        credential = material("credential-id")
        access.enroll_credential(secret, identity, credential, material("key"), -7, 0,
                                 invitation_id=subject.invitation_id)
        baseline = self.record()

        def sign_in(count, token):
            tick(seconds=30)
            access.issue_authentication_challenge(material(f"authentication-{count}"),
                                                  at=clock[0], lifetime=timedelta(minutes=5))
            tick(seconds=3)
            access.consume_challenge(material(f"authentication-{count}"), "authentication",
                                     at=clock[0])
            access.accept_assertion(credential, owner.id, identity,
                                    expected_sign_count=count - 1, sign_count=count,
                                    backup_state=False, at=clock[0], token=token)
        sign_in(1, material("session-token"))
        code, report = self.verify(baseline)
        principals = self.section(report, "access_principals")
        self.assertEqual(principals["status"], "preserved", json.dumps(principals)[:2000])
        # The counter the store only raises, rolled back.
        advanced = self.record()
        self.runtime.execute("UPDATE access_credentials SET sign_count=0")
        code, report = self.verify(advanced)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(self.section(report, "access_principals")["status"], "failed")

    # -- package structure ----------------------------------------------

    def test_every_section_reads_the_one_replaceable_clock(self):
        # _utcnow() is looked up on _common by every caller, so a test or a
        # future caller that replaces it sets one verify time everywhere; a
        # by-name import would silently keep the wall clock in that module.
        for path in sorted(PACKAGE.glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn("_utcnow", [alias.name for alias in node.names], path.name)
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "now"):
                    self.assertEqual(path.name, "_common.py", ast.unparse(node))

    def test_the_installed_package_directory_stays_a_refused_root(self):
        # The package moved one level down (app/lifecycle_inventory/): the
        # refused root is still the directory that holds ``app``.
        release = Path(app.__file__).resolve().parents[1]
        self.assertIn(release, inventory_output._refused_roots(self.runtime.root))


if __name__ == "__main__":
    unittest.main()
