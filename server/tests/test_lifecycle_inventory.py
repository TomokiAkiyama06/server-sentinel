"""Synthetic lifecycle preservation inventory tests (Issue #47).

All rows, identities, secrets and segment bytes are generated placeholders;
no real person, deployment value or playable media is involved.
"""

from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
from uuid import UUID, uuid4, uuid5

from app import lifecycle_inventory as inventory
from app.audit.store import AuditStore
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingError, PairingLedger
from app.detection.owner import store as owner_store
from app.monitoring.runtime import EVENT_NAMESPACE
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


IDENTITY_MARKER = "synthetic-principal-identity-marker"
NAME_MARKER = "Synthetic Display Name Marker"
SECRET_DIGEST = bytes(range(32))
TOKEN_DIGEST = bytes(range(32, 64))
CREDENTIAL_ID = b"synthetic-credential-id-marker"
CREDENTIAL_LABEL = "synthetic-credential-label-marker"
BINDING_DIGEST = bytes(range(64, 96))


def stream(label: str) -> str:
    """The stream UUID a synthetic stream label stands for (RecordingStore
    writes str(UUID) stream identities)."""
    return str(uuid5(EVENT_NAMESPACE, "synthetic-stream:" + label))


class Runtime:
    """A disposable runtime tree: state/state.sqlite3 plus recordings/."""

    def __init__(self, base: Path):
        self.root = base / "runtime"
        for name in ("state", "recordings", "audit"):
            (self.root / name).mkdir(parents=True, mode=0o700)
        self.database = self.root / "state" / "state.sqlite3"
        with closing(Database(self.database).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = 1_700_000_000_000_000

    def execute(self, sql: str, parameters=()):
        with closing(sqlite3.connect(self.database, isolation_level=None)) as connection:
            connection.execute(sql, parameters)

    def recording(self, *, starred: bool, payload: bytes, status: str = "completed",
                  source_id: str | None = None, target_end_ms: int = 10000) -> str:
        recording_id, segment_id = str(uuid4()), str(uuid4())
        source_id = source_id or str(uuid4())
        self.segment_file(segment_id, payload)
        self.execute(
            "INSERT INTO recording_segments (id, source_id, stream_id, sequence, start_ms, "
            "end_ms, codec, container, byte_length, sha256, state, spool) "
            "VALUES (?, ?, ?, ?, 0, 10000, 'synthetic', 'deflate', ?, ?, 'ready', 0)",
            (segment_id, source_id, stream("s"), self.clock, len(payload),
             hashlib.sha256(payload).hexdigest()))
        self.clock += 1
        self.execute(
            "INSERT INTO recordings (id, source_id, start_ms, target_end_ms, ended_ms, "
            "status, critical, starred) VALUES (?, ?, 0, ?, ?, ?, 0, ?)",
            (recording_id, source_id, target_end_ms,
             None if status == "active" else target_end_ms, status, int(starred)))
        self.execute("INSERT INTO recording_links VALUES (?, ?)", (recording_id, segment_id))
        return recording_id

    def add_segment(self, recording_id: str, payload: bytes, *, write_file: bool = True,
                    catalog_payload: bytes | None = None, source_id: str | None = None,
                    start_ms: int = 10000, end_ms: int = 20000, stream_id: str = "s",
                    sequence: int | None = None) -> str:
        """Link a ready segment; by default from the recording's own source,
        as the recording store only links source-matched overlapping media,
        and continuing the latest linked segment's stream (no marker due)."""
        segment_id = str(uuid4())
        stream_id = stream(stream_id)
        with closing(sqlite3.connect(self.database)) as connection:
            if source_id is None:
                source_id = connection.execute(
                    "SELECT source_id FROM recordings WHERE id=?", (recording_id,)).fetchone()[0]
            if sequence is None:
                latest = connection.execute(
                    "SELECT s.stream_id, s.sequence FROM recording_segments s "
                    "JOIN recording_links l ON l.segment_id=s.id WHERE l.recording_id=? "
                    "ORDER BY s.start_ms DESC, s.end_ms DESC LIMIT 1", (recording_id,)).fetchone()
                sequence = (latest[1] + 1 if latest is not None and latest[0] == stream_id
                            else self.clock)
        if write_file:
            self.segment_file(segment_id, payload)
        self.execute(
            "INSERT INTO recording_segments (id, source_id, stream_id, sequence, start_ms, "
            "end_ms, codec, container, byte_length, sha256, state, spool) "
            "VALUES (?, ?, ?, ?, ?, ?, 'synthetic', 'deflate', ?, ?, 'ready', 0)",
            (segment_id, source_id, stream_id, sequence, start_ms, end_ms, len(payload),
             hashlib.sha256(catalog_payload if catalog_payload is not None
                            else payload).hexdigest()))
        self.clock += 1
        self.execute("INSERT INTO recording_links VALUES (?, ?)", (recording_id, segment_id))
        return segment_id

    def segment_file(self, segment_id: str, payload: bytes) -> None:
        path = self.root / "recordings" / (UUID(segment_id).hex + ".seg")
        path.write_bytes(payload)

    def segment_path(self, recording_id: str) -> Path:
        with closing(sqlite3.connect(self.database)) as connection:
            segment_id = connection.execute(
                "SELECT segment_id FROM recording_links WHERE recording_id=?",
                (recording_id,)).fetchone()[0]
        return self.root / "recordings" / (UUID(segment_id).hex + ".seg")

    def audit(self) -> str:
        row_id = str(uuid4())
        self.execute(
            "INSERT INTO security_admin_audit_records VALUES (?, 'owner', 'camera_source.update', "
            "'camera_source', ?, ?, 'succeeded')", (row_id, str(uuid4()), self.clock))
        self.clock += 1_000_000
        return row_id

    def source(self) -> str:
        source_id = str(uuid4())
        self.execute(
            "INSERT INTO camera_sources (id, capture_node_id, source_type, name, enabled, "
            "capabilities, health_state, image_quality_state, created_at, updated_at) "
            "VALUES (?, NULL, 'local_uvc', 'synthetic', 1, '{}', 'offline', 'unknown', "
            "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')", (source_id,))
        return source_id

    def principal(self, role: str, permissions: tuple[str, ...], *,
                  status: str = "active", revoked: bool = False) -> str:
        principal_id = str(uuid4())
        self.execute(
            "INSERT INTO access_principals (id, external_identity, display_name, role, status, "
            "authorization_revision, created_at_us, revoked_at_us) VALUES (?, ?, ?, ?, ?, 0, 1, ?)",
            (principal_id, f"{IDENTITY_MARKER}-{principal_id}", NAME_MARKER, role, status,
             2 if revoked else None))
        for permission in permissions:
            self.execute("INSERT INTO access_principal_permissions VALUES (?, ?)",
                         (principal_id, permission))
        return principal_id

    def invitation(self, principal_id: str, *, revoked: bool) -> str:
        invitation_id = str(uuid4())
        digest = SECRET_DIGEST if revoked else bytes(reversed(SECRET_DIGEST))
        self.execute(
            "INSERT INTO access_invitations (id, secret_digest, principal_id, principal_revision, "
            "deployment_generation, issued_at_us, expires_at_us, redeemed_at_us, revoked_at_us, "
            "attempt_count) VALUES (?, ?, ?, 0, 0, 1, 2, NULL, ?, 0)",
            (invitation_id, digest, principal_id, 3 if revoked else None))
        return invitation_id

    def seed(self) -> dict:
        owner = self.principal("owner", ())
        live = self.principal("invited_user", ("live:view",))
        recordings = self.principal("invited_user", ("recordings:view",))
        revoked = self.principal("invited_user", ("live:view", "recordings:view"),
                                 status="revoked", revoked=True)
        self.execute(
            "INSERT INTO access_credentials (credential_id, principal_id, public_key, algorithm, "
            "sign_count, enrolled_at_us, revoked_at_us, backup_eligible, backup_state, label) "
            "VALUES (?, ?, X'00', -7, 0, 1, NULL, 0, 0, ?)", (CREDENTIAL_ID, owner, CREDENTIAL_LABEL))
        self.execute(
            "INSERT INTO access_sessions (id, token_digest, principal_id, credential_id, "
            "principal_revision, deployment_generation, established_at_us, last_seen_at_us, "
            "idle_lifetime_us, idle_expires_at_us, absolute_expires_at_us, invalidated_at_us, "
            "external_identity_binding, binding_mismatch_suppressed) "
            "VALUES (?, ?, ?, ?, 0, 0, 1, 1, 10, 11, 20, NULL, ?, 0)",
            (str(uuid4()), TOKEN_DIGEST, owner, CREDENTIAL_ID, BINDING_DIGEST))
        self.invitation(live, revoked=False)
        self.invitation(revoked, revoked=True)
        source = self.source()
        return {
            "ordinary": self.recording(starred=False, payload=b"generated-ordinary-bytes",
                                       source_id=source),
            "starred": self.recording(starred=True, payload=b"generated-starred-bytes!",
                                      source_id=source),
            "audit": [self.audit() for _ in range(5)],
            "owner": owner, "live": live, "recordings": recordings, "revoked": revoked,
        }


def run(*arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = inventory.main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


class LifecycleInventoryTests(unittest.TestCase):
    def setUp(self):
        # Verify time for the service retention rules, a day after the
        # synthetic audit clock starts; retention tests move it explicitly.
        self.now = datetime.fromtimestamp(1_700_000_000 + 86_400, timezone.utc)
        patcher = mock.patch.object(inventory, "_utcnow", lambda: self.now, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._directory = TemporaryDirectory()
        self.base = Path(self._directory.name)
        self.runtime = Runtime(self.base)
        self.notes = self.base / "notes"
        self.notes.mkdir(mode=0o700)

    def tearDown(self):
        self._directory.cleanup()

    def record(self, name="baseline.json", *extra: str) -> tuple[int, Path]:
        output = self.notes / name
        code, _, _ = run("record", "--runtime-root", str(self.runtime.root),
                         "--output", str(output), *extra)
        return code, output

    def owner_template_root(self, *, template: bytes | None = None) -> Path:
        """A synthetic Owner-template store; the bytes are a generated marker."""
        root = self.base / "owner-template"
        root.mkdir(mode=0o700, exist_ok=True)
        with closing(sqlite3.connect(root / "owner-template.sqlite3",
                                     isolation_level=None)) as connection:
            migrate(connection, owner_store._MIGRATIONS)
            if template is not None:
                connection.execute(
                    "UPDATE owner_template SET generation=1, template=?, "
                    "provenance='synthetic-provenance-marker' WHERE singleton=1", (template,))
                for operation in ("enroll", "replace"):
                    connection.execute(
                        "INSERT INTO owner_template_audit(at, actor, operation, generation) "
                        "VALUES ('2026-01-01T00:00:00+00:00', 'owner', ?, 1)", (operation,))
        # OwnerTemplateStore creates the database 0600 in a 0700 root.
        os.chmod(root / "owner-template.sqlite3", 0o600)
        return root

    def verify(self, baseline: Path, *extra: str) -> tuple[int, dict, str]:
        report = self.notes / f"report-{uuid4().hex}.json"
        code, stdout, _ = run("verify", "--runtime-root", str(self.runtime.root),
                              "--baseline", str(baseline), "--report", str(report), *extra)
        return code, json.loads(report.read_text()), stdout

    def test_unchanged_seeded_state_is_preserved_and_private(self):
        self.runtime.seed()
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(stat.S_IMODE(baseline.stat().st_mode), 0o600)
        recorded = json.loads(baseline.read_text())
        self.assertTrue(all(value == "present" for value in recorded["coverage"].values()))
        code, report, stdout = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["status"], "preserved")
        self.assertEqual(report["sections"]["audit_security_admin"]["preserved_rows"], 5)
        self.assertTrue(report["owner_present"])
        # The console summary carries statuses and counts, never IDs or digests.
        self.assertNotIn(recorded["audit"]["security_admin"]["chain_sha256"], stdout)
        for recording_id in recorded["recordings"]:
            self.assertNotIn(recording_id, stdout)

    def test_same_size_byte_replacement_is_detected(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        path = self.runtime.segment_path(seeded["starred"])
        original = path.read_bytes()
        replaced = bytes(reversed(original))
        self.assertEqual(len(replaced), len(original))
        self.assertNotEqual(replaced, original)
        path.write_bytes(replaced)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["status"], "failed")
        self.assertIn({"id": seeded["starred"], "reason": "changed"},
                      report["sections"]["recordings"]["failed"])
        self.assertNotIn(seeded["starred"], report["sections"]["recordings"]["preserved"])

    def test_changed_middle_audit_row_is_detected(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        middle = seeded["audit"][2]
        # Simulate out-of-band tampering that the immutability trigger forbids
        # the application itself; count and boundary rows stay identical.
        self.runtime.execute("DROP TRIGGER security_admin_audit_no_update")
        self.runtime.execute(
            "UPDATE security_admin_audit_records SET outcome='denied' WHERE id=?", (middle,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["audit_security_admin"]
        self.assertEqual(section["failed"], [{"id": middle, "reason": "changed"}])
        self.assertFalse(section["chain_match"])

    def test_deleted_audit_row_and_missing_recording_are_failures(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        self.runtime.execute("DELETE FROM security_admin_audit_records WHERE id=?",
                             (seeded["audit"][1],))
        self.runtime.segment_path(seeded["ordinary"]).unlink()
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["audit"][1], "reason": "missing"},
                      report["sections"]["audit_security_admin"]["failed"])
        self.assertIn({"id": seeded["ordinary"], "reason": "changed"},
                      report["sections"]["recordings"]["failed"])

    def test_appended_rows_are_listed_separately_not_counted_as_preserved(self):
        self.runtime.seed()
        _, baseline = self.record()
        appended_audit = self.runtime.audit()
        appended_recording = self.runtime.recording(starred=False, payload=b"generated-later")
        appended_source = self.runtime.source()
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        audit = report["sections"]["audit_security_admin"]
        self.assertEqual(audit["appended"], [appended_audit])
        self.assertEqual(audit["preserved_rows"], 5)
        self.assertTrue(audit["chain_match"])
        recordings = report["sections"]["recordings"]
        self.assertEqual(recordings["appended"], [appended_recording])
        self.assertNotIn(appended_recording, recordings["preserved"])
        self.assertEqual(len(recordings["preserved"]), 2)
        self.assertEqual(report["sections"]["camera_sources"]["appended"], [appended_source])

    def test_empty_inventory_is_reported_empty_not_success(self):
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_EMPTY)
        recorded = json.loads(baseline.read_text())
        self.assertTrue(all(value == "empty" for value in recorded["coverage"].values()))
        code, report, stdout = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_EMPTY)
        self.assertEqual(report["status"], "empty")
        self.assertEqual(report["sections"]["recordings"]["status"], "empty")
        self.assertEqual(report["sections"]["audit_security_admin"]["status"], "empty")
        self.assertIn("coverage starred_recording: empty", stdout)
        self.assertNotIn("verification: preserved", stdout)

    def test_partially_seeded_inventory_is_not_success(self):
        self.runtime.recording(starred=False, payload=b"generated-ordinary-only")
        self.runtime.audit()
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_EMPTY)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_EMPTY)
        self.assertEqual(report["status"], "empty")
        self.assertIn("starred_recording", report["empty_coverage"])
        self.assertIn("owner", report["empty_coverage"])

    def test_output_never_contains_identity_credentials_or_token_digests(self):
        self.runtime.seed()
        _, baseline = self.record()
        _, _, _ = self.verify(baseline)
        for path in self.notes.iterdir():
            text = path.read_text()
            for marker in (IDENTITY_MARKER, NAME_MARKER, SECRET_DIGEST.hex(),
                           bytes(reversed(SECRET_DIGEST)).hex(), TOKEN_DIGEST.hex(),
                           CREDENTIAL_ID.hex(), CREDENTIAL_ID.decode(),
                           CREDENTIAL_LABEL, BINDING_DIGEST.hex(),
                           "external_identity", "display_name", "secret_digest",
                           "token_digest", "public_key", "label"):
                self.assertNotIn(marker, text, path.name)

    def test_credential_marked_inconsistent_is_not_active(self):
        # An inconsistent credential cannot authenticate (effective status
        # INCONSISTENT), so it no longer counts as active.
        seeded = self.runtime.seed()
        _, baseline = self.record()
        self.runtime.execute(
            "UPDATE access_credentials SET inconsistent_at_us=5, "
            "inconsistency_reason='backup_eligibility_changed' WHERE principal_id=?",
            (seeded["owner"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["owner"], "reason": "changed"},
                      report["sections"]["access_principals"]["failed"])

    def test_invitation_validity_changes_are_detected_without_secrets(self):
        # Each change below makes an unredeemed code unusable; none involves
        # the secret digest, which stays out of the output.
        self.runtime.seed()
        live = self.runtime.principal("invited_user", ("live:view",), status="invited")
        changes = {
            "attempts": "UPDATE access_invitations SET attempt_count=5 WHERE id=?",
            "expiry": "UPDATE access_invitations SET expires_at_us=1 WHERE id=?",
            "revision": "UPDATE access_invitations SET principal_revision=7 WHERE id=?",
            "generation": "UPDATE access_invitations SET deployment_generation=7 WHERE id=?",
        }
        ids = {}
        for index, label in enumerate(changes):
            ids[label] = str(uuid4())
            self.runtime.execute(
                "INSERT INTO access_invitations (id, secret_digest, principal_id, "
                "principal_revision, deployment_generation, issued_at_us, expires_at_us, "
                "redeemed_at_us, revoked_at_us, attempt_count) "
                "VALUES (?, ?, ?, 0, 0, 1, 10, NULL, NULL, 0)",
                (ids[label], bytes([index + 1]) * 32, live))
        _, baseline = self.record()
        for label, statement in changes.items():
            self.runtime.execute(statement, (ids[label],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["access_invitations"]["failed"]
        for label in changes:
            self.assertIn({"id": ids[label], "reason": "changed"}, failed)
        for path in self.notes.iterdir():
            for index in range(len(changes)):
                self.assertNotIn((bytes([index + 1]) * 32).hex(), path.read_text())

    def test_deployment_generation_advance_invalidates_recorded_invitations(self):
        self.runtime.seed()
        _, baseline = self.record()
        recorded = json.loads(baseline.read_text())["access"]["invitations"]
        self.runtime.execute(
            "UPDATE access_deployment_state SET authorization_generation=1 WHERE singleton=1")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["access_invitations"]["failed"]
        for invitation_id in recorded:
            self.assertIn({"id": invitation_id, "reason": "changed"}, failed)

    def test_camera_source_configuration_and_approval_are_preserved_privately(self):
        self.runtime.seed()
        serial, device = "synthetic-serial-marker-0001", "/dev/synthetic-video-marker"

        def evidence(serial_value: str, path: str = device, token=None) -> str:
            return json.dumps({
                "device_path": path, "vendor": "synthetic-vendor-marker", "product": "0102",
                "serial": serial_value, "interface": "0",
                "by_id": ["usb-synthetic-by-id-marker"], "topology": "synthetic-topology-marker",
                "formats": ["MJPG"], "device_number": 3, "instance_token": token})
        labels = ("steady", "disabled", "profile", "binding", "approval", "requires", "health")
        ids = {}
        for label in labels:
            ids[label] = self.runtime.source()
            self.runtime.execute(
                "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, "
                "session_token, serial_ambiguous, explicit_binding) VALUES (?, ?, 0, ?, 0, 0)",
                (ids[label], evidence(serial + label), "synthetic-session-" + label))
        _, baseline = self.record()
        # Volatile live state: re-enumeration, a new session, health, timestamps.
        self.runtime.execute(
            "UPDATE uvc_approvals SET evidence=?, session_token=NULL WHERE source_id=?",
            (evidence(serial + "steady", "/dev/synthetic-other", [1, 2, 3]), ids["steady"]))
        self.runtime.execute(
            "UPDATE camera_sources SET health_state='online', last_seen_at='2026-02-01', "
            "updated_at='2026-02-01', negotiated_capture_profile='{}' WHERE id=?",
            (ids["health"],))
        # Operational configuration and durable approval changes.
        self.runtime.execute("UPDATE camera_sources SET enabled=0 WHERE id=?", (ids["disabled"],))
        self.runtime.execute("UPDATE camera_sources SET desired_capture_profile='{\"fps\":5}' "
                             "WHERE id=?", (ids["profile"],))
        self.runtime.execute(
            "INSERT INTO detection_bindings VALUES (?, 'person', 'person', 1, 1, '{}', '{}')",
            (ids["binding"],))
        self.runtime.execute("UPDATE uvc_approvals SET evidence=? WHERE source_id=?",
                             (evidence(serial + "replaced"), ids["approval"]))
        self.runtime.execute("UPDATE uvc_approvals SET requires_approval=1 WHERE source_id=?",
                             (ids["requires"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["camera_sources"]
        for label in ("steady", "health"):
            self.assertIn(ids[label], section["preserved"])
        for label in ("disabled", "profile", "binding", "approval"):
            self.assertIn({"id": ids[label], "reason": "changed"}, section["failed"])
        # Only the durable re-approval latch differs: named, still a failure.
        self.assertIn({"id": ids["requires"], "reason": "reapproval_required"},
                      section["failed"])
        for path in self.notes.iterdir():
            text = path.read_text()
            for marker in (serial, device, "synthetic-by-id-marker", "synthetic-topology-marker",
                           "synthetic-session-", "synthetic-vendor-marker"):
                self.assertNotIn(marker, text, path.name)

    def test_weak_evidence_camera_after_restart_needs_reapproval(self):
        # ReconnectController latches a camera without a unique serial for
        # Owner re-approval after every restart; after a reboot its instance
        # marker changes too. Reported as reapproval_required, never
        # preserved; a further configuration change stays plain 'changed'.
        self.runtime.seed()

        def evidence(token) -> str:
            return json.dumps({
                "device_path": "/dev/video0", "vendor": "0001", "product": "0002",
                "serial": None, "interface": "0", "by_id": [], "topology": "1-1",
                "formats": ["MJPG"], "device_number": 3, "instance_token": token})
        ids = {label: self.runtime.source() for label in ("restart", "reboot", "edited")}
        for source_id in ids.values():
            self.runtime.execute(
                "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, "
                "session_token, serial_ambiguous, explicit_binding) VALUES (?, ?, 0, NULL, 0, 0)",
                (source_id, evidence([1, 2, 3])))
        _, baseline = self.record()
        self.runtime.execute("UPDATE uvc_approvals SET requires_approval=1")
        self.runtime.execute("UPDATE uvc_approvals SET evidence=? WHERE source_id=?",
                             (evidence([9, 9, 9]), ids["reboot"]))
        self.runtime.execute("UPDATE camera_sources SET enabled=0 WHERE id=?", (ids["edited"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["camera_sources"]["failed"]
        for label in ("restart", "reboot"):
            self.assertIn({"id": ids[label], "reason": "reapproval_required"}, failed)
        self.assertIn({"id": ids["edited"], "reason": "changed"}, failed)

    def test_service_retention_deletions_are_listed_not_failed(self):
        # The service's own retention runs at startup and on its schedule, so
        # an update restart deletes what has expired. Exactly those rows are
        # listed as retention_expired (never preserved); anything short of
        # the rule, starred or still active stays a failure. Capacity-pressure
        # deletion of the oldest recordings is not accepted.
        self.runtime.seed()
        now = self.now
        audit_cutoff = now - timedelta(days=90)
        cutoff_us = int(audit_cutoff.timestamp()) * 1_000_000 + audit_cutoff.microsecond
        now_ms = int(now.timestamp() * 1000)
        audit_ms, recording_ms = now_ms - 90 * 86_400_000, now_ms - 20 * 86_400_000
        audit_ids = {"expired": str(uuid4()), "short": str(uuid4())}
        for label, occurred in (("expired", cutoff_us - 1), ("short", cutoff_us + 1_000_000)):
            self.runtime.execute(
                "INSERT INTO security_admin_audit_records VALUES (?, 'owner', "
                "'camera_source.update', 'camera_source', ?, ?, 'succeeded')",
                (audit_ids[label], str(uuid4()), occurred))
        for at in ((audit_cutoff - timedelta(seconds=1)).isoformat(),
                   (audit_cutoff + timedelta(seconds=1)).isoformat()):
            self.runtime.execute(
                "INSERT INTO integrity_audit(at, actor, revision) VALUES (?, 'owner', 1)", (at,))
        for at_ms in (audit_ms - 1, audit_ms):
            self.runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                                 "current_state) VALUES (?, 'normal', 'pressure')", (at_ms,))
        recordings = {}
        for label, (status, ended, starred, critical) in {
                "expired": ("complete", recording_ms, False, False),
                "expired-gapped-critical": ("gapped", recording_ms - 1, False, True),
                "short": ("complete", recording_ms + 1000, False, False),
                "starred": ("complete", recording_ms - 1, True, False),
                "active": ("active", None, False, False)}.items():
            recordings[label] = self.runtime.recording(
                starred=starred, payload=b"generated-retention-" + label.encode(),
                status="active")
            self.runtime.execute("UPDATE recordings SET status=?, ended_ms=?, critical=? "
                                 "WHERE id=?", (status, ended, int(critical), recordings[label]))
        _, baseline = self.record()
        with closing(sqlite3.connect(self.runtime.database)) as connection:
            integrity_ids = [str(row[0]) for row in connection.execute(
                "SELECT id FROM integrity_audit ORDER BY id DESC LIMIT 2")][::-1]
            storage_ids = [str(row[0]) for row in connection.execute(
                "SELECT id FROM storage_state_audit ORDER BY id DESC LIMIT 2")][::-1]
        self.runtime.execute("DELETE FROM security_admin_audit_records WHERE id IN (?, ?)",
                             tuple(audit_ids.values()))
        self.runtime.execute("DELETE FROM integrity_audit WHERE id IN (?, ?)",
                             tuple(integrity_ids))
        self.runtime.execute("DELETE FROM storage_state_audit WHERE id IN (?, ?)",
                             tuple(storage_ids))
        for recording_id in recordings.values():
            self.runtime.execute("DELETE FROM recording_links WHERE recording_id=?",
                                 (recording_id,))
            self.runtime.execute("DELETE FROM recordings WHERE id=?", (recording_id,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        sections = report["sections"]
        self.assertEqual(sections["audit_security_admin"]["retention_expired"],
                         [audit_ids["expired"]])
        self.assertEqual(sections["audit_security_admin"]["failed"],
                         [{"id": audit_ids["short"], "reason": "missing"}])
        self.assertEqual(sections["audit_integrity"]["retention_expired"], [integrity_ids[0]])
        self.assertEqual(sections["audit_integrity"]["failed"],
                         [{"id": integrity_ids[1], "reason": "missing"}])
        self.assertEqual(sections["audit_storage_state"]["retention_expired"], [storage_ids[0]])
        self.assertEqual(sections["audit_storage_state"]["failed"],
                         [{"id": storage_ids[1], "reason": "missing"}])
        section = sections["recordings"]
        # RecordingStore.retention_candidates() does not exclude critical work.
        self.assertEqual(section["retention_expired"],
                         sorted([recordings["expired"], recordings["expired-gapped-critical"]]))
        for label in ("short", "starred", "active"):
            self.assertIn({"id": recordings[label], "reason": "missing"}, section["failed"])
            self.assertNotIn(recordings[label], section["preserved"])
        # Judged at an earlier verify time, nothing had expired yet.
        self.now = now - timedelta(days=1000)
        code, report, _ = self.verify(baseline)
        for name in ("recordings", "audit_security_admin", "audit_integrity",
                     "audit_storage_state"):
            self.assertEqual(report["sections"][name]["retention_expired"], [], name)

    def test_only_retention_deletions_still_verify_as_preserved(self):
        self.runtime.seed()
        now_ms = int(self.now.timestamp() * 1000)
        expired = self.runtime.recording(starred=False, payload=b"generated-retention-only",
                                         status="active")
        self.runtime.execute("UPDATE recordings SET status='complete', ended_ms=? WHERE id=?",
                             (now_ms - 21 * 86_400_000, expired))
        self.runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                             "current_state) VALUES (?, 'normal', 'pressure')",
                             (now_ms - 91 * 86_400_000,))
        _, baseline = self.record()
        self.runtime.execute("DELETE FROM recording_links WHERE recording_id=?", (expired,))
        self.runtime.execute("DELETE FROM recordings WHERE id=?", (expired,))
        self.runtime.execute("DELETE FROM storage_state_audit")
        code, report, stdout = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report)
        self.assertEqual(report["sections"]["recordings"]["retention_expired"], [expired])
        self.assertNotIn(expired, report["sections"]["recordings"]["preserved"])
        self.assertIn("retention_expired=1", stdout)

    def test_dropping_a_table_of_expired_rows_is_never_retention(self):
        # Codex P1: retention deletes rows, never a table. With every row past
        # its period, dropping the table (or one the recording catalog needs)
        # must fail instead of reading as an empty, fully expired table.
        cases = {"security_admin_audit_records": "audit_security_admin",
                 "integrity_audit": "audit_integrity",
                 "storage_state_audit": "audit_storage_state",
                 "recordings": "recordings", "recording_links": "recordings",
                 "recording_segments": "recordings"}
        self.now = datetime.fromtimestamp(1_700_000_000 + 400 * 86_400, timezone.utc)
        for index, (table, section) in enumerate(cases.items()):
            with self.subTest(table):
                runtime = Runtime(self.base / f"dropped-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    runtime.execute("INSERT INTO integrity_audit(at, actor, revision) VALUES "
                                    "('2023-01-01T00:00:00+00:00', 'owner', 1)")
                    runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                                    "current_state) VALUES (1, 'normal', 'pressure')")
                    runtime.execute("UPDATE recordings SET status='complete', ended_ms=1, "
                                    "starred=0")
                    _, baseline = self.record(f"dropped-{index}.json")
                    # Every row here is past its retention period.
                    runtime.execute(f"DROP TABLE {table}")
                    code, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED, table)
                result = report["sections"][section]
                self.assertEqual(result["retention_expired"], [], table)
                self.assertIn({"id": None, "reason": "table_missing"}, result["failed"], table)

    def test_dropping_any_inventoried_table_while_empty_fails(self):
        # Codex P1: a table recorded present must still exist, even when it
        # held no rows at record time, whatever its section comparator does
        # with an empty baseline.
        outcomes = {}
        for index, table in enumerate(inventory.INVENTORIED_TABLES):
            runtime = Runtime(self.base / f"empty-drop-{index}")
            saved, self.runtime = self.runtime, runtime
            try:
                runtime.execute(f"DELETE FROM {table}")
                _, baseline = self.record(f"empty-drop-{index}.json")
                runtime.execute(f"DROP TABLE {table}")
                code, report, _ = self.verify(baseline)
            finally:
                self.runtime = saved
            outcomes[table] = (code, {"id": table, "reason": "table_missing"}
                               in report["sections"]["tables"]["failed"])
        self.assertEqual({table: outcome for table, outcome in outcomes.items()
                          if outcome != (inventory.EXIT_FAILED, True)}, {})

    def test_applied_migration_history_only_grows_by_known_migrations(self):
        # Codex P1: migrate() re-checks every applied row on startup, so the
        # history must persist; a dropped table would replay every migration.
        self.runtime.seed()
        with closing(sqlite3.connect(self.runtime.database)) as connection:
            last = connection.execute("SELECT version, name, checksum FROM schema_migrations "
                                      "ORDER BY version DESC LIMIT 1").fetchone()
        # Recorded one release earlier: the last migration not yet applied.
        self.runtime.execute("DELETE FROM schema_migrations WHERE version=?", (last[0],))
        _, baseline = self.record()
        self.runtime.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", tuple(last))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["schema_migrations"])
        self.assertEqual(report["sections"]["schema_migrations"]["appended"], [last[0]])
        # Each tamper starts from a baseline recorded before the last two
        # migrations; migrate() would refuse every resulting history.
        rejected = {"id": None, "reason": "history_rejected"}
        tampers = {
            # Codex P1: applied rows removed, leaving a strict prefix of the
            # catalog; the next start would re-run their DDL.
            "not migrated": ([], {"id": None, "reason": "not_migrated"}),
            "dropped": (["DROP TABLE schema_migrations"], {"id": None, "reason": "table_missing"}),
            "row removed": (["DELETE FROM schema_migrations WHERE version=1"],
                            {"id": 1, "reason": "missing"}),
            "prefix row replaced": (["UPDATE schema_migrations SET checksum='0' WHERE version=1"],
                                    {"id": 1, "reason": "changed"}),
            "unknown row": (["INSERT INTO schema_migrations VALUES (9999, 'x', 'y')"], rejected),
            "gap": (["INSERT INTO schema_migrations VALUES (:v2, :n2, :c2)"], rejected),
            "reorder": (["INSERT INTO schema_migrations VALUES (:v1, :n2, :c2)",
                         "INSERT INTO schema_migrations VALUES (:v2, :n1, :c1)"], rejected),
            "duplicate": (["INSERT INTO schema_migrations VALUES (:v1, :n1, :c1)",
                           "INSERT INTO schema_migrations VALUES (:v2, :n1, :c1)"], rejected),
        }
        for index, (label, (statements, expected)) in enumerate(tampers.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"migrations-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    with closing(sqlite3.connect(runtime.database)) as connection:
                        tail = connection.execute(
                            "SELECT version, name, checksum FROM schema_migrations "
                            "ORDER BY version DESC LIMIT 2").fetchall()[::-1]
                    values = {"v1": tail[0][0], "n1": tail[0][1], "c1": tail[0][2],
                              "v2": tail[1][0], "n2": tail[1][1], "c2": tail[1][2]}
                    runtime.execute("DELETE FROM schema_migrations WHERE version >= ?",
                                    (tail[0][0],))
                    _, recorded = self.record(f"migrations-{index}.json")
                    with closing(sqlite3.connect(runtime.database,
                                                 isolation_level=None)) as connection:
                        for statement in statements:
                            connection.execute(statement, {key: value for key, value in
                                                           values.items()
                                                           if f":{key}" in statement})
                    code, report, _ = self.verify(recorded)
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn(expected, report["sections"]["schema_migrations"]["failed"])

    def test_every_migration_table_is_inventoried_or_explained(self):
        with closing(sqlite3.connect(self.runtime.database)) as connection:
            created = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name != 'sqlite_sequence'")}
        accounted = (set(inventory.INVENTORIED_TABLES) | set(inventory.TRANSIENT_TABLES)
                     | {name for name in inventory.NOT_INVENTORIED if "." not in name})
        self.assertEqual(created - accounted, set())
        self.assertEqual(set(inventory.INVENTORIED_TABLES) - created, set())

    def test_presence_and_storage_audit_rows_are_preserved(self):
        self.runtime.seed()
        for index in range(3):
            self.runtime.execute(
                "INSERT INTO presence_audit (action, actor, at, state, target) "
                "VALUES ('override', 'owner', ?, 'away', NULL)", (f"2026-01-0{index + 1}",))
            self.runtime.execute(
                "INSERT INTO storage_state_audit (at_ms, previous_state, current_state) "
                "VALUES (?, 'normal', 'pressure')",
                (int(self.now.timestamp() * 1000) - 3600_000 + index,))
        _, baseline = self.record()
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["audit_presence"]["preserved_rows"], 3)
        self.assertEqual(report["sections"]["audit_storage_state"]["preserved_rows"], 3)
        self.runtime.execute("UPDATE presence_audit SET state='home' WHERE sequence=2")
        self.runtime.execute("DELETE FROM storage_state_audit WHERE id=1")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["audit_presence"]["failed"],
                         [{"id": "2", "reason": "changed"}])
        self.assertEqual(report["sections"]["audit_storage_state"]["failed"],
                         [{"id": "1", "reason": "missing"}])

    def test_in_progress_growth_requires_the_marker_of_a_discontinuous_publication(self):
        # _publish() links the segment and adds its marker in one transaction.
        self.runtime.seed()
        marked = self.runtime.recording(starred=False, payload=b"generated-marked",
                                        status="active", target_end_ms=20000)
        unmarked = self.runtime.recording(starred=False, payload=b"generated-unmarked",
                                          status="active", target_end_ms=20000)
        _, baseline = self.record()
        for recording_id in (marked, unmarked):
            self.runtime.add_segment(recording_id, b"generated-restart-" + recording_id.encode(),
                                     start_ms=11000, end_ms=20000, stream_id="restarted",
                                     sequence=0)
        self.runtime.execute(
            "INSERT INTO recording_discontinuities VALUES (?, 10000, 11000, "
            "'stream_discontinuity')", (marked,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [marked])
        self.assertIn({"id": unmarked, "reason": "changed"}, section["failed"])

    def test_replaced_credential_key_with_unchanged_count_is_detected(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        # Normal use advances the sign count and backup state: not a change.
        self.runtime.execute("UPDATE access_credentials SET sign_count=9, backup_state=1")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.runtime.execute("UPDATE access_credentials SET public_key=X'0102' "
                             "WHERE principal_id=?", (seeded["owner"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["owner"], "reason": "changed"},
                      report["sections"]["access_principals"]["failed"])

    def test_live_instance_approval_swap_to_same_model_camera_is_detected(self):
        # Without a usable serial, same_physical_camera() compares the live
        # instance, so another same-model camera is not the approved one.
        self.runtime.seed()

        def evidence(serial, path, token) -> str:
            return json.dumps({
                "device_path": path, "vendor": "1d6b", "product": "0102", "serial": serial,
                "interface": "0", "by_id": [], "topology": "synthetic-topology-a",
                "formats": ["MJPG"], "device_number": 3, "instance_token": token})
        cases = {"serial-less": (None, 0), "ambiguous": ("synthetic-shared-serial", 1)}
        ids = {}
        for label, (serial, ambiguous) in cases.items():
            ids[label] = self.runtime.source()
            self.runtime.execute(
                "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, "
                "session_token, serial_ambiguous, explicit_binding) VALUES (?, ?, 0, NULL, ?, 0)",
                (ids[label], evidence(serial, "/dev/synthetic-node-a", [1, 2, 3]), ambiguous))
        _, baseline = self.record()
        for label, (serial, _) in cases.items():
            self.runtime.execute("UPDATE uvc_approvals SET evidence=? WHERE source_id=?",
                                 (evidence(serial, "/dev/synthetic-node-b", [4, 5, 6]),
                                  ids[label]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        for label in cases:
            self.assertIn({"id": ids[label], "reason": "changed"},
                          report["sections"]["camera_sources"]["failed"])
        for path in self.notes.iterdir():
            for marker in ("synthetic-node-", "synthetic-topology-a", "synthetic-shared-serial"):
                self.assertNotIn(marker, path.read_text())

    def test_camera_registry_source_limit_change_is_detected(self):
        self.runtime.seed()
        _, baseline = self.record()
        self.runtime.execute("UPDATE camera_registry_settings SET max_active_video_sources=1")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["camera_registry_settings"]["failed"],
                         [{"id": "max_active_video_sources", "reason": "changed"}])

    def test_owner_template_store_is_inventoried_as_digests_only(self):
        self.runtime.seed()
        template = b"synthetic-owner-template-marker"
        root = self.owner_template_root(template=template)
        option = ("--owner-template-root", str(root))
        _, baseline = self.record("baseline.json", *option)
        code, report, _ = self.verify(baseline, *option)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["sections"]["owner_template"]["audit"]["preserved_rows"], 2)
        for path in self.notes.iterdir():
            text = path.read_text()
            for marker in (template.decode(), template.hex(), "synthetic-provenance-marker"):
                self.assertNotIn(marker, text, path.name)
        # Omitting the configured store at verify is a change, not a pass.
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        database = root / "owner-template.sqlite3"
        with closing(sqlite3.connect(database, isolation_level=None)) as connection:
            connection.execute("UPDATE owner_template SET template=? WHERE singleton=1",
                               (b"synthetic-other-template",))
            connection.execute("DELETE FROM owner_template_audit WHERE id=1")
        code, report, _ = self.verify(baseline, *option)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["owner_template"]["failed"]
        self.assertIn({"id": "template_digest", "reason": "changed"}, failed)
        self.assertIn({"id": "audit:1", "reason": "missing"}, failed)

    def test_owner_template_store_appearing_or_disappearing_is_detected(self):
        self.runtime.seed()
        root = self.base / "owner-template"
        root.mkdir(mode=0o700)
        option = ("--owner-template-root", str(root))
        _, absent = self.record("absent.json", *option)
        self.owner_template_root()
        code, report, _ = self.verify(absent, *option)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": "state", "reason": "changed"},
                      report["sections"]["owner_template"]["failed"])
        _, present = self.record("present.json", *option)
        (root / "owner-template.sqlite3").unlink()
        code, report, _ = self.verify(present, *option)
        self.assertEqual(code, inventory.EXIT_FAILED)
        # Unconfigured on both sides is reported as such, never failed.
        _, unconfigured = self.record("unconfigured.json")
        code, report, _ = self.verify(unconfigured)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["sections"]["owner_template"]["status"], "not_configured")

    def test_unloadable_uvc_approval_evidence_is_never_preserved(self):
        # ApprovalStore._state() refuses evidence without by_id / formats, with
        # unknown keys or invalid values; the service cannot restore such an
        # approval, so the inventory must not call it preserved.
        self.runtime.seed()
        valid = {"device_path": "/dev/synthetic-node", "vendor": "1d6b", "product": "0102",
                 "serial": "synthetic-serial", "interface": "0", "by_id": [],
                 "topology": None, "formats": ["MJPG"], "device_number": 3,
                 "instance_token": None}
        broken = {
            "no-by-id": {key: value for key, value in valid.items() if key != "by_id"},
            "no-formats": {key: value for key, value in valid.items() if key != "formats"},
            "unknown-key": {**valid, "extra": 1},
            "empty-vendor": {**valid, "vendor": ""},
        }
        ids = {}
        for label, evidence in {"valid": valid, **broken}.items():
            ids[label] = self.runtime.source()
            self.runtime.execute(
                "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, "
                "session_token, serial_ambiguous, explicit_binding) VALUES (?, ?, 0, NULL, 0, 0)",
                (ids[label], json.dumps(evidence)))
        ids["not-json"] = self.runtime.source()
        self.runtime.execute(
            "INSERT INTO uvc_approvals (source_id, evidence, requires_approval, session_token, "
            "serial_ambiguous, explicit_binding) VALUES (?, '{', 0, NULL, 0, 0)",
            (ids["not-json"],))
        _, baseline = self.record()
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["camera_sources"]
        self.assertIn(ids["valid"], section["preserved"])
        for label in (*broken, "not-json"):
            self.assertIn({"id": ids[label], "reason": "unreadable_approval_evidence"},
                          section["failed"])
            self.assertNotIn(ids[label], section["preserved"])

    def test_owner_template_store_with_unsafe_layout_is_never_preserved(self):
        # The store's own invariants: private root, 0600 single-link regular
        # database owned by the service account, never a symlink.
        self.runtime.seed()
        option = ("--owner-template-root", str(self.base / "owner-template"))
        root = self.owner_template_root(template=b"synthetic-owner-template-marker")
        database = root / "owner-template.sqlite3"

        def unsafe_verify(label):
            _, baseline = self.record(f"{label}.json", *option)
            code, report, _ = self.verify(baseline, *option)
            self.assertEqual(code, inventory.EXIT_FAILED, label)
            self.assertIn({"id": "state", "reason": "unsafe"},
                          report["sections"]["owner_template"]["failed"], label)
            recorded = json.loads((self.notes / f"{label}.json").read_text())
            self.assertEqual(recorded["owner_template"],
                             {"configured": True, "state": "unsafe"}, label)
        os.chmod(database, 0o644)
        unsafe_verify("readable-database")
        # Codex P2: run as root, the inventory could read a file the service
        # account cannot open read-write; only exactly 0600 is the store's.
        for mode in (0o400, 0o200, 0o000):
            os.chmod(database, mode)
            unsafe_verify(f"owner-mode-{mode:o}")
        os.chmod(database, 0o600)
        os.chmod(root, 0o750)
        unsafe_verify("group-root")
        # Codex P2: a root the service account cannot write (no journal).
        os.chmod(root, 0o500)
        unsafe_verify("unwritable-root")
        os.chmod(root, 0o700)
        os.link(database, self.base / "second-link")
        unsafe_verify("hard-link")
        (self.base / "second-link").unlink()
        moved = self.base / "elsewhere.sqlite3"
        database.rename(moved)
        database.symlink_to(moved)
        unsafe_verify("symlink")
        database.unlink()
        moved.rename(database)
        _, baseline = self.record("safe.json", *option)
        code, _, _ = self.verify(baseline, *option)
        self.assertEqual(code, inventory.EXIT_PRESERVED)

    def test_credential_sign_count_may_only_advance(self):
        # A lower counter rolls back the authenticator clone-detection floor.
        seeded = self.runtime.seed()
        self.runtime.execute("UPDATE access_credentials SET sign_count=5")
        _, baseline = self.record()
        recorded = json.loads(baseline.read_text())["access"]["principals"]
        self.assertEqual(recorded[seeded["owner"]]["active_credentials"][0][1], 5)
        self.runtime.execute("UPDATE access_credentials SET sign_count=8")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        section = report["sections"]["access_principals"]
        self.assertEqual(section["sign_counts_advanced"], [seeded["owner"]])
        self.assertIn(seeded["owner"], section["preserved"])
        self.runtime.execute("UPDATE access_credentials SET sign_count=4")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["owner"], "reason": "changed"},
                      report["sections"]["access_principals"]["failed"])
        # A counter rising cannot hide another change to the principal.
        self.runtime.execute("UPDATE access_credentials SET sign_count=9")
        self.runtime.execute("UPDATE access_principals SET authorization_revision=4 WHERE id=?",
                             (seeded["owner"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)

    def test_replaced_invitation_secret_binding_is_detected_without_the_secret(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        replacement = bytes(range(100, 132))
        self.runtime.execute(
            "UPDATE access_invitations SET secret_digest=? WHERE principal_id=?",
            (replacement, seeded["live"]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["access_invitations"]["failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["reason"], "changed")
        for path in self.notes.iterdir():
            text = path.read_text()
            for marker in (replacement.hex(), SECRET_DIGEST.hex(),
                           bytes(reversed(SECRET_DIGEST)).hex()):
                self.assertNotIn(marker, text, path.name)

    def test_hidden_non_ready_segment_link_is_never_preserved(self):
        # manifest() reads every linked segment, whatever its state, so a
        # linked pending segment later turns a complete recording gapped.
        seeded = self.runtime.seed()
        active = self.runtime.recording(starred=False, payload=b"generated-active-pending",
                                        status="active", target_end_ms=20000)
        _, baseline = self.record()
        for recording_id in (seeded["ordinary"], active):
            segment_id = self.runtime.add_segment(
                recording_id, b"generated-pending-" + recording_id.encode(),
                start_ms=10000, end_ms=12000, stream_id="hidden", sequence=0)
            self.runtime.execute("UPDATE recording_segments SET state='pending' WHERE id=?",
                                 (segment_id,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        for recording_id in (seeded["ordinary"], active):
            self.assertNotIn(recording_id, section["preserved"])
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])
        # Recorded with the hidden link already present: never preserved either.
        _, tainted = self.record("tainted.json")
        code, report, _ = self.verify(tainted)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["ordinary"], "reason": "no_readable_segment_evidence"},
                      report["sections"]["recordings"]["failed"])

    def test_owner_editable_source_metadata_is_preserved_by_keyed_digest(self):
        self.runtime.seed()
        name, role = "synthetic-camera-name-marker", "synthetic-role-marker"
        ids = {label: self.runtime.source() for label in ("name", "role", "capabilities")}
        for source_id in ids.values():
            self.runtime.execute("UPDATE camera_sources SET name=?, role_label=? WHERE id=?",
                                 (name, role, source_id))
        _, baseline = self.record()
        self.runtime.execute("UPDATE camera_sources SET name='renamed' WHERE id=?", (ids["name"],))
        self.runtime.execute("UPDATE camera_sources SET role_label=NULL WHERE id=?", (ids["role"],))
        self.runtime.execute("UPDATE camera_sources SET capabilities='{\"video_only\":true}' "
                             "WHERE id=?", (ids["capabilities"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        for source_id in ids.values():
            self.assertIn({"id": source_id, "reason": "changed"},
                          report["sections"]["camera_sources"]["failed"])
        for path in self.notes.iterdir():
            for marker in (name, role):
                self.assertNotIn(marker, path.read_text(), path.name)

    def test_open_presence_timeline_gap_may_only_grow(self):
        # The gap is cleared only by an audited Owner action, never during an
        # update; dropping or shrinking it would hide recorded timeline loss.
        self.runtime.seed()
        _, closed = self.record("closed.json")
        self.runtime.execute(
            "INSERT INTO presence_timeline_gap (singleton, since, latest, refused, rejected, "
            "lost, interrupted) VALUES (1, '2026-01-01T00:00:00+00:00', "
            "'2026-01-01T00:01:00+00:00', 1, 0, 2, 0)")
        code, report, _ = self.verify(closed)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["sections"]["presence_timeline_gap"]["appended"], ["gap"])
        _, baseline = self.record()
        self.runtime.execute("UPDATE presence_timeline_gap SET lost=3, "
                             "latest='2026-01-01T00:02:00+00:00'")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.runtime.execute("UPDATE presence_timeline_gap SET lost=1")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["presence_timeline_gap"]["failed"],
                         [{"id": "gap", "reason": "changed"}])
        self.runtime.execute("DELETE FROM presence_timeline_gap")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["presence_timeline_gap"]["failed"],
                         [{"id": "gap", "reason": "missing"}])

    def presence_rows(self) -> dict:
        """Synthetic durable presence state; payloads are generated markers."""
        ids = {name: str(uuid4()) for name in ("kept", "expired", "lost", "edited", "done")}
        for name in ("kept", "expired", "lost", "edited"):
            self.runtime.execute(
                "INSERT INTO presence_observations (id, kind, source, received, payload) "
                "VALUES (?, 'crossing', 'synthetic-source', '2026-01-01T00:00:00.000000+00:00', ?)",
                (ids[name], json.dumps({"marker": "synthetic-presence-payload-" + name})))
            self.runtime.execute(
                "INSERT INTO presence_deliveries (observation, action, state, attempts) "
                "VALUES (?, 'notification', 'pending', 0)", (ids[name],))
            self.runtime.execute("INSERT INTO presence_source_facts (id, digest) VALUES (?, ?)",
                                 (ids[name], hashlib.sha256(name.encode()).hexdigest()))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, "
                             "'2026-01-01T00:00:00.000000+00:00')", (ids["done"],))
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('evidence', 2, "
                             "'2026-01-01T00:00:00.000000+00:00')")
        return ids

    def test_presence_tombstones_and_unresolved_markers_are_preserved(self):
        # Completed tombstones stop delayed critical replays; expired markers
        # keep evidence / notification reported unavailable.
        self.runtime.seed()
        ids = self.presence_rows()
        _, baseline = self.record()
        self.runtime.execute("UPDATE presence_expired_unresolved SET events=3")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        self.runtime.execute("DELETE FROM presence_completed_events WHERE id=?", (ids["done"],))
        self.runtime.execute("UPDATE presence_expired_unresolved SET events=1")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        self.assertIn({"id": "completed_events:" + ids["done"], "reason": "missing"}, failed)
        self.assertIn({"id": "expired_unresolved:evidence", "reason": "changed"}, failed)
        self.runtime.execute("DELETE FROM presence_expired_unresolved")
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": "expired_unresolved:evidence", "reason": "missing"},
                      report["sections"]["presence"]["failed"])

    def test_presence_observations_leave_only_through_a_tombstone(self):
        self.runtime.seed()
        ids = self.presence_rows()
        _, baseline = self.record()
        # The retention path: observation, jobs and fact go, the tombstone
        # appears and the undelivered job adds an expired-unresolved event.
        for table, column in (("presence_deliveries", "observation"),
                              ("presence_observations", "id"), ("presence_source_facts", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["expired"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, "
                             "'2026-02-01T00:00:00.000000+00:00')", (ids["expired"],))
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, "
                             "'2026-02-01T00:00:00.000000+00:00')")
        # A claim (one attempt, one generation) and its delivered outcome.
        self.runtime.execute("UPDATE presence_deliveries SET state='delivered', "
                             "attempts=attempts+1, generation=generation+1 "
                             "WHERE observation=?", (ids["kept"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        # A lost job, a changed payload and a dropped fact are changes.
        for table, column in (("presence_deliveries", "observation"),
                              ("presence_observations", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["lost"],))
        self.runtime.execute("UPDATE presence_observations SET payload='{}' WHERE id=?",
                             (ids["edited"],))
        self.runtime.execute("DELETE FROM presence_source_facts WHERE id=?", (ids["kept"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        for item in ({"id": "observations:" + ids["lost"], "reason": "missing"},
                     {"id": f"deliveries:{ids['lost']}:notification", "reason": "missing"},
                     {"id": "observations:" + ids["edited"], "reason": "changed"},
                     {"id": "source_facts:" + ids["kept"], "reason": "missing"}):
            self.assertIn(item, failed)
        for path in self.notes.iterdir():
            self.assertNotIn("synthetic-presence-payload", path.read_text(), path.name)

    def test_unresolved_job_removed_with_only_a_tombstone_is_detected(self):
        # A tombstone alone would hide an undelivered critical action: both
        # service paths also add its expired-unresolved event.
        self.runtime.seed()
        ids = self.presence_rows()
        self.runtime.execute("UPDATE presence_deliveries SET state='failed', attempts=1, "
                             "generation=1 WHERE observation=?", (ids["lost"],))
        _, baseline = self.record()
        for table, column in (("presence_deliveries", "observation"),
                              ("presence_observations", "id"), ("presence_source_facts", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["lost"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, "
                             "'2026-02-01T00:00:00.000000+00:00')", (ids["lost"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": f"deliveries:{ids['lost']}:notification", "reason": "missing"},
                      report["sections"]["presence"]["failed"])
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, "
                             "'2026-02-01T00:00:00.000000+00:00')")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])

    def test_presence_clocks_sessions_and_override_follow_service_transitions(self):
        self.runtime.seed()
        self.runtime.execute("INSERT INTO presence_clock VALUES (1, "
                             "'2026-01-01T00:00:00.000000+00:00')")
        self.runtime.execute("INSERT INTO presence_control_clock VALUES (1, "
                             "'2026-01-01T00:00:00.000000+00:00')")
        self.runtime.execute("INSERT INTO presence_critical_source_clock VALUES "
                             "('synthetic-source', '2026-01-01T00:00:00.000000+00:00')")
        self.runtime.execute("INSERT INTO presence_outbox_sessions VALUES "
                             "('synthetic-token', '2026-01-01T00:00:00.000000+00:00')")
        self.runtime.execute("INSERT INTO presence_override VALUES (1, 'away', 'owner', "
                             "'2026-01-01T00:00:00.000000+00:00', "
                             "'2026-01-02T00:00:00.000000+00:00')")
        # No live outbox holds the committed lock: the session row is stale.
        _, baseline = self.record()
        # Clocks advance, the stale session becomes an interrupted gap and
        # _retire_override() drops the override once the control clock passes it.
        self.runtime.execute("UPDATE presence_clock SET latest='2026-01-03T00:00:00.000000+00:00'")
        self.runtime.execute("UPDATE presence_control_clock "
                             "SET latest='2026-01-03T00:00:00.000000+00:00'")
        self.runtime.execute("DELETE FROM presence_outbox_sessions")
        self.runtime.execute(
            "INSERT INTO presence_timeline_gap (singleton, since, latest, interrupted) VALUES "
            "(1, '2026-01-03T00:00:00.000000+00:00', '2026-01-03T00:00:00.000000+00:00', 1)")
        self.runtime.execute("DELETE FROM presence_override")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        # A rolled-back clock, a stale session dropped without its gap and an
        # override removed before the control clock reached its expiry (the
        # observation clock does not retire overrides) are changes.
        self.runtime.execute("UPDATE presence_critical_source_clock "
                             "SET latest_occurred='2025-12-31T00:00:00.000000+00:00'")
        self.runtime.execute("DELETE FROM presence_timeline_gap")
        self.runtime.execute("UPDATE presence_control_clock "
                             "SET latest='2026-01-01T12:00:00.000000+00:00'")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        for item in ({"id": "clocks:critical_source:synthetic-source", "reason": "changed"},
                     {"id": "outbox_sessions:1", "reason": "missing"},
                     {"id": "override:owner", "reason": "changed"}):
            self.assertIn(item, failed)

    def test_live_outbox_session_may_close_cleanly(self):
        # The service's own path: open_timeline_session() holds the committed
        # lock; record_timeline_gap(close=...) deletes the row without adding
        # an interrupted count.
        self.runtime.seed()
        @contextmanager
        def reservation():
            yield
        service = PresenceService(Database(self.runtime.database), reservation=reservation)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        session, _ = service.open_timeline_session(now=now)
        try:
            _, live = self.record("live.json")
        finally:
            service.record_timeline_gap(now=now, close=session)
        self.assertTrue(json.loads(live.read_text())["presence"]["outbox_live"])
        code, report, _ = self.verify(live)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        # The same removal of a row nobody held is an unexplained loss.
        session, _ = service.open_timeline_session(now=now)
        session.release()
        _, stale = self.record("stale.json")
        self.assertFalse(json.loads(stale.read_text())["presence"]["outbox_live"])
        self.runtime.execute("DELETE FROM presence_outbox_sessions")
        code, report, _ = self.verify(stale)
        self.assertEqual(code, inventory.EXIT_FAILED)

    def test_presence_delivery_jobs_only_move_forward(self):
        self.runtime.seed()
        ids = self.presence_rows()
        update = ("UPDATE presence_deliveries SET state=?, attempts=?, generation=?, requeued=? "
                  "WHERE observation=?")
        self.runtime.execute(update, ("uncertain", 1, 1, 0, ids["edited"]))
        self.runtime.execute(update, ("delivered", 1, 1, 0, ids["lost"]))
        _, baseline = self.record()
        # Claim, an outcome, and the audited Owner requeue of an uncertain job.
        self.runtime.execute(update, ("submitting", 1, 1, 0, ids["kept"]))
        self.runtime.execute(update, ("failed", 1, 1, 0, ids["expired"]))
        self.runtime.execute(update, ("pending", 1, 2, 1, ids["edited"]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        # Not service transitions: a pending job whose generation moved without
        # a claim or requeue, a delivered job reopening, a job returning to
        # pending without a requeue.
        self.runtime.execute(update, ("pending", 0, 1, 0, ids["kept"]))
        self.runtime.execute(update, ("pending", 1, 1, 0, ids["lost"]))
        self.runtime.execute(update, ("pending", 1, 1, 0, ids["edited"]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        for name in ("kept", "lost", "edited"):
            self.assertIn({"id": f"deliveries:{ids[name]}:notification", "reason": "changed"},
                          failed)

    def test_single_column_tampers_of_service_state_fail(self):
        # Mutation cases over a synthetic service-shaped state: one column of
        # one row edited in a way no service path produces, per table and
        # column the inventory compares. Not compared on purpose:
        # recording_segments.spool (the retention spool flag; a linked
        # segment is never trimmed) and recording_segments.integrity (a cache
        # RecordingStore.manifest() recomputes from the file on every read).
        def build(index):
            runtime = Runtime(self.base / f"column-{index}")
            saved, self.runtime = self.runtime, runtime
            try:
                seeded = runtime.seed()
                ids = self.presence_rows()
                update = ("UPDATE presence_deliveries SET state=?, attempts=?, generation=?, "
                          "requeued=? WHERE observation=?")
                runtime.execute(update, ("uncertain", 1, 1, 0, ids["edited"]))
                runtime.execute(update, ("unavailable", 1, 2, 1, ids["lost"]))
                runtime.execute("INSERT INTO integrity_outbox(at, immediate, findings) VALUES "
                                "('2026-01-01T00:00:00+00:00', 1, ?)", (json.dumps(
                                    [{"kind": "GPU", "state": "CHANGED", "detail": "x"}]),))
                runtime.execute("INSERT INTO integrity_overflow VALUES "
                                "('CPU', 'MISSING', '2026-01-01T00:00:00+00:00')")
                active = runtime.recording(starred=False, payload=b"generated-column-active",
                                           status="active", target_end_ms=30000)
                runtime.add_segment(active, b"generated-column-tail", start_ms=12000,
                                    end_ms=20000)
                runtime.execute("INSERT INTO recording_discontinuities VALUES "
                                "(?, 4000, 5000, 'stream_discontinuity')", (active,))
                expired_node = str(uuid4())
                runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                ("a" * 64, expired_node))
                runtime.execute("INSERT INTO pairing_enrollments VALUES "
                                "(?, ?, ?, 'f', 'epoch', 0, 'expired')",
                                (str(uuid4()), expired_node, "a" * 64))
                _, baseline = self.record(f"column-{index}.json")
            finally:
                self.runtime = saved
            with closing(sqlite3.connect(runtime.database)) as connection:
                segment = connection.execute(
                    "SELECT segment_id FROM recording_links WHERE recording_id=?",
                    (seeded["ordinary"],)).fetchone()[0]
                other_segment = connection.execute(
                    "SELECT segment_id FROM recording_links WHERE recording_id=?",
                    (seeded["starred"],)).fetchone()[0]
                active_segment = connection.execute(
                    "SELECT segment_id FROM recording_links WHERE recording_id=? "
                    "ORDER BY rowid DESC", (active,)).fetchone()[0]
            values = {"edited": ids["edited"], "lost": ids["lost"], "recording": seeded["ordinary"],
                      "segment": segment, "other_segment": other_segment, "active": active,
                      "active_segment": active_segment, "expired_key": "a" * 64,
                      "new_id": str(uuid4())}
            return runtime, baseline, values
        tampers = {
            # presence_deliveries (edited: uncertain 1/1/0; lost: unavailable 1/2/1 requeued)
            "deliveries.attempts inflated": "UPDATE presence_deliveries SET attempts=2 "
                                            "WHERE observation=:edited",
            "deliveries.generation without claim or requeue":
                "UPDATE presence_deliveries SET generation=2 WHERE observation=:edited",
            "deliveries.generation lowered": "UPDATE presence_deliveries SET generation=1 "
                                             "WHERE observation=:lost",
            "deliveries.requeued cleared": "UPDATE presence_deliveries SET requeued=0 "
                                           "WHERE observation=:lost",
            "deliveries.state unknown": "UPDATE presence_deliveries SET state='bogus' "
                                        "WHERE observation=:edited",
            "deliveries.action": "UPDATE presence_deliveries SET action='evidence' "
                                 "WHERE observation=:edited",
            "deliveries.observation": "UPDATE presence_deliveries SET observation=:new_id "
                                      "WHERE observation=:edited",
            # integrity_outbox / integrity_overflow
            "outbox.id": "UPDATE integrity_outbox SET id=99",
            "outbox.at": "UPDATE integrity_outbox SET at='2026-01-02T00:00:00+00:00'",
            "outbox.immediate": "UPDATE integrity_outbox SET immediate=0",
            "outbox.findings": "UPDATE integrity_outbox SET findings='[]'",
            "outbox.delivered": "UPDATE integrity_outbox SET delivered=1",
            "overflow.kind": "UPDATE integrity_overflow SET kind='GPU'",
            "overflow.state": "UPDATE integrity_overflow SET state='CHANGED'",
            "overflow.at": "UPDATE integrity_overflow SET at='2026-01-02T00:00:00+00:00'",
            # recordings (finished)
            "recordings.id": "UPDATE recordings SET id=:new_id WHERE id=:recording",
            "recordings.source_id": "UPDATE recordings SET source_id=:new_id WHERE id=:recording",
            "recordings.event_id": "UPDATE recordings SET event_id=:new_id WHERE id=:recording",
            "recordings.start_ms": "UPDATE recordings SET start_ms=1 WHERE id=:recording",
            "recordings.target_end_ms": "UPDATE recordings SET target_end_ms=9000 "
                                        "WHERE id=:recording",
            "recordings.ended_ms": "UPDATE recordings SET ended_ms=9000 WHERE id=:recording",
            "recordings.status": "UPDATE recordings SET status='gapped' WHERE id=:recording",
            "recordings.critical": "UPDATE recordings SET critical=1 WHERE id=:recording",
            "recordings.starred": "UPDATE recordings SET starred=1 WHERE id=:recording",
            # recording_segments
            **{f"segments.{column}": f"UPDATE recording_segments SET {assignment} "
               "WHERE id=:segment" for column, assignment in (
                   ("source_id", "source_id=:new_id"), ("capture_node_id", "capture_node_id='n'"),
                   ("stream_id", "stream_id='other'"), ("sequence", "sequence=sequence+1000"),
                   ("start_ms", "start_ms=1"), ("end_ms", "end_ms=9000"),
                   ("codec", "codec='other'"), ("container", "container='other'"),
                   ("byte_length", "byte_length=byte_length+1"), ("sha256", "sha256='0'"),
                   ("state", "state='pending'"), ("critical", "critical=1"))},
            # recording_links / recording_discontinuities
            "links.deleted": "DELETE FROM recording_links WHERE recording_id=:recording",
            "links.repointed": "UPDATE recording_links SET segment_id=:other_segment "
                               "WHERE recording_id=:recording",
            "discontinuities.added": "INSERT INTO recording_discontinuities VALUES "
                                     "(:recording, 1000, 2000, 'stream_discontinuity')",
            "discontinuities.in-window removed":
                "DELETE FROM recording_discontinuities WHERE recording_id=:active",
            "discontinuities.reason": "UPDATE recording_discontinuities SET reason='other' "
                                      "WHERE recording_id=:active",
            # an active recording
            "active.source_id": "UPDATE recordings SET source_id=:new_id WHERE id=:active",
            "active.start_ms": "UPDATE recordings SET start_ms=1 WHERE id=:active",
            "active.target extended": "UPDATE recordings SET target_end_ms=40000 WHERE id=:active",
            "active.ended while active": "UPDATE recordings SET ended_ms=20000 WHERE id=:active",
            "active.starred": "UPDATE recordings SET starred=1 WHERE id=:active",
            "active.critical": "UPDATE recordings SET critical=1 WHERE id=:active",
            "active.event_id": "UPDATE recordings SET event_id=:new_id WHERE id=:active",
            "active.status unknown": "UPDATE recordings SET status='bogus' WHERE id=:active",
            "active.segment sha256": "UPDATE recording_segments SET sha256='0' "
                                     "WHERE id=:active_segment",
            "active.segment link dropped": "DELETE FROM recording_links WHERE recording_id=:active "
                                           "AND segment_id=:active_segment",
            # pairing: Codex P1, a node with only an expired enrollment
            "pairing.expired-only binding revoked":
                "UPDATE pairing_key_bindings SET revoked=1 WHERE public_key_digest=:expired_key",
        }
        runtime, baseline, _ = build(len(tampers))
        saved, self.runtime = self.runtime, runtime
        try:
            code, report, _ = self.verify(baseline)
        finally:
            self.runtime = saved
        self.assertEqual(code, inventory.EXIT_PRESERVED, report)  # untampered control
        passed = []
        for index, (label, statement) in enumerate(tampers.items()):
            runtime, baseline, values = build(index)
            with closing(sqlite3.connect(runtime.database, isolation_level=None)) as db:
                db.execute(statement, {key: value for key, value in values.items()
                                       if f":{key}" in statement})
            saved, self.runtime = self.runtime, runtime
            try:
                code, _, _ = self.verify(baseline)
            finally:
                self.runtime = saved
            if code != inventory.EXIT_FAILED:
                passed.append(label)
        self.assertEqual(passed, [])

    def test_integrity_baseline_is_preserved_by_keyed_digest(self):
        self.runtime.seed()
        hardware = "synthetic-hardware-identifier-marker"
        self.runtime.execute("INSERT INTO integrity_baseline VALUES (1, 3, ?)",
                             (json.dumps({"cpu": hardware}),))
        _, baseline = self.record()
        code, _, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.runtime.execute("UPDATE integrity_baseline SET inventory=?",
                             (json.dumps({"cpu": "synthetic-replaced"}),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["integrity_baseline"]["failed"],
                         [{"id": "baseline", "reason": "changed"}])
        self.runtime.execute("DELETE FROM integrity_baseline")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        for path in self.notes.iterdir():
            self.assertNotIn(hardware, path.read_text(), path.name)

    def test_service_writer_can_commit_while_segment_files_are_hashed(self):
        # The state database uses a rollback journal: a read transaction held
        # across file hashing would make service writers hit "database is
        # locked". Files are hashed only after the snapshot transaction ends.
        self.runtime.seed()
        hash_file = inventory._file_digest
        outcomes = []

        def hash_while_writing(directory, segment_id):
            if not outcomes:
                writer = sqlite3.connect(self.runtime.database, timeout=0.2,
                                         isolation_level=None)
                try:
                    writer.execute("BEGIN IMMEDIATE")
                    writer.execute("UPDATE camera_registry_settings "
                                   "SET max_active_video_sources = max_active_video_sources")
                    writer.execute("COMMIT")
                    outcomes.append("committed")
                except sqlite3.OperationalError as error:
                    outcomes.append(str(error))
                finally:
                    writer.close()
            return hash_file(directory, segment_id)
        with mock.patch.object(inventory, "_file_digest", hash_while_writing):
            code, _ = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(outcomes, ["committed"])

    def test_revocations_and_invalidations_never_reverse(self):
        self.runtime.seed()
        node, revoked_node = str(uuid4()), str(uuid4())
        key = "a" * 64
        for node_id, health in ((node, "online"), (revoked_node, "revoked")):
            self.runtime.execute(
                "INSERT INTO capture_nodes VALUES (?, 'synthetic', ?, NULL, "
                "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')", (node_id, health))
        self.runtime.execute("INSERT INTO pairing_node_credentials (node_id, public_key_digest, "
                             "credential_serial_digest, state) VALUES (?, ?, ?, 'revoked')",
                             (revoked_node, key, "b" * 64))
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 1)", (key, revoked_node))
        # Invalidation clears the identity binding (schema CHECK).
        self.runtime.execute("UPDATE access_sessions SET invalidated_at_us=5, "
                             "external_identity_binding=NULL")
        self.runtime.execute("UPDATE access_deployment_state SET authorization_generation=3")
        _, baseline = self.record()
        self.assertNotIn(key, baseline.read_text())
        # Forward moves are fine: revoking more, advancing the generation.
        self.runtime.execute("UPDATE capture_nodes SET health_state='revoked' WHERE id=?", (node,))
        self.runtime.execute("UPDATE access_deployment_state SET authorization_generation=4")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        self.runtime.execute("UPDATE capture_nodes SET health_state='online' WHERE id=?",
                             (revoked_node,))
        self.runtime.execute("UPDATE pairing_node_credentials SET state='active'")
        self.runtime.execute("UPDATE pairing_key_bindings SET revoked=0")
        self.runtime.execute("UPDATE access_sessions SET invalidated_at_us=NULL")
        self.runtime.execute("UPDATE access_deployment_state SET authorization_generation=2")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        reasons = {item["id"].split(":")[0]: item["reason"]
                   for item in report["sections"]["security_state"]["failed"]}
        self.assertEqual(reasons, {
            "capture_nodes_revoked": "revocation_reversed",
            "pairing_credentials": "revocation_reversed",
            "pairing_key_bindings": "changed",
            "sessions_invalidated": "revocation_reversed",
            "authorization_generation": "decreased"})
        self.runtime.execute("DELETE FROM pairing_key_bindings")
        code, report, _ = self.verify(baseline)
        self.assertIn("missing", [item["reason"] for item in
                                  report["sections"]["security_state"]["failed"]])

    def test_pending_integrity_notifications_leave_only_once_accepted(self):
        # IntegrityStore.deliver() deletes an outbox row only after the
        # monitoring bridge recorded its notification event.
        self.runtime.seed()
        hardware = "synthetic-hardware-serial-marker"
        findings = json.dumps([{"kind": "GPU", "state": "CHANGED", "detail": hardware}])
        for _ in range(3):
            self.runtime.execute("INSERT INTO integrity_outbox(at, immediate, findings) "
                                 "VALUES ('2026-01-01T00:00:00+00:00', 1, ?)", (findings,))
        self.runtime.execute("INSERT INTO integrity_overflow VALUES "
                             "('CPU', 'MISSING', '2026-01-01T00:00:00+00:00')")
        self.runtime.execute("INSERT INTO integrity_overflow VALUES "
                             "('MEMORY', 'CHANGED', '2026-01-01T00:00:00+00:00')")
        _, baseline = self.record()
        self.assertNotIn(hardware, baseline.read_text())

        def accept(row_id):
            self.runtime.execute(
                "INSERT INTO notification_events VALUES (?, 'hardware_integrity_failure', "
                "'2026-01-01T00:00:00+00:00', 1, 'sent')",
                (str(uuid5(EVENT_NAMESPACE, f"integrity-outbox:{row_id}")),))
        # Row 1 delivered and accepted; the CPU slot promoted into row 4.
        accept(1)
        self.runtime.execute("DELETE FROM integrity_outbox WHERE id=1")
        self.runtime.execute("DELETE FROM integrity_overflow WHERE kind='CPU'")
        self.runtime.execute(
            "INSERT INTO integrity_outbox(at, immediate, findings) VALUES "
            "('2026-01-01T00:00:00+00:00', 1, ?)",
            (json.dumps([{"kind": "CPU", "state": "MISSING",
                          "detail": "COALESCED_PENDING_WARNING"}]),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED,
                         report["sections"]["integrity_delivery"])
        # Row 2 dropped without acceptance, row 3 rewritten, the MEMORY slot lost.
        self.runtime.execute("DELETE FROM integrity_outbox WHERE id=2")
        self.runtime.execute("UPDATE integrity_outbox SET immediate=0 WHERE id=3")
        self.runtime.execute("DELETE FROM integrity_overflow")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["integrity_delivery"]["failed"],
                                key=lambda item: item["id"]),
                         [{"id": "overflow:MEMORY:CHANGED", "reason": "missing"},
                          {"id": "pending:2", "reason": "missing"},
                          {"id": "pending:3", "reason": "changed"}])

    def test_accepted_integrity_event_matches_the_pending_row(self):
        # Codex P1: _integrity_sink() records the row's failure / warning
        # kind (its immediate flag) at the row's own time under the
        # deterministic event ID; another kind or time is not that event.
        self.runtime.seed()
        when = "2026-01-01T00:00:00+00:00"
        findings = json.dumps([{"kind": "GPU", "state": "CHANGED", "detail": "x"}])
        for immediate in (1, 1, 0):
            self.runtime.execute("INSERT INTO integrity_outbox(at, immediate, findings) "
                                 "VALUES (?, ?, ?)", (when, immediate, findings))
        _, baseline = self.record()
        events = {1: ("hardware_integrity_warning", when),            # wrong kind
                  2: ("hardware_integrity_failure", "2026-01-02T00:00:00+00:00"),  # wrong time
                  3: ("hardware_integrity_warning", when)}             # matches
        for row_id, (kind, at) in events.items():
            self.runtime.execute("DELETE FROM integrity_outbox WHERE id=?", (row_id,))
            self.runtime.execute(
                "INSERT INTO notification_events VALUES (?, ?, ?, 1, 'sent')",
                (str(uuid5(EVENT_NAMESPACE, f"integrity-outbox:{row_id}")), kind, at))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["integrity_delivery"]["failed"],
                         [{"id": "pending:1", "reason": "changed"},
                          {"id": "pending:2", "reason": "changed"}])

    def test_active_pairing_material_changes_only_by_staged_promotion(self):
        self.runtime.seed()
        promoted, replaced = str(uuid4()), str(uuid4())
        old = {promoted: "1" * 64, replaced: "2" * 64}
        for node_id in (promoted, replaced):
            self.runtime.execute(
                "INSERT INTO capture_nodes VALUES (?, 'synthetic', 'online', NULL, "
                "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')", (node_id,))
            self.runtime.execute(
                "INSERT INTO pairing_node_credentials (node_id, public_key_digest, "
                "credential_serial_digest, state, not_after) VALUES (?, ?, ?, 'active', 10.0)",
                (node_id, old[node_id], "3" * 64))
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                 (old[node_id], node_id))
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0)",
                             (promoted, "4" * 64, "5" * 64))
        _, baseline = self.record()
        for marker in ("1" * 64, "4" * 64, "5" * 64):
            self.assertNotIn(marker, baseline.read_text())
        # PairingLedger promotion: bind the staged key, swap it in, consume it.
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             ("4" * 64, promoted))
        self.runtime.execute(
            "UPDATE pairing_node_credentials SET public_key_digest=?, "
            "credential_serial_digest=?, not_after=20.0 WHERE node_id=?",
            ("4" * 64, "5" * 64, promoted))
        self.runtime.execute("DELETE FROM pairing_node_renewals")
        # A replacement that was never staged.
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             ("6" * 64, replaced))
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=? "
                             "WHERE node_id=?", ("6" * 64, replaced))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["security_state"]["failed"],
                         [{"id": f"pairing_credentials:{replaced}", "reason": "changed"}])

    def test_each_staged_renewal_leaves_only_by_a_ledger_path(self):
        self.runtime.seed()
        nodes = {label: str(uuid4()) for label in
                 ("silent", "revoked", "repaired", "restaged", "promoted")}
        for index, (label, node_id) in enumerate(nodes.items()):
            key, staged = f"{index}a".ljust(64, "0"), f"{index}b".ljust(64, "0")
            self.runtime.execute(
                "INSERT INTO capture_nodes VALUES (?, 'synthetic', 'online', NULL, "
                "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')", (node_id,))
            self.runtime.execute(
                "INSERT INTO pairing_node_credentials (node_id, public_key_digest, "
                "credential_serial_digest, state, not_after) VALUES (?, ?, ?, 'active', 10.0)",
                (node_id, key, "c" * 64))
            for bound in (key, staged):
                self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                     (bound, node_id))
            self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0)",
                                 (node_id, staged, "d" * 64))
        _, baseline = self.record()
        # Legitimate: revocation discards it; a fresh pairing replaces the
        # identity; re-staging binds the new key first; promotion consumes it.
        self.runtime.execute("UPDATE pairing_node_credentials SET state='revoked' WHERE node_id=?",
                             (nodes["revoked"],))
        self.runtime.execute("UPDATE pairing_key_bindings SET revoked=1 WHERE node_id=?",
                             (nodes["revoked"],))
        fresh = "e" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             (fresh, nodes["repaired"]))
        self.runtime.execute(
            "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', 'epoch', 0, 'activated')",
            (str(uuid4()), nodes["repaired"], fresh))
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=?, "
                             "credential_serial_digest=? WHERE node_id=?",
                             (fresh, "f" * 64, nodes["repaired"]))
        restaged = "9" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             (restaged, nodes["restaged"]))
        self.runtime.execute("UPDATE pairing_node_renewals SET public_key_digest=? "
                             "WHERE node_id=?", (restaged, nodes["restaged"]))
        self.runtime.execute(
            "UPDATE pairing_node_credentials SET public_key_digest=(SELECT public_key_digest "
            "FROM pairing_node_renewals WHERE node_id=?), credential_serial_digest=?, "
            "not_after=20.0 WHERE node_id=?", (nodes["promoted"], "d" * 64, nodes["promoted"]))
        self.runtime.execute("DELETE FROM pairing_node_renewals WHERE node_id IN (?, ?, ?)",
                             (nodes["revoked"], nodes["repaired"], nodes["promoted"]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        # Silently dropped while the active credential is unchanged.
        self.runtime.execute("DELETE FROM pairing_node_renewals WHERE node_id=?",
                             (nodes["silent"],))
        # Re-staged with a key that was never bound to the node.
        self.runtime.execute("UPDATE pairing_node_renewals SET public_key_digest=? "
                             "WHERE node_id=?", ("8" * 64, nodes["restaged"]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         sorted([{"id": f"pairing_renewals:{nodes['silent']}",
                                  "reason": "missing"},
                                 {"id": f"pairing_renewals:{nodes['restaged']}",
                                  "reason": "unbound"}], key=lambda item: item["id"]))

    def test_each_removed_overflow_slot_needs_its_own_promoted_row(self):
        # Two slots dropped while one unrelated warning is delivered must fail.
        self.runtime.seed()
        when = "2026-01-01T00:00:00+00:00"
        for kind in ("CPU", "MEMORY"):
            self.runtime.execute("INSERT INTO integrity_overflow VALUES (?, 'CHANGED', ?)",
                                 (kind, when))
        _, baseline = self.record()

        def outbox(findings, at, immediate=1):
            self.runtime.execute("INSERT INTO integrity_outbox(at, immediate, findings) "
                                 "VALUES (?, ?, ?)", (at, immediate, json.dumps(findings)))

        def deliver(row_id, kind, at):
            self.runtime.execute("DELETE FROM integrity_outbox WHERE id=?", (row_id,))
            self.runtime.execute(
                "INSERT INTO notification_events VALUES (?, ?, ?, 1, 'sent')",
                (str(uuid5(EVENT_NAMESPACE, f"integrity-outbox:{row_id}")), kind, at))
        self.runtime.execute("DELETE FROM integrity_overflow")
        outbox([{"kind": "GPU", "state": "UNVERIFIABLE", "detail": "x"}],
               "2026-01-05T00:00:00+00:00", 0)
        deliver(1, "hardware_integrity_warning", "2026-01-05T00:00:00+00:00")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(len(report["sections"]["integrity_delivery"]["failed"]), 2)
        # The real promotions: one row per slot. The still-pending one proves
        # its slot; the delivered one leaves only (failure kind, time), which
        # cannot name MEMORY / CHANGED, so that slot is unverifiable.
        outbox([{"kind": "CPU", "state": "CHANGED", "detail": "COALESCED_PENDING_WARNING"}], when)
        outbox([{"kind": "MEMORY", "state": "CHANGED",
                 "detail": "COALESCED_PENDING_WARNING"}], when)
        deliver(3, "hardware_integrity_failure", when)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["integrity_delivery"]["failed"],
                         [{"id": "overflow:MEMORY:CHANGED", "reason": "unverifiable"}])

    def test_delivered_unrelated_row_never_stands_in_for_a_lost_slot(self):
        # Codex P1: a CPU / CHANGED slot is lost while an unrelated GPU /
        # CHANGED row of the same failure kind and time is delivered.
        self.runtime.seed()
        when = "2026-01-01T00:00:00+00:00"
        self.runtime.execute("INSERT INTO integrity_overflow VALUES ('CPU', 'CHANGED', ?)",
                             (when,))
        _, baseline = self.record()
        self.runtime.execute("DELETE FROM integrity_overflow")
        self.runtime.execute(
            "INSERT INTO integrity_outbox(at, immediate, findings) VALUES (?, 1, ?)",
            (when, json.dumps([{"kind": "GPU", "state": "CHANGED", "detail": "x"}])))
        self.runtime.execute("DELETE FROM integrity_outbox WHERE id=1")
        self.runtime.execute(
            "INSERT INTO notification_events VALUES (?, 'hardware_integrity_failure', ?, 1, 'sent')",
            (str(uuid5(EVENT_NAMESPACE, "integrity-outbox:1")), when))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["integrity_delivery"],
                         {"status": "failed",
                          "failed": [{"id": "overflow:CPU:CHANGED", "reason": "unverifiable"}]})

    def _paired_node(self, key: str, serial: str) -> str:
        node = str(uuid4())
        self.runtime.execute(
            "INSERT INTO capture_nodes VALUES (?, 'synthetic', 'online', NULL, "
            "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')", (node,))
        self.runtime.execute(
            "INSERT INTO pairing_node_credentials (node_id, public_key_digest, "
            "credential_serial_digest, state, not_after) VALUES (?, ?, ?, 'active', 10.0)",
            (node, key, serial))
        return node

    def _activated(self, node: str, key: str) -> None:
        self.runtime.execute(
            "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', 'epoch', 0, 'activated')",
            (str(uuid4()), node, key))

    def test_an_old_activated_enrollment_never_explains_a_new_identity(self):
        # Codex P1: the node first paired with key "a", then promoted a
        # renewal to key "b" before the record. Reinstating "a" (still bound,
        # its enrollment still 'activated') is not a fresh pairing.
        self.runtime.seed()
        first, current = "a" * 64, "b" * 64
        node = self._paired_node(current, "c" * 64)
        for key in (first, current):
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
        self._activated(node, first)
        staged = "d" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (staged, node))
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0)",
                             (node, staged, "e" * 64))
        _, baseline = self.record()
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=?, "
                             "credential_serial_digest=? WHERE node_id=?",
                             (first, "f" * 64, node))
        self.runtime.execute("DELETE FROM pairing_node_renewals")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         [{"id": f"pairing_credentials:{node}", "reason": "changed"},
                          {"id": f"pairing_renewals:{node}", "reason": "missing"}])
        # A pairing activated after the record does explain it.
        fresh = "9" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (fresh, node))
        self._activated(node, fresh)
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=? "
                             "WHERE node_id=?", (fresh, node))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        # A baseline without enrollment IDs cannot date activations: none count.
        recorded = json.loads(baseline.read_text())
        state = recorded["security_state"]
        state["pairing_activations"] = [item[1:] for item in state["pairing_activations"]]
        legacy = self.notes / "legacy.json"
        legacy.write_text(json.dumps(recorded))
        os.chmod(legacy, 0o600)
        code, report, _ = self.verify(legacy)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": f"pairing_credentials:{node}", "reason": "changed"},
                      report["sections"]["security_state"]["failed"])

    def test_recorded_activations_persist_and_fresh_pairings_bind_new_keys(self):
        # Codex P1: a migration deletes the recorded 'activated' enrollment
        # and reinserts the same node / key under a new ID to reinstate the
        # superseded key "a". PairingLedger never deletes an enrollment or
        # moves it out of 'activated', and a fresh pairing binds a new key.
        self.runtime.seed()
        first, current = "a" * 64, "b" * 64
        node = self._paired_node(current, "c" * 64)
        for key in (first, current):
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
        recorded = str(uuid4())
        self.runtime.execute(
            "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', 'epoch', 0, 'activated')",
            (recorded, node, first))
        # Approved (key bound) but not yet activated at record time.
        opened, pending_key = str(uuid4()), "d" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             (pending_key, node))
        self.runtime.execute(
            "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', 'epoch', 0, 'consumed')",
            (opened, node, pending_key))
        _, baseline = self.record()
        self.assertNotIn(pending_key, baseline.read_text())
        self.runtime.execute("DELETE FROM pairing_enrollments WHERE id=?", (recorded,))
        self._activated(node, first)
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=?, "
                             "credential_serial_digest=? WHERE node_id=?",
                             (first, "e" * 64, node))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         # The vanished recorded activation is what fails: the
                         # reinserted copy alone would read as an Owner retry.
                         [{"id": f"pairing_enrollments:{recorded}", "reason": "missing"}])
        # With the recorded activation restored, the new copy is what
        # command_approve() produces when the Owner retries this node's live
        # key (approve() makes a new enrollment for it), so it is accepted.
        self.runtime.execute(
            "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', 'epoch', 0, 'activated')",
            (recorded, node, first))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        # The enrollment open at record time completing is a fresh pairing.
        self.runtime.execute("DELETE FROM pairing_enrollments WHERE state='activated' AND id!=?",
                             (recorded,))
        self.runtime.execute("UPDATE pairing_enrollments SET state='activated' WHERE id=?",
                             (opened,))
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=? "
                             "WHERE node_id=?", (pending_key, node))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])

    def test_credential_changes_require_a_live_key_binding(self):
        # Codex P1: _bind_key() refuses a revoked binding and revoke() revokes
        # bindings and credential together, so an active credential over a
        # revoked binding (allowed 0 -> 1 on its own) is never a ledger state.
        self.runtime.seed()
        nodes = {}
        for index, label in enumerate(("promoted", "repaired", "restaged", "unchanged")):
            key = f"{index}a".ljust(64, "0")
            nodes[label] = node = self._paired_node(key, "c" * 64)
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
        for label in ("promoted", "restaged"):
            staged = f"{label}".encode().hex().ljust(64, "0")
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                 (staged, nodes[label]))
            self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0)",
                                 (nodes[label], staged, "d" * 64))
        _, baseline = self.record()
        # Promotion of the staged renewal, but its binding is revoked.
        self.runtime.execute(
            "UPDATE pairing_node_credentials SET public_key_digest=(SELECT public_key_digest "
            "FROM pairing_node_renewals WHERE node_id=?), credential_serial_digest=?, "
            "not_after=20.0 WHERE node_id=?", (nodes["promoted"], "d" * 64, nodes["promoted"]))
        self.runtime.execute(
            "UPDATE pairing_key_bindings SET revoked=1 WHERE public_key_digest=(SELECT "
            "public_key_digest FROM pairing_node_renewals WHERE node_id=?)", (nodes["promoted"],))
        self.runtime.execute("DELETE FROM pairing_node_renewals WHERE node_id=?",
                             (nodes["promoted"],))
        # A fresh pairing whose new key binding is revoked.
        fresh = "e" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 1)",
                             (fresh, nodes["repaired"]))
        self._activated(nodes["repaired"], fresh)
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=? "
                             "WHERE node_id=?", (fresh, nodes["repaired"]))
        # Re-staged onto a newly bound but revoked key.
        restaged = "9" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 1)",
                             (restaged, nodes["restaged"]))
        self.runtime.execute("UPDATE pairing_node_renewals SET public_key_digest=? "
                             "WHERE node_id=?", (restaged, nodes["restaged"]))
        # The active credential's own binding revoked without revoking it.
        self.runtime.execute("UPDATE pairing_key_bindings SET revoked=1 WHERE public_key_digest=?",
                             ("3a".ljust(64, "0"),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: (item["id"], item["reason"])),
                         sorted([{"id": f"pairing_credentials:{nodes['promoted']}",
                                  "reason": "unbound"},
                                 {"id": f"pairing_credentials:{nodes['repaired']}",
                                  "reason": "unbound"},
                                 {"id": f"pairing_renewals:{nodes['restaged']}",
                                  "reason": "unbound"},
                                 {"id": f"pairing_credentials:{nodes['unchanged']}",
                                  "reason": "unbound"},
                                 # Only revoke() revokes a binding, together with
                                 # every binding, open enrollment and the credential.
                                 *({"id": f"pairing_revocation:{node}",
                                    "reason": "incomplete"} for node in nodes.values())],
                                key=lambda item: (item["id"], item["reason"])))

    def test_pairing_state_follows_the_ledger_invariants(self):
        # Codex P1s: an active credential with no live binding of its key to
        # its node; a kept staged renewal whose binding is revoked; a
        # credential revoked without what revoke() does with it.
        self.runtime.seed()
        nodes = {}
        for index, label in enumerate(("revoked-alone", "revoked-staged", "staged-flip")):
            key = f"{index}a".ljust(64, "0")
            nodes[label] = node = self._paired_node(key, "c" * 64)
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
        for label in ("revoked-staged", "staged-flip"):
            staged = f"{label}".encode().hex()[:64].ljust(64, "0")
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                 (staged, nodes[label]))
            self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0)",
                                 (nodes[label], staged, "d" * 64))
        _, baseline = self.record()
        # A node first seen now, with no binding at all, and one whose key
        # is bound to another node.
        unbound, foreign = self._paired_node("e" * 64, "c" * 64), \
            self._paired_node("1a".ljust(64, "0"), "c" * 64)
        for node, key in ((unbound, "e" * 64), (foreign, "1a".ljust(64, "0"))):
            self._activated(node, key)
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             ("e" * 64, str(uuid4())))
        # Revoked without revoking the bindings (and keeping the renewal).
        self.runtime.execute("UPDATE pairing_node_credentials SET state='revoked' "
                             "WHERE node_id IN (?, ?)",
                             (nodes["revoked-alone"], nodes["revoked-staged"]))
        # The kept renewal's binding revoked under an active credential.
        self.runtime.execute(
            "UPDATE pairing_key_bindings SET revoked=1 WHERE public_key_digest=(SELECT "
            "public_key_digest FROM pairing_node_renewals WHERE node_id=?)",
            (nodes["staged-flip"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["security_state"]["failed"]
        for expected in (
                {"id": f"pairing_credentials:{unbound}", "reason": "unbound"},
                {"id": f"pairing_credentials:{foreign}", "reason": "unbound"},
                {"id": f"pairing_revocation:{nodes['revoked-alone']}", "reason": "incomplete"},
                {"id": f"pairing_revocation:{nodes['revoked-staged']}", "reason": "incomplete"},
                {"id": f"pairing_renewals:{nodes['revoked-staged']}", "reason": "unbound"},
                {"id": f"pairing_renewals:{nodes['staged-flip']}", "reason": "unbound"},
                {"id": f"pairing_revocation:{nodes['staged-flip']}", "reason": "incomplete"}):
            self.assertIn(expected, failed)

    def test_ledger_operation_compositions_are_preserved(self):
        # Drive the real PairingLedger across the record boundary: every
        # composition below is a state the service produces.
        self.runtime.seed()
        ledger = PairingLedger(Database(self.runtime.database), HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(Database(self.runtime.database)),
                               clock=lambda: 100.0, process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, counter = Owner(), iter(range(1, 10_000))

        def digest():
            return f"{next(counter):064x}"

        def pair(node, key):
            approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key)
            claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                                  public_key_digest=key, code=code.value)
            ledger.activate(claim, credential_serial_digest=digest(), not_after=50.0)

        def stage(node, current, key, serial):
            ledger.stage_renewal(node_id=node, current_public_key_digest=current[0],
                                 current_credential_digest=current[1],
                                 public_key_digest=key, credential_serial_digest=serial,
                                 not_after=90.0)

        def credential(node):
            with closing(sqlite3.connect(self.runtime.database)) as connection:
                return connection.execute(
                    "SELECT public_key_digest, credential_serial_digest FROM "
                    "pairing_node_credentials WHERE node_id=?", (str(node),)).fetchone()
        labels = ("promote", "restage", "retry", "revoke", "promote-restage", "activate-open",
                  "revoke-repair", "repair", "new")
        nodes = {label: uuid4() for label in labels}
        staged = {}
        for label in labels[:5] + ("revoke-repair", "repair"):
            pair(nodes[label], digest())
        for label in labels[:5]:
            staged[label] = (digest(), digest())
            stage(nodes[label], credential(nodes[label]), *staged[label])
        approval, code = ledger.approve(owner, "owner", node_id=nodes["activate-open"],
                                        public_key_digest=(open_key := digest()))
        open_claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=open_key, code=code.value)
        _, baseline = self.record()
        self.assertTrue(ledger.admits(node_id=nodes["promote"],
                                      public_key_digest=staged["promote"][0],
                                      credential_serial_digest=staged["promote"][1]))
        stage(nodes["restage"], credential(nodes["restage"]), digest(), digest())
        stage(nodes["retry"], credential(nodes["retry"]), staged["retry"][0], digest())
        ledger.revoke(owner, "owner", node_id=nodes["revoke"])
        self.assertTrue(ledger.admits(node_id=nodes["promote-restage"],
                                      public_key_digest=staged["promote-restage"][0],
                                      credential_serial_digest=staged["promote-restage"][1]))
        stage(nodes["promote-restage"], credential(nodes["promote-restage"]), digest(), digest())
        ledger.activate(open_claim, credential_serial_digest=digest(), not_after=50.0)
        ledger.revoke(owner, "owner", node_id=nodes["revoke-repair"])
        pair(nodes["revoke-repair"], digest())
        pair(nodes["repair"], digest())
        pair(nodes["new"], digest())
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        # Known fail-closed side effects: a renewal both staged and promoted
        # after the record cannot show its material, and re-pairing a node
        # already revoked at record time reads as a reversed revocation.
        stage(nodes["repair"], credential(nodes["repair"]), (late := digest()), (serial := digest()))
        self.assertTrue(ledger.admits(node_id=nodes["repair"], public_key_digest=late,
                                      credential_serial_digest=serial))
        _, revoked_baseline = self.record("revoked.json")
        pair(nodes["revoke"], digest())
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": f"pairing_credentials:{nodes['repair']}", "reason": "changed"},
                      report["sections"]["security_state"]["failed"])
        code, report, _ = self.verify(revoked_baseline)
        self.assertEqual(report["sections"]["security_state"]["failed"],
                         [{"id": f"pairing_credentials:{nodes['revoke']}",
                           "reason": "revocation_reversed"}])

    def test_a_staged_key_is_never_an_enrollment_key(self):
        # Codex P1: stage K, consume an approval for K, activate another fresh
        # key J (which deletes the K renewal); a migration then restores the
        # K renewal and marks K's enrollment activated. Both keys are newly
        # bound, but stage_renewal() never stages an enrollment's key.
        self.runtime.seed()
        ledger = PairingLedger(Database(self.runtime.database), HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(Database(self.runtime.database)),
                               clock=lambda: 100.0, process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node = Owner(), uuid4()

        def claim(key):
            approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key)
            return approval, ledger.redeem(enrollment_id=approval.enrollment_id,
                                           public_key_digest=key, code=code.value)
        ledger.activate(claim("a" * 64)[1], credential_serial_digest="b" * 64, not_after=50.0)
        _, baseline = self.record()
        staged, serial = "c" * 64, "d" * 64
        ledger.stage_renewal(node_id=node, current_public_key_digest="a" * 64,
                             current_credential_digest="b" * 64, public_key_digest=staged,
                             credential_serial_digest=serial, not_after=90.0)
        approval, _ = claim(staged)
        ledger.activate(claim("e" * 64)[1], credential_serial_digest="f" * 64, not_after=50.0)
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 90.0)",
                             (str(node), staged, serial))
        self.runtime.execute("UPDATE pairing_enrollments SET state='activated' WHERE id=?",
                             (str(approval.enrollment_id),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         [{"id": f"pairing_enrollments:{approval.enrollment_id}",
                           "reason": "enrollment_key"},
                          {"id": f"pairing_renewals:{node}", "reason": "enrollment_key"}])
        # The same without the restored enrollment state: still refused.
        self.runtime.execute("UPDATE pairing_enrollments SET state='consumed' WHERE id=?",
                             (str(approval.enrollment_id),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         [{"id": f"pairing_enrollments:{approval.enrollment_id}",
                           "reason": "enrollment_key"},
                          {"id": f"pairing_renewals:{node}", "reason": "enrollment_key"}])

    def test_recorded_enrollments_only_move_forward(self):
        # Codex P1: PairingLedger never deletes an enrollment; redeem() moves
        # pending -> consumed / expired, activate() consumed -> activated,
        # revoke() pending / consumed -> revoked; the rest are final.
        self.runtime.seed()
        node = self._paired_node("a" * 64, "c" * 64)
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", ("a" * 64, node))
        states = {"deleted": "pending", "rewound": "consumed", "revived": "expired",
                  "expires": "pending", "revoked": "consumed", "completes": "pending"}
        ids = {}
        for index, (label, state) in enumerate(states.items()):
            key = f"{index}e".ljust(64, "0")
            ids[label] = str(uuid4())
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
            self.runtime.execute(
                "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', 'epoch', 0, ?)",
                (ids[label], node, key, state))
        _, baseline = self.record()
        self.runtime.execute("DELETE FROM pairing_enrollments WHERE id=?", (ids["deleted"],))
        update = "UPDATE pairing_enrollments SET state=? WHERE id=?"
        self.runtime.execute(update, ("pending", ids["rewound"]))
        self.runtime.execute(update, ("activated", ids["revived"]))
        self.runtime.execute(update, ("expired", ids["expires"]))
        self.runtime.execute(update, ("revoked", ids["revoked"]))
        self.runtime.execute(update, ("activated", ids["completes"]))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: (item["id"], item["reason"])),
                         sorted([{"id": f"pairing_enrollments:{ids['deleted']}",
                                  "reason": "missing"},
                                 {"id": f"pairing_enrollments:{ids['rewound']}",
                                  "reason": "changed"},
                                 {"id": f"pairing_enrollments:{ids['revived']}",
                                  "reason": "changed"},
                                 {"id": f"pairing_enrollments:{ids['revived']}",
                                  "reason": "activation_unapplied"},
                                 # Codex P1: flipped to activated alone; activate()
                                 # also installs its key as the node's credential.
                                 {"id": f"pairing_enrollments:{ids['completes']}",
                                  "reason": "activation_unapplied"},
                                 # Codex P1: flipped to revoked alone; only revoke()
                                 # sets it, revoking the whole node and its binding.
                                 {"id": f"pairing_enrollments:{ids['revoked']}",
                                  "reason": "unbound"},
                                 {"id": f"pairing_revocation:{node}", "reason": "incomplete"}],
                                key=lambda item: (item["id"], item["reason"])))

    def test_owner_retries_of_a_bound_key_are_preserved(self):
        # Codex P1 (false failure): pairing_cli.command_approve() retries an
        # interrupted, expired or unacknowledged enrollment by approving the
        # same key for the node its live binding names; approve() then makes
        # a new enrollment that activate() completes.
        self.runtime.seed()
        database = Database(self.runtime.database)

        def ledger():
            return PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                                 audit=AuditStore(database), clock=lambda: 100.0,
                                 process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, before = Owner(), ledger()
        keys = {label: f"{index + 1:064x}" for index, label in
                enumerate(("interrupted", "expired", "unacknowledged", "superseded"))}
        nodes = {label: uuid4() for label in keys}

        def approve(on, label):
            return on.approve(owner, "owner", node_id=nodes[label],
                              public_key_digest=keys[label])

        def complete(on, label, serial):
            approval, code = approve(on, label)
            claim = on.redeem(enrollment_id=approval.enrollment_id,
                              public_key_digest=keys[label], code=code.value)
            on.activate(claim, credential_serial_digest=serial, not_after=50.0)
        approve(before, "interrupted")                       # never redeemed
        stale, code = approve(before, "expired")
        with self.assertRaises(PairingError):                # a restart expires it
            ledger().redeem(enrollment_id=stale.enrollment_id,
                            public_key_digest=keys["expired"], code=code.value)
        complete(before, "unacknowledged", "a" * 64)         # Agent never got it
        complete(before, "superseded", "b" * 64)
        renewed = "f" * 64
        before.stage_renewal(node_id=nodes["superseded"],
                             current_public_key_digest=keys["superseded"],
                             current_credential_digest="b" * 64,
                             public_key_digest=renewed, credential_serial_digest="c" * 64,
                             not_after=90.0)
        self.assertTrue(before.admits(node_id=nodes["superseded"], public_key_digest=renewed,
                                      credential_serial_digest="c" * 64))
        _, baseline = self.record()
        after = ledger()
        for label in keys:
            self.assertEqual(after.bound_node(keys[label]), nodes[label])
            complete(after, label, "d" * 64)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])

    def test_a_retry_never_approves_a_staged_renewal_key(self):
        # Codex P1: the staged key is live for the node, so command_approve()
        # would retry it; approving and activating it deletes the renewal and
        # replaces the credential. That composition fails closed.
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node, staged = Owner(), uuid4(), "c" * 64

        def complete(key, serial):
            approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key)
            claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                                  public_key_digest=key, code=code.value)
            ledger.activate(claim, credential_serial_digest=serial, not_after=50.0)
            return approval
        complete("a" * 64, "b" * 64)
        ledger.stage_renewal(node_id=node, current_public_key_digest="a" * 64,
                             current_credential_digest="b" * 64, public_key_digest=staged,
                             credential_serial_digest="d" * 64, not_after=90.0)
        _, baseline = self.record()
        self.assertEqual(ledger.bound_node(staged), node)
        approval = complete(staged, "e" * 64)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["security_state"]["failed"]
        self.assertIn({"id": f"pairing_enrollments:{approval.enrollment_id}",
                       "reason": "enrollment_key"}, failed)
        self.assertIn({"id": f"pairing_credentials:{node}", "reason": "changed"}, failed)

    def test_window_operation_compositions_against_the_real_ledger(self):
        # Every 2-operation composition inside the record -> verify window,
        # and every 3-operation one involving revoke, over a node paired at
        # record time (with or without a staged renewal), driven through the
        # real PairingLedger. Each must verify as preserved except the
        # documented fail-closed cases: the credential at verify time is a
        # renewal both staged and promoted inside the window, or an
        # enrollment since the record names the key staged at record time
        # (a retry of the promoted key ends exactly where approving the
        # still-staged key does).
        operations = ("fresh", "retry", "stage", "promote", "revoke", "expiry")

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner = Owner()

        class Inapplicable(Exception):
            pass

        def scenario(index, base, ops):
            runtime = Runtime(self.base / f"composition-{index}")
            database = Database(runtime.database)

            def ledger():
                return PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                                     audit=AuditStore(database), clock=lambda: 100.0,
                                     process_epoch=uuid4())
            main, node, counter = ledger(), uuid4(), iter(range(1, 1000))

            def digest():
                return f"{index:08x}{next(counter):056x}"

            def credential():
                with closing(sqlite3.connect(runtime.database)) as connection:
                    return connection.execute(
                        "SELECT public_key_digest, credential_serial_digest, state FROM "
                        "pairing_node_credentials WHERE node_id=?", (str(node),)).fetchone()

            def staged_row():
                with closing(sqlite3.connect(runtime.database)) as connection:
                    return connection.execute(
                        "SELECT public_key_digest, credential_serial_digest FROM "
                        "pairing_node_renewals WHERE node_id=?", (str(node),)).fetchone()

            def complete(key):
                approval, code = main.approve(owner, "owner", node_id=node,
                                              public_key_digest=key)
                claim = main.redeem(enrollment_id=approval.enrollment_id,
                                    public_key_digest=key, code=code.value)
                main.activate(claim, credential_serial_digest=digest(), not_after=50.0)

            def run(op):
                current = credential()
                if op == "fresh":
                    complete(digest())
                elif op == "retry":
                    if main.bound_node(current[0]) != node:
                        raise Inapplicable
                    complete(current[0])
                elif op == "stage":
                    if current[2] != "active":
                        raise Inapplicable
                    main.stage_renewal(node_id=node, current_public_key_digest=current[0],
                                       current_credential_digest=current[1],
                                       public_key_digest=digest(),
                                       credential_serial_digest=digest(), not_after=90.0)
                elif op == "promote":
                    row = staged_row()
                    if row is None or current[2] != "active":
                        raise Inapplicable
                    self.assertTrue(main.admits(node_id=node, public_key_digest=row[0],
                                                credential_serial_digest=row[1]))
                elif op == "revoke":
                    if current[2] != "active":
                        raise Inapplicable
                    main.revoke(owner, "owner", node_id=node)
                elif op == "expiry":
                    approval, code = main.approve(owner, "owner", node_id=node,
                                                  public_key_digest=digest())
                    with self.assertRaises(PairingError):
                        ledger().redeem(enrollment_id=approval.enrollment_id,
                                        public_key_digest=approval.public_key_digest,
                                        code=code.value)
            complete(digest())
            staged_source, recorded_staged = None, None
            if base == "staged":
                run("stage")
                staged_source, recorded_staged = "recorded", staged_row()[0]
            approved_staged = False
            saved, self.runtime = self.runtime, runtime
            try:
                _, baseline = self.record(f"composition-{index}.json")
                credential_source = "recorded"
                for op in ops:
                    approved_staged |= op == "retry" and credential()[0] == recorded_staged
                    run(op)
                    if op in ("fresh", "retry"):
                        credential_source, staged_source = "activation", None
                    elif op == "stage":
                        staged_source = "window"
                    elif op == "promote":
                        credential_source, staged_source = f"promoted-{staged_source}", None
                    elif op == "revoke":
                        staged_source = None
                _, report, _ = self.verify(baseline)
            finally:
                self.runtime = saved
            return (credential_source == "promoted-window" or approved_staged,
                    report["sections"]["security_state"])

        compositions = [(a, b) for a in operations for b in operations]
        compositions += [combo for a in operations for b in operations
                         for combo in ((a, b, "revoke"), (a, "revoke", b), ("revoke", a, b))]
        unexpected, ran = [], 0
        for index, (base, ops) in enumerate(
                (base, ops) for base in ("plain", "staged") for ops in dict.fromkeys(compositions)):
            try:
                fail_closed, section = scenario(index, base, ops)
            except Inapplicable:
                continue
            ran += 1
            if bool(section["failed"]) != fail_closed:
                unexpected.append((base, ops, section["failed"]))
        self.assertGreater(ran, 100, ran)
        self.assertEqual(unexpected, [])

    def test_single_row_tampers_of_a_ledger_state_fail(self):
        # Mutation cases: a state the real PairingLedger produced across the
        # record boundary, then one tampered row per table. Every one fails;
        # the first is Codex's: an enrollment approved since the record,
        # then marked revoked while its key binding stays live.
        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner = Owner()

        def build(index):
            runtime = Runtime(self.base / f"tamper-{index}")
            database = Database(runtime.database)
            ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                                   audit=AuditStore(database), clock=lambda: 100.0,
                                   process_epoch=uuid4())
            node = uuid4()
            keys = {name: f"{index:08x}{n:056x}" for n, name in
                    enumerate(("active", "staged", "pending", "expired"), 1)}
            approval, code = ledger.approve(owner, "owner", node_id=node,
                                            public_key_digest=keys["active"])
            claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                                  public_key_digest=keys["active"], code=code.value)
            ledger.activate(claim, credential_serial_digest="b" * 64, not_after=50.0)
            ledger.stage_renewal(node_id=node, current_public_key_digest=keys["active"],
                                 current_credential_digest="b" * 64,
                                 public_key_digest=keys["staged"],
                                 credential_serial_digest="c" * 64, not_after=90.0)
            stale, code = ledger.approve(owner, "owner", node_id=node,
                                         public_key_digest=keys["expired"])
            with self.assertRaises(PairingError):
                PairingLedger(database, HmacCodeVerifier(b"s" * 32), audit=AuditStore(database),
                              clock=lambda: 100.0, process_epoch=uuid4()).redeem(
                    enrollment_id=stale.enrollment_id, public_key_digest=keys["expired"],
                    code=code.value)
            saved, self.runtime = self.runtime, runtime
            try:
                _, baseline = self.record(f"tamper-{index}.json")
            finally:
                self.runtime = saved
            pending, _ = ledger.approve(owner, "owner", node_id=node,
                                        public_key_digest=keys["pending"])
            return runtime, baseline, node, keys, pending.enrollment_id, approval.enrollment_id
        tampers = {
            "new enrollment revoked, binding live":
                ("UPDATE pairing_enrollments SET state='revoked' WHERE id=:pending",),
            "enrollment deleted": ("DELETE FROM pairing_enrollments WHERE id=:activated",),
            "activated enrollment rewound":
                ("UPDATE pairing_enrollments SET state='consumed' WHERE id=:activated",),
            "expired enrollment revived":
                ("UPDATE pairing_enrollments SET state='pending' WHERE public_key_digest=:expired",),
            "live binding revoked":
                ("UPDATE pairing_key_bindings SET revoked=1 WHERE public_key_digest=:pending",),
            "binding deleted": ("DELETE FROM pairing_key_bindings WHERE public_key_digest=:expired",),
            "credential revoked alone":
                ("UPDATE pairing_node_credentials SET state='revoked' WHERE node_id=:node",),
            "credential serial changed":
                ("UPDATE pairing_node_credentials SET credential_serial_digest=:other "
                 "WHERE node_id=:node",),
            "renewal deleted": ("DELETE FROM pairing_node_renewals WHERE node_id=:node",),
            "renewal key replaced":
                ("UPDATE pairing_node_renewals SET public_key_digest=:other WHERE node_id=:node",),
        }
        runtime, baseline, *_ = build(len(tampers))
        saved, self.runtime = self.runtime, runtime
        try:
            _, report, _ = self.verify(baseline)
        finally:
            self.runtime = saved
        self.assertEqual(report["sections"]["security_state"]["failed"], [])  # untampered
        for index, (label, statements) in enumerate(tampers.items()):
            with self.subTest(label):
                runtime, baseline, node, keys, pending, activated = build(index)
                values = {"node": str(node), "pending": str(pending),
                          "activated": str(activated), "expired": keys["expired"],
                          "other": "e" * 64}
                values["pending"] = (str(pending) if "enrollment" in label
                                     else keys["pending"])
                with closing(sqlite3.connect(runtime.database, isolation_level=None)) as db:
                    for statement in statements:
                        db.execute(statement, {key: value for key, value in values.items()
                                               if f":{key}" in statement})
                saved, self.runtime = self.runtime, runtime
                try:
                    _, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                self.assertTrue(report["sections"]["security_state"]["failed"], label)

    def test_a_staged_renewal_is_never_restaged_onto_a_superseded_key(self):
        # Codex P1: stage_renewal() accepts a key already bound to the node
        # only as a retry of the currently staged key.
        self.runtime.seed()
        node = self._paired_node("a" * 64, "c" * 64)
        superseded, staged = "b" * 64, "d" * 64
        for key in ("a" * 64, superseded, staged):
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0)",
                             (node, staged, "e" * 64))
        _, baseline = self.record()
        # A retry of the staged key with a reissued certificate is allowed.
        self.runtime.execute("UPDATE pairing_node_renewals SET credential_serial_digest=?, "
                             "not_after=30.0 WHERE node_id=?", ("f" * 64, node))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        self.runtime.execute("UPDATE pairing_node_renewals SET public_key_digest=? "
                             "WHERE node_id=?", (superseded, node))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["security_state"]["failed"],
                         [{"id": f"pairing_renewals:{node}", "reason": "changed"}])

    def test_uncovered_durable_tables_are_listed_as_not_inventoried(self):
        self.runtime.seed()
        _, baseline = self.record()
        code, report, stdout = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        for name in ("recording_source_discontinuities", "recording_source_cursors",
                     "roi_calibration_history", "notification_events",
                     "uvc_approvals.session_token", "integrity_status",
                     "recording_health_status"):
            self.assertEqual(report["not_inventoried"][name], "not_inventoried (#132)")
            self.assertIn(f"{name}: not_inventoried (#132)", stdout)

    def test_verify_refuses_a_baseline_that_is_not_private(self):
        self.runtime.seed()
        _, baseline = self.record()
        os.chmod(baseline, 0o644)
        code, _, stderr = run("verify", "--runtime-root", str(self.runtime.root),
                              "--baseline", str(baseline))
        self.assertEqual(code, inventory.EXIT_USAGE)
        self.assertIn("not private", stderr)
        os.chmod(baseline, 0o600)
        link = self.notes / "linked.json"
        link.symlink_to(baseline)
        code, _, _ = run("verify", "--runtime-root", str(self.runtime.root),
                         "--baseline", str(link))
        self.assertEqual(code, inventory.EXIT_USAGE)
        code, _, _ = run("verify", "--runtime-root", str(self.runtime.root),
                         "--baseline", str(baseline))
        self.assertEqual(code, inventory.EXIT_PRESERVED)

    def test_grant_and_revocation_state_is_preserved_by_logical_id(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        recorded = json.loads(baseline.read_text())
        principals = recorded["access"]["principals"]
        self.assertEqual(principals[seeded["live"]]["permissions"], ["live:view"])
        self.assertEqual(principals[seeded["recordings"]]["permissions"], ["recordings:view"])
        self.assertTrue(principals[seeded["revoked"]]["revoked"])
        # A lifecycle operation that silently widened a grant is a failure.
        self.runtime.execute("INSERT INTO access_principal_permissions VALUES (?, 'recordings:view')",
                             (seeded["live"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["live"], "reason": "changed"},
                      report["sections"]["access_principals"]["failed"])

    def test_missing_owner_is_a_failure(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        self.runtime.execute("DELETE FROM access_sessions")
        self.runtime.execute("DELETE FROM access_credentials")
        self.runtime.execute("DELETE FROM access_principals WHERE id=?", (seeded["owner"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertFalse(report["owner_present"])

    def test_refuses_output_inside_runtime_root(self):
        for target in (self.runtime.root / "inventory.json",
                       self.runtime.root / "state" / "inventory.json",
                       self.runtime.root / "recordings" / "inventory.json"):
            code, _, stderr = run("record", "--runtime-root", str(self.runtime.root),
                                  "--output", str(target))
            self.assertEqual(code, inventory.EXIT_USAGE)
            self.assertIn("outside the runtime root", stderr)
            self.assertFalse(target.exists())

    def test_refuses_output_inside_repository_checkout(self):
        checkout = self.base / "checkout"
        (checkout / ".git").mkdir(parents=True)
        (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (checkout / "notes").mkdir()
        worktree = self.base / "worktree"
        worktree.mkdir()
        (worktree / ".git").write_text("gitdir: elsewhere\n")
        repository = Path(inventory.__file__).resolve().parents[1]
        for target in (checkout / "notes" / "inventory.json", worktree / "inventory.json",
                       repository / "inventory-refused.json"):
            code, _, stderr = run("record", "--runtime-root", str(self.runtime.root),
                                  "--output", str(target))
            self.assertEqual(code, inventory.EXIT_USAGE, target)
            self.assertIn("refused", stderr)
            self.assertFalse(target.exists())

    def test_refuses_whole_installed_release_tree(self):
        # Installed layout: <destination>/releases/<version>/venv with
        # <destination>/current -> releases/<version>; the tool runs from that
        # venv, so sys.prefix is the venv and the package is in site-packages.
        from unittest import mock
        import sys
        destination = self.base / "install"
        release = destination / "releases" / "1.0.0"
        venv = release / "venv"
        (venv / "bin").mkdir(parents=True)
        (destination / "releases" / "0.9.0").mkdir()
        (destination / "current").symlink_to("releases/1.0.0")
        targets = (destination / "current" / "inventory.json",
                   release / "inventory.json",
                   destination / "inventory.json",
                   destination / "releases" / "0.9.0" / "inventory.json")
        with mock.patch.object(sys, "prefix", str(venv)), \
                mock.patch.object(sys, "base_prefix", "/usr"):
            for target in targets:
                code, _, stderr = run("record", "--runtime-root", str(self.runtime.root),
                                      "--output", str(target))
                self.assertEqual(code, inventory.EXIT_USAGE, target)
                self.assertIn("installed release", stderr)
                self.assertFalse(target.exists())
            # A private directory beside the installation remains allowed.
            code, _ = self.record("beside-install.json")
            self.assertNotEqual(code, inventory.EXIT_USAGE)

    def test_segment_catalog_metadata_change_is_detected(self):
        # RecordingStore._integrity() reports a segment whose file size differs
        # from byte_length as corrupt; the manifest derives stream
        # discontinuities from stream_id/sequence; codec/container select the
        # player. A migration changing only these must not verify as preserved.
        seeded = self.runtime.seed()
        _, baseline = self.record()
        changes = {
            "byte_length": "byte_length = byte_length + 1",
            "codec": "codec = 'other-codec'",
            "container": "container = 'other-container'",
            "stream_id": "stream_id = 'other-stream'",
            "sequence": "sequence = sequence + 1000",
            "capture_node_id": "capture_node_id = 'other-node'",
            "critical": "critical = 1",
        }
        for column, assignment in changes.items():
            with self.subTest(column=column):
                with closing(sqlite3.connect(self.runtime.database)) as connection:
                    segment_id = connection.execute(
                        "SELECT segment_id FROM recording_links WHERE recording_id=?",
                        (seeded["starred"],)).fetchone()[0]
                    before = connection.execute(
                        "SELECT * FROM recording_segments WHERE id=?", (segment_id,)).fetchone()
                self.runtime.execute(
                    f"UPDATE recording_segments SET {assignment} WHERE id=?", (segment_id,))
                code, report, _ = self.verify(baseline)
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn({"id": seeded["starred"], "reason": "changed"},
                              report["sections"]["recordings"]["failed"])
                with closing(sqlite3.connect(self.runtime.database)) as connection:
                    columns = [row[1] for row in connection.execute(
                        "PRAGMA table_info(recording_segments)")]
                self.runtime.execute(
                    "UPDATE recording_segments SET "
                    + ", ".join(f"{name}=?" for name in columns) + " WHERE id=?",
                    (*before, segment_id))
        # Recording-level retention protection is also compared.
        self.runtime.execute("UPDATE recordings SET critical=1 WHERE id=?", (seeded["ordinary"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": seeded["ordinary"], "reason": "changed"},
                      report["sections"]["recordings"]["failed"])

    def test_in_progress_growth_rejects_byte_length_mismatch(self):
        self.runtime.seed()
        active = self.runtime.recording(starred=False, payload=b"generated-active-length",
                                        status="active", target_end_ms=20000)
        _, baseline = self.record()
        later = self.runtime.add_segment(active, b"generated-active-length-later")
        # Digest matches, catalog length does not: the store reports corrupt.
        self.runtime.execute("UPDATE recording_segments SET byte_length=byte_length+1 "
                             "WHERE id=?", (later,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": active, "reason": "changed"},
                      report["sections"]["recordings"]["failed"])

    def test_refuses_existing_or_relative_output(self):
        existing = self.notes / "existing.json"
        existing.write_text("keep")
        code, _, _ = run("record", "--runtime-root", str(self.runtime.root),
                         "--output", str(existing))
        self.assertEqual(code, inventory.EXIT_USAGE)
        self.assertEqual(existing.read_text(), "keep")
        code, _, _ = run("record", "--runtime-root", str(self.runtime.root),
                         "--output", "relative.json")
        self.assertEqual(code, inventory.EXIT_USAGE)

    def test_decode_and_container_duration_are_marked_manual(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        recorded = json.loads(baseline.read_text())
        self.assertEqual(recorded["manual"], {"container_duration": "manual",
                                              "decode_verification": "manual"})
        item = recorded["recordings"][seeded["ordinary"]]
        self.assertEqual(item["decode_verification"], "manual")
        self.assertEqual(item["container_duration"], "manual")
        self.assertEqual((item["start_ms"], item["target_end_ms"], item["ended_ms"]),
                         (0, 10000, 10000))
        self.assertIn("capture_agent_protected_incidents", recorded["not_applicable"])
        _, report, stdout = self.verify(baseline)
        self.assertEqual(report["manual"]["decode_verification"], "manual")
        self.assertIn("decode_verification: manual", stdout)

    def test_reads_database_without_writing_or_creating_it(self):
        self.runtime.seed()
        before = self.runtime.database.read_bytes()
        mtime = self.runtime.database.stat().st_mtime_ns
        self.record()
        self.assertEqual(self.runtime.database.read_bytes(), before)
        self.assertEqual(self.runtime.database.stat().st_mtime_ns, mtime)
        self.assertEqual(sorted(p.name for p in self.runtime.database.parent.iterdir()),
                         ["state.sqlite3"])
        missing = self.base / "missing-runtime"
        (missing / "state").mkdir(parents=True)
        code, _, _ = run("record", "--runtime-root", str(missing),
                         "--output", str(self.notes / "missing.json"))
        self.assertEqual(code, inventory.EXIT_USAGE)
        self.assertFalse((missing / "state" / "state.sqlite3").exists())
        self.assertFalse((self.notes / "missing.json").exists())

    def test_declared_rewrite_is_reported_separately(self):
        seeded = self.runtime.seed()
        _, baseline = self.record()
        path = self.runtime.segment_path(seeded["ordinary"])
        rewritten = bytes(reversed(path.read_bytes()))
        path.write_bytes(rewritten)
        # Bytes rewritten without the catalog digest following them are not
        # servable, so even a declared rewrite is then a failure.
        code, report, _ = self.verify(baseline, "--declared-rewrite", seeded["ordinary"])
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["declared_rewrites"], [])
        self.runtime.execute(
            "UPDATE recording_segments SET sha256=? WHERE id IN "
            "(SELECT segment_id FROM recording_links WHERE recording_id=?)",
            (hashlib.sha256(rewritten).hexdigest(), seeded["ordinary"]))
        code, report, _ = self.verify(baseline, "--declared-rewrite", seeded["ordinary"])
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["status"], "preserved_except_declared_rewrites")
        self.assertEqual(report["sections"]["recordings"]["declared_rewrites"],
                         [seeded["ordinary"]])
        code, _, stderr = run("verify", "--runtime-root", str(self.runtime.root),
                              "--baseline", str(baseline), "--declared-rewrite", str(uuid4()))
        self.assertEqual(code, inventory.EXIT_USAGE)

    def test_in_progress_recording_may_grow_but_not_lose_segments(self):
        self.runtime.seed()
        active = self.runtime.recording(starred=False, payload=b"generated-active",
                                        status="active", target_end_ms=20000)
        _, baseline = self.record()
        self.runtime.add_segment(active, b"generated-active-later")
        self.runtime.execute("UPDATE recordings SET status='interrupted', ended_ms=20000 "
                             "WHERE id=?", (active,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["sections"]["recordings"]["in_progress_at_record"], [active])
        with closing(sqlite3.connect(self.runtime.database)) as connection:
            first = connection.execute(
                "SELECT s.id FROM recording_segments s JOIN recording_links l "
                "ON l.segment_id=s.id WHERE l.recording_id=? ORDER BY s.start_ms",
                (active,)).fetchone()[0]
        os.unlink(self.runtime.root / "recordings" / (UUID(first).hex + ".seg"))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)

    def test_in_progress_recording_rejects_anything_but_valid_growth(self):
        self.runtime.seed()

        def active(label: str) -> str:
            return self.runtime.recording(starred=False, payload=b"generated-" + label.encode(),
                                          status="active", target_end_ms=20000)
        grows = active("grows")
        source_changed = active("source")
        start_changed = active("start")
        extended = active("extended")
        bad_status = active("status")
        missing_new = active("missing")
        mismatched_new = active("mismatch")
        _, baseline = self.record()
        self.runtime.add_segment(grows, b"generated-grows-later")
        self.runtime.execute("UPDATE recordings SET status='complete', ended_ms=20000 "
                             "WHERE id=?", (grows,))
        self.runtime.execute("UPDATE recordings SET source_id=? WHERE id=?",
                             (str(uuid4()), source_changed))
        # Same catalog duration, shifted start: only the start itself differs.
        self.runtime.execute("UPDATE recordings SET start_ms=5000, target_end_ms=25000 "
                             "WHERE id=?", (start_changed,))
        self.runtime.execute("UPDATE recordings SET target_end_ms=30000 WHERE id=?",
                             (extended,))
        self.runtime.execute("UPDATE recordings SET status='deleted' WHERE id=?",
                             (bad_status,))
        self.runtime.add_segment(missing_new, b"generated-never-written", write_file=False)
        self.runtime.add_segment(mismatched_new, b"generated-on-disk",
                                 catalog_payload=b"generated-in-catalog")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [grows])
        self.assertIn(grows, section["preserved"])
        rejected = [source_changed, start_changed, extended, bad_status,
                    missing_new, mismatched_new]
        for recording_id in rejected:
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])
            self.assertNotIn(recording_id, section["preserved"])


    def test_finished_recording_target_boundary_change_is_detected(self):
        # The manifest clips segments and computes gaps against target_end_ms,
        # so a change to it alone alters the playable recording.
        seeded = self.runtime.seed()
        _, baseline = self.record()
        self.runtime.execute("UPDATE recordings SET target_end_ms=5000 WHERE id=?",
                             (seeded["ordinary"],))
        self.runtime.execute("UPDATE recordings SET ended_ms=5000 WHERE id=?",
                             (seeded["starred"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["recordings"]["failed"]
        self.assertIn({"id": seeded["ordinary"], "reason": "changed"}, failed)
        self.assertIn({"id": seeded["starred"], "reason": "changed"}, failed)

    def test_star_change_during_lifecycle_is_a_failure(self):
        # Owner decision 2026-09-30: starring or unstarring between record and
        # verify stays a failure; take a new baseline instead.
        seeded = self.runtime.seed()
        active = self.runtime.recording(starred=False, payload=b"generated-active-star",
                                        status="active", target_end_ms=20000)
        _, baseline = self.record()
        self.runtime.execute("UPDATE recordings SET starred=1 WHERE id IN (?, ?)",
                             (seeded["ordinary"], active))
        self.runtime.execute("UPDATE recordings SET starred=0 WHERE id=?", (seeded["starred"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["recordings"]["failed"]
        for recording_id in (seeded["ordinary"], seeded["starred"], active):
            self.assertIn({"id": recording_id, "reason": "changed"}, failed)

    def test_in_progress_growth_rejects_foreign_or_out_of_window_segments(self):
        self.runtime.seed()

        def active(label: str) -> str:
            return self.runtime.recording(starred=False, payload=b"generated-" + label.encode(),
                                          status="active", target_end_ms=20000)
        grows = active("grows")
        foreign = active("foreign")
        outside = active("outside")
        shrunk = active("shrunk")
        _, baseline = self.record()
        self.runtime.add_segment(grows, b"generated-grows-later")
        # Ready and hash-matching, but from another camera.
        self.runtime.add_segment(foreign, b"generated-foreign-later", source_id=str(uuid4()))
        # Same source, but wholly after the recording's target end.
        self.runtime.add_segment(outside, b"generated-outside-later",
                                 start_ms=20000, end_ms=30000)
        # A stop may move the target earlier, but not below linked media.
        self.runtime.add_segment(shrunk, b"generated-shrunk-later")
        self.runtime.execute("UPDATE recordings SET target_end_ms=10000, ended_ms=10000, "
                             "status='complete' WHERE id=?", (shrunk,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [grows])
        for recording_id in (foreign, outside, shrunk):
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])
            self.assertNotIn(recording_id, section["preserved"])

    def test_in_progress_recording_end_must_lie_within_its_target(self):
        self.runtime.seed()
        ended_active = self.runtime.recording(starred=False, payload=b"generated-ended-active",
                                              status="active", target_end_ms=20000)
        overrun = self.runtime.recording(starred=False, payload=b"generated-overrun",
                                         status="active", target_end_ms=20000)
        _, baseline = self.record()
        # Still active yet already carrying an end, and an end past the target.
        self.runtime.execute("UPDATE recordings SET ended_ms=15000 WHERE id=?", (ended_active,))
        self.runtime.execute("UPDATE recordings SET target_end_ms=15000, ended_ms=18000, "
                             "status='complete' WHERE id=?", (overrun,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["recordings"]["failed"]
        for recording_id in (ended_active, overrun):
            self.assertIn({"id": recording_id, "reason": "changed"}, failed)


    def test_declared_rewrite_exempts_only_the_media_bytes(self):
        # A declared rewrite covers the intended byte rewrite, never a star
        # change (Owner decision 2026-09-30) or other catalog metadata.
        seeded = self.runtime.seed()
        _, baseline = self.record()
        path = self.runtime.segment_path(seeded["ordinary"])
        path.write_bytes(bytes(reversed(path.read_bytes())))
        self.runtime.execute("UPDATE recordings SET starred=1 WHERE id=?", (seeded["ordinary"],))
        path = self.runtime.segment_path(seeded["starred"])
        path.write_bytes(bytes(reversed(path.read_bytes())))
        self.runtime.execute("UPDATE recordings SET critical=1 WHERE id=?", (seeded["starred"],))
        code, report, _ = self.verify(baseline, "--declared-rewrite", seeded["ordinary"],
                                      "--declared-rewrite", seeded["starred"])
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["declared_rewrites"], [])
        for recording_id in (seeded["ordinary"], seeded["starred"]):
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])

    def test_declared_rewrite_with_catalog_update_and_unchanged_metadata_passes(self):
        # A migration that rewrites bytes and updates the catalog digest and
        # byte length to match is the declared case; the result must still be
        # servable (catalog match).
        seeded = self.runtime.seed()
        _, baseline = self.record()
        path = self.runtime.segment_path(seeded["ordinary"])
        rewritten = b"generated-rewritten-ordinary-bytes"
        path.write_bytes(rewritten)
        self.runtime.execute(
            "UPDATE recording_segments SET sha256=?, byte_length=? WHERE id IN "
            "(SELECT segment_id FROM recording_links WHERE recording_id=?)",
            (hashlib.sha256(rewritten).hexdigest(), len(rewritten), seeded["ordinary"]))
        code, report, _ = self.verify(baseline, "--declared-rewrite", seeded["ordinary"])
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["sections"]["recordings"]["declared_rewrites"],
                         [seeded["ordinary"]])

    def test_event_link_and_discontinuity_changes_are_detected(self):
        seeded = self.runtime.seed()
        event = str(uuid4())
        self.runtime.execute("UPDATE recordings SET event_id=? WHERE id=?",
                             (event, seeded["ordinary"]))
        self.runtime.execute("INSERT INTO recording_discontinuities VALUES (?, 2000, 3000, "
                             "'stream_discontinuity')", (seeded["starred"],))
        _, baseline = self.record()
        self.runtime.execute("UPDATE recordings SET event_id=? WHERE id=?",
                             (str(uuid4()), seeded["ordinary"]))
        self.runtime.execute("DELETE FROM recording_discontinuities WHERE recording_id=?",
                             (seeded["starred"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["recordings"]["failed"]
        for recording_id in (seeded["ordinary"], seeded["starred"]):
            self.assertIn({"id": recording_id, "reason": "changed"}, failed)

    def test_in_progress_discontinuities_may_grow_or_be_trimmed_outside_the_target(self):
        self.runtime.seed()

        def active(label: str) -> str:
            recording_id = self.runtime.recording(
                starred=False, payload=b"generated-" + label.encode(),
                status="active", target_end_ms=20000)
            self.runtime.execute(
                "INSERT INTO recording_discontinuities VALUES (?, 4000, 5000, 'stream_discontinuity')",
                (recording_id,))
            self.runtime.execute(
                "INSERT INTO recording_discontinuities VALUES (?, 16000, 17000, 'stream_discontinuity')",
                (recording_id,))
            return recording_id
        trimmed = active("trimmed")
        lost = active("lost")
        relinked = active("relinked")
        self.runtime.execute("UPDATE recordings SET event_id=? WHERE id=?", (str(uuid4()), relinked))
        _, baseline = self.record()
        # The store's stop path drops markers wholly outside the new target
        # and publishing may add new ones: valid growth.
        self.runtime.execute("UPDATE recordings SET target_end_ms=15000, ended_ms=15000, "
                             "status='complete' WHERE id=?", (trimmed,))
        self.runtime.execute("DELETE FROM recording_discontinuities WHERE recording_id=? "
                             "AND start_ms>=15000", (trimmed,))
        # Publishing a segment that does not continue the cursor adds
        # (prior cursor end, new segment start) for every linked recording.
        self.runtime.add_segment(trimmed, b"generated-trimmed-later", start_ms=11000,
                                 end_ms=15000, stream_id="s-restarted")
        self.runtime.execute(
            "INSERT INTO recording_discontinuities VALUES (?, 10000, 11000, 'stream_discontinuity')",
            (trimmed,))
        # A marker inside the window disappearing, or the event link moving,
        # is not growth.
        self.runtime.execute("DELETE FROM recording_discontinuities WHERE recording_id=? "
                             "AND start_ms=4000", (lost,))
        self.runtime.execute("UPDATE recordings SET event_id=? WHERE id=?", (str(uuid4()), relinked))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [trimmed])
        for recording_id in (lost, relinked):
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])

    def test_in_progress_appended_markers_must_match_a_published_segment(self):
        # RecordingStore._publish() only adds ('stream_discontinuity', cursor
        # end, new segment start) while linking a newly published segment that
        # does not continue the cursor's stream and sequence.
        self.runtime.seed()
        labels = ("published", "sequence-gap", "unanchored", "old-anchor", "reason",
                  "not-prior-end", "inverted", "duplicated", "contiguous")
        ids = {}
        for label in labels:
            ids[label] = self.runtime.recording(
                starred=False, payload=b"generated-" + label.encode(),
                status="active", target_end_ms=30000)
            self.runtime.add_segment(ids[label], b"generated-later-" + label.encode(),
                                     start_ms=12000, end_ms=20000, stream_id="t", sequence=7)
        with closing(sqlite3.connect(self.runtime.database)) as connection:
            recorded_start = connection.execute(
                "SELECT MAX(s.start_ms) FROM recording_segments s JOIN recording_links l "
                "ON l.segment_id=s.id WHERE l.recording_id=?", (ids["old-anchor"],)).fetchone()[0]
        _, baseline = self.record()
        for label, recording_id in ids.items():
            # A new stream unless the case is about sequence continuity.
            stream, sequence = {"sequence-gap": ("t", 9), "contiguous": ("t", 8)}.get(
                label, ("u", 0))
            self.runtime.add_segment(recording_id, b"generated-new-" + label.encode(),
                                     start_ms=22000, end_ms=26000, stream_id=stream,
                                     sequence=sequence)

        def marker(label: str, start: int, end: int,
                   reason: str = "stream_discontinuity") -> None:
            self.runtime.execute("INSERT INTO recording_discontinuities VALUES (?, ?, ?, ?)",
                                 (ids[label], start, end, reason))
        marker("published", 20000, 22000)
        marker("sequence-gap", 20000, 22000)
        marker("unanchored", 20000, 21000)              # no segment starts at 21000
        marker("old-anchor", 10000, recorded_start)     # anchors a recorded segment
        marker("reason", 20000, 22000, "operator_note")
        marker("not-prior-end", 15000, 22000)           # the cursor ended at 20000
        marker("inverted", 23000, 22000)
        marker("duplicated", 20000, 22000)
        marker("duplicated", 20000, 22000)              # one publication, one marker
        marker("contiguous", 20000, 22000)              # same stream, sequence + 1
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"],
                         sorted([ids["published"], ids["sequence-gap"]]))
        for label in labels[2:]:
            self.assertIn({"id": ids[label], "reason": "changed"}, section["failed"])

    def test_in_progress_growth_rejects_timeline_regressions(self):
        # RecordingStore.append() refuses RECORDING_TIMELINE_REGRESSION: a
        # segment starting before the cursor ends, or repeating / rewinding
        # the cursor's sequence on the same stream. Such growth is not valid,
        # with or without a marker.
        self.runtime.seed()
        # (An exact repeat is already refused by UNIQUE(source, stream, sequence).)
        labels = ("advances", "rewound", "rewound-marked", "overlaps", "earlier")
        ids = {}
        for label in labels:
            ids[label] = self.runtime.recording(
                starred=False, payload=b"generated-" + label.encode(),
                status="active", target_end_ms=30000)
            self.runtime.add_segment(ids[label], b"generated-later-" + label.encode(),
                                     start_ms=12000, end_ms=20000, stream_id="t", sequence=7)
        _, baseline = self.record()
        appended = {"advances": (22000, 26000, 8), "rewound": (20000, 26000, 6), "rewound-marked": (22000, 26000, 3),
                    "overlaps": (19000, 26000, 8), "earlier": (10000, 11000, 8)}
        for label, (start, end, sequence) in appended.items():
            self.runtime.add_segment(ids[label], b"generated-new-" + label.encode(),
                                     start_ms=start, end_ms=end, stream_id="t",
                                     sequence=sequence)
        self.runtime.execute(
            "INSERT INTO recording_discontinuities VALUES (?, 20000, 22000, "
            "'stream_discontinuity')", (ids["rewound-marked"],))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [ids["advances"]])
        for label in labels[1:]:
            self.assertIn({"id": ids[label], "reason": "changed"}, section["failed"])

    def test_in_progress_ended_boundary_is_status_specific(self):
        # finish() always ends complete / gapped rows at target_end_ms; only
        # startup recovery ends 'interrupted' rows at the latest linked media.
        self.runtime.seed()

        def active(label: str) -> str:
            return self.runtime.recording(starred=False, payload=b"generated-" + label.encode(),
                                          status="active", target_end_ms=20000)
        stopped = active("stopped")
        gapped = active("gapped")
        early_complete = active("early-complete")
        early_gapped = active("early-gapped")
        recovered = active("recovered")
        recovered_early = active("recovered-early")
        recovered_late = active("recovered-late")
        _, baseline = self.record()
        update = "UPDATE recordings SET status=?, target_end_ms=?, ended_ms=? WHERE id=?"
        self.runtime.execute(update, ("complete", 15000, 15000, stopped))
        self.runtime.execute(update, ("gapped", 20000, 20000, gapped))
        self.runtime.execute(update, ("complete", 20000, 1, early_complete))
        self.runtime.execute(update, ("gapped", 20000, 15000, early_gapped))
        # The recorded segment ends at 10000.
        self.runtime.execute(update, ("interrupted", 20000, 10000, recovered))
        self.runtime.execute(update, ("interrupted", 20000, 5000, recovered_early))
        self.runtime.execute(update, ("interrupted", 20000, 20000, recovered_late))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], sorted([stopped, gapped, recovered]))
        for recording_id in (early_complete, early_gapped, recovered_early, recovered_late):
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])

    def test_in_progress_segments_beyond_an_early_stop_may_be_trimmed(self):
        # Codex P1: RecordingStore.finish() closing an early stop deletes the
        # links to segments wholly outside the stopped window (and _trim()
        # then their unlinked rows and files); overlapping ones must remain.
        self.runtime.seed()
        labels = ("stopped", "overlapping", "still-active", "starred", "critical",
                  "not-shortened")
        ids, tails = {}, {}
        for label in labels:
            ids[label] = self.runtime.recording(
                starred=label == "starred", payload=b"generated-" + label.encode(),
                status="active", target_end_ms=30000)
            tails[label] = self.runtime.add_segment(
                ids[label], b"generated-tail-" + label.encode(), start_ms=12000, end_ms=20000)
        self.runtime.execute("UPDATE recordings SET critical=1 WHERE id=?", (ids["critical"],))
        _, baseline = self.record()
        stop = {"stopped": ("complete", 11000), "overlapping": ("complete", 15000),
                "still-active": ("active", 11000), "starred": ("complete", 11000),
                "critical": ("gapped", 11000), "not-shortened": ("complete", 30000)}
        for label, (status, end) in stop.items():
            self.runtime.execute(
                "UPDATE recordings SET status=?, target_end_ms=?, ended_ms=? WHERE id=?",
                (status, end, None if status == "active" else end, ids[label]))
            self.runtime.execute("DELETE FROM recording_links WHERE recording_id=? "
                                 "AND segment_id=?", (ids[label], tails[label]))
            self.runtime.execute("DELETE FROM recording_segments WHERE id=?", (tails[label],))
            (self.runtime.root / "recordings" / (UUID(tails[label]).hex + ".seg")).unlink()
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [ids["stopped"]])
        for label in labels[1:]:
            self.assertIn({"id": ids[label], "reason": "changed"}, section["failed"])

    def test_segments_already_corrupt_at_record_never_verify(self):
        # Codex P1: an unchanged recording whose segment already failed
        # RecordingStore._integrity() at record time (bytes or length differ
        # from the catalog, or an extra hard link) must not verify.
        seeded = self.runtime.seed()
        self.runtime.segment_path(seeded["ordinary"]).write_bytes(b"generated-altered-bytes!")
        os.link(self.runtime.segment_path(seeded["starred"]), self.notes / "extra-link")
        code, baseline = self.record()
        recorded = json.loads(baseline.read_text())["recordings"]
        for key in ("ordinary", "starred"):
            self.assertFalse(recorded[seeded[key]]["segments"][0]["catalog_match"])
        code, report, stdout = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        for key in ("ordinary", "starred"):
            self.assertIn({"id": seeded[key], "reason": "catalog_mismatch"}, section["failed"])
            self.assertNotIn(seeded[key], section["preserved"])

    def test_a_stop_never_launders_a_segment_corrupt_at_record(self):
        # Codex P1: the active-recording path must also refuse a recording
        # whose recorded segment already failed its catalog check, even when
        # a legitimate early stop then drops that segment.
        self.runtime.seed()
        active = self.runtime.recording(starred=False, payload=b"generated-active-corrupt",
                                        status="active", target_end_ms=30000)
        tail = self.runtime.add_segment(active, b"generated-tail-corrupt",
                                        start_ms=12000, end_ms=20000)
        path = self.runtime.root / "recordings" / (UUID(tail).hex + ".seg")
        path.write_bytes(b"generated-tail-altered")
        _, baseline = self.record()
        self.runtime.execute("UPDATE recordings SET status='complete', target_end_ms=11000, "
                             "ended_ms=11000 WHERE id=?", (active,))
        self.runtime.execute("DELETE FROM recording_links WHERE segment_id=?", (tail,))
        self.runtime.execute("DELETE FROM recording_segments WHERE id=?", (tail,))
        path.unlink()
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertIn({"id": active, "reason": "catalog_mismatch"}, section["failed"])
        self.assertNotIn(active, section["preserved"])
        self.assertEqual(section["in_progress_at_record"], [])

    def test_in_progress_growth_requires_segments_the_store_would_accept(self):
        # Codex P1: RecordingStore.append() runs Segment.validate(); a linked
        # segment it would refuse (here: no positive duration, over the
        # 20-minute ceiling, bad codec / container names, non-UUID stream or
        # capture node, a negative sequence, no bytes) is not valid growth.
        self.runtime.seed()
        cases = {
            "valid": {},
            "zero-duration": {"start_ms": 22000, "end_ms": 22000},
            "over-ceiling": {"start_ms": 22000, "end_ms": 22000 + 1_200_001},
            "codec": {"sql": "codec='Bad Codec'"},
            "container": {"sql": "container=''"},
            "stream": {"sql": "stream_id='not-a-uuid'"},
            "capture-node": {"sql": "capture_node_id='not-a-uuid'"},
            "sequence": {"sql": "sequence=-1"},
            "empty": {"payload": b""},
        }
        ids = {}
        for label, change in cases.items():
            ids[label] = self.runtime.recording(starred=False, payload=b"generated-" +
                                                label.encode(), status="active",
                                                target_end_ms=30000)
        _, baseline = self.record()
        for label, change in cases.items():
            segment = self.runtime.add_segment(
                ids[label], change.get("payload", b"generated-appended-" + label.encode()),
                start_ms=change.get("start_ms", 12000), end_ms=change.get("end_ms", 20000))
            if "sql" in change:
                self.runtime.execute(f"UPDATE recording_segments SET {change['sql']} WHERE id=?",
                                     (segment,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        self.assertEqual(section["in_progress_at_record"], [ids["valid"]])
        for label in list(cases)[1:]:
            self.assertIn({"id": ids[label], "reason": "changed"}, section["failed"], label)

    def test_extra_hard_link_to_a_segment_is_detected(self):
        # RecordingStore._integrity() treats st_nlink != 1 as corrupt.
        seeded = self.runtime.seed()
        active = self.runtime.recording(starred=False, payload=b"generated-active-link",
                                        status="active", target_end_ms=20000)
        _, baseline = self.record()
        os.link(self.runtime.segment_path(seeded["ordinary"]), self.notes / "extra-link")
        later = self.runtime.add_segment(active, b"generated-active-linked-later")
        os.link(self.runtime.root / "recordings" / (UUID(later).hex + ".seg"),
                self.notes / "extra-link-later")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        section = report["sections"]["recordings"]
        for recording_id in (seeded["ordinary"], active):
            self.assertIn({"id": recording_id, "reason": "changed"}, section["failed"])


if __name__ == "__main__":
    unittest.main()
