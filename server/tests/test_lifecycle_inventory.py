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
import ssl
import stat
from tempfile import TemporaryDirectory
import traceback
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


# Issue #136: stage_renewal() stores the issued certificate PEM, whose DER
# SHA-256 must be the staged credential serial digest. Synthetic DER bytes
# (never a real certificate) stand in for it.
_RENEWAL_CERTIFICATES: dict[str, bytes] = {}


def renewal_serial(tag) -> str:
    """A credential serial digest backed by a synthetic certificate PEM."""
    der = b"synthetic-renewal-certificate:" + str(tag).encode()
    serial = hashlib.sha256(der).hexdigest()
    _RENEWAL_CERTIFICATES[serial] = ssl.DER_cert_to_PEM_cert(der).encode("ascii")
    return serial


def renewal_certificate(serial: str) -> bytes:
    return _RENEWAL_CERTIFICATES[serial]


def stage_renewal(ledger, **kwargs):
    """PairingLedger.stage_renewal() with the certificate of ``credential_serial_digest``."""
    return ledger.stage_renewal(
        certificate_pem=renewal_certificate(kwargs["credential_serial_digest"]), **kwargs)


def presence_payload(identifier, at: str = "2026-01-01T00:00:00.000000+00:00") -> str:
    """A payload PresenceService.record() would store (Observation.payload())."""
    from app.presence.models import Kind as PresenceKind, Observation, Quality
    moment = datetime.fromisoformat(at)
    return json.dumps(Observation(PresenceKind.SERVER_MOVEMENT, moment, moment,
                                  source_id=UUID(int=1), confidence=0.9,
                                  quality=Quality.SUFFICIENT, clock_trusted=True, confirmed=True,
                                  identifier=UUID(str(identifier))).payload(), sort_keys=True)


def stream(label: str) -> str:
    """The stream UUID a synthetic stream label stands for (RecordingStore
    writes str(UUID) stream identities)."""
    return str(uuid5(EVENT_NAMESPACE, "synthetic-stream:" + label))


# An enrollment row as PairingLedger.approve() writes it (a lowercase hex
# code digest, a process-epoch UUID, a positive expiry); state appended.
ENROLLMENT_INSERT = ("INSERT INTO pairing_enrollments VALUES (?, ?, ?, '" + "f" * 64
                     + "', '00000000-0000-4000-8000-00000000e90c', 1, ")


class Runtime:
    """A disposable runtime tree: state/state.sqlite3 plus recordings/."""

    def __init__(self, base: Path, migrations=APPLICATION_MIGRATIONS):
        self.root = base / "runtime"
        for name in ("state", "recordings", "audit"):
            (self.root / name).mkdir(parents=True, mode=0o700)
        self.database = self.root / "state" / "state.sqlite3"
        with closing(Database(self.database).connect()) as connection:
            migrate(connection, migrations)
        # Synthetic audit times start a day before the wall clock, so the
        # service retention and future-time checks judge them as recent.
        self.clock = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()) * 1_000_000

    def execute(self, sql: str, parameters=()):
        with closing(sqlite3.connect(self.database, isolation_level=None)) as connection:
            connection.execute(sql, parameters)

    def recording(self, *, starred: bool, payload: bytes, status: str = "complete",
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
        self.sync_cursor(source_id)
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
        self.sync_cursor(source_id)
        self.execute("INSERT INTO recording_links VALUES (?, ?)", (recording_id, segment_id))
        return segment_id

    def sync_cursor(self, source_id: str) -> None:
        """Advance the source cursor as RecordingStore._publish() does: it
        names the latest published segment and never moves back."""
        self.execute(
            "INSERT INTO recording_source_cursors (source_id, stream_id, sequence, end_ms, "
            "capture_node_id, active) SELECT s.source_id, s.stream_id, "
            "(SELECT MAX(o.sequence) FROM recording_segments o WHERE o.source_id = s.source_id "
            "AND o.stream_id = s.stream_id), "
            "(SELECT MAX(o.end_ms) FROM recording_segments o WHERE o.source_id = s.source_id), "
            "NULL, 1 FROM recording_segments s WHERE s.source_id = ? "
            "ORDER BY s.end_ms DESC, s.sequence DESC LIMIT 1 "
            "ON CONFLICT(source_id) DO UPDATE SET stream_id = excluded.stream_id, "
            "sequence = excluded.sequence, end_ms = excluded.end_ms", (source_id,))

    def segment_file(self, segment_id: str, payload: bytes) -> None:
        path = self.root / "recordings" / (UUID(segment_id).hex + ".seg")
        path.write_bytes(payload)

    def segment_path(self, recording_id: str) -> Path:
        with closing(sqlite3.connect(self.database)) as connection:
            segment_id = connection.execute(
                "SELECT segment_id FROM recording_links WHERE recording_id=?",
                (recording_id,)).fetchone()[0]
        return self.root / "recordings" / (UUID(segment_id).hex + ".seg")

    def pairing_audit(self, node: str, *actions: str, outcome: str = "succeeded") -> None:
        """The security/admin audit rows PairingLedger writes with a change."""
        actors = {"approve": "owner", "revoke": "owner", "redeem": "capture_node",
                  "activate": "system"}
        names = {"approve": "approve_capture_node_enrollment",
                 "redeem": "redeem_capture_node_enrollment",
                 "activate": "activate_capture_node_credential",
                 "revoke": "revoke_capture_node_pairing"}
        for action in actions:
            self.execute(
                "INSERT INTO security_admin_audit_records VALUES (?, ?, ?, 'capture_node', ?, ?, ?)",
                (str(uuid4()), actors[action], names[action], str(node), self.clock, outcome))
            self.clock += 1_000_000

    def observation(self, identifier, received: str = "2026-01-01T00:00:00.000000+00:00") -> None:
        """A presence observation row as PresenceService.record() stores it."""
        payload = presence_payload(identifier, received)
        data = json.loads(payload)
        self.execute("INSERT INTO presence_observations (id, kind, source, received, payload) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (str(identifier), data["kind"], data["source_id"], data["received_at"],
                      payload))

    def audit(self) -> str:
        row_id = str(uuid4())
        self.execute(
            "INSERT INTO security_admin_audit_records VALUES (?, 'owner', 'update_source', "
            "'source', ?, ?, 'succeeded')", (row_id, str(uuid4()), self.clock))
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
        # Verify time for the service retention and future-time rules: the
        # wall clock (real ledger audit rows use it); tests move it explicitly.
        self.now = datetime.now(timezone.utc)
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

    def assert_record_refused(self, finding: str, *extra: str) -> None:
        """record writes nothing for a state an unchanged verify would fail."""
        target = self.notes / f"refused-{uuid4().hex}.json"
        code, _, stderr = run("record", "--runtime-root", str(self.runtime.root),
                              "--output", str(target), *extra)
        self.assertEqual(code, inventory.EXIT_FAILED, stderr)
        self.assertIn(finding, stderr)
        self.assertFalse(target.exists())

    def owner_template_root(self, *, template: bytes | None = None, at: str | None = None) -> Path:
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
                for operation in ("ENROLL", "REPLACE"):
                    connection.execute(
                        "INSERT INTO owner_template_audit(at, actor, operation, generation) "
                        "VALUES (?, 'owner', ?, 1)",
                        (at or (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                         operation))
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
                "'update_source', 'source', ?, ?, 'succeeded')",
                (audit_ids[label], str(uuid4()), occurred))
        for at in ((audit_cutoff - timedelta(seconds=1)).isoformat(),
                   (audit_cutoff + timedelta(seconds=1)).isoformat()):
            self.runtime.execute(
                "INSERT INTO integrity_audit(at, actor, revision) VALUES (?, '00000000-0000-4000-8000-0000000000aa', 1)", (at,))
        for at_ms in (audit_ms - 1, audit_ms):
            self.runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                                 "current_state) VALUES (?, 'NORMAL', 'STORAGE_PRESSURE')", (at_ms,))
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
            # finish() closes a recording at its target.
            self.runtime.execute("UPDATE recordings SET status=?, ended_ms=?, critical=?, "
                                 "target_end_ms=COALESCE(?, target_end_ms) WHERE id=?",
                                 (status, ended, int(critical), ended, recordings[label]))
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
        self.runtime.execute("UPDATE recordings SET status='complete', ended_ms=?, "
                             "target_end_ms=? WHERE id=?",
                             (now_ms - 21 * 86_400_000, now_ms - 21 * 86_400_000, expired))
        self.runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                             "current_state) VALUES (?, 'NORMAL', 'STORAGE_PRESSURE')",
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
        self.now = datetime.now(timezone.utc) + timedelta(days=400)
        for index, (table, section) in enumerate(cases.items()):
            with self.subTest(table):
                runtime = Runtime(self.base / f"dropped-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    runtime.execute("INSERT INTO integrity_audit(at, actor, revision) VALUES "
                                    "('2023-01-01T00:00:00+00:00', '00000000-0000-4000-8000-0000000000aa', 1)")
                    runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                                    "current_state) VALUES (1, 'NORMAL', 'STORAGE_PRESSURE')")
                    runtime.execute("UPDATE recordings SET status='complete', ended_ms=1, "
                                    "target_end_ms=1, starred=0")
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
                if table != "schema_migrations":   # the service needs its history
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
        # Recorded one release earlier, before the last migration existed;
        # the update's startup then applies it.
        self.runtime = Runtime(self.base / "one-release-earlier", APPLICATION_MIGRATIONS[:-1])
        self.runtime.seed()
        # record runs with the installed (earlier) release's own tool.
        with mock.patch.object(inventory, "APPLICATION_MIGRATIONS", APPLICATION_MIGRATIONS[:-1]):
            _, baseline = self.record()
        with closing(Database(self.runtime.database).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        last = [APPLICATION_MIGRATIONS[-1].version]
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
                runtime = Runtime(self.base / f"migrations-{index}", APPLICATION_MIGRATIONS[:-2])
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    tail = APPLICATION_MIGRATIONS[-2:]
                    values = {"v1": tail[0].version, "n1": tail[0].name, "c1": tail[0].checksum,
                              "v2": tail[1].version, "n2": tail[1].name, "c2": tail[1].checksum}
                    with mock.patch.object(inventory, "APPLICATION_MIGRATIONS",
                                           APPLICATION_MIGRATIONS[:-2]):
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

    def test_schema_must_match_the_applied_migrations(self):
        # Codex P1: every object the applied catalog creates must exist with
        # its definition, inventoried or not (the service needs them all). A
        # mismatch at record writes no baseline; at verify it is a failure.
        for index, statement in enumerate((
                "DROP TABLE access_sessions",                  # inventoried
                "DROP TABLE presence_inputs",                  # transient
                "DROP INDEX recording_event_id",               # an index
                "ALTER TABLE camera_sources ADD COLUMN drift TEXT")):  # drift
            with self.subTest(statement):
                runtime = Runtime(self.base / f"schema-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"schema-good-{index}.json")
                    runtime.execute(statement)
                    target = self.notes / f"schema-bad-{index}.json"
                    code, _, stderr = run("record", "--runtime-root", str(runtime.root),
                                          "--output", str(target))
                    self.assertEqual(code, inventory.EXIT_USAGE)
                    self.assertIn("schema does not match", stderr)
                    self.assertFalse(target.exists())
                    code, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertEqual(report["sections"]["tables"]["status"], "failed")
                self.assertTrue(any(item["reason"] in ("table_missing", "schema_changed")
                                    for item in report["sections"]["tables"]["failed"]))

    def test_presence_and_storage_audit_rows_are_preserved(self):
        self.runtime.seed()
        for index in range(3):
            self.runtime.execute(
                "INSERT INTO presence_audit (action, actor, at, state, target) "
                "VALUES ('override_set', '00000000-0000-4000-8000-0000000000aa', ?, 'away', NULL)",
                (f"2026-01-0{index + 1}T00:00:00.000000+00:00",))
            self.runtime.execute(
                "INSERT INTO storage_state_audit (at_ms, previous_state, current_state) "
                "VALUES (?, 'NORMAL', 'STORAGE_PRESSURE')",
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
        # Normal use advances the sign count: not a change. (Backup state may
        # flip only on a backup-eligible credential; the seeded one is not.)
        self.runtime.execute("UPDATE access_credentials SET sign_count=9")
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
        # The service cannot restore them: no baseline is written.
        self.assert_record_refused("camera_sources:unreadable_approval_evidence=5")

    def test_owner_template_store_with_unsafe_layout_is_never_preserved(self):
        # The store's own invariants: private root, 0600 single-link regular
        # database owned by the service account, never a symlink.
        self.runtime.seed()
        option = ("--owner-template-root", str(self.base / "owner-template"))
        root = self.owner_template_root(template=b"synthetic-owner-template-marker")
        database = root / "owner-template.sqlite3"

        good_baseline = {}

        def unsafe_verify(label):
            # An unsafe layout is never recorded, and from a safe record it
            # always fails verification.
            self.assert_record_refused("owner_template:unsafe=1", *option)
            code, report, _ = self.verify(good_baseline["path"], *option)
            self.assertEqual(code, inventory.EXIT_FAILED, label)
            self.assertIn({"id": "state", "reason": "unsafe"},
                          report["sections"]["owner_template"]["failed"], label)
        _, good_baseline["path"] = self.record("good.json", *option)
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

    def test_owner_template_audit_retention_is_honored(self):
        # Codex P1: when the store is registered for audit retention,
        # AuditRetentionRuntime.startup_cleanup() deletes its audit rows older
        # than OwnerTemplateStore's own retention before readiness.
        self.runtime.seed()
        option = ("--owner-template-root", str(self.base / "owner-template"))
        root = self.owner_template_root(template=b"synthetic-owner-template-marker",
                                        at=(self.now - timedelta(days=100)).isoformat())
        database = root / "owner-template.sqlite3"
        recent = (self.now - owner_store.DEFAULT_AUDIT_RETENTION
                  + timedelta(seconds=1)).isoformat()
        with closing(sqlite3.connect(database, isolation_level=None)) as connection:
            connection.execute("INSERT INTO owner_template_audit(at, actor, operation, generation) "
                               "VALUES (?, 'owner', 'REPLACE', 1)", (recent,))
        _, baseline = self.record("template.json", *option)
        with closing(sqlite3.connect(database, isolation_level=None)) as connection:
            connection.execute("DELETE FROM owner_template_audit WHERE at < ?", (recent,))
        code, report, _ = self.verify(baseline, *option)
        section = report["sections"]["owner_template"]
        self.assertEqual(code, inventory.EXIT_PRESERVED, section)
        self.assertEqual(len(section["audit"]["retention_expired"]), 2)
        with closing(sqlite3.connect(database, isolation_level=None)) as connection:
            connection.execute("DELETE FROM owner_template_audit")
        code, report, _ = self.verify(baseline, *option)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": "audit:3", "reason": "missing"},
                      report["sections"]["owner_template"]["failed"])

    def test_reused_audit_ids_after_retention_are_new_rows(self):
        # Codex P1: integrity_audit, storage_state_audit and owner_template_audit
        # use INTEGER PRIMARY KEY without AUTOINCREMENT, so once retention
        # removes the highest row its id is reused by the next one. That reads
        # as retention plus an appended row only when the recorded row was due
        # for removal and the new row was written after the record.
        recorded = self.now
        later = recorded + timedelta(hours=1)
        day = timedelta(days=1)
        cases = {   # label: (recorded row age in days, new row time)
            "reused": (91, later), "not-expired": (89, later),
            "older-than-record": (91, recorded - timedelta(hours=1))}
        for index, (label, (age, written)) in enumerate(cases.items()):
            for table in ("storage_state_audit", "integrity_audit", "owner_template_audit"):
                with self.subTest(label=label, table=table):
                    runtime = Runtime(self.base / f"reuse-{index}-{table}")
                    saved, saved_base = self.runtime, self.base
                    self.runtime, self.base = runtime, runtime.root.parent
                    # The store's ancestors must not be group-writable.
                    os.chmod(self.base, 0o700)
                    try:
                        runtime.seed()
                        extra = ()
                        if table == "owner_template_audit":
                            root = self.owner_template_root(template=b"synthetic-template")
                            target, extra = root / "owner-template.sqlite3", (
                                "--owner-template-root", str(root))
                        else:
                            target = runtime.database
                        old_at = recorded - age * day
                        with closing(sqlite3.connect(target, isolation_level=None)) as db:
                            if table == "storage_state_audit":
                                db.execute("INSERT INTO storage_state_audit (at_ms, "
                                           "previous_state, current_state) VALUES (?, 'NORMAL', "
                                           "'STORAGE_PRESSURE')", (int(old_at.timestamp() * 1000),))
                            elif table == "integrity_audit":
                                db.execute("INSERT INTO integrity_audit(at, actor, revision) "
                                           "VALUES (?, '00000000-0000-4000-8000-0000000000aa', 1)", (old_at.isoformat(),))
                            else:
                                db.execute("DELETE FROM owner_template_audit")
                                db.execute("INSERT INTO owner_template_audit(at, actor, "
                                           "operation, generation) VALUES (?, 'owner', "
                                           "'ENROLL', 1)", (old_at.isoformat(),))
                            row_id = db.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0]
                        self.now = recorded
                        _, baseline = self.record(f"reuse-{index}-{table}.json", *extra)
                        with closing(sqlite3.connect(target, isolation_level=None)) as db:
                            db.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
                            if table == "storage_state_audit":
                                db.execute("INSERT INTO storage_state_audit (at_ms, "
                                           "previous_state, current_state) VALUES (?, "
                                           "'STORAGE_PRESSURE', 'NORMAL')",
                                           (int(written.timestamp() * 1000),))
                            elif table == "integrity_audit":
                                db.execute("INSERT INTO integrity_audit(at, actor, revision) "
                                           "VALUES (?, '00000000-0000-4000-8000-0000000000aa', 2)", (written.isoformat(),))
                            else:
                                db.execute("INSERT INTO owner_template_audit(at, actor, "
                                           "operation, generation) VALUES (?, 'owner', "
                                           "'REPLACE', 1)", (written.isoformat(),))
                            self.assertEqual(db.execute(
                                f"SELECT MAX(id) FROM {table}").fetchone()[0], row_id)
                        self.now = later + timedelta(hours=1)
                        code, report, _ = self.verify(baseline, *extra)
                    finally:
                        self.runtime, self.base = saved, saved_base
                        self.now = recorded
                    name = {"storage_state_audit": "audit_storage_state",
                            "integrity_audit": "audit_integrity"}.get(table)
                    section = (report["sections"][name] if name
                               else report["sections"]["owner_template"]["audit"])
                    if label == "reused":
                        self.assertEqual(section["retention_expired"], [str(row_id)])
                        self.assertIn(str(row_id), section["appended"])
                        self.assertEqual(section["failed"], [])
                    else:
                        self.assertIn({"id": str(row_id), "reason": "changed"}, section["failed"])

    def test_reused_audit_ids_follow_the_rowid_allocator(self):
        # Codex P1: without AUTOINCREMENT a new row takes max(rowid) + 1, and
        # retention frees an id only once every row above it is gone. Reused
        # ids must be R+1..R+k above the highest remaining recorded id R,
        # written after the record, with times rising with the id.
        recorded = self.now
        def ms(moment):
            return int(moment.timestamp() * 1000)
        old, recent = recorded - timedelta(days=91), recorded - timedelta(days=10)
        first, second = recorded + timedelta(hours=1), recorded + timedelta(hours=2)
        cases = {   # label: (recorded rows {id: time}, rows after {id: time}, accepted)
            "rewritten-below-retained": ({1: old, 2: recent}, {1: first, 2: "keep"}, False),
            "retained-kept": ({1: old, 2: recent}, {2: "keep", 3: first}, True),
            "suffix-reuse": ({1: old, 2: old}, {1: first, 2: second}, True),
            "gap": ({1: old, 2: old}, {1: first, 3: second}, False),
            "out-of-order": ({1: old, 2: old}, {1: second, 2: first}, False),
        }
        for index, (label, (before, after, accepted)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"rowid-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    for row_id, moment in before.items():
                        runtime.execute("INSERT INTO storage_state_audit VALUES "
                                        "(?, ?, 'NORMAL', 'STORAGE_PRESSURE')", (row_id, ms(moment)))
                    self.now = recorded
                    _, baseline = self.record(f"rowid-{index}.json")
                    for row_id in before:
                        if after.get(row_id) != "keep":
                            runtime.execute("DELETE FROM storage_state_audit WHERE id=?",
                                            (row_id,))
                    for row_id, moment in after.items():
                        if moment != "keep":
                            runtime.execute("INSERT INTO storage_state_audit VALUES "
                                            "(?, ?, 'STORAGE_PRESSURE', 'NORMAL')", (row_id, ms(moment)))
                    self.now = recorded + timedelta(hours=3)
                    _, report, _ = self.verify(baseline)
                finally:
                    self.runtime, self.now = saved, recorded
                section = report["sections"]["audit_storage_state"]
                self.assertEqual(section["status"] == "preserved", accepted, section)

    def test_real_service_retention_and_release_verify_as_preserved(self):
        # Guards the mirrored rules against drift: the real service functions
        # run with the verify time, then verify lists exactly what they
        # removed and keeps what they left (rows at or just inside a cutoff).
        from contextlib import nullcontext
        import zlib
        from app.media.recording import RecordingStore, RootIdentity, Segment
        from app.media.recording.model import Limits
        from app.storage.retention import RetentionService, StorageAudit
        from tests.test_recording import Reservation, SyntheticValidator
        seeded = self.runtime.seed()
        now = self.now
        now_ms = int(now.timestamp() * 1000)
        day_ms = 86_400_000
        # Recordings: ended well past 20 days, exactly at the cutoff (deleted:
        # ended_ms <= cutoff) and one millisecond inside it (kept).
        media = self.runtime.root / "recordings"
        info = media.stat()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        store = RecordingStore(connection, media, RootIdentity(info.st_dev, info.st_ino),
                               Limits(pre_roll_bytes=4096, max_segment_bytes=512,
                                      max_segment_ms=30_000, max_active_recordings=8,
                                      max_spool_segments=16, max_segments_per_recording=100),
                               Reservation(), SyntheticValidator())
        made = {}
        for label, ended in (("old", now_ms - 30 * day_ms), ("at-cutoff", now_ms - 20 * day_ms),
                             ("inside", now_ms - 20 * day_ms + 1)):
            source = uuid4()
            recording = store.start_manual(source, ended - 1000, duration_ms=1000)
            store.append(Segment(source, uuid4(), 0, ended - 1000, ended, "synthetic", "deflate",
                                 zlib.compress(b"generated geometric test payload" * 4)))
            store.finish(recording)
            store.release_source(source)
            made[label] = str(recording)
        # Audit rows: past the 90-day cutoff, exactly at it (kept: '<'), inside.
        audit_cutoff = now - timedelta(days=90)
        cutoff_us = int(audit_cutoff.timestamp()) * 1_000_000 + audit_cutoff.microsecond
        admin = {}
        for label, occurred in (("old", cutoff_us - 1), ("at-cutoff", cutoff_us)):
            admin[label] = str(uuid4())
            self.runtime.execute(
                "INSERT INTO security_admin_audit_records VALUES (?, 'owner', "
                "'update_source', 'source', ?, ?, 'succeeded')",
                (admin[label], str(uuid4()), occurred))
        for at in ((audit_cutoff - timedelta(seconds=1)).isoformat(), audit_cutoff.isoformat()):
            self.runtime.execute("INSERT INTO integrity_audit(at, actor, revision) "
                                 "VALUES (?, '00000000-0000-4000-8000-0000000000aa', 1)", (at,))
        for at_ms in (now_ms - 90 * day_ms - 1, now_ms - 90 * day_ms):
            self.runtime.execute("INSERT INTO storage_state_audit (at_ms, previous_state, "
                                 "current_state) VALUES (?, 'NORMAL', 'STORAGE_PRESSURE')", (at_ms,))
        root = self.owner_template_root(template=b"synthetic-owner-template-marker")
        with closing(sqlite3.connect(root / "owner-template.sqlite3",
                                     isolation_level=None)) as template_db:
            template_db.execute("DELETE FROM owner_template_audit")
            for at in ((audit_cutoff - timedelta(seconds=1)).isoformat(),
                       audit_cutoff.isoformat()):
                template_db.execute("INSERT INTO owner_template_audit(at, actor, operation, "
                                    "generation) VALUES (?, 'owner', 'ENROLL', 1)", (at,))
        # An unresolved critical observation the Owner releases.
        released = uuid4()
        self.runtime.observation(released,
                                 (now - timedelta(days=1)).isoformat(timespec="microseconds"))
        self.runtime.execute("INSERT INTO presence_deliveries (observation, action, state, "
                             "attempts) VALUES (?, 'notification', 'pending', 0)",
                             (str(released),))
        option = ("--owner-template-root", str(root))
        _, baseline = self.record("real.json", *option)
        # The real service paths, at the verify time.
        # The seeded ordinary recording ended long ago and goes too.
        self.assertEqual(RetentionService(store).expired(now_ms, 100), 3)
        store.close()
        connection.close()
        AuditStore(Database(self.runtime.database)).cleanup_expired(now=now)
        with closing(sqlite3.connect(self.runtime.database, isolation_level=None)) as db:
            StorageAudit(db, reservation=nullcontext).expire(now_ms)
        template = owner_store.OwnerTemplateStore(root, max_template_bytes=1024,
                                                  reservation=nullcontext)
        try:
            template.cleanup_expired_batch(now=now)
        finally:
            template.close()

        class Owner:
            def require_owner(self, context):
                return UUID(seeded["owner"])
        PresenceService(Database(self.runtime.database), access=Owner(),
                        reservation=nullcontext).clear_unresolved_critical_event(
            "owner", released, now=now, clock_trusted=True)
        code, report, _ = self.verify(baseline, *option)
        sections = report["sections"]
        self.assertEqual(code, inventory.EXIT_PRESERVED, json.dumps(sections, indent=1)[:2000])
        self.assertEqual(sections["recordings"]["retention_expired"],
                         sorted([made["old"], made["at-cutoff"], seeded["ordinary"]]))
        self.assertIn(made["inside"], sections["recordings"]["preserved"])
        self.assertEqual(sections["audit_security_admin"]["retention_expired"], [admin["old"]])
        for name in ("audit_integrity", "audit_storage_state"):
            self.assertEqual(len(sections[name]["retention_expired"]), 1, name)
        self.assertEqual(len(sections["owner_template"]["audit"]["retention_expired"]), 1)
        self.assertEqual(sections["presence"]["released"], [str(released)])

    def test_owner_template_audit_retention_needs_the_store_utc_format(self):
        # Codex P1: an Owner-template audit time at another offset whose text
        # sorts before the cutoff, though its instant is after it, is not due.
        self.runtime.seed()
        option = ("--owner-template-root", str(self.base / "owner-template"))
        root = self.owner_template_root(template=b"synthetic-owner-template-marker")
        with closing(sqlite3.connect(root / "owner-template.sqlite3",
                                     isolation_level=None)) as db:
            db.execute("DELETE FROM owner_template_audit")
            db.execute("INSERT INTO owner_template_audit(at, actor, operation, generation) "
                       "VALUES ('2023-08-17T20:00:00-05:00', 'owner', 'ENROLL', 1)")
        # Not a time the store writes: no baseline is written at all, so its
        # removal can never read as retention.
        self.assert_record_refused("owner_template:invalid_time=1", *option)

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
        # With the hidden link already present, no baseline is written.
        self.assert_record_refused("recordings:no_readable_segment_evidence")

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
            "lost, interrupted) VALUES (1, '2026-01-01T00:00:00.000000+00:00', "
            "'2026-01-01T00:01:00.000000+00:00', 1, 0, 2, 0)")
        code, report, _ = self.verify(closed)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.assertEqual(report["sections"]["presence_timeline_gap"]["appended"], ["gap"])
        _, baseline = self.record()
        self.runtime.execute("UPDATE presence_timeline_gap SET lost=3, "
                             "latest='2026-01-01T00:02:00.000000+00:00'")
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
            self.runtime.observation(ids[name])
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
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        # Events rise only with an Owner release of unresolved work.
        self.runtime.execute("UPDATE presence_expired_unresolved SET events=3")
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": "expired_unresolved:evidence", "reason": "unexplained"},
                      report["sections"]["presence"]["failed"])
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

    def owner_clear(self, owner: str, identifier: str, at: str) -> None:
        """The rows clear_unresolved_critical_event() writes besides deletions."""
        self.runtime.execute("INSERT INTO presence_audit (action, actor, at, state, target) "
                             "VALUES ('critical_event_cleared', ?, ?, NULL, ?)",
                             (owner, at, identifier))
        self.runtime.execute("INSERT INTO presence_control_clock VALUES (1, ?) ON CONFLICT"
                             "(singleton) DO UPDATE SET latest=excluded.latest", (at,))

    def test_presence_observations_leave_only_through_a_tombstone(self):
        seeded = self.runtime.seed()
        ids = self.presence_rows()
        _, baseline = self.record()
        # The Owner release: observation, jobs and fact go, the tombstone
        # appears and the undelivered job adds an expired-unresolved event.
        at = "2026-02-01T00:00:00.000000+00:00"
        for table, column in (("presence_deliveries", "observation"),
                              ("presence_observations", "id"), ("presence_source_facts", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["expired"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                             (ids["expired"], at))
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, "
                             "?)", (at,))
        self.owner_clear(seeded["owner"], ids["expired"], at)
        # A claim (one attempt, one generation) and its delivered outcome.
        self.runtime.execute("UPDATE presence_deliveries SET state='delivered', "
                             "attempts=attempts+1, generation=generation+1 "
                             "WHERE observation=?", (ids["kept"],))
        code, report, stdout = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        self.assertEqual(report["sections"]["presence"]["released"], [ids["expired"]])
        self.assertIn("released=1", stdout)
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
        seeded = self.runtime.seed()
        ids = self.presence_rows()
        self.runtime.execute("UPDATE presence_deliveries SET state='failed', attempts=1, "
                             "generation=1 WHERE observation=?", (ids["lost"],))
        _, baseline = self.record()
        for table, column in (("presence_deliveries", "observation"),
                              ("presence_observations", "id"), ("presence_source_facts", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["lost"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, "
                             "'2026-02-01T00:00:00.000000+00:00')", (ids["lost"],))
        self.owner_clear(seeded["owner"], ids["lost"], "2026-02-01T00:00:00.000000+00:00")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": "expired_unresolved:notification", "reason": "unexplained"},
                      report["sections"]["presence"]["failed"])
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, "
                             "'2026-02-01T00:00:00.000000+00:00')")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])

    def test_observation_removal_needs_an_owner_clear(self):
        # Main removes an observation (with its jobs and source fact) only in
        # the audited clear_unresolved_critical_event(); expire_history() is
        # not run by Main, so even an old, resolved observation removed as it
        # would remove it is a loss, as is a forged tombstone and marker.
        seeded = self.runtime.seed()
        now = self.now
        fresh = (now - timedelta(days=1)).isoformat(timespec="microseconds")
        old = (now - timedelta(days=21)).isoformat(timespec="microseconds")
        cases = {"forged": (fresh, "failed"), "cleared": (fresh, "failed"),
                 "expired-resolved": (old, "delivered"), "expired-unresolved": (old, "failed"),
                 "expired-plain": (old, None)}
        ids = {}
        for label, (received, state) in cases.items():
            ids[label] = str(uuid4())
            self.runtime.observation(ids[label], received)
            self.runtime.execute("INSERT INTO presence_source_facts (id, digest) VALUES (?, ?)",
                                 (ids[label], hashlib.sha256(label.encode()).hexdigest()))
            if state is not None:
                self.runtime.execute(
                    "INSERT INTO presence_deliveries (observation, action, state, attempts, "
                    "generation) VALUES (?, 'notification', ?, 1, 1)", (ids[label], state))
        _, baseline = self.record()
        at = now.isoformat(timespec="microseconds")
        unresolved = 0
        for label, (_, state) in cases.items():
            for table, column in (("presence_deliveries", "observation"),
                                  ("presence_observations", "id"),
                                  ("presence_source_facts", "id")):
                self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids[label],))
            if state is not None:
                self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                                     (ids[label], at))
                unresolved += state != "delivered"
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', ?, ?)",
                             (unresolved, at))
        # The Owner's clear: audited with the Owner identity, control clock advanced.
        self.runtime.execute("INSERT INTO presence_audit (action, actor, at, state, target) "
                             "VALUES ('critical_event_cleared', ?, ?, NULL, ?)",
                             (seeded["owner"], at, ids["cleared"]))
        self.runtime.execute("INSERT INTO presence_control_clock VALUES (1, ?)", (at,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        for label in ("forged", "expired-unresolved", "expired-resolved", "expired-plain"):
            self.assertIn({"id": f"observations:{ids[label]}", "reason": "missing"}, failed)
        self.assertNotIn({"id": f"observations:{ids['cleared']}", "reason": "missing"}, failed)
        self.assertEqual(report["sections"]["presence"]["released"], [ids["cleared"]])

    def test_owner_clear_mirrors_the_service_exactly(self):
        # clear_unresolved_critical_event(): needs a job neither delivered nor
        # disabled (Codex P1); writes the tombstone at the audit row's time,
        # a NULL audit state, and one expired-unresolved event per such job
        # (a disabled job adds none).
        seeded = self.runtime.seed()
        fresh = (self.now - timedelta(days=1)).isoformat(timespec="microseconds")
        at = self.now.isoformat(timespec="microseconds")
        owner, stranger = seeded["owner"], seeded["live"]
        cases = {"resolved": (("delivered", "delivered"), at, None, owner),
                 "late-tombstone": (("failed", "delivered"), "2099-01-01T00:00:00.000000+00:00",
                                    None, owner),
                 "audit-state": (("failed", "delivered"), at, "away", owner),
                 # Codex P1: an actor that is not an Owner.
                 "not-owner": (("failed", "delivered"), at, None, stranger),
                 "disabled-and-failed": (("disabled", "failed"), at, None, owner)}
        ids = {}
        for label, ((evidence, notification), _, _, _) in cases.items():
            ids[label] = str(uuid4())
            self.runtime.observation(ids[label], fresh)
            for action, state in (("evidence", evidence), ("notification", notification)):
                self.runtime.execute(
                    "INSERT INTO presence_deliveries (observation, action, state, attempts, "
                    "generation) VALUES (?, ?, ?, 1, 1)", (ids[label], action, state))
        _, baseline = self.record()
        notification_events = 0
        for label, ((evidence, notification), tombstone, state, actor) in cases.items():
            for table, column in (("presence_deliveries", "observation"),
                                  ("presence_observations", "id")):
                self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids[label],))
            self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                                 (ids[label], tombstone))
            self.runtime.execute("INSERT INTO presence_audit (action, actor, at, state, target) "
                                 "VALUES ('critical_event_cleared', ?, ?, ?, ?)",
                                 (actor, at, state, ids[label]))
            notification_events += notification not in ("delivered", "disabled")
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', ?, ?)",
                             (notification_events, at))
        # Codex P1: the clear advanced the control clock to its own time; a
        # clock behind it means the clear never ran as recorded.
        self.runtime.execute("INSERT INTO presence_control_clock VALUES (1, ?)", (fresh,))
        code, report, _ = self.verify(baseline)
        failed = report["sections"]["presence"]["failed"]
        self.assertIn({"id": f"observations:{ids['disabled-and-failed']}", "reason": "missing"},
                      failed)
        self.runtime.execute("UPDATE presence_control_clock SET latest=?", (at,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        for label in ("resolved", "late-tombstone", "audit-state", "not-owner"):
            self.assertIn({"id": f"observations:{ids[label]}", "reason": "missing"}, failed)
        self.assertEqual([item for item in failed if ids["disabled-and-failed"] in item["id"]], [])

    def test_jobs_tombstones_and_markers_change_only_with_a_release(self):
        # Codex P1: with timeline expiry not run by Main, a job leaves only
        # with its released observation, and tombstones / expired-unresolved
        # events appear only for released observations.
        self.runtime.seed()
        ids = self.presence_rows()
        _, baseline = self.record()
        at = "2026-02-01T00:00:00.000000+00:00"
        # Only the pending job of a kept observation, dressed as a release.
        self.runtime.execute("DELETE FROM presence_deliveries WHERE observation=?", (ids["kept"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                             (ids["kept"], at))
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, ?)",
                             (at,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        for item in ({"id": f"deliveries:{ids['kept']}:notification", "reason": "missing"},
                     {"id": f"completed_events:{ids['kept']}", "reason": "unexplained"},
                     {"id": "expired_unresolved:notification", "reason": "unexplained"}):
            self.assertIn(item, failed)

    def test_a_release_removes_every_job_and_no_job_is_orphaned(self):
        # Codex P1: clear_unresolved_critical_event() deletes all jobs of the
        # released observation at once; a kept job would be stranded, and no
        # job may point at an observation that is gone.
        seeded = self.runtime.seed()
        ids = self.presence_rows()
        self.runtime.execute("INSERT INTO presence_deliveries (observation, action, state, "
                             "attempts) VALUES (?, 'evidence', 'pending', 0)", (ids["expired"],))
        _, baseline = self.record()
        at = "2026-02-01T00:00:00.000000+00:00"
        # Released, but its evidence job stays.
        self.runtime.execute("DELETE FROM presence_deliveries WHERE observation=? "
                             "AND action='notification'", (ids["expired"],))
        for table, column in (("presence_observations", "id"), ("presence_source_facts", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["expired"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                             (ids["expired"], at))
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, "
                             "?)", (at,))
        self.owner_clear(seeded["owner"], ids["expired"], at)
        # A new job for an observation that does not exist.
        ghost = str(uuid4())
        self.runtime.execute("INSERT INTO presence_deliveries (observation, action, state, "
                             "attempts) VALUES (?, 'notification', 'pending', 0)", (ghost,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        self.assertIn({"id": f"deliveries:{ids['expired']}:evidence", "reason": "retained"},
                      failed)
        self.assertIn({"id": f"deliveries:{ghost}:notification", "reason": "orphaned"}, failed)

    def test_released_and_orphaned_source_facts_fail(self):
        # Codex P2: a source fact is written with its observation and deleted
        # with it, including by the Owner release.
        seeded = self.runtime.seed()
        ids = self.presence_rows()
        _, baseline = self.record()
        at = "2026-02-01T00:00:00.000000+00:00"
        for table, column in (("presence_deliveries", "observation"),
                              ("presence_observations", "id")):
            self.runtime.execute(f"DELETE FROM {table} WHERE {column}=?", (ids["expired"],))
        self.runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                             (ids["expired"], at))
        self.runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('notification', 1, "
                             "?)", (at,))
        self.owner_clear(seeded["owner"], ids["expired"], at)
        ghost = str(uuid4())
        self.runtime.execute("INSERT INTO presence_source_facts (id, digest) VALUES (?, ?)",
                             (ghost, "0" * 64))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        failed = report["sections"]["presence"]["failed"]
        self.assertIn({"id": f"source_facts:{ids['expired']}", "reason": "retained"}, failed)
        self.assertIn({"id": f"source_facts:{ghost}", "reason": "orphaned"}, failed)

    def test_an_observation_created_and_released_inside_the_window(self):
        # Claude review: an observation recorded after the baseline and then
        # released by the real clear_unresolved_critical_event() is accepted
        # and listed; its events are bounded (at least one per release, at
        # most one per action), since its jobs were never recorded.
        from contextlib import nullcontext
        seeded = self.runtime.seed()
        _, baseline = self.record()
        late = uuid4()
        self.runtime.observation(late, self.now.isoformat(timespec="microseconds"))
        for action, state in (("evidence", "delivered"), ("notification", "pending")):
            self.runtime.execute("INSERT INTO presence_deliveries (observation, action, state, "
                                 "attempts) VALUES (?, ?, ?, 0)", (str(late), action, state))

        class Owner:
            def require_owner(self, context):
                return UUID(seeded["owner"])
        PresenceService(Database(self.runtime.database), access=Owner(),
                        reservation=nullcontext).clear_unresolved_critical_event(
            "owner", late, now=self.now, clock_trusted=True)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["presence"])
        self.assertEqual(report["sections"]["presence"]["released"], [str(late)])
        # More events than its actions allow, or none at all, is not a release.
        self.runtime.execute("UPDATE presence_expired_unresolved SET events=events+1 "
                             "WHERE action='notification'")
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": "expired_unresolved:notification", "reason": "unexplained"},
                      report["sections"]["presence"]["failed"])
        self.runtime.execute("DELETE FROM presence_expired_unresolved")
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": "expired_unresolved", "reason": "unexplained"},
                      report["sections"]["presence"]["failed"])

    def test_evidence_times_must_use_the_services_utc_format(self):
        # Codex P1: times are compared as instants and must be written exactly
        # as the service writes them; a non-UTC offset whose text sorts the
        # other way is never accepted (each case would pass a text comparison).
        z = "2026-01-01T10:00:00.000000+00:00"
        later_text_earlier_instant = "2026-01-01T12:00:00.000000+09:00"   # 03:00Z
        cases = {}

        def case(name):
            def register(function):
                cases[name] = function
                return function
            return register

        @case("presence clock")
        def _(runtime, seeded, phase):
            if phase == "before":
                runtime.execute("INSERT INTO presence_clock VALUES (1, ?)", (z,))
            else:
                runtime.execute("UPDATE presence_clock SET latest=?", (later_text_earlier_instant,))
            return "presence", {"id": "clocks:observation", "reason": "changed"}

        @case("override expiry")
        def _(runtime, seeded, phase):
            if phase == "before":
                runtime.execute("INSERT INTO presence_control_clock VALUES (1, ?)",
                                ("2026-01-01T00:00:00.000000+00:00",))
                runtime.execute("INSERT INTO presence_override VALUES (1, 'ABSENT', '00000000-0000-4000-8000-0000000000aa', ?, ?)",
                                ("2026-01-01T00:00:00.000000+00:00",
                                 "2026-01-01T00:30:00.000000+00:00"))
            else:
                runtime.execute("DELETE FROM presence_override")
                runtime.execute("UPDATE presence_control_clock SET latest=?",
                                ("2026-01-01T09:00:00.000000+09:00",))   # 00:00Z
            return "presence", {"id": "override:owner", "reason": "changed"}

        @case("timeline gap")
        def _(runtime, seeded, phase):
            if phase == "before":
                runtime.execute("INSERT INTO presence_timeline_gap VALUES (1, ?, ?, 1, 0, 0, 0)",
                                (z, z))
            else:
                runtime.execute("UPDATE presence_timeline_gap SET latest=?",
                                (later_text_earlier_instant,))
            return "presence_timeline_gap", {"id": "gap", "reason": "invalid_time"}

        @case("integrity audit time")
        def _(runtime, seeded, phase):
            # A row at another offset is not a time the store writes (it is
            # never recorded: record refuses such a state).
            if phase == "after":
                runtime.execute("INSERT INTO integrity_audit(at, actor, revision) VALUES "
                                "('2023-08-17T20:00:00-05:00', "
                                "'00000000-0000-4000-8000-0000000000aa', 1)")
            return "audit_integrity", {"id": "1", "reason": "invalid_time"}

        @case("owner clear time")
        def _(runtime, seeded, phase):
            if phase == "before":
                runtime.observation("00000000-0000-4000-8000-000000000001", z)
                runtime.execute("INSERT INTO presence_deliveries (observation, action, state, "
                                "attempts) VALUES ('00000000-0000-4000-8000-000000000001', "
                                "'notification', 'pending', 0)")
            else:
                at = "2026-01-02T09:00:00.000000+09:00"   # the clear, at a +09:00 offset
                for table, column in (("presence_deliveries", "observation"),
                                      ("presence_observations", "id")):
                    runtime.execute(f"DELETE FROM {table} WHERE {column}=?",
                                    ("00000000-0000-4000-8000-000000000001",))
                runtime.execute("INSERT INTO presence_completed_events VALUES (?, ?)",
                                ("00000000-0000-4000-8000-000000000001", at))
                runtime.execute("INSERT INTO presence_expired_unresolved VALUES "
                                "('notification', 1, ?)", (at,))
                runtime.execute("INSERT INTO presence_audit (action, actor, at, state, target) "
                                "VALUES ('critical_event_cleared', ?, ?, NULL, ?)",
                                (seeded["owner"], at, "00000000-0000-4000-8000-000000000001"))
                runtime.execute("INSERT INTO presence_control_clock VALUES (1, ?)", (at,))
            return "presence", {"id": "observations:00000000-0000-4000-8000-000000000001",
                                "reason": "missing"}

        @case("unknown delivery action")
        def _(runtime, seeded, phase):
            if phase == "after":
                runtime.execute("INSERT INTO presence_expired_unresolved VALUES ('bogus', 1, ?)",
                                (z,))
            return "presence", {"id": "expired_unresolved:bogus", "reason": "unknown_action"}

        for index, (label, function) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"times-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    seeded = runtime.seed()
                    function(runtime, seeded, "before")
                    _, baseline = self.record(f"times-{index}.json")
                    section, expected = function(runtime, seeded, "after")
                    _, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                self.assertIn(expected, report["sections"][section]["failed"])

    def test_every_current_service_time_is_well_formed(self):
        # Codex P1: a time the service compares again must be in its format
        # even when the row is new since the record (an unparsable control
        # clock would block every Owner control operation).
        cases = {
            "control clock": ("INSERT INTO presence_control_clock VALUES (1, 'not-a-service-time')",
                              "presence", {"id": "clocks:control", "reason": "invalid_time"}),
            "source clock": ("INSERT INTO presence_source_clock VALUES ('s', "
                             "'2026-01-01T09:00:00.000000+09:00')",
                             "presence", {"id": "clocks:source:s", "reason": "invalid_time"}),
            "tombstone": ("INSERT INTO presence_completed_events VALUES ("
                          "'00000000-0000-4000-8000-000000000009', 'yesterday')",
                          "presence", {"id": "completed_events:"
                                             "00000000-0000-4000-8000-000000000009",
                                       "reason": "invalid_time"}),
            "override": ("INSERT INTO presence_override VALUES (1, 'ABSENT', 'owner', 'now', NULL)",
                         "presence", {"id": "override:owner", "reason": "invalid_time"}),
            "timeline gap": ("INSERT INTO presence_timeline_gap VALUES (1, 'x', 'y', 1, 0, 0, 0)",
                             "presence_timeline_gap", {"id": "gap", "reason": "invalid_time"}),
            "integrity outbox": ("INSERT INTO integrity_outbox(at, immediate, findings) "
                                 "VALUES ('soon', 1, '[]')",
                                 "integrity_delivery", {"id": "pending:1",
                                                        "reason": "invalid_time"}),
        }
        for index, (label, (statement, section, expected)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"well-formed-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"well-formed-{index}.json")
                    runtime.execute(statement)
                    code, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn(expected, report["sections"][section]["failed"])

    def test_no_service_time_lies_beyond_the_verify_time(self):
        # Codex P1: a well-formed but far-future time would refuse every later
        # operation (a control clock in 9999 locks out Owner control); times
        # may exceed the verify time only by the clock-skew allowance.
        far = "9999-01-01T00:00:00.000000+00:00"
        skewed = (self.now + inventory.CLOCK_SKEW_ALLOWANCE
                  - timedelta(seconds=30)).isoformat(timespec="microseconds")
        future_us = int((self.now + timedelta(days=1)).timestamp()) * 1_000_000
        cases = {
            "control clock": ("INSERT INTO presence_control_clock VALUES (1, ?)", (far,),
                              "presence", "clocks:control"),
            "within the allowance": ("INSERT INTO presence_control_clock VALUES (1, ?)",
                                     (skewed,), "presence", None),
            "clear row": ("INSERT INTO presence_audit (action, actor, at, state, target) VALUES "
                          "('critical_event_cleared', '00000000-0000-4000-8000-000000000001', ?, "
                          "NULL, '00000000-0000-4000-8000-000000000002')", (far,),
                          "presence", "cleared_events:00000000-0000-4000-8000-000000000002"),
            "integrity outbox": ("INSERT INTO integrity_outbox(at, immediate, findings) "
                                 "VALUES (?, 1, '[]')", ("9999-01-01T00:00:00+00:00",),
                                 "integrity_delivery", "pending:1"),
            "security audit": ("INSERT INTO security_admin_audit_records VALUES (?, 'owner', "
                               "'update_source', 'source', ?, ?, 'succeeded')",
                               ("00000000-0000-4000-8000-000000000003",
                                "00000000-0000-4000-8000-000000000004", future_us),
                               "audit_security_admin", "00000000-0000-4000-8000-000000000003"),
        }
        for index, (label, (statement, values, section, item)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"future-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"future-{index}.json")
                    runtime.execute(statement, values)
                    _, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                futures = [entry for entry in report["sections"][section].get("failed", [])
                           if entry["reason"] == "future_time"]
                self.assertEqual(futures, [] if item is None
                                 else [{"id": item, "reason": "future_time"}])

    def test_malformed_audit_times_are_reported_not_fatal(self):
        # Codex P1: a time that does not parse, has the wrong SQLite type or
        # is out of range is an invalid_time finding; verify always reports.
        values = {"malformed text": "not-a-time", "wrong type": 5.5,
                  "max int": 9223372036854775807, "negative int": -1}
        inserts = {
            "audit_security_admin": "INSERT INTO security_admin_audit_records VALUES (?, 'owner', "
                                    "'update_source', 'source', ?, ?, 'succeeded')",
            "audit_integrity": "INSERT INTO integrity_audit(id, at, actor, revision) "
                               "VALUES (?, ?, '00000000-0000-4000-8000-0000000000aa', 1)",
            "audit_storage_state": "INSERT INTO storage_state_audit (id, at_ms, previous_state, "
                                   "current_state) VALUES (?, ?, 'NORMAL', 'STORAGE_PRESSURE')",
            "owner_template": "INSERT INTO owner_template_audit(id, at, actor, operation, "
                              "generation) VALUES (?, ?, 'owner', 'ENROLL', 1)",
        }
        index = 0
        for section, statement in inserts.items():
            for label, value in values.items():
                index += 1
                with self.subTest(section=section, value=label):
                    runtime = Runtime(self.base / f"bad-time-{index}")
                    saved, saved_base = self.runtime, self.base
                    self.runtime, self.base = runtime, runtime.root.parent
                    os.chmod(self.base, 0o700)
                    try:
                        runtime.seed()
                        extra, target, row_id = (), runtime.database, 900
                        if section == "owner_template":
                            root = self.owner_template_root(template=b"synthetic-template")
                            extra = ("--owner-template-root", str(root))
                            target = root / "owner-template.sqlite3"
                        _, baseline = self.record(f"bad-time-{index}.json", *extra)
                        with closing(sqlite3.connect(target, isolation_level=None)) as db:
                            if section == "audit_security_admin":
                                row_id = "00000000-0000-4000-8000-000000000099"
                                db.execute(statement, (row_id, str(uuid4()), value))
                            else:
                                db.execute(statement, (row_id, value))
                        code, report, _ = self.verify(baseline, *extra)
                    finally:
                        self.runtime, self.base = saved, saved_base
                    self.assertEqual(code, inventory.EXIT_FAILED)
                    item = {"id": (f"audit:{row_id}" if section == "owner_template"
                                   else str(row_id)), "reason": "invalid_time"}
                    self.assertIn(item, report["sections"][section]["failed"])

    def test_values_the_services_parse_are_validated_on_the_current_state(self):
        # Codex P1 sweep: every value a service parses or compares later, in
        # rows recorded or new, must be one it writes; each case is one row.
        uid = "00000000-0000-4000-8000-0000000000bb"
        cases = {
            # presence_audit was inventoried without its time (Codex)
            "presence audit malformed time": (
                "INSERT INTO presence_audit (action, actor, at) VALUES ('override_set', ?, 'x')",
                (uid,), "audit_presence", "invalid_time"),
            "presence audit future time": (
                "INSERT INTO presence_audit (action, actor, at) VALUES ('override_set', ?, "
                "'9999-01-01T00:00:00.000000+00:00')", (uid,), "audit_presence", "future_time"),
            "presence audit unknown action": (
                "INSERT INTO presence_audit (action, actor, at) VALUES ('bogus', ?, "
                "'2026-01-01T00:00:00.000000+00:00')", (uid,), "audit_presence", "invalid_value"),
            "security audit unknown action": (
                "INSERT INTO security_admin_audit_records VALUES (?, 'owner', 'bogus', 'source', "
                "?, ?, 'succeeded')", (uid, uid, 1), "audit_security_admin", "invalid_value"),
            "integrity audit actor": (
                "INSERT INTO integrity_audit(at, actor, revision) VALUES "
                "('2026-01-01T00:00:00+00:00', 'owner', 1)", (), "audit_integrity",
                "invalid_value"),
            "storage audit state": (
                "INSERT INTO storage_state_audit (at_ms, previous_state, current_state) "
                "VALUES (1, 'normal', 'pressure')", (), "audit_storage_state", "invalid_value"),
            "delivery state and counter": (
                "INSERT INTO presence_deliveries (observation, action, state, attempts) "
                "VALUES (?, 'evidence', 'bogus', -1)", (uid,), "presence", "invalid_value"),
            "observation payload": (
                "INSERT INTO presence_observations (id, kind, source, received, payload) "
                "VALUES (?, 'person', 's', '2026-01-01T00:00:00.000000+00:00', '{}')",
                (uid,), "presence", "invalid_value"),
            "override state": (
                "INSERT INTO presence_override VALUES (1, 'bogus', ?, "
                "'2026-01-01T00:00:00.000000+00:00', NULL)", (uid,), "presence", "invalid_value"),
            "marker count": (
                "INSERT INTO presence_expired_unresolved VALUES ('evidence', 0, "
                "'2026-01-01T00:00:00.000000+00:00')", (), "presence", "invalid_value"),
            "recording status": (
                "INSERT INTO recordings (id, source_id, start_ms, target_end_ms, status, critical) "
                "VALUES (?, ?, 0, 10, 'bogus', 0)", (uid, uid), "recordings", "invalid_value"),
            "integrity findings": (
                "INSERT INTO integrity_outbox(at, immediate, findings) VALUES "
                "('2026-01-01T00:00:00+00:00', 1, 'not json')", (), "integrity_delivery",
                "invalid_value"),
            "integrity baseline": (
                "INSERT INTO integrity_baseline VALUES (1, 1, '{}')", (), "integrity_baseline",
                "invalid_value"),
            "camera capabilities": (
                "UPDATE camera_sources SET capabilities='not json'", (), "camera_sources",
                "invalid_value"),
            "pairing node id": (
                "INSERT INTO pairing_key_bindings VALUES (?, 'not-a-uuid', 1)", ("e" * 64,),
                "security_state", "invalid_value"),
        }
        for index, (label, (statement, parameters, section, reason)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"domain-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"domain-{index}.json")
                    runtime.execute(statement, parameters)
                    code, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn(reason, [item["reason"] for item in
                                       report["sections"][section].get("failed", [])])

    def test_stored_columns_match_the_model_the_service_rebuilds(self):
        # Codex P1: where a service rebuilds a model from a row, every stored
        # column must be what it would write from that model.
        uid = "00000000-0000-4000-8000-0000000000cc"
        baseline_text = json.dumps({"components": [
            {"kind": "CPU", "location": "socket0", "properties": [], "identity": []},
            {"kind": "CPU", "location": "socket0", "properties": [], "identity": []}],
            "unavailable": []})
        cases = {
            "observation id column": (
                "INSERT INTO presence_observations (id, kind, source, received, payload) "
                "VALUES (?, ?, ?, ?, ?)", lambda: (
                    str(uuid4()), "server_movement", str(UUID(int=1)),
                    "2026-01-01T00:00:00.000000+00:00", presence_payload(uid)),
                "presence", "invalid_value"),
            "observation received column": (
                "INSERT INTO presence_observations (id, kind, source, received, payload) "
                "VALUES (?, ?, ?, ?, ?)", lambda: (
                    uid, "server_movement", str(UUID(int=1)),
                    "2026-01-02T00:00:00.000000+00:00", presence_payload(uid)),
                "presence", "invalid_value"),
            "active recording with an end": (
                "INSERT INTO recordings (id, source_id, start_ms, target_end_ms, ended_ms, "
                "status, critical) VALUES (?, ?, 0, 10, 10, 'active', 0)", lambda: (uid, uid),
                "recordings", "invalid_value"),
            "complete recording ending off its target": (
                "INSERT INTO recordings (id, source_id, start_ms, target_end_ms, ended_ms, "
                "status, critical) VALUES (?, ?, 0, 10, 5, 'complete', 0)", lambda: (uid, uid),
                "recordings", "invalid_value"),
            "interrupted recording off the recovery boundary": (
                "INSERT INTO recordings (id, source_id, start_ms, target_end_ms, ended_ms, "
                "status, critical) VALUES (?, ?, 0, 10, 10, 'interrupted', 0)",
                lambda: (uid, uid), "recordings", "invalid_value"),
            "outbox flag against its findings": (
                "INSERT INTO integrity_outbox(at, immediate, findings) VALUES "
                "('2026-01-01T00:00:00+00:00', 0, ?)", lambda: (json.dumps(
                    [{"kind": "GPU", "state": "CHANGED", "reason": "x"}]),),
                "integrity_delivery", "invalid_value"),
            "ambiguous hardware baseline": (
                "INSERT INTO integrity_baseline VALUES (1, 1, ?)", lambda: (baseline_text,),
                "integrity_baseline", "invalid_value"),
        }
        for index, (label, (statement, values, section, reason)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"model-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"model-{index}.json")
                    runtime.execute(statement, values())
                    code, report, _ = self.verify(baseline)
                    if section == "integrity_baseline":
                        # record refuses a baseline the service could not read.
                        code_record, _, stderr = run(
                            "record", "--runtime-root", str(runtime.root),
                            "--output", str(self.notes / f"model-bad-{index}.json"))
                        self.assertEqual(code_record, inventory.EXIT_USAGE)
                        self.assertIn("hardware baseline", stderr)
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn(reason, [item["reason"] for item in
                                       report["sections"][section].get("failed", [])])

    def test_registry_rows_must_rebuild_as_the_registry_reads_them(self):
        # Codex P1: CameraRegistry._source() builds CaptureProfile(**profile)
        # and every DetectionBinding; JSON that parses but cannot build a
        # source would break source enumeration at startup.
        for index, statement in enumerate((
                "UPDATE camera_sources SET desired_capture_profile='[]'",
                "INSERT INTO detection_bindings SELECT id, 'not-a-uuid', 'person', 1, 1, '{}', "
                "'{}' FROM camera_sources")):
            with self.subTest(statement):
                runtime = Runtime(self.base / f"registry-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"registry-{index}.json")
                    runtime.execute(statement)
                    code, report, _ = self.verify(baseline)
                    self.assert_record_refused("camera_sources:invalid_value")
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn("invalid_value", [item["reason"] for item in
                                                report["sections"]["camera_sources"]["failed"]])

    def test_record_succeeds_exactly_when_an_unchanged_verify_passes(self):
        # Codex P1: record runs every current-state check verify runs, so a
        # baseline is written iff verifying the same state unchanged passes.
        def presence(runtime):
            self.presence_rows()

        def paired(runtime):
            node = self._paired_node("a" * 64, "c" * 64)
            runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", ("a" * 64, node))

        def outbox(runtime):
            runtime.execute("INSERT INTO integrity_outbox(at, immediate, findings) VALUES "
                            "('2026-01-01T00:00:00+00:00', 1, ?)", (json.dumps(
                                [{"kind": "GPU", "state": "CHANGED", "reason": "x"}]),))

        def active(runtime):
            recording = runtime.recording(starred=False, payload=b"generated-property",
                                          status="active", target_end_ms=30000)
            runtime.add_segment(recording, b"generated-property-tail", start_ms=12000,
                                end_ms=20000)
        valid = {"seeded": lambda runtime: None, "presence": presence, "paired": paired,
                 "outbox": outbox, "active recording": active}
        invalid = {
            "unbound credential": lambda runtime: self._paired_node("b" * 64, "c" * 64),
            "outbox flag": lambda runtime: runtime.execute(
                "INSERT INTO integrity_outbox(at, immediate, findings) VALUES "
                "('2026-01-01T00:00:00+00:00', 0, ?)", (json.dumps(
                    [{"kind": "GPU", "state": "CHANGED", "reason": "x"}]),)),
            "control clock": lambda runtime: runtime.execute(
                "INSERT INTO presence_control_clock VALUES (1, 'x')"),
            "future clock": lambda runtime: runtime.execute(
                "INSERT INTO presence_clock VALUES (1, '9999-01-01T00:00:00.000000+00:00')"),
            "observation payload": lambda runtime: runtime.execute(
                "INSERT INTO presence_observations (id, kind, source, received, payload) VALUES "
                "('00000000-0000-4000-8000-0000000000dd', 'person', NULL, "
                "'2026-01-01T00:00:00.000000+00:00', '{}')"),
            "capture profile": lambda runtime: runtime.execute(
                "UPDATE camera_sources SET desired_capture_profile='[]'"),
            "corrupt segment": lambda runtime: next(
                path.write_bytes(b"generated-altered") for path in
                (runtime.root / "recordings").iterdir()),
            "orphan job": lambda runtime: runtime.execute(
                "INSERT INTO presence_deliveries (observation, action, state, attempts) "
                "VALUES ('00000000-0000-4000-8000-0000000000ee', 'evidence', 'pending', 0)"),
        }
        for index, (label, setup) in enumerate({**valid, **invalid}.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"property-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    setup(runtime)
                    target = self.notes / f"property-{index}.json"
                    code, _, stderr = run("record", "--runtime-root", str(runtime.root),
                                          "--output", str(target))
                    if code in (inventory.EXIT_PRESERVED, inventory.EXIT_EMPTY):
                        verified, report, _ = self.verify(target)
                    else:
                        verified, report = None, None
                finally:
                    self.runtime = saved
                if label in valid:
                    self.assertEqual(code, inventory.EXIT_PRESERVED, stderr)
                    self.assertEqual(verified, inventory.EXIT_PRESERVED, report)
                else:
                    self.assertEqual(code, inventory.EXIT_FAILED, stderr)
                    self.assertFalse(target.exists())

    def test_rows_must_rebuild_through_the_service_builders(self):
        # Codex P1 sweep: each row a service rebuilds is rebuilt here with the
        # service's own builder (and its write-side validator where one exists).
        cases = {
            "capabilities not an object": (
                "UPDATE camera_sources SET capabilities='[]'", "camera_sources"),
            "capture node time": (
                "INSERT INTO capture_nodes VALUES ('00000000-0000-4000-8000-0000000000f1', "
                "'n', 'online', NULL, 'not-a-time', 'not-a-time')", "security_state"),
            "principal time": (
                "UPDATE access_principals SET created_at_us='soon' WHERE role='owner'",
                "access_principals"),
            "credential backup state": (
                "UPDATE access_credentials SET backup_state=1", "access_principals"),
            "segment identity": (
                "INSERT INTO recording_segments (id, source_id, stream_id, sequence, start_ms, "
                "end_ms, codec, container, byte_length, sha256, state, spool) VALUES ('x', "
                "'00000000-0000-4000-8000-0000000000f2', 's', 1, 0, 1, 'synthetic', 'deflate', "
                "1, '0', 'ready', 1)", "recordings"),
        }
        for index, (label, (statement, section)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"builder-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"builder-{index}.json")
                    runtime.execute(statement)
                    code, report, _ = self.verify(baseline)
                    self.assert_record_refused(f"{section}:invalid_value")
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn("invalid_value", [item["reason"] for item in
                                                report["sections"][section].get("failed", [])])

    def test_rows_without_a_builder_are_checked_as_their_service_writes_them(self):
        # Codex P1: invitation, session, grant and pairing rows have no
        # read-model builder, and spooled segments are linked later without
        # re-validation; each is checked field by field as its service
        # writes it (UUIDs, digests, enums, integer ranges, time order).
        def one(runtime, sql):
            with closing(sqlite3.connect(runtime.database)) as connection:
                return connection.execute(sql).fetchone()[0]

        def statement(sql, parameters=()):
            return lambda runtime: runtime.execute(sql, parameters)
        open_invitation = "SELECT id FROM access_invitations WHERE revoked_at_us IS NULL"
        node, enrollment, segment = str(uuid4()), str(uuid4()), str(uuid4())
        epoch = "00000000-0000-4000-8000-00000000e90c"

        def spooled(start_ms, end_ms, *, state="ready", spool=1, sequence=0):
            return lambda runtime: runtime.execute(
                "INSERT INTO recording_segments (id, source_id, stream_id, sequence, start_ms, "
                "end_ms, codec, container, byte_length, sha256, state, spool) VALUES "
                "(?, (SELECT source_id FROM recordings LIMIT 1), ?, ?, ?, ?, 'synthetic', "
                "'deflate', 1, ?, ?, ?)",
                (segment, stream("s"), sequence, start_ms, end_ms, "0" * 64, state, spool))
        cases = {
            "appended invitation identity": (statement(
                "INSERT INTO access_invitations VALUES ('x', ?, (SELECT id FROM "
                "access_principals WHERE role='owner'), 0, 0, 1, 2, NULL, NULL, 0)",
                (bytes(range(64, 96)),)), "access_invitations", lambda runtime: "x"),
            "invitation secret digest": (statement(
                f"UPDATE access_invitations SET secret_digest=X'00' WHERE id=({open_invitation})"),
                "access_invitations", lambda runtime: one(runtime, open_invitation)),
            "invitation attempts": (statement(
                f"UPDATE access_invitations SET attempt_count=6 WHERE id=({open_invitation})"),
                "access_invitations", lambda runtime: one(runtime, open_invitation)),
            "invitation redeemed after expiry": (statement(
                f"UPDATE access_invitations SET redeemed_at_us=5 WHERE id=({open_invitation})"),
                "access_invitations", lambda runtime: one(runtime, open_invitation)),
            "session idle expiry": (statement("UPDATE access_sessions SET idle_expires_at_us=12"),
                                    "security_state", lambda runtime: "access_sessions:"
                                    + one(runtime, "SELECT id FROM access_sessions")),
            "session token digest": (statement("UPDATE access_sessions SET token_digest=X'00'"),
                                     "security_state", lambda runtime: "access_sessions:"
                                     + one(runtime, "SELECT id FROM access_sessions")),
            "grant principal": (statement(
                "INSERT INTO access_principal_permissions VALUES ('x', 'live:view')"),
                "access_principals", lambda runtime: "x"),
            "enrollment code digest": (statement(
                "INSERT INTO pairing_enrollments VALUES (?, ?, ?, 'f', ?, 1, 'expired')",
                (enrollment, node, "a" * 64, epoch)), "security_state",
                lambda runtime: f"pairing_enrollments:{enrollment}"),
            "credential serial digest": (statement(
                "INSERT INTO pairing_node_credentials (node_id, public_key_digest, "
                "credential_serial_digest, state) VALUES (?, ?, 'serial', 'revoked')",
                (node, "b" * 64)), "security_state",
                lambda runtime: f"pairing_node_credentials:{node}"),
            "renewal expiry": (statement(
                "INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 0, NULL)",
                (node, "c" * 64, "d" * 64)), "security_state",
                lambda runtime: f"pairing_node_renewals:{node}"),
            "key binding digest": (statement(
                "INSERT INTO pairing_key_bindings VALUES (?, ?, 1)", ("A" * 64, node)),
                "security_state", lambda runtime: f"pairing_key_bindings:{node}"),
            "spooled segment duration": (spooled(5000, 5000), "recordings",
                                         lambda runtime: f"segment:{segment}"),
            "spooled segment past its cursor": (spooled(10000, 30000, sequence=2**40),
                                                "recordings",
                                                lambda runtime: f"segment:{segment}"),
            "pending segment in the spool": (spooled(0, 5000, state="pending"), "recordings",
                                             lambda runtime: f"segment:{segment}"),
        }
        for index, (label, (tamper, section, item)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"rows-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    _, baseline = self.record(f"rows-{index}.json")
                    tamper(runtime)
                    expected = item(runtime)
                    code, report, _ = self.verify(baseline)
                    self.assert_record_refused(f"{section}:invalid_value")
                finally:
                    self.runtime = saved
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn({"id": expected, "reason": "invalid_value"},
                              report["sections"][section].get("failed", []))

    def test_states_the_real_services_write_record_and_verify_unchanged(self):
        # Codex P1 follow-up: the per-column rules for rows without a builder
        # (invitations, sessions, grants, pairing) and for every segment row
        # must accept every state the services write. Here only the real
        # AccessStore, PairingLedger and RecordingStore write those rows, on a
        # clock that moves forward between operations (plus one wall-clock
        # step back, which AccessStore does not refuse), and the state must
        # record and then verify unchanged without a single failure.
        import zlib
        from app.auth.model import AccessValidationError, Permission
        from app.auth.session_binding import SessionBindingKey
        from app.auth.store import AccessStore
        from app.media.recording import RecordingError, RecordingStore, RootIdentity, Segment
        from app.media.recording.model import Limits
        from tests.test_recording import Reservation, SyntheticValidator
        database = Database(self.runtime.database)
        clock = [self.now - timedelta(days=3)]

        def tick(**delta):
            clock[0] += timedelta(**delta)
            return clock[0]
        audit = AuditStore(database, clock=lambda: clock[0])
        access = AccessStore(database, clock=lambda: clock[0], audit=audit,
                             unaudited_writes=True, session_binding=SessionBindingKey.generate())
        # One shared Tailnet login for everybody: it selects no one.
        identity = "shared-tailnet-login@example.invalid"
        counts = {}

        def material(label):
            return hashlib.sha256(f"synthetic-{label}".encode()).digest()

        def enroll(principal_id, label, *, attempts=1):
            secret = material(f"{label}-enrollment-secret")
            tick(minutes=1)
            access.issue_enrollment(principal_id, secret, clock[0] + timedelta(minutes=15))
            for attempt in range(attempts):
                challenge = material(f"{label}-registration-{attempt}")
                tick(seconds=20)
                subject = access.begin_registration(secret, identity, challenge, at=clock[0],
                                                    lifetime=timedelta(minutes=5))
                tick(seconds=5)
                access.consume_challenge(challenge, "registration", at=clock[0])
            credential_id = material(f"{label}-credential-id")
            access.enroll_credential(secret, identity, credential_id, material(f"{label}-key"),
                                     -7, 0, invitation_id=subject.invitation_id)
            counts[credential_id] = 0
            return credential_id

        def assertion(principal_id, credential_id, **effect):
            counts[credential_id] += 1
            return access.accept_assertion(
                credential_id, principal_id, identity,
                expected_sign_count=counts[credential_id] - 1,
                sign_count=counts[credential_id], backup_state=False, at=clock[0], **effect)

        def sign_in(principal_id, credential_id, token):
            challenge = material(token.hex() + "-authentication")
            tick(seconds=30)
            access.issue_authentication_challenge(challenge, at=clock[0],
                                                  lifetime=timedelta(minutes=5))
            tick(seconds=3)
            access.consume_challenge(challenge, "authentication", at=clock[0])
            return assertion(principal_id, credential_id, token=token)

        def owner_transaction(operation):
            # What AccessAdministration runs inside its audited transaction.
            with closing(database.connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                operation(connection)
                connection.execute("COMMIT")

        def session_rows():
            with closing(sqlite3.connect(self.runtime.database)) as connection:
                connection.row_factory = sqlite3.Row
                return connection.execute("SELECT * FROM access_sessions").fetchall()
        # The Owner signs in and steps up for an AUTH-008 operation.
        owner = access.bootstrap_owner("Synthetic Owner")
        owner_credential = enroll(owner.id, "owner")
        owner_token = material("owner-session-token")
        owner_session = sign_in(owner.id, owner_credential, owner_token)
        tick(minutes=2)
        access.authorize_owner(owner_token, identity)
        tick(minutes=10)
        challenge = material("owner-step-up")
        access.begin_step_up(owner_token, identity, challenge, at=clock[0],
                             lifetime=timedelta(minutes=5))
        tick(seconds=4)
        access.consume_challenge(challenge, "step_up", at=clock[0])
        assertion(owner.id, owner_credential, step_up_session_id=owner_session)
        # A principal whose credential turns inconsistent, then is revoked
        # with a second, still open invitation.
        gone = access.invite("Synthetic revoked viewer",
                             (Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        gone_credential = enroll(gone.id, "gone")
        sign_in(gone.id, gone_credential, material("gone-session-token"))
        tick(minutes=1)
        access.issue_enrollment(gone.id, material("gone-second-secret"),
                                clock[0] + timedelta(hours=1))
        tick(minutes=3)
        access.mark_credential_inconsistent(gone_credential, gone.id, at=clock[0])
        tick(minutes=3)
        access.revoke_principal(gone.id)
        # An invitation attempted once, left to expire, then revoked; and one
        # that simply lapses unredeemed.
        pending = access.invite("Synthetic pending viewer", (Permission.LIVE_VIEW,))
        tick(minutes=1)
        access.issue_enrollment(pending.id, material("pending-secret"),
                                clock[0] + timedelta(minutes=15))
        tick(seconds=30)
        access.begin_registration(material("pending-secret"), identity,
                                  material("pending-challenge"), at=clock[0],
                                  lifetime=timedelta(minutes=5))
        tick(minutes=20)
        access.revoke_principal(pending.id)
        lapsed = access.invite("Synthetic lapsed viewer", (Permission.RECORDINGS_VIEW,))
        tick(minutes=1)
        access.issue_enrollment(lapsed.id, material("lapsed-secret"),
                                clock[0] + timedelta(minutes=15))
        # Every session ends and the deployment generation advances.
        tick(minutes=1)
        owner_transaction(lambda connection: access.invalidate_all_sessions_on(
            connection, at=clock[0]))
        sign_in(owner.id, owner_credential, material("owner-second-token"))
        # A grant is withdrawn (live:view), a second credential is revoked.
        viewer = access.invite("Synthetic recordings viewer",
                               (Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        viewer_credential = enroll(viewer.id, "viewer")
        low_level = material("viewer-low-level-token")
        tick(seconds=10)
        access.establish_session(viewer.id, viewer_credential, low_level, proxy_identity=identity)
        tick(minutes=4)
        access.authorize(low_level, identity, Permission.LIVE_VIEW)
        tick(minutes=4)
        access.set_permissions(viewer.id, (Permission.RECORDINGS_VIEW,))
        viewer_second = enroll(viewer.id, "viewer-second")
        sign_in(viewer.id, viewer_second, material("viewer-second-token"))
        tick(minutes=2)
        owner_transaction(lambda connection: access.revoke_credential_on(
            connection, viewer.id, viewer_second, at=clock[0]))
        viewer_token = material("viewer-token")
        sign_in(viewer.id, viewer_credential, viewer_token)
        tick(minutes=5)
        access.authorize(viewer_token, identity, Permission.RECORDINGS_VIEW)
        with self.assertRaises(AccessValidationError):
            access.authorize(viewer_token, identity, Permission.LIVE_VIEW)
        # A live viewer (two registration attempts) whose session sees two
        # binding mismatches (one audited, one coalesced), then is touched
        # every 25 minutes until the idle expiry is clamped by the absolute
        # one: touches at +2 + 25k minutes, the 28th at +702 of 720.
        live = access.invite("Synthetic live viewer", (Permission.LIVE_VIEW,))
        live_credential = enroll(live.id, "live", attempts=2)
        live_token = material("live-token")
        live_session = str(sign_in(live.id, live_credential, live_token))
        for _ in range(2):
            tick(minutes=1)
            with self.assertRaises(AccessValidationError):
                access.authorize(live_token, "another-login@example.invalid", Permission.LIVE_VIEW)
        for _ in range(28):
            tick(minutes=25)
            access.authorize(live_token, identity, Permission.LIVE_VIEW)
        # The wall clock steps back two minutes (an NTP correction) before a
        # revocation: AccessStore keeps no monotonic floor, so the revocation
        # and invalidation times precede the invitation and session.
        skewed = access.invite("Synthetic skewed viewer", (Permission.LIVE_VIEW,))
        skewed_credential = enroll(skewed.id, "skewed")
        skewed_session = str(sign_in(skewed.id, skewed_credential, material("skewed-token")))
        tick(seconds=30)
        access.issue_enrollment(skewed.id, material("skewed-second-secret"),
                                clock[0] + timedelta(minutes=15))
        access.revoke_principal(skewed.id, now=clock[0] - timedelta(minutes=2))

        # PairingLedger on its monotonic clock: renewed (one promoted, one
        # staged), revoked, expired by a Main restart, consumed and pending.
        monotonic = [7200.0]

        def ledger():
            return PairingLedger(database, HmacCodeVerifier(b"s" * 32), audit=audit,
                                 clock=lambda: monotonic[0], process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        gate = Owner()

        def key(label):
            return hashlib.sha256(f"synthetic-node-key-{label}".encode()).hexdigest()

        def wait(seconds):
            tick(seconds=seconds)
            monotonic[0] += seconds
        expiry = (self.now + timedelta(days=30)).timestamp()
        main = ledger()

        def approve(node, label):
            wait(5)
            approval, code = main.approve(gate, "owner", node_id=node,
                                          public_key_digest=key(label))
            wait(40)
            return approval, code

        def pair(node, label):
            approval, code = approve(node, label)
            claim = main.redeem(enrollment_id=approval.enrollment_id,
                                public_key_digest=key(label), code=code.value)
            wait(2)
            main.activate(claim, credential_serial_digest=renewal_serial(label),
                          not_after=expiry)

        def stage(node, current, label, not_after):
            stage_renewal(main, node_id=node, current_public_key_digest=key(current),
                          current_credential_digest=renewal_serial(current),
                          public_key_digest=key(label),
                          credential_serial_digest=renewal_serial(label),
                          not_after=not_after)
        renewed, revoked, expired, consumed, waiting = (uuid4() for _ in range(5))
        pair(renewed, "renewed")
        wait(3600)
        stage(renewed, "renewed", "renewed-2", expiry + 86_400)
        wait(30)
        self.assertTrue(main.admits(node_id=renewed, public_key_digest=key("renewed-2"),
                                    credential_serial_digest=renewal_serial("renewed-2")))
        wait(3600)
        stage(renewed, "renewed-2", "renewed-3", expiry + 2 * 86_400)
        pair(revoked, "revoked")
        wait(300)
        main.revoke(gate, "owner", node_id=revoked)
        approval, code = approve(expired, "expired")
        # Main restarts before the agent redeems: the new epoch expires it.
        main = ledger()
        with self.assertRaises(PairingError):
            main.redeem(enrollment_id=approval.enrollment_id, public_key_digest=key("expired"),
                        code=code.value)
        approval, code = approve(consumed, "consumed")
        main.redeem(enrollment_id=approval.enrollment_id, public_key_digest=key("consumed"),
                    code=code.value)
        approve(waiting, "waiting")

        # RecordingStore through its real publish path: spooled pre-roll, a
        # two-source critical event with stream changes and gaps, manual
        # clips, deadline closing and an interrupted publication.
        media = self.runtime.root / "recordings"
        info = media.stat()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        limits = Limits(pre_roll_bytes=4096, max_segment_bytes=512, max_segment_ms=30_000,
                        max_active_recordings=8, max_spool_segments=16,
                        max_segments_per_recording=100)

        def open_store():
            return RecordingStore(connection, media, RootIdentity(info.st_dev, info.st_ino),
                                  limits, Reservation(), SyntheticValidator())
        store = open_store()
        self.addCleanup(lambda: store.close())
        payload = zlib.compress(b"generated geometric test payload" * 4)
        local, remote = UUID(self.runtime.source()), uuid4()
        stream_a, stream_b, remote_stream = uuid4(), uuid4(), uuid4()
        base = int((self.now - timedelta(days=2)).timestamp() * 1000)

        def put(source, stream_id, sequence, start, end, node=None):
            return store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                        "synthetic", "deflate", payload, capture_node_id=node))
        for sequence in range(5):
            put(local, stream_a, sequence, sequence * 10_000, (sequence + 1) * 10_000)
        for sequence, (start, end) in enumerate(((30_000, 45_000), (45_000, 60_000))):
            put(remote, remote_stream, sequence, start, end, renewed)
        # Event window [40 s, 100 s] on both sources.
        event = store.start_event(uuid4(), (local, remote), base + 55_000, pre_ms=15_000,
                                  post_ms=45_000, critical=True)
        put(local, stream_a, 5, 50_000, 60_000)
        put(local, stream_b, 0, 60_000, 62_000)
        put(local, stream_a, 10, 62_000, 70_000)
        for sequence in range(11, 14):
            put(local, stream_a, sequence, (sequence - 4) * 10_000, (sequence - 3) * 10_000)
        put(remote, remote_stream, 2, 60_000, 75_000, renewed)
        put(remote, remote_stream, 4, 77_000, 90_000, renewed)
        put(remote, remote_stream, 5, 90_000, 100_000, renewed)
        store.advance(base + 100_000 + limits.max_segment_ms)
        # A starred manual clip stopped early, and one stopped inside a
        # still-open segment (closed later by the deadline worker).
        starred = store.start_manual(local, base + 105_000, duration_ms=20_000)
        put(local, stream_a, 14, 100_000, 110_000)
        put(local, stream_a, 15, 110_000, 120_000)
        store.finish(starred, stop_ms=base + 115_000)
        store.set_starred(starred, True)
        late = store.start_manual(local, base + 125_000, duration_ms=30_000)
        put(local, stream_a, 16, 120_000, 130_000)
        self.assertEqual(store.finish(late, stop_ms=base + 135_000)["status"], "active")
        put(local, stream_a, 17, 130_000, 140_000)
        store.advance(base + 135_000 + limits.max_segment_ms)
        # A remote manual clip interrupted by a crash in mid-publication:
        # reopening removes the pending row and marks the clip interrupted.
        crashed = store.start_manual(remote, base + 100_000, duration_ms=30_000)
        put(remote, remote_stream, 6, 100_000, 110_000, renewed)
        with mock.patch.object(RecordingStore, "_write", side_effect=OSError("synthetic")):
            with self.assertRaises(RecordingError):
                put(remote, remote_stream, 7, 110_000, 120_000, renewed)
        store.close()
        store = open_store()
        store.release_source(remote)
        # The local stream restarts as B and resumes A with its counter
        # reset (A0 was trimmed long ago), both contiguous: zero-length
        # markers, and linked A rows above the cursor's sequence.
        put(local, stream_b, 1, 140_000, 142_000)
        put(local, stream_a, 0, 142_000, 150_000)

        with closing(sqlite3.connect(self.runtime.database)) as db:
            db.row_factory = sqlite3.Row
            statuses = {row["id"]: (row["status"], row["ended_ms"]) for row in db.execute(
                "SELECT id, status, ended_ms FROM recordings")}
            self.assertEqual(statuses[str(crashed)], ("interrupted", base + 110_000))
            self.assertEqual(statuses[str(late)], ("complete", base + 135_000))
            self.assertEqual(statuses[str(starred)], ("complete", base + 115_000))
            self.assertTrue(all(statuses[str(item)][0] == "gapped" for item in event))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM recording_segments "
                                        "WHERE state='pending'").fetchone()[0], 0)
            self.assertTrue(db.execute("SELECT 1 FROM recording_discontinuities "
                                       "WHERE start_ms = end_ms").fetchone())
            cursor = db.execute("SELECT stream_id, sequence FROM recording_source_cursors "
                                "WHERE source_id=?", (str(local),)).fetchone()
            self.assertTrue(db.execute(
                "SELECT 1 FROM recording_segments WHERE source_id=? AND stream_id=? "
                "AND sequence > ?", (str(local), cursor[0], cursor[1])).fetchone())
            invitations = db.execute("SELECT * FROM access_invitations").fetchall()
            self.assertIn(2, [row["attempt_count"] for row in invitations])
            self.assertTrue(any(row["revoked_at_us"] is not None
                                and row["revoked_at_us"] > row["expires_at_us"]
                                for row in invitations))
            self.assertTrue(any(row["revoked_at_us"] is not None
                                and row["revoked_at_us"] < row["issued_at_us"]
                                for row in invitations))
        sessions = {row["id"]: row for row in session_rows()}
        clamped = sessions[live_session]
        self.assertGreater(clamped["last_seen_at_us"], clamped["established_at_us"])
        self.assertLess(clamped["absolute_expires_at_us"],
                        clamped["last_seen_at_us"] + clamped["idle_lifetime_us"])
        self.assertEqual(clamped["idle_expires_at_us"], clamped["absolute_expires_at_us"])
        self.assertIsNotNone(clamped["binding_mismatch_audited_at_us"])
        self.assertEqual(clamped["binding_mismatch_suppressed"], 1)
        self.assertGreater(sessions[str(owner_session)]["last_user_verification_at_us"],
                           sessions[str(owner_session)]["established_at_us"])
        self.assertLess(sessions[skewed_session]["invalidated_at_us"],
                        sessions[skewed_session]["established_at_us"])
        # Sessions ended by the expiry sweep keep no binding.
        self.assertTrue(all(row["external_identity_binding"] is None
                            for row in sessions.values() if row["invalidated_at_us"]))

        baseline = self.notes / "real-services.json"
        code, _, stderr = run("record", "--runtime-root", str(self.runtime.root),
                              "--output", str(baseline))
        self.assertEqual(code, inventory.EXIT_PRESERVED, stderr)
        self.assertTrue(all(value == "present" for value in
                            json.loads(baseline.read_text())["coverage"].values()))
        code, report, _ = self.verify(baseline)
        failures = {name: section.get("failed") for name, section in report["sections"].items()
                    if isinstance(section, dict) and section.get("failed")}
        self.assertEqual(failures, {})
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["status"])

    def test_recordings_without_evidence_are_recorded_and_their_rows_verified(self):
        # Owner decision 2026-10-05: a recording the real RecordingStore
        # linked no segment to (interrupted before any segment, an event over
        # a source with no media) never refuses record. It is listed as
        # having no evidence, counted apart from coverage, never preserved
        # evidence; verify only needs its row to survive under the usual
        # identity / status rules (starring it during the update fails).
        import zlib
        from app.media.recording import RecordingStore, RootIdentity, Segment
        from app.media.recording.model import Limits
        from tests.test_recording import Reservation, SyntheticValidator
        self.runtime.seed()
        media = self.runtime.root / "recordings"
        info = media.stat()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        limits = Limits(pre_roll_bytes=4096, max_segment_bytes=512, max_segment_ms=30_000,
                        max_active_recordings=8, max_spool_segments=16,
                        max_segments_per_recording=100)

        def open_store():
            return RecordingStore(connection, media, RootIdentity(info.st_dev, info.st_ino),
                                  limits, Reservation(), SyntheticValidator())
        store = open_store()
        self.addCleanup(lambda: store.close())
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(days=2)).timestamp() * 1000)
        local, silent, remote, quiet, fresh = (uuid4() for _ in range(5))
        stream_a, stream_b, fresh_stream = uuid4(), uuid4(), uuid4()

        def put(source, stream_id, sequence, start, end):
            store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                 "synthetic", "deflate", payload))
        put(local, stream_a, 0, 0, 10_000)
        # An event over a source with media and one with none.
        with_media, without_media = store.start_event(uuid4(), (local, silent), base + 15_000,
                                                      pre_ms=10_000, post_ms=10_000)
        put(local, stream_a, 1, 10_000, 20_000)
        put(local, stream_a, 2, 20_000, 30_000)
        store.advance(base + 25_000 + limits.max_segment_ms)
        # A clip interrupted (Main restart) before any segment arrived.
        interrupted = store.start_manual(remote, base + 40_000, duration_ms=20_000)
        store.close()
        store = open_store()
        # Still active at record time with nothing linked: one closes with
        # no media, one gets its first segment on a fresh source, one on
        # the local source after a stream change (a marker from an unlinked
        # cursor end).
        closes_empty = store.start_manual(quiet, base + 60_000, duration_ms=20_000)
        grows = store.start_manual(fresh, base + 60_000, duration_ms=20_000)
        switches = store.start_manual(local, base + 60_000, duration_ms=20_000)
        without = sorted(str(item) for item in (without_media, interrupted, closes_empty,
                                                 grows, switches))
        with closing(sqlite3.connect(self.runtime.database)) as db:
            rows = dict(db.execute("SELECT id, status FROM recordings"))
        self.assertEqual(rows[str(without_media)], "gapped")
        self.assertEqual(rows[str(interrupted)], "interrupted")

        code, baseline = self.record("no-evidence.json")
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        recorded = json.loads(baseline.read_text())
        self.assertEqual(sorted(key for key, item in recorded["recordings"].items()
                                if item["evidence"] == "no_evidence"), without)
        self.assertEqual(recorded["coverage_counts"]["recordings_without_evidence"], 5)
        code, report, stdout = self.verify(baseline)
        section = report["sections"]["recordings"]
        self.assertEqual(code, inventory.EXIT_PRESERVED, section)
        self.assertEqual(section["no_evidence"], without)
        self.assertFalse(set(without) & set(section["preserved"]))
        self.assertIn(str(with_media), section["preserved"])
        self.assertIn("no_evidence=5", stdout)
        # The active rows move on as the store moves them.
        put(fresh, fresh_stream, 0, 62_000, 70_000)
        put(local, stream_b, 0, 64_000, 72_000)
        store.advance(base + 80_000 + limits.max_segment_ms)
        code, report, _ = self.verify(baseline)
        section = report["sections"]["recordings"]
        self.assertEqual(code, inventory.EXIT_PRESERVED, section)
        self.assertEqual(section["no_evidence"], without)
        self.assertEqual(sorted(section["in_progress_at_record"]),
                         sorted(str(item) for item in (closes_empty, grows, switches)))
        with closing(sqlite3.connect(self.runtime.database)) as db:
            self.assertEqual(db.execute(
                "SELECT start_ms, end_ms FROM recording_discontinuities WHERE recording_id=?",
                (str(switches),)).fetchall(), [(base + 30_000, base + 64_000)])
        # A marker no publication of the first segment adds is not growth.
        self.runtime.execute("INSERT INTO recording_discontinuities VALUES "
                             "(?, ?, ?, 'stream_discontinuity')",
                             (str(grows), base + 60_000, base + 61_000))
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(grows), "reason": "changed"}])
        self.runtime.execute("DELETE FROM recording_discontinuities WHERE recording_id=?",
                             (str(grows),))
        # Starring one during the update is a change; losing a row fails.
        store.set_starred(interrupted, True)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(interrupted), "reason": "changed"}])
        store.set_starred(interrupted, False)
        self.runtime.execute("DELETE FROM recordings WHERE id=?", (str(without_media),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(without_media), "reason": "missing"}])
        self.assertNotIn(str(without_media), report["sections"]["recordings"]["no_evidence"])

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
        self.runtime.execute("INSERT INTO presence_override VALUES (1, 'ABSENT', "
                             "'00000000-0000-4000-8000-0000000000aa', "
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
                                    [{"kind": "GPU", "state": "CHANGED", "reason": "x"}]),))
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
                runtime.execute(ENROLLMENT_INSERT + "'expired')",
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
            # The starred recording, which automatic retention never takes,
            # so a re-identified row cannot read as retention plus an append.
            values = {"edited": ids["edited"], "lost": ids["lost"], "recording": seeded["starred"],
                      "ordinary": seeded["ordinary"],
                      "segment": other_segment, "other_segment": segment, "active": active,
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
            "recordings.starred": "UPDATE recordings SET starred=1 WHERE id=:ordinary",
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
        def inventory_text(marker):
            # The shape IntegrityStore.baseline() reads.
            return json.dumps({"components": [{"kind": "CPU", "location": "socket0",
                                               "properties": [["model", marker]],
                                               "identity": [["serial", marker]]}],
                               "unavailable": []})
        self.runtime.execute("INSERT INTO integrity_baseline VALUES (1, 3, ?)",
                             (inventory_text(hardware),))
        _, baseline = self.record()
        code, _, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        self.runtime.execute("UPDATE integrity_baseline SET inventory=?",
                             (inventory_text("synthetic-replaced"),))
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
        # The activation that created the credential.
        self.runtime.execute(
            ENROLLMENT_INSERT + "'activated')",
            (str(uuid4()), revoked_node, key))
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
        findings = json.dumps([{"kind": "GPU", "state": "CHANGED", "reason": hardware}])
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
                          "reason": "COALESCED_PENDING_WARNING"}]),))
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
                          {"id": "pending:3", "reason": "changed"},
                          # immediate=0 for a CHANGED finding is not what
                          # IntegrityStore.record() derives.
                          {"id": "pending:3", "reason": "invalid_value"}])

    def test_accepted_integrity_event_matches_the_pending_row(self):
        # Codex P1: _integrity_sink() records the row's failure / warning
        # kind (its immediate flag) at the row's own time under the
        # deterministic event ID; another kind or time is not that event.
        self.runtime.seed()
        when = "2026-01-01T00:00:00+00:00"
        immediate_findings = json.dumps([{"kind": "GPU", "state": "CHANGED", "reason": "x"}])
        warning_findings = json.dumps([{"kind": "GPU", "state": "UNVERIFIABLE", "reason": "x"}])
        for immediate in (1, 1, 0):
            # IntegrityStore.record() derives the flag from the findings.
            self.runtime.execute("INSERT INTO integrity_outbox(at, immediate, findings) "
                                 "VALUES (?, ?, ?)", (when, immediate,
                                                      immediate_findings if immediate
                                                      else warning_findings))
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
            self.runtime.execute(
                ENROLLMENT_INSERT + "'activated')",
                (str(uuid4()), node_id, old[node_id]))
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                 (old[node_id], node_id))
        # stage_renewal() binds the staged key when it stages it.
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             ("4" * 64, promoted))
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0, NULL)",
                             (promoted, "4" * 64, "5" * 64))
        _, baseline = self.record()
        for marker in ("1" * 64, "4" * 64, "5" * 64):
            self.assertNotIn(marker, baseline.read_text())
        # PairingLedger promotion: swap the staged key in, consume it.
        self.runtime.pairing_audit(promoted, "activate")
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
            self.runtime.execute(
                ENROLLMENT_INSERT + "'activated')",
                (str(uuid4()), node_id, key))
            for bound in (key, staged):
                self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                     (bound, node_id))
            self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0, NULL)",
                                 (node_id, staged, "d" * 64))
        _, baseline = self.record()
        # Legitimate: revocation discards it; a fresh pairing replaces the
        # identity; re-staging binds the new key first; promotion consumes it.
        self.runtime.pairing_audit(nodes["revoked"], "revoke")
        self.runtime.pairing_audit(nodes["repaired"], "approve", "redeem", "activate")
        self.runtime.pairing_audit(nodes["promoted"], "activate")
        self.runtime.execute("UPDATE pairing_node_credentials SET state='revoked' WHERE node_id=?",
                             (nodes["revoked"],))
        self.runtime.execute("UPDATE pairing_key_bindings SET revoked=1 WHERE node_id=?",
                             (nodes["revoked"],))
        fresh = "e" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             (fresh, nodes["repaired"]))
        self.runtime.execute(
            ENROLLMENT_INSERT + "'activated')",
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
        failed = report["sections"]["security_state"]["failed"]
        # The key re-staged in the window, now replaced, stays bound with
        # nothing left to explain it (keyed, so matched by reason).
        bindings = [item for item in failed if item["id"].startswith("pairing_key_bindings:")]
        self.assertEqual([item["reason"] for item in bindings], ["unexplained"])
        self.assertEqual(sorted([item for item in failed if item not in bindings],
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
        outbox([{"kind": "GPU", "state": "UNVERIFIABLE", "reason": "x"}],
               "2026-01-05T00:00:00+00:00", 0)
        deliver(1, "hardware_integrity_warning", "2026-01-05T00:00:00+00:00")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(len(report["sections"]["integrity_delivery"]["failed"]), 2)
        # The real promotions: one row per slot. The still-pending one proves
        # its slot; the delivered one leaves only (failure kind, time), which
        # cannot name MEMORY / CHANGED, so that slot is unverifiable.
        outbox([{"kind": "CPU", "state": "CHANGED", "reason": "COALESCED_PENDING_WARNING"}], when)
        outbox([{"kind": "MEMORY", "state": "CHANGED",
                 "reason": "COALESCED_PENDING_WARNING"}], when)
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
            (when, json.dumps([{"kind": "GPU", "state": "CHANGED", "reason": "x"}])))
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
        # The activation that created it (activate() is the only way).
        self.runtime.execute(
            ENROLLMENT_INSERT + "'activated')",
            (str(uuid4()), node, key))
        return node

    def _activated(self, node: str, key: str) -> None:
        self.runtime.execute(
            ENROLLMENT_INSERT + "'activated')",
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
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0, NULL)",
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
        self.runtime.pairing_audit(node, "approve", "redeem", "activate")
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
            ENROLLMENT_INSERT + "'activated')",
            (recorded, node, first))
        # Approved (key bound) but not yet activated at record time.
        opened, pending_key = str(uuid4()), "d" * 64
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                             (pending_key, node))
        self.runtime.execute(
            ENROLLMENT_INSERT + "'consumed')",
            (opened, node, pending_key))
        _, baseline = self.record()
        self.assertNotIn(pending_key, baseline.read_text())
        self.runtime.execute("DELETE FROM pairing_enrollments WHERE id=?", (recorded,))
        self._activated(node, first)
        self.runtime.pairing_audit(node, "approve", "redeem", "activate")
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
            ENROLLMENT_INSERT + "'activated')",
            (recorded, node, first))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        # The enrollment open at record time completing is a fresh pairing.
        self.runtime.execute("DELETE FROM pairing_enrollments WHERE state='activated' AND id!=? "
                             "AND public_key_digest=?", (recorded, first))
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
            self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0, NULL)",
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
        self.runtime.pairing_audit(nodes["promoted"], "activate")
        # A fresh pairing whose new key binding is revoked.
        self.runtime.pairing_audit(nodes["repaired"], "approve", "redeem", "activate")
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
                                    "reason": "incomplete"} for node in nodes.values()),
                                 # An unaudited activation cannot be ordered
                                 # before the node's revocation.
                                 {"id": f"pairing_revocation:{nodes['repaired']}",
                                  "reason": "reopened"},
                                 {"id": f"pairing_revocation:{nodes['promoted']}",
                                  "reason": "reopened"},
                                 # No revoke() ran: no revocation audit row.
                                 *({"id": f"pairing_audit:{node}:revoke_capture_node_pairing",
                                    "reason": "unaudited"} for node in nodes.values())],
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
            self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0, NULL)",
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
            stage_renewal(ledger, node_id=node, current_public_key_digest=current[0],
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
            staged[label] = (digest(), renewal_serial(digest()))
            stage(nodes[label], credential(nodes[label]), *staged[label])
        approval, code = ledger.approve(owner, "owner", node_id=nodes["activate-open"],
                                        public_key_digest=(open_key := digest()))
        open_claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=open_key, code=code.value)
        _, baseline = self.record()
        self.assertTrue(ledger.admits(node_id=nodes["promote"],
                                      public_key_digest=staged["promote"][0],
                                      credential_serial_digest=staged["promote"][1]))
        stage(nodes["restage"], credential(nodes["restage"]), digest(),
              renewal_serial(digest()))
        stage(nodes["retry"], credential(nodes["retry"]), staged["retry"][0],
              renewal_serial(digest()))
        ledger.revoke(owner, "owner", node_id=nodes["revoke"])
        self.assertTrue(ledger.admits(node_id=nodes["promote-restage"],
                                      public_key_digest=staged["promote-restage"][0],
                                      credential_serial_digest=staged["promote-restage"][1]))
        stage(nodes["promote-restage"], credential(nodes["promote-restage"]), digest(),
              renewal_serial(digest()))
        ledger.activate(open_claim, credential_serial_digest=digest(), not_after=50.0)
        pair(nodes["repair"], digest())
        pair(nodes["new"], digest())
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        # Known fail-closed side effects: a renewal both staged and promoted
        # after the record cannot show its material, and re-pairing a node
        # already revoked at record time reads as a reversed revocation.
        stage(nodes["repair"], credential(nodes["repair"]), (late := digest()), (serial := renewal_serial(digest())))
        self.assertTrue(ledger.admits(node_id=nodes["repair"], public_key_digest=late,
                                      credential_serial_digest=serial))
        # Re-pairing a node revoked inside the window on the same node ID
        # (the CLI uses a new node per the 2026-10-01 Owner decision).
        ledger.revoke(owner, "owner", node_id=nodes["revoke-repair"])
        pair(nodes["revoke-repair"], digest())
        _, revoked_baseline = self.record("revoked.json")
        pair(nodes["revoke"], digest())
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": f"pairing_credentials:{nodes['repair']}", "reason": "changed"},
                      report["sections"]["security_state"]["failed"])
        self.assertIn({"id": f"pairing_revocation:{nodes['revoke-repair']}",
                       "reason": "incomplete"}, report["sections"]["security_state"]["failed"])
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
        staged, serial = "c" * 64, renewal_serial("d")
        stage_renewal(ledger, node_id=node, current_public_key_digest="a" * 64,
                      current_credential_digest="b" * 64, public_key_digest=staged,
                      credential_serial_digest=serial, not_after=90.0)
        approval, _ = claim(staged)
        ledger.activate(claim("e" * 64)[1], credential_serial_digest="f" * 64, not_after=50.0)
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 90.0, NULL)",
                             (str(node), staged, serial))
        self.runtime.execute("UPDATE pairing_enrollments SET state='activated' WHERE id=?",
                             (str(approval.enrollment_id),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         # The forged activation also has no audit row.
                         [{"id": f"pairing_audit:{node}:activate_capture_node_credential",
                           "reason": "unaudited"},
                          {"id": f"pairing_enrollments:{approval.enrollment_id}",
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
                ENROLLMENT_INSERT + "?)",
                (ids[label], node, key, state))
        _, baseline = self.record()
        self.runtime.execute("DELETE FROM pairing_enrollments WHERE id=?", (ids["deleted"],))
        update = "UPDATE pairing_enrollments SET state=? WHERE id=?"
        self.runtime.execute(update, ("pending", ids["rewound"]))
        self.runtime.execute(update, ("activated", ids["revived"]))
        self.runtime.execute(update, ("expired", ids["expires"]))
        self.runtime.pairing_audit(node, "redeem", outcome="failed")  # its expiry
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
                                 {"id": f"pairing_revocation:{node}", "reason": "incomplete"},
                                 {"id": f"pairing_revocation:{node}", "reason": "reopened"},
                                 # A revoked enrollment beside an active credential.
                                 {"id": f"pairing_enrollments:{node}",
                                  "reason": "revocation_incomplete"},
                                 # The forged transitions have no ledger audit rows.
                                 *({"id": f"pairing_audit:{node}:{action}",
                                    "reason": "unaudited"} for action in (
                                        "activate_capture_node_credential",
                                        "redeem_capture_node_enrollment",
                                        "revoke_capture_node_pairing"))],
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
        stage_renewal(before, node_id=nodes["superseded"],
                      current_public_key_digest=keys["superseded"],
                      current_credential_digest="b" * 64,
                      public_key_digest=renewed, credential_serial_digest=renewal_serial("c"),
                      not_after=90.0)
        self.assertTrue(before.admits(node_id=nodes["superseded"], public_key_digest=renewed,
                                      credential_serial_digest=renewal_serial("c")))
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
        stage_renewal(ledger, node_id=node, current_public_key_digest="a" * 64,
                      current_credential_digest="b" * 64, public_key_digest=staged,
                      credential_serial_digest=renewal_serial("d"), not_after=90.0)
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
        # renewal both staged and promoted inside the window, an enrollment
        # since the record names the key staged at record time (a retry of
        # the promoted key ends exactly where approving the still-staged key
        # does), or something was approved on the node after its revocation.
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
                    stage_renewal(main, node_id=node, current_public_key_digest=current[0],
                                  current_credential_digest=current[1],
                                  public_key_digest=digest(),
                                  credential_serial_digest=renewal_serial(digest()),
                                  not_after=90.0)
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
            approved_staged, revoked = False, False
            pending_after_revoke, reactivated, orphaned = False, False, False
            saved, self.runtime = self.runtime, runtime
            try:
                _, baseline = self.record(f"composition-{index}.json")
                credential_source = "recorded"
                for op in ops:
                    approved_staged |= op == "retry" and credential()[0] == recorded_staged
                    # Anything approved on the node after its revocation
                    # (the CLI re-pairs a revoked node as a new node).
                    # An activation after a revocation re-opened the node on
                    # its own ID, whatever follows (the audit orders them);
                    # a mere approval is revoked again by a later revoke.
                    if op == "revoke":
                        pending_after_revoke = False
                    elif revoked and op == "expiry":
                        pending_after_revoke = True
                    elif revoked and op == "fresh":
                        reactivated = True
                    # A key staged inside the window and then superseded (a
                    # re-stage, or an activation dropping its renewal; or a
                    # promoted one replaced by a fresh key) stays bound with
                    # nothing showing it was staged: fail closed until a
                    # revoke revokes every binding of the node.
                    if op in ("stage", "fresh", "retry") and staged_source == "window":
                        orphaned = True
                    if op == "fresh" and credential_source == "promoted-window":
                        orphaned = True
                    if op == "revoke":
                        orphaned = False
                    run(op)
                    revoked |= op == "revoke"
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
            return (credential_source == "promoted-window" or approved_staged
                    or pending_after_revoke or reactivated or orphaned,
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
            stage_renewal(ledger, node_id=node, current_public_key_digest=keys["active"],
                          current_credential_digest="b" * 64,
                          public_key_digest=keys["staged"],
                          credential_serial_digest=renewal_serial("c"), not_after=90.0)
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
            # Codex P1: a live binding no approval, staging or credential explains.
            "orphan live binding":
                ("INSERT INTO pairing_key_bindings VALUES (:other, :node, 0)",),
            # Current-state invariants, one tamper each.
            "binding of a node without enrollment":
                ("INSERT INTO pairing_key_bindings VALUES (:other, :new_node, 1)",),
            "activated enrollment without credential":
                ("INSERT INTO pairing_key_bindings VALUES (:other, :new_node, 0)",
                 "INSERT INTO pairing_enrollments VALUES (:new_node, :new_node, :other, 'f', "
                 "'e', 0, 'activated')"),
            "credential without activation":
                ("INSERT INTO pairing_key_bindings VALUES (:other, :new_node, 0)",
                 "INSERT INTO pairing_node_credentials (node_id, public_key_digest, "
                 "credential_serial_digest, state) VALUES (:new_node, :other, :other, 'active')"),
            "revoked enrollment beside an active credential":
                ("UPDATE pairing_enrollments SET state='revoked' WHERE id=:pending",),
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
                          "other": "e" * 64, "new_node": str(uuid4())}
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

    def test_a_node_revoked_in_the_window_keeps_nothing_open(self):
        # Codex P1: revoke() revokes every open enrollment and binding of the
        # node, and a revoked node is re-paired as a new node (Owner decision
        # 2026-10-01); an approval left pending on it afterwards is not that.
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node = Owner(), uuid4()
        approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest="a" * 64)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest="a" * 64,
                              code=code.value)
        ledger.activate(claim, credential_serial_digest="b" * 64, not_after=50.0)
        _, baseline = self.record()
        ledger.revoke(owner, "owner", node_id=node)
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["security_state"]["failed"], [])
        ledger.approve(owner, "owner", node_id=node, public_key_digest="c" * 64)
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": f"pairing_revocation:{node}", "reason": "incomplete"},
                      report["sections"]["security_state"]["failed"])

    def test_a_revoked_node_reactivated_and_revoked_again_is_detected(self):
        # Codex P1: revoke -> fresh activation on the same node -> revoke ends
        # fully revoked, but the audit orders the activation after the first
        # revocation. An activation before the revocation (a retry, then
        # revoke) stays accepted.
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, nodes = Owner(), {"reopened": uuid4(), "retried": uuid4()}

        def pair(node, key, serial):
            approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key)
            claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest=key,
                                  code=code.value)
            ledger.activate(claim, credential_serial_digest=serial, not_after=50.0)
        pair(nodes["reopened"], "a" * 64, "b" * 64)
        pair(nodes["retried"], "c" * 64, "d" * 64)
        _, baseline = self.record()
        ledger.revoke(owner, "owner", node_id=nodes["reopened"])
        pair(nodes["reopened"], "e" * 64, "f" * 64)
        ledger.revoke(owner, "owner", node_id=nodes["reopened"])
        pair(nodes["retried"], "c" * 64, "9" * 64)
        ledger.revoke(owner, "owner", node_id=nodes["retried"])
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["security_state"]["failed"],
                         [{"id": f"pairing_revocation:{nodes['reopened']}",
                           "reason": "reopened"}])

    def test_a_promotion_on_a_revoked_node_needs_its_audit_before_the_revoke(self):
        # Codex P1: a promotion writes the activate audit row too and cannot
        # follow a revocation (which deletes the staged renewal); a revoked
        # credential showing the staged material without that row before
        # the revoke row is not a promotion.
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node = Owner(), uuid4()
        approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest="a" * 64)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest="a" * 64,
                              code=code.value)
        ledger.activate(claim, credential_serial_digest="b" * 64, not_after=50.0)
        stage_renewal(ledger, node_id=node, current_public_key_digest="a" * 64,
                      current_credential_digest="b" * 64, public_key_digest="c" * 64,
                      credential_serial_digest=renewal_serial("d"), not_after=90.0)
        _, baseline = self.record()
        ledger.revoke(owner, "owner", node_id=node)
        self.runtime.execute("UPDATE pairing_node_credentials SET public_key_digest=?, "
                             "credential_serial_digest=?, not_after=90.0 WHERE node_id=?",
                             ("c" * 64, renewal_serial("d"), str(node)))
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": f"pairing_revocation:{node}", "reason": "reopened"},
                      report["sections"]["security_state"]["failed"])

    def test_pairing_changes_without_their_ledger_audit_rows_fail(self):
        # Codex P1: every PairingLedger change writes its audit row in the same
        # transaction; the same end state written without it is not a ledger
        # transition (revoke, a fresh activation, a staged promotion).
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner = Owner()
        nodes = {label: uuid4() for label in ("revoked", "activated", "promoted")}

        def claim(node, key):
            approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key)
            return ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest=key,
                                 code=code.value)
        for index, node in enumerate(nodes.values()):
            ledger.activate(claim(node, f"{index + 1:064x}"),
                            credential_serial_digest="b" * 64, not_after=50.0)
        pending = claim(nodes["activated"], "a" * 64)
        stage_renewal(ledger, node_id=nodes["promoted"], current_public_key_digest=f"{3:064x}",
                      current_credential_digest="b" * 64, public_key_digest="c" * 64,
                      credential_serial_digest=renewal_serial("d"), not_after=90.0)
        _, baseline = self.record()
        execute = self.runtime.execute
        # revoke() without its audit row.
        execute("UPDATE pairing_node_credentials SET state='revoked' WHERE node_id=?",
                (str(nodes["revoked"]),))
        execute("UPDATE pairing_key_bindings SET revoked=1 WHERE node_id=?",
                (str(nodes["revoked"]),))
        # activate() of the consumed enrollment without its audit row.
        execute("UPDATE pairing_enrollments SET state='activated' WHERE id=?",
                (str(pending.enrollment_id),))
        execute("UPDATE pairing_node_credentials SET public_key_digest=?, "
                "credential_serial_digest=? WHERE node_id=?",
                ("a" * 64, "e" * 64, str(nodes["activated"])))
        # A promotion without its audit row.
        execute("UPDATE pairing_node_credentials SET public_key_digest=?, "
                "credential_serial_digest=?, not_after=90.0 WHERE node_id=?",
                ("c" * 64, renewal_serial("d"), str(nodes["promoted"])))
        execute("DELETE FROM pairing_node_renewals WHERE node_id=?", (str(nodes["promoted"]),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(sorted(report["sections"]["security_state"]["failed"],
                                key=lambda item: item["id"]),
                         sorted([{"id": f"pairing_audit:{nodes['revoked']}:"
                                        "revoke_capture_node_pairing", "reason": "unaudited"},
                                 {"id": f"pairing_audit:{nodes['activated']}:"
                                        "activate_capture_node_credential", "reason": "unaudited"},
                                 {"id": f"pairing_audit:{nodes['promoted']}:"
                                        "activate_capture_node_credential", "reason": "unaudited"}],
                                key=lambda item: item["id"]))

    def test_pairing_audit_evidence_must_be_a_ledger_row(self):
        # Codex P1: an audit row counts only if it loads through AuditStore's
        # own record validation and carries what the ledger writes: the
        # action's actor category, a capture-node target and this node's ID.
        cases = {"wrong-actor": ("invited_user", "capture_node", None),
                 "wrong-target-kind": ("owner", "principal", None),
                 "wrong-target-id": ("owner", "capture_node", "other"),
                 "ledger-shaped": ("owner", "capture_node", None)}
        for index, (label, (actor, target_kind, target)) in enumerate(cases.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"evidence-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    runtime.seed()
                    node = self._paired_node("a" * 64, "c" * 64)
                    runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)",
                                    ("a" * 64, node))
                    _, baseline = self.record(f"evidence-{index}.json")
                    runtime.execute("UPDATE pairing_node_credentials SET state='revoked'")
                    runtime.execute("UPDATE pairing_key_bindings SET revoked=1")
                    runtime.execute(
                        "INSERT INTO security_admin_audit_records VALUES (?, ?, "
                        "'revoke_capture_node_pairing', ?, ?, ?, 'succeeded')",
                        (str(uuid4()), actor, target_kind,
                         str(uuid4()) if target == "other" else node, runtime.clock))
                    _, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
                unaudited = {"id": f"pairing_audit:{node}:revoke_capture_node_pairing",
                             "reason": "unaudited"}
                if label == "ledger-shaped":
                    self.assertNotIn(unaudited, report["sections"]["security_state"]["failed"])
                else:
                    self.assertIn(unaudited, report["sections"]["security_state"]["failed"])

    def test_a_revoked_credential_keeps_no_live_binding(self):
        # Codex P1: revoke() leaves every binding of the node revoked, no open
        # enrollment and no staged renewal; a credential activated in the
        # window and then flipped to revoked with its binding live is not that.
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node = Owner(), uuid4()
        _, baseline = self.record()
        approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest="a" * 64)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest="a" * 64,
                              code=code.value)
        ledger.activate(claim, credential_serial_digest="b" * 64, not_after=50.0)
        self.runtime.execute("UPDATE pairing_node_credentials SET state='revoked' WHERE node_id=?",
                             (str(node),))
        code, report, _ = self.verify(baseline)
        self.assertIn({"id": f"pairing_credentials:{node}", "reason": "revocation_incomplete"},
                      report["sections"]["security_state"]["failed"])

    def test_every_new_binding_is_explained_by_its_own_key(self):
        # Codex P1: a binding added since the record, revoked or live, is an
        # enrollment's key, the staged or credential key, or (revoked only) a
        # key staged before a revocation of a node that had an active
        # credential in the window. A node revoked with only an open
        # enrollment never staged anything.
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node = Owner(), uuid4()
        ledger.approve(owner, "owner", node_id=node, public_key_digest="a" * 64)
        _, baseline = self.record()
        ledger.revoke(owner, "owner", node_id=node)
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["security_state"]["failed"], [])
        self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 1)",
                             ("e" * 64, str(node)))
        code, report, _ = self.verify(baseline)
        failed = report["sections"]["security_state"]["failed"]
        self.assertEqual([item["reason"] for item in failed
                          if item["id"].startswith("pairing_key_bindings:")], ["unexplained"])

    def test_bindings_stay_within_the_ledger_capacity(self):
        # stage_renewal() binds a new key only below PairingLedger's per-node
        # cap; approve() adds at most one binding per enrollment.
        from app.cameras.remote_agent.pairing import _MAX_KEY_BINDINGS_PER_NODE
        self.runtime.seed()
        node = self._paired_node("a" * 64, "c" * 64)
        with closing(sqlite3.connect(self.runtime.database, isolation_level=None)) as db:
            db.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", ("a" * 64, node))
            db.executemany("INSERT INTO pairing_key_bindings VALUES (?, ?, 1)",
                           [(f"{index:064x}", node)
                            for index in range(1, _MAX_KEY_BINDINGS_PER_NODE + 2)])
        self.assert_record_refused("security_state:over_capacity=1")

    def test_a_staged_renewal_is_never_restaged_onto_a_superseded_key(self):
        # Codex P1: stage_renewal() accepts a key already bound to the node
        # only as a retry of the currently staged key.
        self.runtime.seed()
        node = self._paired_node("a" * 64, "c" * 64)
        superseded, staged = "b" * 64, "d" * 64
        for key in ("a" * 64, superseded, staged):
            self.runtime.execute("INSERT INTO pairing_key_bindings VALUES (?, ?, 0)", (key, node))
        self.runtime.execute("INSERT INTO pairing_node_renewals VALUES (?, ?, ?, 20.0, NULL)",
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

    def test_an_owner_who_cannot_authenticate_is_not_present(self):
        # Codex P1: the passkey ceremony admits only an active, unrevoked
        # Owner with an active (not revoked, not inconsistent) credential.
        tampers = {
            "revoked-owner": "UPDATE access_principals SET status='revoked', revoked_at_us=5 "
                             "WHERE id=:owner",
            "inactive-owner": "UPDATE access_principals SET status='invited' WHERE id=:owner",
            "no-credential": "DELETE FROM access_credentials WHERE principal_id=:owner",
            "revoked-credentials": "UPDATE access_credentials SET revoked_at_us=5 "
                                   "WHERE principal_id=:owner",
            "inconsistent-credentials": "UPDATE access_credentials SET inconsistent_at_us=5, "
                                        "inconsistency_reason='backup_eligibility_changed' "
                                        "WHERE principal_id=:owner",
        }
        for index, (label, statement) in enumerate(tampers.items()):
            with self.subTest(label):
                runtime = Runtime(self.base / f"owner-{index}")
                saved, self.runtime = self.runtime, runtime
                try:
                    seeded = runtime.seed()
                    _, baseline = self.record(f"owner-good-{index}.json")
                    with closing(sqlite3.connect(runtime.database, isolation_level=None)) as db:
                        db.execute("DELETE FROM access_sessions")
                        db.execute(statement, {"owner": seeded["owner"]})
                    # Recording such a state never succeeds ...
                    code, recorded = self.record(f"owner-bad-{index}.json")
                    self.assertEqual(code, inventory.EXIT_EMPTY)
                    self.assertEqual(json.loads(recorded.read_text())["coverage"]["owner"],
                                     "empty")
                    # ... and reaching it from a good record is a failure.
                    code, report, _ = self.verify(baseline)
                finally:
                    self.runtime = saved
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
        # record refuses the state; verify would fail it unchanged.
        self.assert_record_refused("recordings:catalog_mismatch=2")

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
        # A baseline holding the corrupt segment is never written, so no
        # later stop can drop it into a passing result.
        self.assert_record_refused("recordings:catalog_mismatch=1")

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

    def test_unchanged_recordings_need_segments_the_store_would_link(self):
        # Codex P1: the segment checks apply to every accepted recording, not
        # only to growth: an unchanged one whose segment the store would have
        # refused, or that belongs to another source, is not preserved.
        seeded = self.runtime.seed()
        with closing(sqlite3.connect(self.runtime.database)) as connection:
            segments = {key: connection.execute(
                "SELECT segment_id FROM recording_links WHERE recording_id=?",
                (seeded[key],)).fetchone()[0] for key in ("ordinary", "starred")}
        self.runtime.execute("UPDATE recording_segments SET codec='Bad Codec' WHERE id=?",
                             (segments["ordinary"],))
        self.runtime.execute("UPDATE recording_segments SET source_id=? WHERE id=?",
                             (str(uuid4()), segments["starred"]))
        self.assert_record_refused("recordings:invalid_segment=2")

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


    def test_a_staged_renewal_certificate_must_be_the_staged_certificate(self):
        # Migration 21 (#136): pairing_node_renewals.certificate_pem is NULL
        # (a row staged before the migration) or exactly one PEM certificate
        # whose DER SHA-256 is the staged serial digest, as
        # pairing._certificate_pem() checks it. A certificate once staged
        # stays with its row (a retry of the staged key keeps the row).
        self.runtime.seed()
        database = Database(self.runtime.database)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32), audit=AuditStore(database),
                               clock=lambda: 100.0, process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        owner, node = Owner(), uuid4()
        approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest="a" * 64)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest="a" * 64,
                              code=code.value)
        ledger.activate(claim, credential_serial_digest="b" * 64, not_after=50.0)
        serial = renewal_serial("staged-certificate")
        stage_renewal(ledger, node_id=node, current_public_key_digest="a" * 64,
                      current_credential_digest="b" * 64, public_key_digest="c" * 64,
                      credential_serial_digest=serial, not_after=90.0)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        pem = renewal_certificate(serial).decode("ascii")
        other = renewal_certificate(renewal_serial("another-certificate")).decode("ascii")
        corrupted = {"another certificate": other, "not a certificate": "synthetic-not-a-pem",
                     "two certificates": pem + pem, "truncated": pem[:-40],
                     "not text": pem.encode("ascii")}
        for label, value in corrupted.items():
            with self.subTest(label):
                self.runtime.execute("UPDATE pairing_node_renewals SET certificate_pem=? "
                                     "WHERE node_id=?", (value, str(node)))
                code, report, _ = self.verify(baseline)
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertIn({"id": f"pairing_node_renewals:{node}", "reason": "invalid_value"},
                              report["sections"]["security_state"]["failed"])
                self.assert_record_refused("security_state:invalid_value")
        # The staged certificate vanishing from its kept row is not a ledger path.
        self.runtime.execute("UPDATE pairing_node_renewals SET certificate_pem=NULL "
                             "WHERE node_id=?", (str(node),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["security_state"]["failed"],
                         [{"id": f"pairing_renewals:{node}", "reason": "changed"}])
        # A row staged before migration 21 (no certificate) gets one from a
        # retry of its key, which stages the retry's certificate.
        _, before_migration = self.record("before-migration.json")
        retried = renewal_serial("retried-certificate")
        staged = stage_renewal(ledger, node_id=node, current_public_key_digest="a" * 64,
                               current_credential_digest="b" * 64, public_key_digest="c" * 64,
                               credential_serial_digest=retried, not_after=95.0)
        self.assertEqual(staged.certificate_pem, renewal_certificate(retried))
        code, report, _ = self.verify(before_migration)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])

    def test_a_pending_session_revocation_leaves_only_with_its_revocation(self):
        # #134: application_metadata holds the reservation exposure marker;
        # it may only disappear through ReservationSessionRevocation, which
        # advances the authorization generation, invalidates every human
        # session and appends a system invalidate_human_sessions audit row in
        # the same transaction.
        from app.auth.reservation_store import (REVOCATION_PENDING_KEY,
                                                ReservationSessionRevocation)
        from app.auth.store import AccessStore
        self.runtime.seed()
        database = Database(self.runtime.database)
        revocation = ReservationSessionRevocation(
            AccessStore(database, audit=AuditStore(database)))
        revocation.record_exposure()
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        recorded = json.loads(baseline.read_text())
        self.assertEqual(recorded["security_state"]["session_revocation_pending"], "present")
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["security_state"])
        marker = {"id": "session_revocation_pending", "reason": "cleared_without_revocation"}
        # An update that drops the marker without the revocation.
        self.runtime.execute("DELETE FROM application_metadata WHERE key=?",
                             (REVOCATION_PENDING_KEY,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["security_state"]["failed"], [marker])
        # An audit row alone, with the sessions and generation untouched.
        self.runtime.execute(
            "INSERT INTO security_admin_audit_records VALUES (?, 'system', "
            "'invalidate_human_sessions', 'security_settings', "
            "'0b6f3f64-54a9-4e0f-8f5e-7d2c9a4b1e37', ?, 'succeeded')",
            (str(uuid4()), self.runtime.clock))
        code, report, _ = self.verify(baseline)
        self.assertIn(marker, report["sections"]["security_state"]["failed"])
        # A marker the service cannot read (it refuses to open access).
        self.runtime.execute("INSERT INTO application_metadata VALUES (?, '0')",
                             (REVOCATION_PENDING_KEY,))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertIn({"id": "session_revocation_pending", "reason": "invalid_value"},
                      report["sections"]["security_state"]["failed"])
        self.assert_record_refused("security_state:invalid_value")
        self.runtime.execute("UPDATE application_metadata SET value='1' WHERE key=?",
                             (REVOCATION_PENDING_KEY,))
        # The service path clears it with its revocation. Its generation
        # advance also ends every recorded invitation, which verify reports
        # as changed invitations (documented fail-closed side effect).
        revocation.revoke_all_human_sessions()
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["security_state"],
                         {"status": "preserved", "failed": []})
        self.assertEqual({name for name, section in report["sections"].items()
                          if section["status"] == "failed"}, {"access_invitations"})

    def _recording_store(self, connection):
        from app.media.recording import RecordingStore, RootIdentity
        from app.media.recording.model import Limits
        from tests.test_recording import Reservation, SyntheticValidator
        media = self.runtime.root / "recordings"
        info = media.stat()
        store = RecordingStore(connection, media, RootIdentity(info.st_dev, info.st_ino),
                               Limits(pre_roll_bytes=4096, max_segment_bytes=512,
                                      max_segment_ms=30_000, max_active_recordings=8,
                                      max_spool_segments=16, max_segments_per_recording=100),
                               Reservation(), SyntheticValidator())
        self.addCleanup(store.close)
        return store

    def test_ready_spool_segments_need_their_files(self):
        # Codex P1: RecordingStore._start() links every overlapping ready
        # spool row without re-validating it, so a ready spool=1 row whose
        # .seg file is missing or differs from its catalog digest / length /
        # single link would hand the next recording missing media.
        import zlib
        from app.media.recording import Segment
        self.runtime.seed()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        source, stream_id = uuid4(), uuid4()
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        spooled = [store.append(Segment(source, stream_id, sequence, base + sequence * 10_000,
                                        base + (sequence + 1) * 10_000, "synthetic", "deflate",
                                        payload)) for sequence in range(2)]
        with closing(sqlite3.connect(self.runtime.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM recording_segments WHERE "
                                        "state='ready' AND spool=1 AND source_id=?",
                                        (str(source),)).fetchone()[0], 2)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        media = self.runtime.root / "recordings"
        path = media / (spooled[0].hex + ".seg")
        expected = {"id": f"spool:{spooled[0]}", "reason": "spool_file_mismatch"}
        saved = path.read_bytes()
        for label, tamper in (("missing", path.unlink),
                              ("replaced", lambda: path.write_bytes(bytes(len(saved)))),
                              ("hard-linked", lambda: os.link(path, self.notes / "spool-link"))):
            with self.subTest(label):
                tamper()
                code, report, _ = self.verify(baseline)
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertEqual(report["sections"]["recordings"]["failed"], [expected])
                self.assert_record_refused("recordings:spool_file_mismatch=1")
                (self.notes / "spool-link").unlink(missing_ok=True)
                path.unlink(missing_ok=True)
                path.write_bytes(saved)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["recordings"])

    def test_first_segment_marker_of_a_recording_without_evidence_is_required(self):
        # Codex P1: a recording with no linked segment at record time keeps
        # the "no evidence" rule (Owner decision 2026-10-05), but the marker
        # RecordingStore._publish() adds when its first segment does not
        # continue the source cursor recorded then must not vanish.
        import zlib
        from app.media.recording import Segment
        self.runtime.seed()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        switching, lagging = uuid4(), uuid4()
        stream_a, stream_b = uuid4(), uuid4()

        def put(source, stream_id, sequence, start, end):
            return store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                        "synthetic", "deflate", payload))
        for source in (switching, lagging):
            for sequence in range(3):
                put(source, stream_a, sequence, sequence * 10_000, (sequence + 1) * 10_000)
        switches = store.start_manual(switching, base + 60_000, duration_ms=20_000)
        lags = store.start_manual(lagging, base + 60_000, duration_ms=20_000)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        recorded = json.loads(baseline.read_text())
        self.assertEqual(recorded["recordings"][str(switches)]["evidence"], "no_evidence")
        # A stream change: the publication adds (cursor end, start).
        put(switching, stream_b, 0, 64_000, 72_000)
        # An unlinked segment published before the window first moves the
        # cursor; the linked one continues it, so no marker is due.
        put(lagging, stream_a, 3, 40_000, 50_000)
        put(lagging, stream_a, 4, 50_000, 66_000)
        with closing(sqlite3.connect(self.runtime.database)) as db:
            markers = db.execute("SELECT recording_id, start_ms, end_ms FROM "
                                 "recording_discontinuities").fetchall()
        self.assertEqual(markers, [(str(switches), base + 30_000, base + 64_000)])
        code, report, _ = self.verify(baseline)
        section = report["sections"]["recordings"]
        self.assertEqual(code, inventory.EXIT_PRESERVED, section)
        self.assertEqual(sorted(section["in_progress_at_record"]),
                         sorted([str(switches), str(lags)]))
        self.runtime.execute("DELETE FROM recording_discontinuities WHERE recording_id=?",
                             (str(switches),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(switches), "reason": "changed"}])
        # A marker that starts before the recorded cursor end is not one the
        # publication adds either.
        self.runtime.execute("INSERT INTO recording_discontinuities VALUES "
                             "(?, ?, ?, 'stream_discontinuity')",
                             (str(switches), base + 20_000, base + 64_000))
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(switches), "reason": "changed"}])

    def test_an_overlapping_publication_never_explains_a_cursor_advance(self):
        # Codex P1: RecordingStore._publish() links every publication that
        # overlaps an active recording's window. For a recording without
        # evidence at record time, a still-spooled overlapping segment whose
        # link was deleted must fail as a lost link, never stand in as the
        # unlinked predecessor that excuses the next segment's marker.
        import zlib
        from app.media.recording import Segment
        self.runtime.seed()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        source, stream_id = uuid4(), uuid4()

        def put(sequence, start, end):
            return store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                        "synthetic", "deflate", payload))
        for sequence in range(3):
            put(sequence, sequence * 10_000, (sequence + 1) * 10_000)
        recording = store.start_manual(source, base + 60_000, duration_ms=20_000)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        # Both overlap the window, so _publish() links both; the first one,
        # not continuing the recorded cursor (end 30 000), adds a marker.
        overlapping = put(3, 60_000, 68_000)
        put(4, 68_000, 76_000)
        with closing(sqlite3.connect(self.runtime.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM recording_links WHERE "
                                        "recording_id=?", (str(recording),)).fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT spool FROM recording_segments WHERE id=?",
                                        (str(overlapping),)).fetchone()[0], 1)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["recordings"])
        # Codex's repro: only the first link is lost (its marker with it).
        self.runtime.execute("DELETE FROM recording_links WHERE segment_id=?",
                             (str(overlapping),))
        self.runtime.execute("DELETE FROM recording_discontinuities WHERE recording_id=?",
                             (str(recording),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(recording), "reason": "changed"}])
        # Keeping the marker does not make the lost link acceptable either.
        self.runtime.execute("INSERT INTO recording_discontinuities VALUES "
                             "(?, ?, ?, 'stream_discontinuity')",
                             (str(recording), base + 30_000, base + 60_000))
        code, report, _ = self.verify(baseline)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(recording), "reason": "changed"}])

    def test_a_publication_overlapping_a_grown_recording_must_stay_linked(self):
        # The same _publish() rule for a recording that already had evidence
        # at record time: a segment published while it was active and
        # overlapping its window cannot leave it while later ones stay.
        import zlib
        from app.media.recording import Segment
        self.runtime.seed()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        source, stream_a, stream_b = uuid4(), uuid4(), uuid4()

        def put(stream_id, sequence, start, end):
            return store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                        "synthetic", "deflate", payload))
        recording = store.start_manual(source, base, duration_ms=60_000)
        put(stream_a, 0, 0, 10_000)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        # A stream change then a continuation: the dropped middle link leaves
        # the remaining publications looking like a single stream change.
        middle = put(stream_b, 0, 10_000, 20_000)
        put(stream_b, 1, 20_000, 30_000)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["recordings"])
        with closing(sqlite3.connect(self.runtime.database)) as db:
            marker = db.execute("SELECT start_ms, end_ms FROM recording_discontinuities "
                                "WHERE recording_id=?", (str(recording),)).fetchone()
        self.runtime.execute("DELETE FROM recording_links WHERE segment_id=?", (str(middle),))
        self.runtime.execute("UPDATE recording_discontinuities SET end_ms=? WHERE recording_id=?",
                             (base + 20_000, str(recording)))
        self.assertEqual(marker, (base + 10_000, base + 10_000))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(recording), "reason": "changed"}])

    def test_every_overlapping_publication_since_the_record_stays_linked(self):
        # Codex P1: _publish() links every publication overlapping a recording
        # that is active, so for each recording active at record time every
        # still-catalogued publication since the record that overlaps its
        # window (the final one after a stop) must be linked, whether the row
        # changed or not and wherever the publication lies in the window.
        import zlib
        from app.media.recording import Segment
        payload = zlib.compress(b"generated geometric test payload" * 4)

        def scenario(label, prepare):
            runtime = Runtime(self.base / f"links-{label}")
            saved, self.runtime = self.runtime, runtime
            try:
                runtime.seed()
                connection = sqlite3.connect(runtime.database, isolation_level=None)
                self.addCleanup(connection.close)
                store = self._recording_store(connection)
                base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
                source, stream_id = uuid4(), uuid4()

                def put(sequence, start, end):
                    return store.append(Segment(source, stream_id, sequence, base + start,
                                                base + end, "synthetic", "deflate", payload))
                put(0, 0, 10_000)
                recording = store.start_manual(source, base + 10_000, duration_ms=40_000)
                code, baseline = self.record(f"links-{label}.json")
                self.assertEqual(code, inventory.EXIT_PRESERVED)
                lost = prepare(store, put, recording, base)
                code, report, _ = self.verify(baseline)
                self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["recordings"])
                runtime.execute("DELETE FROM recording_links WHERE segment_id=?", (str(lost),))
                code, report, _ = self.verify(baseline)
                return code, report, recording
            finally:
                self.runtime = saved

        def sole(store, put, recording, base):
            # The only publication since the record: the row is unchanged
            # again once its link is gone.
            return put(1, 10_000, 20_000)

        def trailing(store, put, recording, base):
            put(1, 10_000, 20_000)
            return put(2, 20_000, 30_000)

        def stopped(store, put, recording, base):
            put(1, 10_000, 20_000)
            kept = put(2, 20_000, 30_000)
            put(3, 30_000, 40_000)
            # Early stop inside the third segment: finish() keeps the links
            # overlapping the final window and drops the fourth one.
            store.finish(recording, stop_ms=base + 25_000)
            return kept

        for label, prepare in (("sole", sole), ("trailing", trailing), ("stopped", stopped)):
            with self.subTest(label):
                code, report, recording = scenario(label, prepare)
                self.assertEqual(code, inventory.EXIT_FAILED)
                self.assertEqual(report["sections"]["recordings"]["failed"],
                                 [{"id": str(recording), "reason": "changed"}])

    def test_publications_outside_a_stopped_window_need_no_link(self):
        # finish() drops the links of segments wholly outside the stopped
        # window, so those stay catalogued without a link and still verify.
        import zlib
        from app.media.recording import Segment
        self.runtime.seed()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        source, stream_id = uuid4(), uuid4()

        def put(sequence, start, end):
            return store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                        "synthetic", "deflate", payload))
        put(0, 0, 10_000)
        recording = store.start_manual(source, base + 10_000, duration_ms=40_000)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        put(1, 10_000, 20_000)
        dropped = put(2, 20_000, 30_000)
        store.finish(recording, stop_ms=base + 20_000)
        with closing(sqlite3.connect(self.runtime.database)) as db:
            self.assertIsNone(db.execute("SELECT 1 FROM recording_links WHERE segment_id=?",
                                         (str(dropped),)).fetchone())
            self.assertEqual(db.execute("SELECT spool FROM recording_segments WHERE id=?",
                                        (str(dropped),)).fetchone()[0], 1)
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["recordings"])

    def test_a_released_publication_still_needs_its_link(self):
        # Codex P1: release_source() clears spool on every segment of the
        # source, linked ones included. A link lost after that must still
        # fail: the publications since the record are every ready catalog
        # row of the source past the recorded cursor, whatever its spool flag.
        import zlib
        from app.media.recording import Segment
        self.runtime.seed()
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        source, stream_id = uuid4(), uuid4()

        def put(sequence, start, end):
            return store.append(Segment(source, stream_id, sequence, base + start, base + end,
                                        "synthetic", "deflate", payload))
        put(0, 0, 10_000)
        recording = store.start_manual(source, base + 10_000, duration_ms=40_000)
        code, baseline = self.record()
        self.assertEqual(code, inventory.EXIT_PRESERVED)
        linked = put(1, 10_000, 20_000)
        store.release_source(source)
        with closing(sqlite3.connect(self.runtime.database)) as db:
            self.assertEqual(db.execute("SELECT state, spool FROM recording_segments WHERE id=?",
                                        (str(linked),)).fetchone(), ("ready", 0))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_PRESERVED, report["sections"]["recordings"])
        self.runtime.execute("DELETE FROM recording_links WHERE segment_id=?", (str(linked),))
        code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual(report["sections"]["recordings"]["failed"],
                         [{"id": str(recording), "reason": "changed"}])

    def test_a_published_segment_never_becomes_pending(self):
        # Codex P1: RecordingStore._recover() deletes every pending row and
        # its .seg file at the next start. A published segment reset to the
        # pending shape (state, spool=0, integrity='unchecked') with its link
        # dropped must fail before that startup makes the loss permanent.
        import zlib
        from app.media.recording import Segment
        payload = zlib.compress(b"generated geometric test payload" * 4)

        def scenario(label, after_record):
            runtime = Runtime(self.base / f"pending-{label.replace(' ', '-')}")
            saved, self.runtime = self.runtime, runtime
            try:
                runtime.seed()
                connection = sqlite3.connect(runtime.database, isolation_level=None)
                self.addCleanup(connection.close)
                store = self._recording_store(connection)
                base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
                source, stream_id = uuid4(), uuid4()

                def put(sequence, start, end):
                    return store.append(Segment(source, stream_id, sequence, base + start,
                                                base + end, "synthetic", "deflate", payload))
                spooled = put(0, 0, 10_000)
                recording = store.start_manual(source, base + 10_000, duration_ms=40_000)
                code, baseline = self.record(f"pending-{label.replace(' ', '-')}.json")
                self.assertEqual(code, inventory.EXIT_PRESERVED)
                target = spooled if after_record is None else put(1, 10_000, 20_000)
                code, report, _ = self.verify(baseline)
                self.assertEqual(code, inventory.EXIT_PRESERVED,
                                 report["sections"]["recordings"])
                runtime.execute("UPDATE recording_segments SET state='pending', spool=0, "
                                "integrity='unchecked' WHERE id=?", (str(target),))
                runtime.execute("DELETE FROM recording_links WHERE segment_id=?",
                                (str(target),))
                if label == "cursor dropped":
                    # Also drop the cursor so the current state alone looks
                    # like an append on a source never published.
                    runtime.execute("DELETE FROM recording_source_cursors WHERE source_id=?",
                                    (str(source),))
                code, report, _ = self.verify(baseline)
                return code, report, target, recording
            finally:
                self.runtime = saved

        for label in ("spooled at record", "published since", "cursor dropped"):
            with self.subTest(label):
                code, report, target, recording = scenario(
                    label, "published" if label == "published since" else None)
                self.assertEqual(code, inventory.EXIT_FAILED)
                failed = report["sections"]["recordings"]["failed"]
                if label == "cursor dropped":
                    # The record still shows it was published.
                    self.assertIn({"id": f"segment:{target}",
                                   "reason": "published_segment_pending"}, failed)
                else:
                    self.assertIn({"id": f"segment:{target}", "reason": "invalid_value"},
                                  failed)

    def test_malformed_values_never_abort_verification(self):
        # Codex P1: a wrong-typed value must be reported, never raise. Every
        # column of the in-scope tables gets each wrong type in turn on a
        # state real services wrote; verify always writes its report. In the
        # recording tables (rows, links, segments, markers, cursors) every
        # such change fails; elsewhere a column outside the compared set
        # (labels, display names, last-use times) may stay preserved.
        import zlib
        from app.auth.reservation_store import ReservationSessionRevocation
        from app.auth.store import AccessStore
        from app.media.recording import Segment
        self.runtime.seed()
        database = Database(self.runtime.database)
        ReservationSessionRevocation(
            AccessStore(database, audit=AuditStore(database))).record_exposure()
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32), audit=AuditStore(database),
                               clock=lambda: 100.0, process_epoch=uuid4())

        class Owner:
            def require_owner(self, actor_context):
                if actor_context != "owner":
                    raise PermissionError("synthetic denial")
        node = uuid4()
        approval, code = ledger.approve(Owner(), "owner", node_id=node,
                                        public_key_digest="a" * 64)
        ledger.activate(ledger.redeem(enrollment_id=approval.enrollment_id,
                                      public_key_digest="a" * 64, code=code.value),
                        credential_serial_digest="b" * 64, not_after=50.0)
        stage_renewal(ledger, node_id=node, current_public_key_digest="a" * 64,
                      current_credential_digest="b" * 64, public_key_digest="c" * 64,
                      credential_serial_digest=renewal_serial("fuzz"), not_after=90.0)
        connection = sqlite3.connect(self.runtime.database, isolation_level=None)
        self.addCleanup(connection.close)
        store = self._recording_store(connection)
        payload = zlib.compress(b"generated geometric test payload" * 4)
        base = int((self.now - timedelta(hours=1)).timestamp() * 1000)
        source, stream_id = uuid4(), uuid4()
        store.append(Segment(source, stream_id, 0, base, base + 10_000, "synthetic", "deflate",
                             payload))
        recording = store.start_manual(source, base + 5_000, duration_ms=40_000)
        store.append(Segment(source, stream_id, 1, base + 10_000, base + 20_000, "synthetic",
                             "deflate", payload))
        connection.execute("INSERT INTO recording_discontinuities VALUES "
                           "(?, ?, ?, 'stream_discontinuity')",
                           (str(recording), base + 6_000, base + 7_000))
        store.close()
        connection.close()
        code, baseline = self.record()
        self.assertIn(code, (inventory.EXIT_PRESERVED, inventory.EXIT_FAILED))
        self.assertTrue(baseline.exists())
        tables = ("recordings", "recording_links", "recording_segments",
                  "recording_discontinuities", "recording_source_cursors",
                  "security_admin_audit_records", "integrity_audit", "presence_audit",
                  "storage_state_audit", "access_principals", "access_principal_permissions",
                  "access_credentials", "access_invitations", "access_sessions",
                  "access_deployment_state", "pairing_node_credentials", "pairing_enrollments",
                  "pairing_node_renewals", "pairing_key_bindings", "application_metadata",
                  "schema_migrations")
        recording_tables = {"recordings", "recording_links", "recording_segments",
                            "recording_discontinuities", "recording_source_cursors"}
        values = {"text": "synthetic-malformed", "blob": b"\x00\x01", "null": None,
                  "real": 1.5, "huge": 2**63 - 1, "negative": -(2**63)}
        original = self.runtime.database.read_bytes()
        crashes, silent = [], []
        with closing(sqlite3.connect(self.runtime.database)) as db:
            columns = {table: [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
                       for table in tables}
        for table in tables:
            for column in columns[table]:
                for label, value in values.items():
                    self.runtime.database.write_bytes(original)
                    try:
                        with closing(sqlite3.connect(self.runtime.database,
                                                     isolation_level=None)) as db:
                            # Only rows the update really changes (value and
                            # storage type); a no-op is not a tamper.
                            changed = db.execute(
                                f"UPDATE {table} SET {column}=?1 WHERE {column} IS NOT ?1 "
                                f"OR typeof({column}) IS NOT typeof(?1)", (value,)).rowcount
                    except sqlite3.Error:
                        continue  # the schema itself refuses it
                    if not changed:
                        continue
                    try:
                        code, report, _ = self.verify(baseline)
                    except Exception as exc:  # noqa: BLE001 - collected for the report
                        frame = [item for item in traceback.extract_tb(exc.__traceback__)
                                 if item.filename.endswith("lifecycle_inventory.py")][-1]
                        crashes.append(f"{table}.{column}={label}: {type(exc).__name__} "
                                       f"at {frame.name}:{frame.lineno}")
                        continue
                    if "unverifiable" in report:
                        # Only the last-resort net caught it: a rule crashed.
                        crashes.append(f"{table}.{column}={label}: {report['unverifiable']}")
                    if code != inventory.EXIT_FAILED and table in recording_tables:
                        silent.append(f"{table}.{column}={label}")
        self.runtime.database.write_bytes(original)
        self.maxDiff = None
        self.assertEqual(crashes, [])
        self.assertEqual(silent, [])
        # The last-resort net: an unanticipated value still yields a failed report.
        with mock.patch.object(inventory, "compare", side_effect=TypeError("synthetic")):
            code, report, _ = self.verify(baseline)
        self.assertEqual(code, inventory.EXIT_FAILED)
        self.assertEqual((report["status"], report["unverifiable"]), ("failed", "TypeError"))

if __name__ == "__main__":
    unittest.main()
