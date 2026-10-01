"""Synthetic lifecycle preservation inventory tests (Issue #47).

All rows, identities, secrets and segment bytes are generated placeholders;
no real person, deployment value or playable media is involved.
"""

from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
from tempfile import TemporaryDirectory
import unittest
from uuid import UUID, uuid4

from app import lifecycle_inventory as inventory
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
            "VALUES (?, ?, 's', ?, 0, 10000, 'synthetic', 'deflate', ?, ?, 'ready', 0)",
            (segment_id, source_id, self.clock, len(payload),
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
        self._directory = TemporaryDirectory()
        self.base = Path(self._directory.name)
        self.runtime = Runtime(self.base)
        self.notes = self.base / "notes"
        self.notes.mkdir(mode=0o700)

    def tearDown(self):
        self._directory.cleanup()

    def record(self, name="baseline.json") -> tuple[int, Path]:
        output = self.notes / name
        code, _, _ = run("record", "--runtime-root", str(self.runtime.root),
                         "--output", str(output))
        return code, output

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
                "device_path": path, "vendor": "1d6b", "product": "0102",
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
        for label in ("disabled", "profile", "binding", "approval", "requires"):
            self.assertIn({"id": ids[label], "reason": "changed"}, section["failed"])
        for path in self.notes.iterdir():
            text = path.read_text()
            for marker in (serial, device, "synthetic-by-id-marker", "synthetic-topology-marker",
                           "synthetic-session-", "1d6b"):
                self.assertNotIn(marker, text, path.name)

    def test_presence_and_storage_audit_rows_are_preserved(self):
        self.runtime.seed()
        for index in range(3):
            self.runtime.execute(
                "INSERT INTO presence_audit (action, actor, at, state, target) "
                "VALUES ('override', 'owner', ?, 'away', NULL)", (f"2026-01-0{index + 1}",))
            self.runtime.execute(
                "INSERT INTO storage_state_audit (at_ms, previous_state, current_state) "
                "VALUES (?, 'normal', 'pressure')", (index,))
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
