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
                    catalog_payload: bytes | None = None) -> str:
        segment_id = str(uuid4())
        if write_file:
            self.segment_file(segment_id, payload)
        self.execute(
            "INSERT INTO recording_segments (id, source_id, stream_id, sequence, start_ms, "
            "end_ms, codec, container, byte_length, sha256, state, spool) "
            "VALUES (?, ?, 's', ?, 10000, 20000, 'synthetic', 'deflate', ?, ?, 'ready', 0)",
            (segment_id, str(uuid4()), self.clock, len(payload),
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
            "INSERT INTO access_principals VALUES (?, ?, ?, ?, ?, 0, 1, ?)",
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
            "INSERT INTO access_invitations VALUES (?, ?, ?, 0, 0, 1, 2, NULL, ?)",
            (invitation_id, digest, principal_id, 3 if revoked else None))
        return invitation_id

    def seed(self) -> dict:
        owner = self.principal("owner", ())
        live = self.principal("invited_user", ("live:view",))
        recordings = self.principal("invited_user", ("recordings:view",))
        revoked = self.principal("invited_user", ("live:view", "recordings:view"),
                                 status="revoked", revoked=True)
        self.execute("INSERT INTO access_credentials VALUES (?, ?, X'00', -7, 0, 1, NULL)",
                     (CREDENTIAL_ID, owner))
        self.execute(
            "INSERT INTO access_sessions VALUES (?, ?, ?, ?, 0, 0, 1, 1, 10, 11, 20, NULL)",
            (str(uuid4()), TOKEN_DIGEST, owner, CREDENTIAL_ID))
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
                           "external_identity", "display_name", "secret_digest",
                           "token_digest", "public_key"):
                self.assertNotIn(marker, text, path.name)

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
        self.assertEqual(item["catalog_duration_ms"], 10000)
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
        path.write_bytes(bytes(reversed(path.read_bytes())))
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


if __name__ == "__main__":
    unittest.main()
