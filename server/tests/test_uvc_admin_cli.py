"""Issue #11 / Owner decision D3: the local camera administration command.

Synthetic only: a temporary SQLite database, a pseudo-terminal standing in
for the controlling terminal, a fake device discovery with invented USB ids,
serials and paths, and a fake ``/proc`` tree. No real ``/dev/video*`` device
is opened and no real terminal or service is used; mock only.
"""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from app.audit.integration import (
    CaptureNodeNotPairedError, CaptureNodeRevokedError, OwnerAdministration,
)
from app.audit.service import DenyAllOwners, OwnerAuditService, OwnerAuthorizationError
from app.audit.store import AuditStore
from app.cameras.registry import CameraRegistry, CaptureProfile, SourceType
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.cameras.uvc import admin_cli
from app.cameras.uvc.discovery import DiscoveryResult
from app.cameras.uvc.identity import DeviceEvidence
from app.cameras.uvc.persistence import ApprovalStore
from app.cameras.uvc.session_ledger import (
    ProcessIdentity, SessionLedger, current_process_identity, ledger_path, marker_digest,
)
from app.local_admin import CliRefused
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_bootstrap_cli import Console


AUDIT = ("SELECT actor_category, action, target_kind, target_logical_id, outcome "
         "FROM security_admin_audit_records ORDER BY rowid")
PROFILE = "1920x1080@30/MJPG"


def camera(number, serial="SYNTHSERIAL0001", *, port="1-3", formats=("MJPG", "YUYV")):
    return DeviceEvidence(
        f"/dev/video{number}", "1d6b", "0102", serial, "0",
        (f"usb-Synthetic_Cam_{serial}-video-index0",) if serial else (),
        f"devices/pci0000:00/0000:00:14.0/usb1/{port}", formats,
        os.makedev(81, number), (1, 1000 + number, 5000 + number))


# Every private value a fixture camera carries; none may be printed.
PRIVATE = ("SYNTHSERIAL", "/dev/video", "usb-Synthetic_Cam", "pci0000", "usb1/")


class FakeDiscovery:
    def __init__(self, devices=(), failures=0):
        self.devices = tuple(devices)
        self.failures = failures
        self.scans = 0

    def scan(self):
        self.scans += 1
        return DiscoveryResult(self.devices, self.failures)


class _LedgerOwner:
    def require_owner(self, actor_context):
        if actor_context != "owner":
            raise PermissionError("synthetic denial")


def _ledger(database):
    return PairingLedger(database, HmacCodeVerifier(b"s" * 32), audit=AuditStore(database))


def pair_node(database, index, *, revoked=False):
    """A node paired through the real ledger (approve, redeem, activate); synthetic digests."""
    ledger = _ledger(database)
    key = f"{index:x}" * 64
    approval, code = ledger.approve(_LedgerOwner(), "owner", node_id=uuid4(), public_key_digest=key)
    claim = ledger.redeem(enrollment_id=approval.enrollment_id, public_key_digest=key,
                          code=code.value)
    ledger.activate(claim, credential_serial_digest=f"{index + 1:x}" * 64)
    if revoked:
        revoke_node(database, claim.node_id)
    return claim.node_id


def revoke_node(database, node):
    _ledger(database).revoke(_LedgerOwner(), "owner", node_id=node)


# The registry's own audit records (the ledger's pairing records left out).
SOURCE_AUDIT = AUDIT.replace(
    "ORDER BY", "WHERE action IN ('create_source', 'create_capture_node', 'approve_camera', "
                "'update_source') ORDER BY")


class AdminCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.path = self.root / "state.sqlite3"
        self.database = Database(self.path)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        os.chmod(self.path, 0o600)
        self.fixture = CameraRegistry(self.database, unaudited_writes=True)
        self.config = self.root / "deployment.json"
        self.discovery = FakeDiscovery([camera(0), camera(2, "SYNTHSERIAL0002", port="1-4")])
        self.running = []
        self.configured = ()
        self.service_uid = os.geteuid()

    def deployment(self, config):
        return SimpleNamespace(
            service_uid=self.service_uid, settings=SimpleNamespace(database_path=self.path),
            local_uvc=SimpleNamespace(source_ids=tuple(self.configured)) if self.configured else None)

    def holders(self, identity, name):
        self.assertEqual(self.path.name, name)
        return self.running.pop(0) if self.running else 0

    def run_cli(self, *argv, lines=(), console=None, terminal_factory=None, markers=None):
        console = console or Console(self)
        console.type(*lines)
        stdout, stderr = io.StringIO(), io.StringIO()
        # By default the real ``/proc`` and ledger check: this test process
        # holds the database and stands in for the running service.
        extra = {} if markers is None else {"markers": markers}
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(admin_cli, "_load_deployment", self.deployment):
            code = admin_cli.main([argv[0], "--config", str(self.config), *argv[1:]],
                                  terminal_factory=terminal_factory or console.factory,
                                  discovery_factory=lambda: self.discovery, holders=self.holders,
                                  **extra)
        return code, stdout.getvalue(), stderr.getvalue(), console.output()

    def service_store(self, identity=None):
        """The store of a service process with its own session ledger (Issue #317).

        ``identity`` stands for another (earlier) process; by default the
        ledger names this test process.
        """
        ledger = SessionLedger(ledger_path(self.path),
                               **({} if identity is None else {"identity": lambda: identity}))
        return ApprovalStore(self.database, ledger=ledger)

    def rows(self, sql):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(sql)]

    def assertPrivateAbsent(self, *texts):
        for text in texts:
            for value in PRIVATE:
                self.assertNotIn(value, text)

    def local_source(self, name="Synthetic source", *, enabled=True):
        return self.fixture.create_source(
            source_type=SourceType.LOCAL_UVC, name=name, enabled=enabled,
            desired_capture_profile=CaptureProfile(1920, 1080, 30, "MJPG"))

    def labels(self):
        return [admin_cli.candidate_label(device) for device in self.discovery.devices]

    def approval(self, source_id):
        return ApprovalStore(self.database).load(source_id)

    # -- candidates / sources -------------------------------------------

    def test_candidates_show_only_hashed_labels_and_coarse_information(self):
        code, stdout, stderr, terminal = self.run_cli("candidates")
        self.assertEqual((code, stderr, terminal), (0, "", ""))
        lines = stdout.splitlines()
        self.assertEqual(2, len(lines))
        for line, label in zip(lines, self.labels()):
            self.assertRegex(label, r"^cam-[0-9a-f]{10}$")
            self.assertEqual(f"candidate {label} usb=1d6b:0102 serial=present formats=MJPG,YUYV "
                             "approved_for=-", line)
        self.assertPrivateAbsent(stdout, stderr)
        self.assertEqual([], self.rows(AUDIT))

    def test_labels_are_stable_per_live_instance_and_change_on_replug(self):
        device = camera(0)
        refreshed = DeviceEvidence(device.device_path, device.vendor, device.product, device.serial,
                                   device.interface, (), device.topology, ("MJPG",),
                                   device.device_number, device.instance_token)
        replugged = camera(0)
        replugged = DeviceEvidence(replugged.device_path, replugged.vendor, replugged.product,
                                   replugged.serial, replugged.interface, replugged.by_id,
                                   replugged.topology, replugged.formats, replugged.device_number,
                                   (1, 9999, 1))
        self.assertEqual(admin_cli.candidate_label(device), admin_cli.candidate_label(refreshed))
        self.assertNotEqual(admin_cli.candidate_label(device), admin_cli.candidate_label(replugged))
        self.assertNotIn("SYNTHSERIAL", admin_cli.candidate_label(device))

    def test_candidates_mark_absent_and_shared_serials_holders_and_scan_failures(self):
        source = self.local_source()
        held = camera(4, "SYNTHSERIAL0009", port="2-1")
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, source.id, held, serial_ambiguous=False)
            connection.execute("COMMIT")
        self.discovery = FakeDiscovery(
            [camera(0, None), camera(2, "SYNTHSERIALDUP", port="1-4"),
             camera(3, "SYNTHSERIALDUP", port="1-5"), held], failures=1)
        code, stdout, stderr, _ = self.run_cli("candidates")
        self.assertEqual((code, stderr), (0, ""))
        lines = stdout.splitlines()
        self.assertIn("serial=absent", lines[0])
        self.assertIn("serial=shared", lines[1])
        self.assertIn("serial=shared", lines[2])
        self.assertIn(f"serial=present formats=MJPG,YUYV approved_for={source.id}", lines[3])
        self.assertEqual("devices not inspected: 1", lines[4])
        self.assertPrivateAbsent(stdout)

    def test_a_twin_left_by_a_serial_ambiguous_holder_is_held_both_ways(self):
        # Issue #280 item 1: another source holds twin A as serial-ambiguous;
        # A is unplugged and only its twin B (same serial) remains. The
        # store refuses B in the reverse direction (by serial), so the
        # listing and the pre-confirmation check must say so too, instead
        # of failing after the confirmation with a recorded ``failed``.
        source = self.local_source()
        other = self.local_source("Other")
        twin_a = camera(7, "SYNTHSERIALTWIN", port="2-4")
        twin_b = camera(8, "SYNTHSERIALTWIN", port="2-5")
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, other.id, twin_a, serial_ambiguous=True)
            connection.execute("COMMIT")
        self.assertTrue(ApprovalStore(self.database).approved_elsewhere(source.id, twin_b))
        self.discovery = FakeDiscovery([twin_b])
        code, stdout, stderr, _ = self.run_cli("candidates")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"serial=present formats=MJPG,YUYV approved_for={other.id}", stdout)
        code, stdout, stderr, terminal = self.run_cli(
            "approve", str(source.id), admin_cli.candidate_label(twin_b))
        self.assertEqual((code, stdout, terminal), (2, "", ""))
        self.assertIn("refused: camera_approved_for_another_source", stderr)
        self.assertIsNone(self.approval(source.id))
        self.assertEqual([], self.rows(AUDIT))
        # With both twins connected each is told apart by its live instance:
        # only A is held, and B's serial is shared.
        self.discovery = FakeDiscovery([twin_a, twin_b])
        code, stdout, _, _ = self.run_cli("candidates")
        lines = stdout.splitlines()
        self.assertEqual(0, code)
        self.assertIn(f"serial=shared formats=MJPG,YUYV approved_for={other.id}", lines[0])
        self.assertIn("serial=shared formats=MJPG,YUYV approved_for=-", lines[1])

    def test_untrusted_device_text_is_never_printed_raw(self):
        odd = DeviceEvidence("/dev/video9", "SYNTH\u001b[2J", "x", "SYNTHSERIAL0003", "0", (),
                             None, ("M\"J'",), os.makedev(81, 9), (1, 2, 3))
        self.discovery = FakeDiscovery([odd])
        code, stdout, _, _ = self.run_cli("candidates")
        self.assertEqual(0, code)
        self.assertIn("usb=? serial=present formats=M?J?", stdout)
        self.assertNotIn("\u001b", stdout)

    def test_sources_lists_local_sources_with_their_approval_state(self):
        approved = self.local_source("Approved \"room\"")
        pending = self.local_source("Pending", enabled=False)
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, approved.id, camera(0), serial_ambiguous=False)
            connection.execute("COMMIT")
        self.configured = (approved.id,)
        code, stdout, stderr, terminal = self.run_cli("sources")
        self.assertEqual((code, stderr, terminal), (0, "", ""))
        self.assertIn(f"source {approved.id} enabled=yes approval=approved configured=yes "
                      'profile=1920x1080@30/MJPG name="Approved \\"room\\""', stdout)
        self.assertIn(f"source {pending.id} enabled=no approval=none configured=no", stdout)
        self.assertPrivateAbsent(stdout)

    def approve_offline(self, source_id, device, *, serial_ambiguous=False):
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, source_id, device, serial_ambiguous=serial_ambiguous)
            connection.execute("COMMIT")

    def test_sources_shows_an_approved_source_of_the_running_service_as_in_use(self):
        # Issue #300: the running service's ReconnectController keeps an
        # active-session marker on every approved source it reconciles;
        # Issue #317: its session ledger lists the markers of this run.
        first, second = self.local_source("First"), self.local_source("Second")
        store = self.service_store()
        tokens = []
        for source, device in ((first, camera(0)), (second, camera(2, "SYNTHSERIAL0002"))):
            self.approve_offline(source.id, device)
            started = store.start_session(source.id, device)
            self.assertFalse(started.requires_approval)
            tokens.append(started.session_token)
        self.configured = (first.id, second.id)
        calls = []

        def markers(identity, path):
            calls.append(path)
            return admin_cli._current_run_markers(identity, path)
        code, stdout, stderr, _ = self.run_cli("sources", markers=markers)
        self.assertEqual((code, stderr), (0, ""))
        for source in (first, second):
            self.assertIn(f"source {source.id} enabled=yes approval=approved_in_use configured=yes",
                          stdout)
        self.assertNotIn("approval_required", stdout)
        self.assertEqual([self.path], calls)  # one ledger check answers for the whole listing
        self.assertPrivateAbsent(stdout)
        # The ledger is private and holds digests only, never a marker.
        ledger = ledger_path(self.path)
        self.assertEqual(0o600, ledger.stat().st_mode & 0o777)
        content = ledger.read_text()
        for token in tokens:
            self.assertNotIn(token, content)
            self.assertIn(marker_digest(token), content)

    def test_sources_shows_a_marker_left_by_a_stopped_service_as_approval_required(self):
        # No process holds the database: the session was not ended (a crash),
        # and the next start_session turns the marker into approval required.
        source = self.local_source()
        self.approve_offline(source.id, camera(0))
        ApprovalStore(self.database).start_session(source.id, camera(0))
        self.configured = (source.id,)
        code, stdout, stderr, _ = self.run_cli("sources")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"source {source.id} enabled=yes approval=approval_required", stdout)
        self.assertTrue(ApprovalStore(self.database).start_session(source.id, camera(0))
                        .requires_approval)

    def crashed_run(self, *sources):
        """Markers and a ledger left by a service process that no longer exists."""
        own = current_process_identity()
        crashed = ProcessIdentity(own.boot_id, own.pid, own.start_time + 1)
        store = self.service_store(crashed)
        for source, device in sources:
            self.approve_offline(source.id, device)
            self.assertFalse(store.start_session(source.id, device).requires_approval)

    def test_sources_shows_a_crash_left_marker_as_approval_required_before_capture_starts(self):
        # Issue #317: the restarted service holds the database but has not
        # started this source's session (storage admission refused, start
        # failed, waiting to retry). Its ledger is still the crashed run's.
        source = self.local_source()
        self.crashed_run((source, camera(0)))
        self.configured = (source.id,)
        self.running = [1]
        code, stdout, stderr, _ = self.run_cli("sources")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"source {source.id} enabled=yes approval=approval_required configured=yes",
                      stdout)
        self.assertNotIn("approved_in_use", stdout)
        self.assertTrue(ApprovalStore(self.database).start_session(source.id, camera(0))
                        .requires_approval)

    def test_sources_tells_a_crash_left_marker_from_a_current_one_of_the_running_service(self):
        # The restarted service already started another source's session, so
        # its own ledger replaced the crashed run's; the left marker of the
        # source it has not started yet is still not in it.
        started, waiting = self.local_source("Started"), self.local_source("Waiting")
        self.crashed_run((started, camera(0)), (waiting, camera(2, "SYNTHSERIAL0002")))
        self.approve_offline(started.id, camera(0))  # the Owner re-approved it
        self.assertFalse(self.service_store().start_session(started.id, camera(0))
                         .requires_approval)
        self.configured = (started.id, waiting.id)
        self.running = [1]
        code, stdout, stderr, _ = self.run_cli("sources")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"source {started.id} enabled=yes approval=approved_in_use configured=yes",
                      stdout)
        self.assertIn(f"source {waiting.id} enabled=yes approval=approval_required configured=yes",
                      stdout)

    def test_sources_shows_a_left_marker_of_an_unlisted_source_as_approval_required(self):
        # A crash left the marker, the Owner removed the source from
        # local_uvc.source_ids and restarted: the database is held, but the
        # service started no session for this source, and listing it again
        # later requires approval.
        listed, unlisted = self.local_source("Listed"), self.local_source("Unlisted")
        store = self.service_store()
        for source, device in ((listed, camera(0)), (unlisted, camera(2, "SYNTHSERIAL0002"))):
            self.approve_offline(source.id, device)
            store.start_session(source.id, device)
        self.configured = (listed.id,)
        code, stdout, stderr, _ = self.run_cli("sources")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"source {listed.id} enabled=yes approval=approved_in_use configured=yes",
                      stdout)
        self.assertIn(f"source {unlisted.id} enabled=yes approval=approval_required configured=no",
                      stdout)
        self.assertTrue(store.start_session(unlisted.id, camera(2, "SYNTHSERIAL0002"))
                        .requires_approval)

    def test_sources_keeps_approval_required_for_a_latched_source_of_the_running_service(self):
        # A latched manual_intervention_required (e.g. an identical camera
        # without a serial or a shared serial) is never shown as in use.
        latched, never, approved = (self.local_source(name) for name in ("Latched", "Never", "Ok"))
        store = self.service_store()
        self.approve_offline(latched.id, camera(0))
        token = store.start_session(latched.id, camera(0)).session_token
        store.save(latched.id, camera(0), True, session_token=token, serial_ambiguous=True)
        store.start_session(never.id, camera(4, None, port="1-5"))
        self.approve_offline(approved.id, camera(2, "SYNTHSERIAL0002"))
        self.configured = (latched.id, never.id, approved.id)

        def markers(identity, path):
            raise AssertionError("no marker on an approved row: the ledger is not read")
        code, stdout, stderr, _ = self.run_cli("sources", markers=markers)
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"source {latched.id} enabled=yes approval=approval_required", stdout)
        self.assertIn(f"source {never.id} enabled=yes approval=approval_required", stdout)
        self.assertIn(f"source {approved.id} enabled=yes approval=approved ", stdout)
        self.assertNotIn("approved_in_use", stdout)

    def test_sources_refuses_when_the_service_state_cannot_be_read(self):
        source = self.local_source()
        self.approve_offline(source.id, camera(0))
        self.service_store().start_session(source.id, camera(0))
        self.configured = (source.id,)

        def unreadable(identity, path):
            raise CliRefused("service_state_unavailable")
        code, stdout, stderr, _ = self.run_cli("sources", markers=unreadable)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: service_state_unavailable", stderr)

    def test_sources_refuses_a_ledger_it_cannot_trust(self):
        # Issue #317: a ledger that cannot be read, or that is not a private
        # regular file of the service account, refuses instead of guessing.
        source = self.local_source()
        self.approve_offline(source.id, camera(0))
        self.service_store().start_session(source.id, camera(0))
        self.configured = (source.id,)
        ledger = ledger_path(self.path)
        content = ledger.read_bytes()

        def refused():
            code, stdout, stderr, _ = self.run_cli("sources")
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("refused: service_state_unavailable", stderr)

        os.chmod(ledger, 0)
        if not os.access(ledger, os.R_OK):  # not with permission overrides
            refused()
        os.chmod(ledger, 0o640)
        refused()
        os.chmod(ledger, 0o600)
        ledger.write_bytes(b"{")
        refused()
        ledger.unlink()
        (self.root / "elsewhere").write_bytes(content)
        os.chmod(self.root / "elsewhere", 0o600)
        ledger.symlink_to(self.root / "elsewhere")
        refused()
        ledger.unlink()
        os.link(self.root / "elsewhere", ledger)
        refused()
        ledger.unlink()
        ledger.write_bytes(content)
        os.chmod(ledger, 0o600)
        code, stdout, stderr, _ = self.run_cli("sources")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("approval=approved_in_use", stdout)
        with self.assertRaises(CliRefused):
            admin_cli._current_run_markers((0, 0), self.path, account=os.geteuid() + 1)

    # -- create-source --------------------------------------------------

    def test_create_source_confirms_on_the_terminal_and_is_audited(self):
        code, stdout, stderr, terminal = self.run_cli(
            "create-source", "--name", "Server rack", "--profile", PROFILE, lines=("CREATE",))
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Type CREATE to confirm", terminal)
        source_id = UUID(re.search(r"source created: source_id=([0-9a-f-]{36})", stdout).group(1))
        self.assertIn("local_uvc.source_ids", stdout)
        source = self.fixture.get_source(source_id)
        self.assertEqual((SourceType.LOCAL_UVC, "Server rack", True), (
            source.source_type, source.name, source.enabled))
        self.assertEqual(CaptureProfile(1920, 1080, 30, "MJPG"), source.desired_capture_profile)
        self.assertEqual([("owner", "create_source", "source", str(source_id), "succeeded")],
                         self.rows(AUDIT))
        self.assertIsNone(self.approval(source_id))

    def test_create_source_refusals_change_and_record_nothing(self):
        for argv, lines, reason in (
                (("--name", "x", "--profile", "1920x1080@30"), (), "capture_profile_rejected"),
                (("--name", "x", "--profile", "0x1080@30/MJPG"), (), "capture_profile_rejected"),
                (("--name", "x", "--profile", "1920x1080@30/mjpg"), (), "capture_profile_rejected"),
                (("--name", "x", "--profile", PROFILE), ("no",), "owner_confirmation_declined"),
                (("--name", "x", "--profile", PROFILE), ("CREATE ",), None)):
            with self.subTest(argv=argv, lines=lines):
                code, stdout, stderr, _ = self.run_cli("create-source", *argv, lines=lines)
                if reason is None:
                    # The terminal line is stripped, so trailing blanks still confirm.
                    self.assertEqual(0, code)
                    continue
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(f"refused: {reason}", stderr)
        self.assertEqual(1, len(self.fixture.list_sources()))
        self.assertEqual(1, len(self.rows(AUDIT)))

    def test_create_source_respects_the_active_source_limit(self):
        for index in range(4):
            self.local_source(f"Existing {index}")
        code, stdout, stderr, _ = self.run_cli(
            "create-source", "--name", "Fifth", "--profile", PROFILE, lines=("CREATE",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: active_source_limit_reached", stderr)
        self.assertEqual(4, len(self.fixture.list_sources()))
        ((actor, action, _kind, _target, outcome),) = self.rows(AUDIT)
        self.assertEqual(("owner", "create_source", "failed"), (actor, action, outcome))

    # -- rename-source --------------------------------------------------

    def test_rename_source_changes_only_the_name_and_is_audited(self):
        source = self.local_source("camera-1")
        code, stdout, stderr, terminal = self.run_cli(
            "approve", str(source.id), self.labels()[0], lines=("APPROVE",))
        self.assertEqual(0, code, stderr)
        approved = self.approval(source.id)
        # The approval records the camera's capabilities on the source.
        source = self.fixture.get_source(source.id)
        code, stdout, stderr, terminal = self.run_cli(
            "rename-source", str(source.id), "--name", "入口", lines=("RENAME",))
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn('name="camera-1"', terminal)
        self.assertIn('name="入口"', terminal)
        self.assertIn("Type RENAME to confirm", terminal)
        self.assertIn(f"source renamed: source_id={source.id}", stdout)
        renamed = self.fixture.get_source(source.id)
        self.assertEqual("入口", renamed.name)
        self.assertEqual((source.enabled, source.desired_capture_profile, source.role_label,
                          source.capabilities, source.detection_bindings),
                         (renamed.enabled, renamed.desired_capture_profile, renamed.role_label,
                          renamed.capabilities, renamed.detection_bindings))
        self.assertEqual(approved, self.approval(source.id))
        self.assertEqual(("owner", "update_source", "source", str(source.id), "succeeded"),
                         self.rows(AUDIT)[-1])

    def test_rename_source_refusals_change_and_record_nothing(self):
        source = self.local_source("camera-1")
        before = len(self.rows(AUDIT))
        for argv, lines, reason in (
                (("not-a-uuid", "--name", "x"), (), "source_id_rejected"),
                ((str(uuid4()), "--name", "x"), (), "source_not_found"),
                ((str(source.id), "--name", "x"), ("no",), "owner_confirmation_declined")):
            with self.subTest(argv=argv, lines=lines):
                code, stdout, stderr, _ = self.run_cli("rename-source", *argv, lines=lines)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(f"refused: {reason}", stderr)
        self.assertEqual("camera-1", self.fixture.get_source(source.id).name)
        self.assertEqual(before, len(self.rows(AUDIT)))

    def test_unsafe_or_overlong_names_are_refused_before_the_confirmation(self):
        # PR #411 review: shown in full in the prompt and in the live view.
        source = self.local_source("camera-1")
        for name in ("   ", "a\x7fb", "a\x9b31mb", "a\u202ec", "a\u200bb", "a\u2028b",
                     "x" * 129):
            for argv in (("rename-source", str(source.id), "--name", name),
                         ("create-source", "--name", name, "--profile", PROFILE)):
                with self.subTest(name=repr(name), command=argv[0]):
                    code, stdout, stderr, terminal = self.run_cli(*argv)
                    self.assertEqual((code, stdout, terminal), (2, "", ""))
                    self.assertIn("refused: source_name_rejected", stderr)
        self.assertEqual("camera-1", self.fixture.get_source(source.id).name)
        self.assertEqual(1, len(self.fixture.list_sources()))
        self.assertEqual([], self.rows(AUDIT))
        code, _, stderr, _ = self.run_cli(
            "rename-source", str(source.id), "--name", "x" * 128, lines=("RENAME",))
        self.assertEqual(0, code, stderr)

    def test_rename_source_refuses_another_source_type(self):
        node = self.fixture.create_capture_node(name="Synthetic node")
        remote = self.fixture.create_source(source_type=SourceType.REMOTE_AGENT, name="remote",
                                            capture_node_id=node.id, enabled=False)
        code, stdout, stderr, _ = self.run_cli(
            "rename-source", str(remote.id), "--name", "x", lines=("RENAME",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: source_not_local_uvc", stderr)

    def test_mutations_refuse_while_the_service_holds_the_database(self):
        source = self.local_source()
        node = pair_node(self.database, 1)
        for argv in (("create-source", "--name", "x", "--profile", PROFILE),
                     ("approve", str(source.id), self.labels()[0]),
                     ("rename-source", str(source.id), "--name", "x"),
                     ("create-remote-source", "--node", str(node), "--name", "x")):
            with self.subTest(argv=argv[0]):
                self.running = [1]
                console = Console(self)
                code, stdout, stderr, terminal = self.run_cli(*argv, console=console)
                self.assertEqual((code, stdout, terminal), (2, "", ""))
                self.assertIn("refused: service_running", stderr)
                # With socket activation a connection restarts a service stopped alone.
                self.assertIn("sudo systemctl stop server-sentinel-upstream.socket "
                              "server-sentinel.service", stderr)
                # Another local admin command holding the database also counts.
                self.assertIn("bootstrap_cli", stderr)
                self.assertIn("a second admin_cli", stderr)
        self.assertEqual(1, len(self.fixture.list_sources()))
        self.assertIsNone(self.approval(source.id))
        self.assertEqual([], self.rows(SOURCE_AUDIT))
        self.assertEqual([], self.rows("SELECT id FROM capture_nodes"))

    def test_a_service_started_during_the_confirmation_is_refused_inside_the_transaction(self):
        source = self.local_source()
        node = pair_node(self.database, 1)
        for argv, lines, action in (
                (("create-remote-source", "--node", str(node), "--name", "x"), ("CREATE",),
                 "create_source"),
                (("create-source", "--name", "x", "--profile", PROFILE), ("CREATE",), "create_source"),
                (("approve", str(source.id), self.labels()[0]), ("APPROVE",), "approve_camera"),
                (("rename-source", str(source.id), "--name", "入口"), ("RENAME",),
                 "update_source")):
            with self.subTest(argv=argv[0]):
                self.running = [0, 1]
                code, stdout, stderr, _ = self.run_cli(*argv, lines=lines)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("refused: service_running", stderr)
                row = self.rows(AUDIT)[-1]
                self.assertEqual(("owner", action, "failed"), (row[0], row[1], row[4]))
        self.assertEqual(1, len(self.fixture.list_sources()))
        self.assertIsNone(self.approval(source.id))
        self.assertEqual("Synthetic source", self.fixture.get_source(source.id).name)
        self.assertEqual([], self.rows("SELECT id FROM capture_nodes"))
        self.assertEqual(["failed"] * 4, [row[4] for row in self.rows(SOURCE_AUDIT)])

    def test_mutations_need_the_controlling_terminal_and_the_service_account(self):
        def no_terminal():
            raise CliRefused("controlling_terminal_required")
        code, _, stderr, _ = self.run_cli("create-source", "--name", "x", "--profile", PROFILE,
                                          terminal_factory=no_terminal)
        self.assertEqual(2, code)
        self.assertIn("refused: controlling_terminal_required", stderr)
        with patch.object(admin_cli.os, "geteuid", return_value=0):
            code, _, stderr, _ = self.run_cli("candidates")
        self.assertEqual(2, code)
        self.assertIn("refused: run_as_service_account", stderr)
        with patch.object(admin_cli.os, "geteuid", return_value=os.geteuid() + 1):
            code, _, stderr, _ = self.run_cli("candidates")
        self.assertIn("refused: run_as_service_account", stderr)
        self.assertEqual([], self.rows(AUDIT))

    def test_refuses_a_database_of_another_schema(self):
        with closing(self.database.connect()) as connection:
            connection.execute("DELETE FROM schema_migrations WHERE version = "
                               "(SELECT max(version) FROM schema_migrations)")
            connection.commit()
        code, _, stderr, _ = self.run_cli("candidates")
        self.assertEqual(2, code)
        self.assertIn("refused: database_schema_outdated", stderr)

    # -- remote sources (Issue #14) -------------------------------------

    def remote_rows(self):
        return self.rows("SELECT id, capture_node_id, name, enabled FROM camera_sources "
                         "WHERE source_type = 'remote_agent' ORDER BY created_at")

    def node_rows(self):
        return self.rows("SELECT id, health_state FROM capture_nodes ORDER BY id")

    def create_remote(self, node, name="x", lines=("CREATE",), **kwargs):
        return self.run_cli("create-remote-source", "--node", str(node), "--name", name,
                            lines=lines, **kwargs)

    def test_create_remote_source_binds_the_ledger_node_uuid_and_is_audited(self):
        node = pair_node(self.database, 1)
        code, stdout, stderr, terminal = self.create_remote(node, "入口")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f'name="入口" for capture node {node}', terminal)
        self.assertIn("Type CREATE to confirm", terminal)
        match = re.fullmatch(
            r"remote source created: source_id=([0-9a-f-]{36}) node_id=([0-9a-f-]{36})\n"
            r"next: .*capture\.sources\[\]\.source_id.*\n", stdout)
        self.assertIsNotNone(match, stdout)
        source_id = UUID(match.group(1))
        # Printed canonically, so the Agent configuration can take it as is.
        self.assertEqual(str(source_id), match.group(1))
        self.assertEqual(str(node), match.group(2))
        source = self.fixture.get_source(source_id)
        self.assertEqual((SourceType.REMOTE_AGENT, node, "入口", True, None),
                         (source.source_type, source.capture_node_id, source.name, source.enabled,
                          source.desired_capture_profile))
        # The registry node row carries the ledger's UUID; no second identity.
        self.assertEqual([(str(node), "offline")], self.node_rows())
        self.assertEqual([("owner", "create_capture_node", "capture_node", str(node), "succeeded"),
                          ("owner", "create_source", "source", str(source_id), "succeeded")],
                         self.rows(SOURCE_AUDIT))
        # A second camera of the same node reuses that row.
        code, stdout, stderr, _ = self.create_remote(node, "rack")
        self.assertEqual((code, stderr), (0, ""))
        second = UUID(re.search(r"source_id=([0-9a-f-]{36})", stdout).group(1))
        self.assertEqual([(str(node), "offline")], self.node_rows())
        self.assertEqual(3, len(self.rows(SOURCE_AUDIT)))
        self.assertEqual(("owner", "create_source", "source", str(second), "succeeded"),
                         self.rows(SOURCE_AUDIT)[-1])
        self.assertEqual([node, node], [row.capture_node_id for row in self.fixture.list_sources()])

    def test_create_remote_source_refusals_change_and_record_nothing(self):
        paired = pair_node(self.database, 1)
        revoked = pair_node(self.database, 3, revoked=True)
        registry_revoked = pair_node(self.database, 5)
        # A registry node row of the ledger's UUID, revoked in the registry.
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.fixture.create_capture_node_on(connection, registry_revoked, "node")
            connection.execute("UPDATE capture_nodes SET health_state = 'revoked'")
            connection.execute("COMMIT")
        nodes_before = self.node_rows()
        for node, name, lines, reason in (
                ("not-a-uuid", "x", (), "node_id_rejected"),
                (str(paired)[:-1], "x", (), "node_id_rejected"),
                ("{" + str(paired) + "}", "x", (), "node_id_rejected"),
                (uuid4(), "x", (), "capture_node_not_paired"),
                (revoked, "x", (), "capture_node_revoked"),
                (registry_revoked, "x", (), "capture_node_revoked"),
                (paired, "a\u202ec", (), "source_name_rejected"),
                (paired, "   ", (), "source_name_rejected"),
                (paired, "x" * 129, (), "source_name_rejected"),
                (paired, "x", ("no",), "owner_confirmation_declined")):
            with self.subTest(node=str(node), reason=reason):
                code, stdout, stderr, terminal = self.create_remote(node, name, lines)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(f"refused: {reason}", stderr)
                self.assertNotIn(str(node), stderr)
                if reason != "owner_confirmation_declined":
                    self.assertEqual("", terminal)
        self.assertEqual([], self.remote_rows())
        self.assertEqual(nodes_before, self.node_rows())
        self.assertEqual([], self.rows(SOURCE_AUDIT))

    def test_a_node_revoked_during_the_confirmation_is_refused_inside_the_transaction(self):
        node = pair_node(self.database, 1)
        confirm = admin_cli.LocalConsoleOwner.confirm

        def revoke_then_confirm(owner, terminal, prompt, word):
            grant = confirm(owner, terminal, prompt, word)
            revoke_node(self.database, node)
            return grant

        with patch.object(admin_cli.LocalConsoleOwner, "confirm", revoke_then_confirm):
            code, stdout, stderr, _ = self.create_remote(node)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: capture_node_revoked", stderr)
        self.assertEqual([], self.remote_rows())
        self.assertEqual([], self.node_rows())
        ((actor, action, _kind, _target, outcome),) = self.rows(SOURCE_AUDIT)
        self.assertEqual(("owner", "create_source", "failed"), (actor, action, outcome))

    def test_create_remote_source_respects_the_active_source_limit_of_every_type(self):
        node = pair_node(self.database, 1)
        for index in range(4):
            self.local_source(f"Existing {index}")
        code, stdout, stderr, _ = self.create_remote(node, "Fifth")
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: active_source_limit_reached", stderr)
        self.assertEqual([], self.remote_rows())
        # Rolled back together with the source: no node row and no node record.
        self.assertEqual([], self.node_rows())
        ((actor, action, _kind, _target, outcome),) = self.rows(SOURCE_AUDIT)
        self.assertEqual(("owner", "create_source", "failed"), (actor, action, outcome))
        # A disabled source frees its slot.
        self.fixture.update_source(self.fixture.list_sources()[0].id, enabled=False)
        code, _, stderr, _ = self.create_remote(node, "Fifth")
        self.assertEqual(0, code, stderr)
        self.assertEqual(4, sum(source.enabled for source in self.fixture.list_sources()))

    def test_remote_sources_lists_nodes_and_credential_states_while_the_service_runs(self):
        active = pair_node(self.database, 1)
        revoked = pair_node(self.database, 3)
        for node in (active, revoked):
            code, _, stderr, _ = self.create_remote(node, "plain")
            self.assertEqual(0, code, stderr)
        first, second = self.fixture.list_sources()
        # A stored name the command would refuse is still printed escaped.
        self.fixture.update_source(first.id, name='say "hi" \\ \x7f‮')
        revoke_node(self.database, revoked)
        self.local_source()
        self.running = [1, 1]
        code, stdout, stderr, terminal = self.run_cli("remote-sources")
        self.assertEqual((code, stderr, terminal), (0, "", ""))
        self.assertEqual(
            [f"source {first.id} enabled=yes node={active} credential=active "
             'name="say \\"hi\\" \\\\ \\u007f\\u202e"',
             f'source {second.id} enabled=yes node={revoked} credential=revoked name="plain"'],
            stdout.splitlines())

    def test_remote_sources_without_any(self):
        self.local_source()
        code, stdout, stderr, _ = self.run_cli("remote-sources")
        self.assertEqual((code, stdout, stderr), (0, "no remote_agent sources\n", ""))

    def test_owner_administration_refuses_unpaired_nodes_and_denied_actors(self):
        node = pair_node(self.database, 1)
        audit = AuditStore(self.database)
        registry = CameraRegistry(self.database)
        denied = OwnerAdministration(OwnerAuditService(audit, DenyAllOwners()), registry)
        with self.assertRaises(OwnerAuthorizationError):
            denied.create_remote_agent_source(object(), node, name="x")
        admin = OwnerAdministration(OwnerAuditService(audit, _LedgerOwner()), registry)
        with self.assertRaises(CaptureNodeNotPairedError):
            admin.create_remote_agent_source("owner", uuid4(), name="x")
        with self.assertRaises(CaptureNodeNotPairedError):
            admin.create_remote_agent_source("owner", str(node), name="x")
        # A registry node row revoked by the Owner refuses, although the
        # ledger credential is still active.
        registry_revoked = pair_node(self.database, 5)
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            registry.create_capture_node_on(connection, registry_revoked, "node")
            connection.execute("UPDATE capture_nodes SET health_state = 'revoked'")
            connection.execute("COMMIT")
        with self.assertRaises(CaptureNodeRevokedError):
            admin.create_remote_agent_source("owner", registry_revoked, name="x")
        revoke_node(self.database, node)
        with self.assertRaises(CaptureNodeRevokedError):
            admin.create_remote_agent_source("owner", node, name="x")
        self.assertEqual([], self.remote_rows())
        self.assertEqual([(str(registry_revoked), "revoked")], self.node_rows())
        # A node that is not a UUID is refused before the boundary: no record.
        self.assertEqual(["denied", "failed", "failed", "failed"],
                         [row[4] for row in self.rows(SOURCE_AUDIT)])

    # -- approve --------------------------------------------------------

    def test_approve_binds_the_selected_camera_with_its_audit_record(self):
        source = self.local_source()
        label = self.labels()[1]
        code, stdout, stderr, terminal = self.run_cli("approve", str(source.id), label,
                                                      lines=("APPROVE",))
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"Approve camera {label} usb=1d6b:0102 for source {source.id}", terminal)
        self.assertIn(f"camera approved: source_id={source.id} candidate={label}", stdout)
        self.assertIn("local_uvc.source_ids", stdout)
        approval = self.approval(source.id)
        self.assertEqual(self.discovery.devices[1], approval.approved)
        self.assertFalse(approval.requires_approval)
        self.assertIsNone(approval.session_token)
        self.assertFalse(approval.serial_ambiguous)
        self.assertEqual([("owner", "approve_camera", "camera", str(source.id), "succeeded")],
                         self.rows(AUDIT))
        self.assertPrivateAbsent(stdout, stderr, terminal)

    def test_approve_clears_a_stale_active_session_marker(self):
        source = self.local_source()
        ApprovalStore(self.database).start_session(source.id, camera(0))
        self.assertTrue(self.approval(source.id).requires_approval)
        self.configured = (source.id,)
        code, stdout, stderr, _ = self.run_cli("approve", str(source.id), self.labels()[0],
                                               lines=("APPROVE",))
        self.assertEqual((code, stderr), (0, ""))
        self.assertNotIn("local_uvc.source_ids", stdout)
        approval = self.approval(source.id)
        self.assertFalse(approval.requires_approval)
        self.assertIsNone(approval.session_token)

    def test_approve_refuses_ambiguous_or_unusable_cameras(self):
        source = self.local_source()
        other = self.local_source("Other")
        holder_camera = camera(5, "SYNTHSERIAL0005", port="2-2")
        latched = camera(6, "SYNTHSERIAL0006", port="2-3")
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, other.id, holder_camera, serial_ambiguous=False)
            connection.execute("COMMIT")
        cases = (
            ([camera(0, None), camera(2, None, port="1-4")], 0, "camera_without_serial"),
            ([camera(0, "SYNTHSERIALDUP"), camera(2, "SYNTHSERIALDUP", port="1-4")], 0,
             "camera_serial_not_unique"),
            ([holder_camera], 0, "camera_approved_for_another_source"),
            ([camera(0, formats=("YUYV",))], 0, "camera_format_unsupported"),
            ([camera(0, formats=())], 0, "camera_format_unsupported"),
            ([camera(0)], 1, "camera_scan_incomplete"),
        )
        for devices, failures, reason in cases:
            with self.subTest(reason=reason):
                self.discovery = FakeDiscovery(devices, failures)
                label = admin_cli.candidate_label(devices[0])
                code, stdout, stderr, terminal = self.run_cli("approve", str(source.id), label)
                self.assertEqual((code, stdout, terminal), (2, "", ""))
                self.assertIn(f"refused: {reason}", stderr)
                self.assertPrivateAbsent(stderr)
        # A serial this source's approval already latched as ambiguous.
        with closing(self.database.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            ApprovalStore.approve_on(connection, source.id, latched, serial_ambiguous=True)
            connection.execute("COMMIT")
        self.discovery = FakeDiscovery([latched])
        code, _, stderr, _ = self.run_cli("approve", str(source.id), admin_cli.candidate_label(latched))
        self.assertEqual(2, code)
        self.assertIn("refused: camera_serial_not_unique", stderr)
        self.assertEqual([], self.rows(AUDIT))

    def test_approve_refuses_bad_targets_before_any_change(self):
        source = self.local_source()
        disabled = self.local_source("Disabled", enabled=False)
        bare = self.fixture.create_source(source_type=SourceType.LOCAL_UVC, name="Bare", enabled=True)
        partial = self.fixture.create_source(
            source_type=SourceType.LOCAL_UVC, name="Partial", enabled=True,
            desired_capture_profile=CaptureProfile(1920, 1080, None, "MJPG"))
        coded = self.fixture.create_source(
            source_type=SourceType.LOCAL_UVC, name="Coded", enabled=True,
            desired_capture_profile=CaptureProfile(1920, 1080, 30, "MJPG", codec="h264"))
        label = self.labels()[0]
        for argv, reason in (
                ((str(source.id).upper()[:-1], label), "source_id_rejected"),
                ((str(source.id), "video0"), "candidate_label_rejected"),
                ((str(source.id), "cam-0000000000"), "candidate_not_found"),
                ((str(uuid4()), label), "source_not_found"),
                ((str(disabled.id), label), "source_disabled"),
                ((str(bare.id), label), "source_profile_unusable"),
                ((str(partial.id), label), "source_profile_unusable"),
                ((str(coded.id), label), "source_profile_unusable")):
            with self.subTest(reason=reason):
                code, stdout, stderr, terminal = self.run_cli("approve", *argv)
                self.assertEqual((code, stdout, terminal), (2, "", ""))
                self.assertIn(f"refused: {reason}", stderr)
        code, _, stderr, _ = self.run_cli("approve", str(source.id), label, lines=("approve",))
        self.assertIn("refused: owner_confirmation_declined", stderr)
        self.assertIsNone(self.approval(source.id))
        self.assertEqual([], self.rows(AUDIT))

    def test_a_serial_twin_connected_during_the_confirmation_is_refused(self):
        source = self.local_source()
        selected = camera(0)
        twin = camera(3, port="1-6")
        label = admin_cli.candidate_label(selected)

        class Twin(FakeDiscovery):
            def scan(inner):
                inner.scans += 1
                return DiscoveryResult((selected,) if inner.scans == 1 else (selected, twin), 0)

        self.discovery = Twin()
        code, stdout, stderr, _ = self.run_cli("approve", str(source.id), label, lines=("APPROVE",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: camera_serial_not_unique", stderr)
        self.assertIsNone(self.approval(source.id))
        self.assertEqual([("owner", "approve_camera", "camera", str(source.id), "failed")],
                         self.rows(AUDIT))

    def test_a_camera_that_changed_before_the_audited_rescan_is_refused(self):
        source = self.local_source()
        devices = self.discovery.devices
        label = self.labels()[0]

        class Changing(FakeDiscovery):
            def scan(inner):
                inner.scans += 1
                return DiscoveryResult(devices if inner.scans == 1 else devices[1:], 0)

        self.discovery = Changing()
        code, stdout, stderr, _ = self.run_cli("approve", str(source.id), label, lines=("APPROVE",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: candidate_unavailable", stderr)
        self.assertIsNone(self.approval(source.id))
        self.assertEqual([("owner", "approve_camera", "camera", str(source.id), "failed")],
                         self.rows(AUDIT))


class DatabaseHolderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.database = self.root / "state.sqlite3"
        self.database.write_bytes(b"synthetic")
        self.other = self.root / "other"
        self.other.write_bytes(b"other")
        info = os.stat(self.database)
        self.identity = (info.st_dev, info.st_ino)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.account = os.geteuid()

    def process(self, pid, uid, targets):
        directory = self.proc / str(pid)
        (directory / "fd").mkdir(parents=True)
        (directory / "status").write_text(f"Name:\tsynthetic\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        for number, target in enumerate(targets):
            (directory / "fd" / str(number)).symlink_to(target)
        return directory

    def holders(self, own_pid=1):
        return admin_cli._database_holders(self.identity, self.database.name, proc_root=self.proc,
                                           own_pid=own_pid, account=self.account)

    def test_counts_other_processes_of_this_account_holding_the_database(self):
        self.process(1, self.account, [self.database])       # this process
        self.process(2, self.account, [self.other])
        self.process(3, self.account + 1, [self.database])   # another account
        (self.proc / "self").mkdir()
        self.assertEqual(0, self.holders())
        self.process(4, self.account, [self.other, self.database, self.root / "gone"])
        self.assertEqual(1, self.holders())

    def test_an_uninspectable_process_of_this_account_refuses(self):
        directory = self.process(5, self.account, [self.database])
        os.chmod(directory / "fd", 0)
        self.addCleanup(os.chmod, directory / "fd", 0o700)
        if os.access(directory / "fd", os.R_OK):
            self.skipTest("running with permission overrides")
        with self.assertRaises(CliRefused) as refused:
            self.holders()
        self.assertEqual("service_state_unavailable", refused.exception.reason)

    def test_an_unreadable_status_of_a_process_refuses(self):
        # Issue #280 item 2: a process whose uids cannot be read might be the
        # service; it is never skipped as "another account" or "gone".
        self.process(7, self.account, [self.database])
        real_open = Path.open

        def failing(path, *args, **kwargs):
            if str(path).endswith("/7/status"):
                raise PermissionError(13, "synthetic")
            return real_open(path, *args, **kwargs)

        with patch.object(Path, "open", failing), self.assertRaises(CliRefused) as refused:
            self.holders()
        self.assertEqual("service_state_unavailable", refused.exception.reason)

    def test_an_unreadable_status_file_refuses_and_a_vanished_one_is_skipped(self):
        directory = self.process(8, self.account, [self.database])
        os.chmod(directory / "status", 0)
        try:
            if os.access(directory / "status", os.R_OK):
                self.skipTest("running with permission overrides")
            with self.assertRaises(CliRefused) as refused:
                self.holders()
        finally:
            os.chmod(directory / "status", 0o600)
        self.assertEqual("service_state_unavailable", refused.exception.reason)
        (directory / "status").unlink()   # the process exited meanwhile
        self.assertEqual(0, self.holders())

    def test_a_status_without_uids_refuses(self):
        directory = self.process(9, self.account, [self.database])
        (directory / "status").write_text("Name:\tsynthetic\n")
        with self.assertRaises(CliRefused) as refused:
            self.holders()
        self.assertEqual("service_state_unavailable", refused.exception.reason)

    def test_only_descriptors_named_like_the_database_are_stat_ed(self):
        # Issue #280 item 6: a stat on a hung FUSE/NFS descriptor would block
        # instead of refusing, so other files are never stat-ed.
        hung = self.root / "mnt" / "hung-fuse-file"
        hung.parent.mkdir()
        hung.write_bytes(b"synthetic")
        self.process(10, self.account, [hung, self.other, self.database])
        stat_ed = []
        real_stat = os.stat

        def recording(path, *args, **kwargs):
            stat_ed.append(str(path))
            if not str(path).endswith("/10/fd/2"):
                raise AssertionError("a descriptor of another file was stat-ed")
            return real_stat(path, *args, **kwargs)

        with patch.object(admin_cli.os, "stat", recording):
            self.assertEqual(1, self.holders())
        self.assertEqual([str(self.proc / "10" / "fd" / "2")], stat_ed)
        # A same-named file of another directory (a bind mount, another
        # mount namespace) is stat-ed and compared by inode, not by name.
        twin = self.root / "mnt" / self.database.name
        twin.write_bytes(b"other")
        self.process(11, self.account, [twin])
        self.assertEqual(1, self.holders())
        self.assertFalse(admin_cli._may_name_database("pipe:[4242]", self.database.name))
        self.assertFalse(admin_cli._may_name_database("socket:[4242]", self.database.name))
        self.assertFalse(admin_cli._may_name_database(str(self.root / "state.sqlite3-wal"),
                                                      self.database.name))

    def test_a_descriptor_link_that_cannot_be_read_refuses(self):
        self.process(12, self.account, [self.other])
        real_readlink = os.readlink

        def failing(path, *args, **kwargs):
            if str(path).endswith("/12/fd/0"):
                raise PermissionError(13, "synthetic")
            return real_readlink(path, *args, **kwargs)

        with patch.object(admin_cli.os, "readlink", failing), \
                self.assertRaises(CliRefused) as refused:
            self.holders()
        self.assertEqual("service_state_unavailable", refused.exception.reason)

    def test_a_descriptor_that_cannot_be_inspected_refuses(self):
        self.process(6, self.account, [self.other, self.database])
        real_stat = os.stat

        def failing(path, *args, **kwargs):
            if str(path).endswith("/6/fd/1"):
                raise PermissionError(13, "synthetic")
            return real_stat(path, *args, **kwargs)

        with patch.object(admin_cli.os, "stat", failing), self.assertRaises(CliRefused) as refused:
            self.holders()
        self.assertEqual("service_state_unavailable", refused.exception.reason)

    def test_real_proc_sees_another_process_holding_the_file(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import os, sys, time\n"
             "fd = os.open(sys.argv[1], os.O_RDONLY)\nprint('held', flush=True)\ntime.sleep(60)\n",
             str(self.database)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        self.assertEqual("held", child.stdout.readline().strip())
        child.stdout.close()
        # Only the child's real /proc entry: other processes of the suite
        # (for example non-dumpable ones) must not decide this test.
        view = self.root / "view"
        view.mkdir()
        (view / str(child.pid)).symlink_to(f"/proc/{child.pid}")
        name = self.database.name
        self.assertEqual(1, admin_cli._database_holders(self.identity, name, proc_root=view))
        self.assertEqual(0, admin_cli._database_holders(self.identity, name, proc_root=view,
                                                        own_pid=os.getpid(),
                                                        account=self.account + 1))
        child.kill()
        child.wait()
        self.assertEqual(0, admin_cli._database_holders(self.identity, name, proc_root=view))


if __name__ == "__main__":
    unittest.main()
