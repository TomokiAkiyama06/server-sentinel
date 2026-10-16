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

from app.cameras.registry import CameraRegistry, CaptureProfile, SourceType
from app.cameras.uvc import admin_cli
from app.cameras.uvc.discovery import DiscoveryResult
from app.cameras.uvc.identity import DeviceEvidence
from app.cameras.uvc.persistence import ApprovalStore
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

    def holders(self, identity):
        return self.running.pop(0) if self.running else 0

    def run_cli(self, *argv, lines=(), console=None, terminal_factory=None):
        console = console or Console(self)
        console.type(*lines)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(admin_cli, "_load_deployment", self.deployment):
            code = admin_cli.main([argv[0], "--config", str(self.config), *argv[1:]],
                                  terminal_factory=terminal_factory or console.factory,
                                  discovery_factory=lambda: self.discovery, holders=self.holders)
        return code, stdout.getvalue(), stderr.getvalue(), console.output()

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

    def test_mutations_refuse_while_the_service_holds_the_database(self):
        source = self.local_source()
        for argv in (("create-source", "--name", "x", "--profile", PROFILE),
                     ("approve", str(source.id), self.labels()[0])):
            with self.subTest(argv=argv[0]):
                self.running = [1]
                console = Console(self)
                code, stdout, stderr, terminal = self.run_cli(*argv, console=console)
                self.assertEqual((code, stdout, terminal), (2, "", ""))
                self.assertIn("refused: service_running", stderr)
                self.assertIn("systemctl stop", stderr)
        self.assertEqual(1, len(self.fixture.list_sources()))
        self.assertIsNone(self.approval(source.id))
        self.assertEqual([], self.rows(AUDIT))

    def test_a_service_started_during_the_confirmation_is_refused_inside_the_transaction(self):
        source = self.local_source()
        for argv, lines, action in (
                (("create-source", "--name", "x", "--profile", PROFILE), ("CREATE",), "create_source"),
                (("approve", str(source.id), self.labels()[0]), ("APPROVE",), "approve_camera")):
            with self.subTest(argv=argv[0]):
                self.running = [0, 1]
                code, stdout, stderr, _ = self.run_cli(*argv, lines=lines)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("refused: service_running", stderr)
                row = self.rows(AUDIT)[-1]
                self.assertEqual(("owner", action, "failed"), (row[0], row[1], row[4]))
        self.assertEqual(1, len(self.fixture.list_sources()))
        self.assertIsNone(self.approval(source.id))
        self.assertEqual(["failed", "failed"], [row[4] for row in self.rows(AUDIT)])

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
        return admin_cli._database_holders(self.identity, proc_root=self.proc, own_pid=own_pid,
                                           account=self.account)

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
        self.assertEqual(1, admin_cli._database_holders(self.identity, proc_root=view))
        self.assertEqual(0, admin_cli._database_holders(self.identity, proc_root=view,
                                                        own_pid=os.getpid(),
                                                        account=self.account + 1))
        child.kill()
        child.wait()
        self.assertEqual(0, admin_cli._database_holders(self.identity, proc_root=view))


if __name__ == "__main__":
    unittest.main()
