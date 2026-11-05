"""Issue #390 / Owner decision 2026-11-05: the local hardware-baseline command.

Synthetic only: a temporary SQLite database, a pseudo-terminal standing in for
the controlling terminal and an injected probe whose inventory carries
invented serials, WWIDs, UUIDs, PCI addresses and model strings. The host's
real inventory is never read and no real terminal or service is used; mock
only.
"""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.audit.integration import HARDWARE_BASELINE_ID
from app.integrity import admin_cli
from app.integrity.model import Component, Inventory, Kind
from app.integrity.store import IntegrityStore
from app.local_admin import CliRefused
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_bootstrap_cli import Console


AUDIT = ("SELECT actor_category, action, target_kind, target_logical_id, outcome "
         "FROM security_admin_audit_records ORDER BY rowid")
# Every private value a fixture component carries; none may ever be printed.
PRIVATE = ("SYNTH-SERIAL", "SYNTH-WWID", "GPU-5f1c", "0000:01:00.0", "0000:00:02.0",
           "Synthetic Model", "nvme0n1", "sda", "0x10de", "0x2204", "DIMM_A1", "synthetic-socket")


def cpu():
    return Component(Kind.CPU, "synthetic-socket-0", (("model name", "Synthetic Model CPU 9000"),
                                                      ("vendor_id", "SyntheticVendor"),
                                                      ("logical_cpus", "8")))


def memory(serial="SYNTH-SERIAL-DIMM-1"):
    return Component(Kind.MEMORY, "BANK 0:DIMM_A1", (("Size", "16 GB"), ("Part Number", "Synthetic Model RAM")),
                     (("serial", serial),))


def disk(name="nvme0n1", serial="SYNTH-SERIAL-DISK-1", wwid="SYNTH-WWID-1"):
    return Component(Kind.STORAGE, name, (("capacity_bytes", "1024"), ("model", "Synthetic Model SSD")),
                     (("serial", serial), ("wwid", wwid)))


def gpu(slot="0000:01:00.0", uuid="GPU-5f1c0000-synthetic"):
    return Component(Kind.GPU, slot, (("vendor", "0x10de"), ("device", "0x2204")),
                     (("uuid", uuid), ("serial", "SYNTH-SERIAL-GPU-1")))


def inventory(*components, unavailable=()):
    return Inventory(tuple(components) or (cpu(), memory(), disk(), disk("sda", "SYNTH-SERIAL-DISK-2",
                                                                          "SYNTH-WWID-2"), gpu()),
                     frozenset(unavailable))


class FakeProbe:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    def collect(self):
        self.calls += 1
        result = self.results[0] if len(self.results) == 1 else self.results.pop(0)
        if callable(result):
            return result()
        if isinstance(result, BaseException):
            raise result
        return result


class IntegrityAdminCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.path = self.root / "state.sqlite3"
        self.database = Database(self.path)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        os.chmod(self.path, 0o600)
        self.config = self.root / "deployment.json"
        self.probe = FakeProbe(inventory())
        self.running = []
        self.service_uid = os.geteuid()

    def deployment(self, config):
        return SimpleNamespace(service_uid=self.service_uid,
                               settings=SimpleNamespace(database_path=self.path))

    def holders(self, identity, name):
        self.assertEqual(self.path.name, name)
        return self.running.pop(0) if self.running else 0

    def run_cli(self, *argv, lines=(), console=None, terminal_factory=None):
        console = console or Console(self)
        console.type(*lines)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(admin_cli, "_load_deployment", self.deployment):
            code = admin_cli.main([argv[0], "--config", str(self.config), *argv[1:]],
                                  terminal_factory=terminal_factory or console.factory,
                                  probe_factory=lambda: self.probe, holders=self.holders)
        self.console = console
        return code, stdout.getvalue(), stderr.getvalue(), console.output()

    def rows(self, sql):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(sql)]

    def baseline(self):
        with closing(self.database.connect()) as connection:
            return IntegrityStore(connection, reservation=lambda: None,
                                  max_pending_events=1).baseline()

    def assertPrivateAbsent(self, *texts):
        for text in texts:
            for value in PRIVATE:
                self.assertNotIn(value, text)

    def assertNothingRecorded(self):
        self.assertEqual((0, None), self.baseline())
        self.assertEqual([], self.rows("SELECT * FROM integrity_audit"))
        self.assertEqual([], self.rows(AUDIT))

    # -- show -----------------------------------------------------------

    def test_show_without_a_baseline_prints_kinds_states_and_counts_only(self):
        code, stdout, stderr, terminal = self.run_cli("show")
        self.assertEqual((code, stderr, terminal), (0, "", ""))
        self.assertEqual(0, self.console.opened)   # read-only: no terminal
        lines = stdout.splitlines()
        self.assertEqual("baseline: revision=0 components: none", lines[0])
        self.assertEqual("current: components: CPU=1 MEMORY=1 STORAGE=2 GPU=1", lines[1])
        self.assertEqual("current vs baseline: hardware_integrity_failure", lines[2])
        self.assertIn("  STORAGE UNVERIFIABLE reason=BASELINE_REQUIRED count=1 notify=failure", lines)
        self.assertIn("  CPU UNVERIFIABLE reason=BASELINE_REQUIRED count=1 notify=warning", lines)
        # A CPU exposes no unique identifier: after approval it stays a
        # warning (daily summary), never the immediate failure.
        self.assertIn("if the current inventory were approved, an unchanged host would report: "
                      "hardware_integrity_warning", lines)
        self.assertIn("  CPU UNVERIFIABLE reason=UNIQUE_ID_UNAVAILABLE count=1 notify=warning", lines)
        self.assertIn("  STORAGE OK reason=IDENTITY_AND_PROPERTIES_MATCH count=2 notify=none", lines)
        self.assertEqual("last recorded check: none", lines[-1])
        self.assertPrivateAbsent(stdout, stderr)
        self.assertNothingRecorded()

    def test_show_is_allowed_while_the_service_runs_and_prints_its_last_check(self):
        with closing(self.database.connect()) as connection:
            store = IntegrityStore(connection, reservation=_nothing, max_pending_events=4)
            from app.integrity.model import compare
            store.record(compare(None, inventory()), admin_cli.datetime.now(admin_cli.timezone.utc))
        self.running = [1, 1, 1]
        code, stdout, stderr, _ = self.run_cli("show")
        self.assertEqual((code, stderr), (0, ""))
        tail = stdout.splitlines()[stdout.splitlines().index(
            "last recorded check: hardware_integrity_failure"):]
        self.assertEqual(5, len(tail))
        self.assertPrivateAbsent(stdout)

    def test_untrusted_reason_text_is_never_printed(self):
        from app.integrity.model import Finding, State
        lines = admin_cli.finding_lines((Finding(Kind.GPU, State.CHANGED, "serial SYNTH-SERIAL-1"),))
        self.assertEqual(["  GPU CHANGED reason=? count=1 notify=failure"], lines)

    # -- approve --------------------------------------------------------

    def test_approve_confirms_on_the_terminal_and_commits_baseline_with_audit(self):
        code, stdout, stderr, terminal = self.run_cli("approve", lines=("APPROVE",))
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("revision 0 -> 1", terminal)
        self.assertIn("current:      CPU=1 MEMORY=1 STORAGE=2 GPU=1", terminal)
        self.assertIn("Type APPROVE to confirm", terminal)
        self.assertIn("baseline approved: revision=1 components: CPU=1 MEMORY=1 STORAGE=2 GPU=1",
                      stdout)
        self.assertPrivateAbsent(stdout, stderr, terminal)
        self.assertEqual((1, inventory()), self.baseline())
        ((at, actor, revision),) = self.rows("SELECT at, actor, revision FROM integrity_audit")
        self.assertEqual((str(admin_cli.LOCAL_CONSOLE_OWNER_ID), 1), (actor, revision))
        self.assertEqual([("owner", "approve_hardware_baseline", "hardware_baseline",
                           str(HARDWARE_BASELINE_ID), "succeeded")], self.rows(AUDIT))
        stored = str(self.rows("SELECT * FROM security_admin_audit_records"))
        self.assertPrivateAbsent(stored, str(self.rows("SELECT * FROM integrity_audit")))
        # The next comparison of the unchanged host is OK.
        code, stdout, _, _ = self.run_cli("show")
        self.assertEqual(0, code)
        self.assertIn("current vs baseline: hardware_integrity_warning", stdout)
        self.assertNotIn("BASELINE_REQUIRED", stdout)
        self.assertNotIn("notify=failure", stdout)
        # Without the CPU (no unique identifier), the unchanged host is OK.
        self.probe = FakeProbe(inventory(memory(), disk(), gpu()))
        self.assertEqual(0, self.run_cli("approve", lines=("APPROVE",))[0])
        code, stdout, _, _ = self.run_cli("show")
        self.assertIn("current vs baseline: ok", stdout)

    def test_a_later_approval_advances_the_revision_and_a_change_is_shown(self):
        self.assertEqual(0, self.run_cli("approve", lines=("APPROVE",))[0])
        self.probe = FakeProbe(inventory(cpu(), memory(), disk(serial="SYNTH-SERIAL-OTHER"),
                                         disk("sda", "SYNTH-SERIAL-DISK-2", "SYNTH-WWID-2"), gpu()))
        code, stdout, _, _ = self.run_cli("show")
        self.assertEqual(0, code)
        self.assertIn("current vs baseline: hardware_integrity_failure", stdout)
        self.assertPrivateAbsent(stdout)
        code, stdout, _, terminal = self.run_cli("approve", lines=("APPROVE",))
        self.assertEqual(0, code)
        self.assertIn("revision 1 -> 2", terminal)
        self.assertEqual(2, self.baseline()[0])
        self.assertEqual(2, len(self.rows(AUDIT)))

    def test_the_approve_prompt_shows_a_same_count_replacement_against_the_baseline(self):
        self.assertEqual(0, self.run_cli("approve", lines=("APPROVE",))[0])
        self.probe = FakeProbe(inventory(cpu(), memory(), disk(serial="SYNTH-SERIAL-OTHER"),
                                         disk("sda", "SYNTH-SERIAL-DISK-2", "SYNTH-WWID-2"), gpu()))
        code, _, stderr, terminal = self.run_cli("approve", lines=("no",))
        self.assertEqual(2, code)
        self.assertIn("refused: owner_confirmation_declined", stderr)
        # The counts are unchanged; only the comparison reveals the replacement.
        self.assertIn("baseline now: CPU=1 MEMORY=1 STORAGE=2 GPU=1", terminal)
        self.assertIn("current:      CPU=1 MEMORY=1 STORAGE=2 GPU=1", terminal)
        self.assertIn("current vs baseline: hardware_integrity_failure", terminal)
        self.assertIn("    STORAGE CHANGED reason=APPROVED_COMPONENT_CHANGED count=1 notify=failure",
                      terminal)
        self.assertLess(terminal.index("current vs baseline"),
                        terminal.index("An unchanged host would then report"))
        self.assertPrivateAbsent(terminal)
        self.assertEqual(1, self.baseline()[0])

    def test_an_unavailable_kind_is_approved_and_stays_unverifiable(self):
        self.probe = FakeProbe(inventory(cpu(), disk(), gpu(), unavailable=(Kind.MEMORY,)))
        code, stdout, _, terminal = self.run_cli("approve", lines=("APPROVE",))
        self.assertEqual(0, code)
        self.assertIn("current:      CPU=1 MEMORY=unavailable STORAGE=1 GPU=1", terminal)
        self.assertIn("An unchanged host would then report: hardware_integrity_warning", terminal)
        self.assertIn("MEMORY UNVERIFIABLE reason=PROBE_UNAVAILABLE count=1 notify=warning", terminal)
        self.assertEqual(1, self.baseline()[0])

    def test_a_declined_confirmation_changes_and_records_nothing(self):
        for lines in (("no",), ("approve",), ("",), ("APPROVE APPROVE",)):
            with self.subTest(lines=lines):
                code, stdout, stderr, _ = self.run_cli("approve", lines=lines)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("refused: owner_confirmation_declined", stderr)
        self.assertNothingRecorded()

    def test_there_is_no_non_interactive_bypass(self):
        for flag in ("--yes", "--force", "--no-confirm"):
            with self.subTest(flag=flag), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as exit_:
                admin_cli.main(["approve", "--config", str(self.config), flag],
                               terminal_factory=Console(self).factory,
                               probe_factory=lambda: self.probe, holders=self.holders)
            self.assertEqual(2, exit_.exception.code)

        def no_terminal():
            raise CliRefused("controlling_terminal_required")

        code, _, stderr, _ = self.run_cli("approve", terminal_factory=no_terminal)
        self.assertEqual(2, code)
        self.assertIn("refused: controlling_terminal_required", stderr)
        self.assertEqual(0, self.probe.calls)
        self.assertNothingRecorded()

    def test_approve_refuses_while_the_service_holds_the_database(self):
        self.running = [1]
        code, stdout, stderr, terminal = self.run_cli("approve")
        self.assertEqual((code, stdout, terminal), (2, "", ""))
        self.assertIn("refused: service_running", stderr)
        # With socket activation a connection restarts a service stopped alone.
        self.assertIn("sudo systemctl stop server-sentinel-upstream.socket server-sentinel.service",
                      stderr)
        self.assertIn("bootstrap_cli", stderr)
        self.assertEqual(0, self.probe.calls)
        self.assertNothingRecorded()

    def test_a_service_started_during_the_confirmation_is_refused_inside_the_transaction(self):
        self.running = [0, 1]
        code, stdout, stderr, _ = self.run_cli("approve", lines=("APPROVE",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: service_running", stderr)
        self.assertEqual((0, None), self.baseline())
        self.assertEqual([], self.rows("SELECT * FROM integrity_audit"))
        self.assertEqual([("owner", "approve_hardware_baseline", "hardware_baseline",
                           str(HARDWARE_BASELINE_ID), "failed")], self.rows(AUDIT))

    def test_a_baseline_changed_meanwhile_is_refused_by_its_revision(self):
        other = inventory(cpu())

        def concurrent_approval():
            # Another approver commits revision 1 between the prompt and the approval.
            with closing(self.database.connect()) as connection:
                connection.execute("INSERT INTO integrity_baseline VALUES(1, 1, ?)",
                                   ('{"components":[],"unavailable":[]}',))
            return inventory()

        self.probe = FakeProbe(inventory(), concurrent_approval)
        code, stdout, stderr, _ = self.run_cli("approve", lines=("APPROVE",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: baseline_revision_changed", stderr)
        self.assertEqual((1, Inventory(())), self.baseline())
        self.assertNotEqual(other, self.baseline()[1])
        self.assertEqual([], self.rows("SELECT * FROM integrity_audit"))
        self.assertEqual([("owner", "approve_hardware_baseline", "hardware_baseline",
                           str(HARDWARE_BASELINE_ID), "failed")], self.rows(AUDIT))

    def test_an_inventory_that_changed_after_the_prompt_is_refused(self):
        self.probe = FakeProbe(inventory(), inventory(cpu(), memory(), disk(), gpu()))
        code, stdout, stderr, _ = self.run_cli("approve", lines=("APPROVE",))
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: inventory_changed", stderr)
        self.assertNothingRecorded()
        # The same components in another order are the same inventory.
        components = inventory().components
        self.probe = FakeProbe(inventory(), Inventory(tuple(reversed(components))))
        self.assertEqual(0, self.run_cli("approve", lines=("APPROVE",))[0])

    def test_an_empty_or_failed_collection_is_refused(self):
        for result, reason in ((Inventory((), frozenset(Kind)), "inventory_empty"),
                               (OSError("synthetic SYNTH-SERIAL-9"), "inventory_unavailable"),
                               ("not an inventory", "inventory_unavailable")):
            with self.subTest(reason=reason):
                self.probe = FakeProbe(result)
                code, stdout, stderr, terminal = self.run_cli("approve")
                self.assertEqual((code, stdout, terminal), (2, "", ""))
                self.assertIn(f"refused: {reason}", stderr)
                self.assertPrivateAbsent(stderr)
        self.assertNothingRecorded()

    def test_the_baseline_approval_needs_a_consumed_console_grant(self):
        owner = admin_cli._ConsoleOwner()
        approval = admin_cli._ConsoleBaselineApproval(owner)
        with self.assertRaises(PermissionError):
            approval.require_owner()
        with self.assertRaises(PermissionError):
            owner.require_owner(object())
        with self.assertRaises(PermissionError):
            approval.require_owner()

    def test_refuses_root_another_account_and_another_schema(self):
        for euid in (0, os.geteuid() + 1):
            with self.subTest(euid=euid), patch.object(admin_cli.os, "geteuid", return_value=euid):
                code, _, stderr, _ = self.run_cli("show")
            self.assertEqual(2, code)
            self.assertIn("refused: run_as_service_account", stderr)
        with closing(self.database.connect()) as connection:
            connection.execute("DELETE FROM schema_migrations WHERE version = "
                               "(SELECT max(version) FROM schema_migrations)")
            connection.commit()
        code, _, stderr, _ = self.run_cli("show")
        self.assertEqual(2, code)
        self.assertIn("refused: database_schema_outdated", stderr)
        self.assertEqual(0, self.probe.calls)


class _Nothing:
    def __enter__(self):
        return None

    def __exit__(self, *details):
        return False


def _nothing():
    return _Nothing()


if __name__ == "__main__":
    unittest.main()
