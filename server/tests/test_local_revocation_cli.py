"""Issue #10 phase 2 S4c: the local emergency administration commands.

``python -m app.auth.bootstrap_cli list|revoke-principal|revoke-credential``
(Owner decisions D6, S4-3 and S4-6). Synthetic only: a temporary SQLite
database, a pseudo-terminal from ``os.openpty`` standing in for the
controlling terminal, invented ``.invalid`` identities, synthetic credential
bytes and software authenticators. No sudo, real terminal, browser, proxy or
authenticator, and never a real deployment database; mock only.
"""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from app import local_admin
from app.auth import bootstrap_cli
from app.auth.human_surface import SESSION_PATH
from app.auth.model import AccessValidationError, Permission
from app.auth.store import MAX_PRINCIPALS, Requirement
from app.local_admin import ControllingTerminal
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests import test_bootstrap_cli as s2
from tests.test_bootstrap_cli import AUDIT, IDENTITY, NOW, Console
from tests.test_human_gated_authorization import GatedFixture
from tests.test_human_surface import VIEWER, call, status


UNKNOWN = "00000000-0000-4000-8000-000000000000"
LINE = re.compile(r"principal (?P<id>[0-9a-f-]{36}) role=(?P<role>\S+) status=(?P<status>\S+) "
                  r"permissions=(?P<permissions>\S+) name=(?P<name>\".*\")$")
CREDENTIAL_LINE = re.compile(r"  credential (?P<handle>[0-9a-f-]{36}) status=(?P<status>\S+) "
                             r"label=(?P<label>\".*\"|-)$")
ACCESS_TABLES = ("access_principals", "access_principal_permissions", "access_invitations",
                 "access_credentials", "access_sessions", "security_admin_audit_records")


class LocalAdministrationFixture(unittest.TestCase):
    """The S2 command fixture (pseudo-terminal, pinned database) with a populated store."""

    deployment = s2.BootstrapCliTests.deployment
    rows = s2.BootstrapCliTests.rows
    database_bytes = s2.BootstrapCliTests.database_bytes

    def setUp(self):
        s2.BootstrapCliTests.setUp(self)
        self.owner = self.store.bootstrap_owner("Synthetic Owner")
        self.owner_credential = self.credential(self.owner.id, label="Synthetic Owner passkey")
        self.viewer = self.store.invite("Synthetic viewer", (Permission.LIVE_VIEW,))
        self.first = self.credential(self.viewer.id, label="Synthetic phone")
        self.second = self.credential(self.viewer.id, label=None)
        self.other = self.store.invite("Synthetic other", (Permission.RECORDINGS_VIEW,))
        self.other_credential = self.credential(self.other.id, label="Synthetic laptop")
        self.sequence()

    def sequence(self):
        """Distinct creation times in creation order (every row was made at ``NOW``)."""
        with closing(self.database.connect()) as connection:
            for table, column, key in (("access_principals", "created_at_us", "id"),
                                       ("access_credentials", "enrolled_at_us", "credential_id")):
                keys = [row[0] for row in connection.execute(f"SELECT {key} FROM {table} ORDER BY rowid")]
                for index, value in enumerate(keys):
                    connection.execute(f"UPDATE {table} SET {column}={column}+? WHERE {key}=?", (index, value))

    def credential(self, principal_id, *, label):
        secret = secrets.token_bytes(20)
        self.store.issue_enrollment(principal_id, secret, NOW.replace(hour=12))
        return self.store.enroll_credential(secret, IDENTITY, secrets.token_bytes(32), b"synthetic-key", -7, 0,
                                            label=label)

    def handle(self, credential):
        return self.rows(f"SELECT handle FROM access_credentials WHERE credential_id=X'{credential.credential_id.hex()}'")[0][0]

    def session(self, credential):
        token = secrets.token_bytes(32)
        self.store.establish_session(credential.principal_id, credential.credential_id, token,
                                     proxy_identity=IDENTITY)
        return token

    def state(self):
        with closing(self.database.connect()) as connection:
            return [tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                    for table in ACCESS_TABLES]

    def run_cli(self, command, *lines, arguments=(), console=None, path=None, terminal_factory=None):
        console = console or Console(self)
        console.type(*lines)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(bootstrap_cli, "_load_deployment", self.deployment(path or self.path)):
            code = bootstrap_cli.main([command, "--config", str(self.config), *arguments],
                                      terminal_factory=terminal_factory or console.factory,
                                      clock=self.clock)
        return code, stdout.getvalue(), stderr.getvalue(), console.output()


class ListTests(LocalAdministrationFixture):
    def test_list_prints_exactly_the_owner_view_fields(self):
        revoked = self.store.invite("Synthetic revoked", ())
        self.store.revoke_principal(revoked.id)
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_credentials SET revoked_at_us=1 WHERE credential_id=?",
                               (self.second.credential_id,))
        code, stdout, stderr, _ = self.run_cli("list")
        self.assertEqual((code, stderr), (0, ""))
        h = self.handle
        self.assertEqual(stdout.splitlines(), [
            f"principal {self.owner.id} role=owner status=active "
            "permissions=live:view,recordings:view name=\"Synthetic Owner\"",
            f"  credential {h(self.owner_credential)} status=active label=\"Synthetic Owner passkey\"",
            f"principal {self.viewer.id} role=invited_user status=active permissions=live:view "
            "name=\"Synthetic viewer\"",
            f"  credential {h(self.first)} status=active label=\"Synthetic phone\"",
            f"  credential {h(self.second)} status=revoked label=-",
            f"principal {self.other.id} role=invited_user status=active permissions=recordings:view "
            "name=\"Synthetic other\"",
            f"  credential {h(self.other_credential)} status=active label=\"Synthetic laptop\"",
            f"principal {revoked.id} role=invited_user status=revoked permissions=- "
            "name=\"Synthetic revoked\"",
        ])
        # Exactly these fields on every line, and nothing else.
        for line in stdout.splitlines():
            self.assertTrue(LINE.match(line) or CREDENTIAL_LINE.match(line), line)

    def test_list_never_shows_identity_credential_ids_keys_or_codes(self):
        self.session(self.first)
        self.store.issue_enrollment(self.other.id, b"\x07" * 20, NOW.replace(hour=11))
        # The last observed login is stored (D14: stored, never shown).
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_principals SET external_identity=? WHERE id=?",
                               (IDENTITY, str(self.viewer.id)))
        code, stdout, stderr, terminal = self.run_cli("list")
        self.assertEqual(code, 0)
        output = stdout + stderr + terminal
        for value in (IDENTITY, "synthetic-room-account", "synthetic-key", "credential_id", "sign_count",
                      "public_key", "digest", "session", "invitation", "expires"):
            self.assertNotIn(value, output)
        for credential in (self.owner_credential, self.first, self.second, self.other_credential):
            for form in (credential.credential_id.hex(), repr(credential.credential_id)):
                self.assertNotIn(form, output)

    def test_list_reads_through_the_pinned_database_never_by_pathname(self):
        with patch.object(Database, "connect_read_only", side_effect=AssertionError("unpinned read")):
            code, stdout, stderr, _ = self.run_cli("list")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(str(self.viewer.id), stdout)

    def test_list_writes_nothing(self):
        before = (self.state(), self.database_bytes())
        code, _, _, terminal = self.run_cli("list")
        self.assertEqual((code, terminal), (0, ""))
        self.assertEqual((self.state(), self.database_bytes()), before)

    def test_names_and_labels_are_escaped_and_bounded(self):
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_principals SET display_name=? WHERE id=?",
                               ("Synthetic \x1b[2Jname ‮\"quoted\" \\ " + "x" * 200, str(self.viewer.id)))
            connection.execute("UPDATE access_credentials SET label=? WHERE credential_id=?",
                               ("phone\x07\n", self.first.credential_id))
        code, stdout, _, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", stdout)
        self.assertNotIn("‮", stdout)
        self.assertNotIn("\x07", stdout)
        (line,) = [line for line in stdout.splitlines() if str(self.viewer.id) in line]
        self.assertIn('name="Synthetic \\u001b[2Jname \\u202e\\"quoted\\" \\\\ ', line)
        self.assertTrue(line.endswith('x..."'))
        self.assertLess(len(line), 400)
        self.assertIn('label="phone\\u0007\\u000a"', stdout)

    def insert_credentials(self, principal_id, count, *, revoked):
        handles = []
        with closing(self.database.connect()) as connection:
            for index in range(count):
                handle = str(uuid4())
                connection.execute(
                    "INSERT INTO access_credentials (credential_id, principal_id, public_key, algorithm, sign_count, "
                    "enrolled_at_us, revoked_at_us, handle) VALUES (?, ?, ?, -7, 0, ?, ?, ?)",
                    (secrets.token_bytes(32), str(principal_id), b"synthetic-key", 10 + index,
                     1 if revoked else None, handle))
                handles.append(handle)
        return handles

    def insert_revoked_principals(self, count):
        with closing(self.database.connect()) as connection:
            for index in range(count):
                connection.execute("INSERT INTO access_principals VALUES (?, NULL, ?, 'invited_user', 'revoked', 0, ?, ?)",
                                   (str(uuid4()), f"Synthetic revoked {index}", index + 1, index + 1))

    def test_list_bounds_only_revoked_entries(self):
        self.insert_revoked_principals(bootstrap_cli.MAX_LISTED_REVOKED_PRINCIPALS + 3)
        self.insert_credentials(self.viewer.id, bootstrap_cli.MAX_LISTED_REVOKED_CREDENTIALS + 2, revoked=True)
        code, stdout, _, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        lines = stdout.splitlines()
        principals = [line for line in lines if line.startswith("principal ")]
        self.assertEqual(len(principals), 3 + bootstrap_cli.MAX_LISTED_REVOKED_PRINCIPALS)
        # Principals that are not revoked come first, credentials not revoked first.
        self.assertTrue(all("status=revoked" not in line for line in principals[:3]))
        self.assertTrue(all("status=revoked" in line for line in principals[3:]))
        self.assertEqual(lines[-1], "revoked principals not shown: 3")
        viewer = lines.index(next(line for line in lines if str(self.viewer.id) in line))
        self.assertIn(f"credential {self.handle(self.first)} status=active", lines[viewer + 1])
        self.assertIn(f"credential {self.handle(self.second)} status=active", lines[viewer + 2])
        revoked = lines[viewer + 3:viewer + 3 + bootstrap_cli.MAX_LISTED_REVOKED_CREDENTIALS]
        self.assertTrue(all(CREDENTIAL_LINE.match(line)["status"] == "revoked" for line in revoked))
        self.assertEqual(lines[viewer + 3 + bootstrap_cli.MAX_LISTED_REVOKED_CREDENTIALS],
                         "  revoked credentials not shown: 2")

    def test_every_credential_that_is_not_revoked_stays_addressable(self):
        # PR #241 review: no store cap bounds a person's active credentials,
        # so ``list`` must never hide one the emergency command could revoke.
        many = 3 * bootstrap_cli.MAX_LISTED_REVOKED_CREDENTIALS + 40
        revoked = self.insert_credentials(self.viewer.id, many, revoked=True)
        active = self.insert_credentials(self.viewer.id, many, revoked=False)
        with closing(self.database.connect()) as connection:
            # An inconsistent credential is not revoked and stays a target.
            connection.execute("UPDATE access_credentials SET inconsistent_at_us=1, inconsistency_reason='backup_eligibility_changed' "
                               "WHERE handle=?", (active[-1],))
        code, stdout, _, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        listed = {match["handle"]: match["status"] for match in map(CREDENTIAL_LINE.match, stdout.splitlines())
                  if match}
        for handle in active + [self.handle(self.first), self.handle(self.second)]:
            self.assertIn(handle, listed)
        self.assertEqual(listed[active[-1]], "inconsistent")
        self.assertEqual(sum(1 for handle in revoked if handle in listed),
                         bootstrap_cli.MAX_LISTED_REVOKED_CREDENTIALS)
        self.assertIn(f"  revoked credentials not shown: {many - bootstrap_cli.MAX_LISTED_REVOKED_CREDENTIALS}",
                      stdout.splitlines())
        # A handle only the untruncated listing shows is revocable by the command.
        for handle in (active[-2], active[-1]):
            code, _, stderr, _ = self.run_cli("revoke-credential", "REVOKE", arguments=[str(self.viewer.id), handle])
            self.assertEqual((code, stderr), (0, ""))

    def test_every_principal_that_is_not_revoked_is_listed(self):
        self.insert_revoked_principals(2 * bootstrap_cli.MAX_LISTED_REVOKED_PRINCIPALS)
        alive = [self.owner.id, self.viewer.id, self.other.id]
        # The store keeps at most MAX_PRINCIPALS principals that are not revoked.
        alive += [self.store.invite(f"Synthetic extra {index}", ()).id
                  for index in range(MAX_PRINCIPALS - len(alive))]
        code, stdout, _, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        listed = {match["id"]: match["status"] for match in map(LINE.match, stdout.splitlines()) if match}
        self.assertEqual(len(alive), MAX_PRINCIPALS)
        for principal_id in alive:
            self.assertNotEqual(listed[str(principal_id)], "revoked")
        self.assertEqual(stdout.splitlines()[-1],
                         f"revoked principals not shown: {bootstrap_cli.MAX_LISTED_REVOKED_PRINCIPALS}")

    def test_the_pinned_read_connection_refuses_writes(self):
        database = local_admin._existing_database(self.path)
        try:
            with closing(database.connect_read_only()) as connection:
                self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 1)
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("DELETE FROM access_principal_permissions")
        finally:
            database.release()
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals")[0][0], 3)

    def test_an_empty_database_lists_no_principals(self):
        with closing(self.database.connect()) as connection:
            for table in ("access_credentials", "access_invitations", "access_principal_permissions",
                          "access_principals"):
                connection.execute(f"DELETE FROM {table}")
        code, stdout, _, _ = self.run_cli("list")
        self.assertEqual((code, stdout), (0, "no principals\n"))


class RevocationTests(LocalAdministrationFixture):
    def test_revoke_principal_commits_the_effect_and_one_record(self):
        first, second = self.session(self.first), self.session(self.second)
        other = self.session(self.other_credential)
        pending = secrets.token_bytes(20)
        self.store.issue_enrollment(self.viewer.id, pending, NOW.replace(hour=11))
        before = self.rows(AUDIT)
        code, stdout, stderr, terminal = self.run_cli("revoke-principal", "REVOKE", arguments=[str(self.viewer.id)])
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(stdout, f"principal revoked: principal_id={self.viewer.id}\n")
        self.assertIn("on all the devices it synced to", terminal)
        self.assertIn("Synthetic viewer", terminal)
        self.assertEqual(self.rows(AUDIT), before + [
            ("owner", "revoke_principal", "principal", str(self.viewer.id), "succeeded")])
        self.assertEqual(self.rows(f"SELECT status, external_identity FROM access_principals WHERE id='{self.viewer.id}'"),
                         [("revoked", None)])
        self.assertEqual(self.rows(f"SELECT count(*) FROM access_credentials WHERE principal_id='{self.viewer.id}' "
                                   "AND revoked_at_us IS NULL"), [(0,)])
        self.assertEqual(self.rows(f"SELECT count(*) FROM access_invitations WHERE principal_id='{self.viewer.id}' "
                                   "AND redeemed_at_us IS NULL AND revoked_at_us IS NULL"), [(0,)])
        for token in (first, second):
            with self.assertRaises(AccessValidationError):
                self.store.authorize(token, IDENTITY, Permission.LIVE_VIEW)
        with self.assertRaises(AccessValidationError):
            self.store.enroll_credential(pending, IDENTITY, secrets.token_bytes(32), b"synthetic-key", -7, 0)
        # Another person is untouched.
        self.assertEqual(self.store.authorize(other, IDENTITY, Permission.RECORDINGS_VIEW).id, self.other.id)

    def test_revoke_credential_revokes_only_that_credential_and_its_sessions(self):
        first, second = self.session(self.first), self.session(self.second)
        handle = self.handle(self.first)
        before = self.rows(AUDIT)
        code, stdout, stderr, terminal = self.run_cli("revoke-credential", "REVOKE",
                                                      arguments=[str(self.viewer.id), handle])
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(stdout, "credential revoked on all synced devices: "
                                 f"principal_id={self.viewer.id} handle={handle}\n")
        self.assertIn("this passkey is revoked on all the devices it synced to", terminal)
        self.assertIn("not a per-device revocation", terminal)
        self.assertIn('label="Synthetic phone"', terminal)
        self.assertEqual(self.rows(AUDIT), before + [
            ("owner", "revoke_principal_credential", "principal", str(self.viewer.id), "succeeded")])
        self.assertEqual(self.rows(f"SELECT handle, revoked_at_us IS NOT NULL FROM access_credentials "
                                   f"WHERE principal_id='{self.viewer.id}' ORDER BY revoked_at_us IS NULL"),
                         [(handle, 1), (self.handle(self.second), 0)])
        with self.assertRaises(AccessValidationError):
            self.store.authorize(first, IDENTITY, Permission.LIVE_VIEW)
        self.assertEqual(self.store.authorize(second, IDENTITY, Permission.LIVE_VIEW).id, self.viewer.id)
        self.assertEqual(self.rows(f"SELECT status FROM access_principals WHERE id='{self.viewer.id}'"), [("active",)])

    def test_the_handle_and_principal_may_be_given_in_upper_case(self):
        handle = self.handle(self.first)
        code, _, stderr, _ = self.run_cli("revoke-credential", "REVOKE",
                                          arguments=[str(self.viewer.id).upper(), handle.upper()])
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(self.rows(f"SELECT revoked_at_us IS NOT NULL FROM access_credentials WHERE handle='{handle}'"),
                         [(1,)])

    def assert_refused(self, command, arguments, reason, *lines):
        before = self.state()
        code, stdout, stderr, _ = self.run_cli(command, *lines, arguments=arguments)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn(f"refused: {reason}\n", stderr)
        self.assertEqual(self.state(), before)
        return stderr

    def test_the_owner_is_never_a_target_and_the_refusal_points_to_recover(self):
        token = self.session(self.owner_credential)
        for command, arguments in (("revoke-principal", [str(self.owner.id)]),
                                   ("revoke-credential", [str(self.owner.id), self.handle(self.owner_credential)])):
            with self.subTest(command=command):
                stderr = self.assert_refused(command, arguments, "owner_target_use_recover", "REVOKE")
                self.assertIn("'recover'", stderr)
        self.assertEqual(self.store.authorize(token, IDENTITY, Permission.LIVE_VIEW).id, self.owner.id)

    def test_unknown_malformed_foreign_and_revoked_targets_are_refused(self):
        handle = self.handle(self.first)
        cases = [
            ("revoke-principal", [UNKNOWN], "principal_not_found"),
            ("revoke-principal", ["not-a-uuid"], "principal_id_rejected"),
            ("revoke-principal", [str(self.viewer.id).replace("-", "")], "principal_id_rejected"),
            ("revoke-credential", [UNKNOWN, handle], "principal_not_found"),
            ("revoke-credential", [str(self.viewer.id), "x" * 36], "credential_handle_rejected"),
            ("revoke-credential", [str(self.viewer.id), UNKNOWN], "credential_not_found"),
            # Another principal's handle.
            ("revoke-credential", [str(self.viewer.id), self.handle(self.other_credential)], "credential_not_found"),
            # A WebAuthn credential id is not a handle.
            ("revoke-credential", [str(self.viewer.id), self.first.credential_id.hex()], "credential_handle_rejected"),
        ]
        for command, arguments, reason in cases:
            with self.subTest(arguments=arguments):
                self.assert_refused(command, arguments, reason, "REVOKE")
        code, _, _, _ = self.run_cli("revoke-credential", "REVOKE", arguments=[str(self.viewer.id), handle])
        self.assertEqual(code, 0)
        self.assert_refused("revoke-credential", [str(self.viewer.id), handle], "credential_already_revoked", "REVOKE")
        code, _, _, _ = self.run_cli("revoke-principal", "REVOKE", arguments=[str(self.viewer.id)])
        self.assertEqual(code, 0)
        self.assert_refused("revoke-principal", [str(self.viewer.id)], "principal_already_revoked", "REVOKE")
        self.assert_refused("revoke-credential", [str(self.viewer.id), self.handle(self.second)],
                            "principal_already_revoked", "REVOKE")

    def test_a_declined_confirmation_changes_nothing(self):
        for word in ("revoke", "", "REVOKE ALL", "RECOVER"):
            for command, arguments in (("revoke-principal", [str(self.viewer.id)]),
                                       ("revoke-credential", [str(self.viewer.id), self.handle(self.first)])):
                with self.subTest(word=word, command=command):
                    self.assert_refused(command, arguments, "owner_confirmation_declined", word)

    def test_a_target_changed_after_the_confirmation_is_refused_in_the_transaction(self):
        console = Console(self)
        terminal = console.factory()
        original = terminal.read_line

        def read_line():
            # The Web route revoked the person while the console waited.
            word = original()
            with self.store._transaction(write=True) as connection:
                self.store.revoke_principal_on(connection, self.viewer.id, at=NOW)
            return word

        terminal.read_line = read_line
        before = self.rows(AUDIT)
        code, stdout, stderr, _ = self.run_cli("revoke-credential", "REVOKE",
                                               arguments=[str(self.viewer.id), self.handle(self.first)],
                                               console=console, terminal_factory=lambda: terminal)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: principal_already_revoked", stderr)
        self.assertEqual(self.rows(AUDIT), before)

    def test_a_database_renamed_or_replaced_during_the_confirmation_is_refused(self):
        moved = self.root / "moved.sqlite3"

        def replace():
            copy = self.root / "copy.sqlite3"
            shutil.copy2(self.path, copy)
            os.replace(copy, self.path)

        def rename():
            os.rename(self.path, moved)

        def state(path):
            with closing(Database(path).connect()) as connection:
                return [tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                        for table in ACCESS_TABLES]

        for change in (replace, rename):
            for command, arguments in (("revoke-principal", [str(self.viewer.id)]),
                                       ("revoke-credential", [str(self.viewer.id), self.handle(self.first)])):
                with self.subTest(change=change.__name__, command=command):
                    before = state(self.path)
                    console = Console(self)
                    terminal = console.factory()
                    original = terminal.read_line

                    def read_line(original=original, change=change):
                        word = original()
                        change()
                        return word

                    terminal.read_line = read_line
                    code, stdout, stderr, _ = self.run_cli(command, "REVOKE", arguments=arguments, console=console,
                                                           terminal_factory=lambda terminal=terminal: terminal)
                    self.assertEqual((code, stdout), (2, ""))
                    self.assertIn("refused: database_rejected\n", stderr)
                    if change is rename:
                        self.assertFalse(self.path.exists())
                        self.assertEqual(state(moved), before)
                        os.rename(moved, self.path)
                    self.assertEqual(state(self.path), before)

    def test_a_verification_failure_after_the_commit_says_it_was_committed(self):
        original = bootstrap_cli.revoke_principal

        def revoke_then_replace(store, principal_id):
            original(store, principal_id)
            copy = self.root / "copy.sqlite3"
            shutil.copy2(self.path, copy)
            os.replace(copy, self.path)

        before = self.rows(AUDIT)
        with patch.object(bootstrap_cli, "revoke_principal", revoke_then_replace):
            code, stdout, stderr, _ = self.run_cli("revoke-principal", "REVOKE", arguments=[str(self.viewer.id)])
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: committed_verification_failed\n", stderr)
        self.assertIn("the revocation was committed", stderr)
        # Issue #243 item 1: re-checked with 'list' and re-run, not "do not repeat it".
        self.assertIn("run 'list': if the target is still not revoked, investigate the state directory "
                      "and re-run the command", stderr)
        self.assertNotIn("do not repeat", stderr)
        # Committed with its audit record before the verification failed.
        self.assertEqual(self.rows(AUDIT), before + [
            ("owner", "revoke_principal", "principal", str(self.viewer.id), "succeeded")])
        self.assertEqual(self.rows(f"SELECT status FROM access_principals WHERE id='{self.viewer.id}'"),
                         [("revoked",)])

    def test_a_failed_audit_append_rolls_the_revocation_back(self):
        before = self.state()
        with patch.object(bootstrap_cli.AuditStore, "append_on", side_effect=RuntimeError("synthetic")):
            code, stdout, stderr, _ = self.run_cli("revoke-principal", "REVOKE", arguments=[str(self.viewer.id)])
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: database_unavailable", stderr)
        self.assertEqual(self.state(), before)

    def test_nothing_secret_is_taken_from_arguments(self):
        for argv in (["revoke-principal", "--config", str(self.config)],
                     ["revoke-principal", "--config", str(self.config), str(self.viewer.id), "extra"],
                     ["revoke-credential", "--config", str(self.config), str(self.viewer.id)],
                     ["list", "--config", str(self.config), "--identity", IDENTITY]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                bootstrap_cli.main(argv)


class SharedChecksTests(LocalAdministrationFixture):
    """The S2 checks apply to every S4c command, before any change."""

    def commands(self):
        return (("list", [], ()),
                ("revoke-principal", [str(self.viewer.id)], ("REVOKE",)),
                ("revoke-credential", [str(self.viewer.id), self.handle(self.first)], ("REVOKE",)))

    def assert_each_refused(self, reason, **options):
        before = self.state()
        for command, arguments, lines in self.commands():
            with self.subTest(command=command):
                code, stdout, stderr, _ = self.run_cli(command, *lines, arguments=arguments, **options)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(f"refused: {reason}\n", stderr)
        self.assertEqual(self.state(), before)

    def test_refuses_root_and_another_account(self):
        with patch.object(bootstrap_cli.os, "geteuid", return_value=0):
            self.assert_each_refused("run_as_service_account")
        self.service_uid = os.geteuid() + 1
        self.assert_each_refused("run_as_service_account")

    def test_refuses_an_unusable_deployment_configuration(self):
        def broken(config):
            raise ValueError("synthetic configuration failure")

        for command, arguments, lines in self.commands():
            console = Console(self)
            stderr = io.StringIO()
            with self.subTest(command=command), redirect_stdout(io.StringIO()), redirect_stderr(stderr), \
                    patch.object(bootstrap_cli, "_load_deployment", broken):
                code = bootstrap_cli.main([command, "--config", str(self.config), *arguments],
                                          terminal_factory=console.factory, clock=self.clock)
            self.assertEqual(code, 2)
            self.assertIn("refused: deployment_configuration_rejected", stderr.getvalue())
            self.assertEqual(console.opened, 0)

    def test_refuses_without_a_controlling_terminal(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)

        def no_terminal(path, flags):
            raise OSError(6, "no controlling terminal")

        for opener in (no_terminal, lambda path, flags: os.dup(read_end)):
            self.assert_each_refused("controlling_terminal_required",
                                     terminal_factory=lambda: ControllingTerminal(opener=opener))

    def test_refuses_a_database_it_cannot_trust(self):
        missing = self.root / "missing.sqlite3"
        self.assert_each_refused("database_not_found", path=missing)
        self.assertFalse(missing.exists())
        link = self.root / "link.sqlite3"
        link.symlink_to(self.path)
        self.assert_each_refused("database_path_rejected", path=link)
        self.assert_each_refused("database_path_rejected", path=Path("state.sqlite3"))

    def test_refuses_an_outdated_or_newer_schema(self):
        outdated = self.root / "outdated.sqlite3"
        with closing(Database(outdated).connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS[:-1])
        self.assert_each_refused("database_schema_outdated", path=outdated)
        with closing(self.database.connect()) as connection:
            connection.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)",
                               (APPLICATION_MIGRATIONS[-1].version + 1, "synthetic_future", "0" * 64))
        self.assert_each_refused("database_schema_unsupported")


class RunningServerTests(GatedFixture):
    """A revocation committed by the local command while a ``HumanAccess`` serves.

    The command commits outside the gate (D6); the serving process re-reads
    the session, credential and principal inside the next request's own
    transaction, so that request is denied.
    """

    def run_cli(self, command, *arguments):
        console = Console(self)
        console.type("REVOKE")
        path = Path(os.path.realpath(self.database.path))
        def deployment(config):
            return SimpleNamespace(service_uid=os.geteuid(), settings=SimpleNamespace(
                database_path=path, invitation_lifetime=self.store.invitation_lifetime))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(bootstrap_cli, "_load_deployment", deployment):
            code = bootstrap_cli.main([command, "--config", "/synthetic/deployment.json", *arguments],
                                      terminal_factory=console.factory, clock=self.ceremony_clock)
        self.assertEqual((code, stderr.getvalue()), (0, ""))

    def handle(self, credential):
        with closing(self.database.connect()) as connection:
            return connection.execute("SELECT handle FROM access_credentials WHERE credential_id=?",
                                      (credential.credential_id,)).fetchone()[0]

    async def served(self, cookie):
        return status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie))

    async def test_the_next_request_of_a_revoked_principal_is_denied(self):
        principal, key, _ = self.enroll((Permission.LIVE_VIEW,))
        _, other_key, _ = self.enroll((Permission.LIVE_VIEW,))
        cookie, other = await self.sign_in(key), await self.sign_in(other_key)
        self.assertEqual(await self.served(cookie), 200)
        token = self.token(cookie)
        self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())
        self.run_cli("revoke-principal", str(principal.id))
        denial = await self.denial()
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), denial)
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())
        # Another person's session is untouched.
        self.assertEqual(await self.served(other), 200)

    async def test_the_next_request_of_a_revoked_credential_is_denied(self):
        principal, key, credential = self.enroll((Permission.LIVE_VIEW,))
        cookie = await self.sign_in(key)
        self.assertEqual(await self.served(cookie), 200)
        self.run_cli("revoke-credential", str(principal.id), self.handle(credential))
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), await self.denial())
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(self.token(cookie), VIEWER, Requirement.SESSION, admit=self.gated())
        with closing(self.database.connect()) as connection:
            self.assertEqual(connection.execute("SELECT status FROM access_principals WHERE id=?",
                                                (str(principal.id),)).fetchone()[0], "active")

    async def test_revocation_works_while_human_access_is_closed(self):
        principal, key, _ = self.enroll((Permission.LIVE_VIEW,))
        cookie = await self.sign_in(key)
        self.close_access()
        self.run_cli("revoke-principal", str(principal.id))
        self.reopen_access()
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), await self.denial())
