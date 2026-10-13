"""Issue #10 phase 2 S2: the local Owner bootstrap/recovery command.

Synthetic only: a temporary SQLite database, a pseudo-terminal from
``os.openpty`` standing in for the controlling terminal, invented
``.invalid`` identities and synthetic credential bytes. No sudo, no real
terminal, browser or authenticator; mock only.
"""

from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import io
import os
from pathlib import Path
import re
import secrets
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from app.audit.store import AuditStore
from app.auth import bootstrap_cli
from app.auth.invitation_code import INVITATION_LIFETIME, parse_invitation_code
from app.auth.model import AccessValidationError, Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.session_binding import SessionBindingKey
from app.auth.store import AccessStore
from app.auth.webauthn import RelyingParty
from app.local_admin import ControllingTerminal
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.webauthn_fakes import ORIGIN, RP_ID, OpenGate, SyntheticAuthenticator, b64


NOW = datetime(2026, 10, 11, 9, 0, tzinfo=timezone.utc)
IDENTITY = "synthetic-room-account@example.invalid"
CODE = re.compile(r"[0-9A-Z]{4}(?:-[0-9A-Z]{4}){7}")
AUDIT = "SELECT actor_category, action, target_kind, target_logical_id, outcome " \
        "FROM security_admin_audit_records ORDER BY rowid"


class Console:
    """A pseudo-terminal: input is queued on the master side, output read back."""

    def __init__(self, test):
        self.master, self.slave = os.openpty()
        test.addCleanup(os.close, self.master)
        test.addCleanup(os.close, self.slave)
        os.set_blocking(self.master, False)
        self.opened = 0

    def type(self, *lines):
        os.write(self.master, "".join(line + "\n" for line in lines).encode())

    def factory(self):
        def opener(path, flags):
            assert path == "/dev/tty"
            self.opened += 1
            return os.dup(self.slave)
        return ControllingTerminal(opener=opener)

    def output(self) -> str:
        data = b""
        while True:
            try:
                chunk = os.read(self.master, 4096)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EIO):
                    break
                raise
            if not chunk:
                break
            data += chunk
        return data.decode()


class BootstrapCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.path = self.root / "state.sqlite3"
        self.database = Database(self.path)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = lambda: NOW
        self.store = AccessStore(self.database, clock=self.clock, audit=AuditStore(self.database, clock=self.clock),
                                 unaudited_writes=True, session_binding=SessionBindingKey.generate())
        # The deployment configuration the command loads (``--config``):
        # ``Deployment.load`` itself is covered by the deployment tests; here
        # it is replaced by what it yields.
        self.config = self.root / "deployment.json"
        self.lifetime = INVITATION_LIFETIME
        self.service_uid = os.geteuid()
        self.loaded = []

    def deployment(self, path):
        def load(config):
            self.loaded.append(config)
            return SimpleNamespace(service_uid=self.service_uid, settings=SimpleNamespace(
                database_path=path, invitation_lifetime=self.lifetime))
        return load

    def run_cli(self, command, *lines, console=None, path=None, terminal_factory=None):
        console = console or Console(self)
        console.type(*lines)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(bootstrap_cli, "_load_deployment", self.deployment(path or self.path)):
            code = bootstrap_cli.main([command, "--config", str(self.config)],
                                      terminal_factory=terminal_factory or console.factory,
                                      clock=self.clock)
        return code, stdout.getvalue(), stderr.getvalue(), console.output()

    def rows(self, sql):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(sql)]

    def database_bytes(self):
        return b"".join(path.read_bytes() for path in self.root.iterdir() if path.name.startswith("state"))

    def bootstrap(self):
        code, stdout, stderr, terminal = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
        self.assertEqual((code, stderr), (0, ""))
        (display,) = CODE.findall(terminal)
        owner = UUID(re.search(r"principal_id=([0-9a-f-]{36})", stdout).group(1))
        return owner, display, stdout

    def test_bootstrap_creates_the_owner_and_shows_its_code_only_on_the_terminal(self):
        owner, display, stdout = self.bootstrap()
        secret = parse_invitation_code(display)
        self.assertNotIn(display, stdout)
        self.assertIn("code_expires_at=" + (NOW + INVITATION_LIFETIME).isoformat(timespec="seconds"), stdout)
        self.assertEqual(self.rows("SELECT id, role, status, display_name, external_identity FROM access_principals"),
                         [(str(owner), "owner", "invited", "Synthetic Owner", None)])
        ((digest, issued, expires, generation, redeemed),) = self.rows(
            "SELECT secret_digest, issued_at_us, expires_at_us, deployment_generation, redeemed_at_us "
            "FROM access_invitations")
        self.assertEqual(bytes(digest), hashlib.sha256(secret).digest())
        self.assertEqual(expires - issued, int(INVITATION_LIFETIME.total_seconds()) * 1_000_000)
        self.assertEqual((generation, redeemed), (0, None))
        self.assertEqual(self.rows(AUDIT), [
            ("owner", "invite_principal", "principal", str(owner), "succeeded"),
            ("owner", "issue_principal_invitation", "principal", str(owner), "succeeded"),
        ])
        # Stored only as a digest: neither form of the code is in the database files.
        stored = self.database_bytes()
        for form in (display.encode(), display.replace("-", "").encode(), secret):
            self.assertNotIn(form, stored)
        # The code redeems once through the ordinary path, then is spent.
        credential = self.store.enroll_credential(secret, IDENTITY, secrets.token_bytes(32), b"synthetic-key", -7, 0)
        self.assertEqual(credential.principal_id, owner)
        self.assertEqual(self.rows("SELECT status FROM access_principals"), [("active",)])
        with self.assertRaises(AccessValidationError):
            self.store.enroll_credential(secret, IDENTITY, secrets.token_bytes(32), b"synthetic-key", -7, 0)

    def test_bootstrap_refuses_without_a_controlling_terminal_before_any_change(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)

        def no_terminal(path, flags):
            raise OSError(errno.ENXIO, "no controlling terminal")

        for opener in (no_terminal, lambda path, flags: os.dup(read_end)):
            with self.subTest(opener=opener):
                code, stdout, stderr, _ = self.run_cli(
                    "bootstrap", terminal_factory=lambda: ControllingTerminal(opener=opener))
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("refused: controlling_terminal_required", stderr)
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(0,)])
        self.assertEqual(self.rows(AUDIT), [])

    def test_bootstrap_refuses_when_an_owner_exists(self):
        self.bootstrap()
        before = self.rows(AUDIT)
        console = Console(self)
        code, stdout, stderr, terminal = self.run_cli("bootstrap", "Second Owner", "BOOTSTRAP", console=console)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: owner_already_configured", stderr)
        self.assertIsNone(CODE.search(terminal))
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(1,)])
        self.assertEqual(self.rows("SELECT count(*) FROM access_invitations"), [(1,)])
        self.assertEqual(self.rows(AUDIT), before)

    def test_bootstrap_refuses_a_declined_confirmation_or_a_bad_name(self):
        for lines, reason in ((("Synthetic Owner", "bootstrap"), "owner_confirmation_declined"),
                              (("Synthetic Owner", ""), "owner_confirmation_declined"),
                              (("",), "display_name_rejected"),
                              (("x" * 65,), "display_name_rejected"),
                              # The store's one rule (PR #242 review): no
                              # format or separator character either (DEL is
                              # the pseudo-terminal's erase character, so it is
                              # covered by the predicate's own tests).
                              (("bidi\u202eevil",), "display_name_rejected"),
                              (("zero\u200bwidth",), "display_name_rejected"),
                              (("line\u2028sep",), "display_name_rejected")):
            with self.subTest(lines=lines):
                code, stdout, stderr, terminal = self.run_cli("bootstrap", *lines)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("refused: " + reason, stderr)
                self.assertIsNone(CODE.search(terminal))
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(0,)])
        self.assertEqual(self.rows(AUDIT), [])

    def test_refuses_root_and_a_database_it_cannot_trust(self):
        with patch.object(bootstrap_cli.os, "geteuid", return_value=0):
            code, _, stderr, _ = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
        self.assertEqual(code, 2)
        self.assertIn("refused: run_as_service_account", stderr)
        missing = self.root / "missing.sqlite3"
        code, _, stderr, _ = self.run_cli("bootstrap", path=missing)
        self.assertIn("refused: database_not_found", stderr)
        self.assertFalse(missing.exists())
        link = self.root / "link.sqlite3"
        link.symlink_to(self.path)
        code, _, stderr, _ = self.run_cli("bootstrap", path=link)
        self.assertIn("refused: database_path_rejected", stderr)
        code, _, stderr, _ = self.run_cli("bootstrap", path=Path("state.sqlite3"))
        self.assertIn("refused: database_path_rejected", stderr)
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(0,)])

    def test_nothing_secret_is_taken_from_arguments(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            bootstrap_cli.main(["bootstrap", "--config", str(self.config), "--code", "0000"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            bootstrap_cli.main(["bootstrap", "--database", str(self.path)])
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(0,)])

    def test_recover_revokes_owner_credentials_ends_sessions_and_voids_invitations(self):
        owner, display, _ = self.bootstrap()
        old_secret = parse_invitation_code(display)
        credential = self.store.enroll_credential(old_secret, IDENTITY, secrets.token_bytes(32), b"synthetic-key", -7, 0)
        token = secrets.token_bytes(32)
        self.store.establish_session(owner, credential.credential_id, token, proxy_identity=IDENTITY)
        invitee = self.store.invite("Synthetic invitee", (Permission.LIVE_VIEW,))
        pending = secrets.token_bytes(20)
        self.store.issue_enrollment(invitee.id, pending, NOW + timedelta(hours=1))
        before = len(self.rows(AUDIT))
        code, stdout, stderr, terminal = self.run_cli("recover", "Recovered Owner", "RECOVER")
        self.assertEqual((code, stderr), (0, ""))
        (new_display,) = CODE.findall(terminal)
        self.assertNotIn(new_display, stdout)
        self.assertIn(f"owner recovered: principal_id={owner}", stdout)
        self.assertEqual(self.rows("SELECT authorization_generation FROM access_deployment_state"), [(1,)])
        self.assertEqual(self.rows("SELECT count(*) FROM access_sessions WHERE invalidated_at_us IS NULL"), [(0,)])
        self.assertEqual(self.rows("SELECT count(*) FROM access_credentials WHERE revoked_at_us IS NULL"), [(0,)])
        self.assertEqual(self.rows("SELECT status, display_name, external_identity, authorization_revision "
                                   "FROM access_principals WHERE role='owner'"),
                         [("invited", "Recovered Owner", None, 1)])
        self.assertEqual(self.rows(AUDIT)[before:], [
            ("owner", "invalidate_human_sessions", "security_settings",
             "0b6f3f64-54a9-4e0f-8f5e-7d2c9a4b1e37", "succeeded"),
            ("owner", "revoke_principal_credential", "principal", str(owner), "succeeded"),
            ("owner", "issue_principal_invitation", "principal", str(owner), "succeeded"),
        ])
        # The old session, the invitee's pending code and the old Owner code are void.
        with self.assertRaises(AccessValidationError):
            self.store.authorize(token, IDENTITY, Permission.LIVE_VIEW)
        for secret in (pending, old_secret):
            with self.assertRaises(AccessValidationError):
                self.store.enroll_credential(secret, IDENTITY, secrets.token_bytes(32), b"synthetic-key", -7, 0)
        # The new code registers the Owner's replacement credential once.
        replacement = self.store.enroll_credential(parse_invitation_code(new_display), IDENTITY,
                                                   secrets.token_bytes(32), b"synthetic-key", -7, 0)
        self.assertEqual(replacement.principal_id, owner)
        self.assertEqual(self.rows("SELECT status FROM access_principals WHERE role='owner'"), [("active",)])

    def test_recover_keeps_the_name_when_left_empty_and_refuses_without_an_owner(self):
        code, stdout, stderr, _ = self.run_cli("recover", "", "RECOVER")
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: owner_not_configured", stderr)
        self.assertEqual(self.rows(AUDIT), [])
        owner, _, _ = self.bootstrap()
        code, _, stderr, _ = self.run_cli("recover", "", "recover")
        self.assertIn("refused: owner_confirmation_declined", stderr)
        self.assertEqual(self.rows("SELECT authorization_generation FROM access_deployment_state"), [(0,)])
        code, _, stderr, terminal = self.run_cli("recover", "", "RECOVER")
        self.assertEqual(code, 0)
        self.assertEqual(self.rows("SELECT display_name FROM access_principals"), [("Synthetic Owner",)])
        # No credential was registered yet: nothing to revoke, nothing recorded for it.
        self.assertNotIn("revoke_principal_credential", [row[1] for row in self.rows(AUDIT)])
        # Two outstanding Owner invitations never coexist: the first was revoked.
        self.assertEqual(self.rows("SELECT count(*) FROM access_invitations WHERE revoked_at_us IS NULL"), [(1,)])
        # A new name follows the store's one rule (PR #242 review); a refused
        # one changes nothing.
        before = (self.rows(AUDIT), self.rows("SELECT * FROM access_invitations"))
        # (Inside the name: the terminal line is stripped, which removes a
        # trailing separator before the rule sees it.)
        for name in ("x" * 65, "bidi\u202eevil", "p\u2029s"):
            with self.subTest(name=name):
                code, stdout, stderr, _ = self.run_cli("recover", name)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("refused: display_name_rejected", stderr)
        self.assertEqual((self.rows(AUDIT), self.rows("SELECT * FROM access_invitations")), before)
        self.assertEqual(self.rows("SELECT display_name FROM access_principals"), [("Synthetic Owner",)])

    def test_the_lifetime_comes_from_the_deployment_configuration(self):
        # Owner decision 2026-10-11: configurable per deployment (here 2 hours).
        self.lifetime = timedelta(hours=2)
        code, stdout, stderr, terminal = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(self.loaded, [self.config])
        self.assertIn("valid for 2 hours", terminal)
        self.assertIn("code_expires_at=" + (NOW + timedelta(hours=2)).isoformat(timespec="seconds"), stdout)
        ((issued, expires),) = self.rows("SELECT issued_at_us, expires_at_us FROM access_invitations")
        self.assertEqual(expires - issued, 2 * 3600 * 1_000_000)
        code, stdout, stderr, _ = self.run_cli("recover", "", "RECOVER")
        self.assertEqual(code, 0)
        self.assertIn("code_expires_at=" + (NOW + timedelta(hours=2)).isoformat(timespec="seconds"), stdout)

    def test_refuses_an_unusable_deployment_configuration_or_another_account(self):
        def broken(config):
            raise ValueError("synthetic configuration failure")

        console = Console(self)
        console.type("Synthetic Owner", "BOOTSTRAP")
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr), \
                patch.object(bootstrap_cli, "_load_deployment", broken):
            code = bootstrap_cli.main(["bootstrap", "--config", str(self.config)],
                                      terminal_factory=console.factory, clock=self.clock)
        self.assertEqual(code, 2)
        self.assertIn("refused: deployment_configuration_rejected", stderr.getvalue())
        self.assertEqual(console.opened, 0)
        for lifetime in (timedelta(days=8), timedelta(0)):
            with self.subTest(lifetime=lifetime):
                self.lifetime = lifetime
                code, _, stderr, terminal = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
                self.assertEqual(code, 2)
                self.assertIn("refused: deployment_configuration_rejected", stderr)
        self.lifetime = INVITATION_LIFETIME
        self.service_uid = os.geteuid() + 1
        code, _, stderr, _ = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
        self.assertEqual(code, 2)
        self.assertIn("refused: run_as_service_account", stderr)
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(0,)])
        self.assertEqual(self.rows(AUDIT), [])

    def test_refuses_to_issue_without_the_boot_clock(self):
        with patch("app.auth.store.read_boot_instant", return_value=None), \
                patch.object(AccessStore.__init__, "__kwdefaults__",
                             dict(AccessStore.__init__.__kwdefaults__, boot_clock=lambda: None)):
            code, stdout, stderr, terminal = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: invitation_clock_unavailable", stderr)
        self.assertIsNone(CODE.search(terminal))
        self.assertEqual(self.rows("SELECT count(*) FROM access_principals"), [(0,)])
        self.assertEqual(self.rows(AUDIT), [])

    def test_a_code_lost_after_the_commit_is_reported_and_recover_replaces_it(self):
        console = Console(self)
        terminal = console.factory()
        writes = []
        original = terminal.write

        def write(text):
            writes.append(text)
            if "Owner enrollment code" in text:
                raise bootstrap_cli.CliRefused("controlling_terminal_unavailable")
            original(text)

        terminal.write = write
        code, stdout, stderr, output = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP",
                                                    console=console, terminal_factory=lambda: terminal)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: committed_code_not_shown", stderr)
        self.assertIsNone(CODE.search(output + stderr))
        # Committed: the Owner exists with one (lost) authorization.
        self.assertEqual(self.rows("SELECT role, status FROM access_principals"), [("owner", "invited")])
        self.assertEqual(self.rows("SELECT count(*) FROM access_invitations WHERE revoked_at_us IS NULL"), [(1,)])
        # ``recover`` (not ``bootstrap``) issues a replacement and voids the lost one.
        code, _, stderr, _ = self.run_cli("bootstrap", "Synthetic Owner", "BOOTSTRAP")
        self.assertIn("refused: owner_already_configured", stderr)
        code, _, _, output = self.run_cli("recover", "", "RECOVER")
        self.assertEqual(code, 0)
        self.assertEqual(len(CODE.findall(output)), 1)
        self.assertEqual(self.rows("SELECT count(*) FROM access_invitations WHERE revoked_at_us IS NULL"), [(1,)])

    def test_recovery_registration_does_not_exclude_the_revoked_owner_passkey(self):
        # PR #234 review (重要): the revoked passkey may still be in a synced
        # keychain under the same user handle; excluding it would make that
        # authenticator refuse the replacement registration.
        rp = RelyingParty(RP_ID, ORIGIN)
        ceremonies = PasskeyCeremonies(self.store, rp, session_gate=OpenGate(), clock=self.clock)
        owner, display, _ = self.bootstrap()
        first = SyntheticAuthenticator()
        options = ceremonies.begin_registration(parse_invitation_code(display), IDENTITY)
        self.assertEqual(options["excludeCredentials"], [])
        enrolled = ceremonies.finish_registration(parse_invitation_code(display), IDENTITY,
                                                  first.register(options))
        code, _, _, terminal = self.run_cli("recover", "", "RECOVER")
        self.assertEqual(code, 0)
        (new_display,) = CODE.findall(terminal)
        options = ceremonies.begin_registration(parse_invitation_code(new_display), IDENTITY)
        # The same user handle: the authenticator replaces its old passkey.
        self.assertEqual(options["user"]["id"], b64(owner.bytes))
        self.assertEqual(options["excludeCredentials"], [])
        self.assertEqual(self.rows("SELECT count(*) FROM access_credentials WHERE revoked_at_us IS NOT NULL"),
                         [(1,)])
        replacement = ceremonies.finish_registration(parse_invitation_code(new_display), IDENTITY,
                                                     SyntheticAuthenticator().register(options))
        self.assertEqual(replacement.principal_id, owner)
        self.assertNotEqual(replacement.credential_id, enrolled.credential_id)


if __name__ == "__main__":
    unittest.main()
