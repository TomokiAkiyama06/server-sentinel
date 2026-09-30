"""Shared-Tailnet-account identity tests (ADR-0004 §1, SPECIFICATION §11.4/§11.8).

The research room shares one Tailscale login, so the trusted-proxy identity
cannot tell invited people apart. These synthetic tests show that the
invitation and each person's own passkey are the only per-person key, that the
proxy identity is kept only as a non-unique last-observed value plus a keyed
session binding, and that migration 18 rebuilds the access tables without
losing a row. Every authenticator is a software key generated in the test
process; nothing here is evidence of real browser, proxy or Tailscale
behavior (see MANUAL_TEST.md).
"""

from contextlib import closing
from datetime import timedelta
import hashlib
import io
import logging
import os
from pathlib import Path
import pickle
import sqlite3
import stat
import tempfile
import unittest
from uuid import UUID, uuid4

from app.auth.model import AccessValidationError, Permission, PrincipalStatus
from app.auth.passkeys import PasskeyCeremonies
from app.auth.session_binding import KEY_BYTES, SessionBindingKey, SessionBindingKeyError
from app.auth.store import AccessStore, _us
from app.auth.webauthn import RelyingParty
from app.audit.store import AuditStore
from app.diagnostics.export import DiagnosticField
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import MigrationError, migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_webauthn_ceremonies import GENERIC, OWNER_CONTEXT, START, CeremonyTestCase
from tests.webauthn_fakes import ORIGIN, RP_ID, SyntheticAuthenticator


SHARED = "synthetic-lab-shared@example.invalid"
ELSEWHERE = "synthetic-elsewhere@example.invalid"
ALICE_CODE = b"a" * 32
BOB_CODE = b"b" * 32


class SharedLoginTests(CeremonyTestCase):
    """Two invited people behind one shared Tailscale login."""

    def setUp(self):
        super().setUp()
        self.alice = self.invite(ALICE_CODE, permissions=(Permission.LIVE_VIEW,))
        self.bob = self.invite(BOB_CODE, permissions=(Permission.RECORDINGS_VIEW,))
        self.alice_key, self.alice_credential = self.register(identity=SHARED, code=ALICE_CODE)
        self.bob_key, self.bob_credential = self.register(identity=SHARED, code=BOB_CODE)

    def principal_row(self, principal_id):
        with closing(self.database.connect()) as connection:
            return connection.execute("SELECT * FROM access_principals WHERE id=?", (str(principal_id),)).fetchone()

    def test_each_person_registers_and_signs_in_with_their_own_passkey(self):
        self.assertEqual(self.alice_credential.principal_id, self.alice.id)
        self.assertEqual(self.bob_credential.principal_id, self.bob.id)
        alice = self.sign_in(self.alice_key, SHARED)
        bob = self.sign_in(self.bob_key, SHARED)
        self.assertEqual(alice.principal_id, self.alice.id)
        self.assertEqual(bob.principal_id, self.bob.id)
        # Same login, independent people and independent permissions.
        self.assertEqual(self.store.authorize(alice.token, SHARED, Permission.LIVE_VIEW).id, self.alice.id)
        self.assertEqual(self.store.authorize(bob.token, SHARED, Permission.RECORDINGS_VIEW).id, self.bob.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(alice.token, SHARED, Permission.RECORDINGS_VIEW)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(bob.token, SHARED, Permission.LIVE_VIEW)
        # The shared login is recorded on both principals: it is not unique.
        self.assertEqual(self.principal_row(self.alice.id)["external_identity"], SHARED)
        self.assertEqual(self.principal_row(self.bob.id)["external_identity"], SHARED)

    def test_one_persons_passkey_never_signs_in_as_the_other(self):
        request = self.ceremonies.begin_authentication()
        forged = self.alice_key.assertion(request, user_handle=self.bob.id.bytes)
        self.assertGenericDenial(lambda: self.ceremonies.finish_authentication(SHARED, forged))
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 0)

    def test_revoking_one_person_leaves_the_other_working(self):
        alice = self.sign_in(self.alice_key, SHARED)
        bob = self.sign_in(self.bob_key, SHARED)
        self.admin.revoke_principal(OWNER_CONTEXT, self.alice.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(alice.token, SHARED, Permission.LIVE_VIEW)
        self.assertGenericDenial(lambda: self.sign_in(self.alice_key, SHARED))
        self.assertEqual(self.store.authorize(bob.token, SHARED, Permission.RECORDINGS_VIEW).id, self.bob.id)
        self.assertEqual(self.sign_in(self.bob_key, SHARED).principal_id, self.bob.id)
        # Revocation clears the revoked principal's last observed identity only.
        self.assertIsNone(self.principal_row(self.alice.id)["external_identity"])
        self.assertEqual(self.principal_row(self.bob.id)["external_identity"], SHARED)

    def test_revoking_one_credential_leaves_the_other_person_working(self):
        alice = self.sign_in(self.alice_key, SHARED)
        bob = self.sign_in(self.bob_key, SHARED)
        self.admin.revoke_credential(OWNER_CONTEXT, self.alice.id, self.alice_credential.credential_id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(alice.token, SHARED, Permission.LIVE_VIEW)
        self.assertEqual(self.store.authorize(bob.token, SHARED, Permission.RECORDINGS_VIEW).id, self.bob.id)

    def test_two_invited_people_can_share_one_owner_visible_login_value(self):
        # The inherited UNIQUE constraint is gone: two principals may hold the
        # same last observed value.
        with closing(self.database.connect()) as connection:
            values = [row[0] for row in connection.execute(
                "SELECT external_identity FROM access_principals WHERE id IN (?, ?)",
                (str(self.alice.id), str(self.bob.id)))]
        self.assertEqual(values, [None, None])
        self.sign_in(self.alice_key, SHARED)
        self.sign_in(self.bob_key, SHARED)
        self.assertEqual(self.count("SELECT count(*) FROM access_principals WHERE external_identity=?", SHARED), 2)

    def test_last_observed_identity_is_overwritten_each_authentication(self):
        self.sign_in(self.alice_key, SHARED)
        self.sign_in(self.alice_key, ELSEWHERE)
        self.assertEqual(self.principal_row(self.alice.id)["external_identity"], ELSEWHERE)
        self.assertEqual(self.store.credentials_for(self.alice.id)[0].principal_id, self.alice.id)


class ProxyIdentityCannotAuthorizeTests(CeremonyTestCase):
    def setUp(self):
        super().setUp()
        self.principal = self.invite(permissions=(Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        self.key, self.credential = self.register(identity=SHARED)
        self.grant = self.sign_in(self.key, SHARED)

    def test_header_without_a_session_authorizes_nothing(self):
        for token in (None, b"", b"x" * 32, "cookie-text"):
            for permission in Permission:
                with self.subTest(token=token, permission=permission), \
                        self.assertRaises(AccessValidationError) as caught:
                    self.store.authorize(token, SHARED, permission)
                self.assertEqual(str(caught.exception), GENERIC)
        # Nor does it open a ceremony that needs a session.
        self.assertGenericDenial(lambda: self.ceremonies.begin_step_up(b"x" * 32, SHARED))

    def test_valid_session_with_absent_or_malformed_identity_is_refused(self):
        for identity in (None, "", " ", "has space", "x" * 257, "café", b"bytes"):
            with self.subTest(identity=identity), self.assertRaises(AccessValidationError) as caught:
                self.store.authorize(self.grant.token, identity, Permission.LIVE_VIEW)
            self.assertEqual(str(caught.exception), GENERIC)

    def test_spoofed_identity_is_refused_and_the_session_stays_for_its_holder(self):
        with self.assertRaises(AccessValidationError) as caught:
            self.store.authorize(self.grant.token, ELSEWHERE, Permission.LIVE_VIEW)
        self.assertEqual(str(caught.exception), GENERIC)
        # Mismatch refuses that request only; it is not a revocation signal.
        self.assertEqual(self.store.authorize(self.grant.token, SHARED, Permission.LIVE_VIEW).id, self.principal.id)
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions WHERE invalidated_at_us IS NOT NULL"), 0)

    def test_session_keeps_only_a_keyed_binding_never_the_raw_identity(self):
        with closing(self.database.connect()) as connection:
            row = connection.execute("SELECT * FROM access_sessions WHERE id=?", (str(self.grant.session_id),)).fetchone()
        binding = bytes(row["external_identity_binding"])
        self.assertEqual(len(binding), 32)
        for value in row:
            self.assertNotIn(SHARED, str(value))
            if isinstance(value, bytes):
                self.assertNotIn(SHARED.encode(), value)

    def test_a_different_deployment_key_cannot_reproduce_the_binding(self):
        other = AccessStore(self.database, clock=self.clock, audit=self.audit,
                            session_binding=SessionBindingKey.generate())
        with self.assertRaises(AccessValidationError):
            other.authorize(self.grant.token, SHARED, Permission.LIVE_VIEW)
        unkeyed = AccessStore(self.database, clock=self.clock, audit=self.audit)
        with self.assertRaises(AccessValidationError):
            unkeyed.authorize(self.grant.token, SHARED, Permission.LIVE_VIEW)
        with self.assertRaises(AccessValidationError):
            unkeyed.establish_session(self.principal.id, self.credential.credential_id, b"k" * 32,
                                      proxy_identity=SHARED)
        with self.assertRaises(ValueError):
            PasskeyCeremonies(unkeyed, self.rp)

    def test_invalidation_and_expiry_clear_the_binding(self):
        def bindings():
            with closing(self.database.connect()) as connection:
                return {row[0]: row[1] is not None for row in connection.execute(
                    "SELECT id, external_identity_binding FROM access_sessions")}

        second = self.sign_in(self.key, SHARED)
        self.admin.set_permissions(OWNER_CONTEXT, self.principal.id, (Permission.LIVE_VIEW,))
        self.assertEqual(set(bindings().values()), {False})
        third = self.sign_in(self.key, SHARED)
        self.admin.revoke_credential(OWNER_CONTEXT, self.principal.id, self.credential.credential_id)
        self.assertFalse(bindings()[str(third.session_id)])
        self.assertNotIn(True, (bindings()[str(item.session_id)] for item in (self.grant, second, third)))
        # Expiry: a session past its idle lifetime loses its binding at the
        # next session establishment.
        self.invite(b"z" * 32)
        other_key, _ = self.register(identity=SHARED, code=b"z" * 32)
        expiring = self.sign_in(other_key, SHARED)
        self.clock.advance(minutes=31)
        self.sign_in(other_key, SHARED)
        self.assertFalse(bindings()[str(expiring.session_id)])


class SessionBindingKeyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name) / "state"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "session-binding.key"

    def assertUnavailable(self, call):
        with self.assertRaises(SessionBindingKeyError) as caught:
            call()
        self.assertEqual(str(caught.exception), "session binding key is unavailable")
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(str(self.directory), repr(caught.exception))

    def test_created_once_with_owner_only_mode_and_reloaded_unchanged(self):
        key = SessionBindingKey.load_or_create(self.path)
        info = self.path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_size, KEY_BYTES)
        self.assertEqual(info.st_uid, os.geteuid())
        again = SessionBindingKey.load_or_create(self.path)
        self.assertEqual(key.bind(SHARED), again.bind(SHARED))
        self.assertEqual([item.name for item in self.directory.iterdir()], ["session-binding.key"])

    def test_unsafe_key_files_fail_closed_without_being_replaced(self):
        SessionBindingKey.load_or_create(self.path)
        original = self.path.read_bytes()
        self.path.chmod(0o640)
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(self.path))
        self.path.chmod(0o600)
        link = self.directory / "second-link"
        os.link(self.path, link)
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(self.path))
        link.unlink()
        self.path.write_bytes(original + b"x")
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(self.path))
        self.path.write_bytes(original)
        self.assertEqual(self.path.read_bytes(), original)
        SessionBindingKey.load_or_create(self.path)

    def test_symlinks_and_shared_directories_are_refused(self):
        target = self.directory / "target.key"
        self.path.symlink_to(target)
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(self.path))
        self.assertFalse(target.exists())
        self.path.unlink()
        self.directory.chmod(0o770)
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(self.path))
        self.directory.chmod(0o700)
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(Path("relative.key")))
        self.assertUnavailable(lambda: SessionBindingKey.load_or_create(self.directory / "missing" / "k"))

    def test_key_never_appears_in_repr_pickle_logs_errors_database_or_diagnostics(self):
        key = SessionBindingKey.load_or_create(self.path)
        raw = self.path.read_bytes()
        self.assertEqual(repr(key), "SessionBindingKey(<redacted>)")
        self.assertEqual(str(key), repr(key))
        with self.assertRaises(TypeError):
            pickle.dumps(key)
        with self.assertRaises(SessionBindingKeyError) as caught:
            SessionBindingKey(raw + b"x")
        self.assertNotIn(raw.hex(), str(caught.exception))
        # The only allowlisted diagnostic fields have no slot for it.
        for name in ("session_binding.key", "credential.session_binding_key", "credential.hmac_key"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                DiagnosticField(name, raw.hex())

        # A full ceremony with every logger at DEBUG writes neither the key
        # nor the binding nor the raw identity anywhere, and keeps the key out
        # of the database file.
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, previous)
        database = Database(self.directory / "state.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        def clock():
            return START

        audit = AuditStore(database, clock=clock)
        store = AccessStore(database, clock=clock, audit=audit, unaudited_writes=True, session_binding=key)
        ceremonies = PasskeyCeremonies(store, RelyingParty(RP_ID, ORIGIN), clock=clock)
        principal = store.invite("Synthetic person", (Permission.LIVE_VIEW,))
        store.issue_enrollment(principal.id, ALICE_CODE, START + timedelta(minutes=5))
        authenticator = SyntheticAuthenticator()
        creation = ceremonies.begin_registration(ALICE_CODE, SHARED)
        ceremonies.finish_registration(ALICE_CODE, SHARED, authenticator.register(creation))
        grant = ceremonies.finish_authentication(SHARED, authenticator.assertion(ceremonies.begin_authentication()))
        with self.assertRaises(AccessValidationError) as denied:
            store.authorize(grant.token, ELSEWHERE, Permission.LIVE_VIEW)
        binding = key.bind(SHARED)
        logged = stream.getvalue()
        for secret in (raw.hex(), binding.hex(), SHARED, ELSEWHERE):
            self.assertNotIn(secret, logged)
            self.assertNotIn(secret, str(denied.exception))
        contents = (self.directory / "state.sqlite3").read_bytes()
        self.assertNotIn(raw, contents)
        self.assertNotEqual(binding, raw)

    def test_settings_place_the_key_outside_the_database(self):
        settings = Settings(data_directory=self.directory, source_root=Path(__file__).resolve().parents[2])
        self.assertEqual(settings.session_binding_key_path.parent, settings.database_path.parent)
        self.assertNotEqual(settings.session_binding_key_path, settings.database_path)
        self.assertNotIn(str(self.directory), repr(settings))


class SharedIdentityMigrationTests(unittest.TestCase):
    """Migration 18 rebuilds the access tables without cascading deletes."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.database = Database(Path(temp.name) / "state.sqlite3")
        self.before = APPLICATION_MIGRATIONS[:17]
        self.assertEqual(self.before[-1].name, "human_access_webauthn")
        with closing(self.database.connect()) as connection:
            migrate(connection, self.before)
            self.populate(connection)
            self.snapshot = self.read(connection)

    def populate(self, connection):
        t = _us(START)
        owner, active, invited, revoked = (str(uuid4()) for _ in range(4))
        rows = [
            (owner, "synthetic-owner@example.invalid", "Synthetic owner", "owner", "active", 0, t, None),
            (active, "synthetic-viewer@example.invalid", "Synthetic viewer", "invited_user", "active", 2, t, None),
            (invited, "synthetic-invited@example.invalid", "Synthetic invited", "invited_user", "invited", 0, t, None),
            (revoked, "synthetic-revoked@example.invalid", "Synthetic revoked", "invited_user", "revoked", 1, t, t + 5),
        ]
        connection.executemany("INSERT INTO access_principals VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        connection.executemany("INSERT INTO access_principal_permissions VALUES (?, ?)",
                               [(active, "live:view"), (active, "recordings:view"), (invited, "live:view"),
                                (revoked, "recordings:view")])
        credentials = [(b"cred-owner", owner, 0, None, None, "Owner key"), (b"cred-active", active, 7, None, None, None),
                       (b"cred-inconsistent", active, 0, "backup_eligibility_changed", t + 3, None),
                       (b"cred-revoked", revoked, 1, None, None, None)]
        for credential_id, principal, count, reason, inconsistent, label in credentials:
            connection.execute(
                "INSERT INTO access_credentials (credential_id, principal_id, public_key, algorithm, sign_count, enrolled_at_us, revoked_at_us, backup_eligible, backup_state, inconsistency_reason, inconsistent_at_us, label, last_used_at_us) VALUES (?, ?, ?, -7, ?, ?, ?, 1, 0, ?, ?, ?, ?)",
                (credential_id, principal, b"public-" + credential_id, count, t,
                 t + 5 if principal == revoked else None, reason, inconsistent, label, t + 1))
        invitations = [(str(uuid4()), bytes([n]) * 32, principal, redeemed, n)
                       for n, (principal, redeemed) in enumerate(((owner, t), (active, t), (invited, None), (revoked, None)), start=1)]
        connection.executemany(
            "INSERT INTO access_invitations (id, secret_digest, principal_id, principal_revision, deployment_generation, issued_at_us, expires_at_us, redeemed_at_us, revoked_at_us, attempt_count) VALUES (?, ?, ?, 0, 0, ?, ?, ?, NULL, ?)",
            [(i, d, p, t, t + 10_000_000, r, n) for i, d, p, r, n in invitations])
        sessions = [(str(uuid4()), bytes([100 + n]) * 32, principal, credential, invalidated, verified)
                    for n, (principal, credential, invalidated, verified) in enumerate((
                        (owner, b"cred-owner", None, t), (active, b"cred-active", None, None),
                        (active, b"cred-inconsistent", t + 3, t), (revoked, b"cred-revoked", t + 5, None)))]
        sessions = [(i, hashlib.sha256(d).digest(), p, c, inv, v) for i, d, p, c, inv, v in sessions]
        connection.executemany(
            "INSERT INTO access_sessions (id, token_digest, principal_id, credential_id, principal_revision, deployment_generation, established_at_us, last_seen_at_us, idle_lifetime_us, idle_expires_at_us, absolute_expires_at_us, invalidated_at_us, last_user_verification_at_us) VALUES (?, ?, ?, ?, 0, 0, ?, ?, 1800000000, ?, ?, ?, ?)",
            [(i, d, p, c, t, t, t + 1_800_000_000, t + 43_200_000_000, inv, v) for i, d, p, c, inv, v in sessions])
        connection.executemany(
            "INSERT INTO access_webauthn_challenges VALUES (?, ?, ?, ?, ?, ?)",
            [(b"r" * 32, "registration", invitations[2][0], None, t, t + 1),
             (b"s" * 32, "step_up", None, sessions[0][0], t, t + 1),
             (b"a" * 32, "authentication", None, None, t, t + 1)])
        # Rowid gaps prove rowids are carried over rather than renumbered.
        connection.execute("DELETE FROM access_principal_permissions WHERE principal_id=? AND permission='live:view'", (invited,))
        connection.execute("INSERT INTO access_principal_permissions VALUES (?, 'live:view')", (invited,))
        self.ids = dict(owner=owner, active=active, invited=invited, revoked=revoked)

    TABLES = ("access_principals", "access_principal_permissions", "access_credentials",
              "access_invitations", "access_sessions", "access_webauthn_challenges")

    def read(self, connection):
        result = {}
        for table in self.TABLES:
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")
                       if row[1] != "external_identity_binding"]
            result[table] = sorted(tuple(row) for row in connection.execute(
                f"SELECT rowid, {', '.join(columns)} FROM {table}"))
        return result

    def test_migration_preserves_every_child_row_and_rowid(self):
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            after = self.read(connection)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            temp = connection.execute("SELECT name FROM temp.sqlite_master WHERE name LIKE 'mig_%'").fetchall()
            self.assertEqual(temp, [])
        for table in self.TABLES:
            if table == "access_principals":
                continue
            with self.subTest(table=table):
                self.assertEqual(after[table], self.snapshot[table])
        # Principals keep every row and value except the lifecycle rule:
        # only an active principal keeps its last observed identity.
        before = {row[1]: row for row in self.snapshot["access_principals"]}
        for row in after["access_principals"]:
            old = before[row[1]]
            expected = old if old[5] == "active" else old[:2] + (None,) + old[3:]
            self.assertEqual(row, expected)
        self.assertEqual(len(after["access_principals"]), 4)

    def test_migrated_schema_matches_a_fresh_database(self):
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            migrated = sorted(tuple(row) for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name LIKE 'access_%' OR tbl_name LIKE 'access_%'"))
        fresh = Database(self.database.path.parent / "fresh.sqlite3")
        with closing(fresh.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            expected = sorted(tuple(row) for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name LIKE 'access_%' OR tbl_name LIKE 'access_%'"))
        self.assertEqual(migrated, expected)

    def test_rebuilt_constraints_still_hold(self):
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            t = _us(START)
            # Not unique any more, and nullable.
            connection.execute("UPDATE access_principals SET external_identity=? WHERE status='active'", (SHARED,))
            self.assertEqual(connection.execute("SELECT count(*) FROM access_principals WHERE external_identity=?", (SHARED,)).fetchone()[0], 2)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO access_principal_permissions VALUES (?, 'live:view')", (str(uuid4()),))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO access_principals VALUES (?, NULL, 'Second owner', 'owner', 'active', 0, ?, NULL)", (str(uuid4()), t))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE access_sessions SET external_identity_binding=? WHERE invalidated_at_us IS NOT NULL", (b"x" * 32,))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE access_sessions SET external_identity_binding=? WHERE invalidated_at_us IS NULL", (b"short",))

    def test_pre_migration_sessions_have_no_binding_and_are_refused(self):
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
            self.assertEqual(connection.execute("SELECT count(*) FROM access_sessions WHERE external_identity_binding IS NOT NULL").fetchone()[0], 0)
        store = AccessStore(self.database, clock=lambda: START, session_binding=SessionBindingKey.generate())
        # The Owner session is otherwise current; only the missing binding refuses it.
        for identity in ("synthetic-owner@example.invalid", SHARED):
            with self.subTest(identity=identity), self.assertRaises(AccessValidationError):
                store.authorize(bytes([100]) * 32, identity, Permission.LIVE_VIEW)
        store.establish_session(UUID(self.ids["owner"]), b"cred-owner", b"z" * 32, proxy_identity=SHARED)
        self.assertEqual(str(store.authorize(b"z" * 32, SHARED, Permission.LIVE_VIEW).id), self.ids["owner"])
        principal = store.assertion_subject(b"cred-active")[0]
        self.assertEqual(principal.status, PrincipalStatus.ACTIVE)
        self.assertEqual(principal.external_identity, "synthetic-viewer@example.invalid")

    def test_a_failed_verification_rolls_the_whole_migration_back(self):
        # A pre-existing dangling reference (possible only with enforcement
        # off) must abort the rebuild rather than be silently kept or dropped.
        with closing(self.database.connect()) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("INSERT INTO access_principal_permissions VALUES (?, 'live:view')", (str(uuid4()),))
            snapshot = self.read(connection)
            connection.execute("PRAGMA foreign_keys=ON")
            with self.assertRaises(MigrationError):
                migrate(connection, APPLICATION_MIGRATIONS)
            self.assertEqual(self.read(connection), snapshot)
            self.assertEqual(connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0], 17)
            self.assertEqual(connection.execute("SELECT count(*) FROM temp.sqlite_master").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
