from contextlib import closing
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from app.cameras.remote_agent.pairing import (
    HmacCodeVerifier, PairingAuthorizationError, PairingError, PairingLedger,
)
from app.audit.store import AuditStore
from app.storage.database import Database
from app.storage.migrations import MigrationError, migrate
from app.storage.schema import APPLICATION_MIGRATIONS


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
SERIAL_A = "c" * 64


class Owner:
    def __init__(self, allowed=True):
        self.allowed = allowed

    def require_owner(self, actor_context):
        if not self.allowed or actor_context != "owner":
            raise PermissionError("synthetic denial")


class PairingLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.now = 100.0
        self.verifier = HmacCodeVerifier(b"s" * 32)
        self.ledger = PairingLedger(self.database, self.verifier, audit=AuditStore(self.database),
                                    clock=lambda: self.now,
                                    process_epoch=uuid4())
        self.owner = Owner()
        # One node per test: a public key is never bound to two nodes.
        self.node = uuid4()

    def _approval(self):
        return self.ledger.approve(self.owner, "owner", node_id=self.node,
                                   public_key_digest=DIGEST_A)

    def test_code_is_ephemeral_and_only_its_keyed_digest_is_persisted(self):
        approval, code = self._approval()
        self.assertEqual(26, len(code.value))
        self.assertNotIn(code.value, repr(code))
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                "SELECT code_digest, public_key_digest FROM pairing_enrollments WHERE id = ?",
                (str(approval.enrollment_id),),
            ).fetchone()
        self.assertNotEqual(code.value, row["code_digest"])
        self.assertEqual(DIGEST_A, row["public_key_digest"])

    def test_redeem_is_bound_to_key_single_use_and_expiry(self):
        approval, code = self._approval()
        with self.assertRaises(PairingError):
            self.ledger.redeem(enrollment_id=approval.enrollment_id,
                               public_key_digest=DIGEST_B, code=code.value)
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=DIGEST_A, code=code.value)
        self.assertEqual(approval.node_id, claim.node_id)
        with self.assertRaises(PairingError):
            self.ledger.redeem(enrollment_id=approval.enrollment_id,
                               public_key_digest=DIGEST_A, code=code.value)
        expired, expired_code = self._approval()
        self.now += 300
        with self.assertRaises(PairingError):
            self.ledger.redeem(enrollment_id=expired.enrollment_id,
                               public_key_digest=DIGEST_A, code=expired_code.value)
        with closing(self.database.connect()) as connection:
            self.assertEqual("expired", connection.execute(
                "SELECT state FROM pairing_enrollments WHERE id = ?",
                (str(expired.enrollment_id),),
            ).fetchone()[0])

    def test_restart_invalidates_pending_monotonic_approval(self):
        approval, code = self._approval()
        restarted = PairingLedger(self.database, self.verifier, audit=AuditStore(self.database),
                                  clock=lambda: self.now,
                                  process_epoch=uuid4())
        with self.assertRaises(PairingError):
            restarted.redeem(enrollment_id=approval.enrollment_id,
                             public_key_digest=DIGEST_A, code=code.value)

    def test_revocation_invalidates_consumed_claim_before_activation(self):
        approval, code = self._approval()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=DIGEST_A, code=code.value)
        self.ledger.revoke(self.owner, "owner", node_id=claim.node_id)
        with self.assertRaises(PairingError):
            self.ledger.activate(claim, credential_serial_digest=SERIAL_A)

    def test_activation_and_revocation_are_current_authorization(self):
        approval, code = self._approval()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=DIGEST_A, code=code.value)
        self.ledger.activate(claim, credential_serial_digest=SERIAL_A)
        self.assertTrue(self.ledger.admits(node_id=claim.node_id, public_key_digest=DIGEST_A,
                                           credential_serial_digest=SERIAL_A))
        self.ledger.revoke(self.owner, "owner", node_id=claim.node_id)
        self.assertFalse(self.ledger.admits(node_id=claim.node_id, public_key_digest=DIGEST_A,
                                            credential_serial_digest=SERIAL_A))

    def test_owner_authorization_is_required_for_approval_and_revocation(self):
        with self.assertRaises(PairingAuthorizationError):
            self.ledger.approve(Owner(False), "owner", node_id=uuid4(),
                                public_key_digest=DIGEST_A)
        approval, code = self._approval()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=DIGEST_A, code=code.value)
        self.ledger.activate(claim, credential_serial_digest=SERIAL_A)
        with self.assertRaises(PairingAuthorizationError):
            self.ledger.revoke(Owner(False), "owner", node_id=claim.node_id)

    def test_unactivated_or_wrong_credential_never_admits(self):
        approval, code = self._approval()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=DIGEST_A, code=code.value)
        self.assertFalse(self.ledger.admits(node_id=claim.node_id, public_key_digest=DIGEST_A,
                                            credential_serial_digest=SERIAL_A))
        self.ledger.activate(claim, credential_serial_digest=SERIAL_A)
        self.assertFalse(self.ledger.admits(node_id=claim.node_id, public_key_digest=DIGEST_B,
                                            credential_serial_digest=SERIAL_A))


class PairingKeyBindingMigrationTests(unittest.TestCase):
    def test_existing_keys_are_backfilled_and_revoked_keys_stay_revoked(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = Database(Path(temporary.name) / "synthetic.sqlite3")
        renewal = APPLICATION_MIGRATIONS.index(next(
            m for m in APPLICATION_MIGRATIONS if m.name == "pairing_credential_renewal"))
        active, revoked, pending = uuid4(), uuid4(), uuid4()
        digest_c = "d" * 64
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS[:renewal])
            with connection:
                connection.executemany(
                    "INSERT INTO pairing_node_credentials VALUES (?, ?, ?, ?)",
                    [(str(active), DIGEST_A, SERIAL_A, "active"),
                     (str(revoked), DIGEST_B, SERIAL_A, "revoked")])
                connection.executemany(
                    "INSERT INTO pairing_enrollments VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [(str(uuid4()), str(active), DIGEST_A, "e" * 64, "x", 1.0, "activated"),
                     (str(uuid4()), str(pending), digest_c, "e" * 64, "x", 1.0, "revoked")])
            migrate(connection, APPLICATION_MIGRATIONS)
            rows = {tuple(row) for row in connection.execute(
                "SELECT public_key_digest, node_id, revoked FROM pairing_key_bindings")}
        self.assertEqual({(DIGEST_A, str(active), 0), (DIGEST_B, str(revoked), 1),
                          (digest_c, str(pending), 1)}, rows)
        ledger = PairingLedger(database, HmacCodeVerifier(b"s" * 32),
                               audit=AuditStore(database), clock=lambda: 100.0,
                               process_epoch=uuid4())
        for digest, node in ((DIGEST_A, uuid4()), (DIGEST_B, revoked), (digest_c, pending)):
            with self.subTest(digest=digest[:1]), self.assertRaises(PairingError):
                ledger.approve(Owner(), "owner", node_id=node, public_key_digest=digest)
        ledger.approve(Owner(), "owner", node_id=active, public_key_digest=DIGEST_A)

    def test_legacy_key_bound_to_two_nodes_fails_migration_closed(self):
        cases = {
            "two_credentials": (
                [(DIGEST_A, "active"), (DIGEST_A, "active")], []),
            "credential_and_enrollment": (
                [(DIGEST_A, "active")], [(DIGEST_A, "pending")]),
            "two_enrollments": (
                [], [(DIGEST_A, "revoked"), (DIGEST_A, "pending")]),
        }
        for name, (credentials, enrollments) in cases.items():
            with self.subTest(name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                database = Database(Path(temporary.name) / "synthetic.sqlite3")
                renewal = APPLICATION_MIGRATIONS.index(next(
                    m for m in APPLICATION_MIGRATIONS if m.name == "pairing_credential_renewal"))
                with closing(database.connect()) as connection:
                    migrate(connection, APPLICATION_MIGRATIONS[:renewal])
                    with connection:
                        connection.executemany(
                            "INSERT INTO pairing_node_credentials VALUES (?, ?, ?, ?)",
                            [(str(uuid4()), digest, SERIAL_A, state)
                             for digest, state in credentials])
                        connection.executemany(
                            "INSERT INTO pairing_enrollments VALUES (?, ?, ?, ?, ?, ?, ?)",
                            [(str(uuid4()), str(uuid4()), digest, "e" * 64, "x", 1.0, state)
                             for digest, state in enrollments])
                    with self.assertRaises(MigrationError):
                        migrate(connection, APPLICATION_MIGRATIONS)
                    applied = {row[0] for row in connection.execute(
                        "SELECT name FROM schema_migrations")}
                    tables = {row[0] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'")}
                self.assertNotIn("pairing_credential_renewal", applied)
                self.assertNotIn("pairing_key_bindings", tables)


if __name__ == "__main__":
    unittest.main()
