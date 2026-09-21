from contextlib import closing
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from app.cameras.remote_agent.pairing import (
    HmacCodeVerifier, PairingAuthorizationError, PairingError, PairingLedger,
)
from app.storage.database import Database
from app.storage.migrations import migrate
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
        self.ledger = PairingLedger(self.database, self.verifier, clock=lambda: self.now,
                                    process_epoch=uuid4())
        self.owner = Owner()

    def _approval(self):
        return self.ledger.approve(self.owner, "owner", node_id=uuid4(),
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

    def test_restart_invalidates_pending_monotonic_approval(self):
        approval, code = self._approval()
        restarted = PairingLedger(self.database, self.verifier, clock=lambda: self.now,
                                  process_epoch=uuid4())
        with self.assertRaises(PairingError):
            restarted.redeem(enrollment_id=approval.enrollment_id,
                             public_key_digest=DIGEST_A, code=code.value)

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


if __name__ == "__main__":
    unittest.main()
