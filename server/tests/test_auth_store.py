from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from app.auth.model import AccessValidationError, Permission, PrincipalRole, PrincipalStatus
from app.auth.store import AccessStore
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)
IDENTITY = "viewer@example.invalid"
OWNER = "owner@example.invalid"
TOKEN = b"t" * 32
SECRET = b"e" * 32
CREDENTIAL = b"synthetic-credential-id"
PUBLIC_KEY = b"synthetic-public-key"


class AccessStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Database(Path(self.temp.name) / "access.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.store = AccessStore(self.database, clock=lambda: NOW)

    def enroll(self, permissions=(Permission.LIVE_VIEW,)):
        principal = self.store.invite(IDENTITY, "Synthetic viewer", permissions)
        self.store.issue_enrollment(principal.id, SECRET, NOW + timedelta(minutes=5))
        credential = self.store.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        return principal, credential

    def test_independent_permissions_do_not_imply_each_other(self):
        live, live_credential = self.enroll((Permission.LIVE_VIEW,))
        self.store.establish_session(live.id, live_credential.credential_id, b"l" * 32)
        self.assertEqual(self.store.authorize(b"l" * 32, IDENTITY, Permission.LIVE_VIEW).id, live.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(b"l" * 32, IDENTITY, Permission.RECORDINGS_VIEW)

        principal = self.store.invite("recording@example.invalid", "Synthetic recorder", (Permission.RECORDINGS_VIEW,))
        self.store.issue_enrollment(principal.id, b"r" * 32, NOW + timedelta(minutes=5))
        recorder = self.store.enroll_credential(b"r" * 32, principal.external_identity, b"recording-credential", PUBLIC_KEY, -7, 0)
        self.store.establish_session(principal.id, recorder.credential_id, b"s" * 32)
        self.assertEqual(self.store.authorize(b"s" * 32, principal.external_identity, Permission.RECORDINGS_VIEW).id, principal.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(b"s" * 32, principal.external_identity, Permission.LIVE_VIEW)

    def test_revocation_invalidates_current_and_future_sessions(self):
        principal, credential = self.enroll((Permission.LIVE_VIEW,))
        self.store.establish_session(principal.id, credential.credential_id, TOKEN)
        self.assertEqual(self.store.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW).status, PrincipalStatus.ACTIVE)
        self.store.revoke_principal(principal.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW)
        with self.assertRaises(AccessValidationError):
            self.store.establish_session(principal.id, credential.credential_id, b"n" * 32)

    def test_permission_change_invalidates_existing_session_and_requires_new_one(self):
        principal, credential = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        self.store.establish_session(principal.id, credential.credential_id, TOKEN)
        self.store.establish_session(principal.id, credential.credential_id, b"m" * 32)
        self.store.set_permissions(principal.id, (Permission.RECORDINGS_VIEW,))
        for token in (TOKEN, b"m" * 32):
            with self.subTest(token=token), self.assertRaises(AccessValidationError):
                self.store.authorize(token, IDENTITY, Permission.LIVE_VIEW)
        with closing(self.database.connect()) as connection:
            invalidated = connection.execute("SELECT count(*) FROM access_sessions WHERE principal_id=? AND invalidated_at_us IS NOT NULL", (str(principal.id),)).fetchone()[0]
        self.assertEqual(invalidated, 2)
        self.store.establish_session(principal.id, credential.credential_id, b"n" * 32)
        self.assertEqual(self.store.authorize(b"n" * 32, IDENTITY, Permission.RECORDINGS_VIEW).id, principal.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(b"n" * 32, IDENTITY, Permission.LIVE_VIEW)

    def test_enrollment_is_single_use_identity_bound_and_generation_bound(self):
        principal = self.store.invite(IDENTITY, "Synthetic viewer", ())
        self.store.issue_enrollment(principal.id, SECRET, NOW + timedelta(minutes=5))
        with self.assertRaises(AccessValidationError):
            self.store.enroll_credential(SECRET, "other@example.invalid", CREDENTIAL, PUBLIC_KEY, -7, 0)
        credential = self.store.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertEqual(credential.principal_id, principal.id)
        with self.assertRaises(AccessValidationError):
            self.store.enroll_credential(SECRET, IDENTITY, b"other-credential", PUBLIC_KEY, -7, 0)

    def test_enrollment_rejects_redemption_at_exact_expiry(self):
        principal = self.store.invite(IDENTITY, "Synthetic viewer", ())
        expires_at = NOW + timedelta(minutes=5)
        self.store.issue_enrollment(principal.id, SECRET, expires_at)

        with self.assertRaises(AccessValidationError):
            self.store.enroll_credential(
                SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0,
                now=expires_at,
            )

    def test_owner_has_authorization_without_viewer_permission_but_needs_credential_session(self):
        owner = self.store.bootstrap_owner(OWNER, "Synthetic owner")
        self.assertEqual(owner.role, PrincipalRole.OWNER)
        with self.assertRaises(AccessValidationError):
            self.store.bootstrap_owner("second@example.invalid", "Second owner")
        self.store.issue_enrollment(owner.id, b"o" * 32, NOW + timedelta(minutes=5))
        credential = self.store.enroll_credential(b"o" * 32, OWNER, b"owner-credential", PUBLIC_KEY, -7, 0)
        self.store.establish_session(owner.id, credential.credential_id, b"a" * 32)
        self.assertEqual(self.store.authorize(b"a" * 32, OWNER, Permission.LIVE_VIEW).role, PrincipalRole.OWNER)
        self.assertEqual(self.store.authorize(b"a" * 32, OWNER, Permission.RECORDINGS_VIEW).role, PrincipalRole.OWNER)

    def test_expired_idle_session_and_wrong_identity_fail_closed(self):
        principal, credential = self.enroll()
        self.store.establish_session(principal.id, credential.credential_id, TOKEN, idle_lifetime=timedelta(seconds=1), absolute_lifetime=timedelta(seconds=2))
        with self.assertRaises(AccessValidationError):
            self.store.authorize(TOKEN, "other@example.invalid", Permission.LIVE_VIEW)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW, now=NOW + timedelta(seconds=1))

    def test_session_rejects_clock_regression_and_keeps_its_configured_idle_lifetime(self):
        principal, credential = self.enroll()
        self.store.establish_session(principal.id, credential.credential_id, TOKEN,
                                     idle_lifetime=timedelta(seconds=90),
                                     absolute_lifetime=timedelta(minutes=5))
        with self.assertRaises(AccessValidationError):
            self.store.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW,
                                 now=NOW - timedelta(microseconds=1))
        self.store.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW,
                             now=NOW + timedelta(seconds=60))
        # This would be rejected if authorize reset the session to the global
        # 30-minute default instead of its stored 90-second idle lifetime.
        with self.assertRaises(AccessValidationError):
            self.store.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW,
                                 now=NOW + timedelta(seconds=150))

    def test_no_raw_secret_is_persisted(self):
        principal, credential = self.enroll()
        self.store.establish_session(principal.id, credential.credential_id, TOKEN)
        with closing(self.database.connect()) as connection:
            text = " ".join(str(value) for row in connection.execute("SELECT * FROM access_invitations").fetchall() for value in row)
            text += " ".join(str(value) for row in connection.execute("SELECT * FROM access_sessions").fetchall() for value in row)
        self.assertNotIn(SECRET.decode(), text)
        self.assertNotIn(TOKEN.decode(), text)


if __name__ == "__main__":
    unittest.main()
