"""Synthetic audit wiring tests for human access and capture-node pairing.

No real people, devices, credentials or media: every identity, secret, key and
digest below is a synthetic constant.
"""

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from app.audit import (
    ActorCategory, AuditAction, AuditOutcome, AuditStore, OwnerAuditService,
    OwnerAuthorizationError, TargetKind,
)
from app.audit.integration import AccessAdministration
from app.auth.model import AccessValidationError, Permission, PrincipalStatus
from app.auth.session_binding import SessionBindingKey
from app.auth.store import AccessStorageError, AccessStore, UnauditedAccessWriteError
from app.cameras.remote_agent.pairing import (
    HmacCodeVerifier, PairingAuthorizationError, PairingError, PairingLedger,
    PairingStorageError, PairingValidationError,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)
IDENTITY = "synthetic-viewer@example.invalid"
DISPLAY = "Synthetic Viewer Name"
SECRET = b"synthetic-invitation-secret-0001"
TOKEN = b"synthetic-session-token-00000001"
CREDENTIAL = b"synthetic-credential-identifier"
PUBLIC_KEY = b"synthetic-public-key-material"
KEY_DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
SERIAL_DIGEST = "c" * 64

OWNER_CONTEXT = "synthetic-owner-session"
VIEWER_CONTEXT = "synthetic-viewer-session"
NODE_CONTEXT = "synthetic-capture-node-credential"


class SyntheticOwnerAuthorizer:
    """Only the synthetic Owner context passes; others fail with their category."""

    def require_owner(self, actor_context):
        if actor_context == OWNER_CONTEXT:
            return
        if actor_context == VIEWER_CONTEXT:
            raise OwnerAuthorizationError(ActorCategory.INVITED_USER)
        if actor_context == NODE_CONTEXT:
            raise OwnerAuthorizationError(ActorCategory.CAPTURE_NODE)
        raise OwnerAuthorizationError()


class PlainDenial:
    def require_owner(self, actor_context):
        raise PermissionError("synthetic detail " + IDENTITY)


class SyntheticReservation:
    def __init__(self):
        self.refuse = False

    @contextmanager
    def __call__(self):
        if self.refuse:
            raise RuntimeError("synthetic storage refusal")
        yield


def _fail_audit_inserts(database):
    with closing(database.connect()) as connection:
        connection.execute(
            "CREATE TRIGGER synthetic_audit_fault BEFORE INSERT ON security_admin_audit_records "
            "BEGIN SELECT RAISE(ABORT, 'synthetic audit fault'); END")


class _Base(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Database(Path(self.temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.reservation = SyntheticReservation()
        ticks = count()
        # Strictly increasing audit time keeps the listed order deterministic.
        self.audit = AuditStore(self.database, reservation=self.reservation,
                                clock=lambda: NOW + timedelta(microseconds=next(ticks)))
        self.service = OwnerAuditService(self.audit, SyntheticOwnerAuthorizer())

    def records(self):
        return list(reversed(self.audit.list_records(limit=1000)))

    def summary(self):
        return [(r.actor_category, r.action, r.target_kind, r.target_logical_id, r.outcome)
                for r in self.records()]

    def audit_text(self):
        with closing(self.database.connect()) as connection:
            rows = connection.execute("SELECT * FROM security_admin_audit_records").fetchall()
        return " ".join(str(value) for row in rows for value in row)

    def count(self, sql, *args):
        with closing(self.database.connect()) as connection:
            return connection.execute(sql, args).fetchone()[0]


class AccessAuditTests(_Base):
    def setUp(self):
        super().setUp()
        self.access = AccessStore(self.database, clock=lambda: NOW, audit=self.audit,
                                  session_binding=SessionBindingKey.generate())
        self.admin = AccessAdministration(self.service, self.access)

    def invite_and_redeem(self, permissions=(Permission.LIVE_VIEW,)):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, permissions)
        self.admin.issue_invitation(OWNER_CONTEXT, principal.id, SECRET, NOW + timedelta(minutes=5))
        credential = self.access.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        return principal, credential

    def test_invitation_grant_and_revocation_lifecycle_is_audited(self):
        principal, credential = self.invite_and_redeem()
        self.admin.set_permissions(OWNER_CONTEXT, principal.id,
                                   (Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        self.admin.revoke_credential(OWNER_CONTEXT, principal.id, credential.credential_id)
        self.admin.revoke_principal(OWNER_CONTEXT, principal.id)

        target = principal.id
        kind = TargetKind.PRINCIPAL
        ok = AuditOutcome.SUCCEEDED
        self.assertEqual(self.summary(), [
            (ActorCategory.OWNER, AuditAction.INVITE_PRINCIPAL, kind, target, ok),
            (ActorCategory.OWNER, AuditAction.ISSUE_PRINCIPAL_INVITATION, kind, target, ok),
            (ActorCategory.INVITED_USER, AuditAction.REDEEM_PRINCIPAL_INVITATION, kind, target, ok),
            (ActorCategory.OWNER, AuditAction.CHANGE_PRINCIPAL_PERMISSIONS, kind, target, ok),
            (ActorCategory.OWNER, AuditAction.REVOKE_PRINCIPAL_CREDENTIAL, kind, target, ok),
            (ActorCategory.OWNER, AuditAction.REVOKE_PRINCIPAL, kind, target, ok),
        ])
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials WHERE revoked_at_us IS NULL"), 0)

    def test_credential_revocation_ends_only_that_credentials_sessions(self):
        principal, credential = self.invite_and_redeem()
        self.access.establish_session(principal.id, credential.credential_id, TOKEN, proxy_identity=IDENTITY)
        self.admin.revoke_credential(OWNER_CONTEXT, principal.id, credential.credential_id)
        with self.assertRaises(AccessValidationError):
            self.access.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW)
        with self.assertRaises(AccessValidationError):
            self.access.establish_session(principal.id, credential.credential_id, b"n" * 32, proxy_identity=IDENTITY)
        with self.assertRaises(AccessValidationError):
            self.admin.revoke_credential(OWNER_CONTEXT, principal.id, credential.credential_id)
        self.assertEqual(self.records()[-1].outcome, AuditOutcome.FAILED)

    def test_non_owner_owner_only_operations_are_denied_audited_and_not_run(self):
        principal, credential = self.invite_and_redeem()
        self.access.establish_session(principal.id, credential.credential_id, TOKEN, proxy_identity=IDENTITY)
        before = len(self.records())
        operations = (
            (AuditAction.INVITE_PRINCIPAL,
             lambda actor: self.admin.invite(actor, "Other", ())),
            (AuditAction.ISSUE_PRINCIPAL_INVITATION,
             lambda actor: self.admin.issue_invitation(actor, principal.id, b"x" * 32,
                                                       NOW + timedelta(minutes=5))),
            (AuditAction.CHANGE_PRINCIPAL_PERMISSIONS,
             lambda actor: self.admin.set_permissions(actor, principal.id,
                                                      (Permission.RECORDINGS_VIEW,))),
            (AuditAction.REVOKE_PRINCIPAL_CREDENTIAL,
             lambda actor: self.admin.revoke_credential(actor, principal.id, CREDENTIAL)),
            (AuditAction.REVOKE_PRINCIPAL,
             lambda actor: self.admin.revoke_principal(actor, principal.id)),
        )
        for actor, category in ((VIEWER_CONTEXT, ActorCategory.INVITED_USER),
                                (NODE_CONTEXT, ActorCategory.CAPTURE_NODE)):
            for action, operation in operations:
                with self.subTest(actor=category, action=action):
                    with self.assertRaises(OwnerAuthorizationError) as raised:
                        operation(actor)
                    self.assertEqual(raised.exception.actor_category, category)
                    record = self.records()[-1]
                    self.assertEqual(record.outcome, AuditOutcome.DENIED)
                    self.assertEqual(record.actor_category, category)
                    self.assertEqual(record.action, action)
        self.assertEqual(len(self.records()), before + 2 * len(operations))
        # Nothing ran: grants, principal, invitations, credential and session unchanged.
        self.assertEqual(self.count("SELECT count(*) FROM access_principals"), 1)
        self.assertEqual(self.count("SELECT count(*) FROM access_invitations"), 1)
        self.assertEqual(self.access.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW).status,
                         PrincipalStatus.ACTIVE)
        with self.assertRaises(AccessValidationError):
            self.access.authorize(TOKEN, IDENTITY, Permission.RECORDINGS_VIEW)

    def test_plain_permission_error_is_classified_without_its_detail(self):
        admin = AccessAdministration(OwnerAuditService(self.audit, PlainDenial()), self.access)
        with self.assertRaises(OwnerAuthorizationError):
            admin.invite(OWNER_CONTEXT, DISPLAY, ())
        self.assertEqual(self.records()[-1].actor_category, ActorCategory.UNAUTHENTICATED)
        self.assertNotIn(IDENTITY, self.audit_text())
        self.assertEqual(self.count("SELECT count(*) FROM access_principals"), 0)

    def test_owner_only_wrappers_refuse_outside_the_audited_boundary(self):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, ())
        calls = (
            lambda: self.access.invite("Other", ()),
            lambda: self.access.issue_enrollment(principal.id, SECRET, NOW + timedelta(minutes=5)),
            lambda: self.access.set_permissions(principal.id, (Permission.LIVE_VIEW,)),
            lambda: self.access.revoke_principal(principal.id),
        )
        for call in calls:
            with self.subTest(call=call), self.assertRaises(UnauditedAccessWriteError):
                call()
        self.assertEqual(self.count("SELECT count(*) FROM access_principals"), 1)
        self.assertEqual(self.count("SELECT count(*) FROM access_invitations"), 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_principal_permissions"), 0)

    def test_audit_write_failure_rolls_back_owner_mutation(self):
        principal, credential = self.invite_and_redeem()
        self.access.establish_session(principal.id, credential.credential_id, TOKEN, proxy_identity=IDENTITY)
        _fail_audit_inserts(self.database)
        with self.assertRaises(Exception):
            self.admin.set_permissions(OWNER_CONTEXT, principal.id, (Permission.RECORDINGS_VIEW,))
        with self.assertRaises(Exception):
            self.admin.revoke_principal(OWNER_CONTEXT, principal.id)
        with self.assertRaises(Exception):
            self.admin.invite(OWNER_CONTEXT, "Other", ())
        self.assertEqual(self.access.authorize(TOKEN, IDENTITY, Permission.LIVE_VIEW).id, principal.id)
        self.assertEqual(self.count("SELECT count(*) FROM access_principals"), 1)
        # The separate failure records were also refused, and that loss is visible.
        self.assertTrue(self.service.audit_delivery_failed)

    def test_audit_write_failure_rolls_back_invitation_redemption(self):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, ())
        self.admin.issue_invitation(OWNER_CONTEXT, principal.id, SECRET, NOW + timedelta(minutes=5))
        _fail_audit_inserts(self.database)
        with self.assertRaises(AccessStorageError):
            self.access.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_invitations WHERE redeemed_at_us IS NULL"), 1)
        self.assertEqual(self.count("SELECT count(*) FROM access_principals WHERE status='invited'"), 1)

    def test_redemption_audit_failure_is_visible_but_unmatched_attempts_are_not(self):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, ())
        self.admin.issue_invitation(OWNER_CONTEXT, principal.id, SECRET, NOW + timedelta(minutes=5))
        before = len(self.records())
        _fail_audit_inserts(self.database)
        for secret, identity in ((b"u" * 32, IDENTITY), (SECRET, None)):
            with self.assertRaises(AccessValidationError):
                self.access.enroll_credential(secret, identity, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertFalse(self.access.audit_delivery_failed)
        self.assertEqual(self.access.undelivered_audit_records, 0)
        for _ in range(2):
            with self.assertRaises(AccessStorageError):
                self.access.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertTrue(self.access.audit_delivery_failed)
        self.assertEqual(self.access.undelivered_audit_records, 2)
        # The redemption rolled back and no separate audit row was appended.
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_invitations WHERE redeemed_at_us IS NULL"), 1)
        self.assertEqual(len(self.records()), before)

    def test_redemption_storage_refusal_before_match_is_not_counted(self):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, ())
        self.admin.issue_invitation(OWNER_CONTEXT, principal.id, SECRET, NOW + timedelta(minutes=5))
        self.reservation.refuse = True
        with self.assertRaises(RuntimeError):
            self.access.enroll_credential(b"u" * 32, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertFalse(self.access.audit_delivery_failed)
        self.reservation.refuse = False
        self.access.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertFalse(self.access.audit_delivery_failed)
        self.assertEqual(self.access.undelivered_audit_records, 0)

    def test_redemption_is_admitted_by_storage_reservation_and_requires_audit(self):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, ())
        self.admin.issue_invitation(OWNER_CONTEXT, principal.id, SECRET, NOW + timedelta(minutes=5))
        self.reservation.refuse = True
        with self.assertRaises(RuntimeError):
            self.access.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        unaudited = AccessStore(self.database, clock=lambda: NOW)
        with self.assertRaises(AccessStorageError):
            unaudited.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.reservation.refuse = False
        self.access.enroll_credential(SECRET, IDENTITY, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 1)

    def test_rejected_redemption_records_nothing(self):
        principal = self.admin.invite(OWNER_CONTEXT, DISPLAY, ())
        self.admin.issue_invitation(OWNER_CONTEXT, principal.id, SECRET, NOW + timedelta(minutes=5))
        before = len(self.records())
        for secret, identity in ((b"u" * 32, IDENTITY), (SECRET, None)):
            with self.assertRaises(AccessValidationError):
                self.access.enroll_credential(secret, identity, CREDENTIAL, PUBLIC_KEY, -7, 0)
        self.assertEqual(len(self.records()), before)

    def test_failed_owner_operation_records_bounded_failure(self):
        missing = uuid4()
        with self.assertRaises(AccessValidationError):
            self.admin.revoke_principal(OWNER_CONTEXT, missing)
        record = self.records()[-1]
        self.assertEqual((record.action, record.target_logical_id, record.outcome),
                         (AuditAction.REVOKE_PRINCIPAL, missing, AuditOutcome.FAILED))

    def test_audit_rows_contain_no_identity_secret_or_credential_material(self):
        principal, credential = self.invite_and_redeem()
        self.admin.revoke_credential(OWNER_CONTEXT, principal.id, credential.credential_id)
        text = self.audit_text()
        for value in (IDENTITY, DISPLAY, SECRET.decode(), CREDENTIAL.decode(), PUBLIC_KEY.decode(),
                      SECRET.hex(), CREDENTIAL.hex(), PUBLIC_KEY.hex()):
            self.assertNotIn(value, text)

    def test_administration_requires_shared_database(self):
        other = Database(Path(self.temporary.name) / "other.sqlite3")
        with self.assertRaises(ValueError):
            AccessAdministration(OwnerAuditService(AuditStore(other), SyntheticOwnerAuthorizer()),
                                 self.access)
        with self.assertRaises(AccessValidationError):
            AccessStore(self.database, audit=AuditStore(other))


class PairingAuditTests(_Base):
    def setUp(self):
        super().setUp()
        self.now = 100.0
        self.verifier = HmacCodeVerifier(b"s" * 32)
        self.ledger = PairingLedger(self.database, self.verifier, audit=self.audit,
                                    clock=lambda: self.now, process_epoch=uuid4())
        self.authorizer = SyntheticOwnerAuthorizer()
        # One node per test: a public key is never bound to two nodes.
        self.node = uuid4()

    def approve(self, node=None):
        return self.ledger.approve(self.authorizer, OWNER_CONTEXT, node_id=node or self.node,
                                   public_key_digest=KEY_DIGEST)

    def paired(self):
        approval, code = self.approve()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=KEY_DIGEST, code=code.value)
        self.ledger.activate(claim, credential_serial_digest=SERIAL_DIGEST)
        return approval, code, claim

    def test_enrollment_approval_redemption_activation_and_revocation_are_audited(self):
        approval, code, claim = self.paired()
        self.ledger.revoke(self.authorizer, OWNER_CONTEXT, node_id=claim.node_id)
        node, kind, ok = claim.node_id, TargetKind.CAPTURE_NODE, AuditOutcome.SUCCEEDED
        self.assertEqual(self.summary(), [
            (ActorCategory.OWNER, AuditAction.APPROVE_CAPTURE_NODE_ENROLLMENT, kind, node, ok),
            (ActorCategory.CAPTURE_NODE, AuditAction.REDEEM_CAPTURE_NODE_ENROLLMENT, kind, node, ok),
            (ActorCategory.SYSTEM, AuditAction.ACTIVATE_CAPTURE_NODE_CREDENTIAL, kind, node, ok),
            (ActorCategory.OWNER, AuditAction.REVOKE_CAPTURE_NODE_PAIRING, kind, node, ok),
        ])
        text = self.audit_text()
        for value in (code.value, KEY_DIGEST, SERIAL_DIGEST, str(approval.enrollment_id),
                      self.verifier.digest(code.value)):
            self.assertNotIn(value, text)

    def test_non_owner_approval_and_revocation_are_denied_audited_and_not_run(self):
        _, _, claim = self.paired()
        before = len(self.records())
        for actor, category in ((VIEWER_CONTEXT, ActorCategory.INVITED_USER),
                                (NODE_CONTEXT, ActorCategory.CAPTURE_NODE)):
            with self.subTest(actor=category):
                target = uuid4()
                with self.assertRaises(PairingAuthorizationError):
                    self.ledger.approve(self.authorizer, actor, node_id=target,
                                        public_key_digest=KEY_DIGEST)
                self.assertEqual(self.summary()[-1], (
                    category, AuditAction.APPROVE_CAPTURE_NODE_ENROLLMENT,
                    TargetKind.CAPTURE_NODE, target, AuditOutcome.DENIED))
                with self.assertRaises(PairingAuthorizationError):
                    self.ledger.revoke(self.authorizer, actor, node_id=claim.node_id)
                self.assertEqual(self.summary()[-1], (
                    category, AuditAction.REVOKE_CAPTURE_NODE_PAIRING,
                    TargetKind.CAPTURE_NODE, claim.node_id, AuditOutcome.DENIED))
        self.assertEqual(len(self.records()), before + 4)
        self.assertEqual(self.count("SELECT count(*) FROM pairing_enrollments"), 1)
        self.assertTrue(self.ledger.admits(node_id=claim.node_id, public_key_digest=KEY_DIGEST,
                                           credential_serial_digest=SERIAL_DIGEST))

    def test_plain_permission_denial_and_missing_authorizer_are_bounded(self):
        for authorizer in (PlainDenial(), object()):
            with self.subTest(authorizer=type(authorizer).__name__):
                with self.assertRaises(PairingAuthorizationError):
                    self.ledger.approve(authorizer, OWNER_CONTEXT, node_id=uuid4(),
                                        public_key_digest=KEY_DIGEST)
                self.assertEqual(self.records()[-1].actor_category, ActorCategory.UNAUTHENTICATED)
                self.assertEqual(self.records()[-1].outcome, AuditOutcome.DENIED)
        self.assertNotIn(IDENTITY, self.audit_text())
        self.assertEqual(self.count("SELECT count(*) FROM pairing_enrollments"), 0)

    def test_unmatched_redemption_records_nothing_and_expiry_records_once(self):
        approval, code = self.approve()
        before = len(self.records())
        attempts = (
            dict(enrollment_id=uuid4(), public_key_digest=KEY_DIGEST, code=code.value),
            dict(enrollment_id=approval.enrollment_id, public_key_digest=OTHER_DIGEST, code=code.value),
            dict(enrollment_id=approval.enrollment_id, public_key_digest=KEY_DIGEST,
                 code="A" * 26),
        )
        for attempt in attempts:
            with self.assertRaises(PairingError):
                self.ledger.redeem(**attempt)
        self.assertEqual(len(self.records()), before)
        self.now += 300
        for _ in range(2):
            with self.assertRaises(PairingError):
                self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=KEY_DIGEST, code=code.value)
        self.assertEqual(self.summary()[before:], [
            (ActorCategory.CAPTURE_NODE, AuditAction.REDEEM_CAPTURE_NODE_ENROLLMENT,
             TargetKind.CAPTURE_NODE, approval.node_id, AuditOutcome.FAILED),
        ])

    def test_audit_failure_rolls_back_pairing_mutations(self):
        approval, code = self.approve()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=KEY_DIGEST, code=code.value)
        self.ledger.activate(claim, credential_serial_digest=SERIAL_DIGEST)
        second, second_code = self.approve()
        _fail_audit_inserts(self.database)
        with self.assertRaises(PairingStorageError):
            self.approve()
        with self.assertRaises(PairingStorageError):
            self.ledger.redeem(enrollment_id=second.enrollment_id,
                               public_key_digest=KEY_DIGEST, code=second_code.value)
        with self.assertRaises(PairingStorageError):
            self.ledger.revoke(self.authorizer, OWNER_CONTEXT, node_id=claim.node_id)
        self.assertEqual(self.count("SELECT count(*) FROM pairing_enrollments"), 2)
        self.assertEqual(self.count("SELECT count(*) FROM pairing_enrollments WHERE state='pending'"), 1)
        self.assertTrue(self.ledger.admits(node_id=claim.node_id, public_key_digest=KEY_DIGEST,
                                           credential_serial_digest=SERIAL_DIGEST))
        self.assertTrue(self.ledger.audit_delivery_failed)
        # Approval, redemption and revocation each lost one outcome.
        self.assertEqual(self.ledger.undelivered_audit_records, 3)

    def test_redemption_audit_failure_is_visible_but_unmatched_attempts_are_not(self):
        approval, code = self.approve()
        expiring, expiring_code = self.approve()
        before = len(self.records())
        _fail_audit_inserts(self.database)
        for attempt in (
            dict(enrollment_id=uuid4(), public_key_digest=KEY_DIGEST, code=code.value),
            dict(enrollment_id=approval.enrollment_id, public_key_digest=OTHER_DIGEST, code=code.value),
            dict(enrollment_id=approval.enrollment_id, public_key_digest=KEY_DIGEST, code="A" * 26),
        ):
            with self.assertRaises(PairingError):
                self.ledger.redeem(**attempt)
        self.assertFalse(self.ledger.audit_delivery_failed)
        self.assertEqual(self.ledger.undelivered_audit_records, 0)
        with self.assertRaises(PairingStorageError):
            self.ledger.redeem(enrollment_id=approval.enrollment_id,
                               public_key_digest=KEY_DIGEST, code=code.value)
        self.assertTrue(self.ledger.audit_delivery_failed)
        self.assertEqual(self.ledger.undelivered_audit_records, 1)
        self.now += 300
        with self.assertRaises(PairingStorageError):
            self.ledger.redeem(enrollment_id=expiring.enrollment_id,
                               public_key_digest=KEY_DIGEST, code=expiring_code.value)
        self.assertEqual(self.ledger.undelivered_audit_records, 2)
        # Both changes rolled back and no separate audit row was appended.
        self.assertEqual(self.count("SELECT count(*) FROM pairing_enrollments WHERE state='pending'"), 2)
        self.assertEqual(len(self.records()), before)

    def test_failed_revocation_and_activation_record_bounded_failure(self):
        missing = uuid4()
        with self.assertRaises(PairingError):
            self.ledger.revoke(self.authorizer, OWNER_CONTEXT, node_id=missing)
        self.assertEqual(self.summary()[-1], (
            ActorCategory.OWNER, AuditAction.REVOKE_CAPTURE_NODE_PAIRING,
            TargetKind.CAPTURE_NODE, missing, AuditOutcome.FAILED))
        approval, code = self.approve()
        claim = self.ledger.redeem(enrollment_id=approval.enrollment_id,
                                   public_key_digest=KEY_DIGEST, code=code.value)
        self.ledger.revoke(self.authorizer, OWNER_CONTEXT, node_id=claim.node_id)
        with self.assertRaises(PairingError):
            self.ledger.activate(claim, credential_serial_digest=SERIAL_DIGEST)
        self.assertEqual(self.summary()[-1], (
            ActorCategory.SYSTEM, AuditAction.ACTIVATE_CAPTURE_NODE_CREDENTIAL,
            TargetKind.CAPTURE_NODE, claim.node_id, AuditOutcome.FAILED))

    def test_storage_refusal_blocks_pairing_writes_but_not_admission_reads(self):
        _, _, claim = self.paired()
        self.reservation.refuse = True
        with self.assertRaises(RuntimeError):
            self.ledger.revoke(self.authorizer, OWNER_CONTEXT, node_id=claim.node_id)
        self.assertTrue(self.ledger.admits(node_id=claim.node_id, public_key_digest=KEY_DIGEST,
                                           credential_serial_digest=SERIAL_DIGEST))

    def test_ledger_requires_audit_on_the_same_database(self):
        other = Database(Path(self.temporary.name) / "other.sqlite3")
        for audit in (None, AuditStore(other)):
            with self.subTest(audit=audit), self.assertRaises(PairingValidationError):
                PairingLedger(self.database, self.verifier, audit=audit)


if __name__ == "__main__":
    unittest.main()
