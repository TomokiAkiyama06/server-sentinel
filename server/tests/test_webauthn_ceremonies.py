"""Synthetic WebAuthn ceremony tests for Issue #10 (ADR-0004).

Every authenticator is a software key generated in the test process
(``webauthn_fakes``). Nothing here is a real passkey, browser or device, and
passing these tests is not evidence of real browser/authenticator behavior;
see MANUAL_TEST.md for that.
"""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.audit.integration import AccessAdministration
from app.audit.model import ActorCategory, AuditAction, AuditOutcome
from app.audit.service import OwnerAuditService
from app.audit.store import AuditStore
from app.auth.model import AccessValidationError, CredentialStatus, Permission
from app.auth.passkeys import (
    CeremonyDenied, CredentialFinding, DeviceBoundCredentialRequired, PasskeyCeremonies,
)
from app.auth.store import AccessStore, StepUpRequired
from app.auth.webauthn import EDDSA, ES256, RS256, RelyingParty
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.webauthn_fakes import ORIGIN, RP_ID, SyntheticAuthenticator, _DROP, b64, cbor


START = datetime(2026, 9, 30, 9, 0, tzinfo=timezone.utc)
VIEWER = "synthetic-viewer@example.invalid"
OWNER = "synthetic-owner@example.invalid"
OTHER = "synthetic-other@example.invalid"
VIEWER_CODE = b"v" * 32
OWNER_CODE = b"o" * 32
OWNER_CONTEXT = "synthetic-owner-context"
GENERIC = "access is unavailable"


class Clock:
    def __init__(self):
        self.value = START

    def __call__(self):
        return self.value

    def advance(self, **delta):
        self.value += timedelta(**delta)


class Findings:
    def __init__(self):
        self.items = []

    def credential_finding(self, kind, principal_id):
        self.items.append((kind, principal_id))


class OwnerOnly:
    def require_owner(self, actor_context):
        if actor_context != OWNER_CONTEXT:
            raise PermissionError("denied")


class CeremonyTestCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.database = Database(Path(temp.name) / "access.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = Clock()
        self.audit = AuditStore(self.database, clock=self.clock)
        self.store = AccessStore(self.database, clock=self.clock, audit=self.audit, unaudited_writes=True)
        self.findings = Findings()
        self.rp = RelyingParty(RP_ID, ORIGIN)
        self.ceremonies = self.make_ceremonies()
        self.admin = AccessAdministration(OwnerAuditService(self.audit, OwnerOnly()), self.store)

    def make_ceremonies(self, **options):
        return PasskeyCeremonies(self.store, self.rp, clock=self.clock, findings=self.findings, **options)

    # -- helpers --

    def count(self, sql, *args):
        with closing(self.database.connect()) as connection:
            return connection.execute(sql, args).fetchone()[0]

    def audit_actions(self):
        with closing(self.database.connect()) as connection:
            return [(row[0], row[1], row[2]) for row in connection.execute(
                "SELECT action, actor_category, outcome FROM security_admin_audit_records ORDER BY occurred_at_us, rowid")]

    def invite(self, identity=VIEWER, code=VIEWER_CODE, permissions=(Permission.LIVE_VIEW,), minutes=30):
        principal = self.store.invite(identity, "Synthetic person", permissions)
        self.store.issue_enrollment(principal.id, code, self.clock() + timedelta(minutes=minutes))
        return principal

    def register(self, authenticator=None, identity=VIEWER, code=VIEWER_CODE, **options):
        authenticator = authenticator or SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(code, identity)
        credential = self.ceremonies.finish_registration(code, identity, authenticator.register(creation, **options))
        return authenticator, credential

    def owner(self, authenticator=None):
        owner = self.store.bootstrap_owner(OWNER, "Synthetic owner")
        self.store.issue_enrollment(owner.id, OWNER_CODE, self.clock() + timedelta(minutes=10))
        authenticator, _ = self.register(authenticator, OWNER, OWNER_CODE)
        return owner, authenticator

    def sign_in(self, authenticator, identity=VIEWER, **options):
        request = self.ceremonies.begin_authentication()
        return self.ceremonies.finish_authentication(identity, authenticator.assertion(request, **options))

    def assertGenericDenial(self, call):
        with self.assertRaises(AccessValidationError) as caught:
            call()
        error = caught.exception
        self.assertIs(type(error), CeremonyDenied)
        self.assertEqual(str(error), GENERIC)
        self.assertEqual(error.args, (GENERIC,))
        # No chained cause or context can carry the reason out.
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        return error


class RegistrationTests(CeremonyTestCase):
    def test_valid_registration_for_each_algorithm_binds_credential_to_invited_person(self):
        for index, algorithm in enumerate((ES256, EDDSA, RS256)):
            with self.subTest(algorithm=algorithm):
                identity, code = f"synthetic-{index}@example.invalid", bytes([65 + index]) * 32
                principal = self.invite(identity, code)
                authenticator, credential = self.register(SyntheticAuthenticator(algorithm), identity, code)
                self.assertEqual(credential.principal_id, principal.id)
                self.assertEqual(credential.algorithm, algorithm)
                self.assertEqual(credential.credential_id, authenticator.credential_id)
                self.assertEqual(authenticator.user_handle, principal.id.bytes)
                self.assertEqual(credential.status, CredentialStatus.ACTIVE)
                self.assertEqual(self.count("SELECT count(*) FROM access_invitations WHERE principal_id=? AND redeemed_at_us IS NOT NULL", str(principal.id)), 1)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), 0)
        self.assertEqual([action for action, _, _ in self.audit_actions()], ["redeem_principal_invitation"] * 3)

    def test_registration_options_are_non_branding_and_require_user_verification(self):
        self.invite()
        options = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        self.assertEqual(options["rp"], {"id": RP_ID, "name": RP_ID})
        self.assertEqual(options["authenticatorSelection"]["userVerification"], "required")
        self.assertEqual(options["authenticatorSelection"]["residentKey"], "required")
        self.assertEqual(options["attestation"], "none")
        self.assertNotIn("ServerSentinel", repr(options))
        self.assertEqual(set(options), {"rp", "user", "challenge", "pubKeyCredParams", "timeout",
                                        "excludeCredentials", "authenticatorSelection", "attestation"})

    def test_packed_self_attestation_is_verified(self):
        self.invite()
        _, credential = self.register(fmt="packed")
        self.assertEqual(credential.status, CredentialStatus.ACTIVE)

    def test_raw_challenge_is_never_persisted(self):
        self.invite()
        options = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        with closing(self.database.connect()) as connection:
            rows = connection.execute("SELECT challenge_digest FROM access_webauthn_challenges").fetchall()
        challenge = options["challenge"]
        self.assertEqual(len(rows), 1)
        self.assertNotIn(challenge.encode(), bytes(rows[0][0]))
        self.assertEqual(len(bytes(rows[0][0])), 32)

    def test_invalid_registrations_are_refused_generically_without_side_effects(self):
        other = SyntheticAuthenticator()
        cases = {
            "wrong origin": dict(origin="https://other.example.invalid"),
            "origin on another port": dict(origin=ORIGIN + ":8443"),
            "plain http origin": dict(origin="http://sentinel.example.invalid"),
            "wrong rp id": dict(rp_id="other.example.invalid"),
            "wrong client data type": dict(kind="webauthn.get"),
            "cross origin": dict(client_extra={"crossOrigin": True}),
            "top origin": dict(client_extra={"topOrigin": "https://other.example.invalid"}),
            "missing challenge": dict(challenge=_DROP),
            "missing origin": dict(origin=_DROP),
            "user verification missing": dict(uv=False),
            "user presence missing": dict(up=False),
            "unknown challenge": dict(challenge=b64(b"x" * 32)),
            "raw id differs from attested credential": dict(raw_id=b"another-credential"),
            "none with statement": dict(statement={"sig": b"x"}),
            "unsupported attestation format": dict(fmt="fido-u2f", statement={"sig": b"x", "x5c": [b"x"]}),
            "packed with bad signature": dict(fmt="packed", statement={"alg": ES256, "sig": b"\x30\x00"}),
            "packed with certificate chain": dict(fmt="packed", statement={"alg": ES256, "sig": b"x", "x5c": [b"x"]}),
        }
        self.invite()
        for name, options in cases.items():
            with self.subTest(case=name):
                creation = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
                response = other.register(creation, **options)
                self.assertGenericDenial(lambda: self.ceremonies.finish_registration(VIEWER_CODE, VIEWER, response))
                self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
                self.assertEqual(self.audit_actions(), [])
                # The issued challenge was consumed or never matched; a new
                # attempt needs a new challenge.
                if name != "unknown challenge":
                    self.assertGenericDenial(lambda: self.ceremonies.finish_registration(VIEWER_CODE, VIEWER, response))
                # Refresh the invitation's attempt budget for the next case.
                with closing(self.database.connect()) as connection:
                    connection.execute("UPDATE access_invitations SET attempt_count=0")

    def test_replayed_registration_is_refused(self):
        self.invite()
        creation = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        authenticator = SyntheticAuthenticator()
        response = authenticator.register(creation)
        self.ceremonies.finish_registration(VIEWER_CODE, VIEWER, response)
        self.assertGenericDenial(lambda: self.ceremonies.finish_registration(VIEWER_CODE, VIEWER, response))
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 1)

    def test_expired_registration_challenge_is_refused_and_dropped(self):
        self.invite()
        creation = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        response = SyntheticAuthenticator().register(creation)
        self.clock.advance(minutes=5)
        self.assertGenericDenial(lambda: self.ceremonies.finish_registration(VIEWER_CODE, VIEWER, response))
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), 0)

    def test_challenge_from_before_a_backward_clock_step_is_refused(self):
        self.invite()
        creation = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        self.clock.advance(seconds=-1)
        self.assertGenericDenial(lambda: self.ceremonies.finish_registration(
            VIEWER_CODE, VIEWER, SyntheticAuthenticator().register(creation)))

    def test_authentication_challenge_cannot_complete_a_registration(self):
        self.invite()
        self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        request = self.ceremonies.begin_authentication()
        forged = {"challenge": request["challenge"], "user": {"id": b64(b"u" * 16)}}
        self.assertGenericDenial(lambda: self.ceremonies.finish_registration(
            VIEWER_CODE, VIEWER, SyntheticAuthenticator().register(forged)))

    def test_uninvited_expired_redeemed_and_mismatched_codes_get_the_same_denial(self):
        self.invite(minutes=10)
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(b"u" * 32, VIEWER))
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(b"short", VIEWER))
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(VIEWER_CODE, OTHER))
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(VIEWER_CODE, "not an identity"))
        self.register()
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(VIEWER_CODE, VIEWER))
        self.invite(OTHER, b"q" * 32, minutes=1)
        self.clock.advance(minutes=1)
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(b"q" * 32, OTHER))

    def test_challenge_bound_to_one_invitation_cannot_redeem_another(self):
        self.invite()
        self.invite(OTHER, b"q" * 32)
        creation = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        response = SyntheticAuthenticator().register(creation)
        self.assertGenericDenial(lambda: self.ceremonies.finish_registration(b"q" * 32, OTHER, response))
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)

    def test_redemption_attempts_are_bounded_per_code(self):
        self.invite()
        for _ in range(5):
            self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        self.assertGenericDenial(lambda: self.ceremonies.begin_registration(VIEWER_CODE, VIEWER))

    def test_revoked_principal_invitation_cannot_register(self):
        principal = self.invite()
        creation = self.ceremonies.begin_registration(VIEWER_CODE, VIEWER)
        self.store.revoke_principal(principal.id)
        self.assertGenericDenial(lambda: self.ceremonies.finish_registration(
            VIEWER_CODE, VIEWER, SyntheticAuthenticator().register(creation)))
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)

    def test_device_bound_policy_refuses_backup_eligible_credential_distinctly(self):
        self.ceremonies = self.make_ceremonies(require_device_bound=True)
        self.invite()
        with self.assertRaises(DeviceBoundCredentialRequired):
            self.register(SyntheticAuthenticator(backup_eligible=True, backup_state=True))
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        _, credential = self.register(SyntheticAuthenticator())
        self.assertFalse(credential.backup_eligible)

    def test_backup_flags_are_recorded_and_state_without_eligibility_is_malformed(self):
        self.invite()
        _, credential = self.register(SyntheticAuthenticator(backup_eligible=True, backup_state=False))
        self.assertTrue(credential.backup_eligible)
        self.assertFalse(credential.backup_state)
        self.invite(OTHER, b"q" * 32)
        self.assertGenericDenial(lambda: self.register(
            SyntheticAuthenticator(backup_eligible=False, backup_state=True), OTHER, b"q" * 32))

    def test_disallowed_algorithm_is_refused(self):
        self.ceremonies = self.make_ceremonies(allowed_algorithms=(ES256,))
        self.invite()
        self.assertGenericDenial(lambda: self.register(SyntheticAuthenticator(EDDSA)))


class AuthenticationTests(CeremonyTestCase):
    def setUp(self):
        super().setUp()
        self.principal = self.invite(permissions=(Permission.LIVE_VIEW,))
        self.authenticator, self.credential = self.register()

    def test_valid_sign_in_issues_credential_bound_session_with_adr_0003_lifetimes(self):
        grant = self.sign_in(self.authenticator)
        self.assertEqual(grant.principal_id, self.principal.id)
        self.assertNotIn(grant.token.hex(), repr(grant))
        self.assertEqual(self.store.authorize(grant.token, VIEWER, Permission.LIVE_VIEW).id, self.principal.id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(grant.token, VIEWER, Permission.RECORDINGS_VIEW)
        with closing(self.database.connect()) as connection:
            row = connection.execute("SELECT * FROM access_sessions WHERE id=?", (str(grant.session_id),)).fetchone()
        self.assertEqual(bytes(row["credential_id"]), self.credential.credential_id)
        self.assertEqual(row["idle_lifetime_us"], 30 * 60 * 1_000_000)
        self.assertEqual(row["absolute_expires_at_us"] - row["established_at_us"], 12 * 3600 * 1_000_000)
        self.assertEqual(row["last_user_verification_at_us"], row["established_at_us"])
        self.assertNotEqual(bytes(row["token_digest"]), grant.token)
        self.assertEqual(self.audit_actions()[-1], ("authenticate_principal", "invited_user", "succeeded"))
        stored = self.store.credentials_for(self.principal.id)[0]
        self.assertEqual(stored.last_used_at, START)

    def test_counterless_authenticator_may_sign_in_repeatedly(self):
        for _ in range(3):
            self.sign_in(self.authenticator)
        self.assertEqual(self.store.credentials_for(self.principal.id)[0].sign_count, 0)

    def test_counter_advances_and_regression_is_refused_and_reported(self):
        self.invite(OTHER, b"q" * 32)
        counting, _ = self.register(SyntheticAuthenticator(sign_count=5), OTHER, b"q" * 32)
        other = self.store.credentials_for(self.store.assertion_subject(counting.credential_id)[0].id)[0]
        self.assertEqual(other.sign_count, 5)
        self.sign_in(counting, OTHER)
        self.assertEqual(self.store.credentials_for(other.principal_id)[0].sign_count, 6)
        for count in (6, 3, 0):
            with self.subTest(count=count):
                self.assertGenericDenial(lambda: self.sign_in(counting, OTHER, count=count))
        self.assertEqual(self.store.credentials_for(other.principal_id)[0].sign_count, 6)
        self.assertEqual(self.findings.items, [(CredentialFinding.SIGN_COUNT_REGRESSION, other.principal_id)] * 3)
        self.assertEqual(self.audit_actions().count(
            ("detect_principal_credential_sign_count_regression", "system", "failed")), 3)

    def test_invalid_assertions_are_refused_generically_and_change_nothing(self):
        cases = {
            "wrong origin": dict(origin="https://other.example.invalid"),
            "wrong rp id": dict(rp_id="other.example.invalid"),
            "wrong type": dict(kind="webauthn.create"),
            "user verification missing": dict(uv=False),
            "user presence missing": dict(up=False),
            "bad signature": dict(tamper=True),
            "unknown challenge": dict(challenge=b64(b"y" * 32)),
            "user handle of someone else": dict(user_handle=b"z" * 16),
            "user handle missing": dict(omit_user_handle=True),
        }
        before = self.audit_actions()
        for name, options in cases.items():
            with self.subTest(case=name):
                self.assertGenericDenial(lambda: self.sign_in(self.authenticator, **options))
                self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 0)
                self.assertEqual(self.audit_actions(), before)
                self.assertEqual(self.store.credentials_for(self.principal.id)[0].last_used_at, None)

    def test_replayed_and_expired_challenges_are_refused(self):
        request = self.ceremonies.begin_authentication()
        response = self.authenticator.assertion(request)
        self.ceremonies.finish_authentication(VIEWER, response)
        self.assertGenericDenial(lambda: self.ceremonies.finish_authentication(VIEWER, response))
        request = self.ceremonies.begin_authentication()
        response = self.authenticator.assertion(request)
        self.clock.advance(minutes=5)
        self.assertGenericDenial(lambda: self.ceremonies.finish_authentication(VIEWER, response))
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 1)

    def test_failed_attempt_burns_its_challenge(self):
        request = self.ceremonies.begin_authentication()
        self.assertGenericDenial(lambda: self.ceremonies.finish_authentication(
            VIEWER, self.authenticator.assertion(request, uv=False)))
        self.assertGenericDenial(lambda: self.ceremonies.finish_authentication(
            VIEWER, self.authenticator.assertion(request)))

    def test_unregistered_authenticator_is_refused(self):
        self.assertGenericDenial(lambda: self.sign_in(SyntheticAuthenticator()))

    def test_proxy_identity_is_supplementary_and_never_sufficient(self):
        # A valid assertion from another verified login is refused ...
        self.assertGenericDenial(lambda: self.sign_in(self.authenticator, OTHER))
        # ... and the right login without a credential-backed session authorizes nothing.
        for token in (b"", b"t" * 32, b"\x00", "not-bytes", None):
            with self.subTest(token=token), self.assertRaises(AccessValidationError) as caught:
                self.store.authorize(token, VIEWER, Permission.LIVE_VIEW)
            self.assertEqual(str(caught.exception), GENERIC)

    def test_revoking_one_credential_is_credential_scoped(self):
        self.store.issue_enrollment(self.principal.id, b"s" * 32, self.clock() + timedelta(minutes=5))
        second, _ = self.register(code=b"s" * 32)
        first_grant = self.sign_in(self.authenticator)
        second_grant = self.sign_in(second)
        self.admin.revoke_credential(OWNER_CONTEXT, self.principal.id, self.credential.credential_id)
        with self.assertRaises(AccessValidationError):
            self.store.authorize(first_grant.token, VIEWER, Permission.LIVE_VIEW)
        self.assertGenericDenial(lambda: self.sign_in(self.authenticator))
        # The principal's other credential and its session keep working.
        self.assertEqual(self.store.authorize(second_grant.token, VIEWER, Permission.LIVE_VIEW).id, self.principal.id)
        self.sign_in(second)
        statuses = sorted(item.status.value for item in self.store.credentials_for(self.principal.id))
        self.assertEqual(statuses, ["active", "revoked"])

    def test_revoked_principal_is_refused_like_an_uninvited_one(self):
        grant = self.sign_in(self.authenticator)
        self.admin.revoke_principal(OWNER_CONTEXT, self.principal.id)
        revoked = self.assertGenericDenial(lambda: self.sign_in(self.authenticator))
        uninvited = self.assertGenericDenial(lambda: self.sign_in(SyntheticAuthenticator()))
        self.assertEqual((type(revoked), revoked.args), (type(uninvited), uninvited.args))
        with self.assertRaises(AccessValidationError):
            self.store.authorize(grant.token, VIEWER, Permission.LIVE_VIEW)

    def test_backup_state_is_refreshed_from_each_verified_assertion(self):
        self.invite(OTHER, b"q" * 32)
        syncing, credential = self.register(SyntheticAuthenticator(backup_eligible=True), OTHER, b"q" * 32)
        self.assertFalse(credential.backup_state)
        self.sign_in(syncing, OTHER, bs=True)
        self.assertTrue(self.store.credentials_for(credential.principal_id)[0].backup_state)

    def test_changed_backup_eligibility_marks_credential_inconsistent_and_revokes_sessions(self):
        grant = self.sign_in(self.authenticator)
        self.assertGenericDenial(lambda: self.sign_in(self.authenticator, be=True))
        stored = self.store.credentials_for(self.principal.id)[0]
        self.assertEqual(stored.status, CredentialStatus.INCONSISTENT)
        with closing(self.database.connect()) as connection:
            reason = connection.execute("SELECT inconsistency_reason FROM access_credentials").fetchone()[0]
        self.assertEqual(reason, "backup_eligibility_changed")
        with self.assertRaises(AccessValidationError):
            self.store.authorize(grant.token, VIEWER, Permission.LIVE_VIEW)
        # Unusable until replaced, even with the original flag value.
        self.assertGenericDenial(lambda: self.sign_in(self.authenticator))
        self.assertEqual(self.findings.items, [(CredentialFinding.BACKUP_ELIGIBILITY_CHANGED, self.principal.id)])
        self.assertIn(("mark_principal_credential_inconsistent", "system", "succeeded"), self.audit_actions())
        with self.assertRaises(AccessValidationError):
            self.store.establish_session(self.principal.id, self.credential.credential_id, b"n" * 32)

    def test_capture_agent_key_cannot_authenticate_as_a_human(self):
        agent_key = ed25519.Ed25519PrivateKey.generate()
        agent_public = agent_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        node_id = "00000000-0000-4000-8000-00000000abcd"
        with closing(self.database.connect()) as connection:
            connection.execute("INSERT INTO pairing_node_credentials VALUES (?, ?, ?, 'active')",
                               (node_id, hashlib.sha256(agent_public).hexdigest(), "c" * 64))
        for credential_id in (agent_public, node_id.encode(), hashlib.sha256(agent_public).digest()):
            with self.subTest(credential_id=credential_id):
                agent = SyntheticAuthenticator(EDDSA, credential_id=credential_id)
                agent.private_key = agent_key
                agent.user_handle = self.principal.id.bytes
                self.assertGenericDenial(lambda: self.sign_in(agent))
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 0)

    def test_pending_challenges_are_bounded(self):
        from app.auth import store as store_module
        original = store_module.MAX_PENDING_CHALLENGES
        store_module.MAX_PENDING_CHALLENGES = 3
        self.addCleanup(setattr, store_module, "MAX_PENDING_CHALLENGES", original)
        for _ in range(3):
            self.ceremonies.begin_authentication()
        self.assertGenericDenial(self.ceremonies.begin_authentication)
        self.clock.advance(minutes=5)
        self.ceremonies.begin_authentication()


class StepUpTests(CeremonyTestCase):
    def setUp(self):
        super().setUp()
        self.owner_principal, self.owner_key = self.owner()
        self.grant = self.sign_in(self.owner_key, OWNER)

    def step_up(self, authenticator, token=None, **options):
        token = self.grant.token if token is None else token
        request = self.ceremonies.begin_step_up(token, OWNER)
        self.ceremonies.finish_step_up(token, OWNER, authenticator.assertion(request, **options))

    def verification_time(self):
        return self.count("SELECT last_user_verification_at_us FROM access_sessions WHERE id=?", str(self.grant.session_id))

    def test_fresh_owner_session_runs_and_stale_one_requires_step_up(self):
        self.assertEqual(self.ceremonies.authorize_owner_operation(self.grant.token, OWNER).id, self.owner_principal.id)
        self.clock.advance(minutes=5)
        with self.assertRaises(StepUpRequired):
            self.ceremonies.authorize_owner_operation(self.grant.token, OWNER)
        self.step_up(self.owner_key)
        self.assertEqual(self.ceremonies.authorize_owner_operation(self.grant.token, OWNER).id, self.owner_principal.id)
        self.assertEqual(self.audit_actions()[-1], ("verify_principal_step_up", "owner", "succeeded"))

    def test_step_up_allows_only_the_sessions_own_credential(self):
        self.store.issue_enrollment(self.owner_principal.id, b"s" * 32, self.clock() + timedelta(minutes=5))
        second_owner_key, _ = self.register(identity=OWNER, code=b"s" * 32)
        self.invite()
        viewer_key, _ = self.register()
        self.clock.advance(minutes=6)
        before = self.verification_time()
        request = self.ceremonies.begin_step_up(self.grant.token, OWNER)
        self.assertEqual(request["allowCredentials"], [{"type": "public-key", "id": b64(self.owner_key.credential_id)}])
        for other in (second_owner_key, viewer_key):
            with self.subTest(credential=other.credential_id):
                request = self.ceremonies.begin_step_up(self.grant.token, OWNER)
                self.assertGenericDenial(lambda: self.ceremonies.finish_step_up(
                    self.grant.token, OWNER, other.assertion(request)))
                self.assertEqual(self.verification_time(), before)
                with self.assertRaises(StepUpRequired):
                    self.ceremonies.authorize_owner_operation(self.grant.token, OWNER)

    def test_failed_or_cancelled_step_up_changes_nothing(self):
        self.clock.advance(minutes=6)
        before, actions = self.verification_time(), self.audit_actions()
        for options in (dict(uv=False), dict(tamper=True), dict(origin="https://other.example.invalid")):
            with self.subTest(options=options):
                self.assertGenericDenial(lambda: self.step_up(self.owner_key, **options))
        # A cancelled ceremony simply never finishes: the challenge expires unused.
        self.ceremonies.begin_step_up(self.grant.token, OWNER)
        self.clock.advance(minutes=5)
        self.assertEqual(self.verification_time(), before)
        self.assertEqual(self.audit_actions(), actions)

    def test_step_up_challenge_is_bound_to_its_session(self):
        other_session = self.sign_in(self.owner_key, OWNER)
        self.clock.advance(minutes=6)
        request = self.ceremonies.begin_step_up(self.grant.token, OWNER)
        self.assertGenericDenial(lambda: self.ceremonies.finish_step_up(
            other_session.token, OWNER, self.owner_key.assertion(request)))

    def test_non_owner_and_unauthenticated_callers_get_the_generic_denial(self):
        self.invite(permissions=(Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        viewer_key, _ = self.register()
        viewer = self.sign_in(viewer_key)
        for token, identity in ((viewer.token, VIEWER), (b"x" * 32, OWNER), (b"", OWNER), (self.grant.token, OTHER)):
            with self.subTest(identity=identity):
                self.assertGenericDenial(lambda: self.ceremonies.authorize_owner_operation(token, identity))
                self.assertGenericDenial(lambda: self.ceremonies.begin_step_up(token, identity))

    def test_session_without_verification_record_is_never_fresh(self):
        token = b"l" * 32
        self.store.establish_session(self.owner_principal.id, self.owner_key.credential_id, token)
        with self.assertRaises(StepUpRequired):
            self.ceremonies.authorize_owner_operation(token, OWNER)

    def test_revoked_session_credential_cannot_be_revived_by_step_up(self):
        self.clock.advance(minutes=6)
        request = self.ceremonies.begin_step_up(self.grant.token, OWNER)
        self.admin.revoke_credential(OWNER_CONTEXT, self.owner_principal.id, self.owner_key.credential_id)
        self.assertGenericDenial(lambda: self.ceremonies.finish_step_up(
            self.grant.token, OWNER, self.owner_key.assertion(request)))
        self.assertGenericDenial(lambda: self.ceremonies.authorize_owner_operation(self.grant.token, OWNER))


class DenialUniformityTests(CeremonyTestCase):
    def test_every_pre_session_failure_is_one_indistinguishable_denial(self):
        self.invite()
        authenticator, _ = self.register()
        request = self.ceremonies.begin_authentication()
        failures = [
            lambda: self.ceremonies.begin_registration(b"u" * 32, VIEWER),
            lambda: self.ceremonies.finish_registration(b"u" * 32, VIEWER, {"type": "public-key"}),
            lambda: self.ceremonies.finish_authentication(VIEWER, {}),
            lambda: self.ceremonies.finish_authentication(VIEWER, "not a mapping"),
            lambda: self.ceremonies.finish_authentication(VIEWER, authenticator.assertion(request, tamper=True)),
            lambda: self.ceremonies.finish_authentication(OTHER, authenticator.assertion(request)),
            lambda: self.ceremonies.begin_step_up(b"x" * 32, VIEWER),
            lambda: self.ceremonies.finish_step_up(b"x" * 32, VIEWER, {}),
            lambda: self.ceremonies.authorize_owner_operation(b"short", VIEWER),
            lambda: self.ceremonies.authorize_owner_operation(b"x" * 32, VIEWER),
        ]
        seen = set()
        for call in failures:
            error = self.assertGenericDenial(call)
            seen.add((type(error), error.args))
            for secret in (VIEWER, VIEWER_CODE.decode(), OTHER):
                self.assertNotIn(secret, str(error))
        self.assertEqual(seen, {(CeremonyDenied, (GENERIC,))})

    def test_malformed_and_unknown_session_tokens_share_the_store_denial(self):
        messages = set()
        for token in (b"short", b"x" * 32, b"", None, "text"):
            for call in (lambda: self.store.authorize(token, VIEWER, Permission.LIVE_VIEW),
                         lambda: self.store.authorize_owner(token, VIEWER),
                         lambda: self.store.authorize(b"x" * 32, "bad identity", Permission.LIVE_VIEW)):
                with self.assertRaises(AccessValidationError) as caught:
                    call()
                messages.add((type(caught.exception), str(caught.exception)))
        self.assertEqual(messages, {(AccessValidationError, GENERIC)})


class RelyingPartyTests(unittest.TestCase):
    def test_only_a_dedicated_secure_context_origin_is_accepted(self):
        RelyingParty("sentinel.example.invalid", "https://sentinel.example.invalid")
        RelyingParty("sentinel.example.invalid", "https://sentinel.example.invalid:8443")
        RelyingParty("localhost", "http://localhost:8080")
        for rp_id, origin in (
                ("sentinel.example.invalid", "http://sentinel.example.invalid"),
                ("example.invalid", "https://sentinel.example.invalid"),
                ("sentinel.example.invalid", "https://sentinel.example.invalid/dashboard"),
                ("sentinel.example.invalid", "https://sentinel.example.invalid/"),
                ("sentinel.example.invalid", "https://user@sentinel.example.invalid"),
                ("Sentinel.example.invalid", "https://Sentinel.example.invalid"),
                ("192.0.2.1", "http://192.0.2.1"),
                ("192.0.2.1", "https://192.0.2.1"),
                ("sentinel.example.invalid", "https://sentinel.example.invalid:99999")):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                RelyingParty(rp_id, origin)


class CborStrictnessTests(unittest.TestCase):
    def test_malformed_structures_are_refused(self):
        from app.auth.webauthn import WebAuthnVerificationError, b64url_decode, cbor_decode
        self.assertEqual(cbor_decode(cbor({"a": [1, -2, b"x", True, None]})), {"a": [1, -2, b"x", True, None]})
        for data in (cbor(1) + b"\x00", b"\x5f\x41\x00\xff", b"\xa2\x01\x01\x01\x02", b"\xc0\x01",
                     b"\xfb" + b"\x00" * 8, b"\x5a\xff\xff\xff\xff", b"\x81" * 20 + b"\x01"):
            with self.subTest(data=data), self.assertRaises(WebAuthnVerificationError):
                cbor_decode(data)
        for value in ("AB==", "AB+/", "AR", "", "A"):
            with self.subTest(value=value), self.assertRaises(WebAuthnVerificationError):
                b64url_decode(value, limit=16)

    def test_cose_keys_are_strict(self):
        from app.auth.webauthn import WebAuthnVerificationError, parse_cose_key
        good = SyntheticAuthenticator(EDDSA)
        self.assertEqual(parse_cose_key(good.cose_key()).algorithm, EDDSA)
        x = bytes(32)
        for key in ({1: True, 3: EDDSA, -1: 6, -2: x}, {1: 1, 3: EDDSA, -1: True, -2: x},
                    {1: 2, 3: ES256, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32},  # not on the curve
                    {1: 1, 3: -35, -1: 6, -2: x}, {1: 3, 3: RS256, -1: b"\x01" * 128, -2: b"\x01\x00\x01"}):
            with self.subTest(key=key), self.assertRaises(WebAuthnVerificationError):
                parse_cose_key(cbor(key))

    def test_sign_count_rule(self):
        from app.auth.webauthn import sign_count_advances
        self.assertTrue(sign_count_advances(0, 0))
        self.assertTrue(sign_count_advances(0, 1))
        self.assertTrue(sign_count_advances(4, 5))
        for stored, received in ((5, 5), (5, 4), (5, 0), (1, 0)):
            self.assertFalse(sign_count_advances(stored, received))


class AuditVocabularyTests(unittest.TestCase):
    def test_ceremony_audit_records_carry_only_bounded_values(self):
        for action in (AuditAction.AUTHENTICATE_PRINCIPAL, AuditAction.VERIFY_PRINCIPAL_STEP_UP,
                       AuditAction.MARK_PRINCIPAL_CREDENTIAL_INCONSISTENT,
                       AuditAction.DETECT_PRINCIPAL_CREDENTIAL_SIGN_COUNT_REGRESSION):
            self.assertIn(action.value, {item.value for item in AuditAction})
        self.assertIn(ActorCategory.SYSTEM, set(ActorCategory))
        self.assertIn(AuditOutcome.FAILED, set(AuditOutcome))


if __name__ == "__main__":
    unittest.main()
