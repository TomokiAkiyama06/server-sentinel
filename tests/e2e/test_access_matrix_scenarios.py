"""Human-access matrix across the closed HTTP surface and the server-side gates.

Identities: uninvited, ``live:view`` only, ``recordings:view`` only, both,
revoked, a paired capture-node (agent) credential, and a spoofed Tailscale /
proxy identity header. Every token, identity, key and digest is generated or a
synthetic constant; no real person, device, credential or media is used.

Two layers are exercised:

* the composed Main ASGI application (``app.main.create_app``) with a
  permissive injected authorizer: every human, admin and media path answers
  every identity with the same generic ``404`` (WebSocket ``1008``) and never
  consults the authorizer, so no application information reaches anyone
  while human routes stay closed (Issues #6/#10);
* the production grant state behind future routes: ``AccessStore.authorize``,
  the gated ``AccessStore.authorize_request`` (with its CSRF comparison and
  ``sign_out``, Issue #10 phase 2 S1), invitation redemption rows (the
  store's conditional single-use redemption with the S2 code format: a code
  of no matrix identity, an expired, revoked or generation-stale code and a
  replayed one are refused alike, and redemption grants nothing by itself),
  the S3 Owner step-up rows (no matrix identity gets a step-up challenge or
  ``step_up_required``; only a stale Owner session gets the latter, another
  person's credential cannot refresh it, and a wall clock stepped back keeps
  it stale), the S4 Owner administration rows (no matrix identity
  authorizes ``OWNER_OP``, an administration context around a non-Owner
  session is denied and changes nothing, and the Owner's invitation, grant
  delta and credential/principal revocation take effect at the next request),
  the ``live:view`` validator and the
  historical timeline gate. The timeline ``access`` port is a test adapter
  that calls ``AccessStore.authorize`` with ``recordings:view``; the
  production route adapter does not exist yet. The reservation gate is a
  synthetic always-open one here; the real gate is covered by
  ``server/tests/test_human_surface.py`` and ``test_session_gate.py``.

This is not browser, Tailscale, proxy or WebAuthn ceremony acceptance.
"""

import asyncio
from contextlib import closing, contextmanager
from datetime import timedelta
from pathlib import Path
import secrets
import tempfile
import unittest
from uuid import UUID, uuid4

from app.audit.integration import AccessAdministration
from app.audit.model import AuditAction, AuditOutcome
from app.audit.service import OwnerAuditService
from app.audit.store import AuditStore
from app.auth.boot_clock import BootInstant
from app.auth.live_access import BoundLiveAccess, authorize_live_access, live_view_validator
from app.auth.model import AccessValidationError, Permission
from app.auth.owner_operation import HumanOwnerAuthorizer, OwnerOperationContext
from app.auth.serving_gate import ServingGate
from app.auth.session_binding import SessionBindingKey
from app.auth.store import AccessStore, Requirement, StepUpRequired
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.media.live.sessions import LiveAccess
from app.presence.access import AccessDenied
from app.presence.models import Kind, Observation, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.e2e.harness import (
    MixedSourceTopology,
    NetworkGuard,
    SyntheticClock,
    skip_unless_full_coverage_required,
    storage_reservation,
)


LIVE, RECORDINGS = Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW
# A synthetic kernel boot id; CLOCK_BOOTTIME follows the harness monotonic clock.
SYNTHETIC_BOOT_ID = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
GENERIC_DENIAL = "access is unavailable"

# Human, admin and media paths a future dashboard could expose. None is mounted.
HUMAN_PATHS = (
    "/", "/health", "/version", "/login", "/enroll", "/api/auth/assert",
    "/api/auth/registration/options", "/api/auth/registration",
    "/api/auth/step-up/options", "/api/auth/step-up",
    "/api/live/" + str(UUID(int=101)), "/api/sources", "/api/timeline",
    "/api/recordings", "/api/recordings/" + str(UUID(int=7)),
    "/api/recordings/" + str(UUID(int=7)) + "/download",
    "/media/" + str(UUID(int=7)) + "/segment-0001.m4s",
    "/api/admin/principals", "/api/admin/pairing", "/api/admin/audit",
    "/api/admin/principals/" + str(UUID(int=11)) + "/invitation",
    "/api/admin/principals/" + str(UUID(int=11)) + "/permissions",
    "/api/admin/principals/" + str(UUID(int=11)) + "/revoke",
    "/api/admin/principals/" + str(UUID(int=11)) + "/credentials/" + str(UUID(int=12)) + "/revoke",
    "/api/diagnostics/export", "/api/agent/ingest",
)
METHODS = ("GET", "POST", "DELETE")


class Identity:
    """One caller: an opaque session token and the identity it claims."""

    def __init__(self, name, external_identity, token=None):
        self.name = name
        self.external_identity = external_identity
        # Generated per run; never a committed credential value.
        self.token = token if token is not None else secrets.token_bytes(32)
        self.principal = None
        self.session_id = None
        self.credential_id = None

    def headers(self):
        return [(b"cookie", b"serversentinel_session=" + self.token.hex().encode("ascii"))]


class OpenGate:
    """Synthetic always-open reservation gate (``epoch()``/``admit()``)."""

    def __init__(self):
        self.admitted = 0

    def epoch(self):
        return 0

    @contextmanager
    def admit(self, epoch):
        assert epoch == 0
        self.admitted += 1
        yield


class RecordingPermit:
    """Would allow everything; the closed surface must never call it."""

    def __init__(self):
        self.calls = 0

    async def require_system_access(self, request):
        self.calls += 1

    async def require_owner_access(self, request):
        self.calls += 1


class StoreBackedTimelineAccess:
    """Test adapter: the timeline gate delegates to the production grant check."""

    def __init__(self, store):
        self.store = store

    def require_owner(self, context):
        raise AccessDenied()

    def require_recordings(self, context):
        token, identity = context
        try:
            self.store.authorize(token, identity, RECORDINGS)
        except AccessValidationError:
            raise AccessDenied() from None


async def asgi(application, path, *, method="GET", headers=(), kind="http"):
    """Minimal in-process ASGI call; no socket or network client is used."""
    messages = []
    scope = {
        "type": kind, "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "http", "method": method, "path": path,
        "raw_path": path.encode("ascii"), "query_string": b"", "root_path": "",
        "headers": list(headers), "client": ("127.0.0.1", 40000),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        if kind == "websocket":
            return {"type": "websocket.connect"}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await application(scope, receive, send)
    return messages


class AccessMatrixScenarios(unittest.TestCase):
    def setUp(self):
        self.network = NetworkGuard().__enter__()
        self.addCleanup(self.network.__exit__)
        self.addCleanup(lambda: self.assertEqual([], self.network.attempts))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.database = Database(self.root / "main.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.audit = AuditStore(self.database, clock=self.clock.utcnow)
        # Owner-only mutations use the unaudited fixture mode; the audited
        # Owner boundary is covered by server/tests/test_access_pairing_audit.py.
        self.store = AccessStore(self.database, clock=self.clock.utcnow, audit=self.audit,
                                 unaudited_writes=True, session_binding=SessionBindingKey.generate(),
                                 boot_clock=self.boot_instant)
        self.gate = OpenGate()
        self.step_up_digests = {}
        self.identities = {
            "live_only": self.member("live_only", (LIVE,)),
            "recordings_only": self.member("recordings_only", (RECORDINGS,)),
            "both": self.member("both", (LIVE, RECORDINGS)),
            "revoked": self.member("revoked", (LIVE, RECORDINGS)),
        }
        self.store.revoke_principal(self.identities["revoked"].principal.id)
        self.identities["uninvited"] = Identity(
            "uninvited", "synthetic-uninvited@example.invalid")
        self.node_id, self.node_material = self.paired_capture_node()
        # The node's credential material presented as a human session token,
        # with the node identity as the claimed external identity.
        self.identities["agent_credential"] = Identity(
            "agent_credential", "capture-node-" + self.node_id.hex, token=self.node_material)
        # A caller forging the "both" member's Tailscale login with no session
        # of its own: the proxy identity header alone must never authorize.
        self.identities["spoofed_header"] = Identity(
            "spoofed_header", self.identities["both"].external_identity)

    def boot_instant(self):
        return BootInstant(SYNTHETIC_BOOT_ID, 10_000_000 + int(self.clock.monotonic() * 1_000_000))

    def member(self, name, permissions):
        identity = Identity(name, f"synthetic-{name.replace('_', '-')}@example.invalid")
        principal = self.store.invite("Synthetic " + name, permissions)
        secret = secrets.token_bytes(32)
        self.store.issue_enrollment(principal.id, secret, self.clock.utcnow() + timedelta(minutes=10))
        credential_id = secrets.token_bytes(32)
        identity.credential_id = credential_id
        self.store.enroll_credential(secret, identity.external_identity, credential_id,
                                     b"synthetic-public-key-" + name.encode("ascii"), -7, 0)
        identity.session_id = self.store.establish_session(
            principal.id, credential_id, identity.token, proxy_identity=identity.external_identity)
        identity.principal = self.store.authorize(identity.token, identity.external_identity,
                                                  permissions[0])
        return identity

    def paired_capture_node(self):
        owner = type("Owner", (), {"require_owner": lambda _self, context: None})()
        ledger = PairingLedger(self.database, HmacCodeVerifier(secrets.token_bytes(32)),
                               audit=self.audit, clock=self.clock.monotonic)
        node = self.topology.sources[1].node_id
        key_digest, serial_digest = secrets.token_hex(32), secrets.token_hex(32)
        approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key_digest)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                              public_key_digest=key_digest, code=code.value)
        ledger.activate(claim, credential_serial_digest=serial_digest)
        self.assertTrue(ledger.admits(node_id=node, public_key_digest=key_digest,
                                      credential_serial_digest=serial_digest))
        return node, bytes.fromhex(serial_digest)

    def audit_rows(self):
        with closing(self.database.connect()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM security_admin_audit_records").fetchone()[0]

    def outcome(self, identity, permission):
        try:
            self.store.authorize(identity.token, identity.external_identity, permission)
        except AccessValidationError as error:
            self.assertEqual(GENERIC_DENIAL, str(error))
            return False
        return True

    def test_permission_matrix_is_enforced_server_side_with_one_generic_denial(self):
        expected = {
            "uninvited": (False, False), "live_only": (True, False),
            "recordings_only": (False, True), "both": (True, True),
            "revoked": (False, False), "agent_credential": (False, False),
            "spoofed_header": (False, False),
        }
        before = self.audit_rows()
        for name, (live, recordings) in expected.items():
            identity = self.identities[name]
            with self.subTest(identity=name):
                self.assertEqual((live, recordings),
                                 (self.outcome(identity, LIVE), self.outcome(identity, RECORDINGS)))
        # Denied attempts are unauthenticated input: they never grow the audit table.
        self.assertEqual(before, self.audit_rows())

    def test_valid_session_presented_under_another_identity_header_is_denied(self):
        live_only, both = self.identities["live_only"], self.identities["both"]
        # A real session whose proxy identity header is swapped for another member.
        for permission in (LIVE, RECORDINGS):
            with self.subTest(permission=permission.value), \
                    self.assertRaisesRegex(AccessValidationError, f"^{GENERIC_DENIAL}$"):
                self.store.authorize(live_only.token, both.external_identity, permission)
        # The genuine pairing still works: the swap did not revoke anything.
        self.assertTrue(self.outcome(live_only, LIVE))

    def test_live_view_is_bound_to_live_grant_session_and_revision(self):
        validator = live_view_validator(self.database, clock=self.clock.utcnow)
        source = self.topology.sources[0].source_id
        bound = {}
        for name in ("live_only", "both"):
            identity = self.identities[name]
            bound[name] = authorize_live_access(self.store, identity.token, identity.external_identity,
                                                admit=self.admit)
            self.assertTrue(validator(bound[name], source), name)
        for name in ("recordings_only", "revoked", "uninvited", "agent_credential", "spoofed_header"):
            identity = self.identities[name]
            with self.subTest(identity=name), \
                    self.assertRaisesRegex(AccessValidationError, f"^{GENERIC_DENIAL}$"):
                authorize_live_access(self.store, identity.token, identity.external_identity,
                                      admit=self.admit)
        recordings_only = self.identities["recordings_only"]
        live_only = self.identities["live_only"]
        copied = (
            # A live session identifier copied onto another principal.
            BoundLiveAccess(recordings_only.principal.id,
                            recordings_only.principal.authorization_revision,
                            bound["live_only"].access_session_id),
            # A principal with a fabricated session identifier.
            BoundLiveAccess(live_only.principal.id, bound["live_only"].authorization_revision, uuid4()),
            # An access value that is not bound to any human session.
            LiveAccess(live_only.principal.id, bound["live_only"].authorization_revision),
        )
        for access in copied:
            self.assertFalse(validator(access, source))
        # Removing live:view (keeping recordings:view) ends the open live grant.
        self.store.set_permissions(self.identities["both"].principal.id, (RECORDINGS,))
        self.assertFalse(validator(bound["both"], source))
        self.assertTrue(validator(bound["live_only"], source))
        self.store.revoke_principal(live_only.principal.id)
        self.assertFalse(validator(bound["live_only"], source))

    def admit(self):
        return self.gate.admit(self.gate.epoch())

    def request(self, identity, requirement, csrf=None):
        try:
            return self.store.authorize_request(identity.token, identity.external_identity, requirement,
                                                admit=self.admit, csrf=csrf)
        except AccessValidationError as error:
            self.assertEqual(GENERIC_DENIAL, str(error))
            return None

    def test_gated_requirements_follow_the_same_matrix(self):
        expected = {
            "uninvited": (False, False, False), "live_only": (True, True, False),
            "recordings_only": (True, False, True), "both": (True, True, True),
            "revoked": (False, False, False), "agent_credential": (False, False, False),
            "spoofed_header": (False, False, False),
        }
        for name, outcome in expected.items():
            identity = self.identities[name]
            with self.subTest(identity=name):
                self.assertEqual(outcome, tuple(
                    self.request(identity, requirement) is not None
                    for requirement in (Requirement.SESSION, Requirement.LIVE, Requirement.RECORDINGS)))
                # No member is the Owner: both Owner requirements are the generic denial.
                for requirement in (Requirement.OWNER_READ, Requirement.OWNER_OP):
                    self.assertIsNone(self.request(identity, requirement))

    def test_csrf_token_is_per_session_and_never_crosses_members(self):
        tokens = {name: self.store.csrf_token(self.identities[name].session_id)
                  for name in ("live_only", "recordings_only", "both")}
        self.assertEqual(len(set(tokens.values())), 3)
        for name, token in tokens.items():
            identity = self.identities[name]
            with self.subTest(identity=name):
                self.assertIsNotNone(self.request(identity, Requirement.SESSION, csrf=token))
                for other, foreign in tokens.items():
                    if other != name:
                        self.assertIsNone(self.request(identity, Requirement.SESSION, csrf=foreign))
                for malformed in ("", "A" * 43, token + "A", token[:-1]):
                    self.assertIsNone(self.request(identity, Requirement.SESSION, csrf=malformed))
        # A CSRF token never stands in for a session.
        spoofed = self.identities["spoofed_header"]
        self.assertIsNone(self.request(spoofed, Requirement.SESSION, csrf=tokens["both"]))

    def test_sign_out_ends_only_the_callers_session_with_an_audit_record(self):
        both, live_only = self.identities["both"], self.identities["live_only"]
        before = self.audit_rows()
        session = self.request(both, Requirement.SESSION, csrf=self.store.csrf_token(both.session_id))
        self.store.sign_out(session, admit=self.admit)
        self.assertEqual(before + 1, self.audit_rows())
        (record,) = [item for item in self.audit.list_records() if item.action.value == "sign_out_principal"]
        self.assertEqual((record.actor_category.value, record.target_logical_id, record.outcome.value),
                         ("invited_user", both.principal.id, "succeeded"))
        # The old cookie, presented again ("Back" or a copied value), is refused for every grant.
        for requirement in (Requirement.SESSION, Requirement.LIVE, Requirement.RECORDINGS):
            self.assertIsNone(self.request(both, requirement))
        for permission in (LIVE, RECORDINGS):
            self.assertFalse(self.outcome(both, permission))
        with self.assertRaises(AccessValidationError):
            self.store.sign_out(session, admit=self.admit)
        self.assertEqual(before + 1, self.audit_rows())
        # Another member behind the same shared login keeps working.
        self.assertTrue(self.outcome(live_only, LIVE))

    def owner(self):
        """The Owner, signed in through the store's assertion commit (the
        ceremony's signature verification is covered with software
        authenticators in ``server/tests/test_human_step_up.py``)."""
        identity = Identity("owner", "synthetic-owner@example.invalid")
        principal = self.store.bootstrap_owner("Synthetic owner")
        secret = secrets.token_bytes(32)
        self.store.issue_enrollment(principal.id, secret, self.clock.utcnow() + timedelta(minutes=10))
        identity.credential_id = secrets.token_bytes(32)
        self.store.enroll_credential(secret, identity.external_identity, identity.credential_id,
                                     b"synthetic-public-key-owner", -7, 0)
        identity.session_id = self.store.accept_assertion(
            identity.credential_id, principal.id, identity.external_identity,
            expected_sign_count=0, sign_count=0, backup_state=False, token=identity.token)
        identity.principal = principal
        return identity

    def step_up_challenge(self, identity):
        digest = secrets.token_bytes(32)
        try:
            self.store.begin_step_up(identity.token, identity.external_identity, digest,
                                     lifetime=timedelta(minutes=5))
        except AccessValidationError as error:
            self.assertEqual(GENERIC_DENIAL, str(error))
            return False
        self.step_up_digests[identity.token] = digest
        return True

    def step_up_commit(self, session_holder, credential_id, principal_id):
        # The holder's pending step-up challenge, or one that was never issued.
        digest = self.step_up_digests.get(session_holder.token, secrets.token_bytes(32))
        try:
            self.store.accept_assertion(credential_id, principal_id, session_holder.external_identity,
                                        expected_sign_count=0, sign_count=0, backup_state=False,
                                        step_up_session_id=session_holder.session_id,
                                        step_up_challenge=digest)
        except AccessValidationError as error:
            self.assertEqual(GENERIC_DENIAL, str(error))
            return False
        return True

    def assert_stale(self, identity):
        with self.assertRaises(StepUpRequired):
            self.store.authorize_request(identity.token, identity.external_identity, Requirement.OWNER_OP,
                                         admit=self.admit)

    def step_up_audits(self):
        return [item for item in self.audit.list_records() if item.action.value == "verify_principal_step_up"]

    def test_step_up_rows(self):
        owner = self.owner()
        self.assertIsNotNone(self.request(owner, Requirement.OWNER_OP))
        self.clock.advance(5 * 60)
        self.assert_stale(owner)
        # A stale Owner still passes OWNER_READ, the step-up routes' requirement.
        self.assertIsNotNone(self.request(owner, Requirement.OWNER_READ))
        with closing(self.database.connect()) as connection:
            challenges = connection.execute("SELECT count(*) FROM access_webauthn_challenges").fetchone()[0]
        for name, identity in self.identities.items():
            with self.subTest(identity=name):
                # Never step_up_required, never a step-up challenge.
                self.assertIsNone(self.request(identity, Requirement.OWNER_OP))
                self.assertFalse(self.step_up_challenge(identity))
        # The Owner's stale cookie under another member's login is the generic denial.
        both = self.identities["both"]
        self.assertIsNone(self.request(Identity("borrowed", both.external_identity, owner.token),
                                       Requirement.OWNER_OP))
        self.assertFalse(self.step_up_challenge(Identity("borrowed", both.external_identity, owner.token)))
        with closing(self.database.connect()) as connection:
            self.assertEqual(challenges, connection.execute(
                "SELECT count(*) FROM access_webauthn_challenges").fetchone()[0])
        # Another person's credential cannot refresh the stale Owner session,
        # under either principal, even with the Owner's pending challenge;
        # nor can a member refresh their own session.
        self.assertTrue(self.step_up_challenge(owner))
        self.assertFalse(self.step_up_commit(owner, both.credential_id, both.principal.id))
        self.assertFalse(self.step_up_commit(owner, both.credential_id, owner.principal.id))
        self.assertFalse(self.step_up_commit(both, both.credential_id, both.principal.id))
        self.assert_stale(owner)
        self.assertEqual([], self.step_up_audits())
        # The Owner's own credential refreshes it with that same challenge (the
        # refused commits rolled back without spending it), audited with the
        # logical UUID only; the challenge is spent by this commit alone.
        self.assertTrue(self.step_up_commit(owner, owner.credential_id, owner.principal.id))
        self.assertFalse(self.step_up_commit(owner, owner.credential_id, owner.principal.id))
        self.assertIsNotNone(self.request(owner, Requirement.OWNER_OP))
        (record,) = self.step_up_audits()
        self.assertEqual((record.actor_category.value, record.target_logical_id, record.outcome.value),
                         ("owner", owner.principal.id, "succeeded"))
        # Two minutes pass while the wall clock is stepped back by one: stale.
        self.clock.advance(120)
        self.clock.shift_wall(-60)
        self.assert_stale(owner)
        # Members are unaffected by any of it.
        self.assertTrue(self.outcome(self.identities["live_only"], LIVE))

    def redemption(self, secret, identity):
        """Both redemption steps at the store (the ceremony's signature
        verification is covered with software authenticators in
        ``server/tests/test_invitation_redemption.py``)."""
        try:
            self.store.begin_registration(secret, identity, secrets.token_bytes(32),
                                          at=self.clock.utcnow(), lifetime=timedelta(minutes=5))
            return self.store.enroll_credential(secret, identity, secrets.token_bytes(32),
                                                b"synthetic-public-key", -7, 0)
        except AccessValidationError as error:
            self.assertEqual(GENERIC_DENIAL, str(error))
            return None

    def test_invitation_redemption_rows(self):
        from app.auth.invitation_code import (
            INVITATION_LIFETIME, InvalidInvitationCode, new_invitation_code, parse_invitation_code,
        )
        before = self.audit_rows()
        # Every matrix identity without a valid code of its own: refused, nothing written.
        for name, identity in self.identities.items():
            with self.subTest(identity=name):
                unknown = parse_invitation_code(new_invitation_code()[1])
                self.assertIsNone(self.redemption(unknown, identity.external_identity))
        agent = self.identities["agent_credential"]
        self.assertIsNone(self.redemption(agent.token, agent.external_identity))
        # A malformed code never decodes, so it never reaches the store.
        for value in ("", "0000-0000", new_invitation_code()[1].lower()):
            with self.assertRaises(InvalidInvitationCode):
                parse_invitation_code(value)
        self.assertEqual(before, self.audit_rows())

        def issued(principal, lifetime=INVITATION_LIFETIME):
            secret, code = new_invitation_code()
            self.store.issue_enrollment(principal.id, secret, self.clock.utcnow() + lifetime)
            return parse_invitation_code(code)

        viewer = self.identities["live_only"].external_identity
        # Revoked principal, expired code and an advanced generation are refused.
        revoked = self.store.invite("Synthetic revoked invitee", (LIVE,))
        revoked_secret = issued(revoked)
        self.store.revoke_principal(revoked.id)
        expired = issued(self.store.invite("Synthetic late invitee", (LIVE,)), timedelta(seconds=1))
        self.clock.advance(2)
        invitee = self.store.invite("Synthetic invitee", (RECORDINGS,))
        stale = issued(invitee)
        with self.store.audit.transaction(write=True) as connection:
            self.store.invalidate_all_sessions_on(connection, at=self.clock.utcnow())
        for secret in (revoked_secret, expired, stale):
            self.assertIsNone(self.redemption(secret, viewer))
        # A fresh code redeems exactly once, under the shared login, and grants
        # nothing until the person signs in with the registered credential.
        fresh = issued(invitee)
        credential = self.redemption(fresh, viewer)
        self.assertIsNotNone(credential)
        self.assertEqual(invitee.id, credential.principal_id)
        self.assertIsNone(self.redemption(fresh, viewer))
        self.assertIsNone(self.redemption(fresh, self.identities["both"].external_identity))
        self.assertEqual(before + 1, self.audit_rows())
        with closing(self.database.connect()) as connection:
            self.assertEqual(0, connection.execute(
                "SELECT count(*) FROM access_sessions WHERE principal_id=?", (str(invitee.id),)).fetchone()[0])
        for permission in (LIVE, RECORDINGS):
            with self.assertRaises(AccessValidationError):
                self.store.authorize(fresh, viewer, permission)

    def administration(self):
        """The Owner administration over the synthetic gate (epoch 0)."""
        gate = ServingGate(self.gate, stopped=lambda: False)
        return AccessAdministration(OwnerAuditService(self.audit, HumanOwnerAuthorizer()), self.store,
                                    session_gate=gate)

    def admin_state(self):
        with closing(self.database.connect()) as connection:
            return [tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                    for table in ("access_principals", "access_principal_permissions", "access_invitations",
                                  "access_credentials")]

    def test_owner_administration_rows(self):
        from app.auth.invitation_code import parse_invitation_code
        administration = self.administration()
        both = self.identities["both"]
        # No matrix identity authorizes OWNER_OP, so the surface never builds
        # an administration context for one; a context around a non-Owner
        # session (which no surface builds) is denied and changes nothing.
        before = self.admin_state()
        for name, identity in self.identities.items():
            with self.subTest(identity=name):
                self.assertIsNone(self.request(identity, Requirement.OWNER_OP))
                self.assertIsNone(self.request(identity, Requirement.OWNER_READ))
        view = self.request(both, Requirement.SESSION)
        for operation in (
                lambda context: administration.invite(context, "Synthetic x", (LIVE,), epoch=0),
                lambda context: administration.change_permission(context, both.principal.id, RECORDINGS,
                                                                 False, epoch=0),
                lambda context: administration.revoke_principal(context, both.principal.id, epoch=0),
                lambda context: administration.reissue_invitation(context, both.principal.id, epoch=0)):
            with self.assertRaises(Exception):
                operation(OwnerOperationContext(view, 0))
            for raw in (both.token, both.external_identity, both.principal, None):
                with self.assertRaises(Exception):
                    operation(raw)
        self.assertEqual(before, self.admin_state())
        self.assertTrue(self.outcome(both, RECORDINGS))
        # The Owner, fresh: one invitation with live:view only.
        owner = self.owner()
        context = OwnerOperationContext(self.request(owner, Requirement.OWNER_OP), 0)
        principal_id, code, _ = administration.invite(context, "Synthetic invitee", (LIVE,), epoch=0)
        invitee = Identity("invitee", both.external_identity)  # the shared login
        credential = self.redemption(parse_invitation_code(code), invitee.external_identity)
        self.assertEqual(principal_id, credential.principal_id)
        invitee.session_id = self.store.establish_session(principal_id, credential.credential_id, invitee.token,
                                                          proxy_identity=invitee.external_identity)
        self.assertEqual((True, False), (self.outcome(invitee, LIVE), self.outcome(invitee, RECORDINGS)))
        # A no-op change keeps the session; withdrawing live:view ends it.
        self.assertFalse(administration.change_permission(context, principal_id, RECORDINGS, False, epoch=0))
        self.assertTrue(self.outcome(invitee, LIVE))
        self.assertTrue(administration.change_permission(context, principal_id, LIVE, False, epoch=0))
        self.assertIsNone(self.request(invitee, Requirement.LIVE))
        self.assertIsNone(self.request(invitee, Requirement.SESSION))
        # A second credential; revoking one ends only its sessions.
        self.assertTrue(administration.change_permission(context, principal_id, RECORDINGS, True, epoch=0))
        code, _ = administration.reissue_invitation(context, principal_id, epoch=0)
        second = self.redemption(parse_invitation_code(code), invitee.external_identity)
        first = Identity("first", invitee.external_identity)
        first.session_id = self.store.establish_session(principal_id, credential.credential_id, first.token,
                                                        proxy_identity=first.external_identity)
        other = Identity("second", invitee.external_identity)
        self.store.establish_session(principal_id, second.credential_id, other.token,
                                     proxy_identity=other.external_identity)
        entry = next(item for item in self.store.admin_inventory() if item["id"] == str(principal_id))
        with closing(self.database.connect()) as connection:
            handle = connection.execute("SELECT handle FROM access_credentials WHERE credential_id=?",
                                        (credential.credential_id,)).fetchone()[0]
        self.assertIn(handle, [item["handle"] for item in entry["credentials"]])
        administration.revoke_credential(context, principal_id, handle, epoch=0)
        self.assertFalse(self.outcome(first, RECORDINGS))
        self.assertTrue(self.outcome(other, RECORDINGS))
        # The Owner is never a target; revoking the person ends everything.
        state = self.admin_state()
        with self.assertRaises(AccessValidationError):
            administration.revoke_principal(context, owner.principal.id, epoch=0)
        self.assertEqual(state, self.admin_state())
        administration.revoke_principal(context, principal_id, epoch=0)
        self.assertFalse(self.outcome(other, RECORDINGS))
        # The inventory never returns a proxy identity (D14), only logical UUIDs reach the audit.
        text = repr(self.store.admin_inventory())
        for identity in self.identities.values():
            self.assertNotIn(identity.external_identity, text)
        audited = [record for record in self.audit.list_records(limit=1000)
                   if record.action in (AuditAction.INVITE_PRINCIPAL, AuditAction.REVOKE_PRINCIPAL)]
        self.assertIn((AuditAction.REVOKE_PRINCIPAL, AuditOutcome.SUCCEEDED, principal_id),
                      [(record.action, record.outcome, record.target_logical_id) for record in audited])
        self.assertNotIn(code, repr(self.audit.list_records(limit=1000)))
        # Members are unaffected by any of it.
        self.assertTrue(self.outcome(self.identities["live_only"], LIVE))

    def test_historical_timeline_requires_recordings_view_only(self):
        presence = PresenceService(
            self.database, access=StoreBackedTimelineAccess(self.store),
            reservation=storage_reservation, detection=lambda: True,
            storage_status=lambda: True,
        )
        source = self.topology.sources[1]
        now = self.clock.utcnow()
        recorded = presence.record(Observation(
            Kind.CAMERA_HEALTH, now, now, source_id=source.source_id, node_id=source.node_id,
            quality=Quality.SUFFICIENT, clock_trusted=True))
        window = dict(received_from=now - timedelta(seconds=1), received_to=now + timedelta(seconds=1))
        for name in ("recordings_only", "both"):
            identity = self.identities[name]
            history = presence.history((identity.token, identity.external_identity), **window)
            self.assertEqual([str(recorded.identifier)], [item["id"] for item in history["items"]])
            self.assertEqual("not_inferred", history["causality"])
        for name in ("live_only", "uninvited", "revoked", "agent_credential", "spoofed_header"):
            identity = self.identities[name]
            with self.subTest(identity=name), self.assertRaises(AccessDenied) as denied:
                presence.history((identity.token, identity.external_identity), **window)
            self.assertEqual("Not Found", str(denied.exception))

    def test_agent_credential_cannot_become_a_human_principal(self):
        agent = self.identities["agent_credential"]
        # Node credential material is not a human WebAuthn credential or principal.
        with self.assertRaises(AccessValidationError):
            self.store.establish_session(self.node_id, agent.token, secrets.token_bytes(32),
                                         proxy_identity=agent.external_identity)
        with closing(self.database.connect()) as connection:
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM access_principals WHERE id=?", (str(self.node_id),)).fetchone())
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM access_credentials WHERE credential_id=?", (agent.token,)).fetchone())
        for permission in (LIVE, RECORDINGS):
            self.assertFalse(self.outcome(agent, permission))

    def test_closed_human_surface_answers_every_identity_identically(self):
        try:
            from app.main import create_app
            from app.settings import Settings
        except ModuleNotFoundError:
            skip_unless_full_coverage_required(
                "FastAPI from server/requirements.lock is required for the composed app")
        data = self.root / "data"
        data.mkdir(mode=0o700)
        permit = RecordingPermit()
        application = create_app(Settings(data), database=self.database, human_authorizer=permit)
        node_header = self.identities["agent_credential"].token.hex().encode("ascii")
        spoofed = self.identities["spoofed_header"].external_identity.encode("ascii")
        header_sets = {
            name: identity.headers() for name, identity in self.identities.items()
        }
        header_sets["agent_credential"] += [
            (b"authorization", b"Bearer " + node_header),
            (b"x-ssl-client-verify", b"SUCCESS"),
            (b"x-client-cert-serial", node_header),
        ]
        header_sets["spoofed_header"] += [
            (b"tailscale-user-login", spoofed), (b"tailscale-user-name", b"Synthetic Both"),
            (b"x-forwarded-user", spoofed), (b"x-remote-user", spoofed),
            (b"x-forwarded-for", b"100.64.0.1"),
        ]
        header_sets["anonymous"] = []

        async def scenario():
            baseline = await asgi(application, "/", headers=())
            websocket_baseline = await asgi(application, "/api/live/stream", kind="websocket")
            for name, headers in header_sets.items():
                for path in HUMAN_PATHS:
                    for method in METHODS:
                        result = await asgi(application, path, method=method, headers=headers)
                        self.assertEqual(baseline, result, (name, path, method))
                result = await asgi(application, "/api/live/stream", headers=headers, kind="websocket")
                self.assertEqual(websocket_baseline, result, name)
            return baseline, websocket_baseline

        baseline, websocket_baseline = asyncio.run(scenario())
        self.assertEqual(404, baseline[0]["status"])
        self.assertEqual(b'{"detail":"Not Found"}', baseline[1]["body"])
        self.assertIn((b"cache-control", b"no-store"), baseline[0]["headers"])
        self.assertEqual([{"type": "websocket.close", "code": 1008}], websocket_baseline)
        # Nothing, including the injected permissive authorizer, was consulted.
        self.assertEqual(0, permit.calls)
        self.assertFalse(application.routes)


if __name__ == "__main__":
    unittest.main()
