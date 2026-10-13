"""Issue #10 phase 2 S4a: Owner access administration (store and administration).

Synthetic only: software authenticators, synthetic ``/proc/net`` rows, a
temporary SQLite database and the in-process ASGI driver of
``test_human_surface``. Every identity, name and code is an invented value.
Mock only: no browser, proxy, Tailscale or real authenticator is involved.

Owner decisions S4-1 .. S4-8 (Issue #10, 2026-10-13), Issue #232 item 1,
Issue #235 item 3 and Issue #238 item 1.
"""

import base64
from contextlib import closing, nullcontext
from datetime import timedelta
import json
import logging
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from app.audit import AuditStore, OwnerAuditService, OwnerAuthorizationError
from app.audit.integration import AccessAdministration
from app.audit.model import ActorCategory, AuditAction, AuditOutcome
from app.auth import human_surface as surface_module
from app.auth.bootstrap_cli import recover_owner
from app.auth.human_surface import ROUTES, HumanAccess, HumanAccessConfiguration, Route
from app.auth.invitation_code import new_invitation_code, parse_invitation_code
from app.auth.model import AccessValidationError, Permission, PrincipalRole
from app.auth.owner_operation import HumanOwnerAuthorizer, OwnerOperationContext
from app.auth.passkeys import PasskeyCeremonies
from app.auth.reservation import HumanAccessClosed
from app.auth.reservation_store import ReservationSessionRevocation
from app.auth.serving_gate import ServingGate
from app.auth.session_binding import SessionBindingKey
from app.auth.store import (
    MAX_PRINCIPALS, MAX_REDEMPTION_ATTEMPTS, AccessLimitReached, AccessStore, Requirement, SessionView, StepUpRequired,
)
from app.auth.webauthn import RelyingParty
from app.main import create_app
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.admin_fakes import OWNER_IDENTITY, open_serving_gate, owner_context, owner_session
from tests.test_hostname_reservation import checker
from tests.test_human_gated_authorization import GENERIC, STEP_UP, GatedFixture
from tests.test_human_surface import HOST, ORIGIN, VIEWER, call, status
from tests.test_invitation_redemption import BootClock
from tests.test_webauthn_ceremonies import Clock, waiting
from tests.webauthn_fakes import SyntheticAuthenticator


OWNER_OPERATION_PATH = "/api/synthetic/owner-operation"
PRINCIPAL_KEYS = {"id", "display_name", "role", "status", "created_at", "revoked_at", "permissions",
                  "invitation", "credentials"}
INVITATION_KEYS = {"pending", "expires_at"}
CREDENTIAL_KEYS = {"handle", "label", "status", "inconsistency_reason", "backup_eligible", "backup_state",
                   "created_at", "last_used_at", "revoked_at"}


class AdministrationFixture(GatedFixture):
    """A signed-in, fresh Owner whose OWNER_OP context comes from the surface."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.admin = self.access.administration
        self.owner, self.owner_key, _ = self.enroll(owner=True)
        self.owner_cookie = await self.sign_in(self.owner_key)
        self.owner_csrf = await self.csrf(self.owner_cookie)

    async def owner_operation(self, cookie=None, csrf=None):
        """Run a synthetic OWNER_OP route; ``(context or None, response)``."""
        box = {}
        route = Route("POST", re.compile(re.escape(OWNER_OPERATION_PATH)), Requirement.OWNER_OP,
                      "_synthetic_owner_operation", mutating=True, csrf=True, body_limit=2)
        surface = self.surface

        async def handler(request):
            box["context"] = await surface._owner_operation(request)
            await request.send({"type": "http.response.start", "status": 204, "headers": []})
            await request.send({"type": "http.response.body", "body": b""})

        surface._synthetic_owner_operation = handler
        try:
            with patch.object(surface_module, "ROUTES", ROUTES + (route,)):
                result = await call(surface, "POST", OWNER_OPERATION_PATH,
                                    cookie=cookie or self.owner_cookie,
                                    headers=[(b"x-csrf-token", (csrf or self.owner_csrf).encode())],
                                    content_type=None)
        finally:
            del surface._synthetic_owner_operation
        return box.get("context"), result

    async def context(self):
        context, result = await self.owner_operation()
        self.assertEqual(status(result), 204)
        self.assertIsInstance(context, OwnerOperationContext)
        return context

    def access_state(self):
        with closing(self.database.connect()) as connection:
            return [tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                    for table in ("access_principals", "access_principal_permissions", "access_invitations",
                                  "access_credentials")]

    def outcomes(self, action):
        return [record.outcome for record in self.audit.list_records(limit=1000) if record.action is action]

    def entry(self, principal_id):
        return next(item for item in self.store.admin_inventory() if item["id"] == str(principal_id))

    def redeem(self, code, identity=VIEWER):
        secret = parse_invitation_code(code)
        authenticator = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(secret, identity)
        self.ceremonies.finish_registration(secret, identity,
                                            authenticator.register(creation, origin=ORIGIN, rp_id=HOST))
        return authenticator


class WiringTests(AdministrationFixture):
    async def test_human_access_builds_its_administration_on_its_own_gate(self):
        # Issue #232 item 1 / S4a item 12.
        self.assertIsInstance(self.admin, AccessAdministration)
        self.assertIs(self.admin.session_gate, self.access.gate)
        self.assertIsInstance(self.admin.session_gate, ServingGate)
        self.assertIsInstance(self.admin.service.authorizer, HumanOwnerAuthorizer)
        self.assertIs(self.admin.service.store, self.store.audit)
        self.assertIs(self.admin.access, self.store)

    async def test_the_surface_builds_the_context_only_after_a_fresh_owner_op(self):
        context = await self.context()
        self.assertEqual(context.session.role, PrincipalRole.OWNER)
        self.assertEqual(context.session.principal_id, self.owner.id)
        self.assertEqual(context.epoch, self.access.epoch())
        self.assertNotIn(context.session.credential_id.hex(), repr(context))
        # A non-Owner gets the generic denial and no context.
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        viewer = await self.sign_in(viewer_key)
        viewer_context, result = await self.owner_operation(viewer, await self.csrf(viewer))
        self.assertIsNone(viewer_context)
        self.assertEqual(result, GENERIC)

    async def test_step_up_required_neither_builds_a_context_nor_extends_the_session(self):
        # Owner decision S4-2 (#238 item 1).
        self.ceremony_clock.advance(minutes=6)
        rows = self.session_rows()
        context, result = await self.owner_operation()
        self.assertIsNone(context)
        self.assertEqual(result, STEP_UP)
        self.assertEqual(self.session_rows(), rows)


class StoreStepUpIdleTests(AdministrationFixture):
    """#238 item 1: ``authorize_request`` / ``authorize_owner`` raising
    ``StepUpRequired`` commit no idle touch; a fresh one does."""

    async def test_stale_owner_op_and_authorize_owner_do_not_touch_idle(self):
        token = self.token(self.owner_cookie)
        self.ceremony_clock.advance(minutes=6)
        rows = self.session_rows()
        with self.assertRaises(StepUpRequired):
            self.store.authorize_request(token, VIEWER, Requirement.OWNER_OP, admit=self.gated())
        self.assertEqual(self.session_rows(), rows)
        with self.assertRaises(StepUpRequired):
            self.store.authorize_owner(token, VIEWER, admit=self.gated())
        self.assertEqual(self.session_rows(), rows)
        # The same stale session is served (and touched) on OWNER_READ.
        self.store.authorize_request(token, VIEWER, Requirement.OWNER_READ, admit=self.gated())
        self.assertNotEqual(self.session_rows(), rows)

    async def test_fresh_owner_op_still_touches_idle(self):
        token = self.token(self.owner_cookie)
        self.ceremony_clock.advance(minutes=1)
        rows = self.session_rows()
        self.store.authorize_request(token, VIEWER, Requirement.OWNER_OP, admit=self.gated())
        self.assertNotEqual(self.session_rows(), rows)


class InviteTests(AdministrationFixture):
    async def test_invite_commits_principal_grants_and_one_code_with_two_records(self):
        context = await self.context()
        principal_id, code, expires_at = self.admin.invite(
            context, "Synthetic invitee", (Permission.RECORDINGS_VIEW,), epoch=context.epoch)
        self.assertIsInstance(principal_id, UUID)
        self.assertEqual(len(parse_invitation_code(code)), 20)
        self.assertEqual(expires_at, self.ceremony_clock() + timedelta(hours=24))
        entry = self.entry(principal_id)
        self.assertEqual((entry["role"], entry["status"], entry["permissions"]),
                         ("invited_user", "invited", ["recordings:view"]))
        self.assertEqual(entry["invitation"], {"pending": True, "expires_at": expires_at.isoformat()})
        # Both records commit in the invitation's transaction (same time, so
        # compared as a set).
        records = sorted((record.action, record.outcome, record.target_logical_id, record.actor_category)
                         for record in self.audit.list_records(limit=1000)
                         if record.target_logical_id == principal_id)
        self.assertEqual(records, [
            (AuditAction.INVITE_PRINCIPAL, AuditOutcome.SUCCEEDED, principal_id, ActorCategory.OWNER),
            (AuditAction.ISSUE_PRINCIPAL_INVITATION, AuditOutcome.SUCCEEDED, principal_id, ActorCategory.OWNER),
        ])
        # The invitee redeems the code through the ordinary ceremony.
        self.redeem(code)
        self.assertEqual(self.entry(principal_id)["status"], "active")
        self.assertEqual(self.entry(principal_id)["invitation"], {"pending": False, "expires_at": None})

    async def test_a_failure_in_the_transaction_leaves_no_principal_without_its_code(self):
        context = await self.context()
        before = self.access_state()
        with patch.object(self.store, "issue_enrollment_on", side_effect=AccessValidationError("synthetic")):
            with self.assertRaises(AccessValidationError):
                self.admin.invite(context, "Synthetic invitee", (Permission.LIVE_VIEW,), epoch=context.epoch)
        self.assertEqual(self.access_state(), before)
        self.assertEqual(self.outcomes(AuditAction.INVITE_PRINCIPAL), [AuditOutcome.FAILED])
        self.assertEqual(self.outcomes(AuditAction.ISSUE_PRINCIPAL_INVITATION), [])

    async def test_principal_cap_refuses_the_65th_live_principal(self):
        # Owner decision S4-8: at most 64 principals that are not revoked
        # (the Owner included); a revoked one frees a place.
        context = await self.context()
        created = [self.admin.invite(context, f"Synthetic {index}", (), epoch=context.epoch)[0]
                   for index in range(MAX_PRINCIPALS - 1)]
        self.assertEqual(self.count("SELECT count(*) FROM access_principals WHERE status<>'revoked'"),
                         MAX_PRINCIPALS)
        before = self.access_state()
        with self.assertRaises(AccessLimitReached):
            self.admin.invite(context, "Synthetic over the cap", (), epoch=context.epoch)
        self.assertEqual(self.access_state(), before)
        self.assertEqual(self.outcomes(AuditAction.INVITE_PRINCIPAL).count(AuditOutcome.FAILED), 1)
        self.admin.revoke_principal(context, created[0], epoch=context.epoch)
        self.admin.invite(context, "Synthetic replacement", (), epoch=context.epoch)


class InvitationExpiryTests(unittest.TestCase):
    """PR #234 rule and #235 item 3: the expiry is the in-transaction time
    plus the deployment's lifetime, for 1 h, 24 h and 168 h."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.database = Database(self.temporary / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = Clock()

    def administration(self, lifetime):
        audit = AuditStore(self.database, clock=self.clock)
        store = AccessStore(self.database, clock=self.clock, audit=audit, invitation_lifetime=lifetime,
                            session_binding=SessionBindingKey.generate())
        admin = AccessAdministration(OwnerAuditService(audit, HumanOwnerAuthorizer()), store,
                                     session_gate=open_serving_gate())
        return store, audit, admin

    def test_expiry_is_read_after_the_gate_admission_and_lock_waits(self):
        for hours in (1, 24, 168):
            with self.subTest(hours=hours):
                store, audit, admin = self.administration(timedelta(hours=hours))
                context = owner_context(store)
                with waiting(audit, "transaction", lambda: self.clock.advance(minutes=1)):
                    principal_id, code, expires_at = admin.invite(context, f"Synthetic {hours}", (), epoch=0)
                self.assertEqual(expires_at, self.clock() + timedelta(hours=hours))
                with closing(self.database.connect()) as connection:
                    issued, expires = connection.execute(
                        "SELECT issued_at_us, expires_at_us FROM access_invitations WHERE principal_id=?",
                        (str(principal_id),)).fetchone()
                self.assertEqual(expires - issued, hours * 3_600_000_000)
                with waiting(audit, "transaction", lambda: self.clock.advance(seconds=30)):
                    code, reissued = admin.reissue_invitation(context, principal_id, epoch=0)
                self.assertEqual(reissued, self.clock() + timedelta(hours=hours))

    def test_create_app_refuses_a_store_with_another_lifetime(self):
        # Issue #235 item 3: the runtime store must carry the deployment's
        # invitation lifetime, or Owner-issued codes get the wrong expiry.
        for store_hours, setting_hours in ((1, 24), (24, 168), (168, 1), (24, 1)):
            with self.subTest(store=store_hours, setting=setting_hours):
                access = _composition(self, timedelta(hours=store_hours))
                with self.assertRaises(TypeError):
                    create_app(Settings(self.temporary, invitation_lifetime=timedelta(hours=setting_hours)),
                               database=self.database, human_access=access)
                self.assertIsNone(access.store.audit.reservation)
        for hours in (1, 24, 168):
            with self.subTest(both=hours):
                access = _composition(self, timedelta(hours=hours))
                application = create_app(Settings(self.temporary, invitation_lifetime=timedelta(hours=hours)),
                                         database=self.database, human_access=access,
                                         storage_reservation=_Admission())
                self.assertIsNotNone(application)
                self.assertTrue(access.storage_admitted)


class _Admission:
    def __call__(self):
        return nullcontext()


def _composition(case, lifetime):
    """A validated HumanAccess over ``case.database`` whose store has ``lifetime``."""
    audit = AuditStore(case.database, clock=case.clock)
    store = AccessStore(case.database, clock=case.clock, audit=audit, invitation_lifetime=lifetime,
                        session_binding=SessionBindingKey.generate())
    check, _, _, _ = checker(session_revoker=ReservationSessionRevocation(store))
    ceremonies = PasskeyCeremonies(store, RelyingParty(HOST, ORIGIN), session_gate=check)
    return HumanAccess(HumanAccessConfiguration(enabled=True), store=store, ceremonies=ceremonies,
                       reservation=check)


class GateRaceTests(AdministrationFixture):
    """A change between the OWNER_OP authorization and the commit refuses the
    mutation: nothing changes and a ``failed`` record is written."""

    async def assert_refused_after(self, interrupt, error):
        context = await self.context()
        _, viewer_key, viewer_credential = self.enroll((Permission.LIVE_VIEW,))
        viewer_id = viewer_credential.principal_id
        handle = self.entry(viewer_id)["credentials"][0]["handle"]
        operations = {
            AuditAction.INVITE_PRINCIPAL:
                lambda: self.admin.invite(context, "Synthetic invitee", (), epoch=context.epoch),
            AuditAction.ISSUE_PRINCIPAL_INVITATION:
                lambda: self.admin.reissue_invitation(context, viewer_id, epoch=context.epoch),
            AuditAction.CHANGE_PRINCIPAL_PERMISSIONS:
                lambda: self.admin.change_permission(context, viewer_id, Permission.RECORDINGS_VIEW, True,
                                                     epoch=context.epoch),
            AuditAction.REVOKE_PRINCIPAL_CREDENTIAL:
                lambda: self.admin.revoke_credential(context, viewer_id, handle, epoch=context.epoch),
            AuditAction.REVOKE_PRINCIPAL:
                lambda: self.admin.revoke_principal(context, viewer_id, epoch=context.epoch),
        }
        authorizer = self.admin.service.authorizer
        original = authorizer.require_owner
        state = {}

        def paused(actor):
            # Between the authorization and the commit.
            original(actor)
            if "done" not in state:
                interrupt()
                state["done"] = True
            # After the interruption (a local recover writes its own records).
            state["before"] = self.access_state()
            state["outcomes"] = self.outcomes(state["action"])

        with patch.object(authorizer, "require_owner", side_effect=paused):
            for action, operation in operations.items():
                with self.subTest(action=action):
                    state["action"] = action
                    with self.assertRaises(error):
                        operation()
                    self.assertEqual(self.access_state(), state["before"])
                    # Exactly one new record: this operation's failure.
                    self.assertEqual(sorted(self.outcomes(action)), sorted([AuditOutcome.FAILED] + state["outcomes"]))

    async def test_stop_between_authorization_and_commit(self):
        await self.assert_refused_after(self.access.stop, HumanAccessClosed)

    async def test_failed_tick_between_authorization_and_commit(self):
        def fail_tick():
            self.access._serving = False  # what run() does when a tick raises
        await self.assert_refused_after(fail_tick, HumanAccessClosed)

    async def test_close_and_reopen_between_authorization_and_commit(self):
        def cycle():
            self.close_access()
            self.reopen_access()
        await self.assert_refused_after(cycle, HumanAccessClosed)

    async def test_local_recover_between_authorization_and_commit(self):
        # The local recover command commits outside the gate (D6): the epoch
        # is unchanged, so only the in-transaction session re-check refuses.
        def recover():
            recover_owner(self.store, new_invitation_code()[0], at=self.ceremony_clock())
        await self.assert_refused_after(recover, AccessValidationError)

    async def test_owner_credential_revoked_locally_between_authorization_and_commit(self):
        def revoke():
            with closing(self.database.connect()) as connection:
                connection.execute("UPDATE access_credentials SET revoked_at_us=1 WHERE principal_id=?",
                                   (str(self.owner.id),))
                connection.commit()
        await self.assert_refused_after(revoke, AccessValidationError)

    async def test_verification_that_went_stale_before_the_commit_is_step_up(self):
        def age():
            self.ceremony_clock.advance(minutes=5)
        await self.assert_refused_after(age, StepUpRequired)

    async def test_the_route_epoch_is_used_never_a_fresh_one(self):
        # S4a item 2: a context of the old epoch is refused after a reopen,
        # even when the caller passes the gate's new, open epoch.
        context = await self.context()
        self.close_access()
        self.reopen_access()
        fresh = self.access.epoch()
        self.assertNotEqual(fresh, context.epoch)
        before = self.access_state()
        with self.assertRaises(HumanAccessClosed):
            self.admin.invite(context, "Synthetic invitee", (), epoch=context.epoch)
        with self.assertRaises(AccessValidationError):
            self.admin.invite(context, "Synthetic invitee", (), epoch=fresh)
        self.assertEqual(self.access_state(), before)
        self.assertEqual(self.outcomes(AuditAction.INVITE_PRINCIPAL), [AuditOutcome.FAILED] * 2)


class GrantDeltaTests(AdministrationFixture):
    """Owner decision S4-5: grants change as a delta."""

    def revision(self, principal_id):
        return self.count(f"SELECT authorization_revision FROM access_principals WHERE id='{principal_id}'")

    async def test_no_op_keeps_sessions_and_a_real_change_keeps_the_pending_code(self):
        context = await self.context()
        _, key, credential = self.enroll((Permission.LIVE_VIEW,))
        viewer_id = credential.principal_id
        cookie = await self.sign_in(key)
        token = self.token(cookie)
        revision = self.revision(viewer_id)
        # No-op: granting what is held, withdrawing what is not.
        self.assertFalse(self.admin.change_permission(context, viewer_id, Permission.LIVE_VIEW, True,
                                                      epoch=context.epoch))
        self.assertFalse(self.admin.change_permission(context, viewer_id, Permission.RECORDINGS_VIEW, False,
                                                      epoch=context.epoch))
        self.assertFalse(self.admin.set_permissions(context, viewer_id, (Permission.LIVE_VIEW,),
                                                    epoch=context.epoch))
        self.assertEqual(self.revision(viewer_id), revision)
        self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())
        # A pending code (re-issued for the active person), then a real change.
        code, _ = self.admin.reissue_invitation(context, viewer_id, epoch=context.epoch)
        self.assertTrue(self.admin.change_permission(context, viewer_id, Permission.RECORDINGS_VIEW, True,
                                                     epoch=context.epoch))
        self.assertEqual(self.revision(viewer_id), revision + 1)
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())
        # Independent grants: live:view kept, recordings:view added.
        self.assertEqual(self.entry(viewer_id)["permissions"], ["live:view", "recordings:view"])
        self.assertTrue(self.entry(viewer_id)["invitation"]["pending"])
        self.redeem(code)
        self.assertEqual(len(self.entry(viewer_id)["credentials"]), 2)
        # Withdrawing one leaves the other.
        self.assertTrue(self.admin.change_permission(context, viewer_id, Permission.LIVE_VIEW, False,
                                                     epoch=context.epoch))
        self.assertEqual(self.entry(viewer_id)["permissions"], ["recordings:view"])
        cookie = await self.sign_in(key)
        token = self.token(cookie)
        self.store.authorize_request(token, VIEWER, Requirement.RECORDINGS, admit=self.gated())
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())

    async def test_invalid_permission_arguments_are_refused(self):
        context = await self.context()
        _, _, credential = self.enroll((Permission.LIVE_VIEW,))
        for permission, granted in (("live:view", True), (Permission.LIVE_VIEW, 1), (None, False)):
            with self.subTest(permission=permission, granted=granted), self.assertRaises(AccessValidationError):
                self.admin.change_permission(context, credential.principal_id, permission, granted,
                                             epoch=context.epoch)


class OwnerTargetTests(AdministrationFixture):
    """Owner decision S4-3: the Owner principal is never a target."""

    async def test_every_mutation_refuses_the_owner(self):
        context = await self.context()
        handle = self.entry(self.owner.id)["credentials"][0]["handle"]
        operations = {
            AuditAction.ISSUE_PRINCIPAL_INVITATION:
                lambda: self.admin.reissue_invitation(context, self.owner.id, epoch=context.epoch),
            AuditAction.CHANGE_PRINCIPAL_PERMISSIONS:
                lambda: self.admin.change_permission(context, self.owner.id, Permission.LIVE_VIEW, False,
                                                     epoch=context.epoch),
            AuditAction.REVOKE_PRINCIPAL_CREDENTIAL:
                lambda: self.admin.revoke_credential(context, self.owner.id, handle, epoch=context.epoch),
            AuditAction.REVOKE_PRINCIPAL:
                lambda: self.admin.revoke_principal(context, self.owner.id, epoch=context.epoch),
        }
        before = self.access_state()
        for action, operation in operations.items():
            with self.subTest(action=action), self.assertRaises(AccessValidationError):
                operation()
            self.assertEqual(self.outcomes(action), [AuditOutcome.FAILED])
        with self.assertRaises(AccessValidationError):
            self.admin.set_permissions(context, self.owner.id, (), epoch=context.epoch)
        self.assertEqual(self.access_state(), before)
        # The Owner's session still works.
        _, result = await self.owner_operation()
        self.assertEqual(status(result), 204)


class ReissueTests(AdministrationFixture):
    """Owner decision S4-4 and S4-8: one pending code per principal."""

    async def test_reissue_revokes_the_previous_code_for_invited_and_active(self):
        context = await self.context()
        principal_id, first, _ = self.admin.invite(context, "Synthetic invitee", (Permission.LIVE_VIEW,),
                                                   epoch=context.epoch)
        second, _ = self.admin.reissue_invitation(context, principal_id, epoch=context.epoch)
        self.assertNotEqual(first, second)
        self.assertEqual(self.count(f"SELECT count(*) FROM access_invitations WHERE principal_id='{principal_id}' "
                                    "AND revoked_at_us IS NULL AND redeemed_at_us IS NULL"), 1)
        with self.assertRaises(Exception):
            self.redeem(first)
        self.redeem(second)
        self.assertEqual(self.entry(principal_id)["status"], "active")
        # Active: allowed, one new pending code.
        third, _ = self.admin.reissue_invitation(context, principal_id, epoch=context.epoch)
        self.assertTrue(self.entry(principal_id)["invitation"]["pending"])
        # Revoked: refused, nothing issued.
        self.admin.revoke_principal(context, principal_id, epoch=context.epoch)
        before = self.access_state()
        with self.assertRaises(AccessValidationError):
            self.admin.reissue_invitation(context, principal_id, epoch=context.epoch)
        self.assertEqual(self.access_state(), before)
        with self.assertRaises(Exception):
            self.redeem(third)

    async def test_a_second_pending_code_is_refused_by_the_store(self):
        context = await self.context()
        principal_id, _, _ = self.admin.invite(context, "Synthetic invitee", (), epoch=context.epoch)
        with self.assertRaises(AccessLimitReached):
            self.store.issue_enrollment(principal_id, b"x" * 20, self.ceremony_clock() + timedelta(hours=1))
        # An expired code no longer counts.
        self.ceremony_clock.advance(hours=25)
        self.store.issue_enrollment(principal_id, b"y" * 20, self.ceremony_clock() + timedelta(hours=1))

    async def test_unknown_principals_are_refused(self):
        context = await self.context()
        for target in (uuid4(), str(uuid4())):
            with self.subTest(target=type(target).__name__), self.assertRaises(Exception):
                self.admin.reissue_invitation(context, target, epoch=context.epoch)


class CredentialHandleTests(AdministrationFixture):
    async def test_revocation_by_handle_only_for_that_principal(self):
        context = await self.context()
        _, _, first = self.enroll((Permission.LIVE_VIEW,))
        _, _, second = self.enroll((Permission.LIVE_VIEW,))
        first_handle = self.entry(first.principal_id)["credentials"][0]["handle"]
        before = self.access_state()
        for principal_id, handle in ((second.principal_id, first_handle),
                                     (first.principal_id, first.credential_id),
                                     (first.principal_id, first_handle.upper()),
                                     (first.principal_id, str(uuid4()))):
            with self.subTest(handle=handle), self.assertRaises(AccessValidationError):
                self.admin.revoke_credential(context, principal_id, handle, epoch=context.epoch)
        self.assertEqual(self.access_state(), before)
        self.admin.revoke_credential(context, first.principal_id, first_handle, epoch=context.epoch)
        self.assertEqual(self.entry(first.principal_id)["credentials"][0]["status"], "revoked")
        self.assertEqual(self.entry(second.principal_id)["credentials"][0]["status"], "active")


class InventoryTests(AdministrationFixture):
    async def test_inventory_has_exactly_the_owner_view_keys_and_no_secret_material(self):
        context = await self.context()
        principal_id, code, _ = self.admin.invite(context, "Synthetic invitee", (Permission.LIVE_VIEW,),
                                                  epoch=context.epoch)
        self.redeem(code, identity="synthetic-invitee-login@example.invalid")
        inventory = self.store.admin_inventory()
        self.assertEqual(len(inventory), 2)
        for entry in inventory:
            self.assertEqual(set(entry), PRINCIPAL_KEYS)
            self.assertEqual(set(entry["invitation"]), INVITATION_KEYS)
            for credential in entry["credentials"]:
                self.assertEqual(set(credential), CREDENTIAL_KEYS)
                self.assertEqual(str(UUID(credential["handle"])), credential["handle"])
        owner = self.entry(self.owner.id)
        self.assertEqual(owner["permissions"], ["live:view", "recordings:view"])
        text = json.dumps(inventory)
        with closing(self.database.connect()) as connection:
            secrets_ = [bytes(value) for row in connection.execute(
                "SELECT credential_id, public_key FROM access_credentials") for value in row]
            secrets_ += [bytes(row[0]) for row in connection.execute(
                "SELECT secret_digest FROM access_invitations")]
            identities = [row[0] for row in connection.execute(
                "SELECT external_identity FROM access_principals WHERE external_identity IS NOT NULL")]
        self.assertTrue(identities)  # the store keeps the last observed login ...
        for identity in identities + [VIEWER, "synthetic-invitee-login@example.invalid"]:
            self.assertNotIn(identity, text)  # ... but never returns it (D14)
        for value in secrets_:
            for form in (value.hex(), base64.urlsafe_b64encode(value).rstrip(b"=").decode(),
                         base64.b64encode(value).decode()):
                self.assertNotIn(form, text)
        self.assertNotIn(code, text)

    async def test_inventory_writes_nothing(self):
        before = self.access_state()
        with patch.object(self.store, "_transaction", wraps=self.store._transaction) as transaction:
            self.store.admin_inventory()
        self.assertEqual([call_.kwargs.get("write", False) for call_ in transaction.call_args_list], [False])
        self.assertEqual(self.access_state(), before)


class OwnerSessionRecheckTests(unittest.TestCase):
    """``require_owner_session_on`` directly (S4a item 3)."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = Clock()
        self.audit = AuditStore(self.database, clock=self.clock)
        self.store = AccessStore(self.database, clock=self.clock, audit=self.audit,
                                 session_binding=SessionBindingKey.generate())

    def check(self, view, at=None):
        with self.store._transaction(write=True) as connection:
            self.store.require_owner_session_on(connection, view, at or self.clock())

    def test_each_condition(self):
        context = owner_context(self.store)
        view = context.session
        self.check(view)
        self.clock.advance(minutes=5)
        with self.assertRaises(StepUpRequired):
            self.check(view)
        self.clock.advance(minutes=-5)
        variants = {
            "revision": SessionView(view.session_id, view.principal_id, view.credential_id, role=view.role,
                                    authorization_revision=view.authorization_revision + 1,
                                    permissions=view.permissions),
            "principal": SessionView(view.session_id, uuid4(), view.credential_id, role=view.role,
                                     authorization_revision=view.authorization_revision),
            "credential": SessionView(view.session_id, view.principal_id, b"other", role=view.role,
                                      authorization_revision=view.authorization_revision),
            "session": SessionView(uuid4(), view.principal_id, view.credential_id, role=view.role,
                                   authorization_revision=view.authorization_revision),
            "role": SessionView(view.session_id, view.principal_id, view.credential_id,
                                role=PrincipalRole.INVITED_USER,
                                authorization_revision=view.authorization_revision),
            "unauthorized view": SessionView(view.session_id, view.principal_id, view.credential_id),
        }
        for name, variant in variants.items():
            with self.subTest(name=name), self.assertRaises(AccessValidationError) as raised:
                self.check(variant)
            self.assertIs(type(raised.exception), AccessValidationError)
        # Expired idle lifetime: the generic error, never StepUpRequired (#240 item 3).
        with self.assertRaises(AccessValidationError) as raised:
            self.check(view, self.clock() + timedelta(minutes=31))
        self.assertIs(type(raised.exception), AccessValidationError)
        # Signed out, inconsistent credential, deployment generation.
        for statement in ("UPDATE access_sessions SET invalidated_at_us=1, external_identity_binding=NULL",
                          "UPDATE access_credentials SET inconsistent_at_us=1, "
                          "inconsistency_reason='backup_eligibility_changed'",
                          "UPDATE access_deployment_state SET authorization_generation=authorization_generation+1"):
            fresh = owner_context(self.store, credential_id=uuid4().bytes)
            with self.subTest(statement=statement.split(" SET ")[0]):
                self.check(fresh.session)
                with closing(self.database.connect()) as connection:
                    connection.execute(statement)
                    connection.commit()
                with self.assertRaises(AccessValidationError):
                    self.check(fresh.session)

    def test_a_session_never_verified_is_stale(self):
        token = owner_session(self.store, fresh=False)
        with self.assertRaises(StepUpRequired):
            self.store.authorize_request(token, OWNER_IDENTITY, Requirement.OWNER_OP, admit=nullcontext)


class AuthorizerTests(unittest.TestCase):
    def test_only_an_owner_context_passes(self):
        authorizer = HumanOwnerAuthorizer()
        owner = SessionView(uuid4(), uuid4(), b"c", role=PrincipalRole.OWNER, authorization_revision=0)
        viewer = SessionView(uuid4(), uuid4(), b"c", role=PrincipalRole.INVITED_USER, authorization_revision=0)
        authorizer.require_owner(OwnerOperationContext(owner, 3))
        with self.assertRaises(OwnerAuthorizationError) as raised:
            authorizer.require_owner(OwnerOperationContext(viewer, 3))
        self.assertEqual(raised.exception.actor_category, ActorCategory.INVITED_USER)
        for actor in (None, owner, "owner", b"token", object()):
            with self.subTest(actor=type(actor).__name__), self.assertRaises(OwnerAuthorizationError) as raised:
                authorizer.require_owner(actor)
            self.assertEqual(raised.exception.actor_category, ActorCategory.UNAUTHENTICATED)
        for epoch in (None, True, "1", 1.0):
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                OwnerOperationContext(owner, epoch)
        with self.assertRaises(ValueError):
            OwnerOperationContext("session", 1)


class HandleMigrationTests(unittest.TestCase):
    """Migration 24: every existing credential gets its own random handle."""

    def test_backfill_trigger_and_uniqueness(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS[:23])
            connection.execute("INSERT INTO access_principals VALUES (?, NULL, 'Synthetic', 'invited_user', "
                               "'active', 0, 1, NULL)", (str(uuid4()),))
            principal = connection.execute("SELECT id FROM access_principals").fetchone()[0]
            for index in range(20):
                connection.execute("INSERT INTO access_credentials (credential_id, principal_id, public_key, "
                                   "algorithm, sign_count, enrolled_at_us) VALUES (?, ?, X'01', -7, 0, 1)",
                                   (bytes([index + 1]) * 16, principal))
            connection.commit()
            migrate(connection, APPLICATION_MIGRATIONS)
            handles = [row[0] for row in connection.execute("SELECT handle FROM access_credentials")]
            self.assertEqual(len(handles), 20)
            self.assertEqual(len(set(handles)), 20)
            for handle in handles:
                parsed = UUID(handle)
                self.assertEqual((str(parsed), parsed.version), (handle, 4))
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("INSERT INTO access_credentials (credential_id, principal_id, public_key, "
                                   "algorithm, sign_count, enrolled_at_us) VALUES (X'FF', ?, X'01', -7, 0, 1)",
                                   (principal,))
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("UPDATE access_credentials SET handle=? WHERE handle=?", (str(uuid4()), handles[0]))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO access_credentials (credential_id, principal_id, public_key, "
                                   "algorithm, sign_count, enrolled_at_us, handle) VALUES (X'FE', ?, X'01', -7, 0, 1, ?)",
                                   (principal, handles[0]))


class PendingConditionTests(AdministrationFixture):
    """Issue #240 items 1 and 2: "pending" is exactly what a redemption accepts,
    for the inventory and for the one-pending-code cap alike."""

    def setUp(self):
        super().setUp()
        # A synthetic boot clock from the start, so the Owner's sign-in and
        # every invitation carry its readings.
        self.boot = BootClock()
        self.store._boot_clock = self.boot

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.context_ = await self.context()

    def invited(self):
        principal_id, code, _ = self.admin.invite(self.context_, "Synthetic invitee", (Permission.LIVE_VIEW,),
                                                  epoch=self.context_.epoch)
        self.assertTrue(self.entry(principal_id)["invitation"]["pending"])
        return principal_id, code

    def invitation(self, principal_id, column):
        return self.count(f"SELECT {column} FROM access_invitations WHERE principal_id='{principal_id}' "
                          "ORDER BY issued_at_us LIMIT 1")

    def assert_unredeemable_and_replaceable(self, principal_id, code):
        """Not pending, refused by redemption, and replaceable by a new code."""
        entry = self.entry(principal_id)
        self.assertEqual(entry["invitation"], {"pending": False, "expires_at": None})
        with self.assertRaises(Exception):
            self.redeem(code)
        secret, fresh = new_invitation_code()
        self.store.issue_enrollment(principal_id, secret, self.ceremony_clock() + timedelta(hours=1))
        # The unredeemable code was marked revoked with the issue, so it can
        # never come back next to the new one (the cap holds).
        self.assertIsNotNone(self.invitation(principal_id, "revoked_at_us"))
        self.assertEqual(self.count(f"SELECT count(*) FROM access_invitations WHERE principal_id='{principal_id}' "
                                    "AND redeemed_at_us IS NULL AND revoked_at_us IS NULL"), 1)
        self.assertTrue(self.entry(principal_id)["invitation"]["pending"])
        with self.assertRaises(AccessLimitReached):
            self.store.issue_enrollment(principal_id, new_invitation_code()[0],
                                        self.ceremony_clock() + timedelta(hours=1))
        self.redeem(fresh)

    def update(self, principal_id, assignment):
        with closing(self.database.connect()) as connection:
            connection.execute(f"UPDATE access_invitations SET {assignment} WHERE principal_id=?",
                               (str(principal_id),))
            connection.commit()

    async def test_a_code_without_its_boot_clock_pair_is_not_pending(self):
        for assignment in ("issued_boot_id=NULL", "issued_boottime_us=NULL", "lookup_key=NULL"):
            with self.subTest(assignment=assignment):
                principal_id, code = self.invited()
                self.update(principal_id, assignment)
                self.assert_unredeemable_and_replaceable(principal_id, code)

    async def test_an_attempt_exhausted_code_is_not_pending(self):
        principal_id, code = self.invited()
        self.update(principal_id, f"attempt_count={MAX_REDEMPTION_ATTEMPTS}")
        self.assert_unredeemable_and_replaceable(principal_id, code)

    async def test_a_code_after_a_wall_clock_step_back_is_not_pending_and_never_revives(self):
        principal_id, code = self.invited()
        # Ten minutes pass on CLOCK_BOOTTIME while the wall clock stands still
        # (stepped back by ten minutes): invitation_clock_valid refuses.
        self.boot.advance(minutes=10)
        self.assert_unredeemable_and_replaceable(principal_id, code)

    async def test_a_code_of_a_stale_revision_is_not_pending_and_a_grant_change_does_not_revive_it(self):
        principal_id, code = self.invited()
        # The principal's revision moved without the code (as before S4-5).
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_principals SET authorization_revision=authorization_revision+1 "
                               "WHERE id=?", (str(principal_id),))
            connection.commit()
        self.assertFalse(self.entry(principal_id)["invitation"]["pending"])
        stale = self.invitation(principal_id, "principal_revision")
        # A real grant change advances only a code at the current revision.
        self.assertTrue(self.admin.change_permission(self.context_, principal_id, Permission.RECORDINGS_VIEW, True,
                                                     epoch=self.context_.epoch))
        self.assertEqual(self.invitation(principal_id, "principal_revision"), stale)
        self.assertFalse(self.entry(principal_id)["invitation"]["pending"])
        with self.assertRaises(Exception):
            self.redeem(code)
        # A current code moves with the principal and stays pending (S4-5).
        fresh, _ = self.admin.reissue_invitation(self.context_, principal_id, epoch=self.context_.epoch)
        self.assertTrue(self.admin.change_permission(self.context_, principal_id, Permission.LIVE_VIEW, False,
                                                     epoch=self.context_.epoch))
        self.assertTrue(self.entry(principal_id)["invitation"]["pending"])
        self.redeem(fresh)

    async def test_an_unreadable_boot_clock_shows_nothing_pending(self):
        principal_id, _ = self.invited()
        self.boot.available = False
        self.assertFalse(self.entry(principal_id)["invitation"]["pending"])
        self.boot.available = True
        self.assertTrue(self.entry(principal_id)["invitation"]["pending"])


class NoOpAuditTests(AdministrationFixture):
    async def test_a_no_op_grant_change_keeps_one_succeeded_record(self):
        """Issue #240 item 4: a requested change that changes nothing is
        recorded once as ``succeeded`` ("requested, no change"); the
        authorization revision and the sessions stay as they were."""
        context = await self.context()
        _, _, credential = self.enroll((Permission.LIVE_VIEW,))
        state = self.access_state()
        self.assertFalse(self.admin.change_permission(context, credential.principal_id, Permission.LIVE_VIEW,
                                                      True, epoch=context.epoch))
        self.assertEqual(self.access_state(), state)
        records = [record for record in self.audit.list_records(limit=1000)
                   if record.action is AuditAction.CHANGE_PRINCIPAL_PERMISSIONS]
        self.assertEqual([(record.outcome, record.target_logical_id) for record in records],
                         [(AuditOutcome.SUCCEEDED, credential.principal_id)])


class LogHygieneTests(AdministrationFixture):
    async def test_administration_logs_no_code_name_or_identity(self):
        context = await self.context()
        logger = logging.getLogger()
        records = []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Collect(level=logging.DEBUG)
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        level = logger.level
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.setLevel, level)
        principal_id, code, _ = self.admin.invite(context, "Synthetic secret name", (), epoch=context.epoch)
        with self.assertRaises(AccessValidationError):
            self.admin.revoke_principal(context, self.owner.id, epoch=context.epoch)
        text = " ".join(records)
        for value in (code, "Synthetic secret name", VIEWER, context.session.credential_id.hex()):
            self.assertNotIn(value, text)
        del principal_id


if __name__ == "__main__":
    unittest.main()
