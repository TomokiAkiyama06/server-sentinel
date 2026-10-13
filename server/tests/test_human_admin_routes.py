"""Issue #10 phase 2 S4b: the Owner's access-administration routes A1-A6.

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows, a synthetic boot id and ``CLOCK_BOOTTIME``, a temporary
SQLite database and the in-process ASGI driver of ``test_human_surface``.
Every identity, display name and code is an invented value. Mock only: no
browser, proxy, Tailscale or real authenticator is involved.

Owner decisions S4-1 .. S4-8 (Issue #10, 2026-10-13) and Issue #240.
"""

from contextlib import closing
from datetime import timedelta
import json
import logging
from unittest.mock import patch
from uuid import UUID, uuid4

from app.audit.model import AuditAction, AuditOutcome
from app.auth.bootstrap_cli import recover_owner
from app.auth.human_surface import (
    ADMIN_PRINCIPALS_PATH, REGISTRATION_OPTIONS_PATH, REGISTRATION_PATH, SESSION_COOKIE,
    SESSION_PATH, HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable, match_route,
)
from app.auth.invitation_code import new_invitation_code, parse_invitation_code
from app.auth.model import AccessValidationError, Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.rate_limit import (
    ADMIN_MAX_SESSIONS, ADMIN_PER_SESSION_CAPACITY, ADMIN_PER_SESSION_REFILL_SECONDS, SourceRateLimiter,
    admin_rate_limiter,
)
from app.auth.store import MAX_PRINCIPALS, Requirement
from app.logging import SafeJsonFormatter

from tests.test_human_gated_authorization import GENERIC, STEP_UP
from tests.test_human_step_up import StepUpFixture
from tests.test_human_surface import HOST, LAN, ORIGIN, OTHER_LOGIN, VIEWER, call, header, payload, status
from tests.webauthn_fakes import SyntheticAuthenticator, b64


PRINCIPALS = ADMIN_PRINCIPALS_PATH
NAME = "Synthetic invitee Ω"
PRINCIPAL_KEYS = {"id", "display_name", "role", "status", "created_at", "revoked_at", "permissions",
                  "invitation", "credentials"}
INVITATION_KEYS = {"pending", "expires_at"}
CREDENTIAL_KEYS = {"handle", "label", "status", "inconsistency_reason", "backup_eligible", "backup_state",
                   "created_at", "last_used_at", "revoked_at"}
ADMIN_ACTIONS = (AuditAction.INVITE_PRINCIPAL, AuditAction.ISSUE_PRINCIPAL_INVITATION,
                 AuditAction.CHANGE_PRINCIPAL_PERMISSIONS, AuditAction.REVOKE_PRINCIPAL,
                 AuditAction.REVOKE_PRINCIPAL_CREDENTIAL)
FORGED = SESSION_COOKIE + "=" + "B" * 43
OMIT = object()


def rewriting(application, **changes):
    """An ASGI wrapper that changes (or, with ``OMIT``, removes) scope keys."""
    async def rewritten(scope, receive, send):
        scope = dict(scope)
        for key, value in changes.items():
            if value is OMIT:
                scope.pop(key, None)
            else:
                scope[key] = value
        await application(scope, receive, send)
    return rewritten


class AdminRouteFixture(StepUpFixture):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.access.redemption_limiter = SourceRateLimiter(
            per_source_capacity=1000, global_capacity=None, monotonic=self.limit_clock)
        # Lenient here; RateLimitTests installs the real shape.
        self.access.admin_limiter = SourceRateLimiter(
            per_source_capacity=1000, global_capacity=None, monotonic=self.limit_clock)
        self.owner, self.owner_key, _, self.owner_cookie, self.owner_csrf = await self.owner_session()
        self.target, self.target_key, self.target_credential = self.enroll((Permission.LIVE_VIEW,))
        self.target_cookie = await self.sign_in(self.target_key)
        self.target_csrf = await self.csrf(self.target_cookie)

    # -- requests ------------------------------------------------------

    async def admin(self, method, path, body=None, *, cookie=OMIT, csrf=OMIT, raw=None, application=None,
                    **options):
        cookie = self.owner_cookie if cookie is OMIT else cookie
        csrf = self.owner_csrf if csrf is OMIT else csrf
        headers = list(options.pop("headers", ()))
        if csrf is not None:
            headers.append((b"x-csrf-token", csrf.encode()))
        data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        return await call(application or self.surface, method, path, cookie=cookie, headers=headers,
                          body=data, **options)

    def handle(self, principal_id, index=0):
        return self.entry(principal_id)["credentials"][index]["handle"]

    def handle_of(self, credential_id):
        """The administration handle of a credential (read directly: the
        inventory never shows the credential id)."""
        with closing(self.database.connect()) as connection:
            return connection.execute("SELECT handle FROM access_credentials WHERE credential_id=?",
                                      (credential_id,)).fetchone()[0]

    def routes(self, target=None, handle=None):
        """Every administration route: ``name -> (method, path, body)``."""
        target = target or self.target.id
        handle = handle or self.handle(target)
        base = f"{PRINCIPALS}/{target}"
        return {
            "A1 inventory": ("GET", PRINCIPALS, None),
            "A2 invite": ("POST", PRINCIPALS, {"display_name": NAME, "permissions": ["live:view"]}),
            "A3 re-issue": ("POST", base + "/invitation", {}),
            "A4 permission": ("POST", base + "/permissions", {"permission": "recordings:view", "granted": True}),
            # A6 before A5, so that run in order both apply to a live target.
            "A6 revoke credential": ("POST", f"{base}/credentials/{handle}/revoke", {}),
            "A5 revoke principal": ("POST", base + "/revoke", {}),
        }

    def mutations(self, target=None, handle=None):
        return {name: route for name, route in self.routes(target, handle).items() if route[0] == "POST"}

    async def redeem(self, code, authenticator=None):
        """Redeem through the S2 routes; returns the authenticator."""
        authenticator = authenticator or SyntheticAuthenticator()
        begun = await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH,
                           body=json.dumps({"code": code}).encode())
        self.assertEqual(status(begun), 200)
        credential = authenticator.register(payload(begun), origin=ORIGIN, rp_id=HOST)
        finished = await call(self.surface, "POST", REGISTRATION_PATH,
                              body=json.dumps({"code": code, "credential": credential}).encode())
        self.assertEqual(status(finished), 204)
        return authenticator

    async def session_of(self, cookie):
        result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
        return payload(result) if status(result) == 200 else None

    # -- state ---------------------------------------------------------

    def entry(self, principal_id):
        return next(item for item in self.store.admin_inventory() if item["id"] == str(principal_id))

    def access_state(self):
        with closing(self.database.connect()) as connection:
            return [tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1"))
                    for table in ("access_principals", "access_principal_permissions", "access_invitations",
                                  "access_credentials")]

    def admin_records(self):
        return sorted((record.action.value, record.outcome.value, str(record.target_logical_id))
                      for record in self.audit.list_records(limit=1000) if record.action in ADMIN_ACTIONS)

    def snapshot(self):
        """Everything a refused administration request must leave as it was."""
        return self.access_state(), self.session_rows(), self.admin_records()

    def outcomes(self, action):
        return [record.outcome for record in self.audit.list_records(limit=1000) if record.action is action]


class RouteTableTests(AdminRouteFixture):
    async def test_route_table_entries(self):
        target, handle = str(uuid4()), str(uuid4())
        expected = {
            ("GET", PRINCIPALS): (Requirement.OWNER_READ, False, False, 0),
            ("POST", PRINCIPALS): (Requirement.OWNER_OP, True, True, 2048),
            ("POST", f"{PRINCIPALS}/{target}/invitation"): (Requirement.OWNER_OP, True, True, 2),
            ("POST", f"{PRINCIPALS}/{target}/permissions"): (Requirement.OWNER_OP, True, True, 256),
            ("POST", f"{PRINCIPALS}/{target}/revoke"): (Requirement.OWNER_OP, True, True, 2),
            ("POST", f"{PRINCIPALS}/{target}/credentials/{handle}/revoke"): (Requirement.OWNER_OP, True, True, 2),
        }
        for (method, path), (requirement, mutating, csrf, limit) in expected.items():
            with self.subTest(method=method, path=path):
                route = match_route({"method": method, "path": path, "raw_path": path.encode()})
                self.assertIsNotNone(route)
                self.assertEqual((route.requirement, route.mutating, route.csrf, route.body_limit, route.query),
                                 (requirement, mutating, csrf, limit, ()))
                for other in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    if other != method and (other, path) not in expected:
                        self.assertIsNone(match_route({"method": other, "path": path, "raw_path": path.encode()}))
        mismatched = match_route({"method": "POST", "path": f"{PRINCIPALS}/{target}/credentials/{handle}/revoke",
                                  "raw_path": b"x"})
        self.assertIsNone(mismatched)

    async def test_only_canonical_lower_case_uuid_path_ids_match(self):
        target = str(uuid4())
        for path in (f"{PRINCIPALS}/{target.upper()}/revoke", f"{PRINCIPALS}/{{{target}}}/revoke",
                     f"{PRINCIPALS}/{target.replace('-', '')}/revoke", f"{PRINCIPALS}/urn:uuid:{target}/revoke",
                     f"{PRINCIPALS}/{target}/revoke/", f"{PRINCIPALS}//{target}/revoke",
                     f"{PRINCIPALS}/{target[:-1]}/revoke", f"{PRINCIPALS}/{target}x/revoke",
                     f"{PRINCIPALS}/{target}/credentials/{target.upper()}/revoke",
                     f"{PRINCIPALS}/{target}/credentials//revoke", f"{PRINCIPALS}/",
                     f"{PRINCIPALS}/{target}", f"{PRINCIPALS}/{target}/invitation/x"):
            with self.subTest(path=path):
                self.assertIsNone(match_route({"method": "POST", "path": path, "raw_path": path.encode()}))
        # A percent-encoded spelling of a valid id is not that path.
        path = f"{PRINCIPALS}/{target}/revoke"
        encoded = path.replace("-", "%2D", 1).encode()
        self.assertIsNone(match_route({"method": "POST", "path": path, "raw_path": encoded}))
        self.assertIsNone(match_route({"method": "POST", "path": path, "raw_path": None}))
        self.assertIsNone(match_route({"method": "POST", "path": path}))


class HappyPathTests(AdminRouteFixture):
    async def test_invite_redeem_sign_in_with_the_granted_permissions(self):
        result = await self.admin("POST", PRINCIPALS, {"display_name": NAME,
                                                       "permissions": ["recordings:view", "live:view"]})
        self.assertEqual(status(result), 200)
        self.assertEqual(header(result, b"cache-control"), [b"no-store"])
        self.assertEqual(header(result, b"set-cookie"), [])
        body = payload(result)
        self.assertEqual(set(body), {"principal_id", "code", "expires_at"})
        principal_id = UUID(body["principal_id"])
        self.assertEqual(str(principal_id), body["principal_id"])
        self.assertEqual(len(parse_invitation_code(body["code"])), 20)
        self.assertEqual(body["expires_at"], (self.ceremony_clock() + timedelta(hours=24)).isoformat())
        entry = self.entry(principal_id)
        self.assertEqual((entry["display_name"], entry["status"], entry["permissions"], entry["invitation"]),
                         (NAME, "invited", ["live:view", "recordings:view"],
                          {"pending": True, "expires_at": body["expires_at"]}))
        self.assertEqual(sorted(self.admin_records()), sorted([
            ("invite_principal", "succeeded", str(principal_id)),
            ("issue_principal_invitation", "succeeded", str(principal_id)),
        ]))
        # Redeemed through the S2 routes; the person signs in with their passkey.
        key = await self.redeem(body["code"])
        cookie = await self.sign_in(key)
        self.assertEqual(await self.session_of(cookie),
                         {"csrf": await self.csrf(cookie), "role": "invited_user",
                          "permissions": ["live:view", "recordings:view"]})
        self.assertEqual(self.entry(principal_id)["invitation"], {"pending": False, "expires_at": None})

    async def test_invite_with_no_permission_and_a_display_name_at_the_bound(self):
        for name, permissions in (("x" * 64, []), ("Synthetic one", ["live:view"])):
            with self.subTest(length=len(name)):
                result = await self.admin("POST", PRINCIPALS, {"display_name": name, "permissions": permissions})
                self.assertEqual(status(result), 200)
                self.assertEqual(self.entry(payload(result)["principal_id"])["permissions"], permissions)

    async def test_inventory_has_exactly_the_owner_view_keys_and_no_secret_material(self):
        result = await self.admin("GET", PRINCIPALS, csrf=None, origin=None)
        self.assertEqual(status(result), 200)
        self.assertEqual(header(result, b"cache-control"), [b"no-store"])
        body = payload(result)
        self.assertEqual(set(body), {"principals"})
        self.assertEqual(body["principals"], json.loads(json.dumps(list(self.store.admin_inventory()))))
        self.assertEqual(sorted(entry["id"] for entry in body["principals"]),
                         sorted([str(self.owner.id), str(self.target.id)]))
        for entry in body["principals"]:
            self.assertEqual(set(entry), PRINCIPAL_KEYS)
            self.assertEqual(set(entry["invitation"]), INVITATION_KEYS)
            for credential in entry["credentials"]:
                self.assertEqual(set(credential), CREDENTIAL_KEYS)
        text = result[1]["body"].decode()
        with closing(self.database.connect()) as connection:
            material = [bytes(value) for row in connection.execute(
                "SELECT credential_id, public_key FROM access_credentials") for value in row]
            material += [bytes(row[0]) for row in connection.execute(
                "SELECT secret_digest FROM access_invitations")]
            material += [bytes(row[0]) for row in connection.execute(
                "SELECT token_digest FROM access_sessions")]
            identities = [row[0] for row in connection.execute(
                "SELECT external_identity FROM access_principals WHERE external_identity IS NOT NULL")]
        self.assertTrue(identities)
        for identity in identities + [VIEWER]:
            self.assertNotIn(identity, text)  # D14: stored, never returned
        for value in material:
            for form in (value.hex(), b64(value), b64(value).replace("-", "+").replace("_", "/")):
                self.assertNotIn(form, text)
        for name in ("sign_count", "public_key", "credential_id", "external_identity", "secret_digest",
                     "lookup_key", "session", "token"):
            self.assertNotIn(name, text)

    async def test_reissue_revokes_the_old_code_and_the_new_one_redeems(self):
        invited = payload(await self.admin("POST", PRINCIPALS, {"display_name": NAME, "permissions": []}))
        principal_id = invited["principal_id"]
        result = await self.admin("POST", f"{PRINCIPALS}/{principal_id}/invitation", {})
        self.assertEqual(status(result), 200)
        body = payload(result)
        self.assertEqual(set(body), {"code", "expires_at"})
        self.assertNotEqual(body["code"], invited["code"])
        refused = await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH,
                             body=json.dumps({"code": invited["code"]}).encode())
        self.assertEqual(refused, GENERIC)
        await self.redeem(body["code"])
        self.assertEqual(self.entry(principal_id)["status"], "active")
        # An active person can get a code for another credential (S4-4).
        again = await self.admin("POST", f"{PRINCIPALS}/{principal_id}/invitation", {})
        self.assertEqual(status(again), 200)
        await self.redeem(payload(again)["code"])
        self.assertEqual(len(self.entry(principal_id)["credentials"]), 2)

    async def test_permission_delta_ends_the_sessions_only_on_a_real_change(self):
        token = self.token(self.target_cookie)
        ended = "SELECT count(*) FROM access_sessions WHERE invalidated_at_us IS NOT NULL"
        revision = f"SELECT authorization_revision FROM access_principals WHERE id='{self.target.id}'"
        ended_before, revision_before = self.count(ended), self.count(revision)
        path = f"{PRINCIPALS}/{self.target.id}/permissions"
        # No-op: 204, sessions kept, one succeeded record ("requested, no change").
        for body in ({"permission": "live:view", "granted": True},
                     {"permission": "recordings:view", "granted": False}):
            with self.subTest(body=body):
                result = await self.admin("POST", path, body)
                self.assertEqual(status(result), 204)
                self.assertEqual(result[1]["body"], b"")
                self.assertEqual(header(result, b"cache-control"), [b"no-store"])
        self.assertEqual(self.outcomes(AuditAction.CHANGE_PRINCIPAL_PERMISSIONS), [AuditOutcome.SUCCEEDED] * 2)
        self.assertEqual((self.count(ended), self.count(revision)), (ended_before, revision_before))
        self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())
        # Withdrawing live:view: the next LIVE request is refused, the session ended.
        self.assertEqual(status(await self.admin("POST", path, {"permission": "live:view", "granted": False})), 204)
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())
        self.assertIsNone(await self.session_of(self.target_cookie))
        # Granting recordings:view: a new sign-in carries exactly it.
        self.assertEqual(status(await self.admin(
            "POST", path, {"permission": "recordings:view", "granted": True})), 204)
        cookie = await self.sign_in(self.target_key)
        self.assertEqual((await self.session_of(cookie))["permissions"], ["recordings:view"])
        token = self.token(cookie)
        self.store.authorize_request(token, VIEWER, Requirement.RECORDINGS, admit=self.gated())
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(token, VIEWER, Requirement.LIVE, admit=self.gated())

    async def test_revoke_principal_ends_every_session_and_code(self):
        second = await self.sign_in(self.target_key)
        reissued = payload(await self.admin("POST", f"{PRINCIPALS}/{self.target.id}/invitation", {}))
        result = await self.admin("POST", f"{PRINCIPALS}/{self.target.id}/revoke", {})
        self.assertEqual(status(result), 204)
        for cookie in (self.target_cookie, second):
            self.assertIsNone(await self.session_of(cookie))
        entry = self.entry(self.target.id)
        self.assertEqual((entry["status"], entry["invitation"]["pending"]), ("revoked", False))
        self.assertEqual({item["status"] for item in entry["credentials"]}, {"revoked"})
        refused = await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH,
                             body=json.dumps({"code": reissued["code"]}).encode())
        self.assertEqual(refused, GENERIC)
        # The Owner keeps working; a second revocation is refused.
        before = self.access_state()
        self.assertEqual(await self.admin("POST", f"{PRINCIPALS}/{self.target.id}/revoke", {}), GENERIC)
        self.assertEqual(self.access_state(), before)
        self.assertIsNotNone(await self.session_of(self.owner_cookie))

    async def test_revoke_credential_ends_only_that_credentials_sessions(self):
        code = payload(await self.admin("POST", f"{PRINCIPALS}/{self.target.id}/invitation", {}))["code"]
        second_key = await self.redeem(code)
        second_cookie = await self.sign_in(second_key)
        first_handle = self.handle_of(self.target_credential.credential_id)
        second_handle = self.handle_of(second_key.credential_id)
        result = await self.admin("POST", f"{PRINCIPALS}/{self.target.id}/credentials/{first_handle}/revoke", {})
        self.assertEqual(status(result), 204)
        self.assertIsNone(await self.session_of(self.target_cookie))
        self.assertIsNotNone(await self.session_of(second_cookie))
        self.assertEqual({item["handle"]: item["status"] for item in self.entry(self.target.id)["credentials"]},
                         {first_handle: "revoked", second_handle: "active"})
        self.assertEqual(self.entry(self.target.id)["status"], "active")
        # The revoked passkey no longer signs in (on all synced devices that hold it).
        options = await call(self.surface, "POST", "/api/auth/authentication/options")
        assertion = self.target_key.assertion(payload(options), origin=ORIGIN, rp_id=HOST)
        self.assertEqual(await call(self.surface, "POST", "/api/auth/authentication",
                                    body=json.dumps(assertion).encode()), GENERIC)
        # Its handle is now refused.
        self.assertEqual(await self.admin(
            "POST", f"{PRINCIPALS}/{self.target.id}/credentials/{first_handle}/revoke", {}), GENERIC)


class RefusalTests(AdminRouteFixture):
    async def viewers(self):
        callers = {}
        for name, permissions in (("live-only", (Permission.LIVE_VIEW,)),
                                  ("recordings-only", (Permission.RECORDINGS_VIEW,)),
                                  ("both", (Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))):
            _, key, _ = self.enroll(permissions)
            cookie = await self.sign_in(key)
            callers[name] = (cookie, await self.csrf(cookie))
        principal, key, _ = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        self.store.revoke_principal(principal.id)
        callers["revoked person"] = (cookie, csrf)
        return callers

    async def test_every_route_refuses_every_caller_but_the_owner_identically(self):
        callers = await self.viewers()
        foreign_csrf = self.target_csrf
        cases = {
            "no cookie": dict(cookie=None),
            "forged cookie": dict(cookie=FORGED),
            "no cookie, no csrf": dict(cookie=None, csrf=None),
            "missing csrf": dict(csrf=None),
            "another session's csrf": dict(csrf=foreign_csrf),
            "malformed csrf": dict(csrf=self.owner_csrf[:-1]),
            "repeated csrf": dict(headers=[(b"x-csrf-token", self.owner_csrf.encode())]),
            "csrf in the query": dict(csrf=None, query=b"csrf=" + self.owner_csrf.encode()),
            "query": dict(query=b"x=1"),
            "no origin": dict(origin=None),
            "foreign origin": dict(origin=f"https://{HOST}:8443"),
            "http origin": dict(origin=f"http://{HOST}"),
            "other host": dict(host=f"{HOST}:8443"),
            "lan peer": dict(client=LAN),
            "other proxy identity": dict(identity=OTHER_LOGIN),
            "no proxy identity": dict(identity=None),
            "missing raw_path": dict(application=rewriting(self.surface, raw_path=OMIT)),
            "null raw_path": dict(application=rewriting(self.surface, raw_path=None)),
            "websocket": dict(kind="websocket"),
        }
        for name, (cookie, csrf) in callers.items():
            cases[name] = dict(cookie=cookie, csrf=csrf)
        before = self.snapshot()
        for route, (method, path, body) in self.routes().items():
            for name, options in cases.items():
                if method == "GET" and name in ("missing csrf", "no origin", "csrf in the query",
                                                 "another session's csrf", "malformed csrf", "repeated csrf"):
                    continue  # A1 is a read: no CSRF, an absent Origin allowed
                with self.subTest(route=route, case=name):
                    result = await self.admin(method, path, body, **options)
                    if name == "websocket":
                        self.assertEqual(result, [{"type": "websocket.close", "code": 1008}])
                    else:
                        self.assertEqual(result, GENERIC)
                    if name != "other proxy identity":
                        # (a mismatch is audited by the authorization, rate-limited)
                        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.access_state(), before[0])
        self.assertEqual(self.admin_records(), before[2])
        # The Owner's own requests are still served.
        self.assertEqual(status(await self.admin("GET", PRINCIPALS, csrf=None)), 200)
        self.assertEqual(status(await self.admin(*self.routes()["A3 re-issue"])), 200)

    async def test_closed_gate_and_stop_refuse_every_route(self):
        before = self.snapshot()
        self.close_access()
        for route, (method, path, body) in self.routes().items():
            with self.subTest(route=route, state="closed"):
                self.assertEqual(await self.admin(method, path, body), GENERIC)
        self.assertEqual(self.snapshot(), before)
        self.reopen_access()
        self.access.stop()
        for route, (method, path, body) in self.routes().items():
            with self.subTest(route=route, state="stopped"):
                self.assertEqual(await self.admin(method, path, body), GENERIC)
        self.assertEqual(self.snapshot(), before)

    async def test_bad_path_ids_are_refused_before_any_work(self):
        target = str(self.target.id)
        handle = self.handle(self.target.id)
        before = self.snapshot()
        paths = (f"{PRINCIPALS}/{target.upper()}/revoke",
                 f"{PRINCIPALS}/{target}/credentials/{handle.upper()}/revoke",
                 f"{PRINCIPALS}/{target.replace('-', '')}/revoke",
                 f"{PRINCIPALS}/{target}/revoke/",
                 f"{PRINCIPALS}/{target}/credentials/{b64(self.target_credential.credential_id)}/revoke")
        work = []
        with patch.object(self.store, "session_may_be_current", side_effect=lambda *a, **k: work.append(1)):
            for path in paths:
                with self.subTest(path=path):
                    self.assertEqual(await self.admin("POST", path, {}), GENERIC)
            # Percent-encoded spellings of a valid path (decoded path valid, raw not).
            path = f"{PRINCIPALS}/{target}/revoke"
            for raw in (path.replace("-", "%2D", 1).encode(), path.replace("a", "%61", 1).encode(),
                        path.replace("/revoke", "/%72evoke").encode()):
                with self.subTest(raw=raw):
                    self.assertEqual(await self.admin(
                        "POST", path, {}, application=rewriting(self.surface, raw_path=raw)), GENERIC)
        self.assertEqual(work, [])
        self.assertEqual(self.snapshot(), before)

    async def test_targets_that_do_not_exist_or_are_not_administrable(self):
        _, _, other_credential = self.enroll((Permission.LIVE_VIEW,))
        other_handle = self.handle(other_credential.principal_id)
        owner_handle = self.handle(self.owner.id)
        revoked, _, _ = self.enroll((Permission.LIVE_VIEW,))
        revoked_handle = self.handle(revoked.id)
        self.store.revoke_principal(revoked.id)
        unknown = str(uuid4())
        target = self.target.id
        cases = {
            "unknown principal": self.mutations(unknown, str(uuid4())),
            "the Owner": self.mutations(self.owner.id, owner_handle),
            "revoked principal": self.mutations(revoked.id, revoked_handle),
        }
        cases = {(case, route): request for case, routes in cases.items()
                 for route, request in routes.items() if route != "A2 invite"}
        cases[("unknown handle", "A6")] = ("POST", f"{PRINCIPALS}/{target}/credentials/{uuid4()}/revoke", {})
        cases[("other principal's handle", "A6")] = (
            "POST", f"{PRINCIPALS}/{target}/credentials/{other_handle}/revoke", {})
        cases[("Owner's handle under the target", "A6")] = (
            "POST", f"{PRINCIPALS}/{target}/credentials/{owner_handle}/revoke", {})
        for (case, route), (method, path, body) in cases.items():
            with self.subTest(case=case, route=route):
                state = self.access_state()
                records = self.admin_records()
                self.assertEqual(await self.admin(method, path, body), GENERIC)
                self.assertEqual(self.access_state(), state)
                # One failed record of the request's action, nothing else.
                after = self.admin_records()
                for item in records:
                    after.remove(item)
                self.assertEqual([item[1] for item in after], ["failed"])
        # Everyone's access is as it was.
        self.assertIsNotNone(await self.session_of(self.target_cookie))
        self.assertIsNotNone(await self.session_of(self.owner_cookie))
        self.assertEqual(self.entry(self.owner.id)["credentials"][0]["status"], "active")

    async def test_the_principal_cap_is_the_generic_denial(self):
        for index in range(MAX_PRINCIPALS - 2):  # the Owner and the target exist
            self.store.invite(f"Synthetic {index}", ())
        before = self.access_state()
        result = await self.admin("POST", PRINCIPALS, {"display_name": NAME, "permissions": []})
        self.assertEqual(result, GENERIC)
        self.assertEqual(self.access_state(), before)
        self.assertEqual(self.outcomes(AuditAction.INVITE_PRINCIPAL), [AuditOutcome.FAILED])


class BodyTests(AdminRouteFixture):
    async def test_malformed_bodies_are_refused_before_the_authorization(self):
        target = self.target.id
        handle = self.handle(target)
        empty = ([], "x", 1, None, {"x": 1}, {"": 0})
        invalid = {
            PRINCIPALS: [
                {}, {"display_name": NAME}, {"permissions": []},
                {"display_name": NAME, "permissions": [], "extra": 1},
                {"display_name": "", "permissions": []}, {"display_name": "x" * 65, "permissions": []},
                {"display_name": "bad\nname", "permissions": []}, {"display_name": "bad\x7fname", "permissions": []},
                {"display_name": "bad\x85name", "permissions": []}, {"display_name": 7, "permissions": []},
                # Format (Cf: bidirectional overrides and isolates, zero-width,
                # BOM), line and paragraph separators (Zl, Zp; PR #242 review).
                *({"display_name": f"bad{char}name", "permissions": []}
                  for char in ("\u202e", "\u202a", "\u2066", "\u2069", "\u200b", "\u200d", "\u200e",
                               "\ufeff", "\u2028", "\u2029")),
                {"display_name": None, "permissions": []}, {"display_name": [NAME], "permissions": []},
                {"display_name": NAME, "permissions": ["live:view", "live:view"]},
                {"display_name": NAME, "permissions": ["admin"]},
                {"display_name": NAME, "permissions": ["LIVE:VIEW"]},
                {"display_name": NAME, "permissions": "live:view"},
                {"display_name": NAME, "permissions": None},
                {"display_name": NAME, "permissions": {"live:view": True}},
                {"display_name": NAME, "permissions": [["live:view"]]},
            ] + list(empty),
            f"{PRINCIPALS}/{target}/permissions": [
                {}, {"permission": "live:view"}, {"granted": True},
                {"permission": "live:view", "granted": True, "extra": 1},
                {"permission": "live:view", "granted": 1}, {"permission": "live:view", "granted": "true"},
                {"permission": "live:view", "granted": None}, {"permission": "admin", "granted": True},
                {"permission": ["live:view"], "granted": True}, {"permission": "live:view ", "granted": True},
            ] + list(empty),
            f"{PRINCIPALS}/{target}/invitation": list(empty),
            f"{PRINCIPALS}/{target}/revoke": list(empty),
            f"{PRINCIPALS}/{target}/credentials/{handle}/revoke": list(empty),
        }
        raw = (b"", b"not json", b'{"a":1,"a":1}', b"{} {}", b"{", b'{"display_name":NaN}',
               b'{"permission":"live:view","granted":true,"granted":false}',
               b'{"display_name":"x","display_name":"y","permissions":[]}')
        before = self.snapshot()
        work = []
        with patch.object(self.store, "session_may_be_current", side_effect=lambda *a, **k: work.append(1)):
            for path, bodies in invalid.items():
                for body in bodies:
                    with self.subTest(path=path, body=body):
                        self.assertEqual(await self.admin("POST", path, body), GENERIC)
                for data in raw:
                    with self.subTest(path=path, raw=data):
                        self.assertEqual(await self.admin("POST", path, raw=data), GENERIC)
                for content_type in (None, b"text/plain", b"application/x-www-form-urlencoded"):
                    with self.subTest(path=path, content_type=content_type):
                        body = {"display_name": NAME, "permissions": []} if path == PRINCIPALS else (
                            {"permission": "live:view", "granted": True} if path.endswith("permissions") else {})
                        self.assertEqual(await self.admin("POST", path, body, content_type=content_type), GENERIC)
            # Oversized bodies (each route's own limit).
            for path, limit in ((PRINCIPALS, 2048), (f"{PRINCIPALS}/{target}/permissions", 256),
                                (f"{PRINCIPALS}/{target}/revoke", 2)):
                with self.subTest(path=path, oversized=limit):
                    body = b'{"display_name":"' + b"x" * limit + b'","permissions":[]}'
                    self.assertEqual(await self.admin("POST", path, raw=body), GENERIC)
                    self.assertEqual(await self.admin("POST", path, raw=b"{" + b" " * limit + b"}"), GENERIC)
        self.assertEqual(work, [])
        self.assertEqual(self.snapshot(), before)
        # The well-formed requests still work.
        self.assertEqual(status(await self.admin("POST", f"{PRINCIPALS}/{target}/invitation", {})), 200)

    async def test_a_name_escaped_to_the_limit_fits_the_body_bound(self):
        name = "\U0001F600" * 64  # 64 characters, each escaped as a 12-byte surrogate pair
        body = json.dumps({"display_name": name, "permissions": ["live:view", "recordings:view"]}).encode()
        self.assertLessEqual(len(body), 2048)
        self.assertEqual(status(await self.admin("POST", PRINCIPALS, raw=body)), 200)
        lone = b'{"display_name":"\\ud800","permissions":[]}'
        self.assertEqual(await self.admin("POST", PRINCIPALS, raw=lone), GENERIC)


class StepUpTests(AdminRouteFixture):
    async def test_a_stale_owner_gets_the_fixed_403_with_no_change_and_no_idle_touch(self):
        self.elapse(minutes=6)
        before = self.snapshot()
        for route, (method, path, body) in self.mutations().items():
            with self.subTest(route=route):
                self.assertEqual(await self.admin(method, path, body), STEP_UP)
                self.assertEqual(self.snapshot(), before)
        # The read is OWNER_READ: a stale Owner is served (and touched).
        self.assertEqual(status(await self.admin("GET", PRINCIPALS)), 200)
        # A non-Owner never sees the 403, stale or not.
        self.assertEqual(await self.admin("POST", PRINCIPALS, self.routes()["A2 invite"][2],
                                          cookie=self.target_cookie, csrf=self.target_csrf), GENERIC)
        # Step up, then each operation runs.
        self.assertEqual(status(await self.step_up(self.owner_cookie, self.owner_csrf, self.owner_key)), 204)
        for route, (method, path, body) in self.mutations().items():
            with self.subTest(route=route, step="after step-up"):
                self.assertIn(status(await self.admin(method, path, body)), (200, 204))

    async def test_a_stale_owner_with_wrong_csrf_or_identity_gets_the_generic_denial(self):
        self.elapse(minutes=6)
        method, path, body = self.mutations()["A4 permission"]
        for options in (dict(csrf=self.target_csrf), dict(csrf=None), dict(identity=OTHER_LOGIN),
                        dict(origin=None)):
            with self.subTest(options=sorted(options)):
                self.assertEqual(await self.admin(method, path, body, **options), GENERIC)
        self.close_access()
        self.assertEqual(await self.admin(method, path, body), GENERIC)
        self.reopen_access()
        self.assertEqual(await self.admin(method, path, body), STEP_UP)

    async def test_a_verification_going_stale_before_the_commit_is_the_generic_denial(self):
        """The 403 is decided by the authorization only; a recheck failing at
        the commit (here: the five minutes ran out in between) is a failed
        operation and the generic denial."""
        surface = self.surface
        real = surface._owner_operation

        async def then_age(request, **kwargs):
            context = await real(request, **kwargs)
            self.elapse(minutes=5)
            return context

        method, path, body = self.mutations()["A4 permission"]
        state = self.access_state()
        with patch.object(surface, "_owner_operation", side_effect=then_age):
            self.assertEqual(await self.admin(method, path, body), GENERIC)
        self.assertEqual(self.access_state(), state)
        self.assertEqual(self.outcomes(AuditAction.CHANGE_PRINCIPAL_PERMISSIONS), [AuditOutcome.FAILED])


class GateRaceTests(AdminRouteFixture):
    """A change between the route's authorization and the mutation commit
    refuses the change: nothing changes and one failed record is written."""

    async def restart(self):
        await self.stop_serving()
        await self.start_serving()

    async def interrupted(self, interrupt, *, restart=False, after=None):
        surface = self.surface
        real = surface._owner_operation
        for route, (method, path, body) in self.mutations().items():
            with self.subTest(route=route):
                state = {}

                async def paused(request, **kwargs):
                    context = await real(request, **kwargs)
                    interrupt()
                    state["access"] = self.access_state()
                    state["records"] = self.admin_records()
                    return context

                with patch.object(surface, "_owner_operation", side_effect=paused):
                    result = await self.admin(method, path, body)
                self.assertEqual(result, GENERIC)
                self.assertEqual(self.access_state(), state["access"])
                new = self.admin_records()
                for item in state["records"]:
                    new.remove(item)
                self.assertEqual([item[1] for item in new], ["failed"])
                if restart:
                    await self.restart()
                if after is not None:
                    await after()

    async def test_stop_between_authorization_and_commit(self):
        await self.interrupted(self.access.stop, restart=True)

    async def test_failed_tick_between_authorization_and_commit(self):
        def fail_tick():
            self.access._serving = False  # what run() does when a tick raises
        await self.interrupted(fail_tick, restart=True)

    async def test_close_between_authorization_and_commit(self):
        await self.interrupted(self.close_access, after=self.reopen_access_async)

    async def reopen_access_async(self):
        self.reopen_access()

    async def test_close_and_reopen_between_authorization_and_commit(self):
        def cycle():
            self.close_access()
            self.reopen_access()
        await self.interrupted(cycle)

    async def test_local_recover_between_authorization_and_commit(self):
        # The local recover commits outside the gate (D6): only the
        # in-transaction session re-check refuses the change.
        secrets_ = []

        def recover():
            secret, _ = new_invitation_code()
            secrets_.append(secret)
            recover_owner(self.store, secret, at=self.ceremony_clock())

        async def owner_again():
            # The recovered Owner registers a new passkey and signs in again.
            key = SyntheticAuthenticator()
            creation = self.ceremonies.begin_registration(secrets_[-1], VIEWER)
            self.ceremonies.finish_registration(secrets_[-1], VIEWER,
                                                key.register(creation, origin=ORIGIN, rp_id=HOST))
            self.owner_key = key
            self.owner_cookie = await self.sign_in(key)
            self.owner_csrf = await self.csrf(self.owner_cookie)

        await self.interrupted(recover, after=owner_again)

    async def test_inventory_read_after_a_close_returns_nothing(self):
        surface = self.surface
        real = surface._authorize

        async def then_close(*args, **kwargs):
            authorized = await real(*args, **kwargs)
            self.close_access()
            return authorized

        with patch.object(surface, "_authorize", side_effect=then_close):
            self.assertEqual(await self.admin("GET", PRINCIPALS), GENERIC)
        self.reopen_access()
        with patch.object(surface, "_authorize", side_effect=then_close), \
                patch.object(self.store, "admin_inventory", side_effect=AssertionError("read after close")):
            self.assertEqual(await self.admin("GET", PRINCIPALS), GENERIC)
        self.reopen_access()
        self.assertEqual(status(await self.admin("GET", PRINCIPALS)), 200)


class InventoryRaceTests(AdminRouteFixture):
    """A1 re-checks the Owner session inside its own read transaction (PR
    #242 review): the local recover and revocation commands commit outside
    the gate without moving its epoch, so only that re-check stops an
    inventory reaching a session they ended after the authorization."""

    def us(self):
        return int(self.ceremony_clock().timestamp() * 1_000_000)

    def sql(self, statement, parameters=()):
        with closing(self.database.connect()) as connection:
            connection.execute(statement, parameters)

    async def read_after(self, interrupt):
        surface = self.surface
        real = surface._authorize
        epochs = []

        async def then_interrupt(*args, **kwargs):
            authorized = await real(*args, **kwargs)
            try:
                interrupt()
                epochs.append((authorized.epoch, self.access.epoch()))
            except Exception as error:  # surfaced below, not as a denial
                epochs.append(error)
            return authorized

        before = self.access_state()
        with patch.object(surface, "_authorize", side_effect=then_interrupt):
            result = await self.admin("GET", PRINCIPALS)
        # The gate epoch did not move: only the in-transaction re-check refuses.
        self.assertEqual(len(epochs), 1)
        self.assertEqual(epochs[0][0], epochs[0][1])
        self.assertEqual(result, GENERIC)
        self.assertNotIn(str(self.target.id).encode(), result[1]["body"])
        return before

    async def test_a_local_recover_between_authorization_and_read_returns_nothing(self):
        def recover():
            secret, _ = new_invitation_code()
            recover_owner(self.store, secret, at=self.ceremony_clock())

        await self.read_after(recover)
        self.assertIsNone(await self.session_of(self.owner_cookie))

    async def test_a_session_ended_between_authorization_and_read_returns_nothing(self):
        before = await self.read_after(lambda: self.sql(
            "UPDATE access_sessions SET invalidated_at_us=?, external_identity_binding=NULL WHERE principal_id=?",
            (self.us(), str(self.owner.id))))
        self.assertEqual(self.access_state(), before)

    async def test_a_credential_revoked_between_authorization_and_read_returns_nothing(self):
        await self.read_after(lambda: self.sql(
            "UPDATE access_credentials SET revoked_at_us=? WHERE principal_id=?", (self.us(), str(self.owner.id))))

    async def test_a_generation_advanced_between_authorization_and_read_returns_nothing(self):
        await self.read_after(lambda: self.sql(
            "UPDATE access_deployment_state SET authorization_generation=authorization_generation+1 "
            "WHERE singleton=1"))

    async def test_an_authorization_revision_bump_between_authorization_and_read_returns_nothing(self):
        await self.read_after(lambda: self.sql(
            "UPDATE access_principals SET authorization_revision=authorization_revision+1 WHERE id=?",
            (str(self.owner.id),)))

    async def test_the_recheck_writes_nothing_and_does_not_require_freshness(self):
        self.elapse(minutes=6)  # stale: OWNER_READ still serves the inventory
        rows = self.session_rows()
        surface = self.surface
        real = surface._authorize
        after_authorization = []

        async def capture(*args, **kwargs):
            authorized = await real(*args, **kwargs)
            after_authorization.append(self.session_rows())
            return authorized

        with patch.object(surface, "_authorize", side_effect=capture):
            result = await self.admin("GET", PRINCIPALS)
        self.assertEqual(status(result), 200)
        # Only the authorization's own idle touch; the re-check and the read
        # write nothing.
        self.assertEqual(self.session_rows(), after_authorization[0])
        self.assertNotEqual(after_authorization[0], rows)  # the authorization's touch

    async def test_the_store_recheck_refuses_anything_but_a_session_view(self):
        for view in (object(), "x", 1):
            with self.subTest(view=type(view).__name__):
                with self.assertRaises(AccessValidationError):
                    self.store.admin_inventory(owner_session=view)


class RateLimitTests(AdminRouteFixture):
    """Owner decision 2026-10-13: a coarse per-session limiter for A2-A6."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.access.admin_limiter = admin_rate_limiter(monotonic=self.limit_clock)

    def noop(self, cookie=OMIT, csrf=OMIT):
        # A grant the target already holds: a "requested, no change" record.
        return self.admin("POST", f"{PRINCIPALS}/{self.target.id}/permissions",
                          {"permission": "live:view", "granted": True}, cookie=cookie, csrf=csrf)

    async def test_the_default_shape(self):
        limiter = admin_rate_limiter()
        self.assertEqual((ADMIN_PER_SESSION_CAPACITY, ADMIN_PER_SESSION_REFILL_SECONDS, ADMIN_MAX_SESSIONS),
                         (20, 3.0, 256))
        self.assertEqual((limiter.per_source_capacity, limiter.per_source_refill_seconds,
                          limiter.global_capacity, limiter.max_sources), (20, 3.0, None, 256))

    async def test_a_burst_over_the_limit_is_the_generic_denial_with_nothing_written(self):
        for _ in range(ADMIN_PER_SESSION_CAPACITY):
            self.assertEqual(status(await self.noop()), 204)
        before = self.snapshot()
        work = []
        real_epoch = self.access.epoch

        def epoch(*args, **kwargs):
            work.append("gate")
            return real_epoch(*args, **kwargs)

        with patch.object(self.access, "epoch", side_effect=epoch), \
                patch.object(self.access.administration, "change_permission") as change, \
                patch.object(self.access.administration, "invite") as invite:
            for name, (method, path, body) in self.mutations().items():
                with self.subTest(route=name):
                    self.assertEqual(await self.admin(method, path, body), GENERIC)
        self.assertEqual(work, [])
        change.assert_not_called()
        invite.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.access.admin_limiter.limited, len(self.mutations()))
        # The read is not charged, and the session itself still works.
        self.assertEqual(status(await self.admin("GET", PRINCIPALS)), 200)
        self.assertIsNotNone(await self.session_of(self.owner_cookie))

    async def test_the_bucket_refills_one_change_every_three_seconds(self):
        for _ in range(ADMIN_PER_SESSION_CAPACITY):
            self.assertEqual(status(await self.noop()), 204)
        self.assertEqual(await self.noop(), GENERIC)
        self.limit_clock.value += ADMIN_PER_SESSION_REFILL_SECONDS - 0.5
        self.assertEqual(await self.noop(), GENERIC)
        self.limit_clock.value += 0.5
        self.assertEqual(status(await self.noop()), 204)
        self.assertEqual(await self.noop(), GENERIC)
        self.limit_clock.value += ADMIN_PER_SESSION_REFILL_SECONDS * ADMIN_PER_SESSION_CAPACITY
        for _ in range(ADMIN_PER_SESSION_CAPACITY):
            self.assertEqual(status(await self.noop()), 204)
        self.assertEqual(await self.noop(), GENERIC)

    async def test_sessions_have_separate_buckets(self):
        # A non-Owner session is refused by the Owner pre-check before it is
        # charged (PR #242 review): it takes no slot and spends nothing.
        for _ in range(ADMIN_PER_SESSION_CAPACITY + 5):
            self.assertEqual(await self.noop(cookie=self.target_cookie, csrf=self.target_csrf), GENERIC)
        self.assertEqual((self.access.admin_limiter.sources(), self.access.admin_limiter.limited), (0, 0))
        for _ in range(ADMIN_PER_SESSION_CAPACITY):
            self.assertEqual(status(await self.noop()), 204)
        self.assertEqual(await self.noop(), GENERIC)
        # A second Owner session (the Owner signed in again) has its own bucket.
        cookie = await self.sign_in(self.owner_key)
        csrf = await self.csrf(cookie)
        self.assertEqual(status(await self.noop(cookie=cookie, csrf=csrf)), 204)
        self.assertEqual(await self.noop(), GENERIC)

    async def test_non_owner_sessions_cannot_fill_the_table_against_the_owner(self):
        # PR #242 review (重要): with a small table, many non-Owner sessions
        # (each with its own CSRF token) hammering A2-A6 never take a slot,
        # so the Owner's new session can still make its change.
        self.access.admin_limiter = admin_rate_limiter(max_sources=2, monotonic=self.limit_clock)
        sessions = [(self.target_cookie, self.target_csrf)]
        for permissions in ((), (Permission.LIVE_VIEW,), (Permission.RECORDINGS_VIEW,),
                            (Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW)):
            _, key, _ = self.enroll(permissions)
            for _ in range(2):
                cookie = await self.sign_in(key)
                sessions.append((cookie, await self.csrf(cookie)))
        self.assertGreater(len(sessions), self.access.admin_limiter.max_sources)
        before = self.snapshot()
        work = []
        real_epoch = self.access.epoch

        def epoch(*args, **kwargs):
            work.append("gate")
            return real_epoch(*args, **kwargs)

        with patch.object(self.access, "epoch", side_effect=epoch):
            for cookie, csrf in sessions:
                for name, (method, path, body) in self.mutations().items():
                    for _ in range(3):
                        with self.subTest(route=name):
                            self.assertEqual(await self.admin(method, path, body, cookie=cookie, csrf=csrf),
                                             GENERIC)
        # Refused before the charge and before the gate; nothing written.
        self.assertEqual(work, [])
        self.assertEqual((self.access.admin_limiter.sources(), self.access.admin_limiter.limited), (0, 0))
        self.assertEqual(self.snapshot(), before)
        # The Owner's sessions (an existing one and a new one) each get a slot.
        self.assertEqual(status(await self.noop()), 204)
        cookie = await self.sign_in(self.owner_key)
        csrf = await self.csrf(cookie)
        for name, (method, path, body) in self.mutations().items():
            with self.subTest(owner_route=name):
                self.assertIn(status(await self.admin(method, path, body, cookie=cookie, csrf=csrf)), (200, 204))
        self.assertEqual(self.access.admin_limiter.sources(), 2)

    async def test_a_stale_owner_step_up_answer_consumes_one_token(self):
        # Documented (PR #242 review proposal 4): the charge precedes the
        # in-gate freshness decision.
        self.access.admin_limiter = admin_rate_limiter(monotonic=self.limit_clock)
        self.elapse(minutes=6)
        for _ in range(ADMIN_PER_SESSION_CAPACITY):
            self.assertEqual(await self.noop(), STEP_UP)
        self.assertEqual(await self.noop(), GENERIC)
        self.assertEqual(self.access.admin_limiter.limited, 1)

    async def test_forged_or_absent_cookies_are_never_charged(self):
        for _ in range(ADMIN_PER_SESSION_CAPACITY * 3):
            self.assertEqual(await self.noop(cookie=FORGED), GENERIC)
            self.assertEqual(await self.noop(cookie=None), GENERIC)
        for _ in range(ADMIN_PER_SESSION_CAPACITY * 2):
            self.assertEqual(status(await self.admin("GET", PRINCIPALS)), 200)
        self.assertEqual((self.access.admin_limiter.sources(), self.access.admin_limiter.limited), (0, 0))
        for _ in range(ADMIN_PER_SESSION_CAPACITY):
            self.assertEqual(status(await self.noop()), 204)

    async def test_the_key_is_not_logged_and_not_the_identity(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Capture(level=logging.DEBUG)
        logger = logging.getLogger("app.auth.rate_limit")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        for _ in range(ADMIN_PER_SESSION_CAPACITY + 2):
            await self.noop()
        self.assertTrue(records)
        token = self.owner_cookie.split("=", 1)[1]
        for record in records:
            text = repr(record.__dict__)
            for value in (token, VIEWER, self.owner_csrf):
                self.assertNotIn(value, text)
        # One bucket for the one session charged (keyed per session).
        self.assertEqual(self.access.admin_limiter.sources(), 1)

    def test_the_admin_limiter_cannot_be_shared(self):
        default = HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                              ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                                           clock=self.ceremony_clock),
                              reservation=self.check)
        limiter = default.admin_limiter
        self.assertEqual((limiter.per_source_capacity, limiter.per_source_refill_seconds,
                          limiter.global_capacity), (20, 3.0, None))
        self.assertEqual(len({id(default.rate_limiter), id(default.redemption_limiter),
                              id(default.step_up_limiter), id(limiter)}), 4)
        shared = SourceRateLimiter()
        for limiters in ({"rate_limiter": shared, "admin_limiter": shared},
                         {"redemption_limiter": shared, "admin_limiter": shared},
                         {"step_up_limiter": shared, "admin_limiter": shared},
                         {"admin_limiter": object()}):
            with self.subTest(limiters=sorted(limiters)):
                ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                               clock=self.ceremony_clock)
                with self.assertRaises(HumanAccessUnavailable):
                    HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                                ceremonies=ceremonies, reservation=self.check, **limiters)


class CommittedResponseTests(AdminRouteFixture):
    """Nothing that can refuse runs after an A2 / A3 commit (PR #242 review)."""

    async def test_a_naive_expiry_is_refused_before_the_commit(self):
        for name, method_name in (("A2 invite", "invite_with_invitation_on"),
                                  ("A3 re-issue", "reissue_invitation_on")):
            with self.subTest(route=name):
                real = getattr(self.store, method_name)
                method, path, body = self.mutations()[name]
                state = self.access_state()
                failed = len([outcome for outcome in self.outcomes(
                    AuditAction.INVITE_PRINCIPAL if name == "A2 invite"
                    else AuditAction.ISSUE_PRINCIPAL_INVITATION) if outcome is AuditOutcome.FAILED])
                with patch.object(self.store, method_name,
                                  side_effect=lambda *a, **k: real(*a, **k).replace(tzinfo=None)):
                    self.assertEqual(await self.admin(method, path, body), GENERIC)
                self.assertEqual(self.access_state(), state)
                action = AuditAction.INVITE_PRINCIPAL if name == "A2 invite" else AuditAction.ISSUE_PRINCIPAL_INVITATION
                self.assertEqual(len([outcome for outcome in self.outcomes(action)
                                      if outcome is AuditOutcome.FAILED]), failed + 1)
                self.assertEqual(status(await self.admin(method, path, body)), 200)


class HygieneTests(AdminRouteFixture):
    async def test_no_code_name_handle_credential_or_identity_reaches_a_log_or_the_audit(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Capture(level=logging.DEBUG)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, previous)
        secret_name = "Synthetic secret display name"
        invited = payload(await self.admin("POST", PRINCIPALS, {"display_name": secret_name,
                                                                "permissions": ["live:view"]}))
        reissued = payload(await self.admin("POST", f"{PRINCIPALS}/{invited['principal_id']}/invitation", {}))
        key = await self.redeem(reissued["code"])
        handle = self.handle(invited["principal_id"])
        credential_id = key.credential_id
        await self.admin("POST", f"{PRINCIPALS}/{invited['principal_id']}/permissions",
                         {"permission": "recordings:view", "granted": True})
        await self.admin("POST", f"{PRINCIPALS}/{self.owner.id}/revoke", {})
        await self.admin("POST", f"{PRINCIPALS}/{invited['principal_id']}/credentials/{handle}/revoke", {})
        await self.admin("POST", f"{PRINCIPALS}/{invited['principal_id']}/revoke", {})
        await self.admin("POST", PRINCIPALS, {"display_name": "bad\nname", "permissions": []})
        await self.admin("GET", PRINCIPALS, identity=OTHER_LOGIN)
        values = [invited["code"], reissued["code"], secret_name, handle, VIEWER, OTHER_LOGIN,
                  b64(credential_id), credential_id.hex(), self.owner_csrf,
                  self.owner_cookie.split("=", 1)[1]]
        formatter = SafeJsonFormatter()
        for record in records:
            text = " ".join((repr(record.__dict__), formatter.format(record)))
            for value in values:
                self.assertNotIn(value, text)
        audit = repr(self.audit.list_records(limit=1000))
        for value in values:
            self.assertNotIn(value, audit)
        with closing(self.database.connect()) as connection:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(security_admin_audit_records)")]
            rows = repr(connection.execute("SELECT * FROM security_admin_audit_records").fetchall())
        self.assertTrue(columns)
        for value in values:
            self.assertNotIn(value, rows)
