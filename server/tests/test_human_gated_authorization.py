"""Issue #10 phase 2 S1 and Issue #228: gated authorization, CSRF, sign-out.

Synthetic only: software authenticators, synthetic ``/proc/net`` rows, a
temporary SQLite database and the in-process ASGI driver of
``test_human_surface``. Every identity is an invented ``.invalid`` value.
Mock only: no browser, proxy, Tailscale or real authenticator is involved.
"""

import asyncio
import base64
from contextlib import closing
import hmac
import logging
import re
import secrets
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from app.auth import human_surface as surface_module
from app.auth import session_binding as binding_module
from app.auth.human_surface import (
    AUTHENTICATION_OPTIONS_PATH, AUTHENTICATION_PATH, ROUTES, SESSION_COOKIE, SESSION_PATH,
    SIGN_OUT_PATH, HumanAccess, HumanAccessAlreadyRunning, HumanAccessConfiguration,
    HumanAccessState, HumanAccessUnavailable, Route, ServingGate, _Denied,
    match_route, parse_query,
)
from app.auth.model import AccessValidationError, Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.reservation import DAILY_SECONDS, HumanAccessClosed
from app.auth.session_binding import SessionBindingKey
from app.auth.store import Requirement, SessionView, StepUpRequired
from app.logging import Event, SafeJsonFormatter

from tests.test_hostname_reservation import Resolver, checker
from tests.test_human_surface import (
    HOST, ORIGIN, OTHER_LOGIN, VIEWER, HumanSurfaceFixture, call, header, payload, status,
)


SIGN_OUT_AUDIT = "SELECT count(*) FROM security_admin_audit_records WHERE action='sign_out_principal'"
CLEARED = (SESSION_COOKIE + "=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict").encode()
GENERIC = [
    {"type": "http.response.start", "status": 404, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", b"22"),
        (b"cache-control", b"no-store"),
    ]},
    {"type": "http.response.body", "body": b'{"detail":"Not Found"}'},
]
STEP_UP = [
    {"type": "http.response.start", "status": 403, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", b"29"),
        (b"cache-control", b"no-store"),
    ]},
    {"type": "http.response.body", "body": b'{"detail":"step_up_required"}'},
]
SESSION_REQUIREMENTS = (Requirement.SESSION, Requirement.LIVE, Requirement.RECORDINGS,
                        Requirement.OWNER_READ, Requirement.OWNER_OP)


class GatedFixture(HumanSurfaceFixture):
    def token(self, cookie):
        return base64.urlsafe_b64decode(cookie.split("=", 1)[1] + "=")

    async def csrf(self, cookie):
        result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
        self.assertEqual(status(result), 200)
        return payload(result)["csrf"]

    async def sign_out(self, cookie, csrf, **options):
        headers = list(options.pop("headers", ()))
        if csrf is not None:
            headers.append((b"x-csrf-token", csrf.encode()))
        return await call(self.surface, "POST", SIGN_OUT_PATH, cookie=cookie, headers=headers,
                          content_type=None, **options)

    def close_access(self):
        """A check closes access without an exposure: nothing is revoked."""
        self.check._resolver.answer = OSError("synthetic resolver failure")
        self.clock.value += DAILY_SECONDS
        self.assertFalse(self.check.tick().open)

    def reopen_access(self):
        self.check._resolver.answer = Resolver().answer
        self.clock.value += DAILY_SECONDS
        self.assertTrue(self.check.tick().open)

    def session_rows(self):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(
                "SELECT id, last_seen_at_us, idle_expires_at_us, invalidated_at_us, "
                "external_identity_binding IS NULL FROM access_sessions ORDER BY id")]

    def audit_rows(self):
        return self.count("SELECT count(*) FROM security_admin_audit_records")

    def gated(self):
        epoch = self.access.epoch()
        return lambda: self.access.admit(epoch)


class RequirementTests(GatedFixture):
    async def test_requirements_are_enforced_server_side(self):
        _, live_key, _ = self.enroll((Permission.LIVE_VIEW,))
        _, recordings_key, _ = self.enroll((Permission.RECORDINGS_VIEW,))
        _, owner_key, _ = self.enroll(owner=True)
        live = self.token(await self.sign_in(live_key))
        recordings = self.token(await self.sign_in(recordings_key))
        owner = self.token(await self.sign_in(owner_key))
        expected = {
            live: {Requirement.SESSION, Requirement.LIVE},
            recordings: {Requirement.SESSION, Requirement.RECORDINGS},
            owner: set(SESSION_REQUIREMENTS),
        }
        for token, allowed in expected.items():
            for requirement in SESSION_REQUIREMENTS:
                with self.subTest(allowed=sorted(item.value for item in allowed), requirement=requirement):
                    if requirement in allowed:
                        view = self.store.authorize_request(token, VIEWER, requirement, admit=self.gated())
                        self.assertIsInstance(view, SessionView)
                    else:
                        # A non-owner on an Owner requirement is the generic denial, never step-up.
                        with self.assertRaises(AccessValidationError) as raised:
                            self.store.authorize_request(token, VIEWER, requirement, admit=self.gated())
                        self.assertIs(type(raised.exception), AccessValidationError)
                        self.assertEqual(str(raised.exception), "access is unavailable")

    async def test_only_a_stale_owner_gets_step_up_and_only_for_owner_operations(self):
        _, owner_key, _ = self.enroll(owner=True)
        owner = self.token(await self.sign_in(owner_key))
        self.ceremony_clock.advance(minutes=6)
        view = self.store.authorize_request(owner, VIEWER, Requirement.OWNER_READ, admit=self.gated())
        self.assertEqual(view.role.value, "owner")
        with self.assertRaises(StepUpRequired):
            self.store.authorize_request(owner, VIEWER, Requirement.OWNER_OP, admit=self.gated())
        # The same stale session presented with another login, or after
        # revocation, is the generic denial.
        with self.assertRaises(AccessValidationError) as raised:
            self.store.authorize_request(owner, OTHER_LOGIN, Requirement.OWNER_OP, admit=self.gated())
        self.assertIs(type(raised.exception), AccessValidationError)

    def test_pre_credential_and_ungated_requests_are_refused(self):
        token = secrets.token_bytes(32)
        for requirement, admit in ((Requirement.PRE_CREDENTIAL, self.gated()), ("session", self.gated()),
                                   (Requirement.SESSION, None)):
            with self.subTest(requirement=requirement, admit=admit), \
                    patch.object(self.store, "_transaction", side_effect=AssertionError("no read")):
                with self.assertRaises(AccessValidationError):
                    self.store.authorize_request(token, VIEWER, requirement, admit=admit)

    async def test_view_hides_the_credential_identifier(self):
        _, key, credential = self.enroll()
        view = self.store.authorize_request(self.token(await self.sign_in(key)), VIEWER,
                                            Requirement.SESSION, admit=self.gated())
        self.assertEqual(view.credential_id, credential.credential_id)
        self.assertNotIn(repr(credential.credential_id), repr(view))
        self.assertNotIn("credential_id", repr(view))


class CloseBetweenEpochAndCommitTests(GatedFixture):
    async def test_each_requirement_refuses_and_writes_nothing(self):
        _, owner_key, _ = self.enroll(owner=True)
        owner = self.token(await self.sign_in(owner_key))
        for requirement in SESSION_REQUIREMENTS:
            with self.subTest(requirement=requirement):
                # Positive control under a current epoch.
                self.store.authorize_request(owner, VIEWER, requirement, admit=self.gated())
                epoch = self.access.epoch()
                self.close_access()
                before = (self.database.path.read_bytes(), self.admission.admitted)
                with self.assertRaises(HumanAccessClosed):
                    self.store.authorize_request(owner, VIEWER, requirement,
                                                 admit=lambda: self.access.admit(epoch))
                self.assertEqual((self.database.path.read_bytes(), self.admission.admitted), before)
                self.reopen_access()
                # Reopened: the old epoch stays refused, a new one is served.
                with self.assertRaises(HumanAccessClosed):
                    self.store.authorize_request(owner, VIEWER, requirement,
                                                 admit=lambda: self.access.admit(epoch))
                self.store.authorize_request(owner, VIEWER, requirement, admit=self.gated())

    async def test_sign_out_after_a_close_writes_nothing(self):
        principal, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        token = self.token(cookie)
        epoch = self.access.epoch()
        view = self.store.authorize_request(token, VIEWER, Requirement.SESSION,
                                            admit=lambda: self.access.admit(epoch))
        self.close_access()
        before = (self.database.path.read_bytes(), self.audit_rows())
        with self.assertRaises(HumanAccessClosed):
            self.store.sign_out(view, admit=lambda: self.access.admit(epoch))
        self.assertEqual((self.database.path.read_bytes(), self.audit_rows()), before)
        self.reopen_access()
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)

    async def test_http_sign_out_with_a_close_after_the_epoch_is_denied(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        rows = self.session_rows()
        original = self.check.epoch

        def close_after_epoch():
            epoch = original()
            self.close_access()
            return epoch

        with patch.object(self.check, "epoch", side_effect=close_after_epoch):
            result = await self.sign_out(cookie, csrf)
        self.assertEqual(result, GENERIC)
        self.assertEqual(self.session_rows(), rows)
        self.assertEqual(self.count(SIGN_OUT_AUDIT), 0)
        self.reopen_access()
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)


class CsrfAndSignOutTests(GatedFixture):
    async def test_sign_out_ends_the_session_clears_the_cookie_and_audits_the_principal(self):
        principal, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        result = await self.sign_out(cookie, csrf)
        self.assertEqual(status(result), 204)
        self.assertEqual(result[1]["body"], b"")
        self.assertEqual(header(result, b"set-cookie"), [CLEARED])
        self.assertEqual(header(result, b"cache-control"), [b"no-store"])
        ((invalidated, cleared),) = [(row[3], row[4]) for row in self.session_rows()]
        self.assertIsNotNone(invalidated)
        self.assertTrue(cleared)
        records = [record for record in self.audit.list_records() if record.action.value == "sign_out_principal"]
        self.assertEqual([(r.actor_category.value, r.target_logical_id, r.outcome.value) for r in records],
                         [("invited_user", principal.id, "succeeded")])
        # The Back button or an old copy of the cookie: the generic denial,
        # for the session read and for a second sign-out alike.
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), GENERIC)
        self.assertEqual(await self.sign_out(cookie, csrf), GENERIC)
        self.assertEqual(self.count(SIGN_OUT_AUDIT), 1)

    async def test_owner_sign_out_is_audited_as_the_owner(self):
        owner, key, _ = self.enroll(owner=True)
        cookie = await self.sign_in(key)
        self.assertEqual(status(await self.sign_out(cookie, await self.csrf(cookie))), 204)
        (record,) = [record for record in self.audit.list_records() if record.action.value == "sign_out_principal"]
        self.assertEqual((record.actor_category.value, record.target_logical_id), ("owner", owner.id))

    async def test_missing_wrong_or_foreign_csrf_is_refused_and_writes_nothing(self):
        _, key, _ = self.enroll()
        _, other_key, _ = self.enroll((Permission.RECORDINGS_VIEW,))
        cookie = await self.sign_in(key)
        other = await self.sign_in(other_key)
        csrf, foreign = await self.csrf(cookie), await self.csrf(other)
        self.assertNotEqual(csrf, foreign)
        rows = self.session_rows()
        audits = self.audit_rows()
        cases = {
            "missing": dict(csrf=None),
            "malformed": dict(csrf=csrf[:-1]),
            "padded": dict(csrf=csrf + "="),
            "random": dict(csrf=secrets.token_urlsafe(32)),
            "other session": dict(csrf=foreign),
            "repeated": dict(csrf=csrf, headers=[(b"x-csrf-token", csrf.encode())]),
            "in a query": dict(csrf=None, query=b"csrf=" + csrf.encode()),
            "no origin": dict(csrf=csrf, origin=None),
            "foreign origin": dict(csrf=csrf, origin=f"https://{HOST}:8443"),
            "body": dict(csrf=csrf, body=b"x"),
        }
        for name, options in cases.items():
            with self.subTest(case=name):
                options = dict(options)
                self.assertEqual(await self.sign_out(cookie, options.pop("csrf"), **options), GENERIC)
        self.assertEqual(self.session_rows(), rows)
        self.assertEqual(self.audit_rows(), audits)
        # Both sessions still work, and the right token signs out only its own.
        self.assertEqual(status(await self.sign_out(cookie, csrf)), 204)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=other)), 200)

    async def test_csrf_check_happens_inside_the_gated_transaction(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        token = self.token(cookie)
        rows = self.session_rows()
        with self.assertRaises(AccessValidationError):
            self.store.authorize_request(token, VIEWER, Requirement.SESSION, admit=self.gated(),
                                         csrf=secrets.token_urlsafe(32))
        # Refused before the idle touch.
        self.assertEqual(self.session_rows(), rows)
        self.ceremony_clock.advance(minutes=1)
        view = self.store.authorize_request(token, VIEWER, Requirement.SESSION, admit=self.gated(),
                                            csrf=self.store.csrf_token(UUID(rows[0][0])))
        self.assertIsInstance(view, SessionView)
        self.assertNotEqual(self.session_rows(), rows)

    async def test_sign_out_is_refused_while_access_is_closed_and_the_session_survives(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        self.close_access()
        self.assertEqual(await self.sign_out(cookie, csrf), GENERIC)
        self.assertEqual(self.count(SIGN_OUT_AUDIT), 0)
        self.reopen_access()
        self.assertEqual(status(await self.sign_out(cookie, csrf)), 204)

    async def test_shared_machine_sign_out_then_the_next_person(self):
        """MANUAL_TEST J in mock form: one browser profile behind the shared
        login; the first person signs out, the next signs in with their own
        passkey, and the first cookie stays refused."""
        _, first_key, _ = self.enroll((Permission.LIVE_VIEW,))
        _, second_key, _ = self.enroll((Permission.RECORDINGS_VIEW,))
        first = await self.sign_in(first_key)
        self.assertEqual(status(await self.sign_out(first, await self.csrf(first))), 204)
        second = await self.sign_in(second_key)
        result = await call(self.surface, "GET", SESSION_PATH, cookie=second)
        self.assertEqual(payload(result)["permissions"], ["recordings:view"])
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=first), GENERIC)

    async def test_failed_audit_append_rolls_the_sign_out_back(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        lost = self.store.undelivered_audit_records
        with patch.object(self.audit, "append_on", side_effect=RuntimeError("synthetic append failure")):
            self.assertEqual(await self.sign_out(cookie, csrf), GENERIC)
        self.assertEqual(self.store.undelivered_audit_records, lost + 1)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)


def view_id(case, token):
    """The session id of ``token`` as the store sees it (test helper)."""
    return case.store.authorize_request(token, VIEWER, Requirement.SESSION, admit=case.gated()).session_id


class CsrfTokenTests(unittest.TestCase):
    def test_token_is_per_session_per_key_and_domain_separated(self):
        key, other = SessionBindingKey.generate(), SessionBindingKey.generate()
        first, second = uuid4(), uuid4()
        token = key.csrf_token(first)
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(token, key.csrf_token(first))
        self.assertNotEqual(token, key.csrf_token(second))
        self.assertNotEqual(token, other.csrf_token(first))
        # Never a proxy-identity binding of the same key.
        self.assertNotEqual(base64.urlsafe_b64decode(token + "="), key.bind(str(first)))
        self.assertTrue(key.csrf_matches(first, token))
        for presented in (None, b"x", token.encode(), token[:-1], token + "A", other.csrf_token(first),
                          key.csrf_token(second), " " + token[1:]):
            with self.subTest(presented=presented):
                self.assertFalse(key.csrf_matches(first, presented))
        self.assertFalse(key.csrf_matches(str(first), token))
        self.assertNotIn(token, repr(key))

    def test_comparison_is_constant_time(self):
        key, session = SessionBindingKey.generate(), uuid4()
        token = key.csrf_token(session)
        with patch.object(binding_module.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            self.assertTrue(key.csrf_matches(session, token))
            self.assertFalse(key.csrf_matches(session, "A" * 43))
        self.assertEqual(compare.call_count, 2)


class RouteTableTests(GatedFixture):
    def test_route_invariants(self):
        pattern = re.compile("/api/synthetic")
        for method, requirement, mutating, csrf in (
                ("GET", Requirement.SESSION, True, False),
                ("POST", Requirement.SESSION, False, False),
                ("POST", Requirement.SESSION, True, False),
                ("POST", Requirement.PRE_CREDENTIAL, True, True),
                ("GET", Requirement.SESSION, False, True)):
            with self.subTest(method=method, mutating=mutating, csrf=csrf), self.assertRaises(ValueError):
                Route(method, pattern, requirement, "_x", mutating=mutating, csrf=csrf, body_limit=0)
        with self.assertRaises(ValueError):
            Route("GET", pattern, Requirement.SESSION, "_x", mutating=False, csrf=False, body_limit=0,
                  query=(("a", pattern), ("a", pattern)))
        for route in ROUTES:
            with self.subTest(route=route.path.pattern):
                self.assertEqual(route.query, ())
                if route.mutating and route.requirement is not Requirement.PRE_CREDENTIAL:
                    self.assertTrue(route.csrf)

    def test_query_allowlist_is_strict(self):
        route = Route("GET", re.compile("/api/synthetic"), Requirement.RECORDINGS, "_x", mutating=False,
                      csrf=False, body_limit=0,
                      query=(("since", re.compile(r"[0-9]{1,200}")), ("source", re.compile(r"[a-f0-9-]{36}"))))
        source = str(uuid4())
        self.assertEqual(parse_query(route, b""), {})
        self.assertEqual(parse_query(route, b"since=12&source=" + source.encode()),
                         {"since": "12", "source": source})
        for raw in (b"since=1&since=2", b"other=1", b"since", b"since=", b"since=%31", b"since=1+2",
                    b"since=" + b"1" * 129, b"since=1&" + b"x" * 600, "since=١".encode(),
                    b"&since=1", b"since=1&", b"Since=1", "since=1".encode("utf-16"), "since=1"):
            with self.subTest(raw=raw[:24]), self.assertRaises(_Denied):
                parse_query(route, raw)

    async def test_every_mounted_route_refuses_a_query_and_a_re_encoded_path(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        for route in ROUTES:
            path = route.path.pattern.replace("\\", "")
            with self.subTest(path=path):
                headers = [(b"x-csrf-token", csrf.encode())]
                self.assertEqual(await call(self.surface, route.method, path, cookie=cookie, headers=headers,
                                            query=b"x=1"), GENERIC)
        # A percent-encoded spelling of a mounted path is not that path.
        scope_path = SESSION_PATH
        encoded = await self.raw_call(scope_path, b"/api/%73ession", cookie)
        self.assertEqual(encoded, GENERIC)
        self.assertIsNone(match_route({"method": "GET", "path": "/api/session", "raw_path": b"/api/session/"}))
        self.assertIsNone(match_route({"method": "GET", "path": "/api/séssion", "raw_path": None}))
        self.assertIsNotNone(match_route({"method": "GET", "path": SESSION_PATH, "raw_path": SESSION_PATH.encode()}))
        # Issue #232 item 2: without raw_path nothing matches (fail closed).
        self.assertIsNone(match_route({"method": "GET", "path": SESSION_PATH, "raw_path": None}))
        self.assertIsNone(match_route({"method": "GET", "path": SESSION_PATH}))
        self.assertIsNone(match_route({"method": "GET", "path": SESSION_PATH, "raw_path": SESSION_PATH}))
        self.assertEqual(await self.raw_call(SESSION_PATH, None, cookie), GENERIC)
        self.assertEqual(await self.raw_call(SESSION_PATH, self.OMIT, cookie), GENERIC)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)

    OMIT = object()

    async def raw_call(self, path, raw_path, cookie):
        sent = []
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
            "method": "GET", "path": path, "raw_path": raw_path, "query_string": b"", "root_path": "",
            "headers": [(b"host", HOST.encode()), (b"origin", ORIGIN.encode()),
                        (b"tailscale-user-login", VIEWER.encode()), (b"cookie", cookie.encode())],
            "client": ("127.0.0.1", 40000), "server": ("127.0.0.1", 8080),
        }
        if raw_path is self.OMIT:
            del scope["raw_path"]

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await self.surface(scope, receive, send)
        return sent


class StepUpResponseTests(GatedFixture):
    """The fixed 403 of Owner decision D3, through a synthetic OWNER_OP route
    (S1 mounts none; S3/S4 will)."""

    async def probe(self, cookie, csrf):
        route = Route("POST", re.compile("/api/synthetic/owner-operation"), Requirement.OWNER_OP,
                      "_synthetic_owner_operation", mutating=True, csrf=True, body_limit=2)
        surface = self.surface

        async def handler(request):
            await surface._authorize(request, Requirement.OWNER_OP)
            await request.send({"type": "http.response.start", "status": 204, "headers": []})
            await request.send({"type": "http.response.body", "body": b""})

        surface._synthetic_owner_operation = handler
        try:
            with patch.object(surface_module, "ROUTES", ROUTES + (route,)):
                return await call(surface, "POST", "/api/synthetic/owner-operation", cookie=cookie,
                                  headers=[(b"x-csrf-token", csrf.encode())], content_type=None)
        finally:
            del surface._synthetic_owner_operation

    async def test_stale_owner_gets_the_fixed_403_and_everyone_else_the_generic_denial(self):
        _, owner_key, _ = self.enroll(owner=True)
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        owner = await self.sign_in(owner_key)
        viewer = await self.sign_in(viewer_key)
        owner_csrf, viewer_csrf = await self.csrf(owner), await self.csrf(viewer)
        self.assertEqual(status(await self.probe(owner, owner_csrf)), 204)
        self.ceremony_clock.advance(minutes=6)
        self.assertEqual(await self.probe(owner, owner_csrf), STEP_UP)
        # Not the Owner, the wrong CSRF token, or a closed gate: generic.
        self.assertEqual(await self.probe(viewer, viewer_csrf), GENERIC)
        self.assertEqual(await self.probe(owner, viewer_csrf), GENERIC)
        self.close_access()
        self.assertEqual(await self.probe(owner, owner_csrf), GENERIC)
        self.reopen_access()
        self.assertEqual(await self.probe(owner, owner_csrf), STEP_UP)


class ServingGateTests(GatedFixture):
    """Issue #228 item 1: a request already past the entry is refused after
    ``stop()`` or a failed tick (the probe from the PR #219 review)."""

    async def restart(self):
        await self.stop_serving()
        await self.start_serving()

    async def test_in_flight_session_read_is_denied_after_stop_or_a_failed_tick(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        real_pre_check = self.store.session_may_be_current
        real_epoch = self.check.epoch

        def stop():
            self.access.stop()

        def fail_tick():
            # What run() does when a periodic tick raises.
            self.access._serving = False

        for name, interrupt in (("stop", stop), ("tick failure", fail_tick)):
            for point in ("after the pre-check", "after the epoch"):
                with self.subTest(interrupt=name, point=point):
                    self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)
                    rows = self.session_rows()
                    self.ceremony_clock.advance(seconds=10)
                    if point == "after the pre-check":
                        def pre_check(token, **kwargs):
                            result = real_pre_check(token, **kwargs)
                            interrupt()
                            return result
                        patcher = patch.object(self.store, "session_may_be_current", side_effect=pre_check)
                    else:
                        def epoch():
                            result = real_epoch()
                            interrupt()
                            return result
                        patcher = patch.object(self.check, "epoch", side_effect=epoch)
                    with patcher:
                        result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
                    self.assertEqual(result, GENERIC)
                    # No idle touch committed.
                    self.assertEqual(self.session_rows(), rows)
                    await self.restart()

    async def test_in_flight_ceremony_is_denied_after_stop(self):
        challenges = self.count("SELECT count(*) FROM access_webauthn_challenges")
        real = self.ceremonies._challenge

        def challenge():
            value = real()
            self.access.stop()
            return value

        with patch.object(self.ceremonies, "_challenge", side_effect=challenge):
            result = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        self.assertEqual(result, GENERIC)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), challenges)

    async def test_stopped_gate_refuses_every_entry(self):
        epoch = self.access.epoch()
        self.assertIsNotNone(epoch)
        with self.access.admit(epoch):
            pass
        self.access.stop()
        self.assertIsNone(self.access.epoch())
        self.assertIsNone(self.access.gate.epoch())
        with self.assertRaises(HumanAccessClosed):
            with self.access.admit(epoch):
                self.fail("admitted after stop()")
        # The reservation itself is still open: only this composition stopped.
        self.assertTrue(self.check.access_open)

    def test_ceremonies_serve_exactly_one_composition(self):
        self.assertIsInstance(self.ceremonies.session_gate, ServingGate)
        self.assertIs(self.ceremonies.session_gate.reservation, self.check)
        with self.assertRaises(HumanAccessUnavailable):
            HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                        ceremonies=self.ceremonies, reservation=self.check)
        fresh = PasskeyCeremonies(self.store, self.rp, session_gate=self.check, clock=self.ceremony_clock)
        other, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        for gate in (None, object(), other, SimpleGate(other)):
            with self.subTest(gate=gate), self.assertRaises(ValueError):
                fresh.guard_session_gate(gate)
        self.assertIs(fresh.session_gate, self.check)
        # Once guarded, the ceremonies no longer compose with any access.
        fresh.guard_session_gate(SimpleGate(self.check))
        with self.assertRaises(HumanAccessUnavailable):
            HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                        ceremonies=fresh, reservation=self.check)


class SimpleGate:
    """A wrapper exposing ``reservation`` (stand-in for ``ServingGate``)."""

    def __init__(self, reservation):
        self.reservation = reservation

    def epoch(self):
        return self.reservation.epoch()

    def admit(self, epoch):
        return self.reservation.admit(epoch)


class RunLifecycleTests(GatedFixture):
    """Issue #228 items 2-4."""

    async def test_concurrent_run_is_refused_and_changes_nothing(self):
        self.assertEqual(self.access.state, HumanAccessState.SERVING)
        with self.assertRaises(HumanAccessAlreadyRunning):
            await self.access.run()
        self.assertFalse(self.access.stopped)
        self.assertEqual(self.access.state, HumanAccessState.SERVING)

    async def test_state_reports_failing_checks_and_a_failed_run(self):
        await self.stop_serving()
        self.assertEqual(self.access.state, HumanAccessState.STOPPED)
        ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check, clock=self.ceremony_clock)
        fresh = HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store, ceremonies=ceremonies,
                            reservation=self.check)
        self.assertEqual(fresh.state, HumanAccessState.NOT_STARTED)
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        attempts = []
        real_startup = self.check.startup

        def failing_startup():
            attempts.append(True)
            if len(attempts) < 3:
                raise RuntimeError("synthetic startup failure")
            return real_startup()

        sleeps = asyncio.Queue()

        async def stepped(_seconds):
            await sleeps.get()

        with patch.object(self.check, "startup", side_effect=failing_startup):
            task = asyncio.create_task(self.access.run(sleep=stepped))
            await self.until(lambda: len(attempts) == 1 and sleeps.empty())
            await asyncio.sleep(0.05)
            self.assertEqual((self.access.state, self.access.check_failures),
                             (HumanAccessState.CHECK_FAILING, 1))
            sleeps.put_nowait(None)
            await self.until(lambda: self.access.check_failures == 2)
            sleeps.put_nowait(None)
            await self.until(lambda: not self.access.stopped)
            self.assertEqual((self.access.state, self.access.check_failures), (HumanAccessState.SERVING, 0))
            self.access.stop()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(self.access.state, HumanAccessState.STOPPED)
        logging.disable(logging.NOTSET)

        async def broken(_seconds):
            raise RuntimeError("synthetic /secret/path and synthetic@example.invalid")

        with self.assertLogs("app.auth.human_surface", "ERROR") as logs:
            with self.assertRaises(RuntimeError):
                await self.access.run(sleep=broken)
        self.assertEqual(self.access.state, HumanAccessState.FAILED)
        self.assertTrue(self.access.stopped)
        self.assertEqual([record.msg for record in logs.records], [Event.HUMAN_ACCESS_RUN_FAILED])
        formatted = SafeJsonFormatter().format(logs.records[0])
        self.assertNotIn("secret", formatted)
        self.assertNotIn("example.invalid", formatted)
        # A later run() is not blocked by the failed one.
        await self.start_serving()
        self.assertEqual(self.access.state, HumanAccessState.SERVING)

    async def test_sweep_failures_are_logged_at_powers_of_two(self):
        await self.stop_serving()
        sweeps = []

        def failing_sweep():
            sweeps.append(True)
            raise RuntimeError("synthetic sweep failure")

        sleeps = asyncio.Queue()

        async def stepped(_seconds):
            await sleeps.get()

        with patch.object(self.check, "tick", return_value=None), \
                patch.object(self.store, "end_expired_sessions", side_effect=failing_sweep), \
                self.assertLogs("app.auth.human_surface", "ERROR") as logs:
            task = asyncio.create_task(self.access.run(sleep=stepped))
            await self.until(lambda: not self.access.stopped)
            for count in range(1, 9):
                sleeps.put_nowait(None)
                await self.until(lambda: len(sweeps) >= count)
            self.access.stop()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual([record.msg for record in logs.records], [Event.HUMAN_ACCESS_SWEEP_FAILED] * 4)


class DenialAndLogHygieneTests(GatedFixture):
    async def test_every_refusal_is_byte_identical(self):
        _, key, _ = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        self.assertEqual(await self.denial(), GENERIC)
        results = [
            await call(self.surface, "GET", "/api/live/1", cookie=cookie),
            await call(self.surface, "DELETE", SIGN_OUT_PATH, cookie=cookie),
            await call(self.surface, "GET", SIGN_OUT_PATH, cookie=cookie),
            await self.sign_out(cookie, None),
            await self.sign_out(cookie, "A" * 43),
            await call(self.surface, "GET", SESSION_PATH, cookie=SESSION_COOKIE + "=" + "B" * 43),
            await call(self.surface, "GET", SESSION_PATH, cookie=cookie, identity=OTHER_LOGIN),
            await call(self.surface, "POST", AUTHENTICATION_PATH, body=b"{}"),
        ]
        self.close_access()
        results.append(await call(self.surface, "GET", SESSION_PATH, cookie=cookie))
        results.append(await self.sign_out(cookie, csrf))
        self.reopen_access()
        self.access.stop()
        results.append(await call(self.surface, "GET", SESSION_PATH, cookie=cookie))
        for index, result in enumerate(results):
            with self.subTest(index=index):
                self.assertEqual(result, GENERIC)

    async def test_no_token_csrf_identity_or_credential_reaches_a_log(self):
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
        principal, key, credential = self.enroll()
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        view_session = view_id(self, self.token(cookie))
        await self.sign_out(cookie, "A" * 43)
        await call(self.surface, "GET", SESSION_PATH, cookie=cookie, identity=OTHER_LOGIN)
        # Exhaust the per-source sign-in bucket so the rate limiter logs.
        for _ in range(self.limiter.per_source_capacity + 1):
            await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        await self.sign_out(cookie, csrf)
        self.assertTrue(records, "the scenario logged nothing to inspect")
        secrets_seen = (cookie.split("=", 1)[1], csrf, VIEWER, OTHER_LOGIN, str(view_session),
                        base64.urlsafe_b64encode(credential.credential_id).rstrip(b"=").decode(),
                        credential.credential_id.hex())
        formatter = SafeJsonFormatter()
        for record in records:
            text = " ".join((repr(record.__dict__), formatter.format(record)))
            for value in secrets_seen:
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
