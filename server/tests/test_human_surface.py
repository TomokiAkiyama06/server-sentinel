"""Issue #10 phase 1: the human route foundation (ADR-0003, ADR-0004, Issue #181).

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows and Serve status, a temporary SQLite database and an
in-process ASGI driver. Every identity is an invented ``.invalid`` value. No
socket, browser, Tailscale or real authenticator is involved.
"""

import asyncio
from contextlib import closing
from datetime import timedelta
import json
import logging
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from app.auth import reservation as reservation_module
from app.auth.human_surface import (
    AUTHENTICATION_OPTIONS_PATH, AUTHENTICATION_PATH, SESSION_COOKIE, SESSION_PATH,
    HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable, HumanSurface,
)
from app.auth.model import Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.rate_limit import SourceRateLimiter
from app.auth.reservation import DAILY_SECONDS
from app.auth.reservation_store import ReservationSessionRevocation
from app.auth.session_binding import SessionBindingKey
from app.audit import AuditStore
from app.auth.store import AccessStore
from app.auth.webauthn import RelyingParty
from app.main import create_app
from app.settings import Settings
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.asgi import request
from tests.test_hostname_reservation import HOST, Clock, checker, proc
from tests.test_webauthn_ceremonies import Clock as CeremonyClock
from tests.webauthn_fakes import ORIGIN as OTHER_ORIGIN, OpenGate, SyntheticAuthenticator


ORIGIN = f"https://{HOST}"
VIEWER = "synthetic-room-account@example.invalid"
OTHER_LOGIN = "synthetic-other-account@example.invalid"
LOOPBACK = ("127.0.0.1", 40000)
UPSTREAM = ("127.0.0.1", 8080)
LAN = ("192.0.2.50", 40000)
EXPOSED = proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 8443, "0A"))
UNMOUNTED = ("/health", "/version", "/openapi.json", "/docs", "/api/live/1", "/api/sources",
             "/api/recordings", "/api/recordings/1/playback", "/api/recordings/1/download",
             "/api/events", "/api/timeline", "/api/access/invitations", "/diagnostics/export",
             "/api/auth/registration", "/api/session/", "/", "/index.html")


class InnerApplication:
    """The application behind the surface must never see a human request."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        raise AssertionError("a human request reached the application")


async def call(application, method, path, *, identity=VIEWER, origin=ORIGIN, host=HOST,
               cookie=None, body=b"", headers=(), client=LOOPBACK, server=UPSTREAM,
               kind="http", query=b"", content_type=b"application/json"):
    sent = []
    header_list = []
    if host is not None:
        header_list.append((b"host", host.encode()))
    if origin is not None:
        header_list.append((b"origin", origin.encode()))
    if identity is not None:
        header_list.append((b"tailscale-user-login", identity.encode()))
    if cookie is not None:
        header_list.append((b"cookie", cookie.encode()))
    if method == "POST" and content_type is not None:
        header_list.append((b"content-type", content_type))
    header_list.extend(headers)
    scope = {
        "type": kind, "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
        "method": method, "path": path, "raw_path": path.encode(), "query_string": query,
        "root_path": "", "headers": header_list, "client": client, "server": server,
    }
    chunks = [body]

    async def receive():
        if chunks:
            return {"type": "http.request", "body": chunks.pop(0), "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await application(scope, receive, send)
    return sent


def status(messages):
    return messages[0]["status"]


def payload(messages):
    return json.loads(messages[1]["body"])


def header(messages, name):
    return [value for key, value in messages[0]["headers"] if key == name]


class HumanSurfaceFixture(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.database = Database(self.temporary / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.ceremony_clock = CeremonyClock()
        self.audit = AuditStore(self.database, clock=self.ceremony_clock)
        self.store = AccessStore(self.database, clock=self.ceremony_clock, audit=self.audit,
                                 unaudited_writes=True, session_binding=SessionBindingKey.generate())
        self.revoker = ReservationSessionRevocation(self.store)
        self.clock = Clock()
        self.check, self.files, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        self.assertTrue(self.check.startup().open)
        self.rp = RelyingParty(HOST, ORIGIN)
        self.ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                            clock=self.ceremony_clock)
        self.limit_clock = Clock()
        self.limiter = SourceRateLimiter(monotonic=self.limit_clock)
        self.access = HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                                  ceremonies=self.ceremonies, reservation=self.check,
                                  rate_limiter=self.limiter)
        self.inner = InnerApplication()
        self.surface = HumanSurface(self.inner, self.access)
        self.codes = iter(bytes([index]) * 32 for index in range(1, 200))

    def tearDown(self):
        self.assertEqual(self.inner.calls, 0)

    def enroll(self, permissions=(Permission.LIVE_VIEW,), *, owner=False):
        if owner:
            principal = self.store.bootstrap_owner("Synthetic owner")
        else:
            principal = self.store.invite("Synthetic viewer", permissions)
        code = next(self.codes)
        self.store.issue_enrollment(principal.id, code, self.ceremony_clock() + timedelta(minutes=30))
        authenticator = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(code, VIEWER)
        credential = self.ceremonies.finish_registration(
            code, VIEWER, authenticator.register(creation, origin=ORIGIN, rp_id=HOST))
        return principal, authenticator, credential

    async def sign_in(self, authenticator, identity=VIEWER):
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH, identity=identity)
        self.assertEqual(status(options), 200)
        assertion = authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST)
        finished = await call(self.surface, "POST", AUTHENTICATION_PATH, identity=identity,
                              body=json.dumps(assertion).encode())
        self.assertEqual(status(finished), 204)
        (cookie,) = header(finished, b"set-cookie")
        return cookie.decode().split(";")[0]

    async def denial(self):
        """The response an uninvited caller without any session receives."""
        return await call(self.surface, "GET", SESSION_PATH)

    def count(self, sql):
        with closing(self.database.connect()) as connection:
            return connection.execute(sql).fetchone()[0]


class SignInAndSessionTests(HumanSurfaceFixture):
    async def test_live_only_viewer_signs_in_and_sees_only_its_own_permissions(self):
        _, authenticator, _ = self.enroll((Permission.LIVE_VIEW,))
        cookie = await self.sign_in(authenticator)
        result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie, origin=None)
        self.assertEqual(status(result), 200)
        self.assertEqual(payload(result), {"permissions": ["live:view"], "role": "invited_user"})
        self.assertEqual(header(result, b"cache-control"), [b"no-store"])
        self.assertEqual(header(result, b"server"), [])

    async def test_owner_session_reports_every_permission(self):
        _, authenticator, _ = self.enroll(owner=True)
        cookie = await self.sign_in(authenticator)
        result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
        self.assertEqual(payload(result), {"permissions": ["live:view", "recordings:view"],
                                           "role": "owner"})

    async def test_finish_sets_only_a_host_only_strict_session_cookie_and_no_data(self):
        _, authenticator, _ = self.enroll()
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        # Discoverable credential: no credential list reveals who is invited.
        self.assertEqual(payload(options)["allowCredentials"], [])
        self.assertEqual(payload(options)["userVerification"], "required")
        assertion = authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST)
        finished = await call(self.surface, "POST", AUTHENTICATION_PATH,
                              body=json.dumps(assertion).encode())
        self.assertEqual(status(finished), 204)
        self.assertEqual(finished[1]["body"], b"")
        (cookie,) = header(finished, b"set-cookie")
        name, _, attributes = cookie.decode().partition(";")
        self.assertTrue(name.startswith(SESSION_COOKIE + "="))
        self.assertEqual(attributes, " Path=/; Secure; HttpOnly; SameSite=Strict")
        self.assertNotIn("Domain", attributes)

    async def test_user_verification_is_required_at_sign_in(self):
        _, authenticator, _ = self.enroll()
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        assertion = authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST, uv=False)
        finished = await call(self.surface, "POST", AUTHENTICATION_PATH,
                              body=json.dumps(assertion).encode())
        self.assertEqual(finished, await self.denial())
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 0)

    async def test_malformed_finish_bodies_are_denied_without_a_session(self):
        _, authenticator, _ = self.enroll()
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        assertion = json.dumps(authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST))
        expected = await self.denial()
        for body, content_type in (
                (b"not json", b"application/json"),
                (b"[]", b"application/json"),
                (b'{"id":"a","id":"b"}', b"application/json"),
                (b"x" * (64 * 1024 + 1), b"application/json"),
                (assertion.encode(), b"text/plain"),
                (assertion.encode(), None)):
            with self.subTest(body=body[:16], content_type=content_type):
                result = await call(self.surface, "POST", AUTHENTICATION_PATH, body=body,
                                    content_type=content_type)
                self.assertEqual(result, expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 0)

    async def test_assertion_from_another_origin_is_refused(self):
        _, authenticator, _ = self.enroll()
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        assertion = authenticator.assertion(payload(options), origin=f"https://{HOST}:8443", rp_id=HOST)
        result = await call(self.surface, "POST", AUTHENTICATION_PATH, body=json.dumps(assertion).encode())
        self.assertEqual(result, await self.denial())


class GenericDenialTests(HumanSurfaceFixture):
    async def test_proxy_identity_alone_never_authorizes(self):
        # An invited, enrolled person's login without a credential-backed
        # session is denied exactly like a closed listener (ADR-0004 §1).
        self.enroll()
        result = await call(self.surface, "GET", SESSION_PATH)
        self.assertEqual(status(result), 404)
        self.assertEqual(result[1]["body"], b'{"detail":"Not Found"}')
        closed = create_app(Settings(self.temporary))
        self.assertEqual(result, await request(closed, SESSION_PATH))

    async def test_missing_malformed_duplicate_unknown_and_expired_sessions_are_denied(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        expected = await self.denial()
        unknown = SESSION_COOKIE + "=" + "A" * 43
        for value in (None, SESSION_COOKIE + "=", SESSION_COOKIE + "=short", unknown,
                      SESSION_COOKIE + "=" + "A" * 42 + "!", f"{cookie}; {cookie}",
                      "session=" + cookie.split("=", 1)[1]):
            with self.subTest(cookie=value):
                self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=value), expected)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)
        self.ceremony_clock.advance(minutes=31)
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), expected)

    async def test_revoked_principal_and_credential_get_the_uninvited_response(self):
        principal, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)
        self.store.revoke_principal(principal.id)
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), await self.denial())
        # A revoked person cannot sign in again either.
        options = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        assertion = authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST)
        result = await call(self.surface, "POST", AUTHENTICATION_PATH, body=json.dumps(assertion).encode())
        self.assertEqual(result, await self.denial())

    async def test_revoked_credential_ends_its_session(self):
        principal, authenticator, credential = self.enroll()
        cookie = await self.sign_in(authenticator)
        with self.store._transaction(write=True) as connection:
            self.store.revoke_credential_on(connection, principal.id, credential.credential_id,
                                            at=self.ceremony_clock())
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), await self.denial())

    async def test_live_only_and_recordings_only_reach_nothing_they_lack(self):
        # Only the session self-description exists in this phase; every live,
        # recording, timeline, event, admin and download path is the generic
        # denial for both grants, before and after sign-in.
        expected = await self.denial()
        for permissions in ((Permission.LIVE_VIEW,), (Permission.RECORDINGS_VIEW,)):
            _, authenticator, _ = self.enroll(permissions)
            cookie = await self.sign_in(authenticator)
            session = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
            self.assertEqual(payload(session)["permissions"], [permissions[0].value])
            for path in UNMOUNTED:
                for method in ("GET", "POST", "DELETE", "HEAD", "OPTIONS"):
                    with self.subTest(permissions=permissions, path=path, method=method):
                        result = await call(self.surface, method, path, cookie=cookie)
                        self.assertEqual(result, expected)

    async def test_mounted_paths_with_other_methods_or_queries_are_denied(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        expected = await self.denial()
        for method, path in (("POST", SESSION_PATH), ("HEAD", SESSION_PATH), ("PUT", SESSION_PATH),
                             ("GET", AUTHENTICATION_PATH), ("GET", AUTHENTICATION_OPTIONS_PATH)):
            with self.subTest(method=method, path=path):
                self.assertEqual(await call(self.surface, method, path, cookie=cookie), expected)
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie, query=b"x=1"),
                         expected)

    async def test_websocket_is_always_closed(self):
        result = await call(self.surface, "GET", SESSION_PATH, kind="websocket")
        self.assertEqual(result, [{"type": "websocket.close", "code": 1008}])


class OriginTests(HumanSurfaceFixture):
    async def test_reserved_host_and_exact_origin_are_required(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        expected = await self.denial()
        for host, origin in ((f"{HOST}:8443", ORIGIN), ("127.0.0.1:8080", ORIGIN), (None, ORIGIN),
                             (HOST, f"https://{HOST}:8443"), (HOST, f"http://{HOST}"),
                             (HOST, OTHER_ORIGIN), (HOST, "null"), (HOST, ORIGIN + "/")):
            with self.subTest(host=host, origin=origin):
                result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie, host=host,
                                    origin=origin)
                self.assertEqual(result, expected)
        duplicate = await call(self.surface, "GET", SESSION_PATH, cookie=cookie,
                               headers=[(b"host", HOST.encode())])
        self.assertEqual(duplicate, expected)
        # Absent Origin is accepted for the non-mutating read only.
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie,
                                           origin=None)), 200)

    async def test_ceremony_routes_require_the_exact_origin(self):
        expected = await self.denial()
        for origin in (None, f"https://{HOST}:8443", OTHER_ORIGIN):
            with self.subTest(origin=origin):
                result = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH, origin=origin)
                self.assertEqual(result, expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), 0)


class TrustedProxyPathTests(HumanSurfaceFixture):
    async def test_identity_header_from_a_lan_peer_is_refused_before_it_is_read(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        expected = await self.denial()
        with patch.object(self.store, "authorize_session",
                          side_effect=AssertionError("must not authorize")) as authorize, \
                patch("app.auth.human_surface.proxy_identity",
                      side_effect=AssertionError("must not read the header")) as read:
            for client, server, extra in (
                    (LAN, UPSTREAM, ()),
                    (LAN, UPSTREAM, [(b"x-forwarded-for", b"127.0.0.1"),
                                     (b"forwarded", b"for=127.0.0.1")]),
                    (LOOPBACK, ("192.0.2.1", 8080), ()),
                    (("::ffff:192.0.2.50", 40000), UPSTREAM, ()),
                    (None, UPSTREAM, ()),
                    (("not-an-address", 1), UPSTREAM, ())):
                with self.subTest(client=client, server=server):
                    result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie,
                                        client=client, server=server, headers=extra)
                    self.assertEqual(result, expected)
                    result = await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH,
                                        client=client, server=server, headers=extra)
                    self.assertEqual(result, expected)
        authorize.assert_not_called()
        read.assert_not_called()
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), 0)

    async def test_identity_header_must_be_present_single_and_unambiguous(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        expected = await self.denial()
        for identity, extra in ((None, ()),
                                (VIEWER, [(b"tailscale-user-login", OTHER_LOGIN.encode())]),
                                (VIEWER + "," + OTHER_LOGIN, ()),
                                ("=?utf-8?q?synthetic?=@example.invalid", ()),
                                ("synthetic user@example.invalid", ()),
                                ("", ())):
            with self.subTest(identity=identity, extra=extra):
                result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie,
                                    identity=identity, headers=extra)
                self.assertEqual(result, expected)

    async def test_session_cookie_with_another_proxy_identity_is_refused(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie, identity=OTHER_LOGIN)
        self.assertEqual(result, await self.denial())
        # The holder keeps working (Owner decision 2026-09-30, PR #107).
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)

    async def test_two_people_behind_one_login_each_get_their_own_principal(self):
        _, live_authenticator, _ = self.enroll((Permission.LIVE_VIEW,))
        _, recordings_authenticator, _ = self.enroll((Permission.RECORDINGS_VIEW,))
        live = await self.sign_in(live_authenticator)
        recordings = await self.sign_in(recordings_authenticator)
        self.assertEqual(payload(await call(self.surface, "GET", SESSION_PATH, cookie=live))["permissions"],
                         ["live:view"])
        self.assertEqual(payload(await call(self.surface, "GET", SESSION_PATH,
                                            cookie=recordings))["permissions"], ["recordings:view"])


class ReservationGateTests(HumanSurfaceFixture):
    async def test_closed_reservation_denies_everything_and_stores_no_challenge(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        challenges = self.count("SELECT count(*) FROM access_webauthn_challenges")
        expected = await self.denial()
        self.files.files["tcp"] = EXPOSED
        self.clock.value += DAILY_SECONDS
        self.assertFalse(self.check.tick().open)
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), expected)
        self.assertEqual(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), challenges)

    async def test_fork_child_pid_guard_denies_every_route(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        challenges = self.count("SELECT count(*) FROM access_webauthn_challenges")
        expected = await self.denial()
        # A fork child: the running pid differs from the one the gate
        # recorded (patched on the gate, not on the process-wide os module).
        with patch.object(self.check, "_gate_pid", reservation_module.os.getpid() + 1), \
                patch.object(self.store, "authorize_session",
                             side_effect=AssertionError("must not authorize")):
            self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), expected)
            self.assertEqual(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), challenges)

    async def test_pid_guard_refuses_the_gate_confirmation_after_authorization(self):
        # The fork happens between the request-time verdict and admit():
        # authorization ran, but the gate refuses to confirm it.
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        original = self.store.authorize_session
        patcher = patch.object(self.check, "_gate_pid", reservation_module.os.getpid() + 1)
        self.addCleanup(patcher.stop)

        def forked(*args, **kwargs):
            result = original(*args, **kwargs)
            patcher.start()
            return result

        with patch.object(self.store, "authorize_session", side_effect=forked):
            result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
        self.assertEqual(result, await self.denial())

    async def test_check_closing_during_authorization_denies_the_answer(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        original = self.store.authorize_session

        def close_meanwhile(*args, **kwargs):
            result = original(*args, **kwargs)
            self.files.files["tcp"] = EXPOSED
            self.clock.value += DAILY_SECONDS
            self.assertFalse(self.check.tick().open)
            return result

        with patch.object(self.store, "authorize_session", side_effect=close_meanwhile):
            result = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
        self.assertEqual(result, await self.denial())


class RateLimitTests(HumanSurfaceFixture):
    async def test_unauthenticated_ceremony_requests_are_limited_per_source(self):
        expected = await self.denial()
        for _ in range(self.limiter.per_source_capacity):
            self.assertEqual(status(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)), 200)
        stored = self.count("SELECT count(*) FROM access_webauthn_challenges")
        with patch.object(self.ceremonies, "begin_authentication",
                          side_effect=AssertionError("limited before the gate")), \
                self.assertLogs("app.auth.rate_limit", "WARNING") as logs:
            self.assertEqual(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH), expected)
            self.assertEqual(await call(self.surface, "POST", AUTHENTICATION_PATH, body=b"{}"), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), stored)
        # Value-free: one event, no identity or digest in the record.
        self.assertEqual(len(logs.records), 1)
        record = logs.records[0]
        self.assertEqual(record.msg, "human_request_rate_limited")
        self.assertNotIn("example.invalid", repr(record.__dict__))
        # Another source still gets through; the limited one recovers over time.
        self.assertEqual(status(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH,
                                           identity=OTHER_LOGIN)), 200)
        self.limit_clock.value += self.limiter.per_source_refill_seconds
        self.assertEqual(status(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)), 200)

    async def test_authenticated_session_reads_are_not_charged(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        for _ in range(self.limiter.per_source_capacity * 2):
            self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)

    async def test_forged_session_cookies_never_take_the_gate_or_write(self):
        # Issue #181 item 4 on the session route: well-formed random cookies
        # (and stale ones) from a holder of the shared login are refused by
        # a read-only lookup, never taking the gate lock or a write lock.
        _, authenticator, _ = self.enroll()
        invalidated = await self.sign_in(authenticator)
        with self.store._transaction(write=True) as connection:
            connection.execute("UPDATE access_sessions SET invalidated_at_us=last_seen_at_us, "
                               "external_identity_binding=NULL")
        expired = await self.sign_in(authenticator)
        expected = await self.denial()
        # Past the idle lifetime with no sweep yet: the row is still present
        # and not invalidated.
        self.ceremony_clock.advance(minutes=31)
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions WHERE invalidated_at_us IS NULL"), 1)
        real_lock = self.check._session_gate_lock
        gate = {"taken": 0}

        class CountingLock:
            def __enter__(self):
                gate["taken"] += 1
                return real_lock.__enter__()

            def __exit__(self, *exc):
                return real_lock.__exit__(*exc)

            def __getattr__(self, name):
                return getattr(real_lock, name)

        original_transaction = self.store._transaction
        writes = []

        def counting_transaction(write=False):
            if write:
                writes.append(True)
            return original_transaction(write=write)

        before = (self.database.path.read_bytes(), self.limiter.limited, self.limiter.sources())
        forged = [SESSION_COOKIE + "=" + secrets.token_urlsafe(32) for _ in range(200)]
        with patch.object(self.check, "_session_gate_lock", CountingLock()), \
                patch.object(self.store, "_transaction", side_effect=counting_transaction), \
                patch.object(self.store, "authorize_session",
                             side_effect=AssertionError("denied before authorization")), \
                patch.object(self.store, "end_expired_sessions",
                             side_effect=AssertionError("denied without a write")):
            for cookie in forged + [expired, invalidated]:
                self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), expected)
        self.assertEqual(gate["taken"], 0)
        self.assertEqual(writes, [])
        self.assertEqual((self.database.path.read_bytes(), self.limiter.limited, self.limiter.sources()),
                         before)
        # Sign-in and a live session are unaffected by the flood.
        live = await self.sign_in(authenticator)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=live)), 200)

    def test_session_pre_check_is_read_only_and_fails_closed(self):
        self.assertFalse(self.store.session_may_be_current(b"short"))
        self.assertFalse(self.store.session_may_be_current("not bytes"))
        self.assertFalse(self.store.session_may_be_current(bytes(32)))
        with patch.object(Database, "connect", side_effect=OSError("unavailable")):
            self.assertFalse(self.store.session_may_be_current(bytes(32)))


class SourceRateLimiterTests(unittest.TestCase):
    def test_global_bucket_bounds_all_sources(self):
        clock = Clock()
        limiter = SourceRateLimiter(per_source_capacity=5, global_capacity=3, monotonic=clock)
        with self.assertLogs("app.auth.rate_limit", "WARNING"):
            self.assertEqual([limiter.allow(f"s{index}@example.invalid") for index in range(4)],
                             [True, True, True, False])

    def test_memory_is_bounded_and_full_tables_fail_closed(self):
        clock = Clock()
        limiter = SourceRateLimiter(per_source_capacity=2, per_source_refill_seconds=10,
                                    max_sources=2, monotonic=clock)
        self.assertTrue(limiter.allow("a@example.invalid"))
        self.assertTrue(limiter.allow("b@example.invalid"))
        with self.assertLogs("app.auth.rate_limit", "WARNING"):
            # Both buckets are in use: a new source is refused, not added.
            self.assertFalse(limiter.allow("c@example.invalid"))
        self.assertEqual(limiter.sources(), 2)
        clock.value += 10
        # The least recently used bucket has refilled and is evicted.
        self.assertTrue(limiter.allow("c@example.invalid"))
        self.assertEqual(limiter.sources(), 2)

    def test_backward_clock_never_adds_tokens_and_bad_inputs_refuse(self):
        clock = Clock()
        limiter = SourceRateLimiter(per_source_capacity=1, monotonic=clock)
        self.assertTrue(limiter.allow("a@example.invalid"))
        clock.value -= 1000
        with self.assertLogs("app.auth.rate_limit", "WARNING"):
            self.assertFalse(limiter.allow("a@example.invalid"))
            self.assertFalse(limiter.allow(""))
            clock.value = float("nan")
            self.assertFalse(limiter.allow("b@example.invalid"))
        for options in ({"per_source_capacity": 0}, {"global_capacity": True},
                        {"per_source_refill_seconds": float("inf")}, {"max_sources": 1.5}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                SourceRateLimiter(**options)


class CompositionTests(HumanSurfaceFixture):
    def compose(self, **overrides):
        values = dict(store=self.store, ceremonies=self.ceremonies, reservation=self.check)
        values.update(overrides)
        configuration = values.pop("configuration", HumanAccessConfiguration(enabled=True))
        return HumanAccess(configuration, **values)

    def test_closed_unless_explicitly_enabled(self):
        for configuration in (HumanAccessConfiguration(), HumanAccessConfiguration(enabled=1),
                              None, {"enabled": True}):
            with self.subTest(configuration=configuration), self.assertRaises(HumanAccessUnavailable):
                self.compose(configuration=configuration)

    def test_a_real_fully_configured_reservation_gate_is_required(self):
        # Issue #181 item 3: no human-route composition without the check.
        for gate in (None, OpenGate()):
            with self.subTest(gate=gate), self.assertRaises((HumanAccessUnavailable, ValueError)):
                ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=gate)
                self.compose(ceremonies=ceremonies, reservation=gate)
        # The production socket-owner and hostname resolvers are mandatory.
        for missing in ("resolver", "socket_owners", "session_revoker", "own_sockets",
                        "unprivileged_port_start"):
            with self.subTest(missing=missing):
                check, _, _, _ = checker(clock=self.clock, **{missing: None})
                self.assertFalse(check.opening_configured)
                ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=check)
                with self.assertRaises(HumanAccessUnavailable):
                    self.compose(ceremonies=ceremonies, reservation=check)
        # Ceremonies bound to another gate than the reservation are refused.
        other, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        with self.assertRaises(HumanAccessUnavailable):
            self.compose(reservation=other)

    def test_relying_party_must_be_the_reserved_https_origin(self):
        for rp in (RelyingParty("sentinel.example.invalid", OTHER_ORIGIN),
                   RelyingParty(HOST, f"https://{HOST}:8443"),
                   RelyingParty("localhost", "http://localhost:8080")):
            with self.subTest(origin=rp.origin), self.assertRaises(HumanAccessUnavailable):
                ceremonies = PasskeyCeremonies(self.store, rp, session_gate=self.check)
                self.compose(ceremonies=ceremonies)

    def test_store_must_be_audited_with_a_binding_key(self):
        other = AccessStore(self.database, audit=self.audit, session_binding=SessionBindingKey.generate())
        with self.assertRaises(HumanAccessUnavailable):
            self.compose(store=other)
        with self.assertRaises(HumanAccessUnavailable):
            HumanSurface(self.inner, object())

    def test_create_app_accepts_only_a_validated_composition(self):
        with self.assertRaises(TypeError):
            create_app(Settings(self.temporary), human_access=object())


class ApplicationCompositionTests(HumanSurfaceFixture):
    async def test_application_runs_the_check_and_serves_only_after_it_opens(self):
        _, authenticator, _ = self.enroll()
        check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        self.assertFalse(check.access_open)
        ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=check, clock=self.ceremony_clock)
        access = HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                             ceremonies=ceremonies, reservation=check, tick_seconds=0.01)
        application = create_app(Settings(self.temporary), database=self.database, human_access=access)
        before = await call(application, "POST", AUTHENTICATION_OPTIONS_PATH)
        self.assertEqual(before, await self.denial())
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        async with application.router.lifespan_context(application):
            for _ in range(500):
                if check.access_open:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(check.access_open)
            options = await call(application, "POST", AUTHENTICATION_OPTIONS_PATH)
            assertion = authenticator.assertion(payload(options), origin=ORIGIN, rp_id=HOST)
            finished = await call(application, "POST", AUTHENTICATION_PATH,
                                  body=json.dumps(assertion).encode())
            cookie = header(finished, b"set-cookie")[0].decode().split(";")[0]
            result = await call(application, "GET", SESSION_PATH, cookie=cookie)
            self.assertEqual(payload(result)["permissions"], ["live:view"])
            for path in UNMOUNTED:
                self.assertEqual(await call(application, "GET", path, cookie=cookie),
                                 await self.denial())
        self.assertFalse(application.routes)


if __name__ == "__main__":
    unittest.main()
