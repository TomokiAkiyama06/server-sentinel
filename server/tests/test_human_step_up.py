"""Issue #10 phase 2 S3: the Owner step-up routes (AUTH-008, Owner decision D3).

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows, a synthetic boot id and ``CLOCK_BOOTTIME``, a temporary
SQLite database and the in-process ASGI driver of ``test_human_surface``.
Every identity is an invented ``.invalid`` value. Mock only: no browser,
proxy, Tailscale or real authenticator is involved, and no real Owner
operation route exists yet (S4): the ``OWNER_OP`` contract is exercised
through a synthetic route added to the table for the test only.
"""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import re
import secrets
import unittest
from unittest.mock import patch
from uuid import UUID

from app.auth import human_surface as surface_module
from app.auth.boot_clock import STEP_UP_ROLLBACK_TOLERANCE, BootInstant, step_up_fresh
from app.auth.human_surface import (
    ROUTES, HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable, STEP_UP_OPTIONS_PATH, STEP_UP_PATH, Route, match_route,
)
from app.auth.model import AccessValidationError, Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.rate_limit import SourceRateLimiter, step_up_rate_limiter
from app.auth.store import OWNER_STEP_UP_FRESHNESS, Requirement, SessionView, StepUpRequired
from app.logging import Event, SafeJsonFormatter

from tests.test_human_gated_authorization import GENERIC, STEP_UP, GatedFixture
from tests.test_human_surface import (
    AUTHENTICATION_OPTIONS_PATH, HOST, LAN, ORIGIN, OTHER_LOGIN, VIEWER, call, header, payload, status,
)
from tests.test_invitation_redemption import OTHER_BOOT, BootClock
from tests.test_webauthn_ceremonies import waiting
from tests.webauthn_fakes import SyntheticAuthenticator, b64


OWNER_OPERATION_PATH = "/api/synthetic/owner-operation"
STEP_UP_AUDIT = "SELECT count(*) FROM security_admin_audit_records WHERE action='verify_principal_step_up'"
STEP_UP_CHALLENGES = "SELECT count(*) FROM access_webauthn_challenges WHERE ceremony='step_up'"
OPTION_KEYS = ["allowCredentials", "challenge", "rpId", "timeout", "userVerification"]


def microseconds(value):
    return (value - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1)


class StepUpFixture(GatedFixture):
    def setUp(self):
        super().setUp()
        # A synthetic boot clock that moves only when a test says so.
        self.boot = BootClock()
        self.store._boot_clock = self.boot
        # Roomy sign-in and step-up limiters unless a test exercises a limit.
        self.access.rate_limiter = SourceRateLimiter(
            per_source_capacity=1000, global_capacity=None, monotonic=self.limit_clock)
        self.access.step_up_limiter = SourceRateLimiter(
            per_source_capacity=1000, global_capacity=None, monotonic=self.limit_clock)

    def elapse(self, **delta):
        """Both clocks move together, as on a host whose wall clock is not stepped."""
        self.ceremony_clock.advance(**delta)
        self.boot.advance(**delta)

    async def owner_session(self):
        principal, key, credential = self.enroll(owner=True)
        cookie = await self.sign_in(key)
        return principal, key, credential, cookie, await self.csrf(cookie)

    async def begin(self, cookie, csrf, *, body=b"", **options):
        headers = list(options.pop("headers", ()))
        if csrf is not None:
            headers.append((b"x-csrf-token", csrf.encode()))
        options.setdefault("content_type", None)
        return await call(self.surface, "POST", STEP_UP_OPTIONS_PATH, cookie=cookie, headers=headers,
                          body=body, **options)

    async def finish(self, cookie, csrf, assertion, **options):
        headers = list(options.pop("headers", ()))
        if csrf is not None:
            headers.append((b"x-csrf-token", csrf.encode()))
        body = assertion if isinstance(assertion, bytes) else json.dumps(assertion).encode()
        return await call(self.surface, "POST", STEP_UP_PATH, cookie=cookie, headers=headers,
                          body=body, **options)

    async def step_up(self, cookie, csrf, authenticator, **assertion_options):
        begun = await self.begin(cookie, csrf)
        self.assertEqual(status(begun), 200)
        assertion = authenticator.assertion(
            payload(begun), **{"origin": ORIGIN, "rp_id": HOST, **assertion_options})
        return await self.finish(cookie, csrf, assertion)

    async def owner_operation(self, cookie, csrf):
        """A synthetic ``OWNER_OP`` route (S4 mounts the real ones)."""
        route = Route("POST", re.compile(re.escape(OWNER_OPERATION_PATH)), Requirement.OWNER_OP,
                      "_synthetic_owner_operation", mutating=True, csrf=True, body_limit=2)
        surface = self.surface

        async def handler(request):
            await surface._authorize(request, Requirement.OWNER_OP)
            await request.send({"type": "http.response.start", "status": 204, "headers": []})
            await request.send({"type": "http.response.body", "body": b""})

        surface._synthetic_owner_operation = handler
        try:
            with patch.object(surface_module, "ROUTES", ROUTES + (route,)):
                return await call(surface, "POST", OWNER_OPERATION_PATH, cookie=cookie,
                                  headers=[(b"x-csrf-token", csrf.encode())], content_type=None)
        finally:
            del surface._synthetic_owner_operation

    def verification(self, cookie):
        """The session's verification time and boot pair, read directly."""
        digest = hashlib.sha256(self.token(cookie)).digest()
        with closing(self.database.connect()) as connection:
            return tuple(connection.execute(
                "SELECT last_user_verification_at_us, last_user_verification_boot_id, "
                "last_user_verification_boottime_us FROM access_sessions WHERE token_digest=?",
                (digest,)).fetchone())

    def credential_state(self):
        with closing(self.database.connect()) as connection:
            return sorted(tuple(row) for row in connection.execute(
                "SELECT credential_id, sign_count, backup_state, last_used_at_us FROM access_credentials"))

    def unchanged_state(self, cookie):
        return (self.verification(cookie), self.credential_state(), self.count(STEP_UP_AUDIT))


class StepUpRouteTests(StepUpFixture):
    async def test_stale_owner_steps_up_and_the_owner_operation_runs(self):
        owner, key, credential, cookie, csrf = await self.owner_session()
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)
        self.elapse(minutes=6)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        begun = await self.begin(cookie, csrf)
        self.assertEqual(status(begun), 200)
        self.assertEqual(header(begun, b"cache-control"), [b"no-store"])
        self.assertEqual(header(begun, b"set-cookie"), [])
        options = payload(begun)
        # Only what the ceremony needs: no camera, recording, principal or deployment data.
        self.assertEqual(sorted(options), OPTION_KEYS)
        self.assertEqual(options["allowCredentials"],
                         [{"type": "public-key", "id": b64(credential.credential_id)}])
        self.assertEqual((options["rpId"], options["userVerification"], options["timeout"]),
                         (HOST, "required", 300000))
        self.assertEqual(self.count(STEP_UP_CHALLENGES), 1)
        finished = await self.finish(cookie, csrf, key.assertion(options, origin=ORIGIN, rp_id=HOST))
        self.assertEqual(status(finished), 204)
        self.assertEqual(finished[1]["body"], b"")
        self.assertEqual(header(finished, b"set-cookie"), [])
        self.assertEqual(self.count(STEP_UP_CHALLENGES), 0)
        # The verification and its boot pair are the in-transaction readings.
        self.assertEqual(self.verification(cookie),
                         (microseconds(self.ceremony_clock()), self.boot.boot_id, self.boot.us))
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)
        (record,) = [item for item in self.audit.list_records()
                     if item.action.value == "verify_principal_step_up"]
        self.assertEqual((record.actor_category.value, record.target_logical_id, record.outcome.value),
                         ("owner", owner.id, "succeeded"))

    async def test_route_table_entries(self):
        for path, limit in ((STEP_UP_OPTIONS_PATH, 2), (STEP_UP_PATH, 64 * 1024)):
            route = match_route({"method": "POST", "path": path, "raw_path": path.encode()})
            with self.subTest(path=path):
                self.assertIsNotNone(route)
                # A stale Owner must reach it (not OWNER_OP); a non-Owner must not (not SESSION).
                self.assertIs(route.requirement, Requirement.OWNER_READ)
                self.assertEqual((route.mutating, route.csrf, route.body_limit, route.query), (True, True, limit, ()))
                self.assertIsNone(match_route({"method": "GET", "path": path, "raw_path": path.encode()}))

    async def test_a_new_begin_replaces_the_pending_challenge(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        first = payload(await self.begin(cookie, csrf))
        second = payload(await self.begin(cookie, csrf))
        self.assertEqual(self.count(STEP_UP_CHALLENGES), 1)
        before = self.unchanged_state(cookie)
        self.assertEqual(await self.finish(cookie, csrf, key.assertion(first, origin=ORIGIN, rp_id=HOST)), GENERIC)
        self.assertEqual(self.unchanged_state(cookie), before)
        # The refused finish burned nothing of the current challenge.
        self.assertEqual(status(await self.finish(
            cookie, csrf, key.assertion(second, origin=ORIGIN, rp_id=HOST))), 204)

    async def test_fresh_session_after_sign_in_needs_no_step_up(self):
        _, _, _, cookie, csrf = await self.owner_session()
        verified = self.verification(cookie)
        self.assertEqual(verified[1:], (self.boot.boot_id, self.boot.us))
        self.elapse(minutes=4)
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)


class OtherPersonTests(StepUpFixture):
    async def test_two_people_at_one_workstation_owner_session_left_stale(self):
        """MANUAL_TEST J in mock form: the Owner signed in and walked away; a
        second invited person at the same browser profile (same cookie jar)
        cannot refresh the Owner's stale session with their own passkey."""
        _, owner_key, _, cookie, csrf = await self.owner_session()
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        # The Owner registers a second passkey too; only the session's own counts.
        owner, _ = self.store.assertion_subject(owner_key.credential_id)
        code = next(self.codes)
        self.store.issue_enrollment(owner.id, code, self.ceremony_clock() + timedelta(minutes=30))
        second_owner_key = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(code, VIEWER)
        self.ceremonies.finish_registration(code, VIEWER, second_owner_key.register(creation, origin=ORIGIN, rp_id=HOST))
        self.elapse(minutes=10)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        before = self.unchanged_state(cookie)
        for other in (viewer_key, second_owner_key):
            with self.subTest(credential=b64(other.credential_id)):
                begun = await self.begin(cookie, csrf)
                assertion = other.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
                self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
                self.assertEqual(self.unchanged_state(cookie), before)
                self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        # The Owner's own passkey still works afterwards.
        self.assertEqual(status(await self.step_up(cookie, csrf, owner_key)), 204)
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)

    async def test_non_owner_sessions_get_the_generic_denial_before_any_write(self):
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        viewer = await self.sign_in(viewer_key)
        viewer_csrf = await self.csrf(viewer)
        rows = self.session_rows()
        challenges = self.count("SELECT count(*) FROM access_webauthn_challenges")
        self.elapse(minutes=1)
        self.assertEqual(await self.begin(viewer, viewer_csrf), GENERIC)
        # A forged step-up assertion over a sign-in challenge.
        options = payload(await call(self.surface, "POST", "/api/auth/authentication/options"))
        challenges += 1
        assertion = viewer_key.assertion(options, origin=ORIGIN, rp_id=HOST)
        self.assertEqual(await self.finish(viewer, viewer_csrf, assertion), GENERIC)
        # Refused inside the authorization transaction: no idle touch, no challenge.
        self.assertEqual(self.session_rows(), rows)
        self.assertEqual(self.count("SELECT count(*) FROM access_webauthn_challenges"), challenges)
        self.assertEqual(self.count(STEP_UP_AUDIT), 0)
        # Without any session at all: the same response.
        self.assertEqual(await self.begin(None, None), GENERIC)
        self.assertEqual(await self.finish(None, None, assertion), GENERIC)

    async def test_store_refuses_a_step_up_commit_for_a_non_owner_session(self):
        _, viewer_key, credential = self.enroll((Permission.LIVE_VIEW,))
        viewer = await self.sign_in(viewer_key)
        view = self.store.authorize_request(self.token(viewer), VIEWER, Requirement.SESSION, admit=self.gated())
        before = self.verification(viewer)
        with self.assertRaises(AccessValidationError):
            self.store.accept_assertion(credential.credential_id, view.principal_id, VIEWER,
                                        expected_sign_count=0, sign_count=0, backup_state=False,
                                        step_up_session_id=view.session_id)
        self.assertEqual(self.verification(viewer), before)


class FailedStepUpTests(StepUpFixture):
    async def test_cancelled_or_failed_step_up_changes_nothing(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        before = self.unchanged_state(cookie)
        cases = {
            "user verification declined": dict(uv=False),
            "user presence missing": dict(up=False),
            "bad signature": dict(tamper=True),
            "other origin": dict(origin=f"https://{HOST}:8443"),
            "other relying party": dict(rp_id="other.example.invalid"),
            "sign-in client data type": dict(kind="webauthn.create"),
            "unknown challenge": dict(challenge=b64(secrets.token_bytes(32))),
        }
        for name, options in cases.items():
            with self.subTest(case=name):
                begun = await self.begin(cookie, csrf)
                assertion = key.assertion(payload(begun), **{"origin": ORIGIN, "rp_id": HOST, **options})
                self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
                self.assertEqual(self.unchanged_state(cookie), before)
                self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        for body in (b"not json", b"[]", b'{"id":"a","id":"b"}', b"{}", b"x" * (64 * 1024 + 1)):
            with self.subTest(body=body[:12]):
                await self.begin(cookie, csrf)
                self.assertEqual(await self.finish(cookie, csrf, body), GENERIC)
        # Cancelled: the prompt is dismissed and nothing is sent; later the
        # challenge has expired and its answer is refused.
        begun = await self.begin(cookie, csrf)
        self.elapse(minutes=5)
        late = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
        self.assertEqual(await self.finish(cookie, csrf, late), GENERIC)
        self.assertEqual(self.unchanged_state(cookie), before)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)

    async def test_a_replayed_step_up_assertion_is_refused(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
        self.assertEqual(status(await self.finish(cookie, csrf, assertion)), 204)
        self.elapse(minutes=6)
        before = self.unchanged_state(cookie)
        self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
        self.assertEqual(self.unchanged_state(cookie), before)


class FreshnessTests(StepUpFixture):
    async def test_the_window_is_exactly_five_minutes_from_the_in_transaction_verification(self):
        self.assertEqual(OWNER_STEP_UP_FRESHNESS, timedelta(minutes=5))
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
        # A two-minute wait for storage admission before the commit: the
        # window starts at the commit, not when the request arrived.
        with waiting(self.store, "_audited_transaction", lambda: self.elapse(minutes=2)):
            self.assertEqual(status(await self.finish(cookie, csrf, assertion)), 204)
        verified = self.verification(cookie)
        self.assertEqual(verified[0], microseconds(self.ceremony_clock()))
        self.elapse(minutes=5, microseconds=-1)
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)
        self.elapse(microseconds=1)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        # Each clock on its own ends the window too.
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.ceremony_clock.advance(minutes=5)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.boot.advance(minutes=5)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)

    async def test_a_backward_wall_clock_step_makes_the_session_stale(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        # Two minutes pass, but the wall clock is stepped back by one of them:
        # still inside the wall window, yet stale (fail closed).
        self.boot.advance(minutes=2)
        self.ceremony_clock.advance(minutes=1)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        # A step back behind the session's last activity ends every request
        # until the clock is past it again (not only Owner operations).
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.ceremony_clock.advance(minutes=-1)
        self.assertEqual(await self.owner_operation(cookie, csrf), GENERIC)
        self.assertEqual(await self.begin(cookie, csrf), GENERIC)
        self.ceremony_clock.advance(minutes=1)
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)

    async def test_a_restored_future_verification_is_stale(self):
        _, _, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=1)
        digest = hashlib.sha256(self.token(cookie)).digest()
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_sessions SET last_user_verification_at_us=? WHERE token_digest=?",
                               (microseconds(self.ceremony_clock()) + 60_000_000, digest))
            connection.commit()
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_sessions SET last_user_verification_at_us=?, "
                               "last_user_verification_boottime_us=? WHERE token_digest=?",
                               (microseconds(self.ceremony_clock()), self.boot.us + 60_000_000, digest))
            connection.commit()
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)

    async def test_another_boot_or_an_unreadable_boot_clock_is_stale(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.boot.boot_id = OTHER_BOOT
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)
        self.boot.available = False
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        # A step-up that could never make the session fresh is refused.
        before = self.unchanged_state(cookie)
        self.assertEqual(await self.step_up(cookie, csrf, key), GENERIC)
        self.assertEqual(self.unchanged_state(cookie), before)
        self.boot.available = True
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)

    async def test_a_session_without_a_boot_pair_is_stale_until_a_step_up(self):
        # Sessions established before migration 23 carry no pair.
        _, key, _, cookie, csrf = await self.owner_session()
        digest = hashlib.sha256(self.token(cookie)).digest()
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_sessions SET last_user_verification_boot_id=NULL, "
                               "last_user_verification_boottime_us=NULL WHERE token_digest=?", (digest,))
            connection.commit()
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.assertEqual(status(await self.owner_operation(cookie, csrf)), 204)


class FreshnessRuleTests(unittest.TestCase):
    BOOT = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
    WINDOW = 300_000_000

    def fresh(self, wall, monotonic, **overrides):
        values = dict(verified_us=1_000_000_000, verified_boot_id=self.BOOT, verified_boottime_us=50_000_000,
                      now_us=1_000_000_000 + wall, now=BootInstant(self.BOOT, 50_000_000 + monotonic),
                      freshness_us=self.WINDOW)
        values.update(overrides)
        return step_up_fresh(**values)

    def test_rule(self):
        tolerance = STEP_UP_ROLLBACK_TOLERANCE // timedelta(microseconds=1)
        self.assertTrue(self.fresh(0, 0))
        self.assertTrue(self.fresh(self.WINDOW - 1, self.WINDOW - 1))
        self.assertFalse(self.fresh(self.WINDOW, self.WINDOW - 1))
        self.assertFalse(self.fresh(self.WINDOW - 1, self.WINDOW))
        # Wall clock ahead (stepped forward): the earlier clock ends the window.
        self.assertTrue(self.fresh(60_000_000, 1_000_000))
        # Wall clock behind beyond the tolerance (stepped back): stale.
        self.assertTrue(self.fresh(60_000_000, 60_000_000 + tolerance))
        self.assertFalse(self.fresh(60_000_000, 60_000_000 + tolerance + 1))
        self.assertFalse(self.fresh(-1, 0))
        self.assertFalse(self.fresh(0, -1))
        for overrides in (dict(now=None), dict(now=BootInstant(OTHER_BOOT, 50_000_000)),
                          dict(verified_boot_id=None), dict(verified_boottime_us=None),
                          dict(verified_boottime_us=True), dict(verified_us=None),
                          dict(freshness_us=0), dict(freshness_us=True), dict(now_us=1.5)):
            with self.subTest(overrides=overrides):
                self.assertFalse(self.fresh(0, 0, **overrides))


class CsrfAndOriginTests(StepUpFixture):
    async def test_begin_and_finish_require_csrf_exact_origin_and_the_trusted_path(self):
        _, key, _, cookie, csrf = await self.owner_session()
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW,))
        foreign = await self.csrf(await self.sign_in(viewer_key))
        self.elapse(minutes=6)
        cases = {
            "missing": dict(csrf=None),
            "foreign session": dict(csrf=foreign),
            "malformed": dict(csrf=csrf[:-1]),
            "repeated": dict(headers=[(b"x-csrf-token", csrf.encode())]),
            "in a query": dict(csrf=None, query=b"csrf=" + csrf.encode()),
            "no origin": dict(origin=None),
            "foreign origin": dict(origin=f"https://{HOST}:8443"),
            "http origin": dict(origin=f"http://{HOST}"),
            "other host": dict(host=f"{HOST}:8443"),
            "lan peer": dict(client=LAN),
            "other login": dict(identity=OTHER_LOGIN),
            "no login": dict(identity=None),
        }
        before = self.unchanged_state(cookie)
        for name, options in cases.items():
            options = dict(options)
            token = options.pop("csrf", csrf)
            with self.subTest(case=name, step="begin"):
                self.assertEqual(await self.begin(cookie, token, **options), GENERIC)
                self.assertEqual(self.count(STEP_UP_CHALLENGES), 0)
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
        rows = self.session_rows()
        for name, options in cases.items():
            options = dict(options)
            token = options.pop("csrf", csrf)
            with self.subTest(case=name, step="finish"):
                self.assertEqual(await self.finish(cookie, token, assertion, **options), GENERIC)
        for content_type in (b"text/plain", None):
            with self.subTest(content_type=content_type):
                self.assertEqual(await self.finish(cookie, csrf, assertion, content_type=content_type), GENERIC)
        self.assertEqual(await self.begin(cookie, csrf, body=b"x"), GENERIC)
        # None of them refreshed, touched or audited anything.
        self.assertEqual(self.unchanged_state(cookie), before)
        self.assertEqual(self.session_rows(), rows)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)


class ClosedAccessTests(StepUpFixture):
    async def restart(self):
        await self.stop_serving()
        await self.start_serving()

    async def test_step_up_is_refused_while_access_is_closed(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        self.close_access()
        self.assertEqual(await self.begin(cookie, csrf), GENERIC)
        self.assertEqual(self.count(STEP_UP_CHALLENGES), 0)
        self.reopen_access()
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
        before = self.unchanged_state(cookie)
        self.close_access()
        self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
        self.assertEqual(self.unchanged_state(cookie), before)
        self.reopen_access()
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)

    async def test_stop_or_a_failed_tick_in_flight_refuses_the_step_up(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        real_begin = self.ceremonies.begin_step_up
        real_finish = self.ceremonies.finish_step_up

        def stop():
            self.access.stop()

        def fail_tick():
            # What run() does when a periodic tick raises.
            self.access._serving = False

        for name, interrupt in (("stop", stop), ("tick failure", fail_tick)):
            with self.subTest(interrupt=name, step="begin"):
                def begin(*args, **kwargs):
                    interrupt()
                    return real_begin(*args, **kwargs)
                challenges = self.count(STEP_UP_CHALLENGES)
                with patch.object(self.ceremonies, "begin_step_up", side_effect=begin):
                    result = await self.begin(cookie, csrf)
                await self.restart()
                self.assertEqual(result, GENERIC)
                self.assertEqual(self.count(STEP_UP_CHALLENGES), challenges)
            with self.subTest(interrupt=name, step="finish"):
                begun = await self.begin(cookie, csrf)
                assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
                before = self.unchanged_state(cookie)

                def finish(*args, **kwargs):
                    interrupt()
                    return real_finish(*args, **kwargs)
                self.assertEqual(self.count(STEP_UP_CHALLENGES), 1)
                with patch.object(self.ceremonies, "finish_step_up", side_effect=finish):
                    result = await self.finish(cookie, csrf, assertion)
                # Refused before anything is consumed (``_step_up_epoch``):
                # the pending challenge is still stored, not spent by the
                # refused request.
                self.assertEqual(self.count(STEP_UP_CHALLENGES), 1)
                await self.restart()
                self.assertEqual(result, GENERIC)
                self.assertEqual(self.unchanged_state(cookie), before)
                self.assertEqual(self.count(STEP_UP_CHALLENGES), 1)
        self.assertEqual(await self.owner_operation(cookie, csrf), STEP_UP)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)

    async def test_the_ceremony_commits_under_the_authorization_epoch(self):
        """A close/reopen cycle between the authorization and the ceremony
        refuses the commit: the ceremony reuses the request's epoch."""
        _, key, _, cookie, csrf = await self.owner_session()
        self.elapse(minutes=6)
        real_begin = self.ceremonies.begin_step_up
        real_finish = self.ceremonies.finish_step_up

        def cycle():
            self.close_access()
            self.reopen_access()

        def begin(*args, **kwargs):
            cycle()
            return real_begin(*args, **kwargs)

        with patch.object(self.ceremonies, "begin_step_up", side_effect=begin):
            self.assertEqual(await self.begin(cookie, csrf), GENERIC)
        self.assertEqual(self.count(STEP_UP_CHALLENGES), 0)
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
        before = self.unchanged_state(cookie)

        def finish(*args, **kwargs):
            cycle()
            return real_finish(*args, **kwargs)

        with patch.object(self.ceremonies, "finish_step_up", side_effect=finish):
            self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
        self.assertEqual(self.unchanged_state(cookie), before)

    def test_ceremony_epoch_argument_is_strict(self):
        for epoch in (None, True, "0", 1.0):
            with self.subTest(epoch=epoch):
                with self.assertRaises(AccessValidationError):
                    self.ceremonies.begin_step_up(b"x" * 32, VIEWER, epoch=epoch)
                with self.assertRaises(AccessValidationError):
                    self.ceremonies.finish_step_up(b"x" * 32, VIEWER, {}, epoch=epoch)
        self.assertEqual(self.count(STEP_UP_CHALLENGES), 0)


class RateLimitAndHygieneTests(StepUpFixture):
    async def test_step_up_routes_are_charged_to_their_own_limiter_before_any_work(self):
        _, key, _, cookie, csrf = await self.owner_session()
        self.access.step_up_limiter = SourceRateLimiter(per_source_capacity=2, global_capacity=None,
                                                        monotonic=self.limit_clock)
        self.elapse(minutes=6)
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST, tamper=True)
        self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
        rows = self.session_rows()
        refused = self.access.refused_step_ups
        signin_limited = self.access.rate_limiter.limited
        # Record (never raise: ``_authorize`` turns any exception into the
        # generic denial, which would hide work done after the limiter).
        work = []
        real_body = self.surface._body
        real_current = self.store.session_may_be_current

        async def body(*args, **kwargs):
            work.append("body")
            return await real_body(*args, **kwargs)

        def current(*args, **kwargs):
            work.append("session")
            return real_current(*args, **kwargs)

        with patch.object(self.surface, "_body", side_effect=body), \
                patch.object(self.store, "session_may_be_current", side_effect=current), \
                patch.object(self.ceremonies, "begin_step_up") as begin_ceremony, \
                patch.object(self.ceremonies, "finish_step_up") as finish_ceremony:
            self.assertEqual(await self.begin(cookie, csrf), GENERIC)
            self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
        self.assertEqual(work, [])
        begin_ceremony.assert_not_called()
        finish_ceremony.assert_not_called()
        self.assertEqual(self.access.step_up_limiter.limited, 2)
        # Neither the sign-in limiter nor the refusal counter saw them.
        self.assertEqual(self.access.rate_limiter.limited, signin_limited)
        self.assertEqual(self.access.refused_step_ups, refused)
        self.assertEqual(self.session_rows(), rows)
        self.limit_clock.value += 60
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)

    async def test_a_sign_in_flood_does_not_block_the_owner_step_up(self):
        """Owner decision 2026-10-12: separate buckets per route."""
        _, key, _, cookie, csrf = await self.owner_session()
        self.access.rate_limiter = SourceRateLimiter(per_source_capacity=3, monotonic=self.limit_clock)
        self.access.step_up_limiter = step_up_rate_limiter(monotonic=self.limit_clock)
        self.elapse(minutes=6)
        for _ in range(3):
            self.assertEqual(status(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)), 200)
        # The sign-in bucket of this source (the shared login) is empty.
        self.assertEqual(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH), GENERIC)
        self.assertEqual(self.access.rate_limiter.limited, 1)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.assertEqual(self.access.step_up_limiter.limited, 0)
        self.assertEqual(self.access.rate_limiter.limited, 1)

    async def test_a_step_up_flood_does_not_spend_the_sign_in_bucket(self):
        _, key, _, cookie, csrf = await self.owner_session()
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW,))
        self.access.rate_limiter = SourceRateLimiter(per_source_capacity=2, monotonic=self.limit_clock)
        self.access.step_up_limiter = step_up_rate_limiter(monotonic=self.limit_clock)
        self.elapse(minutes=6)
        for _ in range(5):
            self.assertEqual(status(await self.begin(cookie, csrf)), 200)
        for _ in range(3):
            self.assertEqual(await self.begin(cookie, csrf), GENERIC)
        self.assertEqual(self.access.step_up_limiter.limited, 3)
        # Two sign-in requests (options and finish) fit the sign-in bucket of
        # capacity 2 only if the flood spent none of it.
        await self.sign_in(viewer_key)
        self.assertEqual(self.access.rate_limiter.limited, 0)
        # The step-up bucket refills at one per 12 seconds.
        self.limit_clock.value += 11
        self.assertEqual(await self.begin(cookie, csrf), GENERIC)
        self.limit_clock.value += 13
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)

    def test_one_limiter_object_cannot_serve_two_routes(self):
        default = HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                              ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                                           clock=self.ceremony_clock),
                              reservation=self.check)
        limiter = default.step_up_limiter
        self.assertEqual((limiter.per_source_capacity, limiter.per_source_refill_seconds,
                          limiter.global_capacity), (5, 12.0, None))
        self.assertEqual(len({id(default.rate_limiter), id(default.redemption_limiter), id(limiter)}), 3)
        shared = SourceRateLimiter()
        other = SourceRateLimiter()
        for limiters in ({"rate_limiter": shared, "step_up_limiter": shared},
                         {"redemption_limiter": shared, "step_up_limiter": shared},
                         {"rate_limiter": shared, "redemption_limiter": other, "step_up_limiter": shared},
                         {"step_up_limiter": object()}):
            with self.subTest(limiters=sorted(limiters)):
                ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                               clock=self.ceremony_clock)
                with self.assertRaises(HumanAccessUnavailable):
                    HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                                ceremonies=ceremonies, reservation=self.check, **limiters)

    async def test_every_refusal_is_byte_identical(self):
        _, key, _, cookie, csrf = await self.owner_session()
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW,))
        viewer = await self.sign_in(viewer_key)
        self.elapse(minutes=6)
        begun = await self.begin(cookie, csrf)
        assertion = key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST, uv=False)
        results = [
            await self.begin(None, None),
            await self.begin(viewer, await self.csrf(viewer)),
            await self.begin(cookie, None),
            await self.finish(cookie, csrf, assertion),
            await self.finish(cookie, csrf, b"{}"),
            await call(self.surface, "GET", STEP_UP_OPTIONS_PATH, cookie=cookie),
            await call(self.surface, "PUT", STEP_UP_PATH, cookie=cookie),
            await call(self.surface, "POST", STEP_UP_PATH + "/", cookie=cookie),
        ]
        self.close_access()
        results.append(await self.begin(cookie, csrf))
        self.reopen_access()
        self.access.stop()
        results.append(await self.begin(cookie, csrf))
        for index, result in enumerate(results):
            with self.subTest(index=index):
                self.assertEqual(result, GENERIC)

    async def test_no_secret_reaches_a_log_and_refusals_are_counted_value_free(self):
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
        owner, key, credential, cookie, csrf = await self.owner_session()
        _, viewer_key, _ = self.enroll((Permission.LIVE_VIEW,))
        self.elapse(minutes=6)
        seen = [cookie.split("=", 1)[1], csrf, VIEWER, OTHER_LOGIN, str(owner.id),
                b64(credential.credential_id), credential.credential_id.hex()]
        for _ in range(4):
            begun = await self.begin(cookie, csrf)
            assertion = viewer_key.assertion(payload(begun), origin=ORIGIN, rp_id=HOST)
            seen += [payload(begun)["challenge"], assertion["response"]["signature"]]
            self.assertEqual(await self.finish(cookie, csrf, assertion), GENERIC)
        await self.finish(cookie, csrf, b"{}", identity=OTHER_LOGIN)
        self.assertEqual(status(await self.step_up(cookie, csrf, key)), 204)
        self.assertEqual(self.access.refused_step_ups, 5)
        events = [record.msg for record in records if record.msg == Event.OWNER_STEP_UP_REFUSED]
        self.assertEqual(len(events), 3)  # at 1, 2 and 4
        formatter = SafeJsonFormatter()
        for record in records:
            text = " ".join((repr(record.__dict__), formatter.format(record)))
            for value in seen:
                self.assertNotIn(value, text)
        # The audit log holds only the logical UUID of the Owner.
        for item in self.audit.list_records():
            text = repr(item)
            for value in seen[:4] + seen[5:]:
                self.assertNotIn(value, text)


class StoreFreshnessTests(StepUpFixture):
    async def test_authorize_owner_uses_the_same_rule(self):
        _, key, _, cookie, _ = await self.owner_session()
        token = self.token(cookie)
        self.assertIsNotNone(self.store.authorize_owner(token, VIEWER, admit=self.gated()))
        self.boot.advance(minutes=2)  # wall clock stepped back by two minutes
        with self.assertRaises(StepUpRequired):
            self.store.authorize_owner(token, VIEWER, admit=self.gated())
        with self.assertRaises(StepUpRequired):
            self.store.authorize_request(token, VIEWER, Requirement.OWNER_OP, admit=self.gated())
        view = self.store.authorize_request(token, VIEWER, Requirement.OWNER_READ, admit=self.gated())
        self.assertIsInstance(view, SessionView)
        self.assertIsInstance(view.session_id, UUID)


if __name__ == "__main__":
    unittest.main()
