"""Issue #301 follow-up: the Owner's notification destination notice.

Without a configured notification destination (Slack) no Owner notification
(camera offline, capture node, hardware integrity, recording health, human
access, ...) leaves the Main Server; with Slack configured a delivery of this
process may still have failed. ``GET /api/monitoring/notifications``
(``OWNER_READ``) lets the Owner's dashboard show either fact. Synthetic only:
software authenticators, a temporary SQLite database and the in-process ASGI
driver of ``test_human_surface``. Mock only: no camera, browser, proxy,
Tailscale, Slack or real authenticator is involved.
"""

from unittest import TestCase

from app.auth.human_surface import (
    ADMIN_PRINCIPALS_PATH, CAMERA_OFFLINE_NOTICE_PATH, NOTIFICATION_NOTICE_PATH, SESSION_PATH,
    HumanAccessUnavailable, match_route,
)
from app.auth.model import Permission
from app.auth.store import Requirement
from app.monitoring.runtime import MonitoringStatus, RuntimeState
from app.notifications.service import NOTIFICATION_CAUSES

from tests.test_camera_offline_notice_route import Reader
from tests.test_human_admin_routes import AdminRouteFixture
from tests.test_human_gated_authorization import GENERIC
from tests.test_human_surface import payload, status


class NotificationNoticeRouteTests(AdminRouteFixture):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.reader = Reader("delivered")
        self.access.attach_notification_notice(self.reader)

    async def read(self, **options):
        return await self.admin("GET", NOTIFICATION_NOTICE_PATH, csrf=None, **options)

    async def test_route_table_entry(self):
        path = NOTIFICATION_NOTICE_PATH
        route = match_route({"method": "GET", "path": path, "raw_path": path.encode()})
        self.assertEqual((Requirement.OWNER_READ, False, False, 0),
                         (route.requirement, route.mutating, route.csrf, route.body_limit))
        for method in ("POST", "PUT", "DELETE"):
            self.assertIsNone(match_route({"method": method, "path": path, "raw_path": path.encode()}))
        for other in (path + "/", "/api/monitoring", path + "/slack", "/api/monitoring/notification"):
            self.assertIsNone(match_route({"method": "GET", "path": other, "raw_path": other.encode()}))

    async def test_the_owner_reads_one_fixed_word(self):
        for value, expected in (("delivered", {"cause": None}),
                                ("not_configured", {"cause": "not_configured"}),
                                ("delivery_failed", {"cause": "delivery_failed"}),
                                ("delivered", {"cause": None})):
            with self.subTest(value=value):
                self.reader.value = value
                result = await self.read()
                self.assertEqual(200, status(result))
                self.assertEqual(expected, payload(result))

    async def test_non_owner_sessions_are_refused_before_the_reader(self):
        # Deployment configuration and delivery health are the Owner's alone:
        # neither permission, alone or together, nor a revoked session or no
        # session reaches the reader.
        self.reader.value = "not_configured"
        cookies = {"live:view only": self.target_cookie, "no session": None}
        for name, permissions in (("recordings:view only", (Permission.RECORDINGS_VIEW,)),
                                  ("both permissions", (Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))):
            _, key, _ = self.enroll(permissions)
            cookies[name] = await self.sign_in(key)
        revoked, revoked_key, _ = self.enroll((Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW))
        cookies["revoked"] = await self.sign_in(revoked_key)
        self.assertEqual(204, status(await self.admin(
            "POST", f"{ADMIN_PRINCIPALS_PATH}/{revoked.id}/revoke", {})))
        for name, cookie in cookies.items():
            with self.subTest(name):
                self.assertEqual(GENERIC, await self.read(cookie=cookie))
        self.assertEqual(0, self.reader.calls)
        # Control: the sessions above were current before the revocation.
        self.assertEqual(200, status(await self.admin("GET", SESSION_PATH, csrf=None,
                                                      cookie=cookies["both permissions"])))

    async def test_a_stale_owner_is_still_served(self):
        # OWNER_READ: no fresh user verification is required to see it.
        self.elapse(minutes=6)
        self.reader.value = "not_configured"
        self.assertEqual({"cause": "not_configured"}, payload(await self.read()))

    async def test_background_polls_never_renew_the_idle_expiry(self):
        # Like the camera offline notice (Codex PR #388 P1): the Web samples
        # this route every 60 s with no user interaction.
        self.reader.value = "not_configured"
        for _ in range(5):  # 25 minutes of polling after the last touch
            self.elapse(minutes=5)
            self.assertEqual(200, status(await self.read()))
        self.elapse(minutes=6)  # 31 minutes: past the idle limit (30)
        self.assertEqual(GENERIC, await self.read())
        self.assertEqual(GENERIC, await self.admin("GET", SESSION_PATH, csrf=None))

    async def test_closed_access_is_refused_before_the_reader(self):
        self.close_access()
        self.assertEqual(GENERIC, await self.read())
        self.assertEqual(0, self.reader.calls)

    async def test_a_failing_or_unknown_reader_answer_is_never_a_guessed_one(self):
        # `unverified` (the runtime is not running) is "could not be checked".
        for value in (RuntimeError("synthetic"), None, 0, 1, True, False, "", "DELIVERED",
                      "not_configured ", "notified", "configured", "failed", "unverified",
                      "https://hooks.slack.invalid/synthetic"):
            with self.subTest(value=value):
                self.reader.value = value
                self.assertEqual(GENERIC, await self.read())

    async def test_the_route_takes_no_query(self):
        self.reader.value = "not_configured"
        self.assertEqual(GENERIC, await self.read(query=b"detail=1"))
        self.assertEqual(0, self.reader.calls)

    async def test_the_camera_offline_notice_stays_separate(self):
        # Attaching this reader mounts nothing else.
        self.assertIsNone(self.access.camera_offline_notice)
        self.assertEqual(GENERIC, await self.admin("GET", CAMERA_OFFLINE_NOTICE_PATH, csrf=None))

    async def test_attach_refuses_anything_but_one_reader(self):
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_notification_notice(object())
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_notification_notice(Reader())
        # The same reader again is accepted.
        self.access.attach_notification_notice(self.reader)
        self.assertIs(self.reader, self.access.notification_notice)


class WithoutReaderTests(AdminRouteFixture):
    async def test_without_a_reader_the_route_is_the_generic_denial(self):
        self.assertIsNone(self.access.notification_notice)
        self.assertEqual(GENERIC, await self.admin("GET", NOTIFICATION_NOTICE_PATH, csrf=None))


class NotificationCauseTests(TestCase):
    def test_the_cause_word_follows_the_status(self):
        # (state, configured, delivery_failed) -> word.
        cases = {}
        for state in RuntimeState:
            for failed in (False, True):
                # Not configured is a configuration fact, whatever the state.
                cases[(state, False, failed)] = "not_configured"
                cases[(state, True, failed)] = (
                    ("delivery_failed" if failed else "delivered")
                    if state == RuntimeState.RUNNING else "unverified")
        for (state, configured, failed), expected in cases.items():
            with self.subTest(state=state, configured=configured, failed=failed):
                status_ = MonitoringStatus(state, notifications_configured=configured,
                                           notification_delivery_failed=failed)
                self.assertEqual(expected, status_.notification_cause)
                self.assertIn(status_.notification_cause, NOTIFICATION_CAUSES)

    def test_the_default_status_is_not_configured(self):
        self.assertEqual("not_configured", MonitoringStatus(RuntimeState.STARTING).notification_cause)
