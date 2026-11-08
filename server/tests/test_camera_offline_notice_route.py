"""Issue #301 item 2: the Owner's camera offline notice on the human surface.

When a camera source stays not online past the deployment threshold and no
notification destination (Slack) is configured, or Slack is configured but
the latest camera offline delivery did not reach it (Issue #394), the Owner
is not notified outside the dashboard; ``GET /api/monitoring/camera-offline`` (``OWNER_READ``)
lets the Owner's dashboard show that fact. Synthetic only: software
authenticators, synthetic ``/proc/net`` rows, a temporary SQLite database and
the in-process ASGI driver of ``test_human_surface``. Mock only: no camera,
browser, proxy, Tailscale, Slack or real authenticator is involved.
"""

from unittest import TestCase

from app.auth.human_surface import (
    ADMIN_PRINCIPALS_PATH, CAMERA_OFFLINE_NOTICE_PATH, SESSION_PATH, HumanAccessUnavailable, match_route,
)
from app.auth.model import Permission
from app.auth.store import Requirement
from app.monitoring.runtime import MonitoringStatus, RuntimeState

from tests.test_human_admin_routes import AdminRouteFixture
from tests.test_human_gated_authorization import GENERIC
from tests.test_human_surface import payload, status


class Reader:
    """A synthetic notice reader that records its calls."""

    def __init__(self, value="notified"):
        self.value = value
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class CameraOfflineNoticeRouteTests(AdminRouteFixture):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.reader = Reader()
        self.access.attach_camera_offline_notice(self.reader)

    async def read(self, **options):
        return await self.admin("GET", CAMERA_OFFLINE_NOTICE_PATH, csrf=None, **options)

    async def test_route_table_entry(self):
        path = CAMERA_OFFLINE_NOTICE_PATH
        route = match_route({"method": "GET", "path": path, "raw_path": path.encode()})
        self.assertEqual((Requirement.OWNER_READ, False, False, 0),
                         (route.requirement, route.mutating, route.csrf, route.body_limit))
        self.assertIsNone(match_route({"method": "POST", "path": path, "raw_path": path.encode()}))
        for other in (path + "/", "/api/monitoring", "/api/monitoring/camera-offline/x"):
            self.assertIsNone(match_route({"method": "GET", "path": other, "raw_path": other.encode()}))

    async def test_the_owner_reads_one_boolean_and_one_fixed_word(self):
        for value, expected in (("notified", {"offline_unnotified": False, "cause": None}),
                                ("not_configured", {"offline_unnotified": True,
                                                    "cause": "not_configured"}),
                                ("delivery_failed", {"offline_unnotified": True,
                                                     "cause": "delivery_failed"}),
                                ("notified", {"offline_unnotified": False, "cause": None})):
            with self.subTest(value=value):
                self.reader.value = value
                result = await self.read()
                self.assertEqual(200, status(result))
                self.assertEqual(expected, payload(result))

    async def test_non_owner_sessions_are_refused_before_the_reader(self):
        # The notification configuration is the Owner's alone: neither
        # permission, alone or together, nor a revoked session reaches it.
        self.reader.value = "delivery_failed"
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
        self.assertEqual({"offline_unnotified": True, "cause": "not_configured"},
                         payload(await self.read()))

    async def test_background_polls_never_renew_the_idle_expiry(self):
        # Codex PR #388 (P1): the Web samples this route every 60 s with no
        # user interaction; it must not keep an unattended session alive.
        self.reader.value = "not_configured"
        for _ in range(5):  # 25 minutes of polling after the last touch
            self.elapse(minutes=5)
            self.assertEqual(200, status(await self.read()))
        self.elapse(minutes=6)  # 31 minutes: past the idle limit (30)
        self.assertEqual(GENERIC, await self.read())
        self.assertEqual(GENERIC, await self.admin("GET", SESSION_PATH, csrf=None))

    async def test_a_session_read_still_renews_while_polls_do_not(self):
        # Control for the test above: the same timeline with one touching
        # session read in the middle keeps the session alive.
        for _ in range(5):
            self.elapse(minutes=5)
            self.assertEqual(200, status(await self.read()))
        self.assertEqual(200, status(await self.admin("GET", SESSION_PATH, csrf=None)))
        self.elapse(minutes=6)
        self.assertEqual(200, status(await self.read()))

    async def test_closed_access_is_refused_before_the_reader(self):
        self.close_access()
        self.assertEqual(GENERIC, await self.read())
        self.assertEqual(0, self.reader.calls)

    async def test_a_failing_or_unknown_reader_answer_is_never_a_guessed_one(self):
        for value in (RuntimeError("synthetic"), None, 0, 1, True, False, "true", "false",
                      "", "NOTIFIED", "delivery_failed ", "failed"):
            with self.subTest(value=value):
                self.reader.value = value
                self.assertEqual(GENERIC, await self.read())

    async def test_the_route_takes_no_query(self):
        self.reader.value = "not_configured"
        self.assertEqual(GENERIC, await self.read(query=b"source=1"))
        self.assertEqual(0, self.reader.calls)

    async def test_attach_refuses_anything_but_one_reader(self):
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_camera_offline_notice(object())
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_camera_offline_notice(Reader())
        # The same reader again is accepted.
        self.access.attach_camera_offline_notice(self.reader)
        self.assertIs(self.reader, self.access.camera_offline_notice)


class WithoutReaderTests(AdminRouteFixture):
    async def test_without_a_reader_the_route_is_the_generic_denial(self):
        self.assertIsNone(self.access.camera_offline_notice)
        self.assertEqual(GENERIC, await self.admin("GET", CAMERA_OFFLINE_NOTICE_PATH, csrf=None))


class UnnotifiedStatusTests(TestCase):
    def test_the_cause_word_follows_the_status(self):
        # Issue #394: (degraded, notifications, delivery failing) -> word.
        cases = {
            (False, False, False): "notified",
            (False, True, True): "notified",
            (True, False, False): "not_configured",
            (True, False, True): "not_configured",
            (True, True, False): "notified",
            (True, True, True): "delivery_failed",
        }
        for (degraded, notifications, failing), expected in cases.items():
            with self.subTest(degraded=degraded, notifications=notifications, failing=failing):
                status_ = MonitoringStatus(RuntimeState.RUNNING, camera_offline_degraded=degraded,
                                           camera_offline_notifications=notifications,
                                           camera_offline_delivery_failing=failing)
                self.assertEqual(expected, status_.camera_offline_cause)
                self.assertIs(expected != "notified", status_.camera_offline_unnotified)

    def test_only_a_current_condition_without_a_destination_is_unnotified(self):
        cases = {
            (False, False): False,
            (False, True): False,
            (True, True): False,
            (True, False): True,
        }
        for (degraded, notifications), expected in cases.items():
            with self.subTest(degraded=degraded, notifications=notifications):
                status_ = MonitoringStatus(RuntimeState.RUNNING, camera_offline_degraded=degraded,
                                           camera_offline_notifications=notifications)
                self.assertIs(expected, status_.camera_offline_unnotified)
