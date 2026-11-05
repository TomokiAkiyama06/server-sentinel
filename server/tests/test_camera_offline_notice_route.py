"""Issue #301 item 2: the Owner's camera offline notice on the human surface.

When a camera source stays not online past the deployment threshold and no
notification destination (Slack) is configured, the Owner is not notified
outside the dashboard; ``GET /api/monitoring/camera-offline`` (``OWNER_READ``)
lets the Owner's dashboard show that fact. Synthetic only: software
authenticators, synthetic ``/proc/net`` rows, a temporary SQLite database and
the in-process ASGI driver of ``test_human_surface``. Mock only: no camera,
browser, proxy, Tailscale, Slack or real authenticator is involved.
"""

from unittest import TestCase

from app.auth.human_surface import CAMERA_OFFLINE_NOTICE_PATH, HumanAccessUnavailable, match_route
from app.auth.store import Requirement
from app.monitoring.runtime import MonitoringStatus, RuntimeState

from tests.test_human_admin_routes import AdminRouteFixture
from tests.test_human_gated_authorization import GENERIC
from tests.test_human_surface import payload, status


class Reader:
    """A synthetic notice reader that records its calls."""

    def __init__(self, value=False):
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

    async def test_the_owner_reads_exactly_one_boolean(self):
        for value in (False, True, False):
            with self.subTest(value=value):
                self.reader.value = value
                result = await self.read()
                self.assertEqual(200, status(result))
                self.assertEqual({"offline_unnotified": value}, payload(result))

    async def test_non_owner_sessions_are_refused_before_the_reader(self):
        self.reader.value = True
        self.assertEqual(GENERIC, await self.read(cookie=self.target_cookie))
        self.assertEqual(GENERIC, await self.read(cookie=None))
        self.assertEqual(0, self.reader.calls)

    async def test_a_stale_owner_is_still_served(self):
        # OWNER_READ: no fresh user verification is required to see it.
        self.elapse(minutes=6)
        self.reader.value = True
        self.assertEqual({"offline_unnotified": True}, payload(await self.read()))

    async def test_closed_access_is_refused_before_the_reader(self):
        self.close_access()
        self.assertEqual(GENERIC, await self.read())
        self.assertEqual(0, self.reader.calls)

    async def test_a_failing_or_non_boolean_reader_is_never_a_guessed_answer(self):
        for value in (RuntimeError("synthetic"), None, 0, 1, "true", "false"):
            with self.subTest(value=value):
                self.reader.value = value
                self.assertEqual(GENERIC, await self.read())

    async def test_the_route_takes_no_query(self):
        self.reader.value = True
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
