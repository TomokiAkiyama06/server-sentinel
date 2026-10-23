"""Issue #205: the Owner's scene calibration routes on the human surface.

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows, a temporary SQLite database, generated luma samples and
the in-process ASGI driver of ``test_human_surface``. Mock only: no camera,
browser, proxy, Tailscale or real authenticator is involved.
"""

from contextlib import closing
import json
from uuid import uuid4

from app.audit.model import AuditAction
from app.auth.human_surface import (
    SCENE_CALIBRATION_PATH, SCENE_SOURCES_PATH, HumanAccessUnavailable, match_route,
)
from app.auth.store import Requirement
from app.detection.roi.calibration_service import (
    SceneCalibrationConfiguration, SceneCalibrationService, TransientReferences,
)
from app.detection.roi.runtime import (
    ArchiveCalibrationProvider, SceneMonitoringConfiguration, SceneMonitoringDependencies,
    SceneMonitoringRuntime, SceneSourceState,
)
from app.cameras.registry.models import SourceType

from tests.test_human_admin_routes import AdminRouteFixture
from tests.test_human_gated_authorization import GENERIC, STEP_UP
from tests.test_human_surface import payload, status
from tests.test_scene_calibration import Feed, assert_no_frame_trace, database_bytes, template
from tests.test_scene_runtime import OTHER, Recorder, binding
from tests.test_uvc_runtime import wait_for


CONFIRMED = {"normal_position_confirmed": True}
STATUS_KEYS = {"source_id", "origin", "version", "calibrated_at", "phase", "failure",
               "owner_calibration_available", "detection", "detection_reason"}


class SceneRouteFixture(AdminRouteFixture):
    timeout = 5.0

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.references = TransientReferences()
        remote = binding(OTHER, SourceType.REMOTE_AGENT, sample_interval_ns=1_000_000)
        self.runtime = SceneMonitoringRuntime(
            SceneMonitoringConfiguration((remote,)),
            SceneMonitoringDependencies(
                recorder=Recorder(), tick_seconds=0.01,
                calibrations=ArchiveCalibrationProvider(self.database.connect_read_only,
                                                        references=self.references)))
        self.service = SceneCalibrationService(
            SceneCalibrationConfiguration((template(),), acquisition_timeout_seconds=self.timeout),
            self.runtime, self.database.connect_read_only, references=self.references)
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.addCleanup(self.service.close)
        self.access.attach_scene_calibration(self.service)

    @property
    def calibrate_path(self):
        return f"{SCENE_SOURCES_PATH}/{OTHER}/calibration"

    async def calibrate(self, body=CONFIRMED, **options):
        return await self.admin("POST", self.calibrate_path, body, **options)

    async def read_status(self, **options):
        return await self.admin("GET", SCENE_CALIBRATION_PATH, csrf=None, **options)

    def history(self):
        with closing(self.database.connect()) as connection:
            return [row[0] for row in connection.execute(
                "SELECT version FROM roi_calibration_history ORDER BY version")]

    def calibration_records(self):
        return [(record.actor_category.value, record.outcome.value, record.target_logical_id)
                for record in self.audit.list_records(limit=1000)
                if record.action is AuditAction.CALIBRATE_SCENE_SOURCE]


class SceneRouteTests(SceneRouteFixture):
    async def test_route_table_entries(self):
        source = str(uuid4())
        expected = {
            ("GET", SCENE_CALIBRATION_PATH): (Requirement.OWNER_READ, False, False, 0),
            ("POST", f"{SCENE_SOURCES_PATH}/{source}/calibration"): (Requirement.OWNER_OP, True, True, 128),
        }
        for (method, path), values in expected.items():
            route = match_route({"method": method, "path": path, "raw_path": path.encode()})
            self.assertEqual((route.requirement, route.mutating, route.csrf, route.body_limit), values)
        for path in (f"{SCENE_SOURCES_PATH}/{source.upper()}/calibration", f"{SCENE_SOURCES_PATH}/{source}",
                     f"{SCENE_SOURCES_PATH}/{source}/calibration/", SCENE_SOURCES_PATH):
            self.assertIsNone(match_route({"method": "POST", "path": path, "raw_path": path.encode()}))
        self.assertIsNone(match_route({"method": "POST", "path": SCENE_CALIBRATION_PATH,
                                       "raw_path": SCENE_CALIBRATION_PATH.encode()}))

    async def test_owner_calibrates_and_reads_a_value_free_status(self):
        result = await self.read_status()
        self.assertEqual(200, status(result))
        (item,) = payload(result)["sources"]
        self.assertEqual(STATUS_KEYS, set(item))
        self.assertEqual((str(OTHER), "none", None, "idle", None, True, "inactive"),
                         (item["source_id"], item["origin"], item["version"], item["phase"], item["failure"],
                          item["owner_calibration_available"], item["detection"]))
        with Feed(self.runtime):
            result = await self.calibrate()
            self.assertEqual(200, status(result))
            body = payload(result)
            self.assertEqual(({"outcome", "version", "calibrated_at"}, "calibrated", 1),
                             (set(body), body["outcome"], body["version"]))
            self.assertTrue(wait_for(lambda: self.runtime.status().sources[0].state
                                     is SceneSourceState.ACTIVE))
        self.assertEqual([1], self.history())
        self.assertEqual([("owner", "succeeded", OTHER)], self.calibration_records())
        (item,) = payload(await self.read_status())["sources"]
        self.assertEqual(("owner", 1, body["calibrated_at"]), (item["origin"], item["version"], item["calibrated_at"]))
        # Nothing about the image, its digest, the polygon or the policy.
        text = json.dumps(payload(await self.read_status()))
        for forbidden in ("sha256", "polygon", "policy", "pixels", "reference", "stream"):
            self.assertNotIn(forbidden, text)
        assert_no_frame_trace(self, database_bytes(self.database.path))

    async def test_non_owner_sessions_are_refused_on_both_routes(self):
        before = self.history(), self.calibration_records()
        with Feed(self.runtime):
            self.assertEqual(GENERIC, await self.read_status(cookie=self.target_cookie))
            self.assertEqual(GENERIC, await self.calibrate(cookie=self.target_cookie, csrf=self.target_csrf))
            self.assertEqual(GENERIC, await self.read_status(cookie=None))
            self.assertEqual(GENERIC, await self.calibrate(cookie=None, csrf=None))
        self.assertEqual(before, (self.history(), self.calibration_records()))
        self.assertIs(SceneSourceState.INACTIVE, self.runtime.status().sources[0].state)

    async def test_a_stale_owner_must_step_up_and_nothing_happens_before(self):
        self.elapse(minutes=6)
        with Feed(self.runtime):
            self.assertEqual(STEP_UP, await self.calibrate())
            self.assertEqual([], self.history())
            self.assertEqual([], self.calibration_records())
            # The status read stays available to a stale Owner (OWNER_READ).
            self.assertEqual(200, status(await self.read_status()))
            self.assertEqual(204, status(await self.step_up(self.owner_cookie, self.owner_csrf,
                                                            self.owner_key)))
            self.assertEqual("calibrated", payload(await self.calibrate())["outcome"])
        self.assertEqual([1], self.history())

    async def test_strict_body_csrf_and_known_source(self):
        for body in ({}, {"normal_position_confirmed": False}, {"normal_position_confirmed": 1},
                     {"normal_position_confirmed": True, "extra": 1}, []):
            with self.subTest(body=body):
                self.assertEqual(GENERIC, await self.calibrate(body))
        self.assertEqual(GENERIC, await self.calibrate(raw=b'{"normal_position_confirmed":true,'
                                                          b'"normal_position_confirmed":true}'))
        self.assertEqual(GENERIC, await self.calibrate(csrf=None))
        self.assertEqual(GENERIC, await self.admin("POST", f"{SCENE_SOURCES_PATH}/{uuid4()}/calibration",
                                                   CONFIRMED))
        self.assertEqual([], self.history())
        self.assertEqual([], self.calibration_records())

    async def test_a_refused_attempt_is_reported_and_audited_as_failed(self):
        self.service.configuration = SceneCalibrationConfiguration((template(),), acquisition_timeout_seconds=1)
        result = await self.calibrate()
        self.assertEqual(200, status(result))
        self.assertEqual({"outcome": "refused", "reason": "no_frame"}, payload(result))
        self.assertEqual([], self.history())
        self.assertEqual([("owner", "failed", OTHER)], self.calibration_records())
        (item,) = payload(await self.read_status())["sources"]
        self.assertEqual(("none", "no_frame"), (item["origin"], item["failure"]))

    async def test_a_closed_gate_during_acquisition_commits_nothing(self):
        original = self.service._read

        def read_then_close(*args):
            frame = original(*args)
            self.close_access()
            return frame

        self.service._read = read_then_close
        with Feed(self.runtime):
            self.assertEqual(GENERIC, await self.calibrate())
        self.assertEqual([], self.history())
        self.assertEqual([("owner", "failed", OTHER)], self.calibration_records())
        self.assertEqual({}, self.references._frames)


class UnattachedTests(AdminRouteFixture):
    async def test_without_a_service_both_routes_are_the_generic_denial(self):
        self.assertEqual(GENERIC, await self.admin("GET", SCENE_CALIBRATION_PATH, csrf=None))
        self.assertEqual(GENERIC, await self.admin("POST", f"{SCENE_SOURCES_PATH}/{OTHER}/calibration",
                                                   CONFIRMED))

    async def test_attach_refuses_anything_but_one_service(self):
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_scene_calibration(object())
