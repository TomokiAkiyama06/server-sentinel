"""The Main shutdown time budget (Issue #364)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from app import stop_budget
from app.cameras.uvc.config import LocalUvcConfiguration, parse_local_uvc
from app.cameras.uvc.runtime import HEALTH_FENCE_SECONDS, HEALTH_SINK_SETTLE_SECONDS
from app.cameras.uvc.supervisor import LocalUvcSupervisor
from app.main import create_app
from app.presence.runtime import (
    DEFAULT_DISPATCH_SETTLE_SECONDS, MAXIMUM_DISPATCH_SETTLE_SECONDS, SceneTimelineConfiguration,
)
from app.settings import ConfigurationError, Settings
from app.auth.reservation import ENUMERATION_TIMEOUT_SECONDS
from app.detection.roi.runtime import DECODER_REAP_TIMEOUT_SECONDS, SceneMonitoringRuntime
from app.storage.database import BUSY_TIMEOUT_SECONDS
from app.integrity import probes
import inspect


LIMIT = stop_budget.UNIT_STOP_TIMEOUT_SECONDS - stop_budget.OTHER_STOP_STEPS_RESERVE_SECONDS


def uvc(join):
    return LocalUvcConfiguration((uuid4(),), join_timeout_seconds=join)


def timeline(settle):
    return SceneTimelineConfiguration(maximum_source_latency=timedelta(seconds=30),
                                      clock=lambda: (datetime.now(timezone.utc), True),
                                      dispatch_settle_seconds=settle)


class StopBudgetTests(unittest.TestCase):
    def test_local_uvc_overhead_is_the_sum_of_its_stop_waits(self):
        self.assertEqual(stop_budget.LOCAL_UVC_STOP_OVERHEAD_SECONDS,
                         LocalUvcSupervisor.WATCHDOG_JOIN_MINIMUM_SECONDS
                         + HEALTH_FENCE_SECONDS + HEALTH_SINK_SETTLE_SECONDS)
        self.assertEqual(43.0, stop_budget.local_uvc_stop_seconds(uvc(40)))
        self.assertEqual(0.0, stop_budget.local_uvc_stop_seconds(None))

    def test_the_reserve_is_derived_from_the_stop_step_constants(self):
        # Issue #383: each part of the reserve names its own bound.
        self.assertEqual(stop_budget.RESERVATION_CHECK_STOP_SECONDS,
                         ENUMERATION_TIMEOUT_SECONDS + BUSY_TIMEOUT_SECONDS)
        stop_timeout = inspect.signature(SceneMonitoringRuntime.stop).parameters["timeout"].default
        self.assertEqual(stop_budget.SCENE_STOP_SECONDS, 2 * stop_timeout + DECODER_REAP_TIMEOUT_SECONDS)
        self.assertEqual(stop_budget.OTHER_STOP_STEPS_RESERVE_SECONDS,
                         stop_budget.HTTP_GRACEFUL_SHUTDOWN_SECONDS + stop_budget.RESERVATION_CHECK_STOP_SECONDS
                         + stop_budget.SCENE_STOP_SECONDS + stop_budget.PROCESS_EXIT_SECONDS)
        self.assertEqual(35.0, stop_budget.OTHER_STOP_STEPS_RESERVE_SECONDS)
        self.assertEqual(40.0, stop_budget.MAXIMUM_LOCAL_UVC_JOIN_SECONDS)
        # The HTTP server is built with the graceful bound.
        source = (Path(__file__).resolve().parents[1] / "app" / "__main__.py").read_text()
        self.assertIn("timeout_graceful_shutdown=HTTP_GRACEFUL_SHUTDOWN_SECONDS", source)

    def test_the_phase_2_bounds_are_derived_and_not_yet_in_the_reserve(self):
        # Issue #385: each new bound names its own constants. They are not
        # in the reserve (an Owner decision: they lower the longest join).
        self.assertEqual(stop_budget.INTEGRITY_PROBE_STOP_SECONDS,
                         probes.STOP_POLL_SECONDS + probes.STOP_REAP_SECONDS)
        self.assertLess(probes.STOP_POLL_SECONDS + probes.STOP_REAP_SECONDS,
                        probes.COMMAND_OUTPUT_SECONDS + probes.COMMAND_REAP_SECONDS)
        self.assertEqual(stop_budget.SETTLE_POLL_OVERSHOOT_SECONDS, BUSY_TIMEOUT_SECONDS)
        self.assertEqual(5.0, stop_budget.STOP_ADMISSION_WAIT_SECONDS)
        with_phase_2 = (stop_budget.OTHER_STOP_STEPS_RESERVE_SECONDS
                        + stop_budget.INTEGRITY_PROBE_STOP_SECONDS
                        + stop_budget.SETTLE_POLL_OVERSHOOT_SECONDS)
        self.assertEqual(41.25, with_phase_2)
        # The longest join they would leave (documented in DEPLOYMENT.md).
        self.assertEqual(33.75, stop_budget.UNIT_STOP_TIMEOUT_SECONDS - with_phase_2
                         - stop_budget.LOCAL_UVC_STOP_OVERHEAD_SECONDS
                         - stop_budget.CAMERA_OFFLINE_SETTLE_SECONDS)

    def test_the_deployment_file_refuses_a_join_over_the_budget(self):
        # Issue #383: `--check` refuses it, not only `create_app()`.
        parse_local_uvc({"source_ids": [str(uuid4())], "join_timeout_seconds": 40})
        for join in (40.01, 60):
            with self.assertRaises(ConfigurationError):
                parse_local_uvc({"source_ids": [str(uuid4())], "join_timeout_seconds": join})

    def test_every_deployment_local_uvc_setting_fits_without_a_scene_timeline(self):
        # The deployment file holds no notification settle, so `--check` can
        # never be refused by this budget: even the longest join fits with
        # the camera offline settle.
        longest = parse_local_uvc({"source_ids": [str(uuid4())], "join_timeout_seconds": 40})
        stop_budget.check_stop_budget(longest, None)
        stop_budget.check_stop_budget(None, MAXIMUM_DISPATCH_SETTLE_SECONDS)
        stop_budget.check_stop_budget(LocalUvcConfiguration((uuid4(),)), DEFAULT_DISPATCH_SETTLE_SECONDS)

    def test_bounds_whose_sum_exceeds_the_budget_are_refused(self):
        # Issue #364: the longest join (43 s stop) + 30 s settle overruns.
        with self.assertRaises(ConfigurationError):
            stop_budget.check_stop_budget(uvc(40), MAXIMUM_DISPATCH_SETTLE_SECONDS)
        edge = LIMIT - 43.0
        stop_budget.check_stop_budget(uvc(40), edge)
        with self.assertRaises(ConfigurationError):
            stop_budget.check_stop_budget(uvc(40), edge + 0.01)
        stop_budget.check_stop_budget(uvc(LIMIT - 3.0 - MAXIMUM_DISPATCH_SETTLE_SECONDS),
                                      MAXIMUM_DISPATCH_SETTLE_SECONDS)

    def test_create_app_refuses_a_composition_over_the_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory))
            with self.assertRaises(ConfigurationError):
                create_app(settings, local_uvc=uvc(40), scene_timeline=timeline(30))
            # Within the budget the check passes; the composition is then
            # refused for its own reason (no scene monitoring), not this one.
            with self.assertRaises(TypeError):
                create_app(settings, local_uvc=uvc(40), scene_timeline=timeline(12))

    def test_the_installed_unit_uses_the_budget_timeout(self):
        # The unit template stays literal (`test_listener_owner_contract`
        # reads it as text); the budget must name the same timeout.
        source = (Path(__file__).resolve().parents[1] / "install.py").read_text()
        self.assertEqual(1, source.count("\nTimeoutStopSec="))
        self.assertIn(f"\nTimeoutStopSec={stop_budget.UNIT_STOP_TIMEOUT_SECONDS}\n", source)


if __name__ == "__main__":
    unittest.main()
