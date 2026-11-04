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
        self.assertEqual(63.0, stop_budget.local_uvc_stop_seconds(uvc(60)))
        self.assertEqual(0.0, stop_budget.local_uvc_stop_seconds(None))

    def test_every_deployment_local_uvc_setting_fits_without_a_scene_timeline(self):
        # The deployment file holds no notification settle, so `--check` can
        # never be refused by this budget: even the longest join fits with
        # the camera offline settle.
        longest = parse_local_uvc({"source_ids": [str(uuid4())], "join_timeout_seconds": 60})
        stop_budget.check_stop_budget(longest, None)
        stop_budget.check_stop_budget(None, MAXIMUM_DISPATCH_SETTLE_SECONDS)
        stop_budget.check_stop_budget(LocalUvcConfiguration((uuid4(),)), DEFAULT_DISPATCH_SETTLE_SECONDS)

    def test_bounds_whose_sum_exceeds_the_budget_are_refused(self):
        # Issue #364: 60 s join (63 s stop) + 30 s settle overran 90 s.
        with self.assertRaises(ConfigurationError):
            stop_budget.check_stop_budget(uvc(60), MAXIMUM_DISPATCH_SETTLE_SECONDS)
        edge = LIMIT - 63.0
        stop_budget.check_stop_budget(uvc(60), edge)
        with self.assertRaises(ConfigurationError):
            stop_budget.check_stop_budget(uvc(60), edge + 0.01)
        stop_budget.check_stop_budget(uvc(LIMIT - 3.0 - MAXIMUM_DISPATCH_SETTLE_SECONDS),
                                      MAXIMUM_DISPATCH_SETTLE_SECONDS)

    def test_create_app_refuses_a_composition_over_the_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory))
            with self.assertRaises(ConfigurationError):
                create_app(settings, local_uvc=uvc(60), scene_timeline=timeline(30))
            # Within the budget the check passes; the composition is then
            # refused for its own reason (no scene monitoring), not this one.
            with self.assertRaises(TypeError):
                create_app(settings, local_uvc=uvc(60), scene_timeline=timeline(12))

    def test_the_installed_unit_uses_the_budget_timeout(self):
        # The unit template stays literal (`test_listener_owner_contract`
        # reads it as text); the budget must name the same timeout.
        source = (Path(__file__).resolve().parents[1] / "install.py").read_text()
        self.assertEqual(1, source.count("\nTimeoutStopSec="))
        self.assertIn(f"\nTimeoutStopSec={stop_budget.UNIT_STOP_TIMEOUT_SECONDS}\n", source)


if __name__ == "__main__":
    unittest.main()
