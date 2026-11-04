"""The Main shutdown time budget (Issue #364).

Standard library only: the installer writes the unit's stop timeout from
this module, and `app.main.create_app()` refuses a composition whose bounded
stop steps cannot finish inside it, rather than letting systemd kill Main in
the middle of a critical notification settle (Owner decision 2026-11-04:
refuse the configuration, do not shorten the settle at stop time).
"""

from __future__ import annotations

from app.settings import ConfigurationError


# The installed unit's `TimeoutStopSec` (Owner decision 2026-10-08). Past it
# systemd sends SIGKILL.
UNIT_STOP_TIMEOUT_SECONDS = 90
# Left for the stop steps that have no configurable bound here (human access
# stop, scene stop, timeline finish, the monitoring runtime stop) and for the
# process exit.
OTHER_STOP_STEPS_RESERVE_SECONDS = 10.0
# On top of `join_timeout_seconds`, a local UVC stop waits at most 1 s for the
# frame-progress watchdog join (`WorkerSupervisor.WATCHDOG_JOIN_MINIMUM_SECONDS`),
# 1 s for the fenced `offline` writes of workers that outlived the join
# (`HEALTH_FENCE_SECONDS`) and 1 s for pending health-sink deliveries
# (`HEALTH_SINK_SETTLE_SECONDS`). `tests.test_stop_budget` checks the sum.
LOCAL_UVC_STOP_OVERHEAD_SECONDS = 3.0
# Without a scene critical dispatcher, shutdown waits at most this long for a
# camera offline notification (Issue #301 item 2) or a scene calibration
# notice (#205) still being delivered, longer than the 10 s Slack timeout.
# Only one of the notification settles runs at a stop.
CAMERA_OFFLINE_SETTLE_SECONDS = 12.0


def local_uvc_stop_seconds(local_uvc) -> float:
    """The longest a local UVC stop can take; 0 without local UVC capture."""
    if local_uvc is None:
        return 0.0
    return local_uvc.join_timeout_seconds + LOCAL_UVC_STOP_OVERHEAD_SECONDS


def bounded_stop_seconds(local_uvc, dispatch_settle_seconds: float | None) -> float:
    """The configurable part of the worst-case stop.

    `dispatch_settle_seconds` is the scene timeline's critical settle, or
    None without a scene timeline (the camera offline / calibration settle
    then applies instead).
    """
    settle = (CAMERA_OFFLINE_SETTLE_SECONDS if dispatch_settle_seconds is None
              else float(dispatch_settle_seconds))
    return local_uvc_stop_seconds(local_uvc) + settle


def check_stop_budget(local_uvc, dispatch_settle_seconds: float | None) -> None:
    """Refuse bounds whose sum does not fit the unit's stop timeout."""
    limit = UNIT_STOP_TIMEOUT_SECONDS - OTHER_STOP_STEPS_RESERVE_SECONDS
    if bounded_stop_seconds(local_uvc, dispatch_settle_seconds) > limit:
        raise ConfigurationError(
            "local UVC join timeout and notification settle exceed the stop budget")
