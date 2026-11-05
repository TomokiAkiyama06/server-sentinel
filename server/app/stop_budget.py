"""The Main shutdown time budget (Issue #364).

Standard library only. `UNIT_STOP_TIMEOUT_SECONDS` names the installed
unit's literal `TimeoutStopSec` (`tests.test_stop_budget` checks they
match), and `app.main.create_app()` refuses a composition whose bounded
stop steps cannot finish inside it, rather than letting systemd kill Main in
the middle of a critical notification settle (Owner decision 2026-11-04:
refuse the configuration, do not shorten the settle at stop time). The
reserve for the other stop steps is derived from their bounds (Issue #383).
"""

from __future__ import annotations

from app.settings import ConfigurationError


# The installed unit's `TimeoutStopSec` (Owner decision 2026-10-08). Past it
# systemd sends SIGKILL.
UNIT_STOP_TIMEOUT_SECONDS = 90
# Issue #383 (phase 1): the stop steps outside the configurable bounds,
# derived from their own constants (`tests.test_stop_budget` checks each):
# - the HTTP server's graceful wait for open requests before the lifespan
#   shutdown starts (`timeout_graceful_shutdown`);
HTTP_GRACEFUL_SHUTDOWN_SECONDS = 5.0
# - the human access stop waits for an in-flight hostname reservation check:
#   all its enumerations share one deadline (`ENUMERATION_TIMEOUT_SECONDS`), plus
#   one SQLite busy timeout for loading the listener exceptions;
RESERVATION_CHECK_STOP_SECONDS = 10.0 + 5.0
# - the scene runtime stop: worker join and final delivery pass, each 5 s,
#   plus the decoder reap (`DECODER_REAP_TIMEOUT_SECONDS`);
SCENE_STOP_SECONDS = 5.0 + 5.0 + 1.0
# - process exit and the short steps between them.
PROCESS_EXIT_SECONDS = 4.0
# Not bounded yet (Issue #383 phase 2, separate Issue): waits for the storage
# admission behind a monitoring job, the SQLite busy timeouts of the writes in
# the human access stop, the timeline finish and the dispatch, and a hung
# filesystem call, and the one monitoring step already running when the stop
# began (an integrity probe run or the recording self-test): a tick starts no
# further long step after it (`MonitoringRuntime.begin_stop`), and the
# settles queue behind it. PROCESS_EXIT_SECONDS is an estimate, not derived.
OTHER_STOP_STEPS_RESERVE_SECONDS = (HTTP_GRACEFUL_SHUTDOWN_SECONDS + RESERVATION_CHECK_STOP_SECONDS
                                    + SCENE_STOP_SECONDS + PROCESS_EXIT_SECONDS)
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
# The longest local UVC `join_timeout_seconds` that fits with the camera
# offline settle; the deployment file refuses a longer one (`--check`).
MAXIMUM_LOCAL_UVC_JOIN_SECONDS = (UNIT_STOP_TIMEOUT_SECONDS - OTHER_STOP_STEPS_RESERVE_SECONDS
                                  - LOCAL_UVC_STOP_OVERHEAD_SECONDS - CAMERA_OFFLINE_SETTLE_SECONDS)


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
