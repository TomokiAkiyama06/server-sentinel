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


class StopInterrupted(Exception):
    """Issue #385: a check stopped part-way because the Main shutdown began.

    Its partial result is discarded, never recorded as a finding.
    """


class _Interrupted:
    """The type of `INTERRUPTED`; it has a single instance."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "INTERRUPTED"


# Issue #385 (PR #389 review): what a check returns when the Main shutdown cut
# it short, so the monitoring runtime can tell it from a check that completed
# (and keeps the step's degraded flag and retry as they were).
INTERRUPTED = _Interrupted()


def never() -> bool:
    """The default `interrupted` / `stopping` check: no shutdown ever begins."""
    return False


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
# - process exit and the short steps between them (an estimate, not derived);
PROCESS_EXIT_SECONDS = 4.0
# Issue #385 (phase 2; Owner decisions 2026-11-05 and 2026-11-08: these three
# terms are in the reserve, so the longest local UVC join is 28.75 s):
# - the monitoring step already running when the stop began, when it is the
#   hardware integrity check: its probe in flight is killed within one poll
#   slice and reaped for at most 1 s (`integrity.probes.STOP_POLL_SECONDS`
#   + `STOP_REAP_SECONDS`), and nothing is recorded. The settles and every
#   cross-thread storage admission queue behind this step, so it counts once;
INTEGRITY_PROBE_STOP_SECONDS = 0.25 + 1.0
# - a shutdown settle checks its deadline between polls; a poll started
#   before it begins no further outcome write or callback after it
#   (`NotificationService.poll(deadline=)`), so it overshoots by at most the
#   one write in progress: one SQLite busy timeout (`BUSY_TIMEOUT_SECONDS`)
#   plus that write's own I/O. Only one settle runs at a stop (or, when none
#   did, the stop's own poll, `MonitoringRuntime._persist_outcomes`) and the
#   final storage sample's wait already counts this overshoot as settle time.
#   A completion callback whose transaction waits for more than one lock
#   (a rollback-journal commit) can take longer; that is not bounded yet
#   (Issue #396).
SETTLE_POLL_OVERSHOOT_SECONDS = 5.0
# - the stop's last outcome write (Owner decision 2026-11-08): the deliveries
#   that finished after the last settle's deadline (or while it ended
#   unsettled) and the retained refused writes are written by
#   `NotificationService.persist_completed` in one transaction whose
#   RESERVED (`BEGIN IMMEDIATE`) and EXCLUSIVE (`COMMIT`) lock waits share
#   one SQLite busy timeout (`BUSY_TIMEOUT_SECONDS`,
#   `NotificationEventStore.upsert_many`), plus its own I/O, once per stop. Without it the next start could send a reconciled kind again.
LATE_OUTCOME_WRITE_SECONDS = 5.0
OTHER_STOP_STEPS_RESERVE_SECONDS = (HTTP_GRACEFUL_SHUTDOWN_SECONDS + RESERVATION_CHECK_STOP_SECONDS
                                    + SCENE_STOP_SECONDS + PROCESS_EXIT_SECONDS
                                    + INTEGRITY_PROBE_STOP_SECONDS + SETTLE_POLL_OVERSHOOT_SECONDS
                                    + LATE_OUTCOME_WRITE_SECONDS)
# Once the stop began, a write from another thread waits for the storage
# admission (`MonitoringRuntime.reservation`) at most until this long after the
# stop while the jobs queued at the stop still run (every such wait shares
# that deadline, PR #389 review), and this long from the later of its start
# and their end afterwards; it is then refused as a denial (nothing written;
# the caller handles it as any storage refusal and the next start does it
# again). Not in the reserve (Owner decision 2026-11-05): behind a bounded
# step (the integrity check above) the wait ends with that step and adds
# nothing; the cap only matters behind the steps that are still unbounded
# (below), whose own time the reserve cannot cover anyway.
STOP_ADMISSION_WAIT_SECONDS = 5.0
# Still not bounded (Issue #385): the other monitoring steps already running
# when the stop began (retention `_trim`, the storage sample, the daily
# summary, a startup retry, a recording self-test adapter stage), the SQLite
# busy timeouts summed over the many writes in the human access stop, the
# timeline finish and the dispatch, and of a check that completed just before
# the stop (the integrity `store.record` / `deliver` and the self-test's
# `record_result` writes), a hung filesystem call, and the dispatch steps
# before the critical settle, with their deadline-less polls. The completion
# callbacks of deliveries that finished after the last settle's deadline are
# not called; their outcome rows are written (`LATE_OUTCOME_WRITE_SECONDS`).
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
