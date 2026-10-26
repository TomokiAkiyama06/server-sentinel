"""Structured logging with an allowlist instead of unsafe string scrubbing."""

from datetime import datetime, timezone
from enum import StrEnum
import json
import logging
import math
import sys
from typing import TextIO


class Event(StrEnum):
    STARTED = "application_started"
    STOPPED = "application_stopped"
    STARTUP_FAILED = "application_startup_failed"
    AUDIT_RETENTION_DEGRADED = "audit_retention_degraded"
    MONITORING_STARTED = "monitoring_started"
    MONITORING_UNCONFIGURED = "monitoring_storage_unconfigured"
    MONITORING_STARTUP_FAILED = "monitoring_startup_failed"
    MONITORING_DEGRADED = "monitoring_degraded"
    # Issue #351: the previous process exited without its graceful stop.
    MONITORING_PREVIOUS_RUN_UNCLEAN = "monitoring_previous_run_unclean"
    # Issue #351: `pending` recording-health failures left out of the
    # restart resend (beyond the limit).
    RECORDING_HEALTH_FAILURE_UNRESTORED = "recording_health_failure_unrestored"
    LOCAL_UVC_UNCONFIGURED = "local_uvc_unconfigured"
    LOCAL_UVC_STORAGE_UNADMITTED = "local_uvc_storage_unadmitted"
    LOCAL_UVC_STARTED = "local_uvc_started"
    LOCAL_UVC_DEGRADED = "local_uvc_degraded"
    LOCAL_UVC_STARTUP_FAILED = "local_uvc_startup_failed"
    LOCAL_UVC_STOPPED = "local_uvc_stopped"
    LOCAL_UVC_STOP_FAILED = "local_uvc_stop_failed"
    LOCAL_UVC_HEALTH_FENCE_INCOMPLETE = "local_uvc_health_fence_incomplete"
    LOCAL_UVC_HEALTH_FENCE_PIN_RELEASED = "local_uvc_health_fence_pin_released"
    LOCAL_UVC_SOURCE_HEALTH_CHANGED = "local_uvc_source_health_changed"
    LOCAL_UVC_SESSION_LEDGER_UNPUBLISHED = "local_uvc_session_ledger_unpublished"
    LOCAL_UVC_SESSION_LEDGER_REPUBLISHED = "local_uvc_session_ledger_republished"
    SCENE_MONITORING_UNCONFIGURED = "scene_monitoring_unconfigured"
    SCENE_MONITORING_STARTED = "scene_monitoring_started"
    SCENE_MONITORING_UNAVAILABLE = "scene_monitoring_unavailable"
    SCENE_MONITORING_STARTUP_FAILED = "scene_monitoring_startup_failed"
    SCENE_MONITORING_STOP_FAILED = "scene_monitoring_stop_failed"
    SCENE_SOURCE_FAILED = "scene_source_failed"
    SCENE_CRITICAL_UNDELIVERED = "scene_critical_undelivered"
    SCENE_CRITICAL_RECORDER_STALLED = "scene_critical_recorder_stalled"
    SCENE_CRITICAL_IN_FLIGHT_AT_STOP = "scene_critical_in_flight_at_stop"
    SCENE_FRAME_DECODER_FAILING = "scene_frame_decoder_failing"
    SCENE_FRAME_DECODER_RECOVERED = "scene_frame_decoder_recovered"
    SCENE_FRAME_DECODER_SANDBOX_UNAVAILABLE = "scene_frame_decoder_sandbox_unavailable"
    SCENE_CALIBRATION_REFRESH_DEFERRED = "scene_calibration_refresh_deferred"
    SCENE_STREAM_HISTORY_EXHAUSTED = "scene_stream_history_exhausted"
    SCENE_UNDELIVERED_UNRECORDED = "scene_undelivered_unrecorded"
    # Issue #205 calibration (Owner decision 2026-10-22, option A): a
    # reference re-acquired after a restart, a source whose stored
    # calibration could not be re-acquired, and an undelivered notice.
    SCENE_REFERENCE_REACQUIRED = "scene_reference_reacquired"
    SCENE_CALIBRATION_REQUIRED = "scene_calibration_required"
    SCENE_CALIBRATION_NOTICE_UNDELIVERED = "scene_calibration_notice_undelivered"
    SCENE_REACQUISITION_FAILED = "scene_reacquisition_failed"
    SCENE_REFERENCE_DIGESTS_SCRUBBED = "scene_reference_digests_scrubbed"
    SCENE_REFERENCE_DIGEST_SCRUB_FAILED = "scene_reference_digest_scrub_failed"
    HUMAN_LISTENER_ACTIVATION_INVALID = "human_listener_activation_invalid"
    HUMAN_REQUEST_RATE_LIMITED = "human_request_rate_limited"
    INVITATION_REDEMPTION_REFUSED = "invitation_redemption_refused"
    OWNER_STEP_UP_REFUSED = "owner_step_up_refused"
    CREDENTIAL_FINDING_UNRECORDED = "credential_finding_unrecorded"
    HUMAN_ACCESS_CHECK_FAILED = "human_access_check_failed"
    HUMAN_ACCESS_SWEEP_FAILED = "human_access_sweep_failed"
    HUMAN_ACCESS_RUN_FAILED = "human_access_run_failed"
    HUMAN_ACCESS_COMPOSITION_FAILED = "human_access_composition_failed"
    TIMELINE_FACT_QUARANTINED = "timeline_fact_quarantined"
    TIMELINE_FLUSH_FAILING = "timeline_flush_failing"
    TIMELINE_FLUSH_RECOVERED = "timeline_flush_recovered"
    TIMELINE_OUTBOX_OPENED = "timeline_outbox_opened"
    TIMELINE_OUTBOX_OPEN_FAILED = "timeline_outbox_open_failed"
    TIMELINE_OUTBOX_LEFT_OPEN = "timeline_outbox_left_open"
    TIMELINE_OUTBOX_CLOSE_FAILED = "timeline_outbox_close_failed"
    CRITICAL_DISPATCH_FAILING = "critical_dispatch_failing"
    CRITICAL_DISPATCH_RECOVERED = "critical_dispatch_recovered"
    CRITICAL_NOTIFICATIONS_UNSETTLED = "critical_notifications_unsettled"
    # Issue #318: a confirmed critical whose timeline record was refused
    # (storage hard stop) attempted Slack, or did not fit the bounded queue.
    UNRECORDED_CRITICAL_ALERT_ATTEMPTED = "unrecorded_critical_alert_attempted"
    UNRECORDED_CRITICAL_ALERT_DROPPED = "unrecorded_critical_alert_dropped"
    UNRECORDED_CRITICAL_ALERTS_FAILING = "unrecorded_critical_alerts_failing"
    UNRECORDED_CRITICAL_ALERTS_UNSENT = "unrecorded_critical_alerts_unsent"
    CAMERA_OFFLINE_NOTIFICATION_RATE_LIMITED = "camera_offline_notification_rate_limited"
    CAMERA_OFFLINE_NOTIFICATION_DROPPED = "camera_offline_notification_dropped"
    # PR #339: pending rows beyond the hourly limit left out of the restart resend.
    CAMERA_OFFLINE_NOTIFICATION_UNRESTORED = "camera_offline_notification_unrestored"
    CAMERA_OFFLINE_NOTIFICATIONS_UNSETTLED = "camera_offline_notifications_unsettled"
    SESSION_REVOCATION_MARKER_UNSAVED = "session_revocation_marker_unsaved"
    SESSION_REVOCATION_MARKER_SAVED = "session_revocation_marker_saved"
    REQUEST_DENIED = "request_denied"
    CAPTURE_CONTINUITY_RELEASED_EVICTED = "capture_continuity_released_evicted"
    CAPTURE_CONTINUITY_ACK_NODE_MISMATCH = "capture_continuity_ack_node_mismatch"
    CAPTURE_CONTINUITY_ACK_UNKNOWN_SOURCE = "capture_continuity_ack_unknown_source"
    UNSTRUCTURED = "unstructured_redacted"


class SafeJsonFormatter(logging.Formatter):
    """Never format arbitrary messages, exception text, extras or request data.

    All free-form data is discarded, including known and unknown secret formats.
    Numeric status/duration values and a bounded non-negative ``count`` (a
    number of rows, never an identifier) are the only optional metadata
    accepted.
    """

    def format(self, record: logging.LogRecord) -> str:
        event = record.msg if isinstance(record.msg, Event) else Event.UNSTRUCTURED
        output = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": logging.getLevelName(record.levelno)
            if record.levelno in {10, 20, 30, 40, 50} else "ERROR",
            "event": event.value,
        }
        status = getattr(record, "status", None)
        if type(status) is int and 100 <= status <= 599:
            output["status"] = status
        duration = getattr(record, "duration_ms", None)
        if (type(duration) in {float, int} and 0 <= duration <= 86400000
                and math.isfinite(duration)):
            output["duration_ms"] = duration
        count = getattr(record, "count", None)
        if type(count) is int and 0 <= count <= 1_000_000:
            output["count"] = count
        return json.dumps(output, separators=(",", ":"), ensure_ascii=True)


class SafeStreamHandler(logging.StreamHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        # logging's normal diagnostic prints the raw record and interpolation
        # arguments to stderr when formatting or stream writes fail.
        try:
            sys.stderr.write('{"level":"ERROR","event":"logging_failed"}\n')
        except Exception:
            pass


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    handler = SafeStreamHandler(stream)
    handler.setFormatter(SafeJsonFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
    # Uvicorn's default access logger includes URL/header-adjacent request data.
    # All framework logging is directed through the same value-free formatter.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "starlette"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
