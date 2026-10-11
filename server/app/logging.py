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
    SCENE_MONITORING_UNCONFIGURED = "scene_monitoring_unconfigured"
    SCENE_MONITORING_STARTED = "scene_monitoring_started"
    SCENE_MONITORING_UNAVAILABLE = "scene_monitoring_unavailable"
    SCENE_MONITORING_STARTUP_FAILED = "scene_monitoring_startup_failed"
    SCENE_MONITORING_STOP_FAILED = "scene_monitoring_stop_failed"
    SCENE_SOURCE_FAILED = "scene_source_failed"
    SCENE_CRITICAL_UNDELIVERED = "scene_critical_undelivered"
    SCENE_CRITICAL_RECORDER_STALLED = "scene_critical_recorder_stalled"
    SCENE_CRITICAL_IN_FLIGHT_AT_STOP = "scene_critical_in_flight_at_stop"
    HUMAN_LISTENER_ACTIVATION_INVALID = "human_listener_activation_invalid"
    HUMAN_REQUEST_RATE_LIMITED = "human_request_rate_limited"
    INVITATION_REDEMPTION_REFUSED = "invitation_redemption_refused"
    HUMAN_ACCESS_CHECK_FAILED = "human_access_check_failed"
    HUMAN_ACCESS_SWEEP_FAILED = "human_access_sweep_failed"
    HUMAN_ACCESS_RUN_FAILED = "human_access_run_failed"
    TIMELINE_FACT_QUARANTINED = "timeline_fact_quarantined"
    TIMELINE_FLUSH_FAILING = "timeline_flush_failing"
    TIMELINE_FLUSH_RECOVERED = "timeline_flush_recovered"
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
    Numeric status/duration values are the only optional metadata accepted.
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
