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
    REQUEST_DENIED = "request_denied"
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
