"""Deployment configuration for local UVC capture.

Standard library only: the standalone installer validates deployment
configuration with this module and must not import capture, registry or web
framework code.  The configuration names logical registry source UUIDs only;
device paths, serials and other physical evidence are never accepted here.
"""

from dataclasses import dataclass, field
from uuid import UUID

from app.settings import ConfigurationError


MAX_LOCAL_UVC_SOURCES = 4
_TIMING_BOUNDS = {
    "poll_timeout_seconds": (0.05, 30.0),
    "retry_delay_seconds": (0.05, 60.0),
    "join_timeout_seconds": (0.1, 60.0),
    # Frame-progress watchdog: no frame for this long on a live capture reports
    # ``degraded`` (``video_frame_stalled``) instead of ``online``. The
    # effective window is never shorter than 10 negotiated frame intervals.
    "frame_stall_seconds": (0.25, 30.0),
    # A stall lasting this long closes and reopens the capture (``offline``).
    "frame_stall_reopen_seconds": (0.5, 300.0),
    # While capture is live, the full device scan (which opens every video
    # node) runs at most this often; a closed capture always rescans first.
    "presence_scan_seconds": (0.1, 10.0),
}


@dataclass(frozen=True)
class LocalUvcConfiguration:
    """Deployment-approved logical local UVC sources and worker timing."""

    source_ids: tuple[UUID, ...] = field(repr=False)
    poll_timeout_seconds: float = 1.0
    # One registry health write per retry while a source has no approval, so
    # the default keeps idle write load at about one row update per second.
    retry_delay_seconds: float = 1.0
    join_timeout_seconds: float = 3.0
    frame_stall_seconds: float = 1.0
    frame_stall_reopen_seconds: float = 5.0
    presence_scan_seconds: float = 1.0

    def __post_init__(self) -> None:
        ids = self.source_ids
        if (not isinstance(ids, tuple) or not 1 <= len(ids) <= MAX_LOCAL_UVC_SOURCES
                or any(not isinstance(value, UUID) for value in ids)
                or len(set(ids)) != len(ids)):
            raise ConfigurationError("local UVC sources must be 1 to 4 distinct source UUIDs")
        for name, (low, high) in _TIMING_BOUNDS.items():
            value = getattr(self, name)
            if type(value) not in (int, float) or not low <= value <= high:
                raise ConfigurationError("local UVC worker timing is out of range")
            object.__setattr__(self, name, float(value))
        if self.frame_stall_reopen_seconds < self.frame_stall_seconds:
            # Reopening before the stall is reported would hide the stall.
            raise ConfigurationError("local UVC worker timing is out of range")


def parse_local_uvc(value: object) -> LocalUvcConfiguration:
    """Parse the deployment ``local_uvc`` object with value-free errors."""
    if not isinstance(value, dict):
        raise ConfigurationError("invalid local UVC configuration")
    allowed = {"source_ids", *_TIMING_BOUNDS}
    if "source_ids" not in value or not set(value) <= allowed:
        raise ConfigurationError("invalid local UVC configuration")
    raw = value["source_ids"]
    if not isinstance(raw, list) or len(raw) > MAX_LOCAL_UVC_SOURCES:
        raise ConfigurationError("local UVC sources must be 1 to 4 distinct source UUIDs")
    identities = []
    for item in raw:
        # Only canonical lowercase UUID text is accepted, so one source cannot
        # be listed twice under two spellings that compare equal.
        try:
            identity = UUID(item) if isinstance(item, str) else None
        except ValueError:
            identity = None
        if identity is None or str(identity) != item:
            raise ConfigurationError("local UVC sources must be 1 to 4 distinct source UUIDs")
        identities.append(identity)
    timing = {name: value[name] for name in _TIMING_BOUNDS if name in value}
    return LocalUvcConfiguration(tuple(identities), **timing)
