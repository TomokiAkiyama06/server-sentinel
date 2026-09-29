"""Explicit capture-profile options within a source's exact allowlist.

A high-resolution room-overview option is never inferred from a camera role
label, source type or resolution alone. It is available only when the
integration that inspected the source lists that exact profile set as a
room-overview option, together with explicitly supplied capture thresholds.
No threshold, resolution or cadence here is a deployment default: final
values are benchmark-derived (``MANUAL_TEST.md`` C / R).
"""

from dataclasses import dataclass
from enum import StrEnum

from .model import SourceProfiles, positive_integer


class CaptureOption(StrEnum):
    STANDARD = "standard"
    ROOM_OVERVIEW_HIGH_RESOLUTION = "room_overview_high_resolution"


@dataclass(frozen=True)
class RoomOverviewCriteria:
    """Caller-supplied minimum capture size for the room-overview option.

    Values come from the operator's measured camera capabilities. They are
    required whenever a room-overview option is listed, so a missing value
    fails construction instead of silently using a guessed threshold.
    """

    minimum_capture_width: int
    minimum_capture_height: int

    def __post_init__(self) -> None:
        positive_integer(self.minimum_capture_width, "minimum_capture_width")
        positive_integer(self.minimum_capture_height, "minimum_capture_height")


def room_overview_violations(profiles: SourceProfiles,
                             criteria: RoomOverviewCriteria) -> tuple[str, ...]:
    """Return sanitized reason codes; an empty tuple means the set is valid.

    Structural rules (MEDIA-001): the full-resolution capture must not force
    inference or remote viewers to process the full source resolution/FPS.
    Durable recording may keep the capture resolution but never exceed it.
    """
    if not isinstance(profiles, SourceProfiles):
        raise ValueError("invalid source profiles")
    if not isinstance(criteria, RoomOverviewCriteria):
        raise ValueError("invalid room-overview criteria")
    capture = profiles.capture.format
    recording = profiles.recording.format
    viewer = profiles.viewer.format
    inference = profiles.inference
    reasons = []
    if (capture.width < criteria.minimum_capture_width
            or capture.height < criteria.minimum_capture_height):
        reasons.append("capture_below_room_overview_minimum")
    capture_pixels = capture.width * capture.height
    if (inference.width > capture.width or inference.height > capture.height
            or inference.width * inference.height >= capture_pixels):
        reasons.append("inference_not_downscaled")
    if inference.fps > capture.fps:
        reasons.append("inference_fps_exceeds_capture")
    if (viewer.width > capture.width or viewer.height > capture.height
            or viewer.width * viewer.height >= capture_pixels):
        reasons.append("viewer_not_downscaled")
    if viewer.fps > capture.fps:
        reasons.append("viewer_fps_exceeds_capture")
    if recording.width > capture.width or recording.height > capture.height:
        reasons.append("recording_exceeds_capture")
    if recording.fps > capture.fps:
        reasons.append("recording_fps_exceeds_capture")
    return tuple(reasons)
