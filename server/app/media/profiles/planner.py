"""Conservative stream-copy eligibility; no codec backend is implied."""

from dataclasses import dataclass, fields
from enum import StrEnum

from .model import VideoFormat


class EncodeMode(StrEnum):
    STREAM_COPY = "stream_copy"
    TRANSCODE_REQUIRED = "transcode_required"


@dataclass(frozen=True)
class EncodePlan:
    mode: EncodeMode
    reasons: tuple[str, ...]
    source: VideoFormat
    target: VideoFormat


def plan_encoding(source: VideoFormat, target: VideoFormat) -> EncodePlan:
    """Require complete equality; remux/rescale/retime need another adapter.

    An exact plan is necessary but insufficient for a real copy operation:
    the installed adapter must support the codec/container combination. A
    transcode_required plan without a suitable adapter remains unavailable.
    """
    reasons = []
    if not source.verified or not target.verified:
        reasons.append("format_not_verified")
    if not source.video_only or not target.video_only:
        reasons.append("video_only_not_verified")
    for field in fields(VideoFormat):
        if field.name in {"verified", "video_only"}:
            continue
        original = getattr(source, field.name)
        requested = getattr(target, field.name)
        if original is None or requested is None:
            reasons.append(f"{field.name}_unknown")
        elif original != requested:
            reasons.append(f"{field.name}_different")
    if reasons:
        return EncodePlan(EncodeMode.TRANSCODE_REQUIRED, tuple(reasons), source, target)
    return EncodePlan(EncodeMode.STREAM_COPY, (), source, target)
