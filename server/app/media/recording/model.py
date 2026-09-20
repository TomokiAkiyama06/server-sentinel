"""Trusted, already muxed video segments; no codec or network parser lives here."""

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID
import re


class RecordingError(RuntimeError):
    """Stable non-sensitive failure category suitable for an internal health event."""


@dataclass(frozen=True)
class Limits:
    pre_roll_bytes: int
    max_segment_bytes: int
    max_segment_ms: int
    max_active_recordings: int
    max_spool_segments: int
    max_segments_per_recording: int
    pre_roll_ms: int = 30_000
    max_sources: int = 4

    def __post_init__(self):
        values = vars(self).values()
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("invalid recording limits")
        if self.pre_roll_ms > 1_200_000 or self.max_segment_ms > 1_200_000:
            raise ValueError("recording duration exceeds maximum")


@dataclass(frozen=True)
class Segment:
    source_id: UUID
    stream_id: UUID
    sequence: int
    start_ms: int
    end_ms: int
    codec: str
    container: str
    data: bytes = field(repr=False)
    capture_node_id: UUID | None = None

    def validate(self, limits: Limits) -> None:
        if (not isinstance(self.source_id, UUID) or not isinstance(self.stream_id, UUID)
                or (self.capture_node_id is not None
                    and not isinstance(self.capture_node_id, UUID))):
            raise ValueError("invalid recording identity")
        if (type(self.sequence) is not int or not 0 <= self.sequence < 2**63
                or type(self.start_ms) is not int or type(self.end_ms) is not int
                or self.start_ms < 0 or self.end_ms >= 2**63
                or not 0 < self.end_ms - self.start_ms <= limits.max_segment_ms):
            raise ValueError("invalid segment timeline")
        if (type(self.data) is not bytes or not 0 < len(self.data) <= limits.max_segment_bytes
                or any(type(value) is not str
                       or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,31}", value)
                       for value in (self.codec, self.container))):
            raise ValueError("invalid compressed segment")


class StoragePolicy(Protocol):
    def admit(self, media_bytes: int, *, critical: bool) -> None:
        """Reserve bytes atomically, including metadata/temporary overhead.

        Reject ordinary work with STORAGE_PRESSURE or unsafe writes with
        STORAGE_HARD_STOP. Implementations coordinate other filesystem writers,
        preserve the deployment-configured hard reserve, and raise on denial.
        This call must hold the reservation until release(), including fsync.
        """

    def release(self) -> None:
        """Release only this writer's most recent successful reservation."""


class SegmentValidator(Protocol):
    def validate(self, segment: Segment) -> None:
        """Attest bounded, independently decodable, video-only muxed content.

        The audited codec adapter must reject audio, invalid containers, excessive
        decoded dimensions and incompatible timestamps/configuration. A bytes
        label or filename is not validation. No production validator is supplied
        until the codec/transport adapter is selected and audited.
        """
