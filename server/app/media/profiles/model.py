"""Transport-independent video profiles; all deployment values are explicit."""

from dataclasses import dataclass
from fractions import Fraction
from uuid import UUID


def positive_integer(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def positive_fraction(value: Fraction, name: str) -> None:
    if not isinstance(value, Fraction) or value <= 0:
        raise ValueError(f"{name} must be a positive Fraction")


@dataclass(frozen=True)
class VideoFormat:
    """Exact parsed/negotiated format, never an unverified client assertion.

    Unknown codec details are represented by None and prevent stream-copy.
    configuration_sha256 identifies codec initialization bytes, not media.
    A transport adapter must establish video-only content before constructing
    a verified descriptor. This class itself does not parse or verify a codec.
    """

    width: int
    height: int
    fps: Fraction
    time_base: Fraction
    maximum_bitrate: int
    codec: str | None = None
    codec_profile: str | None = None
    container: str | None = None
    pixel_format: str | None = None
    color_space: str | None = None
    configuration_sha256: str | None = None
    verified: bool = False
    video_only: bool = False

    def __post_init__(self) -> None:
        for name in ("width", "height", "maximum_bitrate"):
            positive_integer(getattr(self, name), name)
        positive_fraction(self.fps, "fps")
        positive_fraction(self.time_base, "time_base")
        if type(self.verified) is not bool or type(self.video_only) is not bool:
            raise ValueError("verification flags must be booleans")
        for name in ("codec", "codec_profile", "container", "pixel_format",
                     "color_space"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be nonempty or unknown")
        digest = self.configuration_sha256
        if digest is not None and (
            not isinstance(digest, str) or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("configuration_sha256 must be a lowercase SHA-256")


@dataclass(frozen=True)
class CaptureProfile:
    format: VideoFormat
    maximum_timestamp_gap: Fraction

    def __post_init__(self) -> None:
        positive_fraction(self.maximum_timestamp_gap, "maximum_timestamp_gap")


@dataclass(frozen=True)
class RecordingProfile:
    format: VideoFormat


@dataclass(frozen=True)
class ViewerProfile:
    format: VideoFormat


@dataclass(frozen=True)
class InferenceProfile:
    width: int
    height: int
    fps: Fraction
    maximum_timestamp_gap: Fraction

    def __post_init__(self) -> None:
        positive_integer(self.width, "width")
        positive_integer(self.height, "height")
        positive_fraction(self.fps, "fps")
        positive_fraction(self.maximum_timestamp_gap, "maximum_timestamp_gap")


@dataclass(frozen=True)
class SourceProfiles:
    capture: CaptureProfile
    recording: RecordingProfile
    inference: InferenceProfile
    viewer: ViewerProfile


@dataclass(frozen=True)
class QueueLimits:
    maximum_packets: int
    maximum_bytes: int

    def __post_init__(self) -> None:
        positive_integer(self.maximum_packets, "maximum_packets")
        positive_integer(self.maximum_bytes, "maximum_bytes")


@dataclass(frozen=True)
class CompressedPacket:
    source_id: UUID
    stream_id: UUID
    sequence: int
    pts: int
    dts: int
    time_base: Fraction
    keyframe: bool
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, UUID) or not isinstance(self.stream_id, UUID):
            raise ValueError("source and stream identities must be UUIDs")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("sequence must be a nonnegative integer")
        if type(self.pts) is not int or type(self.dts) is not int:
            raise ValueError("PTS and DTS must be integers")
        positive_fraction(self.time_base, "time_base")
        if type(self.keyframe) is not bool:
            raise ValueError("keyframe must be a boolean")
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("compressed payload must be nonempty immutable bytes")
