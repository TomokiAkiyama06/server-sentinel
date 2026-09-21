"""Synthetic profile isolation; no codec process, browser, or camera is used."""

from dataclasses import replace
from fractions import Fraction
from hashlib import sha256
from uuid import UUID

from app.media.profiles import (
    CaptureProfile, CompressedPacket, InferenceProfile, QueueLimits,
    RecordingProfile, SourcePipeline, SourceProfiles, VideoFormat, ViewerProfile,
)


class _Adapter:
    def __init__(self, plan):
        self.plan, self.packets, self.closed = plan, [], False

    def write(self, packet):
        assert not self.closed
        self.packets.append(packet)

    def reset(self):
        pass

    def close(self):
        self.closed = True


class _Factory:
    def __init__(self):
        self.adapters = []

    def __call__(self, plan):
        value = _Adapter(plan)
        self.adapters.append(value)
        return value


def run_media_profiles_smoke():
    """Viewer demand and quality changes cannot alter durable recording."""
    source, stream, viewer = UUID(int=51), UUID(int=52), UUID(int=53)
    format_ = VideoFormat(
        1920, 1080, Fraction(30), Fraction(1, 30), 1_000_000,
        codec="synthetic", codec_profile="fixture", container="fixture",
        pixel_format="fixture", color_space="fixture",
        configuration_sha256=sha256(b"generated codec configuration").hexdigest(),
        verified=True, video_only=True,
    )
    profiles = SourceProfiles(
        CaptureProfile(format_, Fraction(2)), RecordingProfile(format_),
        InferenceProfile(640, 360, Fraction(5), Fraction(2)), ViewerProfile(format_),
    )
    recordings, viewers = _Factory(), _Factory()
    pipeline = SourcePipeline(source, stream, profiles, QueueLimits(8, 1024),
                              QueueLimits(8, 1024), recordings, viewers)

    def packet(sequence, *, keyframe=True):
        return CompressedPacket(source, stream, sequence, sequence, sequence,
                                Fraction(1, 30), keyframe, b"synthetic-packet")

    try:
        # No subscriber starts no viewer adapter, but recording and configured
        # low-rate inference both continue on the source generation.
        assert pipeline.offer(packet(0)).viewer_queued is False
        assert pipeline.pump(1) == (1, 0)
        assert not viewers.adapters
        assert pipeline.inference.select(stream, 0, Fraction(1, 30)).emit
        assert not pipeline.inference.select(stream, 1, Fraction(1, 30)).emit

        pipeline.add_viewer(viewer)
        assert pipeline.offer(packet(1)).viewer_queued
        assert pipeline.pump(1) == (1, 1)
        recording_format = pipeline.profiles.recording.format
        adapted = ViewerProfile(replace(format_, width=1280, height=720, fps=Fraction(15)))
        pipeline.replace_viewer_profile(adapted)
        assert pipeline.profiles.viewer == adapted
        assert pipeline.profiles.recording.format == recording_format
        pipeline.remove_viewer(viewer)
        assert viewers.adapters[-1].closed
        assert pipeline.offer(packet(2)).viewer_queued is False
        assert pipeline.pump(1) == (1, 0)
        assert [item.sequence for item in recordings.adapters[0].packets] == [0, 1, 2]
    finally:
        pipeline.close()
