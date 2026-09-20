"""Synthetic packets exercise profile independence, bounds and resource release."""

from dataclasses import replace
from fractions import Fraction
import hashlib
import unittest
from uuid import UUID

from app.media.profiles import (
    AdapterUnavailable, CaptureProfile, CompressedPacket, EncodeMode,
    InferenceProfile, InferenceSampler, QueueLimits, RecordingProfile,
    SourcePipeline, SourceProfiles, VideoFormat, ViewerProfile, plan_encoding,
)


SOURCE = UUID(int=1)
STREAM = UUID(int=2)
SUBSCRIBER = UUID(int=3)


def video_format(**changes):
    # Test-only numbers are not product defaults. No encoded person/room media.
    value = VideoFormat(
        width=3840, height=2160, fps=Fraction(30), time_base=Fraction(1, 30),
        maximum_bitrate=12_000_000, codec="synthetic", codec_profile="fixture",
        container="synthetic-packets", pixel_format="fixture", color_space="fixture",
        configuration_sha256=hashlib.sha256(b"generated test codec config").hexdigest(),
        verified=True, video_only=True,
    )
    return replace(value, **changes)


def inference_profile(**changes):
    value = InferenceProfile(640, 360, Fraction(5), Fraction(2))
    return replace(value, **changes)


def source_profiles():
    format_ = video_format()
    return SourceProfiles(CaptureProfile(format_), RecordingProfile(format_),
                          inference_profile(), ViewerProfile(format_))


def packet(sequence, *, keyframe=False, source=SOURCE, stream=STREAM, **changes):
    value = CompressedPacket(source, stream, sequence, sequence, sequence,
                             Fraction(1, 30), keyframe, b"synthetic-packet")
    return replace(value, **changes)


class SyntheticAdapter:
    def __init__(self, plan):
        self.plan = plan
        self.packets = []
        self.resets = 0
        self.closed = False
        self.close_calls = 0
        self.fail_write = False
        self.fail_reset = False
        self.fail_close = False

    def write(self, item):
        if self.fail_write:
            raise RuntimeError("backend error contents must not escape")
        if self.closed:
            raise AssertionError("closed adapter received work")
        self.packets.append(item)

    def reset(self):
        if self.fail_reset:
            raise RuntimeError("backend error contents must not escape")
        self.resets += 1

    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError("backend error contents must not escape")
        self.closed = True


class SyntheticFactory:
    def __init__(self, *, copy_only=False):
        self.adapters = []
        self.copy_only = copy_only

    def __call__(self, plan):
        if self.copy_only and plan.mode != EncodeMode.STREAM_COPY:
            raise AdapterUnavailable()
        adapter = SyntheticAdapter(plan)
        self.adapters.append(adapter)
        return adapter


def pipeline(*, source=SOURCE, recording=None, viewer=None,
             recording_limits=QueueLimits(8, 1024), viewer_limits=QueueLimits(8, 1024)):
    return SourcePipeline(source, STREAM, source_profiles(), recording_limits,
                          viewer_limits, recording, viewer)


class PlannerTests(unittest.TestCase):
    def test_copy_requires_exact_complete_verified_compatibility(self):
        source = video_format()
        self.assertEqual(plan_encoding(source, source).mode, EncodeMode.STREAM_COPY)
        changes = {
            "width": 1920, "height": 1080, "fps": Fraction(15),
            "time_base": Fraction(1, 90_000), "maximum_bitrate": 2_000_000,
            "codec": "other", "codec_profile": "other", "container": "other",
            "pixel_format": "other", "color_space": "other",
            "configuration_sha256": "0" * 64, "verified": False, "video_only": False,
        }
        for name, value in changes.items():
            with self.subTest(name=name):
                plan = plan_encoding(source, replace(source, **{name: value}))
                self.assertEqual(plan.mode, EncodeMode.TRANSCODE_REQUIRED)
                self.assertTrue(plan.reasons)

    def test_unknown_values_are_not_proof_even_when_both_match(self):
        for name in ("codec", "codec_profile", "container", "pixel_format",
                     "color_space", "configuration_sha256"):
            with self.subTest(name=name):
                unknown = video_format(**{name: None})
                self.assertEqual(plan_encoding(unknown, unknown).mode,
                                 EncodeMode.TRANSCODE_REQUIRED)

    def test_invalid_rates_bounds_and_hashes_fail_before_allocation(self):
        for values in ({"fps": 30}, {"fps": Fraction(0)}, {"time_base": Fraction(-1)},
                       {"width": True}, {"maximum_bitrate": 0},
                       {"configuration_sha256": "not-a-digest"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                video_format(**values)
        with self.assertRaises(ValueError):
            QueueLimits(0, 1024)


class SamplingTests(unittest.TestCase):
    def test_capture_thirty_fps_inference_five_fps_without_frame_history(self):
        sampler = InferenceSampler(inference_profile(), STREAM)
        selected = [pts for pts in range(90)
                    if sampler.select(STREAM, pts, Fraction(1, 30)).emit]
        self.assertEqual(selected, list(range(0, 90, 6)))
        decision = sampler.select(STREAM, 90, Fraction(1, 30))
        self.assertEqual((decision.width, decision.height), (640, 360))

    def test_noninteger_cadence_uses_pts_not_packet_count(self):
        sampler = InferenceSampler(inference_profile(fps=Fraction(7, 2)), STREAM)
        times = [Fraction(pts * 1001, 30_000) for pts in range(300)]
        selected = [timestamp for timestamp in times
                    if sampler.select(STREAM, timestamp.numerator,
                                      Fraction(1, timestamp.denominator)).emit]
        self.assertEqual(len(selected), 35)
        for index, timestamp in enumerate(selected):
            self.assertGreaterEqual(timestamp, Fraction(index * 2, 7))
            self.assertLess(timestamp - Fraction(index * 2, 7), Fraction(1001, 30_000))

    def test_duplicate_backward_huge_gap_and_explicit_stream_restart(self):
        sampler = InferenceSampler(inference_profile(), STREAM)
        self.assertTrue(sampler.select(STREAM, 100, Fraction(1, 30)).emit)
        self.assertFalse(sampler.select(STREAM, 100, Fraction(1, 30)).emit)
        self.assertEqual(sampler.select(STREAM, 0, Fraction(1, 30)).reason,
                         "timestamp_reset")
        self.assertEqual(sampler.select(STREAM, 10**30, Fraction(1, 30)).reason,
                         "timestamp_gap")
        replacement = UUID(int=4)
        sampler.begin_stream(replacement)
        self.assertFalse(sampler.select(STREAM, 0, Fraction(1, 30)).emit)
        self.assertEqual(sampler.select(replacement, 0, Fraction(1, 30)).reason,
                         "first_frame")


class PipelineTests(unittest.TestCase):
    def test_viewer_demand_lifetime_and_adaptation_leave_recording_unchanged(self):
        recording, viewer = SyntheticFactory(), SyntheticFactory()
        value = pipeline(recording=recording, viewer=viewer)
        original = value.profiles
        self.assertFalse(viewer.adapters)
        value.offer(packet(0, keyframe=True))
        self.assertEqual(value.pump(8), (1, 0))
        value.add_viewer(SUBSCRIBER)
        value.add_viewer(SUBSCRIBER)
        self.assertEqual(value.subscriber_count, 1)
        value.offer(packet(1, keyframe=True))
        value.pump(8)
        new_view = ViewerProfile(video_format(width=1280, height=720, fps=Fraction(15)))
        value.replace_viewer_profile(new_view)
        self.assertTrue(viewer.adapters[0].closed)
        self.assertEqual(viewer.adapters[1].plan.target, new_view.format)
        self.assertEqual(viewer.adapters[1].plan.mode, EncodeMode.TRANSCODE_REQUIRED)
        value.replace_inference_profile(inference_profile(fps=Fraction(2)))
        value.offer(packet(2, keyframe=True))
        value.pump(8)
        value.offer(packet(3))
        value.remove_viewer(SUBSCRIBER)
        self.assertTrue(viewer.adapters[1].closed)
        self.assertEqual(value.viewer_status.queued_bytes, 0)
        self.assertEqual(value.pump(8), (1, 0))
        self.assertEqual(value.profiles.capture, original.capture)
        self.assertEqual(value.profiles.recording, original.recording)
        self.assertEqual([item.sequence for item in recording.adapters[0].packets],
                         [0, 1, 2, 3])
        self.assertEqual(len(recording.adapters), 1)
        self.assertFalse(recording.adapters[0].closed)
        value.close()
        value.close()
        self.assertEqual(recording.adapters[0].close_calls, 1)

    def test_last_subscriber_closes_viewer_and_late_join_waits_for_keyframe(self):
        factory = SyntheticFactory()
        value = pipeline(viewer=factory)
        second = UUID(int=5)
        value.add_viewer(SUBSCRIBER)
        value.add_viewer(second)
        self.assertFalse(value.offer(packet(0)).viewer_queued)
        value.remove_viewer(SUBSCRIBER)
        self.assertFalse(factory.adapters[0].closed)
        self.assertTrue(value.offer(packet(1, keyframe=True)).viewer_queued)
        self.assertTrue(value.viewer_status.healthy)
        self.assertEqual(value.viewer_status.skipped_until_keyframe, 1)
        value.remove_viewer(second)
        self.assertTrue(factory.adapters[0].closed)
        self.assertEqual(value.viewer_status.queued_packets, 0)
        value.add_viewer(second)
        self.assertEqual(len(factory.adapters), 2)
        self.assertFalse(value.offer(packet(2)).viewer_queued)

    def test_viewer_backpressure_does_not_damage_recording(self):
        recording, viewer = SyntheticFactory(), SyntheticFactory()
        value = pipeline(recording=recording, viewer=viewer,
                         viewer_limits=QueueLimits(1, 64))
        value.add_viewer(SUBSCRIBER)
        value.offer(packet(0, keyframe=True))
        value.offer(packet(1))
        self.assertEqual(value.viewer_status.reason, "backpressure")
        self.assertEqual(value.viewer_status.queued_bytes, 0)
        self.assertEqual(value.viewer_status.dropped_packets, 2)
        self.assertFalse(value.viewer_status.healthy)
        self.assertTrue(value.recording_status.healthy)
        value.offer(packet(2, keyframe=True))
        self.assertEqual(value.pump(8), (3, 1))
        self.assertEqual(viewer.adapters[0].resets, 1)
        self.assertEqual([item.sequence for item in recording.adapters[0].packets], [0, 1, 2])
        self.assertFalse(value.viewer_status.healthy)  # A known gap stays visible.

    def test_byte_limit_oversized_packet_and_recording_loss_are_explicit(self):
        factory = SyntheticFactory()
        value = pipeline(recording=factory, recording_limits=QueueLimits(20, 20))
        value.offer(packet(0, keyframe=True, data=b"generated-a"))
        value.offer(packet(1, data=b"generated-b"))
        self.assertEqual(value.recording_status.queued_bytes, 0)
        self.assertFalse(value.recording_status.healthy)
        result = value.offer(packet(2, keyframe=True, data=b"x" * 21))
        self.assertFalse(result.recording_queued)
        self.assertEqual(value.recording_status.reason, "packet_exceeds_byte_limit")
        self.assertLessEqual(value.recording_status.queued_bytes, 20)
        self.assertTrue(value.offer(packet(3, keyframe=True)).recording_queued)

    def test_sequence_gap_and_decode_clock_reset_require_new_keyframe(self):
        factory = SyntheticFactory()
        value = pipeline(recording=factory)
        value.offer(packet(0, keyframe=True))
        value.pump(1)
        self.assertEqual(value.offer(packet(2)).reason, "sequence_gap")
        self.assertFalse(value.offer(packet(3)).recording_queued)
        self.assertTrue(value.offer(packet(4, keyframe=True)).recording_queued)
        result = value.offer(packet(5, keyframe=True, dts=-30, pts=-30))
        self.assertEqual(result.reason, "decode_timestamp_reset")
        self.assertEqual(value.recording_status.discontinuities, 2)
        self.assertTrue(result.recording_queued)
        self.assertEqual(value.offer(packet(5)).reason, "stale_or_duplicate_packet")

    def test_pts_reordering_is_not_confused_with_decode_clock_reset(self):
        factory = SyntheticFactory()
        value = pipeline(recording=factory)
        value.offer(packet(0, keyframe=True, pts=2))
        value.offer(packet(1, pts=0))
        value.offer(packet(2, pts=1))
        self.assertTrue(value.recording_status.healthy)
        self.assertEqual(value.pump(3), (3, 0))

    def test_four_sources_reject_cross_source_and_old_generation_packets(self):
        values = [pipeline(source=UUID(int=index), recording=SyntheticFactory())
                  for index in range(10, 14)]
        for value in values:
            self.assertFalse(value.offer(packet(0, keyframe=True)).recording_queued)
            own = packet(0, source=value.source_id, keyframe=True)
            self.assertTrue(value.offer(own).recording_queued)
            self.assertFalse(value.offer(replace(own, stream_id=UUID(int=99))).recording_queued)
            self.assertEqual(value.pump(2), (1, 0))
            self.assertEqual(value.recording_status.dropped_packets, 0)

    def test_missing_or_unsupported_adapter_never_claims_healthy_output(self):
        value = pipeline(viewer=SyntheticFactory(copy_only=True))
        self.assertFalse(value.recording_status.available)
        self.assertFalse(value.recording_status.healthy)
        value.replace_viewer_profile(ViewerProfile(video_format(width=640, height=360)))
        value.add_viewer(SUBSCRIBER)
        self.assertEqual(value.viewer_status.reason, "adapter_unavailable")
        self.assertFalse(value.offer(packet(0, keyframe=True)).viewer_queued)
        self.assertEqual(value.pump(1), (0, 0))

    def test_adapter_write_failure_releases_resources_and_reports_loss(self):
        factory = SyntheticFactory()
        value = pipeline(recording=factory)
        value.offer(packet(0, keyframe=True))
        value.offer(packet(1))
        factory.adapters[0].fail_write = True
        self.assertEqual(value.pump(2), (0, 0))
        self.assertTrue(factory.adapters[0].closed)
        self.assertTrue(value.recording_status.failed)
        self.assertEqual(value.recording_status.reason, "adapter_write_failed")
        self.assertEqual(value.recording_status.dropped_packets, 2)
        self.assertEqual(value.recording_status.queued_bytes, 0)

    def test_failed_viewer_cleanup_blocks_replacement_until_retry_releases_it(self):
        factory = SyntheticFactory()
        value = pipeline(viewer=factory)
        value.add_viewer(SUBSCRIBER)
        factory.adapters[0].fail_close = True
        value.remove_viewer(SUBSCRIBER)
        self.assertTrue(value.viewer_status.failed)
        self.assertEqual(value.viewer_status.reason, "adapter_close_failed")
        value.add_viewer(SUBSCRIBER)
        self.assertEqual(len(factory.adapters), 1)
        self.assertFalse(value.offer(packet(0, keyframe=True)).viewer_queued)
        factory.adapters[0].fail_close = False
        value.remove_viewer(SUBSCRIBER)
        value.add_viewer(SUBSCRIBER)
        self.assertTrue(factory.adapters[0].closed)
        self.assertEqual(len(factory.adapters), 2)

    def test_time_base_change_and_closed_pipeline_cannot_continue_silently(self):
        value = pipeline(recording=SyntheticFactory())
        value.offer(packet(0, keyframe=True))
        result = value.offer(packet(1, time_base=Fraction(1, 90_000)))
        self.assertEqual(result.reason, "renegotiation_required")
        self.assertFalse(value.recording_status.healthy)
        self.assertEqual(value.recording_status.queued_bytes, 0)
        self.assertFalse(value.offer(packet(2, keyframe=True)).recording_queued)
        value.close()
        self.assertEqual(value.recording_status.queued_bytes, 0)
        with self.assertRaises(RuntimeError):
            value.offer(packet(2, keyframe=True))
        with self.assertRaises(RuntimeError):
            value.add_viewer(SUBSCRIBER)

    def test_stale_packet_cannot_force_time_base_renegotiation(self):
        factory = SyntheticFactory()
        value = pipeline(recording=factory)
        value.offer(packet(0, keyframe=True))
        value.pump(1)
        duplicate = packet(0, time_base=Fraction(1, 90_000))
        self.assertEqual(value.offer(duplicate).reason, "stale_or_duplicate_packet")
        self.assertTrue(value.offer(packet(1)).recording_queued)
        self.assertTrue(value.recording_status.healthy)
        self.assertEqual(factory.adapters[0].resets, 0)

    def test_video_only_invariant_applies_to_every_output_profile(self):
        invalid_format = video_format(video_only=False)
        for field, profile in (("recording", RecordingProfile(invalid_format)),
                               ("viewer", ViewerProfile(invalid_format))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                SourcePipeline(SOURCE, STREAM, replace(source_profiles(), **{field: profile}),
                               QueueLimits(8, 1024), QueueLimits(8, 1024))
        value = pipeline()
        original = value.profiles.viewer
        with self.assertRaises(ValueError):
            value.replace_viewer_profile(ViewerProfile(invalid_format))
        self.assertEqual(value.profiles.viewer, original)


if __name__ == "__main__":
    unittest.main()
