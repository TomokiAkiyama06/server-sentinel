"""Synthetic integration: SourcePipeline sampling -> scheduler -> isolated worker."""

from fractions import Fraction
import hashlib
import unittest
from uuid import UUID

from app.detection.foundation import (Detection, DetectorKind, Health, InferenceFeed,
                                     InferenceScheduler, IsolatedDetector, MotionBaseline,
                                     Observation, Quality, Reason, SourcePolicy,
                                     WorkerLimits, WorkerSpec)
from app.detection.foundation.config import create_motion
from app.media.profiles import (CaptureProfile, InferenceProfile, QueueLimits,
                                RecordingProfile, SourcePipeline, SourceProfiles,
                                VideoFormat, ViewerProfile)

SOURCE = UUID(int=1)
STREAM = UUID(int=2)
NEXT_STREAM = UUID(int=3)
TIME_BASE = Fraction(1, 30)
# Test-only values, not deployment defaults.
POLICY = SourcePolicy(cadence_ns=10, maximum_cadence_ns=80, maximum_queue_age_ns=1000,
                      maximum_evaluation_ns=1000, maximum_observation_age_ns=10_000,
                      maximum_pixels=64)
LIMITS = WorkerLimits(evaluation_timeout_ns=5_000_000_000, start_timeout_ns=20_000_000_000,
                      restart_backoff_ns=1, maximum_consecutive_failures=3,
                      address_space_bytes=1 << 30, open_files=64, maximum_frame_bytes=192)


def source_profiles(inference=None):
    format_ = VideoFormat(
        width=64, height=48, fps=Fraction(30), time_base=TIME_BASE,
        maximum_bitrate=1_000_000, codec="synthetic", codec_profile="fixture",
        container="synthetic-packets", pixel_format="fixture", color_space="fixture",
        configuration_sha256=hashlib.sha256(b"generated test codec config").hexdigest(),
        verified=True, video_only=True)
    inference = inference or InferenceProfile(4, 4, Fraction(5), Fraction(2))
    return SourceProfiles(CaptureProfile(format_, Fraction(2)), RecordingProfile(format_),
                          inference, ViewerProfile(format_))


def pipeline(stream=STREAM):
    limits = QueueLimits(maximum_packets=4, maximum_bytes=1024)
    return SourcePipeline(SOURCE, stream, source_profiles(), limits, limits)


class Clock:
    value = 0

    def __call__(self):
        return self.value


class Renderer:
    """Generated uniform pixels at the sampled dimensions."""

    def __init__(self):
        self.value = 0
        self.sizes = []
        self.fail = False

    def __call__(self, width, height):
        self.sizes.append((width, height))
        if self.fail:
            raise RuntimeError("decoder path /dev/secret must not escape")
        return bytes([self.value]) * (width * height)


class InferenceFeedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.scheduler = InferenceScheduler(clock_ns=self.clock)
        worker = WorkerSpec(DetectorKind.MOTION, MotionBaseline.implementation,
                            MotionBaseline.version, create_motion,
                            {"pixel_delta": 10, "changed_fraction": 0.5})
        self.detector = IsolatedDetector(worker, LIMITS, clock_ns=self.clock)
        self.addCleanup(self.detector.close)
        self.scheduler.register(SOURCE, self.detector, POLICY)
        self.assertEqual("running", self.detector.maintain().state)
        self.pipeline = pipeline()
        self.feed = InferenceFeed(self.scheduler, self.pipeline)
        self.render = Renderer()

    def offer(self, pts, *, stream=STREAM, quality=Quality.SUFFICIENT):
        self.clock.value += 100
        return self.feed.offer_decoded(stream_id=stream, pts=pts, time_base=TIME_BASE,
                                       quality=quality, channels=1, render=self.render)

    def test_sampled_frames_flow_through_isolated_worker(self):
        results = []
        for pts in range(0, 31):  # 30 fps capture sampled at 5 fps inference
            self.render.value = 0 if pts < 15 else 200
            result = self.offer(pts)
            if result.offered:
                results.append(self.scheduler.run_one())
        self.assertEqual(6, len(results))
        self.assertEqual({(4, 4)}, set(self.render.sizes))
        self.assertEqual(Reason.WARMUP, results[0].result.reason)
        observations = [item.result.observation for item in results[1:]]
        # Samples at pts 6, 12 | 18 (change at 15) | 24, 30.
        self.assertEqual([Observation.ABSENT, Observation.ABSENT, Observation.PRESENT,
                          Observation.ABSENT, Observation.ABSENT], observations)
        self.assertEqual(Health.HEALTHY, results[-1].health)
        status = self.feed.status()
        self.assertEqual((31, 25, 6), (status.decoded, status.sampled_out, status.offered))
        # Re-delivering a frame is idempotent: the sampler rejects it.
        self.assertEqual("duplicate_timestamp", self.offer(30).reason)

    def test_timestamp_gap_invalidates_published_conclusion(self):
        for pts in (0, 6):
            self.offer(pts)
            self.scheduler.run_one()
        self.assertEqual(Observation.ABSENT, self.scheduler.snapshot(SOURCE).result.observation)
        result = self.offer(6 + 90)  # three seconds exceed the two second gap
        self.assertEqual((True, "timestamp_gap"), (result.offered, result.reason))
        self.assertEqual(Reason.DISCONTINUITY, self.scheduler.snapshot(SOURCE).result.reason)
        # The detector restarts its temporal baseline instead of comparing across loss.
        self.assertEqual(Reason.WARMUP, self.scheduler.run_one().result.reason)

    def test_render_failure_and_unknown_quality_are_unknown_not_absent(self):
        for pts in (0, 6):
            self.offer(pts)
            self.scheduler.run_one()
        self.render.fail = True
        self.assertEqual("render_failed", self.offer(12).reason)
        snapshot = self.scheduler.snapshot(SOURCE)
        self.assertEqual(Detection(Observation.UNKNOWN, Reason.FAILURE), snapshot.result)
        self.render.fail = False
        self.assertEqual("quality_unusable", self.offer(18, quality=Quality.UNKNOWN).reason)
        self.assertEqual(Reason.QUALITY, self.scheduler.snapshot(SOURCE).result.reason)
        self.assertEqual(1, self.feed.status().render_failures)

    def test_unusable_quality_between_samples_invalidates_without_rendering(self):
        for pts in (0, 6):
            self.offer(pts)
            self.scheduler.run_one()
        self.assertEqual(Observation.ABSENT, self.scheduler.snapshot(SOURCE).result.observation)
        rendered = len(self.render.sizes)
        # pts 7..9 fall between inference ticks (6 and 12): not sampled, but
        # their quality still withdraws the earlier conclusion at once.
        for pts, quality in ((7, Quality.DEGRADED), (8, Quality.INSUFFICIENT),
                             (9, Quality.UNKNOWN)):
            with self.subTest(quality=quality):
                result = self.offer(pts, quality=quality)
                self.assertEqual((False, "quality_unusable"), (result.offered, result.reason))
                self.assertEqual(Detection(Observation.UNKNOWN, Reason.QUALITY),
                                 self.scheduler.snapshot(SOURCE).result)
        self.assertEqual(rendered, len(self.render.sizes))
        self.assertEqual((2, 3), (self.feed.status().offered,
                                  self.feed.status().quality_rejected))
        # A sufficient frame on the next tick resumes from warmup.
        self.assertTrue(self.offer(12).offered)
        self.assertEqual(Reason.WARMUP, self.scheduler.run_one().result.reason)

    def test_closed_pipeline_blocks_and_new_generation_rebinds(self):
        self.offer(0)
        self.scheduler.run_one()
        self.pipeline.close()
        self.assertEqual("pipeline_unavailable", self.offer(6).reason)
        self.assertEqual(Reason.DISCONTINUITY, self.scheduler.snapshot(SOURCE).result.reason)
        replacement = pipeline(NEXT_STREAM)
        self.feed.bind(replacement)
        result = self.offer(0, stream=NEXT_STREAM)
        self.assertEqual((True, "first_frame"), (result.offered, result.reason))
        snapshot = self.scheduler.run_one()
        self.assertEqual((NEXT_STREAM, Reason.WARMUP),
                         (snapshot.stream_id, snapshot.result.reason))
        # A frame from the retired generation is not sampled.
        self.assertEqual("stale_stream", self.offer(6).reason)
        with self.assertRaises(ValueError):
            self.feed.bind(ForeignPipeline())

    def test_pipeline_close_without_further_frames_invalidates_on_poll(self):
        for pts in (0, 6):
            self.offer(pts)
            self.scheduler.run_one()
        self.assertEqual(Observation.ABSENT, self.scheduler.snapshot(SOURCE).result.observation)
        self.assertFalse(self.feed.poll())
        self.assertEqual(Observation.ABSENT, self.scheduler.snapshot(SOURCE).result.observation)
        # Decoding stops with the close: no offer_decoded() follows.
        self.pipeline.close()
        self.assertTrue(self.feed.poll())
        self.assertEqual(Detection(Observation.UNKNOWN, Reason.DISCONTINUITY),
                         self.scheduler.snapshot(SOURCE).result)
        # The transition is counted once however often the owner polls.
        self.assertTrue(self.feed.poll())
        self.assertEqual(1, self.feed.status().discontinuities)

    def test_unreadable_pipeline_status_is_unavailable_on_poll(self):
        self.offer(0)
        self.scheduler.run_one()
        self.feed._pipeline = BrokenStatusPipeline()
        self.assertTrue(self.feed.poll())
        self.assertEqual(Reason.DISCONTINUITY, self.scheduler.snapshot(SOURCE).result.reason)

    def test_inference_profile_change_resets_temporal_state(self):
        for pts in (0, 6):
            self.offer(pts)
            self.scheduler.run_one()
        self.pipeline.replace_inference_profile(
            InferenceProfile(2, 2, Fraction(5), Fraction(2)))
        result = self.offer(12)
        self.assertEqual((True, "first_frame"), (result.offered, result.reason))
        self.assertEqual(Reason.WARMUP, self.scheduler.run_one().result.reason)
        self.assertEqual((2, 2), self.render.sizes[-1])

    def test_crashed_worker_during_feed_is_unknown(self):
        self.offer(0)
        self.scheduler.run_one()
        self.detector._process.kill()
        self.detector._process.join(5)
        self.offer(6)
        snapshot = self.scheduler.run_one()
        self.assertEqual(Observation.UNKNOWN, snapshot.result.observation)
        self.assertIs(Health.UNAVAILABLE, snapshot.health)


class ForeignPipeline:
    source_id = UUID(int=99)


class BrokenStatusPipeline:
    source_id = SOURCE

    @property
    def status(self):
        raise RuntimeError("device path /dev/secret must not escape")


if __name__ == "__main__":
    unittest.main()
