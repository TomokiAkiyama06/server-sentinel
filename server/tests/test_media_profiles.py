"""Synthetic packets exercise profile independence, bounds and resource release."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
import hashlib
import unittest
from uuid import UUID

from app.media.profiles import (
    AdapterUnavailable, CaptureProfile, CompressedPacket, EncodeMode,
    InferenceProfile, InferenceSampler, QueueLimits, RecordingProfile,
    SourcePipeline, SourceProfileAdmissions, SourceProfileCapabilities,
    SourceProfiles, VideoFormat, ViewerProfile, plan_encoding,
)
from app.cameras.registry.models import SourceType


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
    return SourceProfiles(CaptureProfile(format_, Fraction(2)), RecordingProfile(format_),
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
             recording_limits=QueueLimits(8, 1024), viewer_limits=QueueLimits(8, 1024),
             profiles=None, admission=None):
    profiles = profiles or source_profiles()
    return SourcePipeline(source, STREAM, profiles, recording_limits,
                          viewer_limits, recording, viewer, admission)


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


class AdmissionTests(unittest.TestCase):
    def capabilities(self, source=SOURCE, source_type=SourceType.LOCAL_UVC,
                     profiles=None):
        profiles = profiles or source_profiles()
        return SourceProfileCapabilities(
            source, source_type, (profiles,),
        )

    def test_profiles_are_admitted_from_that_sources_exact_allowlist(self):
        admissions = SourceProfileAdmissions(4)
        supported = source_profiles()
        admitted = admissions.admit(self.capabilities(), supported)
        self.assertTrue(admitted.admitted)
        self.assertIsNotNone(admitted.lease)
        self.assertEqual(admissions.admitted(SOURCE), supported)

        # The alternative is synthetic and deliberately not a product default.
        alternative = replace(
            supported,
            inference=inference_profile(fps=Fraction(2)),
            viewer=ViewerProfile(video_format(width=1280, height=720,
                                               fps=Fraction(15))),
        )
        rejected = admissions.admit(self.capabilities(), alternative)
        self.assertFalse(rejected.admitted)
        self.assertEqual(rejected.reasons, ("profile_set_unsupported",))
        self.assertEqual(admissions.admitted(SOURCE), supported)

    def test_source_allowlists_cannot_be_reused_or_change_source_type(self):
        admissions = SourceProfileAdmissions(2)
        profiles = source_profiles()
        first = admissions.admit(self.capabilities(), profiles)
        self.assertTrue(first.admitted)
        changed = admissions.admit(
            self.capabilities(source_type=SourceType.REMOTE_AGENT), profiles,
        )
        self.assertFalse(changed.admitted)
        self.assertIn("source_type_changed", changed.reasons)

        other = UUID(int=44)
        other_decision = admissions.admit(self.capabilities(other), profiles)
        self.assertTrue(other_decision.admitted)
        third = admissions.admit(self.capabilities(UUID(int=45)), profiles)
        self.assertEqual(third.reasons, ("active_source_limit",))
        self.assertTrue(admissions.release(other_decision.lease))
        replacement = admissions.admit(self.capabilities(UUID(int=45)), profiles)
        self.assertTrue(replacement.admitted)
        self.assertTrue(admissions.release(first.lease))
        changed = admissions.admit(
            self.capabilities(source_type=SourceType.REMOTE_AGENT), profiles,
        )
        self.assertEqual(changed.reasons, ("source_type_changed",))

    def test_capabilities_require_verified_video_without_hardware_defaults(self):
        profiles = source_profiles()
        unverified = replace(
            profiles,
            capture=CaptureProfile(video_format(verified=False), Fraction(2)),
        )
        with self.assertRaises(ValueError):
            self.capabilities(profiles=unverified)
        with self.assertRaises(ValueError):
            SourceProfileAdmissions(0)

    def test_concurrent_source_admission_does_not_overbook(self):
        admissions = SourceProfileAdmissions(4)
        profiles = source_profiles()
        sources = [UUID(int=value) for value in range(100, 108)]
        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            decisions = tuple(executor.map(
                lambda source: admissions.admit(self.capabilities(source), profiles),
                sources,
            ))
        self.assertEqual(sum(decision.admitted for decision in decisions), 4)
        self.assertEqual(admissions.active_sources, 4)
        self.assertTrue(all(decision.admitted
                            or decision.reasons == ("active_source_limit",)
                            for decision in decisions))

    def test_stale_release_cannot_remove_replacement_generation(self):
        admissions = SourceProfileAdmissions(1)
        profiles = source_profiles()
        first = admissions.admit(self.capabilities(), profiles)
        replacement = admissions.admit(self.capabilities(), profiles)
        self.assertFalse(admissions.release(first.lease))
        self.assertEqual(admissions.active_sources, 1)
        blocked = admissions.admit(self.capabilities(UUID(int=200)), profiles)
        self.assertEqual(blocked.reasons, ("active_source_limit",))
        self.assertTrue(admissions.release(replacement.lease))

    def test_released_or_superseded_lease_cannot_run_a_pipeline(self):
        admissions = SourceProfileAdmissions(1)
        profiles = source_profiles()
        first = admissions.admit(self.capabilities(), profiles)
        old_pipeline = pipeline(recording=SyntheticFactory(), profiles=profiles,
                                admission=first.lease)
        blocked = admissions.admit(self.capabilities(), profiles)
        self.assertEqual(blocked.reasons, ("pipeline_active",))
        self.assertTrue(old_pipeline.status.state in {"degraded", "healthy"})
        old_pipeline.close()
        replacement = admissions.admit(self.capabilities(), profiles)
        with self.assertRaises(RuntimeError):
            old_pipeline.replace_inference_profile(inference_profile(fps=Fraction(2)))
        with self.assertRaises(ValueError):
            pipeline(recording=SyntheticFactory(), profiles=profiles,
                     admission=first.lease)

        self.assertTrue(admissions.release(replacement.lease))
        with self.assertRaises(ValueError):
            pipeline(recording=SyntheticFactory(), profiles=profiles,
                     admission=replacement.lease)

    def test_admission_bound_pipeline_rejects_unlisted_adaptation(self):
        base = source_profiles()
        allowed_viewer = ViewerProfile(video_format(width=1280, height=720,
                                                     fps=Fraction(15)))
        allowed = replace(base, viewer=allowed_viewer)
        capabilities = SourceProfileCapabilities(
            SOURCE, SourceType.LOCAL_UVC, (base, allowed),
        )
        admissions = SourceProfileAdmissions(1)
        decision = admissions.admit(capabilities, base)
        self.assertFalse(hasattr(decision.lease, "release_pipeline"))
        self.assertFalse(hasattr(decision.lease, "transition"))
        value = pipeline(recording=SyntheticFactory(), viewer=SyntheticFactory(),
                         profiles=base, admission=decision.lease)
        self.addCleanup(value.close)
        value.replace_viewer_profile(allowed_viewer)
        self.assertEqual(value.profiles, allowed)
        self.assertEqual(admissions.admitted(SOURCE), allowed)
        with self.assertRaises(ValueError):
            pipeline(recording=SyntheticFactory(), profiles=base,
                     admission=decision.lease)
        with self.assertRaises(ValueError):
            pipeline(recording=SyntheticFactory(), profiles=allowed,
                     admission=decision.lease)
        unsupported = ViewerProfile(video_format(width=640, height=360,
                                                  fps=Fraction(5)))
        value.add_viewer(SUBSCRIBER)
        with self.assertRaises(ValueError):
            value.replace_viewer_profile(unsupported)
        self.assertEqual(value.profiles, allowed)
        self.assertEqual(admissions.admitted(SOURCE), allowed)
        self.assertIsNotNone(value.viewer_status)
        self.assertTrue(value.viewer_status.active)
        self.assertEqual(value.subscriber_count, 1)
        with self.assertRaises(ValueError):
            value.replace_inference_profile(inference_profile(fps=Fraction(2)))
        self.assertEqual(value.profiles, allowed)
        self.assertEqual(admissions.admitted(SOURCE), allowed)

    def test_failed_pipeline_cleanup_retains_exclusive_lease_claim(self):
        profiles = source_profiles()
        admissions = SourceProfileAdmissions(1)
        decision = admissions.admit(self.capabilities(), profiles)
        factory = SyntheticFactory()
        value = pipeline(recording=factory, profiles=profiles, admission=decision.lease)
        factory.adapters[0].fail_close = True
        value.close()
        self.assertFalse(admissions.release(decision.lease))
        with self.assertRaises(ValueError):
            pipeline(recording=SyntheticFactory(), profiles=profiles,
                     admission=decision.lease)

        factory.adapters[0].fail_close = False
        value.close()
        replacement = pipeline(recording=SyntheticFactory(), profiles=profiles,
                               admission=decision.lease)
        value.close()  # The stale claim cannot release the replacement claim.
        self.assertNotEqual(replacement.status.state, "unavailable")
        self.assertTrue(replacement.offer(packet(0, keyframe=True)).recording_queued)
        replacement.close()


class PipelineTests(unittest.TestCase):
    def test_source_status_reports_demand_paths_and_known_capture_loss(self):
        recording, viewer = SyntheticFactory(), SyntheticFactory()
        value = pipeline(recording=recording, viewer=viewer)
        self.addCleanup(value.close)
        self.assertEqual(value.status.state, "degraded")
        self.assertIsNone(value.status.viewer)
        value.offer(packet(0, keyframe=True))
        value.pump(1)
        self.assertEqual(value.status.state, "healthy")

        value.add_viewer(SUBSCRIBER)
        self.assertEqual(value.status.state, "degraded")
        self.assertIn("viewer_awaiting_keyframe", value.status.reasons)
        value.offer(packet(2, keyframe=True))
        value.pump(1)
        status = value.status
        self.assertEqual(status.state, "degraded")
        self.assertEqual(status.capture_discontinuities, 1)
        self.assertIn("sequence_gap", status.reasons)
        value.remove_viewer(SUBSCRIBER)
        self.assertIsNone(value.status.viewer)

    def test_unavailable_recording_or_capture_renegotiation_is_not_healthy(self):
        value = pipeline(recording=None)
        self.assertEqual(value.status.state, "unavailable")
        self.assertIn("recording_unavailable", value.status.reasons)

        value = pipeline(recording=SyntheticFactory())
        self.addCleanup(value.close)
        value.offer(packet(0, keyframe=True))
        value.pump(1)
        value.offer(packet(1, time_base=Fraction(1, 90_000)))
        self.assertEqual(value.status.state, "unavailable")
        self.assertIn("capture_renegotiation_required", value.status.reasons)

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

    def test_viewer_replacement_preserves_generation_loss_without_double_counting(self):
        for fault in ("backpressure", "write_failure"):
            for restart in ("profile", "resubscribe"):
                with self.subTest(fault=fault, restart=restart):
                    recording, viewer = SyntheticFactory(), SyntheticFactory()
                    value = pipeline(recording=recording, viewer=viewer,
                                     viewer_limits=QueueLimits(1, 64))
                    self.addCleanup(value.close)
                    value.add_viewer(SUBSCRIBER)
                    value.offer(packet(0, keyframe=True))
                    sequence = 1
                    if fault == "backpressure":
                        value.offer(packet(sequence))
                        sequence += 1
                    else:
                        viewer.adapters[0].fail_write = True
                    value.pump(8)
                    loss = value.viewer_status
                    self.assertGreater(loss.dropped_packets, 0)
                    for width in (1280, 640):
                        if restart == "profile":
                            value.replace_viewer_profile(ViewerProfile(video_format(width=width)))
                        else:
                            value.remove_viewer(SUBSCRIBER)
                            value.add_viewer(SUBSCRIBER)
                        self.assertTrue(value.offer(packet(sequence, keyframe=True)).viewer_queued)
                        value.pump(8)
                        sequence += 1
                        status = value.viewer_status
                        self.assertTrue(status.active and status.available)
                        self.assertFalse(status.failed or status.awaiting_keyframe)
                        self.assertFalse(status.healthy)
                        self.assertEqual(status.reason, "prior_viewer_loss")
                        self.assertEqual(status.dropped_packets, loss.dropped_packets)
                        self.assertEqual(status.discontinuities, loss.discontinuities)
                        self.assertTrue(value.recording_status.healthy)

    def test_loss_free_profile_replacement_can_be_healthy(self):
        value = pipeline(viewer=SyntheticFactory())
        self.addCleanup(value.close)
        value.add_viewer(SUBSCRIBER)
        value.offer(packet(0))  # Initial join between keyframes is not loss.
        value.offer(packet(1, keyframe=True))
        value.pump(8)
        value.replace_viewer_profile(ViewerProfile(video_format(width=1280)))
        value.offer(packet(2, keyframe=True))
        value.pump(8)
        self.assertTrue(value.viewer_status.healthy)
        self.assertEqual(value.viewer_status.skipped_until_keyframe, 1)

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

    def test_failed_idle_viewer_cleanup_remains_source_degradation(self):
        factory = SyntheticFactory()
        value = pipeline(recording=SyntheticFactory(), viewer=factory)
        self.addCleanup(value.close)
        value.offer(packet(0, keyframe=True))
        value.pump(1)
        value.add_viewer(SUBSCRIBER)
        factory.adapters[0].fail_close = True
        value.remove_viewer(SUBSCRIBER)

        status = value.status
        self.assertEqual(status.state, "degraded")
        self.assertIsNotNone(status.viewer)
        self.assertTrue(status.viewer.failed)
        self.assertIn("viewer_adapter_close_failed", status.reasons)

    def test_failed_viewer_cleanup_cannot_publish_a_replacement_profile(self):
        base = source_profiles()
        replacement = replace(base, viewer=ViewerProfile(video_format(width=1280)))
        admissions = SourceProfileAdmissions(1)
        decision = admissions.admit(SourceProfileCapabilities(
            SOURCE, SourceType.LOCAL_UVC, (base, replacement),
        ), base)
        factory = SyntheticFactory()
        value = pipeline(profiles=base, recording=SyntheticFactory(), viewer=factory,
                         admission=decision.lease)
        self.addCleanup(value.close)
        value.add_viewer(SUBSCRIBER)
        factory.adapters[0].fail_close = True

        with self.assertRaises(RuntimeError):
            value.replace_viewer_profile(replacement.viewer)

        self.assertEqual(value.profiles, base)
        self.assertEqual(admissions.admitted(SOURCE), base)
        self.assertEqual(factory.adapters[0].plan.target, base.viewer.format)

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

    def test_consecutive_sequence_forward_timestamp_gap_is_visible_on_both_paths(self):
        recording, viewer = SyntheticFactory(), SyntheticFactory()
        value = pipeline(recording=recording, viewer=viewer)
        value.add_viewer(SUBSCRIBER)
        value.offer(packet(0, keyframe=True))
        value.pump(1)
        result = value.offer(packet(1, pts=300, dts=300))
        self.assertEqual(result.reason, "decode_timestamp_gap")
        self.assertFalse(result.recording_queued)
        self.assertFalse(result.viewer_queued)
        for status in (value.recording_status, value.viewer_status):
            self.assertFalse(status.healthy)
            self.assertEqual(status.discontinuities, 1)
            self.assertTrue(status.awaiting_keyframe)
        result = value.offer(packet(2, keyframe=True, pts=301, dts=301))
        self.assertTrue(result.recording_queued)
        self.assertTrue(result.viewer_queued)
        self.assertEqual(value.pump(1), (1, 1))
        self.assertFalse(value.recording_status.healthy)
        self.assertFalse(value.viewer_status.healthy)

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
