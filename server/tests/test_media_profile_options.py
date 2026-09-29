"""Room-overview option, adapter selection and synthetic resource harness.

All descriptors and packets are generated. No camera, codec, accelerator,
network or real-person media is used, and no number here is a default.
"""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from fractions import Fraction
import io
import json
import os
import socket
import unittest
from uuid import UUID

from app.cameras.registry.models import SourceType
from app.media.profiles import (
    AccelerationPolicy, AdapterCandidate, AdapterKind, AdapterSelector,
    AdapterStartFailed, AdapterUnavailable, CaptureOption, EncodeMode, InferenceProfile,
    QueueLimits, RecordingProfile, RoomOverviewCriteria, SourcePipeline,
    SourceProfileAdmissions, SourceProfileCapabilities, ViewerProfile, plan_encoding,
    room_overview_violations,
)
from app.media.profiles import measure
from tests.test_media_profiles import (
    SOURCE, STREAM, SUBSCRIBER, SyntheticAdapter, inference_profile, packet,
    source_profiles, video_format,
)


CRITERIA = RoomOverviewCriteria(3840, 2160)


def overview_profiles(**changes):
    # 4K-class synthetic capture/recording, downscaled viewer and inference.
    value = source_profiles()
    value = replace(value, viewer=ViewerProfile(video_format(width=1920, height=1080,
                                                             fps=Fraction(15))),
                    inference=inference_profile(fps=Fraction(3)))
    return replace(value, **changes)


def standard_profiles():
    format_ = video_format(width=1920, height=1080)
    value = source_profiles()
    return replace(value, capture=replace(value.capture, format=format_),
                   recording=RecordingProfile(format_), viewer=ViewerProfile(format_))


def capabilities(sets, overview=(), criteria=None, source=SOURCE):
    return SourceProfileCapabilities(source, SourceType.REMOTE_AGENT, tuple(sets),
                                     tuple(overview), criteria)


class RoomOverviewOptionTests(unittest.TestCase):
    def test_valid_overview_set_is_structurally_downscaled(self):
        self.assertEqual(room_overview_violations(overview_profiles(), CRITERIA), ())

    def test_each_structural_violation_has_a_sanitized_reason(self):
        base = overview_profiles()
        cases = {
            "capture_below_room_overview_minimum": replace(
                base, capture=replace(base.capture, format=video_format(width=2560,
                                                                        height=1440))),
            "inference_not_downscaled": replace(
                base, inference=InferenceProfile(3840, 2160, Fraction(3), Fraction(2))),
            "inference_fps_exceeds_capture": replace(
                base, inference=inference_profile(fps=Fraction(60))),
            "viewer_not_downscaled": replace(base, viewer=ViewerProfile(video_format())),
            "viewer_fps_exceeds_capture": replace(
                base, viewer=ViewerProfile(video_format(width=1280, height=720,
                                                        fps=Fraction(60)))),
            "recording_exceeds_capture": replace(
                base, recording=RecordingProfile(video_format(width=7680, height=4320))),
            "recording_fps_exceeds_capture": replace(
                base, recording=RecordingProfile(video_format(fps=Fraction(60)))),
        }
        for reason, profiles in cases.items():
            with self.subTest(reason=reason):
                violations = room_overview_violations(profiles, CRITERIA)
                self.assertIn(reason, violations)
                self.assertFalse(any(character.isdigit() for item in violations
                                     for character in item))

    def test_criteria_are_explicit_positive_integers(self):
        for values in ((0, 2160), (3840, -1), (True, 2160), (3840.0, 2160)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                RoomOverviewCriteria(*values)

    def test_capabilities_reject_invalid_or_implicit_overview_options(self):
        overview = overview_profiles()
        with self.assertRaisesRegex(ValueError, "criteria"):
            capabilities((overview,), (overview,), None)
        with self.assertRaisesRegex(ValueError, "listed option"):
            capabilities((overview,), (), CRITERIA)
        with self.assertRaisesRegex(ValueError, "profile_sets"):
            capabilities((standard_profiles(),), (overview,), CRITERIA)
        with self.assertRaisesRegex(ValueError, "unique"):
            SourceProfileCapabilities(SOURCE, SourceType.REMOTE_AGENT, (overview,),
                                      [overview], CRITERIA)
        with self.assertRaisesRegex(ValueError, "unique"):
            capabilities((overview,), (overview, overview), CRITERIA)
        invalid = replace(overview, viewer=ViewerProfile(video_format()))
        with self.assertRaises(ValueError) as raised:
            capabilities((invalid,), (invalid,), CRITERIA)
        self.assertIn("viewer_not_downscaled", str(raised.exception))
        self.assertNotIn("3840", str(raised.exception))
        self.assertNotIn(str(SOURCE), str(raised.exception))

    def test_high_resolution_set_is_not_an_overview_option_unless_listed(self):
        # A 4K-class set without the explicit listing stays a standard option,
        # and nothing is inferred from source type or a room_overview role.
        overview = overview_profiles()
        listed = capabilities((overview,))
        self.assertEqual(listed.option_sets(CaptureOption.STANDARD), (overview,))
        self.assertEqual(listed.option_sets(CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION), ())
        decision = SourceProfileAdmissions(4).admit(
            listed, overview, CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.reasons, ("capture_option_mismatch",))

    def test_overview_option_requires_explicit_request_and_bounds_lease(self):
        overview = overview_profiles()
        standard = standard_profiles()
        allowed = capabilities((standard, overview), (overview,), CRITERIA)
        admissions = SourceProfileAdmissions(4)
        implicit = admissions.admit(allowed, overview)
        self.assertFalse(implicit.admitted)
        self.assertEqual(implicit.reasons, ("capture_option_mismatch",))
        self.assertIsNone(admissions.admitted(SOURCE))
        with self.assertRaises(ValueError):
            admissions.admit(allowed, overview, "room_overview_high_resolution")
        decision = admissions.admit(allowed, overview,
                                    CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION)
        self.assertTrue(decision.admitted)
        self.assertIs(decision.option, CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION)
        self.assertIs(decision.lease.option, CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION)
        self.assertEqual(decision.lease.profile_sets, (overview,))
        self.assertFalse(decision.lease.permits(standard))
        self.assertEqual(admissions.admitted(SOURCE), overview)

    def test_standard_request_cannot_select_overview_set_and_vice_versa(self):
        overview = overview_profiles()
        standard = standard_profiles()
        allowed = capabilities((standard, overview), (overview,), CRITERIA)
        admissions = SourceProfileAdmissions(4)
        wrong = admissions.admit(allowed, standard,
                                 CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION)
        self.assertEqual(wrong.reasons, ("capture_option_mismatch",))
        unknown = admissions.admit(allowed, replace(standard, inference=inference_profile(
            fps=Fraction(1))), CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION)
        self.assertEqual(unknown.reasons, ("profile_set_unsupported",))
        only_overview = capabilities((overview,), (overview,), CRITERIA)
        missing = admissions.admit(only_overview, standard)
        self.assertEqual(missing.reasons, ("capture_option_unavailable",))
        self.assertIsNone(admissions.admitted(SOURCE))
        standard_lease = admissions.admit(allowed, standard)
        self.assertTrue(standard_lease.admitted)
        self.assertEqual(standard_lease.lease.profile_sets, (standard,))

    def test_pipeline_adaptation_stays_inside_the_admitted_option(self):
        overview = overview_profiles()
        adapted = replace(overview, viewer=ViewerProfile(
            video_format(width=1280, height=720, fps=Fraction(10))))
        standard_same_capture = replace(overview, viewer=ViewerProfile(
            video_format(width=1920, height=1080, fps=Fraction(10))))
        allowed = capabilities((overview, adapted, standard_same_capture),
                               (overview, adapted), CRITERIA)
        admissions = SourceProfileAdmissions(4)
        lease = admissions.admit(allowed, overview,
                                 CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION).lease
        pipe = SourcePipeline(SOURCE, STREAM, overview, QueueLimits(8, 1024),
                              QueueLimits(8, 1024), SyntheticAdapter, SyntheticAdapter,
                              lease)
        pipe.replace_viewer_profile(adapted.viewer)
        self.assertEqual(admissions.admitted(SOURCE), adapted)
        with self.assertRaises(ValueError):
            pipe.replace_viewer_profile(standard_same_capture.viewer)
        self.assertEqual(pipe.profiles, adapted)
        self.assertEqual(admissions.admitted(SOURCE), adapted)
        pipe.close()
        self.assertTrue(admissions.release(lease))
        self.assertIsNone(admissions.admitted(SOURCE))

    def test_one_to_four_sources_select_options_independently(self):
        admissions = SourceProfileAdmissions(4)
        overview = overview_profiles()
        standard = standard_profiles()
        for index in range(4):
            source = UUID(int=100 + index)
            allowed = capabilities((standard, overview), (overview,), CRITERIA, source)
            option = (CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION if index == 2
                      else CaptureOption.STANDARD)
            chosen = overview if index == 2 else standard
            self.assertTrue(admissions.admit(allowed, chosen, option).admitted)
        self.assertEqual(admissions.active_sources, 4)
        self.assertEqual(admissions.admitted(UUID(int=102)), overview)
        self.assertEqual(admissions.admitted(UUID(int=103)), standard)


def _plan():
    format_ = video_format()
    return plan_encoding(format_, replace(format_, width=1280, height=720))


class _Recorder:
    def __init__(self, *, supported=True, probe_error=False, start_error=None,
                 returns_none=False):
        self.supported = supported
        self.probe_error = probe_error
        self.start_error = start_error
        self.returns_none = returns_none
        self.probes = 0
        self.adapters = []

    def probe(self, plan):
        self.probes += 1
        if self.probe_error:
            raise RuntimeError("/dev/secret-device detail must not escape")
        return self.supported

    def factory(self, plan):
        if self.start_error is not None:
            raise self.start_error
        if self.returns_none:
            return None
        adapter = SyntheticAdapter(plan)
        self.adapters.append(adapter)
        return adapter


def _candidate(name, kind, recorder):
    return AdapterCandidate(name, kind, recorder.probe, recorder.factory)


class AdapterSelectionTests(unittest.TestCase):
    def test_hardware_is_used_when_available(self):
        hardware, software = _Recorder(), _Recorder()
        selector = AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, (
            _candidate("accel", AdapterKind.HARDWARE, hardware),
            _candidate("cpu", AdapterKind.SOFTWARE, software)))
        adapter = selector(_plan())
        self.assertIs(adapter, hardware.adapters[0])
        self.assertEqual(software.probes, 0)
        selection = selector.last_selection
        self.assertEqual((selection.selected, selection.kind, selection.fallback,
                          selection.state), ("accel", AdapterKind.HARDWARE, False, "ready"))

    def test_missing_accelerator_falls_back_visibly_to_software(self):
        software = _Recorder()
        selector = AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, (
            _candidate("cpu", AdapterKind.SOFTWARE, software),))
        self.assertIs(selector(_plan()), software.adapters[0])
        selection = selector.last_selection
        self.assertTrue(selection.fallback)
        self.assertEqual(selection.state, "software_fallback")
        self.assertEqual(selection.kind, AdapterKind.SOFTWARE)
        self.assertEqual(selection.reasons, ("hardware_not_installed",
                                             "hardware_unavailable", "software_fallback"))

    def test_each_hardware_failure_mode_is_named_in_the_fallback(self):
        cases = {
            "hardware_unsupported_plan": _Recorder(supported=False),
            "hardware_probe_failed": _Recorder(probe_error=True),
            "hardware_start_failed": _Recorder(start_error=RuntimeError("/dev/x detail")),
            "hardware_start_failed ": _Recorder(returns_none=True),
            "hardware_unsupported_plan ": _Recorder(start_error=AdapterUnavailable()),
        }
        for reason, hardware in cases.items():
            with self.subTest(reason=reason):
                selector = AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, (
                    _candidate("accel", AdapterKind.HARDWARE, hardware),
                    _candidate("cpu", AdapterKind.SOFTWARE, _Recorder())))
                selector(_plan())
                selection = selector.last_selection
                self.assertTrue(selection.fallback)
                self.assertEqual(selection.reasons,
                                 (reason.strip(), "hardware_unavailable",
                                  "software_fallback"))
                self.assertNotIn("/dev", repr(selection))
                self.assertNotIn("detail", repr(selection))

    def test_require_hardware_never_substitutes_software(self):
        software = _Recorder()
        selector = AdapterSelector(AccelerationPolicy.REQUIRE_HARDWARE, (
            _candidate("cpu", AdapterKind.SOFTWARE, software),))
        with self.assertRaises(AdapterUnavailable):
            selector(_plan())
        self.assertEqual(software.probes, 0)
        selection = selector.last_selection
        self.assertFalse(selection.available)
        self.assertEqual(selection.state, "unavailable")
        self.assertIn("hardware_unavailable", selection.reasons)

    def test_start_failure_without_fallback_is_failed_not_unavailable(self):
        selector = AdapterSelector(AccelerationPolicy.REQUIRE_HARDWARE, (
            _candidate("accel", AdapterKind.HARDWARE,
                       _Recorder(start_error=RuntimeError("secret detail"))),))
        with self.assertRaises(AdapterStartFailed) as raised:
            selector(_plan())
        self.assertEqual(str(raised.exception), "")
        self.assertEqual(selector.last_selection.reasons,
                         ("hardware_start_failed", "hardware_unavailable"))

    def test_nothing_installed_is_explicitly_unavailable(self):
        for policy in AccelerationPolicy:
            with self.subTest(policy=policy):
                selector = AdapterSelector(policy, ())
                with self.assertRaises(AdapterUnavailable):
                    selector(_plan())
                self.assertEqual(selector.last_selection.state, "unavailable")
                self.assertFalse(selector.last_selection.fallback)

    def test_software_only_ignores_hardware_and_is_not_a_fallback(self):
        hardware, software = _Recorder(), _Recorder()
        selector = AdapterSelector(AccelerationPolicy.SOFTWARE_ONLY, (
            _candidate("accel", AdapterKind.HARDWARE, hardware),
            _candidate("cpu", AdapterKind.SOFTWARE, software)))
        selector(_plan())
        self.assertEqual(hardware.probes, 0)
        self.assertEqual((selector.last_selection.kind, selector.last_selection.fallback,
                          selector.last_selection.reasons),
                         (AdapterKind.SOFTWARE, False, ()))

    def test_non_bool_probe_result_is_not_support(self):
        hardware = _Recorder(supported="yes")
        selector = AdapterSelector(AccelerationPolicy.REQUIRE_HARDWARE, (
            _candidate("accel", AdapterKind.HARDWARE, hardware),))
        with self.assertRaises(AdapterUnavailable):
            selector(_plan())
        self.assertEqual(hardware.adapters, [])

    def test_selection_reruns_on_each_start_after_recovery(self):
        hardware = _Recorder(supported=False)
        selector = AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, (
            _candidate("accel", AdapterKind.HARDWARE, hardware),
            _candidate("cpu", AdapterKind.SOFTWARE, _Recorder())))
        selector(_plan())
        self.assertTrue(selector.last_selection.fallback)
        hardware.supported = True
        selector(_plan())
        self.assertFalse(selector.last_selection.fallback)
        self.assertEqual(selector.last_selection.kind, AdapterKind.HARDWARE)

    def test_invalid_configuration_fails_before_use(self):
        recorder = _Recorder()
        with self.assertRaises(ValueError):
            AdapterSelector("prefer_hardware", ())
        with self.assertRaises(ValueError):
            AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, [])
        with self.assertRaises(ValueError):
            AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, (
                _candidate("cpu", AdapterKind.SOFTWARE, recorder),
                _candidate("cpu", AdapterKind.HARDWARE, recorder)))
        with self.assertRaises(ValueError):
            AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, tuple(
                _candidate(f"cpu{index}", AdapterKind.SOFTWARE, recorder)
                for index in range(9)))
        for name in ("", "CPU", "/dev/video0", "a" * 33, 3):
            with self.subTest(name=name), self.assertRaises(ValueError):
                AdapterCandidate(name, AdapterKind.SOFTWARE, recorder.probe,
                                 recorder.factory)
        with self.assertRaises(ValueError):
            AdapterCandidate("cpu", "software", recorder.probe, recorder.factory)
        with self.assertRaises(ValueError):
            AdapterSelector(AccelerationPolicy.SOFTWARE_ONLY, ())("not a plan")

    def test_pipeline_maps_selection_outcomes_without_silent_success(self):
        limits = QueueLimits(8, 1024)
        unavailable = AdapterSelector(AccelerationPolicy.REQUIRE_HARDWARE, ())
        pipe = SourcePipeline(SOURCE, STREAM, source_profiles(), limits, limits,
                              unavailable, unavailable)
        self.assertEqual(pipe.recording_status.reason, "adapter_unavailable")
        self.assertEqual(pipe.status.state, "unavailable")
        failed = AdapterSelector(AccelerationPolicy.REQUIRE_HARDWARE, (
            _candidate("accel", AdapterKind.HARDWARE,
                       _Recorder(start_error=RuntimeError("detail"))),))
        pipe = SourcePipeline(SOURCE, STREAM, source_profiles(), limits, limits,
                              failed, failed)
        self.assertEqual(pipe.recording_status.reason, "adapter_start_failed")
        self.assertTrue(pipe.recording_status.failed)
        software = _Recorder()
        fallback = AdapterSelector(AccelerationPolicy.PREFER_HARDWARE, (
            _candidate("cpu", AdapterKind.SOFTWARE, software),))
        pipe = SourcePipeline(SOURCE, STREAM, source_profiles(), limits, limits,
                              fallback, fallback)
        pipe.add_viewer(SUBSCRIBER)
        pipe.offer(packet(0, keyframe=True))
        self.assertEqual(pipe.pump(4), (1, 1))
        self.assertEqual(len(software.adapters), 2)
        self.assertTrue(fallback.last_selection.fallback)
        self.assertEqual(pipe.recording_plan.mode, EncodeMode.STREAM_COPY)
        pipe.close()
        self.assertTrue(all(adapter.closed for adapter in software.adapters))


def _config(**changes):
    values = dict(sources=2, packets=300, packet_bytes=512, keyframe_interval=30,
                  viewers=1, queue_packets=16, queue_bytes=65536, pump_every=1,
                  pump_budget=4, acceleration=AccelerationPolicy.PREFER_HARDWARE)
    values.update(changes)
    return measure.MeasureConfig(**values)


class MeasurementHarnessTests(unittest.TestCase):
    def test_config_bounds_fail_closed(self):
        for changes in ({"sources": 0}, {"sources": 5}, {"packets": 0},
                        {"packets": 10**9}, {"packet_bytes": 0}, {"viewers": -1},
                        {"queue_packets": 0}, {"pump_budget": 0}, {"pump_every": 0},
                        {"keyframe_interval": 0}, {"sources": True},
                        {"acceleration": "prefer_hardware"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                _config(**changes)

    def test_healthy_run_reports_bounded_depth_and_fallback(self):
        result = measure.run_measurement(_config())
        self.assertFalse(result["deployment_acceptance"])
        self.assertEqual(len(result["sources"]), 2)
        self.assertEqual(result["adapter_selection"]["state"], "software_fallback")
        self.assertIn("hardware_unavailable", result["adapter_selection"]["reasons"])
        for source in result["sources"]:
            self.assertEqual(source["state"], "healthy")
            self.assertEqual(source["recording"]["delivered_packets"], 300)
            self.assertEqual(source["viewer"]["delivered_packets"], 300)
            self.assertEqual(source["inference_samples"], 50)
            self.assertLessEqual(source["recording"]["maximum_queued_packets"], 16)
        self.assertGreaterEqual(result["resources"]["cpu_seconds"], 0)

    def test_slow_consumer_backpressure_is_visible_and_bounded(self):
        result = measure.run_measurement(_config(pump_every=8, pump_budget=1,
                                                 queue_packets=4))
        for source in result["sources"]:
            recording = source["recording"]
            self.assertEqual(source["state"], "degraded")
            self.assertGreater(recording["dropped_packets"], 0)
            self.assertGreater(recording["discontinuities"], 0)
            self.assertLessEqual(recording["maximum_queued_packets"], 4)
            self.assertLessEqual(recording["maximum_queued_bytes"], 65536)

    def test_viewer_absent_has_no_viewer_path(self):
        result = measure.run_measurement(_config(viewers=0, sources=4))
        self.assertEqual(len(result["sources"]), 4)
        self.assertTrue(all(source["viewer"] is None for source in result["sources"]))

    def test_rss_unobservable_is_reported_not_zero(self):
        original = measure._rss_bytes
        measure._rss_bytes = lambda: None
        try:
            result = measure.run_measurement(_config(packets=10))
        finally:
            measure._rss_bytes = original
        self.assertFalse(result["resources"]["rss_observable"])
        self.assertIsNone(result["resources"]["rss_peak_sampled_bytes"])

    def test_cli_prints_no_private_values_and_exits_by_availability(self):
        argv = ["--sources", "1", "--packets", "60", "--packet-bytes", "64",
                "--keyframe-interval", "30", "--viewers", "1", "--queue-packets", "8",
                "--queue-bytes", "4096", "--pump-every", "1", "--pump-budget", "2"]
        output = io.StringIO()
        with redirect_stdout(output):
            code = measure.main([*argv, "--acceleration", "prefer_hardware"])
        self.assertEqual(code, 0)
        text = output.getvalue()
        result = json.loads(text)
        self.assertEqual(result["sources"][0]["state"], "healthy")
        forbidden = {socket.gethostname(), os.getcwd(), str(SOURCE), str(UUID(int=1)),
                     os.environ.get("HOME", "\0"), os.environ.get("USER", "\0")}
        for value in forbidden:
            if value:
                self.assertNotIn(value, text)
        self.assertNotIn("/", text)
        output = io.StringIO()
        with redirect_stdout(output):
            code = measure.main([*argv, "--acceleration", "require_hardware"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["sources"][0]["state"],
                         "unavailable")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            measure.main([*argv[:2], "5", *argv[2:], "--acceleration", "software_only"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
