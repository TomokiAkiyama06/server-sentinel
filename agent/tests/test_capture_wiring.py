"""Issue #14: the Agent's capture wiring, live preview consumer and local approval CLI.

Synthetic discovery, pipelines and JPEG-shaped bytes only (``test_uvc_capture``
fakes); no real camera, device node or network is used.
"""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from media_capture_agent import capture_admin, cli
from media_capture_agent.config import ConfigurationError, Settings
from media_capture_agent.preview import PreviewTap
from media_capture_agent.uvc_approvals import ApprovalStore
from media_capture_agent.uvc_pipeline import Frame, FrameQueue, PipelineError
from tests import support
from tests.test_uvc_capture import (
    SOURCES, CaptureCase, FakeDiscovery, evidence, synthetic_jpeg, wait_for,
)


class CaptureSettingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-capture-config-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.value = support.configuration(self.root)

    def parse(self, capture):
        return Settings.parse(dict(self.value, capture=capture), code_root=self.root / "code")

    def test_the_capture_section_is_optional_and_explicit(self):
        self.assertIsNone(Settings.parse(self.value, code_root=self.root / "code").capture)
        self.assertIsNone(self.parse(None).capture)
        source = str(uuid4())
        capture = self.parse({"gst_launch": "/usr/bin/gst-launch-1.0",
                              "sources": [{"source_id": source,
                                           "profile": "1920x1080@30/MJPG"}]}).capture
        self.assertEqual((str(capture.gst_launch), str(capture.sources[0].source_id),
                          capture.sources[0].width, capture.sources[0].height,
                          capture.sources[0].fps),
                         ("/usr/bin/gst-launch-1.0", source, 1920, 1080, 30))

    def test_invalid_capture_sections_are_refused(self):
        source = {"source_id": str(uuid4()), "profile": "1920x1080@30/MJPG"}
        for capture in ({"sources": [source]},
                        {"gst_launch": "gst-launch-1.0", "sources": [source]},
                        {"gst_launch": "/usr/bin/gst-launch-1.0", "sources": []},
                        {"gst_launch": "/usr/bin/gst-launch-1.0", "sources": [source] * 2},
                        {"gst_launch": "/usr/bin/gst-launch-1.0",
                         "sources": [dict(source, source_id=str(uuid4())) for _ in range(5)]},
                        {"gst_launch": "/usr/bin/gst-launch-1.0",
                         "sources": [dict(source, profile="1920x1080@30/YUYV")]},
                        {"gst_launch": "/usr/bin/gst-launch-1.0",
                         "sources": [dict(source, profile="1920x1080@0/MJPG")]},
                        {"gst_launch": "/usr/bin/gst-launch-1.0",
                         "sources": [dict(source, audio=True)]},
                        {"gst_launch": "/usr/bin/gst-launch-1.0",
                         "sources": [dict(source, source_id="camera-1")]}):
            with self.subTest(capture=capture):
                with self.assertRaises(ConfigurationError):
                    self.parse(capture)


class UnitTests(unittest.TestCase):
    def test_capture_allows_the_video_class_but_no_sound_device(self):
        # PR #412 review: discovery probes every video4linux node (UVC adds a
        # metadata node) and a re-plugged camera gets a new number.
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        self.addCleanup(sys.path.remove, str(Path(__file__).resolve().parents[1]))
        from install import render_unit
        temporary = tempfile.TemporaryDirectory(prefix="agent-capture-unit-")
        self.addCleanup(temporary.cleanup)
        value = support.configuration(Path(temporary.name))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0",
                            "sources": [{"source_id": str(SOURCES[0]),
                                         "profile": "640x480@15/MJPG"}]}
        parsed = Settings.parse(value, code_root=Path(temporary.name) / "code")
        unit = render_unit(Path("/opt/example/0.1.0/media-capture-agent"),
                           Path("/etc/example/config.json"), parsed, "synthetic", 123)
        self.assertIn("DevicePolicy=closed", unit)
        self.assertIn("DeviceAllow=char-video4linux rw", unit)
        self.assertIn("SupplementaryGroups=video", unit)
        self.assertIn("Wants=modprobe@videodev.service", unit)
        self.assertIn("After=modprobe@videodev.service", unit)
        self.assertNotIn("audio", unit)
        self.assertNotIn("snd", unit)
        self.assertNotIn("char-alsa", unit)


class PreviewTapTests(unittest.TestCase):
    def test_only_the_newest_frame_is_kept_and_the_queue_never_overflows(self):
        source = uuid4()
        queue = FrameQueue(2)
        tap = PreviewTap([(source, queue)])
        self.addCleanup(tap.close)
        self.assertIsNone(tap.latest(source))
        for sequence in range(1, 21):
            queue.put(Frame(synthetic_jpeg(sequence), sequence, 1, 0.0))
            self.assertTrue(wait_for(lambda: tap.latest(source) is not None
                                     and tap.latest(source).sequence == sequence))
        self.assertEqual(queue.drop_stats()[0], 0)
        self.assertEqual(tap.latest(source).data, synthetic_jpeg(20))
        self.assertNotIn(synthetic_jpeg(20).hex()[:16], repr(tap.latest(source)))

    def test_close_stops_every_thread_even_with_closed_queues(self):
        before = set(threading.enumerate())
        queues = [(uuid4(), FrameQueue(1)) for _ in range(4)]
        tap = PreviewTap(queues)
        for _, queue in queues:
            queue.close()
        tap.close()
        self.assertTrue(wait_for(lambda: not [thread for thread in threading.enumerate()
                                              if thread not in before and thread.is_alive()]))
        self.assertEqual(tap.sources(), ())


class CaptureWithPreviewTests(CaptureCase):
    def test_an_online_camera_feeds_the_preview_without_queue_drops(self):
        device = evidence(0)
        capture, pipeline = self.approved_online(FakeDiscovery(device), device)
        tap = PreviewTap([(SOURCES[0], capture.frames(SOURCES[0]))])
        self.addCleanup(tap.close)
        for number in range(1, 30):
            # Paced like a camera: each frame is consumed before the next.
            pipeline.feed(synthetic_jpeg(number))
            self.assertTrue(wait_for(lambda: tap.latest(SOURCES[0]) is not None
                                     and tap.latest(SOURCES[0]).data
                                     == synthetic_jpeg(number)))
        self.assertEqual(self.state(capture), ("online", "video_ready"))
        self.assertEqual(capture.frames(SOURCES[0]).drop_stats()[0], 0)


class ApprovedCameraReconnectTests(CaptureCase):
    def test_an_admin_approval_reconnects_at_the_next_service_start(self):
        from types import SimpleNamespace
        device = evidence(0, serial="SYN-SERIAL-0009")
        discovery = FakeDiscovery(device)
        admin_settings = SimpleNamespace(
            service_uid=self.settings.service_uid, runtime_root=self.settings.runtime_root,
            capture=SimpleNamespace(sources=(SimpleNamespace(source_id=SOURCES[0], width=640,
                                                             height=480, fps=15),)))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = capture_admin.main(
                ["approve", "--config", "/nonexistent", str(SOURCES[0]),
                 capture_admin.candidate_label(device)],
                settings_loader=lambda path: admin_settings, discovery=discovery,
                confirm=lambda prompt: "APPROVE")
        self.assertEqual(code, 0)
        # The service's next start reconnects it by serial, without the Owner.
        capture = self.capture(discovery)
        self.assertEqual(self.state(capture), ("degraded", "capture_starting"))
        self.stream(capture, self.launcher.pipelines[-1])
        self.assertEqual(self.state(capture), ("online", "video_ready"))


class CheckReasonTests(unittest.TestCase):
    def test_capture_failures_have_their_own_codes(self):
        from media_capture_agent.uvc_approvals import ApprovalStorageError
        from media_capture_agent.uvc_capture import CaptureRefused
        self.assertEqual(cli.check_reason(PipelineError("synthetic")),
                         "capture_pipeline_unavailable")
        for error in (ApprovalStorageError("synthetic"), CaptureRefused("synthetic")):
            self.assertEqual(cli.check_reason(error), "capture_state_unavailable")
        self.assertTrue({"capture_pipeline_unavailable", "capture_state_unavailable"}
                        <= cli.CHECK_REASONS)

    def test_check_builds_the_launcher_but_never_opens_the_approval_store(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-capture-check-")
        self.addCleanup(temporary.cleanup)
        value = support.configuration(Path(temporary.name))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0",
                            "sources": [{"source_id": str(SOURCES[0]),
                                         "profile": "640x480@15/MJPG"}]}
        parsed = Settings.parse(value, code_root=Path(temporary.name) / "code")
        launchers = []
        with patch.object(cli, "_capture_launcher",
                          side_effect=lambda settings: launchers.append(settings) or object()), \
                patch.object(cli, "_capture", side_effect=AssertionError("opened")), \
                patch.object(cli.Settings, "load", return_value=parsed), \
                patch.object(cli, "MediaStore") as media, \
                patch.object(cli, "Agent") as agent:
            media.return_value.device_numbers_stale = False
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--config", "/nonexistent", "--check"]), 0)
        self.assertEqual(len(launchers), 1)
        self.assertNotIn("capture", agent.call_args.kwargs)

    def test_the_agent_checks_run_before_any_capture_is_built(self):
        # #116 (PR #412 review): fail closed before the cameras.
        temporary = tempfile.TemporaryDirectory(prefix="agent-capture-order-")
        self.addCleanup(temporary.cleanup)
        value = support.configuration(Path(temporary.name))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0",
                            "sources": [{"source_id": str(SOURCES[0]),
                                         "profile": "640x480@15/MJPG"}]}
        parsed = Settings.parse(value, code_root=Path(temporary.name) / "code")
        from media_capture_agent.storage import StorageRefused
        with patch.object(cli, "_capture_launcher") as launcher, \
                patch.object(cli, "_capture") as built, \
                patch.object(cli.Settings, "load", return_value=parsed), \
                patch.object(cli, "MediaStore"), \
                patch.object(cli, "Agent",
                             side_effect=StorageRefused("dedicated_nonroot_account_required")):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(cli.main(["--config", "/nonexistent"]), 1)
        self.assertIn("service_account_mismatch", stderr.getvalue())
        launcher.assert_not_called()
        built.assert_not_called()


class CaptureAdminTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-capture-admin-")
        self.addCleanup(temporary.cleanup)
        value = support.configuration(Path(temporary.name))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0",
                            "sources": [{"source_id": str(SOURCES[0]),
                                         "profile": "640x480@15/MJPG"}]}
        self.settings = Settings.parse(value, code_root=Path(temporary.name) / "code")
        self.camera = evidence(0, serial="SYN-SERIAL-0001")
        self.discovery = FakeDiscovery(self.camera, evidence(2, serial="SYN-SERIAL-0002"))
        self.prompts = []

    def run_cli(self, *argv, typed="APPROVE", settings=None):
        def confirm(prompt):
            self.prompts.append(prompt)
            return typed

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = capture_admin.main([argv[0], "--config", "/nonexistent", *argv[1:]],
                                      settings_loader=lambda path: settings or self.settings,
                                      discovery=self.discovery, confirm=confirm)
        return code, stdout.getvalue(), stderr.getvalue()

    def approved(self):
        store = ApprovalStore(self.settings)
        try:
            return store.load(SOURCES[0])
        finally:
            store.close()

    def label(self, device):
        return capture_admin.candidate_label(device)

    def test_candidates_show_labels_but_no_serial_or_path(self):
        code, stdout, stderr = self.run_cli("candidates")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(f"candidate {self.label(self.camera)} usb=1d6b:0102 serial=present "
                      f"formats=MJPG,YUYV approved_for=-", stdout)
        for private in ("SYN-SERIAL", "/dev/video", "usb1/1-"):
            self.assertNotIn(private, stdout)

    def test_approve_asks_on_the_terminal_and_persists_the_exact_camera(self):
        code, stdout, stderr = self.run_cli("approve", str(SOURCES[0]), self.label(self.camera))
        self.assertEqual((code, stderr), (0, ""), stderr)
        self.assertIn("Type APPROVE to confirm", self.prompts[0])
        self.assertIn(f"camera approved: source_id={SOURCES[0]}", stdout)
        state = self.approved()
        self.assertEqual(state.approved, self.camera)
        self.assertFalse(state.requires_approval)
        # Closed cleanly: the next service start is not a recovery.
        self.assertIsNone(state.session_token)
        code, stdout, _ = self.run_cli("candidates")
        self.assertIn(f"approved_for={SOURCES[0]}", stdout)

    def test_refusals_change_nothing(self):
        cases = (
            (("approve", str(SOURCES[0]), self.label(self.camera)), "no",
             "owner_confirmation_declined"),
            (("approve", str(SOURCES[0]), "cam-0000000000"), "APPROVE", "candidate_not_found"),
            (("approve", str(uuid4()), self.label(self.camera)), "APPROVE",
             "source_not_configured"),
            (("approve", "camera-1", self.label(self.camera)), "APPROVE", "source_id_rejected"),
            (("approve", str(SOURCES[0]), "camera-1"), "APPROVE", "candidate_label_rejected"),
        )
        for argv, typed, reason in cases:
            with self.subTest(reason=reason):
                code, stdout, stderr = self.run_cli(*argv, typed=typed)
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn(f"refused: {reason}", stderr)
        # No session was even started: nothing is stored for the source.
        self.assertIsNone(self.approved())

    def test_candidates_start_no_session(self):
        self.run_cli("candidates")
        state = self.approved()
        self.assertIsNone(state)

    def test_approved_for_survives_a_new_device_instance(self):
        # The label hashes the per-boot instance; `approved_for` uses the serial.
        self.run_cli("approve", str(SOURCES[0]), self.label(self.camera))
        replugged = evidence(0, serial="SYN-SERIAL-0001", token=(9, 999, 9))
        self.discovery.devices = [replugged]
        _, stdout, _ = self.run_cli("candidates")
        self.assertIn(f"approved_for={SOURCES[0]}", stdout)
        self.assertNotIn(self.label(self.camera), stdout)

    def test_shared_or_latched_serials_are_not_approved(self):
        twin = evidence(2, serial="SYN-SERIAL-0001")
        self.discovery.devices = [self.camera, twin]
        code, _, stderr = self.run_cli("approve", str(SOURCES[0]), self.label(self.camera))
        self.assertEqual(code, 2)
        self.assertIn("refused: camera_serial_not_unique", stderr)
        self.assertIn("serial=shared", self.run_cli("candidates")[1])
        # A latched ambiguity for the same serial refuses as well.
        from media_capture_agent.uvc_approvals import ApprovalStore as Store
        store = Store(self.settings)
        try:
            token = store.start_session(SOURCES[0]).session_token
            store.save(SOURCES[0], self.camera, True, session_token=token,
                       serial_ambiguous=True, release=True)
        finally:
            store.close()
        self.discovery.devices = [self.camera]
        code, _, stderr = self.run_cli("approve", str(SOURCES[0]), self.label(self.camera))
        self.assertIn("refused: camera_serial_not_unique", stderr)

    def test_a_camera_approved_for_another_source_is_refused(self):
        value = support.configuration(Path(tempfile.mkdtemp(prefix="agent-capture-two-")))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0", "sources": [
            {"source_id": str(SOURCES[0]), "profile": "640x480@15/MJPG"},
            {"source_id": str(SOURCES[1]), "profile": "640x480@15/MJPG"}]}
        two = Settings.parse(value, code_root=Path("/nonexistent/code"))
        code, _, stderr = self.run_cli("approve", str(SOURCES[0]), self.label(self.camera),
                                       settings=two)
        self.assertEqual(code, 0, stderr)
        code, _, stderr = self.run_cli("approve", str(SOURCES[1]), self.label(self.camera),
                                       settings=two)
        self.assertEqual(code, 2)
        self.assertIn("refused: camera_approved_for_another_source", stderr)

    def test_a_camera_that_changed_at_the_prompt_is_a_fixed_refusal(self):
        from media_capture_agent.uvc_capture import UvcCapture
        with patch.object(UvcCapture, "approve", side_effect=ValueError("synthetic")):
            code, stdout, stderr = self.run_cli("approve", str(SOURCES[0]),
                                                self.label(self.camera))
        self.assertEqual((code, stdout), (2, ""))
        self.assertEqual(stderr.strip().splitlines()[-1],
                         f"{capture_admin.PROG}: refused: candidate_unavailable")
        # The session was released: the next start is not a recovery.
        self.assertIsNone(self.approved().session_token)

    def test_revoke_removes_the_approval_so_the_camera_can_move(self):
        value = support.configuration(Path(tempfile.mkdtemp(prefix="agent-capture-move-")))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0", "sources": [
            {"source_id": str(SOURCES[0]), "profile": "640x480@15/MJPG"},
            {"source_id": str(SOURCES[1]), "profile": "640x480@15/MJPG"}]}
        two = Settings.parse(value, code_root=Path("/nonexistent/code"))
        label = self.label(self.camera)
        self.assertEqual(self.run_cli("approve", str(SOURCES[0]), label, settings=two)[0], 0)
        code, _, stderr = self.run_cli("revoke", str(SOURCES[0]), typed="no", settings=two)
        self.assertIn("refused: owner_confirmation_declined", stderr)
        code, stdout, stderr = self.run_cli("revoke", str(SOURCES[0]), typed="REVOKE",
                                            settings=two)
        self.assertEqual(code, 0, stderr)
        self.assertIn(f"camera approval removed: source_id={SOURCES[0]}", stdout)
        self.assertIn("Type REVOKE to confirm", self.prompts[-1])
        self.assertEqual(self.run_cli("approve", str(SOURCES[1]), label, settings=two)[0], 0)
        code, _, stderr = self.run_cli("revoke", str(SOURCES[0]), typed="REVOKE", settings=two)
        self.assertIn("refused: source_not_approved", stderr)

    def test_a_latched_serial_stays_unapprovable_after_replacing_or_revoking(self):
        # PR #412 review: approve another camera, revoke, approve the latched
        # one again must still be refused.
        from media_capture_agent.uvc_approvals import ApprovalStore as Store
        store = Store(self.settings)
        try:
            token = store.start_session(SOURCES[0]).session_token
            store.save(SOURCES[0], self.camera, False, session_token=token,
                       serial_ambiguous=True, release=True)
        finally:
            store.close()
        other = evidence(2, serial="SYN-SERIAL-0002")
        self.assertIn("serial=latched", self.run_cli("candidates")[1])
        code, _, stderr = self.run_cli("approve", str(SOURCES[0]), self.label(other))
        self.assertEqual(code, 0, stderr)
        code, _, stderr = self.run_cli("revoke", str(SOURCES[0]), typed="REVOKE")
        self.assertEqual(code, 0, stderr)
        code, _, stderr = self.run_cli("approve", str(SOURCES[0]), self.label(self.camera))
        self.assertEqual(code, 2)
        self.assertIn("refused: camera_serial_not_unique", stderr)
        store = Store(self.settings)
        try:
            latched = store.latched_digests()
        finally:
            store.close()
        self.assertEqual(len(latched), 1)
        with open(self.settings.runtime_root / "uvc-latched-serials.json") as stream:
            self.assertNotIn("SYN-SERIAL", stream.read())

    def test_the_signal_mask_is_restored_after_an_unexpected_error(self):
        import signal
        from media_capture_agent.uvc_capture import UvcCapture
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        with patch.object(UvcCapture, "approve", side_effect=TypeError("synthetic")):
            with self.assertRaises(TypeError):
                self.run_cli("approve", str(SOURCES[0]), self.label(self.camera))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before)

    def test_signals_are_blocked_while_the_approval_is_written(self):
        import signal
        from media_capture_agent.uvc_capture import UvcCapture
        original = UvcCapture.approve
        seen = []

        def approve(capture, source, device):
            seen.append(signal.pthread_sigmask(signal.SIG_BLOCK, []))
            os.kill(os.getpid(), signal.SIGTERM)
            return original(capture, source, device)

        with patch.object(UvcCapture, "approve", approve):
            code, stdout, stderr = self.run_cli("approve", str(SOURCES[0]),
                                                self.label(self.camera))
        self.assertIn(signal.SIGTERM, seen[0])
        self.assertEqual(code, 0, stderr)
        self.assertIn("camera approved", stdout)
        self.assertEqual(self.approved().approved, self.camera)

    def test_a_concurrent_approval_for_another_source_is_seen_under_the_lock(self):
        # PR #412 review: the earlier snapshot is checked again after the prompt.
        value = support.configuration(Path(tempfile.mkdtemp(prefix="agent-capture-race-")))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0", "sources": [
            {"source_id": str(SOURCES[0]), "profile": "640x480@15/MJPG"},
            {"source_id": str(SOURCES[1]), "profile": "640x480@15/MJPG"}]}
        two = Settings.parse(value, code_root=Path("/nonexistent/code"))

        def confirm_while_another_approves(prompt):
            store = ApprovalStore(two)
            try:
                token = store.start_session(SOURCES[1]).session_token
                store.save(SOURCES[1], self.camera, False, session_token=token,
                           serial_ambiguous=False, release=True)
            finally:
                store.close()
            return "APPROVE"

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = capture_admin.main(
                ["approve", "--config", "/nonexistent", str(SOURCES[0]), self.label(self.camera)],
                settings_loader=lambda path: two, discovery=self.discovery,
                confirm=confirm_while_another_approves)
        self.assertEqual(code, 2)
        self.assertIn("refused: camera_approved_for_another_source", stderr.getvalue())

    def test_a_nested_cli_approval_for_another_source_is_seen_under_the_lock(self):
        # Codex P2 on PR #412 (3f63ee1): the other approval runs through the
        # real command while this one waits at its prompt.
        value = support.configuration(Path(tempfile.mkdtemp(prefix="agent-capture-nested-")))
        value["capture"] = {"gst_launch": "/usr/bin/gst-launch-1.0", "sources": [
            {"source_id": str(SOURCES[0]), "profile": "640x480@15/MJPG"},
            {"source_id": str(SOURCES[1]), "profile": "640x480@15/MJPG"}]}
        two = Settings.parse(value, code_root=Path("/nonexistent/code"))
        label = self.label(self.camera)
        nested = []

        def confirm_after_another_approval(prompt):
            if "for source " + str(SOURCES[0]) in prompt:
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    nested.append(capture_admin.main(
                        ["approve", "--config", "/nonexistent", str(SOURCES[1]), label],
                        settings_loader=lambda path: two, discovery=self.discovery,
                        confirm=lambda prompt: "APPROVE"))
            return "APPROVE"

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = capture_admin.main(
                ["approve", "--config", "/nonexistent", str(SOURCES[0]), label],
                settings_loader=lambda path: two, discovery=self.discovery,
                confirm=confirm_after_another_approval)
        self.assertEqual(nested, [0])
        self.assertEqual(code, 2, stdout.getvalue())
        self.assertIn("refused: camera_approved_for_another_source", stderr.getvalue())

    def test_ctrl_c_at_the_prompt_is_a_fixed_refusal(self):
        import signal

        def interrupted(prompt):
            os.kill(os.getpid(), signal.SIGINT)
            return "APPROVE"

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = capture_admin.main(
                ["approve", "--config", "/nonexistent", str(SOURCES[0]), self.label(self.camera)],
                settings_loader=lambda path: self.settings, discovery=self.discovery,
                confirm=interrupted)
        self.assertEqual(code, 2)
        self.assertIn("refused: interrupted", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertIsNone(self.approved())

    def test_the_confirmation_is_read_from_a_real_terminal(self):
        # Codex P1 on PR #412: a terminal is not seekable.
        import pty
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        os.write(master, b"APPROVE\n")
        word = capture_admin.read_confirmation("Type APPROVE: ", opener=lambda *_: slave)
        self.assertEqual(word, "APPROVE")
        # The echo and the prompt may arrive in separate reads (Codex P2).
        import select
        output, deadline = b"", time.monotonic() + 5
        while b"Type APPROVE: " not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                output += os.read(master, 1024)
        self.assertIn(b"Type APPROVE: ", output)
        not_a_terminal = os.open(os.devnull, os.O_RDWR)
        with self.assertRaises(capture_admin.AdminRefused):
            capture_admin.read_confirmation("x", opener=lambda *_: not_a_terminal)

    def test_a_same_serial_camera_connected_at_the_prompt_is_refused(self):
        # Codex P2 on PR #412.
        def confirm_and_plug_a_twin(prompt):
            self.discovery.devices = [self.camera, evidence(6, serial="SYN-SERIAL-0001")]
            return "APPROVE"

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = capture_admin.main(
                ["approve", "--config", "/nonexistent", str(SOURCES[0]), self.label(self.camera)],
                settings_loader=lambda path: self.settings, discovery=self.discovery,
                confirm=confirm_and_plug_a_twin)
        self.assertEqual(code, 2)
        self.assertIn("refused: camera_serial_not_unique", stderr.getvalue())
        state = self.approved()
        self.assertIsNone(state.approved)
        self.assertIsNone(state.session_token)

    def test_a_camera_without_a_serial_is_not_approved(self):
        self.discovery.devices = [evidence(4, serial=None)]
        code, _, stderr = self.run_cli("approve", str(SOURCES[0]),
                                       self.label(self.discovery.devices[0]))
        self.assertEqual(code, 2)
        self.assertIn("refused: camera_without_serial", stderr)

    def test_a_running_service_is_refused(self):
        held = ApprovalStore(self.settings)
        self.addCleanup(held.close)
        code, _, stderr = self.run_cli("candidates")
        self.assertEqual(code, 2)
        self.assertIn("refused: service_running", stderr)

    def test_root_other_accounts_and_missing_capture_are_refused(self):
        with patch.object(capture_admin.os, "geteuid", return_value=0):
            self.assertIn("run_as_service_account", self.run_cli("candidates")[2])
        with patch.object(capture_admin.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertIn("run_as_service_account", self.run_cli("candidates")[2])
        bare = Settings.parse(support.configuration(Path(tempfile.mkdtemp(
            prefix="agent-capture-bare-"))), code_root=Path("/nonexistent/code"))
        self.assertIn("capture_unconfigured", self.run_cli("candidates", settings=bare)[2])


if __name__ == "__main__":
    unittest.main()
