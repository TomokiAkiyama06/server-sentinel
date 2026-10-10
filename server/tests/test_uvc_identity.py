"""Synthetic identity/health transitions; no physical devices are opened."""

from dataclasses import replace
import threading
import unittest
from unittest import mock
from uuid import UUID

from app.cameras.uvc import identity
from app.cameras.uvc.identity import (
    CameraState, DeviceEvidence, ReconnectController, match_reconnect, same_physical_camera,
)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.camera = DeviceEvidence("/dev/video0", "synthetic-vendor", "synthetic-model", "synthetic-serial")
        self.events = []
        self.source_id = UUID(int=1)
        self.control = ReconnectController(self.source_id, self.camera, self.events.append)

    def test_serial_match_survives_device_number_and_usb_port_change(self):
        returned = replace(self.camera, device_path="/dev/video7", topology="synthetic-port-2")
        self.assertEqual(self.control.reconcile([returned]), returned)
        self.assertEqual(self.control.state, CameraState.DEGRADED)
        self.control.capture_ready(returned)
        self.assertEqual(self.control.state, CameraState.ONLINE)
        self.assertEqual(self.control.source_id, self.source_id)

    def test_other_serial_never_substitutes_even_same_path(self):
        other = replace(self.camera, serial="another-synthetic-serial")
        self.assertIsNone(self.control.reconcile([other]))
        self.assertEqual(self.control.state, CameraState.OFFLINE)

    def test_live_instance_comparison_ignores_mutable_metadata(self):
        live = replace(self.camera, device_number=3, instance_token=(1, 2, 3))
        refreshed = replace(live, by_id=("synthetic-alias",), formats=("MJPG",))
        reused = replace(live, instance_token=(1, 2, 4))
        weak = replace(live, serial=None)
        for ambiguous in (True, False):
            self.assertTrue(same_physical_camera(live, refreshed, serial_ambiguous=ambiguous))
        self.assertFalse(same_physical_camera(live, reused, serial_ambiguous=True))
        self.assertTrue(same_physical_camera(weak, replace(weak, by_id=("synthetic-alias",))))
        self.assertFalse(same_physical_camera(weak, replace(weak, instance_token=(1, 2, 4))))

    def test_capture_ready_accepts_refreshed_metadata_but_not_another_instance(self):
        weak = replace(self.camera, serial=None, instance_token=(1, 2, 3))
        self.control.approve(weak, [weak])
        refreshed = replace(weak, by_id=("synthetic-alias",), formats=("MJPG",))
        self.assertEqual(refreshed, self.control.reconcile([refreshed]))
        self.control.capture_ready(refreshed)
        self.assertEqual(self.control.state, CameraState.ONLINE)
        with self.assertRaises(ValueError):
            self.control.capture_ready(replace(weak, instance_token=(1, 2, 4)))
        twin = replace(weak, device_path="/dev/video1", instance_token=(5, 6, 7))
        with self.assertRaises(ValueError):
            self.control.capture_profile_unavailable(twin)

    def test_duplicate_serial_requires_owner_and_latches(self):
        other = replace(self.camera, device_path="/dev/video1")
        self.assertIsNone(self.control.reconcile([self.camera, other]))
        self.assertEqual(self.control.state, CameraState.MANUAL)
        self.assertIsNone(self.control.reconcile([self.camera]))
        with self.assertRaises(ValueError):
            self.control.capture_ready(self.camera)
        self.control.approve(self.camera, [self.camera])
        self.control.capture_ready(self.camera)
        self.assertEqual(self.control.state, CameraState.ONLINE)

    def test_nonserial_path_topology_by_id_do_not_prove_identity(self):
        weak = replace(self.camera, serial=None, topology="synthetic-port", by_id=("synthetic-usb-model",))
        for candidates in ([weak], [weak, replace(weak, device_path="/dev/video2")]):
            result = match_reconnect(weak, tuple(candidates))
            self.assertEqual(result.state, CameraState.MANUAL)
            self.assertIsNone(result.device)

    def test_disconnect_is_audited_and_other_source_survives(self):
        other_events = []
        other = ReconnectController(UUID(int=2), self.camera, other_events.append)
        for control in (self.control, other):
            control.reconcile([self.camera])
            control.capture_ready(self.camera)
        self.control.disconnected()
        self.assertEqual(self.events[-1].reason, "device_disconnected")
        self.assertEqual(self.control.state, CameraState.OFFLINE)
        self.assertEqual(other.state, CameraState.ONLINE)
        self.control.reconcile([self.camera])
        self.control.capture_ready(self.camera)
        self.assertEqual(self.control.state, CameraState.ONLINE)

    def test_stop_fence_between_ready_checks_cannot_be_overwritten_by_online(self):
        # Issue #194 / PR #201: a stop fence that lands after capture_ready's
        # checks began must never be overwritten by a late ``online``. The
        # fence runs in another thread exactly while capture_ready validates
        # the binding. It either takes the lock first (and capture_ready then
        # refuses) or times out while capture_ready holds the lock (and
        # capture_ready then lowers its own ``online`` and refuses); a
        # successful fence followed by ``online`` is the race.
        self.control.reconcile([self.camera])
        real = identity.same_live_instance
        fence = {}

        def interleave(first, second):
            if not fence:
                stopper = threading.Thread(
                    target=lambda: fence.setdefault("ok", self.control.fence_stopping(0.2)))
                stopper.start()
                stopper.join(5)
                fence["state"] = self.control.state
            return real(first, second)

        accepted = False
        with mock.patch.object(identity, "same_live_instance", interleave):
            try:
                self.control.capture_ready(self.camera)
                accepted = True
            except ValueError:
                pass
        self.assertIn("ok", fence)
        if fence["ok"]:
            self.assertEqual(CameraState.OFFLINE, fence["state"])
            self.assertFalse(accepted, "late capture_ready overwrote the stop fence")
        else:
            self.assertFalse(accepted, "late online survived a timed-out stop fence")
            self.assertTrue(self.control.fence_stopping(1.0))
        self.assertEqual(CameraState.OFFLINE, self.control.state)
        self.assertEqual("capture_service_stopping", self.events[-1].reason)
        with self.assertRaises(ValueError):
            self.control.capture_ready(self.camera)
        self.assertEqual(CameraState.OFFLINE, self.control.state)

    def _failing_handoff_start(self):
        original = threading.Thread.start

        def start(thread):
            if thread.name == "serversentinel-local-uvc-health-delivery":
                raise RuntimeError("synthetic: can't start new thread")
            return original(thread)

        return mock.patch.object(threading.Thread, "start", start)

    def _notifying_controller(self):
        notified = []
        control = ReconnectController(self.source_id, self.camera, self.events.append,
                                      notify=notified.append)
        control.reconcile([self.camera])
        control.capture_ready(self.camera)
        return control, notified

    def test_failed_handoff_start_keeps_final_event_queued_and_settle_delivers_it(self):
        # PR #201 (Codex): a failed handoff thread start used to mark the
        # delivery idle with the final offline event still queued, so the
        # stop's settle_delivery() succeeded and nothing ever delivered it.
        control, notified = self._notifying_controller()
        with self._failing_handoff_start():
            control.capture_closing()
            self.assertEqual(1, control.undelivered)
            self.assertGreaterEqual(control.delivery_start_failures, 1)
            self.assertNotIn("video_capture_closed", [event.reason for event in notified])
            # The retried start fails as well; the stopping caller then
            # delivers the queue itself, bounded by the timeout.
            self.assertTrue(control.settle_delivery(1.0))
        self.assertEqual("video_capture_closed", notified[-1].reason)
        self.assertEqual(0, control.undelivered)

    def test_settle_delivery_reports_an_event_it_cannot_deliver(self):
        control, notified = self._notifying_controller()
        with self._failing_handoff_start():
            control.capture_closing()
            # Delivery lock busy (another deliverer) and no thread: bounded.
            with control._delivery:
                self.assertFalse(control.settle_delivery(0.1))
                self.assertEqual(1, control.undelivered)
            self.assertTrue(control.settle_delivery(1.0))
        self.assertEqual("video_capture_closed", notified[-1].reason)

    def test_blocking_delivery_drains_events_a_failed_handoff_left(self):
        control, notified = self._notifying_controller()
        with self._failing_handoff_start():
            control.capture_closing()
        self.assertEqual(1, control.undelivered)
        control.disconnected()
        self.assertEqual(["video_capture_closed", "device_disconnected"],
                         [event.reason for event in notified[-2:]])
        self.assertEqual(0, control.undelivered)
        self.assertTrue(control.settle_delivery(0.0))

    def test_stop_fence_that_times_out_still_refuses_a_late_online(self):
        # PR #201 (Codex): a fence that cannot take the transition lock in
        # time (capture_ready inside a slow state callback) used to leave no
        # stop flag, so the late ``online`` stayed and later frames kept it.
        results = []

        def emit(event):
            self.events.append(event)
            if event.state is CameraState.ONLINE and not results:
                stopper = threading.Thread(
                    target=lambda: results.append(control.fence_stopping(0.05)))
                stopper.start()
                stopper.join(5)

        control = ReconnectController(self.source_id, self.camera, emit)
        control.reconcile([self.camera])
        with self.assertRaises(ValueError):
            control.capture_ready(self.camera)
        self.assertEqual([False], results)
        self.assertEqual(CameraState.OFFLINE, control.state)
        self.assertEqual("capture_service_stopping", self.events[-1].reason)
        with self.assertRaises(ValueError):
            control.capture_ready(self.camera)
        self.assertEqual(CameraState.OFFLINE, control.state)

    def test_disabled_and_failed_capture_never_report_healthy(self):
        self.control.reconcile([self.camera])
        self.control.capture_failed()
        with self.assertRaises(ValueError):
            self.control.capture_ready(self.camera)
        self.control.set_enabled(False)
        self.assertIsNone(self.control.reconcile([self.camera]))
        with self.assertRaises(ValueError):
            self.control.approve(self.camera, [self.camera])

    def test_approval_needs_exact_single_current_candidate(self):
        for candidates in ([], [self.camera, self.camera], [replace(self.camera, serial="changed")]):
            with self.assertRaises(ValueError):
                self.control.approve(self.camera, candidates)

    def test_event_and_repr_exclude_physical_device_values(self):
        self.control.reconcile([self.camera])
        for text in (repr(self.camera), repr(self.events[-1])):
            self.assertNotIn("synthetic-serial", text)
            self.assertNotIn("/dev/video0", text)


if __name__ == "__main__":
    unittest.main()
