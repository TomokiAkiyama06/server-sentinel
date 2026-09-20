"""Failure/cadence orchestration with synthetic recorder adapters only."""

from unittest import TestCase

from app.media.health.service import HealthState, PipelineStatus, RecordingHealthService, Stage


class FakeRecorder:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.status = PipelineStatus((True,), True, True)
        self.health = ("OK",)
        self.leftover = False

    def call(self, stage):
        self.calls.append(stage)
        if self.fail == stage:
            raise OSError("synthetic-sensitive-device-value")

    def cleanup(self):
        self.call("cleanup")
        self.leftover = False

    def pipeline_status(self):
        self.call("pipeline")
        return self.status

    def check_storage(self):
        self.call("storage")

    def write_test_segment(self):
        self.leftover = True
        self.call("write")

    def reopen_and_decode(self):
        self.call("decode")

    def storage_health(self):
        self.call("health")
        return self.health


class RecordingHealthTests(TestCase):
    def setUp(self):
        self.adapter = FakeRecorder()
        self.recorded = []
        self.clock = [0.0]
        self.service = RecordingHealthService(self.adapter, lambda *args: self.recorded.append(args),
                                              monotonic=lambda: self.clock[0])

    def test_order_and_cleanup_after_success(self):
        self.assertEqual(self.service.startup().state, HealthState.OK)
        self.assertEqual(self.adapter.calls, ["cleanup", "pipeline", "storage", "write", "decode", "cleanup", "health"])
        self.assertFalse(self.adapter.leftover)

    def test_each_write_validation_failure_cleanup_and_sanitized_result(self):
        for operation, stage in (("storage", Stage.STORAGE), ("write", Stage.WRITE), ("decode", Stage.REOPEN_DECODE)):
            with self.subTest(operation=operation):
                self.adapter.fail = operation
                result = self.service.startup()
                self.assertEqual(result.state, HealthState.FAILED)
                self.assertIn(stage, result.stages)
                self.assertFalse(self.adapter.leftover)
                self.assertNotIn("sensitive", str(self.recorded))

    def test_missing_fresh_frames_never_writes(self):
        for sources in ((False,), (None,), (), (True, True, True, True, True)):
            self.adapter.status = PipelineStatus(sources, True, True)
            self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.assertNotIn("write", self.adapter.calls)

    def test_dead_recorder_or_encoder_never_writes(self):
        for status in (PipelineStatus((True,), False, True), PipelineStatus((True,), True, False)):
            self.adapter.status = status
            self.assertIn(Stage.PIPELINE, self.service.startup().stages)
        self.assertNotIn("write", self.adapter.calls)

    def test_cleanup_failure_blocks_daily_artifact_accumulation(self):
        self.adapter.leftover = True
        self.adapter.fail = "cleanup"
        self.service.startup()
        self.clock[0] += 86400
        result = self.service.tick()
        self.assertEqual(result.state, HealthState.FAILED)
        self.assertIn(Stage.CLEANUP, result.stages)
        self.assertNotIn("write", self.adapter.calls)
        self.assertTrue(self.adapter.leftover)
        self.adapter.fail = None
        self.service.startup()
        self.assertFalse(self.adapter.leftover)

    def test_process_cancellation_cleans_and_reports_then_propagates(self):
        def cancel():
            self.adapter.leftover = True
            raise KeyboardInterrupt()
        self.adapter.write_test_segment = cancel
        with self.assertRaises(KeyboardInterrupt):
            self.service.startup()
        self.assertFalse(self.adapter.leftover)
        self.assertEqual(self.recorded[-1][0].state, HealthState.FAILED)
        self.assertNotIn("health", self.adapter.calls)

    def test_device_health_cancellation_records_failure_before_propagating(self):
        for exception in (KeyboardInterrupt, SystemExit):
            self.recorded.clear()
            def cancel():
                raise exception()
            self.adapter.storage_health = cancel
            with self.assertRaises(exception):
                self.service.startup()
            self.assertFalse(self.adapter.leftover)
            self.assertEqual(self.recorded[-1][0].state, HealthState.FAILED)
            self.assertEqual(self.recorded[-1][0].stages, (Stage.DEVICE_HEALTH,))
            self.assertIsNone(self.service._last_check)

    def test_final_cleanup_cancellation_records_failure_without_another_probe(self):
        cleanup = self.adapter.cleanup
        calls = []
        def cancel_final_cleanup():
            calls.append(True)
            if len(calls) == 2:
                raise KeyboardInterrupt()
            cleanup()
        self.adapter.cleanup = cancel_final_cleanup
        with self.assertRaises(KeyboardInterrupt):
            self.service.startup()
        self.assertEqual(self.recorded[-1][0].state, HealthState.FAILED)
        self.assertEqual(self.recorded[-1][0].stages, (Stage.CLEANUP,))
        self.assertNotIn("health", self.adapter.calls)
        self.assertTrue(self.adapter.leftover)

    def test_smart_critical_and_unavailable_never_healthy(self):
        self.adapter.health = ("CRITICAL",)
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        self.adapter.health = ("CRITICAL", "UNVERIFIABLE")
        self.assertEqual(self.service.startup().state, HealthState.FAILED)
        for value in ((), ("UNVERIFIABLE",), ("unexpected",)):
            self.adapter.health = value
            self.assertEqual(self.service.startup().state, HealthState.UNAVAILABLE)

    def test_no_codec_adapter_reports_unavailable(self):
        self.service.adapter = None
        result = self.service.startup()
        self.assertEqual(result.state, HealthState.UNAVAILABLE)
        self.assertEqual(result.stages, (Stage.ADAPTER,))

    def test_cadence_and_restart(self):
        self.service.startup()
        self.clock[0] = 86399
        self.assertIsNone(self.service.tick())
        self.clock[0] = 86400
        self.assertIsNotNone(self.service.tick())
        self.service.startup()
        self.assertEqual(len(self.recorded), 3)

    def test_local_fault_record_failure_is_not_swallowed(self):
        def unavailable(*args):
            raise OSError("local-store-unavailable")
        self.service.record_result = unavailable
        with self.assertRaises(OSError):
            self.service.startup()
        self.assertIsNone(self.service._last_check)
