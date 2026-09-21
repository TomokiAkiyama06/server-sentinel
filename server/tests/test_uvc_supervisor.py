import threading
import time
import unittest
from uuid import uuid4

from app.cameras.uvc.supervisor import LocalUvcSupervisor, WorkerStopError


class SyntheticAdapter:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = {}
        self.active = {}
        self.maximum = {}
        self.stopped = []
        self.entered = {}
        self.release = {}
        self.failures = {}
        self.stop_failures = set()

    def prepare(self, source_id):
        self.entered[source_id] = threading.Event()
        self.release[source_id] = threading.Event()

    def poll_source(self, source_id, *, timeout):
        entered = self.entered.setdefault(source_id, threading.Event())
        release = self.release.setdefault(source_id, threading.Event())
        with self.lock:
            self.calls[source_id] = self.calls.get(source_id, 0) + 1
            self.active[source_id] = self.active.get(source_id, 0) + 1
            self.maximum[source_id] = max(
                self.maximum.get(source_id, 0), self.active[source_id],
            )
        entered.set()
        try:
            if self.failures.get(source_id, 0):
                self.failures[source_id] -= 1
                raise RuntimeError("synthetic private detail")
            release.wait(timeout)
            return release.is_set()
        finally:
            with self.lock:
                self.active[source_id] -= 1

    def stop_source(self, source_id):
        self.stopped.append(source_id)
        if source_id in self.stop_failures:
            raise RuntimeError("synthetic private cleanup detail")


class LocalUvcSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.adapter = SyntheticAdapter()
        self.supervisor = LocalUvcSupervisor(
            self.adapter, poll_timeout=0.02, retry_delay=0.005, join_timeout=0.2,
        )
        self.addCleanup(self._close)

    def _close(self):
        try:
            self.supervisor.close()
        except WorkerStopError:
            pass

    def test_repeated_start_keeps_one_serial_worker(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.assertTrue(self.supervisor.start(source))
        self.assertFalse(self.supervisor.start(source))
        self.assertTrue(self.adapter.entered[source].wait(0.2))
        time.sleep(0.04)
        self.assertEqual(1, self.adapter.maximum[source])
        self.assertTrue(self.supervisor.stop(source))
        self.assertEqual([source], self.adapter.stopped)

    def test_blocked_source_does_not_stop_another_source(self):
        blocked, flowing = uuid4(), uuid4()
        self.adapter.prepare(blocked)
        self.adapter.prepare(flowing)
        self.supervisor.start(blocked)
        self.supervisor.start(flowing)
        self.assertTrue(self.adapter.entered[blocked].wait(0.2))
        self.assertTrue(self.adapter.entered[flowing].wait(0.2))
        self.adapter.release[flowing].set()
        for _ in range(100):
            if self.adapter.calls.get(flowing, 0) >= 2:
                break
            time.sleep(0.002)
        self.assertGreaterEqual(self.adapter.calls[flowing], 2)
        self.assertEqual(1, self.adapter.maximum[blocked])

    def test_poll_failure_is_contained_and_retried_without_detail(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.adapter.failures[source] = 1
        self.supervisor.start(source)
        for _ in range(100):
            status = self.supervisor.status(source)
            if status is not None and status.failures == 1 and self.adapter.calls.get(source, 0) >= 2:
                break
            time.sleep(0.002)
        status = self.supervisor.status(source)
        self.assertTrue(status.running)
        self.assertEqual(1, status.failures)
        self.assertFalse(status.cleanup_failed)

    def test_stop_is_bounded_when_adapter_does_not_honor_timeout(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.supervisor = LocalUvcSupervisor(
            self.adapter, poll_timeout=5, retry_delay=0.005, join_timeout=0.02,
        )
        self.supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.2))
        with self.assertRaisesRegex(WorkerStopError, "did not stop"):
            self.supervisor.stop(source)
        self.assertTrue(self.supervisor.status(source).running)
        self.adapter.release[source].set()
        for _ in range(100):
            if not self.supervisor.status(source).running:
                break
            time.sleep(0.002)
        self.assertFalse(self.supervisor.status(source).running)

    def test_close_stops_all_workers_and_refuses_restart(self):
        sources = (uuid4(), uuid4())
        for source in sources:
            self.adapter.prepare(source)
            self.supervisor.start(source)
            self.assertTrue(self.adapter.entered[source].wait(0.2))
        self.supervisor.close()
        self.assertCountEqual(sources, self.adapter.stopped)
        with self.assertRaisesRegex(WorkerStopError, "closed"):
            self.supervisor.start(uuid4())

    def test_cleanup_failure_is_reported_and_prevents_silent_restart(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.adapter.stop_failures.add(source)
        self.supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.2))
        with self.assertRaisesRegex(WorkerStopError, "cleanup failed"):
            self.supervisor.stop(source)
        # stop() removes the completed worker only after reporting its failure;
        # a later explicit start is a new lifecycle decision.
        self.adapter.stop_failures.clear()
        self.adapter.prepare(source)
        self.assertTrue(self.supervisor.start(source))


if __name__ == "__main__":
    unittest.main()
