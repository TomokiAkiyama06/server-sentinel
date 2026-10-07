import threading
import time
import unittest
from uuid import uuid4

from app.cameras.uvc.supervisor import LocalUvcSupervisor, WorkerStopError


def wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


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


class PausingLock:
    """Pause one thread before its second critical section."""

    def __init__(self):
        self.lock = threading.Lock()
        self.target = None
        self.target_acquires = 0
        self.first_released = threading.Event()
        self.second_entered = threading.Event()
        self.resume = threading.Event()

    def __enter__(self):
        if threading.current_thread() is self.target:
            self.target_acquires += 1
            if self.target_acquires == 2:
                self.second_entered.set()
                if not self.resume.wait(0.5):
                    raise RuntimeError("synthetic lock pause timed out")
        self.lock.acquire()
        return self

    def __exit__(self, *_args):
        self.lock.release()
        if (threading.current_thread() is self.target
                and self.target_acquires == 1):
            self.first_released.set()


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

    def test_stop_does_not_discard_concurrent_replacement_worker(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.2))

        lock = PausingLock()
        self.supervisor._lock = lock
        stopped = []
        stopper = threading.Thread(
            target=lambda: stopped.append(self.supervisor.stop(source)),
        )
        lock.target = stopper
        stopper.start()
        self.assertTrue(lock.first_released.wait(0.2))

        self.adapter.release[source].set()
        self.assertTrue(lock.second_entered.wait(0.2))
        self.adapter.prepare(source)
        self.assertTrue(self.supervisor.start(source))
        self.assertTrue(self.adapter.entered[source].wait(0.2))

        lock.resume.set()
        stopper.join(0.2)
        self.assertFalse(stopper.is_alive())
        self.assertEqual([True], stopped)
        self.assertTrue(self.supervisor.status(source).running)
        self.assertTrue(self.supervisor.stop(source))


class WatchedAdapter(SyntheticAdapter):
    """Adapter exposing the off-worker frame-progress check."""

    def __init__(self):
        super().__init__()
        self.checked = {}
        self.check_failures = 0
        self.checked_event = threading.Event()

    def check_frame_progress(self, source_id):
        with self.lock:
            self.checked[source_id] = self.checked.get(source_id, 0) + 1
            fail = self.check_failures > 0
            if fail:
                self.check_failures -= 1
        self.checked_event.set()
        if fail:
            raise RuntimeError("synthetic private detail")
        return False


class FrameProgressWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.adapter = WatchedAdapter()
        self.supervisor = LocalUvcSupervisor(
            self.adapter, poll_timeout=5.0, retry_delay=0.01, join_timeout=1.0,
            watchdog_interval=0.01,
        )
        self.addCleanup(self._close)

    def _close(self):
        for release in self.adapter.release.values():
            release.set()
        try:
            self.supervisor.close()
        except WorkerStopError:
            pass

    def test_watchdog_checks_a_source_while_its_worker_is_blocked(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.5))
        # The worker stays inside poll_source (a blocked kernel call); the
        # frame-progress check still runs from the supervisor watchdog.
        deadline = time.monotonic() + 2
        while self.adapter.checked.get(source, 0) < 3 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertGreaterEqual(self.adapter.checked.get(source, 0), 3)
        self.assertEqual(1, self.adapter.calls[source])

    def test_watchdog_keeps_checking_a_worker_whose_stop_timed_out(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.5))
        with self.assertRaises(WorkerStopError):
            self.supervisor.stop(source)
        self.assertTrue(self.supervisor.status(source).running)
        count = self.adapter.checked.get(source, 0)
        deadline = time.monotonic() + 2
        while self.adapter.checked.get(source, 0) < count + 3 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertGreaterEqual(self.adapter.checked.get(source, 0), count + 3)
        # Once the worker actually exits it is no longer checked. A second,
        # live source paces the watchdog: once it has been checked twice
        # more, at least one full watchdog pass ran after the exit.
        other = uuid4()
        self.adapter.prepare(other)
        self.supervisor.start(other)
        self.adapter.release[source].set()
        self.assertTrue(wait_until(lambda: not self.supervisor.status(source).running))
        count = self.adapter.checked.get(source, 0)
        paced = self.adapter.checked.get(other, 0)
        self.assertTrue(wait_until(lambda: self.adapter.checked.get(other, 0) >= paced + 2))
        self.assertEqual(count, self.adapter.checked.get(source, 0))

    def test_watchdog_failure_is_contained_and_counted_without_text(self):
        source = uuid4()
        self.adapter.check_failures = 2
        self.adapter.prepare(source)
        self.supervisor.start(source)
        deadline = time.monotonic() + 2
        while self.adapter.checked.get(source, 0) < 4 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertGreaterEqual(self.adapter.checked.get(source, 0), 4)
        self.assertEqual(2, self.supervisor.watchdog_failures)
        self.assertTrue(self.supervisor.status(source).running)

    def test_close_stops_the_watchdog(self):
        source = uuid4()
        self.adapter.prepare(source)
        self.supervisor.start(source)
        self.assertTrue(self.adapter.checked_event.wait(1))
        self.adapter.release[source].set()
        self.supervisor.close()
        self.assertFalse(self.supervisor.watchdog_running)
        count = dict(self.adapter.checked)
        time.sleep(0.05)
        self.assertEqual(count, self.adapter.checked)

    def test_close_keeps_watching_a_worker_that_did_not_stop(self):
        # Issue #122: close() must not stop the watchdog before the workers
        # are joined. A worker blocked in a kernel call past the join bound
        # stays registered and must remain watched, or its source keeps an
        # online claim although it delivers no frames.
        supervisor = LocalUvcSupervisor(
            self.adapter, poll_timeout=5.0, retry_delay=0.01, join_timeout=0.05,
            watchdog_interval=0.01,
        )
        self.addCleanup(self._close_other, supervisor)
        source = uuid4()
        self.adapter.prepare(source)
        supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.5))
        with self.assertRaisesRegex(WorkerStopError, "did not stop"):
            supervisor.close()
        self.assertTrue(supervisor.status(source).running)
        self.assertTrue(supervisor.watchdog_running)
        count = self.adapter.checked.get(source, 0)
        self.assertTrue(wait_until(lambda: self.adapter.checked.get(source, 0) >= count + 3))
        # A closed supervisor never starts another worker.
        with self.assertRaisesRegex(WorkerStopError, "closed"):
            supervisor.start(uuid4())
        # Once the blocked call returns, the worker exits and the watchdog
        # exits on its own: nothing is left that it must report.
        self.adapter.release[source].set()
        self.assertTrue(wait_until(lambda: not supervisor.status(source).running))
        self.assertTrue(wait_until(lambda: not supervisor.watchdog_running))
        # A repeated close joins the exited worker and succeeds.
        supervisor.close()
        self.assertIsNone(supervisor.status(source))
        self.assertEqual([source], self.adapter.stopped)

    def test_repeated_close_stops_the_watchdog_after_joining(self):
        supervisor = LocalUvcSupervisor(
            self.adapter, poll_timeout=5.0, retry_delay=0.01, join_timeout=0.05,
            watchdog_interval=0.01,
        )
        self.addCleanup(self._close_other, supervisor)
        source = uuid4()
        self.adapter.prepare(source)
        supervisor.start(source)
        self.assertTrue(self.adapter.entered[source].wait(0.5))
        with self.assertRaises(WorkerStopError):
            supervisor.close()
        with self.assertRaises(WorkerStopError):
            supervisor.close()
        # Still blocked after the second timed-out close: still watched.
        self.assertTrue(supervisor.watchdog_running)
        self.adapter.release[source].set()
        self.assertTrue(wait_until(lambda: not supervisor.status(source).running))
        supervisor.close()
        self.assertTrue(wait_until(lambda: not supervisor.watchdog_running))

    def _close_other(self, supervisor):
        for release in self.adapter.release.values():
            release.set()
        try:
            supervisor.close()
        except WorkerStopError:
            pass

    def test_adapter_without_check_starts_no_watchdog(self):
        supervisor = LocalUvcSupervisor(SyntheticAdapter(), watchdog_interval=0.01)
        source = uuid4()
        supervisor.start(source)
        self.assertFalse(supervisor.watchdog_running)
        supervisor._adapter.release[source].set()
        supervisor.close()


if __name__ == "__main__":
    unittest.main()
