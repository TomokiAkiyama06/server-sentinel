"""Hardware-free Agent ring scenarios on a synthetic clock and quota.

The production ``DiskRing`` and ``MediaStore`` run against an ephemeral
private directory. Segment bytes are generated opaque placeholders, never
camera media, and every scenario runs with outbound networking refused.
"""

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import threading
import unittest
from uuid import UUID

from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import (DenyControls, POST, PRE, RETENTION, SECOND,
                                            RingConfig, RingRefused, SegmentProfile)
from media_capture_agent.storage import MediaStore

from tests.e2e.harness import (
    AllowRingControls,
    NetworkGuard,
    SyntheticClock,
    SyntheticQuota,
    agent_configuration,
    agent_settings,
    REQUIRE_FULL_COVERAGE,
)


NODE = UUID(int=300)
MINUTE = 60 * SECOND
# Generated filler near the bounded profile size (6100 bytes per 60 s segment).
PAYLOAD = b"synthetic-compressed-segment" * 200
LEDGER_BYTES = 16 * 1024 * 1024


def sources(count):
    return tuple(UUID(int=400 + index) for index in range(count))


class AgentFixtureUidTests(unittest.TestCase):
    """Every Agent fixture refuses UID 0 the same way, before touching disk."""

    def test_root_skips_locally_and_fails_where_full_coverage_is_required(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "agent"
            for required, raised in (("", unittest.SkipTest), ("1", AssertionError)):
                with self.subTest(required=required), \
                        mock.patch.dict("os.environ", {REQUIRE_FULL_COVERAGE: required}), \
                        mock.patch("os.geteuid", return_value=0):
                    with self.assertRaises(raised) as caught:
                        agent_settings(root, NODE)
                    self.assertIn("UID 0", str(caught.exception))
                    with self.assertRaises(raised):
                        agent_configuration(root, NODE)
                    self.assertFalse(root.exists())
            # A non-root run still builds the fixture.
            if os.geteuid() != 0:
                with mock.patch.dict("os.environ", {REQUIRE_FULL_COVERAGE: "1"}):
                    self.assertEqual(agent_settings(root, NODE).media_root, root / "media")


class RingScenario(unittest.TestCase):
    """Shared wiring: one Agent node, 1-4 video sources, 60 s segments."""

    source_count = 2

    def setUp(self):
        self.network = NetworkGuard().__enter__()
        self.addCleanup(self.network.__exit__)
        self.addCleanup(lambda: self.assertEqual([], self.network.attempts))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        # Anchor far enough from the epoch that T-10 minutes is positive.
        self.t0 = self.clock.now_us()
        self.build(self.source_count)

    def build(self, count, *, ledger_bytes=LEDGER_BYTES, name="agent"):
        self.settings = agent_settings(self.root / name, NODE)
        self.quota = SyntheticQuota(self.settings.media_root)
        self.store = MediaStore(self.settings, space=self.quota,
                                stable_device=lambda _expected: True)
        self.addCleanup(self.store.close)
        self.ledger_bytes = ledger_bytes
        self.open_ring()
        self.sources = sources(count)
        self.profiles = tuple(SegmentProfile(source, 800, 400, MINUTE, 100)
                              for source in self.sources)

    def open_ring(self):
        # Every ring (including rebuilt and restarted ones) closes its own
        # ledger; a late-bound ``self.ring`` cleanup would leak earlier ones.
        self.ring = DiskRing(self.settings, self.store, ledger_maximum_bytes=self.ledger_bytes,
                             authority=AllowRingControls())
        self.addCleanup(self.ring.close)

    def restart(self):
        self.ring.close()
        self.open_ring()

    def configure(self, mode="duration", value=600, *, at=None):
        return self.ring.configure(RingConfig(mode, value), self.profiles,
                                   now_us=self.t0 if at is None else at, clock_trusted=True)

    def capture(self, start, end, *, skip=()):
        """Append one segment per source per minute; ``skip`` holds (source, start)."""
        for begin in range(start, end, MINUTE):
            for source in self.sources:
                if (source, begin) in skip:
                    continue
                self.ring.append(source, begin, begin + MINUTE, PAYLOAD,
                                 now_us=begin + MINUTE, clock_trusted=True)

    def connect(self, at):
        return self.ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                            now_us=at, clock_trusted=True)

    def lose(self, at):
        return self.ring.observe_connection(authenticated=True, connected=False, unexpected=True,
                                            now_us=at, clock_trusted=True)

    def status(self, at, *, trusted=True):
        return self.ring.status(now_us=at, clock_trusted=trusted)

    def estimate(self, duration):
        unit = self.store.allocation_unit
        return sum(profile.bytes_for(duration, unit) for profile in self.profiles)

    def count(self, table):
        return self.ring.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


class DurationModeLifecycleTests(RingScenario):
    def test_loss_pins_t_minus_10_continues_t_plus_10_across_reconnect_and_expires_at_60_days(self):
        for count in (1, 4):
            with self.subTest(sources=count):
                if count != self.source_count:
                    self.build(count, name=f"agent-{count}")
                self.assert_duration_lifecycle(count)

    def assert_duration_lifecycle(self, count):
        t0 = self.t0
        self.configure(at=t0 - 2 * PRE)
        self.capture(t0 - 2 * PRE, t0)
        # The selected 600 s FIFO keeps exactly ten segments per source.
        self.assertEqual(10 * count, len(self.store.list_segments()))
        ready = self.status(t0)
        self.assertEqual(("healthy", "protection_ready"), (ready["state"], ready["reason"]))

        self.connect(t0)
        incident = self.lose(t0)
        self.assertIsInstance(incident, UUID)
        active = self.ring.incident(incident, now_us=t0)
        self.assertEqual(("main_connection_lost", "active"),
                         (active["trigger_reason"], active["state"]))
        self.assertEqual((t0 - PRE, t0 + POST), (active["started_at_us"], active["target_end_us"]))

        # Autonomous continuation while Main is unreachable. The Agent
        # restarts mid-window (T+3) and must restore the still-active
        # incident and keep protecting the rest of T+10.
        self.capture(t0, t0 + 3 * MINUTE)
        self.restart()
        restored = self.ring.incident(incident, now_us=t0 + 3 * MINUTE)
        self.assertEqual(("active", t0 + POST), (restored["state"], restored["target_end_us"]))
        self.assertEqual(1, self.count("incidents"))
        # Then reconnect half-way through T+10. Reconnect neither ends nor
        # duplicates it.
        self.capture(t0 + 3 * MINUTE, t0 + 5 * MINUTE)
        self.assertIsNone(self.connect(t0 + 5 * MINUTE))
        self.capture(t0 + 5 * MINUTE, t0 + POST)
        self.assertEqual(1, self.count("incidents"))

        complete = self.ring.incident(incident, now_us=t0 + POST)
        self.assertEqual("complete", complete["state"])
        self.assertFalse(complete["has_gaps"])
        self.assertEqual({str(source): [(t0 - PRE, t0 + POST)] for source in self.sources},
                         {key: value["intervals_us"] for key, value in complete["coverage"].items()})
        self.assertEqual(t0 + POST + RETENTION, complete["expires_at_us"])
        self.assertEqual(60 * 86400 * SECOND, RETENTION)

        # Ordinary FIFO keeps running without touching the protected window.
        later = t0 + POST + 15 * MINUTE
        self.capture(t0 + POST, later)
        self.assertEqual(20 * count + 10 * count, len(self.store.list_segments()))
        self.restart()
        retained = self.ring.incident(incident, now_us=later)
        self.assertEqual(("complete", False), (retained["state"], retained["has_gaps"]))
        self.assertEqual(complete["allocated_bytes"],
                         self.status(later)["protected_allocated_bytes"])

        expiry = complete["expires_at_us"]
        self.ring.tick(now_us=expiry - 1, clock_trusted=True)
        self.assertEqual("complete", self.ring.incident(incident, now_us=expiry - 1)["state"])
        # An uncertain clock never authorizes the 60-day deletion.
        self.ring.tick(now_us=expiry, clock_trusted=False)
        self.assertEqual("complete", self.ring.incident(incident, now_us=expiry)["state"])
        self.ring.tick(now_us=expiry, clock_trusted=True)
        self.assertEqual("deleted", self.ring.incident(incident, now_us=expiry)["state"])
        self.assertEqual({}, self.store.list_segments())
        self.assertEqual(0, self.quota.used())


class CapacityModeLifecycleTests(RingScenario):
    def test_capacity_fifo_bounds_ordinary_bytes_while_protection_survives_and_owner_deletes(self):
        t0 = self.t0
        limit = self.estimate(PRE)
        self.configure("capacity", limit, at=t0 - 2 * PRE)
        # Sample status every five minutes: each capacity-mode status call
        # re-verifies the mount many times, so per-minute sampling is slow.
        for begin in range(t0 - 2 * PRE, t0, 5 * MINUTE):
            self.capture(begin, begin + 5 * MINUTE)
            self.assertLessEqual(self.status(begin + 5 * MINUTE)["ordinary_allocated_bytes"], limit)
        ready = self.status(t0)
        self.assertEqual("healthy", ready["state"])
        self.assertGreaterEqual(ready["estimated_duration_us"], PRE)
        self.assertFalse(any(item["gaps_us"] for item in ready["pre_loss_coverage"].values()))

        self.connect(t0)
        incident = self.lose(t0)
        self.capture(t0, t0 + POST)
        complete = self.ring.incident(incident, now_us=t0 + POST)
        self.assertEqual(("complete", False), (complete["state"], complete["has_gaps"]))
        # Protected bytes are outside the ordinary capacity limit.
        self.assertGreater(complete["allocated_bytes"], limit)

        later = t0 + POST + 2 * PRE
        for begin in range(t0 + POST, later, 5 * MINUTE):
            self.capture(begin, begin + 5 * MINUTE)
            status = self.status(begin + 5 * MINUTE)
            self.assertLessEqual(status["ordinary_allocated_bytes"], limit)
            self.assertEqual(complete["allocated_bytes"], status["protected_allocated_bytes"])

        # Owner deletion is an authorized control, refused by default.
        self.ring.authority = DenyControls()
        with self.assertRaisesRegex(RingRefused, "owner_authorization_required"):
            self.ring.delete_incident(incident, now_us=later, clock_trusted=True)
        self.assertEqual("complete", self.ring.incident(incident, now_us=later)["state"])
        self.ring.authority = AllowRingControls()
        self.ring.delete_incident(incident, now_us=later, clock_trusted=True)
        self.assertEqual("deleted", self.ring.incident(incident, now_us=later)["state"])
        after = self.status(later)
        self.assertEqual(0, after["protected_allocated_bytes"])
        self.assertLessEqual(after["ordinary_allocated_bytes"], limit)
        self.assertFalse(any(item["gaps_us"] for item in after["pre_loss_coverage"].values()))


class RealScaleCapacityModeTests(RingScenario):
    """Capacity mode at a realistic profile with a small explicit ledger cap.

    Two sources at a 4 Mbit/s bound and 10 s segments need about 620 MB for
    the bounded ten-minute pre-loss window. Only the byte counters are
    synthetic; segment payloads stay small generated placeholders.
    """

    ledger = 32 * 1024 * 1024

    def build(self, count, *, ledger_bytes=None, name="agent"):
        super().build(count, ledger_bytes=self.ledger, name=name)
        self.ring.close()
        self.store.close()
        self.settings = replace(self.settings, max_segment_bytes=8 * 1024 * 1024)
        self.quota = SyntheticQuota(self.settings.media_root, capacity=8 * 1024 ** 3)
        self.store = MediaStore(self.settings, space=self.quota,
                                stable_device=lambda _expected: True)
        self.addCleanup(self.store.close)
        self.open_ring()
        self.profiles = tuple(SegmentProfile(source, 4_000_000, 4_000_000, 10 * SECOND, 0)
                              for source in self.sources)

    def capture_every(self, start, end, step=10 * SECOND):
        for begin in range(start, end, step):
            for source in self.sources:
                self.ring.append(source, begin, begin + step, PAYLOAD,
                                 now_us=begin + step, clock_trusted=True)

    def test_700_mib_capacity_is_admitted_and_protects_t_minus_10_t_plus_10(self):
        t0 = self.t0
        # Journal/database headroom stays proportional to the 32 MiB cap.
        self.assertLess(self.ring.ledger_headroom, 2 * self.ledger + 512 * 1024)
        with self.assertRaisesRegex(RingRefused, "insufficient_pre_loss_capacity"):
            self.configure("capacity", 500 * 1024 * 1024, at=t0 - PRE - 2 * MINUTE)
        ready = self.configure("capacity", 700 * 1024 * 1024, at=t0 - PRE - 2 * MINUTE)
        self.assertEqual("capacity", ready["mode"])
        self.assertGreaterEqual(ready["estimated_duration_us"], PRE)
        self.assertGreaterEqual(ready["capacity_horizon_us"], ready["estimated_duration_us"])
        self.assertLessEqual(ready["ledger_required_bytes"], self.ledger)

        self.capture_every(t0 - PRE - 2 * MINUTE, t0)
        status = self.status(t0)
        self.assertEqual(("healthy", "protection_ready"), (status["state"], status["reason"]))
        self.connect(t0)
        incident = self.lose(t0)
        self.capture_every(t0, t0 + POST)
        complete = self.ring.incident(incident, now_us=t0 + POST)
        self.assertEqual(("complete", False), (complete["state"], complete["has_gaps"]))
        self.assertEqual({str(source): [(t0 - PRE, t0 + POST)] for source in self.sources},
                         {key: value["intervals_us"] for key, value in complete["coverage"].items()})
        after = self.status(t0 + POST)
        self.assertLessEqual(after["ordinary_allocated_bytes"], 700 * 1024 * 1024)
        self.assertLessEqual(after["ledger_required_bytes"], self.ledger)


class PartialGapAndPreserveTests(RingScenario):
    def test_missing_pre_and_post_segments_are_reported_as_partial_gaps(self):
        t0 = self.t0
        first, second = self.sources
        self.configure()
        self.capture(t0 - PRE, t0, skip={(first, t0 - 3 * MINUTE)})
        self.connect(t0)
        incident = self.lose(t0)
        # The second camera stalls for two minutes of T+10.
        self.capture(t0, t0 + POST, skip={(second, t0 + 2 * MINUTE), (second, t0 + 3 * MINUTE)})
        result = self.ring.incident(incident, now_us=t0 + POST)
        self.assertEqual("partial", result["state"])
        self.assertTrue(result["has_gaps"])
        self.assertEqual([(t0 - 3 * MINUTE, t0 - 2 * MINUTE)],
                         result["coverage"][str(first)]["gaps_us"])
        self.assertEqual([(t0 + 2 * MINUTE, t0 + 4 * MINUTE)],
                         result["coverage"][str(second)]["gaps_us"])
        status = self.status(t0 + POST)
        self.assertEqual(("degraded", "protected_incident_partial"),
                         (status["state"], status["reason"]))

    def test_critical_preserve_shares_segments_and_owner_delete_keeps_the_other_incident(self):
        t0 = self.t0
        self.configure()
        self.capture(t0 - PRE, t0)
        self.ring.authority = DenyControls()
        with self.assertRaisesRegex(RingRefused, "authenticated_preserve_required"):
            self.ring.preserve("camera_tamper", t0 - PRE, t0 + POST, now_us=t0, clock_trusted=True)
        self.ring.authority = AllowRingControls()
        with self.assertRaisesRegex(RingRefused, "invalid_preservation_reason"):
            self.ring.preserve("person", t0 - PRE, t0 + POST, now_us=t0, clock_trusted=True)

        self.connect(t0)
        loss = self.lose(t0)
        tamper = self.ring.preserve("camera_tamper", t0 - PRE, t0 + POST,
                                    now_us=t0, clock_trusted=True)
        self.capture(t0, t0 + POST)
        one = self.ring.incident(loss, now_us=t0 + POST)
        two = self.ring.incident(tamper, now_us=t0 + POST)
        self.assertEqual(("complete", "complete"), (one["state"], two["state"]))
        self.assertEqual("camera_tamper", two["trigger_reason"])
        # Shared segments are stored and counted once.
        self.assertEqual(20 * len(self.sources), self.count("segments"))
        self.assertEqual(one["allocated_bytes"], two["allocated_bytes"])
        self.assertEqual(one["allocated_bytes"],
                         self.status(t0 + POST)["protected_allocated_bytes"])

        self.ring.delete_incident(loss, now_us=t0 + POST, clock_trusted=True)
        kept = self.ring.incident(tamper, now_us=t0 + POST)
        self.assertEqual(("complete", False), (kept["state"], kept["has_gaps"]))
        self.assertEqual(kept["allocated_bytes"], self.quota.used())
        self.ring.delete_incident(tamper, now_us=t0 + POST, clock_trusted=True)
        # The ordinary FIFO still owns the latest ten minutes.
        self.assertEqual(10 * len(self.sources), len(self.store.list_segments()))


class SimultaneousBudgetAdmissionTests(RingScenario):
    source_count = 1

    def test_exact_pre_plus_post_budget_is_accepted_and_pre_only_budget_is_rejected(self):
        headroom = self.ring.ledger_headroom
        reserve = self.settings.safety_reserve_bytes
        self.quota.capacity = self.estimate(PRE) + reserve + headroom
        with self.assertRaisesRegex(RingRefused, "insufficient_simultaneous_pre_post_budget"):
            self.configure()
        self.assertIsNone(self.ring.config)
        self.quota.capacity = self.estimate(PRE + POST) + reserve + headroom - 1
        with self.assertRaisesRegex(RingRefused, "insufficient_simultaneous_pre_post_budget"):
            self.configure()
        self.quota.capacity += 1
        self.configure()
        self.assertEqual("duration", self.ring.config.mode)

    def test_buffered_pre_is_credited_once_and_later_headroom_loss_is_visible(self):
        t0 = self.t0
        self.configure()
        self.capture(t0 - PRE, t0)
        pre = self.quota.used()
        status = self.status(t0)
        self.assertEqual(pre, status["required_pre_allocated"])
        expected = max(self.estimate(POST), self.estimate(PRE + POST) - pre) + self.ring.ledger_headroom
        self.assertEqual(expected, status["required_additional"])
        reserve = self.settings.safety_reserve_bytes
        self.quota.capacity = pre + status["required_additional"] + reserve
        self.assertEqual("healthy", self.status(t0)["state"])
        # Another filesystem consumer takes one allocation unit later.
        self.quota.other = self.store.allocation_unit
        reduced = self.status(t0)
        self.assertEqual(("STORAGE_PRESSURE", "post_loss_headroom_reduced"),
                         (reduced["state"], reduced["reason"]))

    def test_existing_protected_usage_rejects_new_simultaneous_budget(self):
        t0 = self.t0
        self.configure()
        self.capture(t0 - PRE, t0)
        self.connect(t0)
        incident = self.lose(t0)
        self.capture(t0, t0 + POST)
        protected = self.quota.used()
        at = t0 + POST + PRE
        self.assertEqual(protected, self.status(at)["protected_allocated_bytes"])
        # No ordinary pre-loss remains buffered at ``at``: a new incident
        # needs the full T-10 + T+10 envelope on top of the protected bytes.
        needed = self.status(at)["required_additional"] + self.settings.safety_reserve_bytes
        self.assertEqual(self.estimate(PRE + POST) + self.ring.ledger_headroom
                         + self.settings.safety_reserve_bytes, needed)
        # The capacity would admit the envelope if protected bytes were
        # reclaimable, so a refusal proves they are neither credited nor freed.
        self.quota.capacity = protected + needed - 1
        self.assertGreaterEqual(self.quota.capacity, needed)
        with self.assertRaisesRegex(RingRefused, "insufficient_simultaneous_pre_post_budget"):
            self.ring.configure(RingConfig("duration", 600), self.profiles,
                                now_us=at, clock_trusted=True)
        kept = self.ring.incident(incident, now_us=at)
        self.assertEqual(("complete", False), (kept["state"], kept["has_gaps"]))
        self.assertEqual(protected, self.quota.used())
        self.quota.capacity += 1
        self.ring.configure(RingConfig("duration", 600), self.profiles, now_us=at, clock_trusted=True)
        self.assertEqual(protected, self.quota.used())

    def concurrent_preserves(self):
        barrier = threading.Barrier(2)
        results = []

        def request():
            barrier.wait(5)
            try:
                results.append(self.ring.preserve("server_movement", self.t0 - PRE, self.t0 + POST,
                                                  now_us=self.t0, clock_trusted=True))
            except RingRefused as exc:
                results.append(str(exc))

        threads = [threading.Thread(target=request) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())
        return results

    def test_concurrent_preserves_reject_the_one_that_exceeds_the_ledger_budget(self):
        self.ring.close()
        self.ledger_bytes = 450 * 4096
        self.open_ring()
        self.configure()
        self.capture(self.t0 - PRE, self.t0)
        results = self.concurrent_preserves()
        accepted = [item for item in results if isinstance(item, UUID)]
        self.assertEqual(1, len(accepted))
        self.assertEqual(["insufficient_ledger_capacity"],
                         [item for item in results if not isinstance(item, UUID)])
        self.assertEqual(1, self.count("incidents"))
        self.capture(self.t0, self.t0 + POST)
        self.assertEqual("complete", self.ring.incident(accepted[0], now_us=self.t0 + POST)["state"])
        self.assertEqual(20, self.count("segments"))
        self.assertEqual(20, self.count("protection"))

    def test_concurrent_preserves_both_admitted_without_double_counting(self):
        self.ring.close()
        self.ledger_bytes = 512 * 4096
        self.open_ring()
        self.configure()
        self.capture(self.t0 - PRE, self.t0)
        results = self.concurrent_preserves()
        self.assertTrue(all(isinstance(item, UUID) for item in results))
        self.assertEqual(2, len(set(results)))
        self.capture(self.t0, self.t0 + POST)
        details = [self.ring.incident(item, now_us=self.t0 + POST) for item in results]
        self.assertEqual(["complete", "complete"], [item["state"] for item in details])
        self.assertEqual(20, self.count("segments"))
        self.assertEqual(40, self.count("protection"))
        self.assertEqual(details[0]["allocated_bytes"], self.quota.used())
        self.assertEqual(self.quota.used(),
                         self.status(self.t0 + POST)["protected_allocated_bytes"])


if __name__ == "__main__":
    unittest.main()
