"""Agent media-root refusal scenarios: no fallback, no reserve consumption.

Mount inventory, stable-device identity and free space are synthetic ports;
directory substitution uses a real ephemeral filesystem. The scenarios never
touch a real block device or mount table.
"""

from dataclasses import replace
import os
import unittest
from uuid import UUID

from media_capture_agent.ring_models import POST, PRE, RingRefused
from media_capture_agent.storage import StorageRefused, read_mounts

from tests.e2e.test_agent_ring_scenarios import MINUTE, PAYLOAD, RingScenario


def tree(root):
    """Every path below root, excluding the Agent's private ledger directory."""
    found = set()
    for directory, names, files in os.walk(root):
        if os.path.basename(directory) == "state":
            names[:] = []
            continue
        found.update(os.path.relpath(os.path.join(directory, item), root) for item in names + files)
    return found


class MediaRootRefusalTests(RingScenario):
    source_count = 1

    def protected_incident(self):
        t0 = self.t0
        self.configure()
        self.capture(t0 - PRE, t0)
        self.connect(t0)
        incident = self.lose(t0)
        self.capture(t0, t0 + 5 * MINUTE)
        return incident

    def assert_refused_without_fallback(self, reason, attribute, value):
        segments = set(self.store.list_segments())
        before = tree(self.root)
        original = getattr(self.store, attribute)
        setattr(self.store, attribute, value)
        now = self.t0 + 6 * MINUTE
        with self.assertRaisesRegex(RingRefused, "media_storage_unavailable|segment_storage_refused"):
            self.ring.append(self.sources[0], now - MINUTE, now, PAYLOAD,
                             now_us=now, clock_trusted=True)
        status = self.status(now)
        self.assertEqual(("STORAGE_HARD_STOP", reason), (status["state"], status["reason"]))
        self.assertIsNone(status["filesystem_free"])
        # No new file or directory appeared anywhere: no fallback root.
        self.assertEqual(before, tree(self.root))
        setattr(self.store, attribute, original)
        self.assertEqual(segments, set(self.store.list_segments()))

    def test_missing_mount_refuses_without_creating_fallback_or_deleting_evidence(self):
        incident = self.protected_incident()
        self.assert_refused_without_fallback("mount_missing", "mounts", lambda: [])
        self.assertEqual("active", self.ring.incident(incident, now_us=self.t0 + 6 * MINUTE)["state"])

    def test_replaced_mount_identity_or_stable_device_is_refused(self):
        self.protected_incident()
        mounts = self.store.mounts
        cases = {
            "mount_identity_mismatch": ("mounts", lambda: [
                replace(item, identity=replace(item.identity, filesystem="synthetic-substitute"))
                for item in read_mounts()]),
            "stable_device_mismatch": ("stable_device", lambda _expected: False),
        }
        for reason, (attribute, value) in cases.items():
            with self.subTest(reason=reason):
                self.assert_refused_without_fallback(reason, attribute, value)
        self.assertIs(mounts, self.store.mounts)

    def test_substituted_media_directory_is_never_written(self):
        self.protected_incident()
        media = self.settings.media_root
        moved = media.with_name("media-moved")
        count = len(list(media.iterdir()))
        os.rename(media, moved)
        media.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(StorageRefused, "media_root_replaced"):
                self.store.check()
            now = self.t0 + 6 * MINUTE
            with self.assertRaises(RingRefused):
                self.ring.append(self.sources[0], now - MINUTE, now, PAYLOAD,
                                 now_us=now, clock_trusted=True)
            self.assertEqual([], list(media.iterdir()))
            self.assertEqual(count, len(list(moved.iterdir())))
            self.assertEqual("STORAGE_HARD_STOP", self.status(now)["state"])
        finally:
            media.rmdir()
        # A symlink to another directory is also a substitution.
        media.symlink_to(moved, target_is_directory=True)
        try:
            with self.assertRaisesRegex(StorageRefused, "storage_path_unavailable"):
                self.store.check()
        finally:
            media.unlink()
        os.rename(moved, media)
        self.store.check()
        self.assertEqual(count, len(self.store.list_segments()))


class HardReserveTests(RingScenario):
    source_count = 1

    def test_pressure_never_reclaims_required_pre_loss_ordinary_media(self):
        # Capacity mode has no duration FIFO cutoff, so only the T-10 guard
        # keeps the required pre-loss window out of pressure reclamation.
        for mode in ("duration", "capacity"):
            with self.subTest(mode=mode):
                self.build(1, name=f"agent-{mode}")
                self.assert_pre_loss_kept_under_pressure(mode)

    def assert_pre_loss_kept_under_pressure(self, mode):
        t0 = self.t0
        self.configure(mode, 600 if mode == "duration" else self.estimate(PRE), at=t0 - PRE)
        self.capture(t0 - PRE, t0)
        self.connect(t0)
        rows = self.ring._rows()
        self.assertEqual(10, len(rows))
        now = t0 + MINUTE
        # Only the oldest segment falls outside T-10 at ``now``; the other
        # nine are the required pre-loss window for a future incident.
        required = {row["id"] for row in rows if row["end"] > now - PRE}
        self.assertEqual(9, len(required))
        oldest = UUID(rows[0]["id"])
        reserve = self.settings.safety_reserve_bytes
        unit = self.store.allocation_unit
        needed = -(-len(PAYLOAD) // unit) * unit
        freed = self.store.segment_allocations()[oldest]
        # Reclaiming the one eligible segment leaves one block short of the
        # next write plus reserve and ledger headroom.
        self.quota.other = (self.quota.capacity - (self.quota.used() - freed)
                            - (reserve + self.ring.ledger_headroom + needed - unit))
        with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
            self.ring.append(self.sources[0], t0, now, PAYLOAD, now_us=now, clock_trusted=True)
        stored = {row["id"] for row in self.ring._rows() if row["state"] == "stored"}
        self.assertEqual(required, stored)
        self.assertEqual(required, {str(item) for item in self.store.list_segments()})
        status = self.status(now)
        self.assertNotEqual("healthy", status["state"])
        self.assertEqual([(t0, now)], status["pre_loss_coverage"][str(self.sources[0])]["gaps_us"])
        # A loss now still pins every surviving pre-loss segment.
        incident = self.lose(now)
        pinned = {row["segment"] for row in self.ring.db.execute(
            "SELECT segment FROM protection WHERE incident=?", (str(incident),))}
        self.assertTrue(required <= pinned)

    def test_pressure_reclaims_ordinary_first_keeps_protection_and_stops_before_reserve(self):
        t0 = self.t0
        limit = 2 * self.estimate(PRE)
        self.configure("capacity", limit, at=t0 - 2 * PRE)
        self.capture(t0 - 2 * PRE, t0)
        self.connect(t0)
        incident = self.lose(t0)
        self.capture(t0, t0 + POST)
        protected = self.ring.incident(incident, now_us=t0 + POST)
        self.assertEqual("complete", protected["state"])
        protected_ids = {row["segment"] for row in self.ring.db.execute(
            "SELECT segment FROM protection WHERE incident=?", (str(incident),))}
        ordinary = [row["id"] for row in self.ring._rows() if row["id"] not in protected_ids]
        self.assertEqual(10, len(ordinary))

        reserve = self.settings.safety_reserve_bytes
        unit = self.store.allocation_unit
        headroom = self.ring.ledger_headroom
        # Leave room for the reserve and ledger headroom, but two blocks short
        # of the next segment: only ordinary pre-incident media may be reclaimed.
        self.quota.other = (self.quota.capacity - self.quota.used()
                            - reserve - headroom - len(PAYLOAD) + 2 * unit)
        now = t0 + POST + MINUTE
        self.ring.append(self.sources[0], now - MINUTE, now, PAYLOAD, now_us=now, clock_trusted=True)
        remaining = {row["id"] for row in self.ring._rows()}
        self.assertTrue(protected_ids <= remaining)
        self.assertLess(len(remaining & set(ordinary)), len(ordinary))
        # The oldest ordinary segments were reclaimed first.
        survivors = [item for item in ordinary if item in remaining]
        self.assertEqual(ordinary[len(ordinary) - len(survivors):], survivors)
        self.assertEqual(("complete", False),
                         (self.ring.incident(incident, now_us=now)["state"],
                          self.ring.incident(incident, now_us=now)["has_gaps"]))

        # Even after every remaining ordinary segment is reclaimed, the next
        # write would cut into the reserve: it is refused, not squeezed in.
        allocations = self.store.segment_allocations()
        reclaimable = sum(allocations[UUID(item)] for item in survivors)
        self.quota.other = (self.quota.capacity - (self.quota.used() - reclaimable)
                            - reserve - unit)
        later = now + MINUTE
        with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
            self.ring.append(self.sources[0], now, later, PAYLOAD, now_us=later, clock_trusted=True)
        rows = {row["id"] for row in self.ring._rows() if row["state"] == "stored"}
        self.assertEqual(set(), rows & set(ordinary))
        self.assertTrue(protected_ids <= rows)
        self.assertTrue({str(item) for item in self.store.list_segments()} >= protected_ids)
        self.assertEqual(reserve + unit, self.quota.capacity - self.quota.used() - self.quota.other)
        # Free space never fell below the reserve because the write was
        # refused first; recording is nevertheless refused, which is a hard
        # stop rather than mere pressure.
        refused = self.status(later)
        self.assertEqual(("STORAGE_HARD_STOP", "segment_write_refused_at_reserve"),
                         (refused["state"], refused["reason"]))
        self.assertGreaterEqual(refused["filesystem_free"], reserve)
        self.assertEqual("complete", self.ring.incident(incident, now_us=later)["state"])
        # Once another consumer breaches the reserve itself: hard stop.
        self.quota.other += 2 * unit
        status = self.status(later)
        self.assertEqual(("STORAGE_HARD_STOP", "safety_reserve_unavailable"),
                         (status["state"], status["reason"]))
        with self.assertRaisesRegex(StorageRefused, "STORAGE_HARD_STOP"):
            self.store.write_segment(UUID(int=999), PAYLOAD)
        self.assertEqual("complete", self.ring.incident(incident, now_us=later)["state"])

    def test_refused_capture_reports_hard_stop_throughout_and_recovers_with_space(self):
        # Several minutes of capture arrive while the filesystem sits just
        # above the reserve: every write is refused before crossing it, so
        # free space never drops below the reserve. Status must say recording
        # is refused on every sample, not pressure or healthy.
        t0 = self.t0
        # A 20-minute duration ring still filling: no FIFO trim frees space.
        self.configure(value=1200, at=t0 - PRE)
        self.capture(t0 - PRE, t0)
        reserve = self.settings.safety_reserve_bytes
        unit = self.store.allocation_unit
        self.quota.other = (self.quota.capacity - self.quota.used() - reserve
                            - self.ring.ledger_headroom)
        kept = set(self.store.list_segments())
        for begin in range(t0, t0 + 5 * MINUTE, MINUTE):
            now = begin + MINUTE
            with self.assertRaisesRegex(RingRefused, "segment_storage_refused"):
                self.ring.append(self.sources[0], begin, now, PAYLOAD, now_us=now, clock_trusted=True)
            status = self.status(now)
            self.assertEqual(("STORAGE_HARD_STOP", "segment_write_refused_at_reserve"),
                             (status["state"], status["reason"]))
            self.assertGreaterEqual(status["filesystem_free"], reserve)
        # Nothing required for the pre-loss window was reclaimed to squeeze in.
        now = t0 + 5 * MINUTE
        self.assertTrue(set(self.store.list_segments()) <= kept)
        # Space returns: status leaves hard stop before the next write, and
        # capture resumes.
        self.quota.other -= 2 * self.estimate(POST) + unit
        recovered = self.status(now)
        self.assertNotEqual("STORAGE_HARD_STOP", recovered["state"])
        self.ring.append(self.sources[0], now, now + MINUTE, PAYLOAD,
                         now_us=now + MINUTE, clock_trusted=True)
        self.assertNotEqual("STORAGE_HARD_STOP", self.status(now + MINUTE)["state"])

if __name__ == "__main__":
    unittest.main()
