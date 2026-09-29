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
        self.assertEqual("STORAGE_PRESSURE", self.status(later)["state"])
        self.assertEqual("complete", self.ring.incident(incident, now_us=later)["state"])
        # Once another consumer breaches the reserve itself: hard stop.
        self.quota.other += 2 * unit
        status = self.status(later)
        self.assertEqual(("STORAGE_HARD_STOP", "safety_reserve_unavailable"),
                         (status["state"], status["reason"]))
        with self.assertRaisesRegex(StorageRefused, "STORAGE_HARD_STOP"):
            self.store.write_segment(UUID(int=999), PAYLOAD)
        self.assertEqual("complete", self.ring.incident(incident, now_us=later)["state"])

if __name__ == "__main__":
    unittest.main()
