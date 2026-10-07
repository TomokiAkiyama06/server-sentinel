"""Near-reserve FIFO with seeded variable segment sizes (Issue #130).

Synthetic bytes only. Real video segments vary in size below their bound; the
next-write check must not read ``STORAGE_HARD_STOP`` while such writes keep
succeeding, and must never read healthy before a write is actually refused.
"""

from fractions import Fraction
import math
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from media_capture_agent import ring as ring_module
from media_capture_agent.config import Settings
from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import PRE, SECOND, RingConfig, RingRefused, SegmentProfile, round_up
from media_capture_agent.storage import MediaStore
from tests.support import configuration
from tests.test_ring import LEDGER_BYTES, T0, AllowControls, Quota


# Segments span tens of allocation units, as real minute-long segments span
# many, so size variance is not hidden by rounding to whole units.
SEGMENT_LIMIT = 64 * 4096


def legacy_charge():
    """The pre-#130 charge: every simulated append at the largest of the
    source's last eight real allocations (an unbounded deviation factor
    always selects the per-append recent-maximum cap)."""
    return patch.multiple(ring_module, RECENT_ALLOCATION_SEGMENTS=8, DEVIATION_FACTOR=Fraction(10 ** 9))


class VariableSegmentSizeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def ring(self):
        root = Path(tempfile.mkdtemp(dir=self.temporary.name))
        value = configuration(root)
        value["max_segment_bytes"] = SEGMENT_LIMIT
        settings = Settings.parse(value, code_root=root / "code")
        quota = Quota(settings.media_root)
        store = MediaStore(settings, space=quota, stable_device=lambda _expected: True)
        self.addCleanup(store.close)
        ring = DiskRing(settings, store, ledger_maximum_bytes=LEDGER_BYTES, authority=AllowControls())
        self.addCleanup(ring.close)
        return settings, quota, store, ring

    def run_fifo(self, *, seed, cadences, minutes, slack_units, spread=0.08, spikes=0.0):
        """A duration-mode FIFO whose real segments vary around half their
        bound (seeded normal sizes, optional spikes up to the bound). After
        warm-up, other consumers leave ``slack_units`` above the reserve and
        ledger headroom. Status is sampled after every step, then the next
        step's appends are attempted."""
        settings, quota, store, ring = self.ring()
        unit = store.allocation_unit
        profiles = tuple(SegmentProfile(UUID(int=1300 + index), 34000 * 60 // cadence, 17000 * 60 // cadence,
                                        cadence * SECOND, 100) for index, cadence in enumerate(cadences))
        sizes = random.Random(seed)

        def payload(profile):
            bound = profile.segment_bytes()
            if spikes and sizes.random() < spikes:
                return b"\x5a" * sizes.randint(bound // 2, bound)
            return b"\x5a" * max(1, min(bound, int(sizes.gauss(bound * 0.5, bound * spread))))

        step = math.gcd(*cadences) * SECOND

        def due(at):
            return [profile for profile in profiles if (at - T0) % profile.segment_duration_us == 0]

        ring.configure(RingConfig("duration", 600), profiles, now_us=T0, clock_trusted=True)
        for at in range(T0 - PRE + step, T0 + 1, step):
            for profile in due(at):
                ring.append(profile.source_id, at - profile.segment_duration_us, at, payload(profile),
                            now_us=at, clock_trusted=True)
        quota.other = (quota.capacity - quota.used() - settings.safety_reserve_bytes
                       - ring.ledger_headroom - slack_units * unit)
        result = {"steps": 0, "false_hard_stop": 0, "refused": 0, "refused_after": {},
                  "within_estimate_unannounced": 0}
        previous = ring.status(now_us=T0, clock_trusted=True)
        for at in range(T0 + step, T0 + minutes * 60 * SECOND + 1, step):
            batch = due(at)
            estimate = None
            if len(batch) == len(profiles):
                # One batch of every source: its charge is exactly what the
                # status sampled at the previous step compared with.
                recent = ring._recent_allocations(store.segment_allocations(), unit)
                estimate = ring._batch_charge([(1, recent[profile.source_id]) for profile in profiles], unit)
            refused, actual = False, 0
            for profile in batch:
                data = payload(profile)
                actual += round_up(len(data), unit)
                try:
                    ring.append(profile.source_id, at - profile.segment_duration_us, at, data,
                                now_us=at, clock_trusted=True)
                except RingRefused as exc:
                    self.assertEqual("segment_storage_refused", str(exc))
                    refused = True
            # Writes are refused before the reserve, never written past it.
            self.assertGreaterEqual(ring._budget(ring.profiles, at, clock_trusted=True)["filesystem_free"],
                                    settings.safety_reserve_bytes)
            hard_stop = previous["state"] == "STORAGE_HARD_STOP"
            result["steps"] += 1
            if refused:
                result["refused"] += 1
                key = (previous["state"], previous["reason"])
                result["refused_after"][key] = result["refused_after"].get(key, 0) + 1
                if estimate is not None and actual <= estimate and not hard_stop:
                    result["within_estimate_unannounced"] += 1
            elif hard_stop:
                result["false_hard_stop"] += 1
            previous = ring.status(now_us=at, clock_trusted=True)
        return result

    def assert_never_unannounced(self, result):
        """A refused write is preceded by a hard stop or by pressure, never by
        a healthy or merely degraded status; a refusal of a batch no larger
        than its recent-bitrate estimate is always preceded by a hard stop."""
        for state, reason in result["refused_after"]:
            self.assertIn(state, {"STORAGE_HARD_STOP", "STORAGE_PRESSURE"}, (state, reason))
        self.assertEqual(0, result["within_estimate_unannounced"])

    def compare(self, scenarios):
        """Totals of the current and the legacy charge over seeded runs."""
        totals = []
        for legacy in (False, True):
            total = {"false_hard_stop": 0, "refused": 0, "announced_hard_stop": 0}
            for scenario in scenarios:
                if legacy:
                    with legacy_charge():
                        result = self.run_fifo(**scenario)
                else:
                    result = self.run_fifo(**scenario)
                self.assert_never_unannounced(result)
                total["false_hard_stop"] += result["false_hard_stop"]
                total["refused"] += result["refused"]
                total["announced_hard_stop"] += sum(
                    count for (state, _reason), count in result["refused_after"].items()
                    if state == "STORAGE_HARD_STOP")
            totals.append(total)
        return totals

    def test_batch_charge_is_mean_plus_two_correlated_deviations_capped_at_recent_maxima(self):
        unit = 4096
        # Eight recent allocations of 30, 30, ..., 50 units: mean 32.5 units,
        # sample variance 50 units squared.
        sizes = [30 * unit] * 7 + [50 * unit]
        mean = Fraction(sum(sizes), 8)
        variance = sum((size - mean) ** 2 for size in sizes) / 7
        recent = (mean, variance, 30 * unit, 50 * unit)
        self.assertEqual(variance, 50 * unit * unit)
        # Two synchronized sources with this same history: their sizes may be
        # perfectly correlated, so deviations add, 65 units + 2 * 2 *
        # sqrt(50) units = 93.3, rounded up to 94 units. Adding variances
        # (65 + 2 * sqrt(100) = 85 units) holds only for independent sources
        # and undercharged this batch (Codex review of PR #143). Still below
        # the 100 units of both at their recent maximum.
        self.assertEqual(94 * unit, DiskRing._batch_charge([(1, recent), (1, recent)], unit))
        # Chained appends of one source may be autocorrelated too: 6 appends
        # need 195 + 2 * 6 * sqrt(50) = 279.9 units, rounded up to 280, not
        # the 195 + 2 * sqrt(300) = 229.6 of independent appends, nor 6 * 50.
        self.assertEqual(280 * unit, DiskRing._batch_charge([(6, recent)], unit))
        # Never above every append at its recent maximum.
        wide = (Fraction(10 * unit), Fraction(400 * unit * unit), 1 * unit, 20 * unit)
        self.assertEqual(20 * unit, DiskRing._batch_charge([(1, wide)], unit))
        fixed = (Fraction(7 * unit), Fraction(0), 7 * unit, 7 * unit)
        self.assertEqual(14 * unit, DiskRing._batch_charge([(2, fixed)], unit))

    def test_one_large_recent_segment_no_longer_reads_hard_stop_while_typical_writes_fit(self):
        # Each source's recent history: seven 30-unit segments and one
        # 50-unit segment. Charging both next appends the recent maximum
        # (100 units) read a hard stop with 94 to 99 units available, although
        # a typical batch (60 units) fits. At the recent real bitrate the batch
        # is charged 94 units (mean plus two deviations, the two sources'
        # deviations added as if perfectly correlated): from there not a hard
        # stop, but still pressure.
        settings, quota, store, ring = self.ring()
        unit = store.allocation_unit
        profiles = tuple(SegmentProfile(UUID(int=1400 + index), 34000, 17000, 60 * SECOND, 100)
                         for index in range(2))
        ring.configure(RingConfig("duration", 600), profiles, now_us=T0, clock_trusted=True)
        history = [30] * 3 + [50] + [30] * 4
        for index, units in enumerate(history):
            end = T0 - (len(history) - 1 - index) * 60 * SECOND
            for profile in profiles:
                ring.append(profile.source_id, end - 60 * SECOND, end, b"\x5a" * (units * unit),
                            now_us=end, clock_trusted=True)
        allocations = sorted(store.segment_allocations().values())
        self.assertEqual([30 * unit] * 14 + [50 * unit] * 2, allocations)
        headroom = round_up(ring.ledger_headroom, unit)

        def available(units):
            # Nothing ages out by the next appends at T0 + 60 s.
            free = ring._budget(ring.profiles, T0, clock_trusted=True)["filesystem_free"]
            quota.other += free - (settings.safety_reserve_bytes + headroom + units * unit)
            return ring.status(now_us=T0, clock_trusted=True)

        status = available(94)
        self.assertEqual("STORAGE_PRESSURE", status["state"])
        with legacy_charge():
            legacy = ring.status(now_us=T0, clock_trusted=True)
        self.assertEqual(("STORAGE_HARD_STOP", "segment_write_refused_at_reserve"),
                         (legacy["state"], legacy["reason"]))
        # With 85 to 93 units the correlated batch may need more than is
        # available: a hard stop, not pressure (summing only the variances
        # charged 85 units and read pressure here).
        for units in (93, 85, 84):
            status = available(units)
            self.assertEqual(("STORAGE_HARD_STOP", "segment_write_refused_at_reserve"),
                             (status["state"], status["reason"]), units)
        # Typical writes fit with 60 units available.
        available(60)
        for profile in profiles:
            ring.append(profile.source_id, T0, T0 + 60 * SECOND, b"\x5a" * (30 * unit),
                        now_us=T0 + 60 * SECOND, clock_trusted=True)

    def test_short_history_is_charged_its_recent_maximum(self):
        _settings, _quota, store, ring = self.ring()
        unit = store.allocation_unit
        profile = SegmentProfile(UUID(int=1410), 34000, 17000, 60 * SECOND, 100)
        ring.configure(RingConfig("duration", 600), (profile,), now_us=T0, clock_trusted=True)
        for index, units in enumerate((10, 40, 10)):
            end = T0 - (2 - index) * 60 * SECOND
            ring.append(profile.source_id, end - 60 * SECOND, end, b"\x5a" * (units * unit),
                        now_us=end, clock_trusted=True)
        allocations = store.segment_allocations()
        self.assertEqual((40 * unit, 0, 10 * unit, 40 * unit),
                         ring._recent_allocations(allocations, unit)[profile.source_id])
        bound = round_up(profile.segment_bytes(), unit)
        self.assertEqual((bound, 0, bound, bound),
                         ring._recent_allocations(allocations, unit, at_bound=True)[profile.source_id])

    def test_two_sources_variable_sizes_no_more_false_hard_stops_and_no_unannounced_refusal(self):
        # Normally distributed sizes: with two deviations, perfectly
        # correlated, the charge per append is at least the sample maximum of
        # eight recent sizes almost always, so it equals the pre-#130 charge
        # here (47 false hard stops of 400 samples, both).
        current, legacy = self.compare([
            {"seed": 130, "cadences": (60, 60), "minutes": 200, "slack_units": 24},
            {"seed": 131, "cadences": (60, 60), "minutes": 200, "slack_units": 40},
        ])
        self.assertGreater(legacy["refused"], 0)
        self.assertEqual(legacy["refused"], current["refused"])
        # Every real refusal of these seeded runs was announced by a hard stop.
        self.assertEqual(current["refused"], current["announced_hard_stop"])
        self.assertEqual(legacy["refused"], legacy["announced_hard_stop"])
        self.assertLessEqual(current["false_hard_stop"], legacy["false_hard_stop"])

    def test_four_sources_variable_sizes_no_more_false_hard_stops(self):
        current, legacy = self.compare([
            {"seed": 130, "cadences": (60, 60, 60, 60), "minutes": 120, "slack_units": 48},
        ])
        self.assertGreater(legacy["refused"], 0)
        self.assertEqual(legacy["refused"], current["refused"])
        self.assertEqual(current["refused"], current["announced_hard_stop"])
        self.assertLessEqual(current["false_hard_stop"], legacy["false_hard_stop"])

    def test_mixed_cadence_chained_appends_no_more_false_hard_stops(self):
        # The 10 s source appends six times per 60 s source append; its
        # chained appends may be autocorrelated, so their deviations add.
        current, legacy = self.compare([
            {"seed": 130, "cadences": (10, 60), "minutes": 60, "slack_units": 24},
        ])
        self.assertGreater(legacy["refused"], 0)
        self.assertEqual(legacy["refused"], current["refused"])
        self.assertEqual(current["refused"], current["announced_hard_stop"])
        self.assertLessEqual(current["false_hard_stop"], legacy["false_hard_stop"])

    def test_bitrate_spike_above_the_recent_estimate_is_never_refused_while_healthy(self):
        # One segment in ten jumps to between half and all of the bound. A
        # spike above the recent estimate may be refused while status read
        # pressure (the maximum-bitrate warning), never healthy, under the
        # legacy charge as well.
        current, legacy = self.compare([
            {"seed": 132, "cadences": (60, 60), "minutes": 120, "slack_units": 16, "spread": 0.05,
             "spikes": 0.1},
        ])
        self.assertGreater(current["refused"], current["announced_hard_stop"])
        self.assertGreater(legacy["refused"], legacy["announced_hard_stop"])
        self.assertLessEqual(current["false_hard_stop"], legacy["false_hard_stop"])
