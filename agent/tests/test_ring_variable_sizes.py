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
from tests.support import configuration, ring_temporary_directory
from tests.test_ring import LEDGER_BYTES, T0, AllowControls, Quota


# Segments span tens of allocation units, as real minute-long segments span
# many, so size variance is not hidden by rounding to whole units.
SEGMENT_LIMIT = 64 * 4096


def legacy_charge():
    """The pre-#130 charge: every simulated append at the largest of the
    source's last eight real allocations (an unbounded deviation factor
    always selects the per-append recent-maximum cap)."""
    return patch.multiple(ring_module, RECENT_ALLOCATION_SEGMENTS=8, DEVIATION_FACTOR=Fraction(10 ** 9),
                          MINIMUM_MEASURED_BATCHES=10 ** 9)


def correlated_charge():
    """The charge before measured batch totals: deviations of every batch
    added as if perfectly correlated, never above the recent maxima."""
    return patch.multiple(ring_module, MINIMUM_MEASURED_BATCHES=10 ** 9)


def samples(sizes, cadence=60 * SECOND, offset=0):
    """Rounded ``(start, end, allocation)`` samples, most recent first."""
    return tuple((-(index + 1) * cadence + offset, -index * cadence + offset, size)
                 for index, size in enumerate(sizes))


def recent_of(sizes, unit, **alignment):
    """``_recent_allocations`` of one source whose recent history is ``sizes``
    (most recent first, whole units)."""
    recent = [round_up(size, unit) for size in sizes[:8]]
    mean = Fraction(sum(recent), len(recent))
    variance = sum((size - mean) ** 2 for size in recent) / (len(recent) - 1)
    cap = max(recent)
    return (mean, variance, min(recent), cap, samples(sizes, **alignment))


class VariableSegmentSizeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = ring_temporary_directory()
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

    def run_fifo(self, *, seed, cadences, minutes, slack_units, spread=0.08, spikes=0.0, correlated=False):
        """A duration-mode FIFO whose real segments vary around half their
        bound (seeded normal sizes, optional spikes up to the bound; with
        ``correlated`` every source appending at an instant writes the same
        size, as synchronized cameras filming one changing scene may). After
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
            shared = payload(batch[0]) if correlated and batch else None
            for profile in batch:
                data = shared if correlated else payload(profile)
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

    def compare(self, scenarios, baseline=legacy_charge):
        """Totals of the current and a baseline charge over seeded runs."""
        totals = []
        for legacy in (False, True):
            total = {"false_hard_stop": 0, "refused": 0, "announced_hard_stop": 0}
            for scenario in scenarios:
                if legacy:
                    with baseline():
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
        recent = (mean, variance, 30 * unit, 50 * unit, ())
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
        wide = (Fraction(10 * unit), Fraction(400 * unit * unit), 1 * unit, 20 * unit, ())
        self.assertEqual(20 * unit, DiskRing._batch_charge([(1, wide)], unit))
        fixed = (Fraction(7 * unit), Fraction(0), 7 * unit, 7 * unit, ())
        self.assertEqual(14 * unit, DiskRing._batch_charge([(2, fixed)], unit))

    def test_batch_charge_rounding_is_pinned_and_never_below_the_exact_charge(self):
        unit = 4096
        # The summed mean is rounded up to whole bytes once: two means of
        # 10 units plus half a byte need 20 units plus one byte, so 21 units.
        half = (Fraction(20 * unit + 1, 2), Fraction(0), 10 * unit, 11 * unit, ())
        self.assertEqual(21 * unit, DiskRing._batch_charge([(1, half), (1, half)], unit))
        # Each source's deviation term is rounded up to whole bytes on its
        # own: 2 * sqrt(1/16) = 0.5 byte becomes 1 byte per source, so means
        # of 10 units - 1 byte and 10 units need 20 units + 1 byte, that is
        # 21 units (one rounding of the summed 1-byte deviation would give
        # exactly 20 units).
        low = (Fraction(10 * unit - 1), Fraction(1, 16), 9 * unit, 11 * unit, ())
        high = (Fraction(10 * unit), Fraction(1, 16), 9 * unit, 11 * unit, ())
        self.assertEqual(21 * unit, DiskRing._batch_charge([(1, low), (1, high)], unit))
        # Whole-unit means with no spread are charged exactly, not a unit more.
        exact = (Fraction(10 * unit), Fraction(0), 10 * unit, 10 * unit, ())
        self.assertEqual(30 * unit, DiskRing._batch_charge([(3, exact)], unit))
        # Seeded property: a whole number of units, never below the exact
        # rational charge, never above every append at its recent maximum.
        sizes = random.Random(130)
        for _ in range(300):
            appends = []
            for _source in range(sizes.randint(1, 4)):
                cap = sizes.randint(1, 64) * unit
                mean = Fraction(sizes.randint(1, cap), sizes.randint(1, 7))
                variance = Fraction(sizes.randint(0, (cap // 2) ** 2), sizes.randint(1, 7))
                appends.append((sizes.randint(0, 6), (min(mean, Fraction(cap)), variance, 1, cap, ())))
            charge = DiskRing._batch_charge(appends, unit)
            cap = sum(count * recent[3] for count, recent in appends)
            self.assertEqual(0, charge % unit)
            self.assertLessEqual(charge, cap)
            if charge < cap:
                mean = sum(count * recent[0] for count, recent in appends)
                # charge - mean >= 2 * sum(count * sqrt(variance)), checked
                # in exact arithmetic from below with each root rounded down.
                floor = sum(math.isqrt(math.floor(recent[1] * (2 * count) ** 2)) for count, recent in appends)
                self.assertGreaterEqual(charge, mean + floor)

    def test_recent_allocations_round_each_sample_up_to_whole_units(self):
        # ``st_blocks * 512`` need not be a multiple of ``f_frsize``: a
        # 30-unit-and-512-byte allocation consumes 31 whole units of free
        # space. Two sources with eight such samples each must be charged
        # 62 units per batch, not round_up(60 units + 1024 bytes) = 61 units
        # (Claude review of PR #143). The credit stays the unrounded sample.
        _settings, _quota, store, ring = self.ring()
        unit = store.allocation_unit
        profiles = tuple(SegmentProfile(UUID(int=1420 + index), 34000, 17000, 60 * SECOND, 100)
                         for index in range(2))
        ring.configure(RingConfig("duration", 600), profiles, now_us=T0, clock_trusted=True)
        for index in range(8):
            end = T0 - (7 - index) * 60 * SECOND
            for profile in profiles:
                ring.append(profile.source_id, end - 60 * SECOND, end, b"\x5a" * (30 * unit),
                            now_us=end, clock_trusted=True)
        # Every other sample of each source sits exactly on a unit boundary:
        # rounding it is a no-op, so the rounded history has no spread.
        allocations = {}
        for profile in profiles:
            rows = ring.db.execute("SELECT id FROM segments WHERE source=? ORDER BY end",
                                   (str(profile.source_id),)).fetchall()
            for position, row in enumerate(rows):
                allocations[UUID(row[0])] = 30 * unit + (512 if position % 2 == 0 else unit)
        recent = ring._recent_allocations(allocations, unit)
        for profile in profiles:
            self.assertEqual((Fraction(31 * unit), Fraction(0), 30 * unit + 512, 31 * unit),
                             recent[profile.source_id][:4])
            self.assertEqual([31 * unit] * 8, [size for _start, _end, size in recent[profile.source_id][4]])
        self.assertEqual(62 * unit, ring._batch_charge([(1, recent[profile.source_id]) for profile in profiles],
                                                       unit))
        # Whole-unit allocations (ext4-like) are unchanged by the rounding.
        whole = {identifier: 30 * unit for identifier in allocations}
        self.assertEqual((Fraction(30 * unit), Fraction(0), 30 * unit, 30 * unit),
                         ring._recent_allocations(whole, unit)[profiles[0].source_id][:4])

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
        # Pressure, not a hard stop. The earlier pressure reason
        # ``post_loss_headroom_reduced`` takes precedence in the status, so
        # pin the next-write simulation itself: not refused at the recent
        # real bitrate, refused at the maximum bitrate (the reason
        # ``segment_write_at_risk_at_maximum_bitrate`` would report).
        self.assertEqual(("STORAGE_PRESSURE", "post_loss_headroom_reduced"),
                         (status["state"], status["reason"]))
        budget = ring._budget(ring.profiles, T0, clock_trusted=True)
        self.assertFalse(ring._next_write_refused(T0, budget, clock_trusted=True))
        self.assertTrue(ring._next_write_refused(T0, budget, clock_trusted=True, at_bound=True))
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
                         ring._recent_allocations(allocations, unit)[profile.source_id][:4])
        bound = round_up(profile.segment_bytes(), unit)
        self.assertEqual((bound, 0, bound, bound, ()),
                         ring._recent_allocations(allocations, unit, at_bound=True)[profile.source_id])

    def test_two_sources_variable_sizes_no_more_false_hard_stops_and_no_unannounced_refusal(self):
        # Normally distributed sizes of two independent sources: measured
        # from the recent batch history (covariance never credited below
        # zero), the charge reads hard stop before 45, not 47, of 400 minutes
        # whose every append succeeded, and every refusal still follows a
        # hard stop.
        current, legacy = self.compare([
            {"seed": 130, "cadences": (60, 60), "minutes": 200, "slack_units": 24},
            {"seed": 131, "cadences": (60, 60), "minutes": 200, "slack_units": 40},
        ])
        self.assertEqual((45, 47), (current["false_hard_stop"], legacy["false_hard_stop"]))
        self.assertEqual((9, 9), (current["refused"], legacy["refused"]))
        self.assertEqual((9, 9), (current["announced_hard_stop"], legacy["announced_hard_stop"]))

    def test_four_sources_variable_sizes_no_more_false_hard_stops(self):
        current, legacy = self.compare([
            {"seed": 130, "cadences": (60, 60, 60, 60), "minutes": 120, "slack_units": 48},
        ])
        self.assertGreater(legacy["refused"], 0)
        self.assertEqual(legacy["refused"], current["refused"])
        self.assertEqual(current["refused"], current["announced_hard_stop"])
        self.assertLessEqual(current["false_hard_stop"], legacy["false_hard_stop"])

    def test_measured_batch_history_charges_the_real_covariance_of_synchronized_sources(self):
        unit = 4096
        # Ten aligned recent allocations (most recent first) of 30 units with
        # one 40-unit segment each, at different minutes: mean 31 units,
        # sample variance 10 units squared, sample covariance negative.
        first = [30 * unit] * 10
        first[2] = 40 * unit
        second = [30 * unit] * 10
        second[5] = 40 * unit

        def charges(*sources, counts=None):
            appends = list(zip(counts or [1] * len(sources), sources))
            with correlated_charge():
                correlated = DiskRing._batch_charge(appends, unit)
            return DiskRing._batch_charge(appends, unit), correlated

        # Independent outliers: 62 + 2 * sqrt((10 + 10) * 99 / 70) = 72.6,
        # so 73 units, where the perfectly correlated bound charged 62.5 + 2 *
        # 2 * sqrt(12.5) = 76.6, so 77 units. The negative covariance is
        # never credited.
        self.assertEqual((73 * unit, 77 * unit), charges(recent_of(first, unit), recent_of(second, unit)))
        # Perfectly correlated sizes are charged at least as much as by the
        # perfectly correlated bound: 62 + 2 * sqrt(4 * 10 * 99 / 70) = 77.04,
        # so 78 units (the prediction-bound widening for ten samples).
        self.assertEqual((78 * unit, 77 * unit), charges(recent_of(first, unit), recent_of(first, unit)))
        # Chained appends of one source still count as perfectly correlated:
        # two appends each, 124 + 2 * sqrt(4 * 20 * 99 / 70) = 145.3, so 146
        # units, not 154.
        self.assertEqual((146 * unit, 154 * unit), charges(recent_of(first, unit), recent_of(second, unit),
                                                           counts=[2, 2]))
        # Without enough aligned past batches the perfectly correlated bound
        # is charged: nine samples, another cadence, a gap after three
        # segments, a single source.
        gapped = recent_of(second, unit)[:4] + (
            recent_of(second, unit)[4][:3] + recent_of(second, unit, offset=-60 * SECOND)[4][3:],)
        for sources in (
                (recent_of(first[:9], unit), recent_of(second[:9], unit)),
                (recent_of(first, unit), recent_of(second, unit, cadence=30 * SECOND)),
                (recent_of(first, unit), gapped),
                (recent_of(first, unit),)):
            current, correlated = charges(*sources)
            self.assertEqual(correlated, current)
        # 60 s and 61 s segments whose latest ends coincide overlap through
        # all sixteen samples, but another cadence is not one synchronized
        # batch (Codex review of PR #272).
        current, correlated = charges(recent_of(first * 2, unit), recent_of(second * 2, unit, cadence=61 * SECOND))
        self.assertEqual((correlated, 77 * unit), (current, correlated))
        # A phase offset within one cadence still aligns the past batches.
        self.assertEqual(73 * unit, charges(recent_of(first, unit),
                                            recent_of(second, unit, offset=-30 * SECOND))[0])

    def test_measured_history_stops_at_a_gap_every_source_shares(self):
        # Thirteen minutes of 30-unit segments with one 40-unit segment per
        # source, but the minute four steps back is missing for both sources
        # (every write refused): the stored rows on both sides of it still
        # align by position, yet only three consecutive batches follow the
        # gap, so the perfectly correlated bound is charged (Codex review of
        # PR #272).
        _settings, _quota, store, ring = self.ring()
        unit = store.allocation_unit
        profiles = tuple(SegmentProfile(UUID(int=1430 + index), 34000, 17000, 60 * SECOND, 100)
                         for index in range(2))
        ring.configure(RingConfig("duration", 900), profiles, now_us=T0, clock_trusted=True)
        histories = [[30] * 13, [30] * 13]
        histories[0][1] = 40
        histories[1][6] = 40
        for index in reversed(range(13)):
            if index == 3:
                continue  # The shared gap.
            end = T0 - index * 60 * SECOND
            for profile, history in zip(profiles, histories):
                ring.append(profile.source_id, end - 60 * SECOND, end, b"\x5a" * (history[index] * unit),
                            now_us=end, clock_trusted=True)
        recent = ring._recent_allocations(store.segment_allocations(), unit)
        appends = [(1, recent[profile.source_id]) for profile in profiles]
        self.assertEqual([3, 3], [len(recent[profile.source_id][4]) for profile in profiles])
        with correlated_charge():
            correlated = DiskRing._batch_charge(appends, unit)
        self.assertEqual(correlated, DiskRing._batch_charge(appends, unit))
        # A clock-uncertain row ends the history too: its timestamps are not
        # comparable with the other source's (Codex review of PR #272).
        rows = ring.db.execute("SELECT id FROM segments WHERE source=? ORDER BY end DESC",
                               (str(profiles[0].source_id),)).fetchall()
        ring.db.execute("UPDATE segments SET clock_trusted=0 WHERE id=?", (rows[1][0],))
        recent = ring._recent_allocations(store.segment_allocations(), unit)
        self.assertEqual([1, 3], [len(recent[profile.source_id][4]) for profile in profiles])
        # Without the gap the same history is measured, below that bound.
        whole = [(1, recent_of([size * unit for size in history[:12]], unit)) for history in histories]
        with correlated_charge():
            bound = DiskRing._batch_charge(whole, unit)
        self.assertLess(DiskRing._batch_charge(whole, unit), bound)

    def test_measured_history_stops_at_a_trailing_refused_batch(self):
        # Twelve aligned minutes, then the latest minute refused for both
        # sources: its rows are ``missing``, so no newer stored row shows the
        # gap, yet the history before it must not be measured until ten new
        # aligned batches exist (Codex review of PR #272).
        _settings, _quota, store, ring = self.ring()
        unit = store.allocation_unit
        profiles = tuple(SegmentProfile(UUID(int=1450 + index), 34000, 17000, 60 * SECOND, 100)
                         for index in range(2))
        ring.configure(RingConfig("duration", 900), profiles, now_us=T0, clock_trusted=True)
        histories = [[30] * 13, [30] * 13]
        histories[0][1] = 40
        histories[1][6] = 40
        for index in reversed(range(13)):
            end = T0 - index * 60 * SECOND
            for profile, history in zip(profiles, histories):
                ring.append(profile.source_id, end - 60 * SECOND, end, b"\x5a" * (history[index] * unit),
                            now_us=end, clock_trusted=True)
        recent = ring._recent_allocations(store.segment_allocations(), unit)
        appends = [(1, recent[profile.source_id]) for profile in profiles]
        with correlated_charge():
            correlated = DiskRing._batch_charge(appends, unit)
        self.assertLess(DiskRing._batch_charge(appends, unit), correlated)
        for profile in profiles:
            ring.db.execute("UPDATE segments SET state='missing' WHERE source=? AND end=?",
                            (str(profile.source_id), T0))
        recent = ring._recent_allocations(store.segment_allocations(), unit)
        appends = [(1, recent[profile.source_id]) for profile in profiles]
        self.assertEqual([0, 0], [len(recent[profile.source_id][4]) for profile in profiles])
        with correlated_charge():
            correlated = DiskRing._batch_charge(appends, unit)
        self.assertEqual(correlated, DiskRing._batch_charge(appends, unit))

    def test_measured_history_stops_at_a_cadence_reconfiguration(self):
        # Every source reconfigured together from 30 s to 60 s segments: one
        # new 60 s batch after fifteen old 30 s batches still aligns by
        # position and duration across sources, but the old allocations do
        # not estimate the new cadence, so the history ends there and the
        # perfectly correlated bound is charged (Codex review of PR #272).
        _settings, _quota, store, ring = self.ring()
        unit = store.allocation_unit
        sources = [UUID(int=1440 + index) for index in range(2)]

        def profiles(cadence):
            return tuple(SegmentProfile(source, 34000 * 60 // cadence, 17000 * 60 // cadence, cadence * SECOND, 100)
                         for source in sources)

        old, new = profiles(30), profiles(60)
        start = T0 - 16 * 30 * SECOND
        ring.configure(RingConfig("duration", 900), old, now_us=start, clock_trusted=True)
        for index in range(15):
            end = start + (index + 1) * 30 * SECOND
            for source, units in zip(sources, (30 + (index % 2), 31 - (index % 2))):
                ring.append(source, end - 30 * SECOND, end, b"\x5a" * (units * unit), now_us=end, clock_trusted=True)
        reconfigured = start + 15 * 30 * SECOND
        ring.configure(RingConfig("duration", 900), new, now_us=reconfigured, clock_trusted=True)
        end = reconfigured + 60 * SECOND
        for source in sources:
            ring.append(source, reconfigured, end, b"\x5a" * (30 * unit), now_us=end, clock_trusted=True)
        recent = ring._recent_allocations(store.segment_allocations(), unit)
        self.assertEqual([1, 1], [len(recent[source][4]) for source in sources])
        appends = [(1, recent[source]) for source in sources]
        with correlated_charge():
            correlated = DiskRing._batch_charge(appends, unit)
        self.assertEqual(correlated, DiskRing._batch_charge(appends, unit))

    def test_raised_profile_bound_restarts_the_allocation_history(self):
        # Two sources wrote fifteen 10-unit segments, then their bound rose
        # with the same cadence. The old allocations do not estimate the new
        # profile: until segments are written under it, each next append is
        # charged its new bound, not the 20 units of the old history, and
        # the history survives a restart (Codex review of PR #272).
        settings, _quota, store, ring = self.ring()
        unit = store.allocation_unit
        sources = [UUID(int=1450 + index) for index in range(2)]

        def profiles(maximum):
            return tuple(SegmentProfile(source, maximum, maximum // 2, 60 * SECOND, 100) for source in sources)

        start = T0 - 15 * 60 * SECOND
        ring.configure(RingConfig("duration", 900), profiles(8000), now_us=start, clock_trusted=True)
        for index in range(15):
            end = start + (index + 1) * 60 * SECOND
            for source in sources:
                ring.append(source, end - 60 * SECOND, end, b"\x5a" * (10 * unit), now_us=end, clock_trusted=True)

        def charge(ring):
            recent = ring._recent_allocations(store.segment_allocations(), unit)
            return DiskRing._batch_charge([(1, recent[source]) for source in sources], unit)

        self.assertEqual(20 * unit, charge(ring))
        raised = profiles(32000)
        ring.configure(RingConfig("duration", 900), raised, now_us=T0, clock_trusted=True)
        bound = sum(round_up(profile.segment_bytes(), unit) for profile in raised)
        self.assertGreater(bound, 20 * unit)
        self.assertEqual(bound, charge(ring))
        ring.close()
        reopened = DiskRing(settings, store, ledger_maximum_bytes=LEDGER_BYTES, authority=AllowControls())
        self.addCleanup(reopened.close)
        self.assertEqual(bound, charge(reopened))
        # Segments written under the new profile form its history; an
        # unchanged reconfiguration keeps it.
        for source in sources:
            reopened.append(source, T0, T0 + 60 * SECOND, b"\x5a" * (12 * unit), now_us=T0 + 60 * SECOND,
                            clock_trusted=True)
        self.assertEqual(24 * unit, charge(reopened))
        reopened.configure(RingConfig("duration", 900), raised, now_us=T0 + 60 * SECOND, clock_trusted=True)
        self.assertEqual(24 * unit, charge(reopened))

    def test_measured_batch_charge_never_decreases_as_appends_are_added(self):
        # The next-write check evaluates only the latest append between two
        # credit changes, so adding an append (another count of a source, or
        # a source that did not append yet) must never lower the charge, even
        # where sources' sizes offset each other (Codex review of PR #272:
        # staggered sources, 176 units for counts (1, 1, 0) but 102 for
        # (1, 1, 1)).
        unit = 4096
        generator = random.Random(1302)
        for _ in range(300):
            length = generator.randint(10, 16)
            history = [[generator.randint(1, 64) * unit for _ in range(length)]
                       for _source in range(generator.randint(2, 4))]
            if generator.random() < 0.5:
                # Offsetting sizes of the first two sources.
                history[1] = [65 * unit - size for size in history[0]]
            recent = [recent_of(sizes, unit) for sizes in history]
            counts = [generator.randint(0, 3) for _sizes in history]
            charge = DiskRing._batch_charge(list(zip(counts, recent)), unit)
            for source in range(len(history)):
                more = list(counts)
                more[source] += 1
                self.assertLessEqual(charge, DiskRing._batch_charge(list(zip(more, recent)), unit),
                                     (counts, source))

    def test_measured_batch_charge_is_whole_units_and_never_below_its_prediction_bound(self):
        unit = 4096
        generator = random.Random(1301)
        for _ in range(200):
            history = [[generator.randint(1, 64 * unit) for _ in range(generator.randint(10, 16))]
                       for _source in range(generator.randint(2, 4))]
            length = min(len(sizes) for sizes in history)
            counts = [generator.randint(1, 3) for _sizes in history]
            recent = [recent_of([round_up(size, unit) for size in sizes], unit) for sizes in history]
            charge = DiskRing._batch_charge(list(zip(counts, recent)), unit)
            totals = [sum(count * round_up(sizes[index], unit) for count, sizes in zip(counts, history))
                      for index in range(length)]
            cap = sum(count * source[3] for count, source in zip(counts, recent))
            mean = Fraction(sum(totals), length)
            variance = sum((total - mean) ** 2 for total in totals) / (length - 1)
            # From below, each root rounded down: never under the exact bound.
            floor = math.isqrt(math.floor(variance * 4 * Fraction((length + 1) * (length - 1),
                                                                    length * (length - 3))))
            # Whole units, never above every append at its recent maximum
            # (the pre-#130 charge).
            self.assertEqual(0, charge % unit)
            self.assertLessEqual(charge, cap)
            self.assertGreaterEqual(charge, min(cap, mean + floor))

    def test_four_sources_measured_totals_read_fewer_false_hard_stops_than_the_correlated_bound(self):
        # Independent sizes of four synchronized sources: the perfectly
        # correlated bound charged a batch about four per-source deviations
        # above its mean, where its total deviates about two. Measured from
        # the recent batch history, the 120 minutes read hard stop before 23,
        # not 26, minutes whose every append succeeded; the one refusal is
        # still announced by a hard stop.
        current, correlated = self.compare([
            {"seed": 130, "cadences": (60, 60, 60, 60), "minutes": 120, "slack_units": 48},
        ], baseline=correlated_charge)
        self.assertEqual((23, 26), (current["false_hard_stop"], correlated["false_hard_stop"]))
        self.assertEqual((1, 1), (current["refused"], correlated["refused"]))
        self.assertEqual(current["refused"], current["announced_hard_stop"])

    def test_correlated_sources_are_charged_no_less_than_by_the_correlated_bound(self):
        # Two synchronized sources writing the same size at every instant:
        # the measured totals carry that correlation, so the batch is charged
        # as by the perfectly correlated bound, with the same outcome. Of four
        # refusals two followed a hard stop and two a batch above every
        # estimate (both sources' largest recent allocations), which read
        # pressure under each charge, never healthy.
        for baseline in (correlated_charge, legacy_charge):
            current, previous = self.compare([
                {"seed": 133, "cadences": (60, 60), "minutes": 200, "slack_units": 24, "correlated": True},
            ], baseline=baseline)
            self.assertEqual(previous, current)
            self.assertEqual((7, 4, 2), (current["false_hard_stop"], current["refused"],
                                         current["announced_hard_stop"]))

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
