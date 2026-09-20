"""Synthetic inventory only. No commands read the test runner's host inventory."""

from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from uuid import UUID
import json
import os
import signal
import sqlite3
import subprocess
import threading
from itertools import permutations

from app.integrity import probes
from app.integrity.model import Component, Finding, Inventory, Kind, State, compare
from app.integrity.probes import CommandRunner, LinuxProbe, ProbeUnavailable
from app.integrity.service import IntegrityService
from app.integrity.store import IntegrityStore, integrity_migration
from app.storage.migrations import migrate


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def disk(serial="synthetic-disk-a", *, slot="disk0", size="1000"):
    return Component(Kind.STORAGE, slot, (("capacity_bytes", size),), (("serial", serial),) if serial else ())


class Owner:
    def require_owner(self):
        return UUID("00000000-0000-4000-8000-000000000001")


class CompareTests(TestCase):
    def test_known_identity_survives_enumeration_change(self):
        findings = compare(Inventory((disk(),)), Inventory((disk(slot="disk9"),)))
        self.assertEqual([item.state for item in findings], [State.OK])

    def test_same_model_replacement_is_changed(self):
        findings = compare(Inventory((disk(),)), Inventory((disk("synthetic-disk-b"),)))
        self.assertEqual(findings[0].state, State.CHANGED)
        self.assertTrue(findings[0].immediate)

    def test_missing_and_new(self):
        findings = compare(Inventory((disk(),)), Inventory((disk("synthetic-other", slot="disk8"),)))
        self.assertEqual({item.state for item in findings}, {State.MISSING, State.NEW_DEVICE})

    def test_identical_nonserial_never_ok(self):
        findings = compare(Inventory((disk(""),)), Inventory((disk(""),)))
        self.assertEqual(findings[0].state, State.UNVERIFIABLE)

    def test_nonserial_enumeration_change_is_not_proof_of_removal(self):
        findings = compare(Inventory((disk(""),)), Inventory((disk("", slot="disk8"),)))
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE])

    def test_probe_failure_never_reports_missing(self):
        findings = compare(Inventory((disk(),)), Inventory((), frozenset({Kind.STORAGE})))
        self.assertEqual(findings[0].state, State.UNVERIFIABLE)
        self.assertTrue(findings[0].immediate)

    def test_partial_identity_is_unknown_not_changed(self):
        old = Component(Kind.STORAGE, "disk0", (), (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        new = Component(Kind.STORAGE, "disk0", (), (("serial", "synthetic-a"),))
        self.assertEqual(compare(Inventory((old,)), Inventory((new,)))[0].state, State.UNVERIFIABLE)

    def test_unique_partial_identity_survives_renumbering_and_location_reuse(self):
        old = Component(Kind.STORAGE, "disk0", (), (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        new = Component(Kind.STORAGE, "disk9", (), (("serial", "synthetic-a"),))
        findings = compare(Inventory((old,)), Inventory((disk("synthetic-other"), new)))
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])

    def test_retained_unique_identifier_still_reports_changed_other_identity(self):
        old = Component(Kind.STORAGE, "disk0", (), (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        new = Component(Kind.STORAGE, "disk9", (), (("serial", "synthetic-a"), ("wwid", "synthetic-replaced")))
        self.assertEqual([item.state for item in compare(Inventory((old,)), Inventory((new,)))], [State.CHANGED])

    def test_identityless_moved_disk_is_unknown_before_reused_location(self):
        findings = compare(Inventory((disk(),)), Inventory((disk("synthetic-replacement"), disk("", slot="disk9"))))
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])

    def test_incomplete_moved_disk_is_unknown_before_reused_location(self):
        for properties in ((), (("model", "Synthetic Disk"),)):
            incomplete = Component(Kind.STORAGE, "disk9", properties, (), False)
            findings = compare(Inventory((disk(),)), Inventory((disk("synthetic-replacement"), incomplete)))
            self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])

    def test_multiple_incomplete_candidates_are_unknown_without_arbitrary_binding(self):
        current = Inventory((disk("synthetic-replacement"),
                             Component(Kind.STORAGE, "disk8", (), (), False),
                             Component(Kind.STORAGE, "disk9", (), (), False)))
        findings = compare(Inventory((disk(),)), current)
        self.assertEqual([item.state for item in findings],
                         [State.UNVERIFIABLE, State.NEW_DEVICE, State.NEW_DEVICE])
        self.assertEqual(findings[0].reason, "AMBIGUOUS_IDENTITY")

    def test_conflicting_capacity_is_not_matched_as_incomplete_moved_disk(self):
        changed = Component(Kind.STORAGE, "disk9", (("capacity_bytes", "2000"),), (), False)
        findings = compare(Inventory((disk(),)), Inventory((disk("synthetic-replacement"), changed)))
        self.assertEqual([item.state for item in findings], [State.CHANGED, State.NEW_DEVICE])

    def test_weak_or_location_match_cannot_consume_another_approved_disk(self):
        current = Inventory((disk("synthetic-b", slot="disk0"), disk("", slot="disk9")))
        for first in (disk(""), disk("synthetic-a")):
            findings = compare(Inventory((first, disk("synthetic-b", slot="disk1"))), current)
            self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.OK])

    def test_conflicting_unique_links_are_ambiguous_not_missing(self):
        old = Component(Kind.STORAGE, "disk0", (), (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        current = Inventory((Component(Kind.STORAGE, "disk8", (), (("serial", "synthetic-a"),)),
                             Component(Kind.STORAGE, "disk9", (), (("wwid", "synthetic-w"),))))
        findings = compare(Inventory((old,)), current)
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])
        self.assertFalse(any(item.state == State.MISSING for item in findings))

    def test_split_identifier_surplus_observation_is_reported_as_new_device(self):
        """One approved disk cannot account for two observed disks (SPEC 10.1-10.2)."""
        old = Component(Kind.STORAGE, "disk0", (("capacity_bytes", "1000"),),
                        (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        halves = (Component(Kind.STORAGE, "disk8", (("capacity_bytes", "1000"),), (("serial", "synthetic-a"),)),
                  Component(Kind.STORAGE, "disk9", (("capacity_bytes", "1000"),), (("wwid", "synthetic-w"),)))
        for ordered in (halves, tuple(reversed(halves))):
            findings = compare(Inventory((old,)), Inventory(ordered))
            self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])
            self.assertEqual(findings[0].reason, "AMBIGUOUS_IDENTITY")
            self.assertEqual(findings[1].kind, Kind.STORAGE)
            self.assertEqual(findings[1].reason, "SURPLUS_AMBIGUOUS_COMPONENT")
            self.assertNotIn("synthetic-a", repr(findings))

    def test_ambiguous_baseline_keeps_its_other_compatible_links(self):
        """An identity-ambiguous component can still be the only fit for a third disk."""
        first = Component(Kind.STORAGE, "old-a", (), (("serial", "synthetic-a"),))
        second = Component(Kind.STORAGE, "old-b", (("model", "synthetic-one"),), ())
        third = Component(Kind.STORAGE, "old-c", (("model", "synthetic-two"),), ())
        current = (Component(Kind.STORAGE, "new-a", (("model", "synthetic-one"),), (("serial", "synthetic-a"),)),
                   Component(Kind.STORAGE, "new-b", (("model", "synthetic-two"),), (("serial", "synthetic-a"),)),
                   Component(Kind.STORAGE, "new-c", (("model", "synthetic-three"),), ()))
        for old_order in permutations((first, second, third)):
            for new_order in permutations(current):
                findings = compare(Inventory(old_order), Inventory(new_order))
                self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE] * 3)

    def test_incompatible_baseline_does_not_absorb_a_surplus_observation(self):
        """A MISSING approved disk explains no observation of its own category."""
        first = Component(Kind.STORAGE, "old-a", (("capacity_bytes", "1000"),),
                          (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        second = Component(Kind.STORAGE, "old-b", (("capacity_bytes", "2000"),),
                           (("serial", "synthetic-b"),))
        current = (Component(Kind.STORAGE, "new-a", (("capacity_bytes", "1000"),), (("serial", "synthetic-a"),)),
                   Component(Kind.STORAGE, "new-b", (("capacity_bytes", "1000"),), (("wwid", "synthetic-w"),)))
        for old_order in permutations((first, second)):
            for new_order in permutations(current):
                findings = compare(Inventory(old_order), Inventory(new_order))
                self.assertEqual(sorted(item.state for item in findings),
                                 sorted([State.UNVERIFIABLE, State.MISSING, State.NEW_DEVICE]))

    def test_surplus_new_device_is_not_claimed_while_the_baseline_can_explain_it(self):
        """Two approved disks explain two ambiguous observations; report no growth."""
        first = Component(Kind.STORAGE, "disk0", (), (("serial", "synthetic-a"), ("wwid", "synthetic-w")))
        second = Component(Kind.STORAGE, "disk1", (), ())
        current = (Component(Kind.STORAGE, "disk8", (), (("serial", "synthetic-a"),)),
                   Component(Kind.STORAGE, "disk9", (), (("wwid", "synthetic-w"),)))
        for old_order in permutations((first, second)):
            for new_order in permutations(current):
                findings = compare(Inventory(old_order), Inventory(new_order))
                self.assertEqual([item.state for item in findings],
                                 [State.UNVERIFIABLE, State.UNVERIFIABLE])

    def test_duplicate_unique_identity_not_ok(self):
        findings = compare(Inventory((disk(),)), Inventory((disk(), disk(slot="disk1"))))
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])

    def test_duplicate_exact_identities_are_unknown_before_property_comparison(self):
        baseline = Inventory((disk(),))
        current = (disk(size="2000"), disk(slot="disk9"))
        for ordered in (current, tuple(reversed(current))):
            findings = compare(baseline, Inventory(ordered))
            self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])
            self.assertEqual(findings[0].reason, "AMBIGUOUS_IDENTITY")

    def test_duplicate_baseline_identities_do_not_derive_drift_from_arbitrary_pairing(self):
        baseline = Inventory((disk(), disk(slot="disk9", size="2000")))
        # One observation cannot cover both approved duplicates; two can.
        for current, extra in (((disk(size="3000"),), [State.MISSING]),
                               ((disk(size="3000"), disk(slot="disk9", size="4000")), [])):
            findings = compare(baseline, Inventory(current))
            self.assertEqual([item.state for item in findings],
                             [State.UNVERIFIABLE, State.UNVERIFIABLE] + extra)

    def test_duplicated_baseline_identity_is_missing_without_any_observation(self):
        """A successful probe returning nothing proves absence, duplicates or not."""
        def module(slot):
            return Component(Kind.MEMORY, slot, (("capacity_bytes", "8"),),
                             (("serial", "synthetic-vendor-default"),))
        findings = compare(Inventory((module("slot0"), module("slot1"))), Inventory(()))
        self.assertEqual([item.state for item in findings], [State.MISSING, State.MISSING])
        self.assertTrue(all(item.immediate for item in findings))
        self.assertTrue(all(item.reason == "APPROVED_COMPONENT_ABSENT" for item in findings))

    def test_duplicate_identity_count_deficit_is_missing(self):
        """Fewer observations than approved duplicates proves one of them absent."""
        def module(slot, serial="synthetic-vendor-default"):
            return Component(Kind.MEMORY, slot, (("capacity_bytes", "8"),), (("serial", serial),))
        baseline = Inventory((module("slot0"), module("slot1")))
        findings = compare(baseline, Inventory((module("slot9"),)))
        self.assertEqual([item.state for item in findings],
                         [State.UNVERIFIABLE, State.UNVERIFIABLE, State.MISSING])
        self.assertEqual(findings[2].reason, "MISSING_AMBIGUOUS_COMPONENT")
        self.assertTrue(findings[2].immediate)
        self.assertNotIn(State.NEW_DEVICE, [item.state for item in findings])
        self.assertNotIn("synthetic-vendor-default", repr(findings))

    def test_duplicate_identity_deficit_and_surplus_are_reported_together(self):
        """Three approved duplicates, one survivor and two unrelated arrivals."""
        def module(slot, serial="synthetic-vendor-default"):
            return Component(Kind.MEMORY, slot, (("capacity_bytes", "8"),), (("serial", serial),))
        baseline = Inventory((module("slot0"), module("slot1"), module("slot2")))
        current = (module("slot9"), Component(Kind.MEMORY, "slot8", (("capacity_bytes", "16"),),
                                              (("serial", "synthetic-other"),)))
        findings = compare(baseline, Inventory(current))
        self.assertEqual([item.state for item in findings[:3]], [State.UNVERIFIABLE] * 3)
        self.assertEqual(sorted(item.state for item in findings[3:]),
                         sorted([State.NEW_DEVICE, State.MISSING, State.MISSING]))

    def test_duplicated_baseline_identity_stays_unknown_while_a_candidate_remains(self):
        """A duplicate still refuses arbitrary drift when an observation exists."""
        def module(slot, serial):
            return Component(Kind.MEMORY, slot, (("capacity_bytes", "8"),), (("serial", serial),))
        baseline = Inventory((module("slot0", "synthetic-vendor-default"),
                              module("slot1", "synthetic-vendor-default")))
        findings = compare(baseline, Inventory((module("slot0", "synthetic-other"),)))
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.MISSING])
        self.assertEqual(findings[0].reason, "AMBIGUOUS_IDENTITY")

    def test_shared_partial_and_anonymous_candidates_are_resolved_globally(self):
        def observed(slot, size, identity):
            return Component(Kind.STORAGE, slot, (("capacity_bytes", size),), identity)
        baseline = (observed("old-a", "1000", (("serial", "a"), ("wwid", "x"))),
                    observed("old-b", "2000", (("serial", "a"), ("wwid", "y"))),
                    observed("old-c", "1000", (("serial", "c"), ("wwid", "y"))))
        current = (observed("new-a", "1000", (("wwid", "y"),)),
                   observed("new-b", "2000", ()), observed("new-c", "1000", ()))
        for old_order in permutations(baseline):
            for new_order in permutations(current):
                findings = compare(Inventory(old_order), Inventory(new_order))
                self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE] * 3)

    def test_field_order_cannot_hide_a_duplicate_identity(self):
        first = Component(Kind.STORAGE, "disk0", (), (("serial", "a"), ("wwid", "x")))
        second = Component(Kind.STORAGE, "disk1", (), (("wwid", "x"), ("serial", "a")))
        findings = compare(Inventory((first,)), Inventory((first, second)))
        self.assertEqual([item.state for item in findings], [State.UNVERIFIABLE, State.NEW_DEVICE])

    def test_ambiguous_partial_candidates_remain_available_to_anonymous_baseline(self):
        first = Component(Kind.STORAGE, "old-a", (("model", "Synthetic"),),
                          (("serial", "a"), ("wwid", "x")))
        second = Component(Kind.STORAGE, "old-b", (("capacity_bytes", "2000"),), ())
        current = (Component(Kind.STORAGE, "new-a", (("capacity_bytes", "1000"),), (("serial", "a"),)),
                   Component(Kind.STORAGE, "new-b", (("capacity_bytes", "2000"),), (("wwid", "x"),)))
        for old_order in permutations((first, second)):
            for new_order in permutations(current):
                self.assertEqual([item.state for item in compare(Inventory(old_order), Inventory(new_order))],
                                 [State.UNVERIFIABLE, State.UNVERIFIABLE])

    def test_ambiguous_exact_candidates_remain_available_to_anonymous_baseline(self):
        first = disk("synthetic-a", slot="old-a")
        second = disk("", slot="old-b", size="2000")
        current = (disk("synthetic-a", slot="new-a"), disk("synthetic-a", slot="new-b", size="2000"))
        for old_order in permutations((first, second)):
            self.assertEqual([item.state for item in compare(Inventory(old_order), Inventory(current))],
                             [State.UNVERIFIABLE, State.UNVERIFIABLE])

    def test_unapproved_inventory_never_becomes_baseline(self):
        findings = compare(None, Inventory((disk(),)))
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(item.state == State.UNVERIFIABLE for item in findings))

    def test_repr_and_findings_do_not_expose_identifiers(self):
        observation = Inventory((disk(),))
        self.assertNotIn("synthetic-disk-a", repr(observation))
        self.assertNotIn("synthetic-disk-a", repr(observation.components[0]))
        self.assertNotIn("synthetic-disk-a", repr(compare(observation, observation)))


class StoreTests(TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        migrate(self.db, (integrity_migration(1),))
        self.addCleanup(self.db.close)
        self.reserved = False
        self.denied = False
        self.store = IntegrityStore(self.db, reservation=self.reservation, max_pending_events=8)

    @contextmanager
    def reservation(self):
        if self.denied:
            raise RuntimeError("STORAGE_HARD_STOP")
        self.assertFalse(self.reserved)
        self.reserved = True
        try:
            yield
        finally:
            self.reserved = False

    def test_approval_denies_by_default(self):
        with self.assertRaises(PermissionError):
            self.store.approve(Inventory((disk(),)), expected_revision=0, at=NOW)
        self.assertEqual(self.store.baseline(), (0, None))

    def test_approval_audited_atomic_and_revision_checked(self):
        self.store.approval = Owner()
        self.assertEqual(self.store.approve(Inventory((disk(),)), expected_revision=0, at=NOW), 1)
        with self.assertRaises(ValueError):
            self.store.approve(Inventory(()), expected_revision=0, at=NOW)
        self.assertEqual(self.store.baseline(), (1, Inventory((disk(),))))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_audit").fetchone()[0], 1)
        self.assertNotIn("synthetic-disk", str(tuple(self.db.execute("SELECT * FROM integrity_audit").fetchone())))

    def test_drift_does_not_rewrite_and_failed_sink_retains_fault(self):
        self.store.approval = Owner()
        self.store.approve(Inventory((disk(),)), expected_revision=0, at=NOW)
        findings = compare(self.store.baseline()[1], Inventory(()))
        self.store.record(findings, NOW)
        def broken(*args):
            raise OSError("synthetic-private-value")
        self.assertFalse(self.store.deliver(broken))
        self.assertEqual(self.store.baseline()[1], Inventory((disk(),)))
        self.assertEqual(self.db.execute("SELECT delivered FROM integrity_outbox").fetchone()[0], 0)
        seen = []
        self.assertTrue(self.store.deliver(lambda *args: seen.append(args)))
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][2])
        self.assertNotIn("synthetic-private", str(seen))
        self.assertIn("MISSING", self.db.execute("SELECT findings FROM integrity_status").fetchone()[0])

    def test_startup_daily_and_wall_clock_rollback(self):
        class Probe:
            calls = 0
            def collect(self):
                self.calls += 1
                return Inventory((disk(),))
        probe = Probe()
        clock = [0.0]
        wall = [NOW]
        service = IntegrityService(self.store, probe, lambda *args: None,
                                   monotonic=lambda: clock[0], utcnow=lambda: wall[0])
        service.startup()
        self.assertEqual(probe.calls, 1)
        clock[0] = 86399
        self.assertIsNone(service.tick())
        wall[0] -= timedelta(days=2)
        clock[0] = 86400
        service.tick()
        self.assertEqual(probe.calls, 2)
        service.startup()
        self.assertEqual(probe.calls, 3)

    def test_probe_exception_sanitized(self):
        class Probe:
            def collect(self):
                raise RuntimeError("synthetic-secret-serial")
        findings = IntegrityService(self.store, Probe(), lambda *args: None).startup()
        self.assertEqual(len(findings), 4)
        self.assertNotIn("synthetic-secret", str(findings))

    def test_full_outbox_preserves_daily_probe_cadence_and_retries_delivery(self):
        store = IntegrityStore(self.db, reservation=self.reservation, max_pending_events=1)
        store.record(compare(None, Inventory(())), NOW)
        class Probe:
            calls = 0
            def collect(self):
                self.calls += 1
                return Inventory(())
        probe = Probe()
        attempts = []
        def unavailable(*args):
            attempts.append(True)
            raise OSError("synthetic-unavailable")
        clock = [0.0]
        service = IntegrityService(store, probe, unavailable, monotonic=lambda: clock[0], utcnow=lambda: NOW)
        self.assertTrue(service.startup())
        for _ in range(3):
            clock[0] += 1
            self.assertIsNone(service.tick())
        self.assertEqual(probe.calls, 1)
        self.assertEqual(len(attempts), 5)
        self.assertEqual(self.db.execute("SELECT delivery_blocked FROM integrity_status").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_overflow").fetchone()[0], 4)

    def test_autocommit_required_and_worker_confined(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "AUTOCOMMIT"):
            IntegrityStore(db, reservation=self.reservation, max_pending_events=8)
        errors = []
        def wrong_worker():
            try:
                self.store.deliver(lambda *args: None)
            except RuntimeError as exc:
                errors.append(str(exc))
        thread = threading.Thread(target=wrong_worker)
        thread.start()
        thread.join()
        self.assertEqual(errors, ["INTEGRITY_WORKER_UNAVAILABLE"])

    def test_python_autocommit_true_closes_reserved_success_and_failure_transactions(self):
        self.db.autocommit = True
        self.store.approval = Owner()
        self.store.approve(Inventory((disk(),)), expected_revision=0, at=NOW)
        self.store.record(compare(None, Inventory(())), NOW)
        self.assertFalse(self.db.in_transaction)
        self.db.execute("CREATE TRIGGER fail_outbox BEFORE INSERT ON integrity_outbox "
                        "BEGIN SELECT RAISE(ABORT, 'synthetic-storage-failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.record(compare(None, Inventory(())), NOW)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_outbox").fetchone()[0], 1)
        self.db.execute("DROP TRIGGER fail_outbox")
        self.store.deliver(lambda *args: None)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_outbox").fetchone()[0], 0)

    def test_reservation_covers_approval_record_and_ack_transactions(self):
        writes = []
        def observe(statement):
            if statement.startswith(("BEGIN", "INSERT", "UPDATE", "DELETE", "COMMIT")):
                writes.append(self.reserved)
        self.db.set_trace_callback(observe)
        self.store.approval = Owner()
        self.store.approve(Inventory((disk(),)), expected_revision=0, at=NOW)
        self.store.record(compare(self.store.baseline()[1], Inventory(())), NOW)
        self.store.deliver(lambda *args: self.assertFalse(self.reserved))
        self.assertTrue(writes)
        self.assertTrue(all(writes))
        self.denied = True
        with self.assertRaisesRegex(RuntimeError, "STORAGE_HARD_STOP"):
            self.store.record(compare(None, Inventory(())), NOW)
        self.assertFalse(self.db.in_transaction)

    def test_pending_outbox_bounded_and_acked_ids_never_reused(self):
        store = IntegrityStore(self.db, reservation=self.reservation, max_pending_events=1)
        findings = compare(None, Inventory(()))
        store.record(findings, NOW)
        with self.assertRaisesRegex(RuntimeError, "INTEGRITY_OUTBOX_FULL"):
            store.record(findings, NOW)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_outbox").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT delivery_blocked FROM integrity_status").fetchone()[0], 1)
        identifiers = []
        for _ in range(5):
            store.deliver(lambda identifier, *args: identifiers.append(identifier))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_outbox").fetchone()[0], 0)
        store.record(findings, NOW)
        store.deliver(lambda identifier, *args: identifiers.append(identifier))
        self.assertGreater(identifiers[1], identifiers[0])
        self.assertFalse(self.db.in_transaction)

    def test_saturated_transient_faults_survive_healthy_observation_and_restart(self):
        store = IntegrityStore(self.db, reservation=self.reservation, max_pending_events=1)
        store.record((Finding(Kind.CPU, State.NEW_DEVICE, "UNAPPROVED_COMPONENT"),), NOW)
        for kind in Kind:
            for state in (State.CHANGED, State.MISSING, State.NEW_DEVICE, State.UNVERIFIABLE):
                for _ in range(2):
                    with self.assertRaisesRegex(RuntimeError, "INTEGRITY_OUTBOX_FULL"):
                        store.record((Finding(kind, state, "TRANSIENT_SYNTHETIC_WARNING"),), NOW + timedelta(seconds=1))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_overflow").fetchone()[0], 16)
        store.record((Finding(Kind.STORAGE, State.OK, "IDENTITY_AND_PROPERTIES_MATCH"),), NOW + timedelta(seconds=2))
        self.assertEqual(self.db.execute("SELECT delivery_blocked FROM integrity_status").fetchone()[0], 1)
        store = IntegrityStore(self.db, reservation=self.reservation, max_pending_events=1)
        seen = []
        for _ in range(17):
            store.deliver(lambda *args: seen.append(args))
        self.assertEqual(len(seen), 17)
        self.assertEqual(len({event[0] for event in seen}), 17)
        categories = {(finding["kind"], finding["state"]) for event in seen[1:] for finding in event[3]}
        self.assertEqual(len(categories), 16)
        self.assertTrue(all(event[1] == NOW + timedelta(seconds=1) for event in seen[1:]))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_overflow").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT delivery_blocked FROM integrity_status").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM integrity_outbox").fetchone()[0], 0)


class FakeRunner:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
    def run(self, command):
        value = self.outputs.get(command[0])
        if value is None:
            raise ProbeUnavailable()
        return value


class LinuxProbeTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.probe = LinuxProbe(self.root, FakeRunner())

    def put(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def test_synthetic_linux_inventory(self):
        self.put("proc/cpuinfo", "processor : 0\nphysical id : 0\nmodel name : Synthetic CPU\ncpu cores : 1\n\n")
        self.put("sys/class/block/sda/size", "2048")
        self.put("sys/class/block/sda/device/serial", "synthetic-serial")
        self.put("sys/class/block/sda/device/model", "Synthetic Disk")
        self.put("sys/class/block/sda/wwid", "synthetic-wwid")
        self.put("sys/bus/pci/devices/0000:01:00.0/class", "0x030000")
        for key in ("vendor", "device", "subsystem_vendor", "subsystem_device"):
            self.put("sys/bus/pci/devices/0000:01:00.0/" + key, "0x1234")
        self.probe.runner = FakeRunner({
            "dmidecode": b"Handle 0x0001, DMI type 17, 92 bytes\nMemory Device\n\tSize: 8 GB\n\tLocator: DIMM 0\n\tSerial Number: synthetic-memory\n",
            "nvidia-smi": b"00000000:01:00.0, GPU-synthetic, [N/A]\n",
        })
        inventory = self.probe.collect()
        self.assertEqual(inventory.unavailable, frozenset())
        self.assertEqual({item.kind for item in inventory.components}, set(Kind))
        storage = next(item for item in inventory.components if item.kind == Kind.STORAGE)
        self.assertEqual(dict(storage.properties)["capacity_bytes"], "1048576")
        gpu = next(item for item in inventory.components if item.kind == Kind.GPU)
        self.assertEqual(dict(gpu.identity)["uuid"], "GPU-synthetic")
        self.assertNotIn("synthetic-serial", repr(inventory))
        self.probe.runner = FakeRunner({"nvidia-smi": b"00010000:01:00.0, GPU-other-domain, [N/A]\n"})
        self.assertEqual(self.probe._gpu()[0].identity, ())

    def test_unavailable_hardware_is_unknown(self):
        self.assertEqual(self.probe.collect().unavailable, frozenset(Kind))

    def test_zero_capacity_enumerated_device_is_not_confirmed_missing(self):
        self.put("sys/class/block/disk0/size", "0")
        current = self.probe.collect()
        self.assertNotIn(Kind.STORAGE, current.unavailable)
        findings = compare(Inventory((disk(),)), current)
        storage = [item for item in findings if item.kind == Kind.STORAGE]
        self.assertEqual([item.state for item in storage], [State.UNVERIFIABLE])

    def test_unrelated_empty_drive_preserves_verified_recording_disk(self):
        self.put("sys/class/block/disk0/size", "2048")
        self.put("sys/class/block/disk0/device/serial", "synthetic-disk-a")
        self.put("sys/class/block/sr0/size", "0")
        baseline = Inventory((Component(Kind.STORAGE, "disk0", (("capacity_bytes", "1048576"),),
                                        (("serial", "synthetic-disk-a"),)),))
        findings = compare(baseline, self.probe.collect())
        storage = [item for item in findings if item.kind == Kind.STORAGE]
        self.assertEqual([item.state for item in storage], [State.OK, State.NEW_DEVICE])
        self.assertFalse(any(item.immediate for item in storage))

    def test_memory_placeholder_serial_is_not_identity(self):
        self.probe.runner = FakeRunner({"dmidecode": b"Handle 0x0001\nMemory Device\n Size: 8 GB\n Locator: DIMM 0\n Serial Number: Not Specified\n"})
        self.assertEqual(self.probe._memory()[0].identity, ())

    def test_smart_failure_and_missing_information(self):
        for payload, expected in (({"smart_status": {"passed": False}}, "CRITICAL"),
                                  ({"nvme_smart_health_information_log": {"critical_warning": 2}}, "CRITICAL"),
                                  ({"smart_status": {"passed": True}}, "OK"), ({}, "UNVERIFIABLE")):
            self.probe.runner = FakeRunner({"smartctl": json.dumps(payload).encode()})
            self.assertEqual(self.probe.storage_health(("/dev/synthetic0",)), (expected,))

    def test_arbitrary_commands_rejected_before_spawn(self):
        with self.assertRaises(ProbeUnavailable):
            CommandRunner().run(("sh", "-c", "anything"))


class _Stream:
    def __init__(self, descriptor, owner):
        self._descriptor, self._owner = descriptor, owner

    def fileno(self):
        return self._descriptor

    def close(self):
        self._owner.closed = True


class _StuckChild:
    """Synthetic child that stays unreapable, like uninterruptible disk I/O."""

    pid = 424242

    def __init__(self, descriptor):
        self.closed = False
        self.waits = []
        self.stdout = _Stream(descriptor, self)

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.waits.append(timeout)
        raise subprocess.TimeoutExpired("synthetic-probe", timeout)


class _Spawn:
    def __init__(self, child):
        self._child = child

    def Popen(self, *arguments, **options):
        return self._child

    def __getattr__(self, name):
        return getattr(subprocess, name)


class _Signals:
    def __init__(self, killpg):
        self.killpg = killpg

    def __getattr__(self, name):
        return getattr(os, name)


class ProbeCleanupTests(TestCase):
    """Synthetic child objects only; no real probe process is ever spawned."""

    def setUp(self):
        reader, writer = os.pipe()
        os.close(writer)
        self.addCleanup(os.close, reader)
        self.child = _StuckChild(reader)
        self.killed = []

    def run_probe(self, killpg):
        spawn, signals = probes.subprocess, probes.os
        probes.subprocess, probes.os = _Spawn(self.child), _Signals(killpg)
        self.addCleanup(setattr, probes, "subprocess", spawn)
        self.addCleanup(setattr, probes, "os", signals)
        with self.assertRaises(ProbeUnavailable):
            CommandRunner().run(("dmidecode", "--type", "17"))

    def test_unkillable_probe_does_not_block_the_worker(self):
        self.run_probe(lambda pid, number: self.killed.append((pid, number)))
        self.assertEqual(self.killed, [(_StuckChild.pid, signal.SIGKILL)])
        # The status wait and the cleanup reap, both bounded, so a wedged disk
        # cannot stall the startup/daily check.
        self.assertEqual(len(self.child.waits), 2)
        self.assertTrue(all(timeout is not None for timeout in self.child.waits))
        self.assertTrue(self.child.closed)

    def test_failed_signal_still_reaps_and_closes_the_probe_pipe(self):
        """A child exiting between poll() and the signal must not stay a zombie."""
        def refuse(pid, number):
            self.killed.append((pid, number))
            raise ProcessLookupError("synthetic-probe")

        self.run_probe(refuse)
        self.assertEqual(self.killed, [(_StuckChild.pid, signal.SIGKILL)])
        self.assertEqual(len(self.child.waits), 2)
        self.assertTrue(all(timeout is not None for timeout in self.child.waits))
        self.assertTrue(self.child.closed)
