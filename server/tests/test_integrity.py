"""Synthetic inventory only. No commands read the test runner's host inventory."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from uuid import UUID
import json
import sqlite3

from app.integrity.model import Component, Inventory, Kind, State, compare
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

    def test_duplicate_unique_identity_not_ok(self):
        findings = compare(Inventory((disk(),)), Inventory((disk(), disk(slot="disk1"))))
        self.assertEqual(findings[0].state, State.UNVERIFIABLE)

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
        self.store = IntegrityStore(self.db)

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

    def test_unavailable_hardware_is_unknown(self):
        self.assertEqual(self.probe.collect().unavailable, frozenset(Kind))

    def test_zero_capacity_enumerated_device_is_not_confirmed_missing(self):
        self.put("sys/class/block/disk0/size", "0")
        current = self.probe.collect()
        self.assertIn(Kind.STORAGE, current.unavailable)
        findings = compare(Inventory((disk(),)), current)
        storage = [item for item in findings if item.kind == Kind.STORAGE]
        self.assertEqual([item.state for item in storage], [State.UNVERIFIABLE])

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
