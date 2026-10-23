"""Issue #321: recorded major/minor numbers only corroborate the filesystem UUID.

A reboot may renumber the same disk (sda/sdb swapped: 8:16 became 8:0). While
the approved UUID resolves to the device that the runtime root and the mounted
mount point are on, and that device is not the operating-system root's, a
stale recorded pair must not stop the service: it is reported (value-free
launcher warning, monitoring status, one Owner notice per boot and device
numbers). Only a changed minor of the same kind of device is stale: a changed
major, a loop device or a new device-mapper device still refuses, as every
other identity failure does. Disposable directories, a fake sysfs
`/sys/dev/block`, a fake boot ID, injected UUID/mount/root lookups and an
intercepted Slack transport only; no real block device, mount or Slack
endpoint is used.
"""

import contextlib
from datetime import timedelta
from dataclasses import replace
import io
import json
import os
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.deployment import DEVICE_NUMBERS_STALE_WARNING, Deployment, main as deployment_main
from app.diagnostics.sources import StorageAdapter
from app.media.health.service import HealthState
from app.media.recording.model import RecordingError
from app.monitoring.config import (
    RecordingFilesystem, parse_monitoring, renumbered_device_acceptable,
)
from app.monitoring.filesystem import IdentifiedRecordingFilesystem
from app.monitoring.runtime import MonitoringStatus, RuntimeState
from app.settings import ConfigurationError
from app.storage.policy import StorageState

from tests.test_diagnostic_sources import CompositeDiagnosticSource, FakeMonitoring, values
from tests.test_monitoring_runtime import RECORDING_LIMITS, STORAGE_LIMITS, RuntimeFixture


UUID = "00000000-1111-2222-3333-444444444444"


def other_numbers(device: int) -> list[int]:
    """The same disk as the kernel might number it after a reboot (minor differs)."""
    return [os.major(device), os.minor(device) + 16]


def spare_device(taken: int, major: int, minor: int) -> int:
    """Synthetic numbers for a fake sysfs entry that never meet ``taken``."""
    while os.makedev(major, minor) == taken:
        minor += 1
    return os.makedev(major, minor)


def other_major(device: int) -> list[int]:
    """Another driver's numbers, e.g. a loop device `7:0` instead of `8:16`."""
    return [7, 0] if os.major(device) != 7 else [8, 16]


class FakeSysfs:
    """A disposable sysfs patched in as `/sys/dev/block`.

    Laid out like the kernel's: `dev/<maj>:<min>` links to the device
    directory under `devices/`, a hardware disk has a `device` link to its
    bus device, a partition is a directory inside its parent disk with a
    `partition` attribute, a loop disk has `loop/backing_file` and no
    `device`, a virtual disk (nbd, zram) has neither, a dm device has `dm/`
    and links its underlying devices under `slaves/`.
    """

    def __init__(self, case: unittest.TestCase):
        temporary = tempfile.TemporaryDirectory(prefix="server-device-numbers-sysfs-")
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "dev").mkdir()
        (self.root / "devices").mkdir()
        (self.root / "bus").mkdir()
        patcher = patch("app.monitoring.config.SYS_DEV_BLOCK", self.root / "dev")
        patcher.start()
        case.addCleanup(patcher.stop)

    def device(self, device: int, name: str, *, parent: Path | None = None,
               loop: bool = False, dm: bool = False, slaves=(),
               hardware: bool | None = None) -> Path:
        directory = (parent if parent is not None else self.root / "devices") / name
        directory.mkdir()
        if hardware is None:
            # Whole disks that are no loop/dm device are hardware by default.
            hardware = parent is None and not loop and not dm and not slaves
        if hardware:
            bus = self.root / "bus" / name
            bus.mkdir()
            (directory / "device").symlink_to(bus)
        if parent is not None:
            (directory / "partition").write_text("1\n")
        if loop:
            (directory / "loop").mkdir()
            (directory / "loop" / "backing_file").write_text("/synthetic/image\n")
        if dm:
            (directory / "dm").mkdir()
        if slaves:
            (directory / "slaves").mkdir()
            for slave in slaves:
                (directory / "slaves" / slave.name).symlink_to(slave)
        (self.root / "dev" / f"{os.major(device)}:{os.minor(device)}").symlink_to(directory)
        return directory

    def node(self, device: int, kind: str = "disk") -> Path:
        """Model ``device`` as a hardware disk, a loop disk, a virtual disk
        without a bus device (`nbd`) or a dm device on a hardware disk."""
        name = f"{kind}-{os.major(device)}-{os.minor(device)}"
        slaves = ()
        if kind == "dm":
            slaves = (self.device(os.makedev(8, 240 + os.minor(device) % 16),
                                  name + "-disk"),)
        return self.device(device, name, loop=kind == "loop", dm=kind == "dm",
                           slaves=slaves, hardware=kind == "disk" or None)


class DeploymentValidationTests(unittest.TestCase):
    """`Deployment.load` (the launcher's and `--check`'s validation)."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="server-device-numbers-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime = self.root / "runtime"
        for path in (self.runtime, self.runtime / "state", self.runtime / "recordings",
                     self.runtime / "audit"):
            path.mkdir(mode=0o700)
        (self.root / "code").mkdir()
        self.device = self.runtime.stat().st_dev
        self.numbers = [os.major(self.device), os.minor(self.device)]
        self.config = self.root / "deployment.json"
        self.sysfs = FakeSysfs(self)
        self.sysfs.node(self.device)
        # Defaults model a correctly mounted, separately backed runtime volume.
        self.approved = self.device
        self.mounted = True
        self.os_root = self.device + 1

    def value(self, *, runtime_device=None, recording_device=None, monitoring=True):
        value = {
            "runtime_root": str(self.runtime), "runtime_mount_point": str(self.root),
            "runtime_device": runtime_device or self.numbers,
            "runtime_filesystem_uuid": UUID, "capture_ca_directory": None,
            "service_uid": os.geteuid(), "human_host": "127.0.0.1", "human_port": 8000,
            "log_level": "INFO",
        }
        if monitoring:
            value["monitoring"] = {
                "time_zone": "UTC", "storage_limits": STORAGE_LIMITS,
                "recording_limits": RECORDING_LIMITS,
                "recording_filesystem": {"filesystem_uuid": UUID,
                                         "device": recording_device or self.numbers,
                                         "mount_point": str(self.root)},
            }
        return value

    @contextlib.contextmanager
    def host(self):
        def lookup(uuid):
            if uuid != UUID:
                raise ConfigurationError("approved runtime filesystem is unavailable")
            return self.approved

        with patch("app.deployment.ADMINISTRATOR_UID", os.geteuid()), patch(
                "app.deployment._approved_filesystem_device", side_effect=lookup), patch(
                "app.deployment.os.path.ismount", return_value=self.mounted), patch(
                "app.deployment._administrator_directory"), patch(
                "app.deployment._operating_system_root_device", return_value=self.os_root):
            yield

    def load(self, value):
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        with self.host():
            return Deployment.load(self.config, code_root=self.root / "code")

    def check(self, value):
        """Run `--check` exactly as `ExecStartPre` does; returns (code, stdout, stderr)."""
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)
        stdout, stderr = io.StringIO(), io.StringIO()
        with self.host(), patch("app.deployment._runtime_roots",
                                return_value=(self.root / "code", None)), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = deployment_main(["--config", str(self.config), "--check"])
            except SystemExit as exit:
                code = exit.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_matching_numbers_pass_without_a_stale_flag(self):
        deployment = self.load(self.value())
        self.assertFalse(deployment.filesystem_device_numbers_stale)
        self.assertTrue(deployment.monitoring.recording_filesystem.recorded_device_numbers_match(
            self.device))
        code, stdout, stderr = self.check(self.value())
        self.assertEqual(0, code)
        self.assertIn("validation passed", stdout)
        self.assertEqual("", stderr)

    def test_renumbered_disk_with_verified_uuid_and_mount_passes_as_stale(self):
        # The 2026-10-22 incident: the UUID still names the mounted device,
        # only the recorded numbers are from the previous boot.
        stale = other_numbers(self.device)
        for value in (self.value(runtime_device=stale),
                      self.value(recording_device=stale),
                      self.value(runtime_device=stale, recording_device=stale),
                      self.value(runtime_device=stale, monitoring=False)):
            with self.subTest(value=value.get("monitoring", {}).get("recording_filesystem")):
                deployment = self.load(value)
                self.assertTrue(deployment.filesystem_device_numbers_stale)
                code, stdout, stderr = self.check(value) if "monitoring" in value else (0, "", "")
                if "monitoring" in value:
                    self.assertEqual(0, code)
                    self.assertIn("validation passed", stdout)
                    self.assertIn(DEVICE_NUMBERS_STALE_WARNING, stderr)
                    # Value-free: neither number pair, the UUID nor a path.
                    for secret in (UUID, str(self.root), f"{stale[0]}, {stale[1]}",
                                   f"{self.numbers[0]}, {self.numbers[1]}"):
                        self.assertNotIn(secret, stdout + stderr)
                if "monitoring" in value:
                    filesystem = deployment.monitoring.recording_filesystem
                    # Both recorded pairs travel to the runtime, so it reports either.
                    self.assertEqual(tuple(value["runtime_device"]), filesystem.runtime_device)
                    self.assertFalse(filesystem.recorded_device_numbers_match(self.device))

    def test_uuid_not_naming_the_mounted_device_is_refused_whatever_the_numbers(self):
        # A cloned or reused UUID on another disk, or the approved disk present
        # but not the one mounted: the UUID device differs from the mount's.
        self.approved = self.device + 7
        for numbers in (self.numbers, other_numbers(self.device),
                        [os.major(self.approved), os.minor(self.approved)]):
            with self.subTest(numbers=numbers):
                with self.assertRaisesRegex(ConfigurationError, "filesystem identity mismatch"):
                    self.load(self.value(runtime_device=numbers, recording_device=numbers))
                code, _, stderr = self.check(self.value(runtime_device=numbers,
                                                        recording_device=numbers))
                self.assertEqual(1, code)
                self.assertNotIn("warning", stderr)

    def test_changed_major_loop_and_unknown_devices_are_refused(self):
        # A changed major is another driver (e.g. a root-filesystem image
        # mounted with `-o loop`, 7:N): refused as before Issue #321.
        for value in (self.value(runtime_device=other_major(self.device)),
                      self.value(recording_device=other_major(self.device))):
            with self.subTest(value=value["runtime_device"]):
                with self.assertRaisesRegex(ConfigurationError, "identity mismatch"):
                    self.load(value)
                code, _, stderr = self.check(value)
                self.assertEqual(1, code)
                self.assertNotIn("warning", stderr)
        # Same major but a loop device: its image may sit on the root
        # filesystem, so a renumbered loop device is never accepted.
        sysfs = FakeSysfs(self)
        sysfs.node(self.device, "loop")
        with self.assertRaisesRegex(ConfigurationError, "identity mismatch"):
            self.load(self.value(runtime_device=other_numbers(self.device)))
        # An exact match is not re-judged (the deployment approved it).
        self.assertFalse(self.load(self.value()).filesystem_device_numbers_stale)
        # Without a sysfs entry nothing proves the kind: refused.
        FakeSysfs(self)
        with self.assertRaisesRegex(ConfigurationError, "identity mismatch"):
            self.load(self.value(recording_device=other_numbers(self.device)))

    def test_missing_uuid_is_refused(self):
        value = self.value(runtime_device=other_numbers(self.device))
        value["runtime_filesystem_uuid"] = "99999999-8888-7777-6666-555555555555"
        with self.assertRaisesRegex(ConfigurationError, "unavailable"):
            self.load(value)

    def test_unmounted_runtime_filesystem_is_refused_even_with_stale_numbers(self):
        self.mounted = False
        for numbers in (self.numbers, other_numbers(self.device)):
            with self.subTest(numbers=numbers):
                with self.assertRaisesRegex(ConfigurationError, "filesystem identity mismatch"):
                    self.load(self.value(runtime_device=numbers))

    def test_root_filesystem_is_refused_even_with_stale_numbers(self):
        stale = other_numbers(self.device)
        self.os_root = self.device
        with self.assertRaisesRegex(ConfigurationError, "root filesystem device"):
            self.load(self.value(runtime_device=stale))
        self.os_root = self.device + 1
        value = self.value(runtime_device=stale)
        value["runtime_mount_point"] = "/"
        with self.assertRaisesRegex(ConfigurationError, "must not be root"):
            self.load(value)

    def test_recording_filesystem_still_refuses_a_different_device(self):
        # The monitoring section is checked with the same rule: its own UUID
        # must name the recordings directory's mounted device.
        value = self.value(recording_device=other_numbers(self.device))
        value["monitoring"]["recording_filesystem"]["filesystem_uuid"] = (
            "99999999-8888-7777-6666-555555555555")
        with self.assertRaises(ConfigurationError):
            self.load(value)


class RecordingFilesystemTests(unittest.TestCase):
    """`parse_monitoring` and the per-sample `IdentifiedRecordingFilesystem`."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="server-device-numbers-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.mount = Path(temporary.name)
        self.recordings = self.mount / "recordings"
        self.recordings.mkdir(mode=0o700)
        self.device = self.recordings.stat().st_dev
        self.approved = self.device
        self.mounted = True
        self.sysfs = FakeSysfs(self)
        self.sysfs.node(self.device)

    def parse(self, numbers, *, root=None):
        return parse_monitoring({
            "time_zone": "UTC", "storage_limits": dict(STORAGE_LIMITS),
            "recording_limits": dict(RECORDING_LIMITS),
            "recording_filesystem": {"filesystem_uuid": UUID, "device": numbers,
                                     "mount_point": str(self.mount)},
        }, recordings_directory=self.recordings,
            resolve_device=lambda uuid: self.approved,
            root_device=lambda: self.device + 1 if root is None else root,
            is_mount=lambda path: self.mounted).recording_filesystem

    def test_parse_accepts_stale_numbers_only_with_a_verified_identity(self):
        filesystem = self.parse(other_numbers(self.device))
        self.assertFalse(filesystem.recorded_device_numbers_match(self.device))
        self.assertTrue(self.parse([os.major(self.device), os.minor(self.device)])
                        .recorded_device_numbers_match(self.device))
        for change in ("uuid", "mount", "root"):
            with self.subTest(change=change):
                self.approved, self.mounted, root = self.device, True, None
                if change == "uuid":
                    self.approved = self.device + 7
                elif change == "mount":
                    self.mounted = False
                else:
                    root = self.device
                with self.assertRaisesRegex(ConfigurationError, "mismatch"):
                    self.parse(other_numbers(self.device), root=root)
        self.approved, self.mounted = self.device, True
        with self.assertRaisesRegex(ConfigurationError, "mismatch"):
            self.parse(other_major(self.device))

    def test_renumbering_rule_by_device_kind(self):
        disk = os.makedev(8, 0)
        loop = os.makedev(7, 3)
        mapped = os.makedev(253, 1)
        # A fresh sysfs, so the synthetic numbers never meet the runner's.
        sysfs = FakeSysfs(self)
        sysfs.node(disk)
        sysfs.node(loop, "loop")
        sysfs.node(mapped, "dm")
        cases = (
            ((8, 0), disk, True),      # unchanged
            ((8, 16), disk, True),     # sda/sdb swapped (the incident)
            ((7, 0), disk, False),     # changed major
            ((8, 16), loop, False),    # disk now a loop device
            ((7, 0), loop, False),     # renumbered loop device
            ((7, 3), loop, True),      # an exact match is not re-judged
            ((8, 16), mapped, False),  # disk now a device-mapper device
            ((253, 4), mapped, True),  # renumbered device-mapper device
            ((8, 16), os.makedev(8, 32), False),  # no sysfs entry: fail closed
        )
        for recorded, device, expected in cases:
            with self.subTest(recorded=recorded, device=(os.major(device), os.minor(device))):
                self.assertIs(expected, renumbered_device_acceptable(recorded, device))

    def test_only_devices_resting_on_hardware_disks_are_renumbered(self):
        # `losetup -P` partitions get major 259, the same as NVMe; only the
        # parent loop disk has `loop/`. LVM/dm on a loop device is loop-backed.
        sysfs = FakeSysfs(self)
        loop0 = sysfs.device(os.makedev(7, 0), "loop0", loop=True)
        loop0p1 = sysfs.device(os.makedev(259, 5), "loop0p1", parent=loop0)
        nvme = sysfs.device(os.makedev(259, 0), "nvme0n1")
        nvme_part = sysfs.device(os.makedev(259, 2), "nvme0n1p2", parent=nvme)
        loop1 = sysfs.device(os.makedev(7, 1), "loop1", loop=True)
        sysfs.device(os.makedev(253, 0), "dm-0", dm=True, slaves=(loop1,))
        sysfs.device(os.makedev(253, 1), "dm-1", dm=True, slaves=(nvme_part,))
        inner = sysfs.device(os.makedev(253, 3), "dm-3", dm=True, slaves=(loop0p1,))
        sysfs.device(os.makedev(253, 2), "dm-2", dm=True, slaves=(inner,))
        broken = sysfs.root / "devices" / "missing-slave"
        sysfs.device(os.makedev(253, 5), "dm-5", dm=True, slaves=(broken,))
        nbd = sysfs.device(os.makedev(43, 1), "nbd1", hardware=False)
        sysfs.device(os.makedev(253, 6), "dm-6", dm=True, slaves=(nbd,))
        sysfs.device(os.makedev(253, 7), "dm-7", dm=True)
        sysfs.device(os.makedev(253, 8), "dm-8", dm=True, slaves=(nvme_part, nbd))
        cases = (
            ((259, 1), os.makedev(259, 5), False),  # loop partition, NVMe numbers recorded
            ((259, 7), os.makedev(259, 2), True),   # NVMe partition renumbered
            ((259, 7), os.makedev(259, 0), True),   # NVMe disk renumbered
            ((253, 4), os.makedev(253, 0), False),  # dm on a loop disk
            ((253, 4), os.makedev(253, 1), True),   # dm on an NVMe partition
            ((253, 4), os.makedev(253, 2), False),  # dm on dm on a loop partition
            ((253, 4), os.makedev(253, 5), False),  # unreadable slave: fail closed
            ((43, 3), os.makedev(43, 1), False),    # nbd-like disk: no bus device
            ((253, 4), os.makedev(253, 6), False),  # dm over an nbd-like disk
            ((253, 4), os.makedev(253, 7), False),  # dm without any slave
            ((253, 4), os.makedev(253, 8), False),  # dm over hardware and nbd
            ((259, 5), os.makedev(259, 5), True),   # an exact match is not re-judged
        )
        for recorded, device, expected in cases:
            with self.subTest(recorded=recorded, device=(os.major(device), os.minor(device))):
                self.assertIs(expected, renumbered_device_acceptable(recorded, device))

    def test_stacking_deeper_than_the_bound_is_refused(self):
        sysfs = FakeSysfs(self)
        below = sysfs.device(os.makedev(259, 0), "nvme0n1")
        for level in range(12):
            below = sysfs.device(os.makedev(253, level), f"dm-{level}", dm=True,
                                      slaves=(below,))
        self.assertTrue(renumbered_device_acceptable((253, 20), os.makedev(253, 0)))
        self.assertFalse(renumbered_device_acceptable((253, 20), os.makedev(253, 11)))

    def identity(self, numbers, runtime_device=None):
        return RecordingFilesystem(self.recordings, UUID, tuple(numbers), self.mount,
                                   lambda uuid: self.approved, lambda path: self.mounted,
                                   runtime_device=runtime_device)

    def test_every_sample_still_refuses_a_uuid_or_mount_change(self):
        current = (os.major(self.device), os.minor(self.device))
        metadata = self.recordings / "metadata.sqlite3"
        metadata.write_bytes(b"")
        metadata.chmod(0o600)
        cases = ((other_numbers(self.device), None), (current, tuple(other_numbers(self.device))),
                 (current, current))
        for numbers, runtime_device in cases:
            with self.subTest(numbers=numbers, runtime_device=runtime_device):
                self.approved, self.mounted = self.device, True
                filesystem = IdentifiedRecordingFilesystem(
                    self.identity(numbers, runtime_device), metadata)
                self.assertEqual((tuple(numbers), runtime_device) == (current, current)
                                 or (tuple(numbers) == current and runtime_device is None),
                                 filesystem.device_numbers_current)
                filesystem.check()  # a stale recorded value admits storage
                self.approved = self.device + 7
                with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                    filesystem.check()
                self.approved, self.mounted = self.device, False
                with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                    filesystem.check()
        # A renumbered loop device is refused whenever the root is pinned,
        # even when the deployment was validated before it appeared.
        self.approved, self.mounted = self.device, True
        loop = FakeSysfs(self)
        loop.node(self.device, "loop")
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            IdentifiedRecordingFilesystem(self.identity(other_numbers(self.device)), metadata)
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            IdentifiedRecordingFilesystem(self.identity(other_major(self.device)), metadata)
        # The UUID must already name the pinned device when the root is pinned.
        self.approved, self.mounted = self.device + 7, True
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            IdentifiedRecordingFilesystem(self.identity(other_numbers(self.device)), metadata)

    def metadata(self) -> Path:
        metadata = self.recordings / "metadata.sqlite3"
        metadata.write_bytes(b"")
        metadata.chmod(0o600)
        return metadata

    def test_backing_topology_is_revalidated_at_every_sample(self):
        # Issue #340: a stale dm device first rests on a hardware disk; a live
        # table reload then moves it onto a loop device (or an md member swap
        # onto an nbd-like virtual disk) without changing its own number, the
        # mount or `st_dev`. The next sample must refuse, and a return to
        # hardware-only backing must admit again (not latched).
        sysfs = FakeSysfs(self)
        disk = sysfs.device(spare_device(self.device, 8, 240), "sdz")
        loop = sysfs.device(spare_device(self.device, 7, 9), "loop9", loop=True)
        nbd = sysfs.device(spare_device(self.device, 43, 7), "nbd7", hardware=False)
        mapped = sysfs.device(self.device, "dm-stale", dm=True, slaves=(disk,))
        filesystem = IdentifiedRecordingFilesystem(
            self.identity(other_numbers(self.device)), self.metadata())
        self.assertFalse(filesystem.device_numbers_current)
        filesystem.check()
        filesystem.snapshot()
        for replacement in (loop, nbd):
            with self.subTest(backing=replacement.name):
                (mapped / "slaves" / disk.name).unlink()
                (mapped / "slaves" / replacement.name).symlink_to(replacement)
                for sample in (filesystem.check, filesystem.snapshot, filesystem.check):
                    with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                        sample()
                # Restored: the very next sample admits again.
                (mapped / "slaves" / replacement.name).unlink()
                (mapped / "slaves" / disk.name).symlink_to(disk)
                filesystem.check()
                filesystem.snapshot()
        # An added loop member beside the hardware disk refuses as well.
        (mapped / "slaves" / loop.name).symlink_to(loop)
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            filesystem.check()
        (mapped / "slaves" / loop.name).unlink()
        # A vanished or unreadable sysfs entry fails closed at the sample.
        (sysfs.root / "dev" / f"{os.major(self.device)}:{os.minor(self.device)}").unlink()
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            filesystem.check()

    def test_a_topology_refusal_is_kept_as_one_value_free_flag(self):
        # Codex P1 on PR #344: an admission's refusal must reach the next tick
        # even when the topology is restored before it; repeated refusals are
        # one flag (bounded), and a UUID/mount refusal does not set it.
        sysfs = FakeSysfs(self)
        disk = sysfs.device(spare_device(self.device, 8, 240), "sdz")
        loop = sysfs.device(spare_device(self.device, 7, 9), "loop9", loop=True)
        mapped = sysfs.device(self.device, "dm-stale", dm=True, slaves=(disk,))
        filesystem = IdentifiedRecordingFilesystem(
            self.identity(other_numbers(self.device)), self.metadata())
        filesystem.check()
        self.assertFalse(filesystem.take_topology_refusal())
        (mapped / "slaves" / disk.name).unlink()
        (mapped / "slaves" / loop.name).symlink_to(loop)
        for _ in range(3):
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                filesystem.snapshot()
        (mapped / "slaves" / loop.name).unlink()
        (mapped / "slaves" / disk.name).symlink_to(disk)
        filesystem.check()
        self.assertIs(True, filesystem.take_topology_refusal())
        self.assertIs(False, filesystem.take_topology_refusal())
        self.approved = self.device + 7
        with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
            filesystem.check()
        self.assertFalse(filesystem.take_topology_refusal())

    def test_a_raising_topology_judgement_fails_closed(self):
        filesystem = IdentifiedRecordingFilesystem(
            self.identity(other_numbers(self.device)), self.metadata())
        with patch("app.monitoring.config._hardware_backed", side_effect=RuntimeError):
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                filesystem.check()
        filesystem.check()

    def test_current_numbers_never_read_sysfs(self):
        current = (os.major(self.device), os.minor(self.device))
        metadata = self.metadata()
        # Even a loop device in sysfs is not re-judged when nothing is stale.
        FakeSysfs(self).node(self.device, "loop")
        with patch("app.monitoring.config._hardware_backed",
                   side_effect=AssertionError("sysfs read")) as walked, \
                patch("app.monitoring.config.SYS_DEV_BLOCK",
                      Path("/nonexistent-sysfs-must-not-be-read")), \
                patch.object(RecordingFilesystem, "recorded_device_numbers_acceptable",
                             side_effect=AssertionError("topology judged")):
            for runtime_device in (None, current):
                filesystem = IdentifiedRecordingFilesystem(
                    self.identity(current, runtime_device), metadata)
                self.assertTrue(filesystem.device_numbers_current)
                filesystem.check()
                filesystem.snapshot()
            walked.assert_not_called()


class StaleDeviceNumbersRuntimeTests(RuntimeFixture):
    """The monitoring runtime starts, reports the stale value and notifies once
    per boot and device numbers (Owner decision 2026-10-22)."""

    def setUp(self):
        super().setUp()
        FakeSysfs(self).node(self.device)
        self.boot = Path(self.temporary.name) / "boot_id"
        self.boot.write_text("6f1c0d7e-3a52-4b8e-9c11-2d4e5f607182\n")
        patcher = patch("app.monitoring.runtime.BOOT_ID_PATH", self.boot)
        patcher.start()
        self.addCleanup(patcher.stop)

    def configuration(self, **overrides):
        configuration = super().configuration(**overrides)
        filesystem = replace(configuration.recording_filesystem,
                             runtime_device=tuple(other_numbers(self.device)))
        return replace(configuration, recording_filesystem=filesystem)

    def notices(self):
        return [text for text in self.slack_texts() if "recording_device" in text]

    async def run_once(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            return runtime.status

    async def test_stale_numbers_start_storage_and_notify_the_owner_once(self):
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertTrue(application.state.audit_storage_admitted)
            self.assertTrue(runtime.status.recording_filesystem_ok)
            self.assertTrue(runtime.status.recording_device_numbers_stale)
            self.assertEqual(StorageState.NORMAL, runtime.status.storage_state)
            await runtime.call(runtime.tick)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(
                ["ServerSentinel attention notice: recording_device_numbers_changed"],
                self.notices())
            self.assertIn(("recording_device_numbers_changed", "sent"), self.events())
            # The daily summary counts the stale value among its errors.
            summary = await runtime.call(runtime._summary, self.clock.utcnow())
            self.assertGreaterEqual(summary.error_count, 1)
        # A restart within the same boot (e.g. a restart loop) finds the row
        # and sends nothing; the stale state stays visible.
        self.clock.advance(timedelta(minutes=5))
        self.assertTrue((await self.run_once()).recording_device_numbers_stale)
        self.assertEqual(1, len(self.notices()))
        # A new boot notifies once more while the value is still stale.
        self.boot.write_text("0b7e2a91-5c3d-4f60-8e12-9a8b7c6d5e4f\n")
        self.clock.advance(timedelta(minutes=5))
        await self.run_once()
        await self.run_once()
        self.assertEqual(2, len(self.notices()))
        self.assertEqual(2, [kind for kind, _ in self.events()].count(
            "recording_device_numbers_changed"))

    def stored_notice(self):
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db:
            return db.execute(
                "SELECT event_id, at, delivery FROM notification_events "
                "WHERE kind='recording_device_numbers_changed'").fetchall()

    def set_delivery(self, delivery):
        with contextlib.closing(sqlite3.connect(self.settings.database_path)) as db, db:
            db.execute("UPDATE notification_events SET delivery=? "
                       "WHERE kind='recording_device_numbers_changed'", (delivery,))

    async def test_a_pending_notice_left_by_a_crash_is_resent_once_with_its_id(self):
        # Codex PR #323: the process exited after the `pending` row was
        # written but before the Slack outcome was stored. The restart in the
        # same boot must not treat that uncertain delivery as done
        # (notifications README: `pending` is never confirmed delivery).
        await self.run_once()
        [(event_id, at, _delivery)] = self.stored_notice()
        self.set_delivery("pending")
        self.clock.advance(timedelta(minutes=5))
        await self.run_once()
        self.assertEqual(2, len(self.notices()))
        # The same row (ID and original time) now holds the outcome.
        self.assertEqual([(event_id, at, "sent")], self.stored_notice())
        # Once the outcome is stored, a further restart sends nothing.
        self.clock.advance(timedelta(minutes=5))
        await self.run_once()
        self.assertEqual(2, len(self.notices()))
        self.assertEqual([(event_id, at, "sent")], self.stored_notice())

    async def test_a_pending_notice_is_resent_once_within_the_restarted_process(self):
        await self.run_once()
        self.set_delivery("pending")
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await runtime.call(runtime.tick)
            await runtime.call(runtime.tick)
            await self.settle(runtime)
        self.assertEqual(2, len(self.notices()))

    async def test_a_final_stored_outcome_is_not_resent(self):
        for delivery in ("sent", "failed", "disabled"):
            with self.subTest(delivery=delivery):
                before = len(self.notices())
                if not before:
                    await self.run_once()
                    before = len(self.notices())
                self.set_delivery(delivery)
                self.clock.advance(timedelta(minutes=5))
                await self.run_once()
                self.assertEqual(before, len(self.notices()))
                self.assertEqual(delivery, self.stored_notice()[0][2])

    async def test_without_a_boot_id_each_start_notifies(self):
        self.boot.unlink()
        await self.run_once()
        self.clock.advance(timedelta(minutes=5))
        await self.run_once()
        self.assertEqual(2, len(self.notices()))

    async def test_current_numbers_send_no_notice(self):
        configuration = super().configuration()
        application = self.application(configuration)
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.assertFalse(runtime.status.recording_device_numbers_stale)
            self.assertNotIn("recording_device_numbers_changed", dict(self.events()))

    async def test_backing_moved_onto_loop_at_runtime_hard_stops_until_restored(self):
        # Issue #340: accepted at open on a hardware-backed dm device, then a
        # live table reload moves it onto a loop device while the number, the
        # mount and `st_dev` stay. The next tick and every admission refuse
        # (STORAGE_HARD_STOP, one immediate alert); restoring resumes them.
        sysfs = FakeSysfs(self)
        disk = sysfs.device(spare_device(self.device, 8, 240), "sdz")
        loop = sysfs.device(spare_device(self.device, 7, 9), "loop9", loop=True)
        mapped = sysfs.device(self.device, "dm-stale", dm=True, slaves=(disk,))

        def recording():
            # Hardware integrity (no approved baseline here) alerts on its own.
            return [text for text in self.slack_texts() if "recording_" in text]

        def admit():
            with runtime._policy.control():
                pass

        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            self.assertEqual(RuntimeState.RUNNING, runtime.status.state)
            self.assertTrue(runtime.status.recording_filesystem_ok)
            self.assertTrue(runtime.status.recording_device_numbers_stale)
            await runtime.call(admit)
            self.assertEqual(["ServerSentinel attention notice: recording_device_numbers_changed"],
                             recording())
            (mapped / "slaves" / disk.name).unlink()
            (mapped / "slaves" / loop.name).symlink_to(loop)
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                await runtime.call(admit)
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            self.assertFalse(runtime.status.recording_filesystem_ok)
            self.assertEqual(StorageState.HARD_STOP, runtime.status.storage_state)
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(["ServerSentinel attention notice: recording_device_numbers_changed",
                              "ServerSentinel critical alert: recording_health_failure"],
                             recording())
            # Restored to hardware-only backing: not latched.
            (mapped / "slaves" / loop.name).unlink()
            (mapped / "slaves" / disk.name).symlink_to(disk)
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            self.assertTrue(runtime.status.recording_filesystem_ok)
            self.assertNotEqual(StorageState.HARD_STOP, runtime.status.storage_state)
            self.assertTrue(runtime.status.recording_device_numbers_stale)
            await runtime.call(admit)
            await self.settle(runtime)
            # The stale-numbers notice stays one per boot and numbers.
            self.assertEqual(1, len(self.notices()))
            self.assertEqual(2, len(recording()))

    async def test_an_admission_only_refusal_alerts_once_at_the_next_tick(self):
        # Codex P1 on PR #344: the backing moves onto a loop device only while
        # admissions run and is restored before the periodic tick. The tick
        # must still raise the one immediate alert for that episode.
        sysfs = FakeSysfs(self)
        disk = sysfs.device(spare_device(self.device, 8, 240), "sdz")
        loop = sysfs.device(spare_device(self.device, 7, 9), "loop9", loop=True)
        mapped = sysfs.device(self.device, "dm-stale", dm=True, slaves=(disk,))

        def alerts():
            return [text for text in self.slack_texts() if "recording_health_failure" in text]

        def admit():
            with runtime._policy.control():
                pass

        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            await self.settle(runtime)
            await runtime.call(admit)
            self.assertEqual([], alerts())
            (mapped / "slaves" / disk.name).unlink()
            (mapped / "slaves" / loop.name).symlink_to(loop)
            for _ in range(3):
                with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                    await runtime.call(admit)
            (mapped / "slaves" / loop.name).unlink()
            (mapped / "slaves" / disk.name).symlink_to(disk)
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(["ServerSentinel critical alert: recording_health_failure"], alerts())
            self.assertEqual(HealthState.FAILED, runtime.status.recording_health)
            self.assertFalse(runtime.status.recording_filesystem_ok)
            # Restored: the next tick recovers without another alert; the
            # health verdict stays FAILED until the next daily self-test.
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertTrue(runtime.status.recording_filesystem_ok)
            self.assertNotEqual(StorageState.HARD_STOP, runtime.status.storage_state)
            await runtime.call(admit)
            self.assertEqual(1, len(alerts()))
            self.assertEqual(HealthState.FAILED, runtime.status.recording_health)
            # A later admission-only episode alerts once more.
            (mapped / "slaves" / disk.name).unlink()
            (mapped / "slaves" / loop.name).symlink_to(loop)
            with self.assertRaisesRegex(RecordingError, "STORAGE_HARD_STOP"):
                await runtime.call(admit)
            (mapped / "slaves" / loop.name).unlink()
            (mapped / "slaves" / disk.name).symlink_to(disk)
            self.clock.advance(timedelta(minutes=1))
            await runtime.call(runtime.tick)
            await self.settle(runtime)
            self.assertEqual(2, len(alerts()))
            self.assertEqual(1, len(self.notices()))

    async def test_renumbered_loop_device_fails_closed_at_runtime(self):
        FakeSysfs(self).node(self.device, "loop")
        application = self.application()
        async with application.router.lifespan_context(application):
            runtime = application.state.monitoring
            self.assertEqual(RuntimeState.FAILED, runtime.status.state)
            self.assertFalse(application.state.audit_storage_admitted)
            await self.settle(runtime)
            self.assertEqual(["ServerSentinel critical alert: recording_health_failure"],
                             self.slack_texts())
            self.assertEqual([], list(self.recordings.iterdir()))


class DiagnosticsTests(unittest.TestCase):
    def test_stale_numbers_show_the_recording_filesystem_degraded(self):
        for stale, expected in ((False, "ok"), (True, "degraded")):
            monitoring = FakeMonitoring(MonitoringStatus(
                RuntimeState.RUNNING, storage_state=StorageState.NORMAL,
                recording_filesystem_ok=True, recording_device_numbers_stale=stale))
            reported = values(CompositeDiagnosticSource((StorageAdapter(monitoring),)).collect())
            self.assertEqual(expected, reported["storage"]["recording_filesystem.state"])
            self.assertEqual("ok", reported["storage"]["storage.state"])


if __name__ == "__main__":
    unittest.main()
