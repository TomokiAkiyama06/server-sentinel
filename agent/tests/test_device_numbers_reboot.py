"""Issue #324: a reboot renumbering of the approved media filesystem.

The Agent counterpart of Main's Issue #321 tests
(`server/tests/test_device_numbers_reboot.py`). UUID + mount stay the identity;
only a same-major, hardware-backed minor change is accepted, as degraded. A
fake sysfs and injected root device stand in for the kernel; no real block
device, mount or capture host is touched.
"""

import contextlib
import dataclasses
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from media_capture_agent import cli
from media_capture_agent.cli import CHECK_WARNINGS, main
from media_capture_agent.config import ExpectedMount
from media_capture_agent.runtime import Agent
from media_capture_agent.storage import (DEVICE_NUMBERS_STALE, MAX_BLOCK_STACK_DEPTH,
                                         MediaStore, Mount, StorageRefused,
                                         block_device_number,
                                         renumbered_device_acceptable)
from tests.support import MockSession, SyntheticCapture, configuration, settings


class FakeSysfs:
    """A disposable sysfs patched in as `/sys/dev/block`.

    Laid out like the kernel's: `dev/<maj>:<min>` links to the device directory
    under `devices/`, a hardware disk has a `device` link to its bus device, a
    partition is a directory inside its parent disk with a `partition`
    attribute, a loop disk has `loop/backing_file` and no `device`, a virtual
    disk (nbd, zram) has neither, a dm device has `dm/` and links its
    underlying devices under `slaves/`.
    """

    def __init__(self, case):
        temporary = tempfile.TemporaryDirectory(prefix="agent-device-numbers-sysfs-")
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("dev", "devices", "bus"):
            (self.root / name).mkdir()
        patcher = patch("media_capture_agent.storage.SYS_DEV_BLOCK", self.root / "dev")
        patcher.start()
        case.addCleanup(patcher.stop)

    def device(self, device, name, *, parent=None, loop=False, dm=False, slaves=(),
               hardware=None):
        directory = (parent if parent is not None else self.root / "devices") / name
        directory.mkdir()
        if hardware is None:
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


DISK = os.makedev(8, 0)


class RenumberingRuleTests(unittest.TestCase):
    """`renumbered_device_acceptable`, parallel to Main's rule tests."""

    def setUp(self):
        self.sysfs = FakeSysfs(self)

    def test_disk_minor_renumbering_is_accepted(self):
        self.sysfs.device(DISK, "sda")
        self.assertTrue(renumbered_device_acceptable((8, 16), DISK))

    def test_equal_numbers_are_accepted_without_sysfs(self):
        loop = os.makedev(7, 0)
        self.assertTrue(renumbered_device_acceptable((7, 0), loop))

    def test_major_change_is_refused(self):
        self.sysfs.device(DISK, "sda")
        self.assertFalse(renumbered_device_acceptable((7, 0), DISK))
        loop = os.makedev(7, 0)
        self.sysfs.device(loop, "loop0", loop=True)
        self.assertFalse(renumbered_device_acceptable((8, 16), loop))
        dm = os.makedev(252, 0)
        self.sysfs.device(dm, "dm-0", dm=True, slaves=(self.sysfs.root / "devices" / "sda",))
        self.assertFalse(renumbered_device_acceptable((8, 0), dm))

    def test_loop_renumbering_is_refused(self):
        loop = os.makedev(7, 3)
        self.sysfs.device(loop, "loop3", loop=True)
        self.assertFalse(renumbered_device_acceptable((7, 0), loop))

    def test_missing_sysfs_entry_is_refused(self):
        self.assertFalse(renumbered_device_acceptable((8, 16), DISK))

    def test_loop_partition_sharing_nvme_major_is_refused(self):
        loop = self.sysfs.device(os.makedev(7, 0), "loop0", loop=True)
        partition = os.makedev(259, 5)
        self.sysfs.device(partition, "loop0p1", parent=loop)
        self.assertFalse(renumbered_device_acceptable((259, 1), partition))

    def test_nvme_partition_and_disk_renumbering_is_accepted(self):
        disk = self.sysfs.device(os.makedev(259, 0), "nvme0n1")
        partition = os.makedev(259, 3)
        self.sysfs.device(partition, "nvme0n1p1", parent=disk)
        self.assertTrue(renumbered_device_acceptable((259, 1), partition))
        self.assertTrue(renumbered_device_acceptable((259, 2), os.makedev(259, 0)))

    def test_dm_renumbering_on_hardware_is_accepted(self):
        disk = self.sysfs.device(os.makedev(259, 0), "nvme0n1")
        partition = self.sysfs.device(os.makedev(259, 1), "nvme0n1p1", parent=disk)
        dm = os.makedev(252, 1)
        self.sysfs.device(dm, "dm-1", dm=True, slaves=(partition,))
        self.assertTrue(renumbered_device_acceptable((252, 0), dm))

    def test_dm_on_loop_or_virtual_disks_is_refused(self):
        loop = self.sysfs.device(os.makedev(7, 0), "loop0", loop=True)
        loop_partition = self.sysfs.device(os.makedev(259, 9), "loop0p1", parent=loop)
        nbd = self.sysfs.device(os.makedev(43, 0), "nbd0", hardware=False)
        hardware = self.sysfs.device(DISK, "sda")
        cases = {
            "dm_on_loop": (os.makedev(252, 1), (loop,)),
            "dm_on_nbd": (os.makedev(252, 2), (nbd,)),
            "dm_mixed_hardware_and_nbd": (os.makedev(252, 3), (hardware, nbd)),
            "dm_without_slaves": (os.makedev(252, 4), ()),
        }
        for name, (device, slaves) in cases.items():
            self.sysfs.device(device, name, dm=True, slaves=slaves)
        # dm -> dm -> loop partition (multi-level stacking).
        inner = self.sysfs.device(os.makedev(252, 5), "dm-inner", dm=True,
                                  slaves=(loop_partition,))
        cases["dm_dm_loop_partition"] = (os.makedev(252, 6), (inner,))
        self.sysfs.device(os.makedev(252, 6), "dm_dm_loop_partition", dm=True,
                          slaves=(inner,))
        for name, (device, _slaves) in cases.items():
            with self.subTest(name=name):
                self.assertFalse(renumbered_device_acceptable((252, 0), device))

    def test_virtual_disk_without_bus_device_is_refused(self):
        nbd = os.makedev(43, 1)
        self.sysfs.device(nbd, "nbd1", hardware=False)
        self.assertFalse(renumbered_device_acceptable((43, 0), nbd))

    def test_broken_slave_link_is_refused(self):
        dm = os.makedev(252, 1)
        directory = self.sysfs.device(dm, "dm-1", dm=True)
        (directory / "slaves").mkdir()
        (directory / "slaves" / "gone").symlink_to(self.sysfs.root / "devices" / "absent")
        self.assertFalse(renumbered_device_acceptable((252, 0), dm))

    def test_stack_deeper_than_bound_is_refused(self):
        below = self.sysfs.device(DISK, "sda")
        for level in range(MAX_BLOCK_STACK_DEPTH + 1):
            below = self.sysfs.device(os.makedev(252, level + 1), f"dm-{level}", dm=True,
                                      slaves=(below,))
        top = os.makedev(252, MAX_BLOCK_STACK_DEPTH + 1)
        self.assertFalse(renumbered_device_acceptable((252, 0), top))
        # A shallow stack on the same hardware disk is accepted.
        self.assertTrue(renumbered_device_acceptable((252, 0), os.makedev(252, 2)))


class RenumberingCase(unittest.TestCase):
    """The real temporary directory's mount, a fake sysfs and injected root device."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-device-numbers-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = settings(self.root)
        self.device = os.stat(self.settings.media_root).st_dev
        self.numbers = (os.major(self.device), os.minor(self.device))
        # Model the temporary tree as its own approved mount, so the case does
        # not depend on whether the runner's temporary directory is on `/`.
        approved = dataclasses.replace(
            self.settings.expected_mount, mount_point=self.root, filesystem_root=Path("/"),
            major=self.numbers[0], minor=self.numbers[1])
        self.settings = dataclasses.replace(self.settings, expected_mount=approved)
        self.mounts = [Mount(dataclasses.replace(approved, filesystem_uuid=None), 1, False)]
        self.sysfs = FakeSysfs(self)
        self.uuid_devices = []

    def renumbered(self, *, major=None, minor=None):
        expected = self.settings.expected_mount
        changed = dataclasses.replace(
            expected, major=self.numbers[0] if major is None else major,
            minor=self.numbers[1] + 1 if minor is None else minor)
        self.settings = dataclasses.replace(self.settings, expected_mount=changed)

    def stable_device(self, expected):
        self.uuid_devices.append((expected.major, expected.minor))
        return True

    def store(self, **kwargs):
        kwargs.setdefault("stable_device", self.stable_device)
        kwargs.setdefault("root_device", lambda: self.device + 1)
        kwargs.setdefault("mounts", lambda: list(self.mounts))
        kwargs.setdefault("mount_id", lambda _fd: 1)
        store = MediaStore(self.settings, **kwargs)
        self.addCleanup(store.close)
        return store

    def hardware(self):
        self.sysfs.device(self.device, "disk")

    def assert_device_refused(self, **kwargs):
        with self.assertRaises(StorageRefused) as raised:
            self.store(**kwargs)
        self.assertEqual((str(raised.exception), raised.exception.diagnostic),
                         ("mount_identity_mismatch", "mount_device_mismatch"))
        self.assertEqual(list(self.settings.media_root.iterdir()), [])



@unittest.skipIf(os.geteuid() == 0, "the Agent refuses root by design")
class MediaStoreRenumberingTests(RenumberingCase):
    """Admission: UUID + mount are the identity; numbers are judged after them."""

    def test_matching_numbers_are_not_stale_and_read_no_sysfs(self):
        store = self.store()
        self.assertFalse(store.device_numbers_stale)
        # No sysfs entry exists: an equal pair never consults it.
        self.assertEqual(list((self.sysfs.root / "dev").iterdir()), [])

    def test_hardware_minor_renumbering_is_accepted_as_stale_and_writes(self):
        self.hardware()
        self.renumbered()
        store = self.store()
        self.assertTrue(store.device_numbers_stale)
        identity = uuid4()
        store.write_segment(identity, b"synthetic renumbered capture")
        self.assertIn(identity, store.list_segments())
        # The UUID was checked against the mounted device, not the stale numbers.
        self.assertTrue(self.uuid_devices)
        self.assertEqual(set(self.uuid_devices), {self.numbers})

    def test_uuid_mismatch_still_refuses_a_renumbered_device(self):
        self.hardware()
        self.renumbered()
        with self.assertRaisesRegex(StorageRefused, "stable_device_mismatch"):
            self.store(stable_device=lambda _expected: False)

    def test_major_change_is_refused(self):
        self.hardware()
        self.renumbered(major=self.numbers[0] + 1, minor=self.numbers[1])
        self.assert_device_refused()

    def test_missing_sysfs_evidence_is_refused(self):
        self.renumbered()
        self.assert_device_refused()

    def test_loop_backed_device_is_refused(self):
        self.sysfs.device(self.device, "loop", loop=True)
        self.renumbered()
        self.assert_device_refused()

    def test_root_filesystem_device_is_refused(self):
        self.hardware()
        self.renumbered()
        self.assert_device_refused(root_device=lambda: self.device)

    def test_approved_root_mount_point_is_never_renumbered(self):
        self.hardware()
        self.renumbered()
        expected = dataclasses.replace(self.settings.expected_mount)
        rooted = dataclasses.replace(expected, mount_point=Path("/"))
        self.settings = dataclasses.replace(self.settings, expected_mount=rooted)
        mount = dataclasses.replace(expected, filesystem_uuid=None, mount_point=Path("/"),
                                    major=self.numbers[0], minor=self.numbers[1])
        self.assert_device_refused(mounts=lambda: [Mount(mount, 1, False)],
                                   mount_id=lambda _fd: 1)

    def test_narrow_service_bind_is_renumbered_with_its_parent(self):
        self.hardware()
        self.renumbered()
        expected = self.settings.expected_mount
        relative = self.settings.media_root.relative_to(expected.mount_point)
        parent = dataclasses.replace(expected, filesystem_uuid=None,
                                     major=self.numbers[0], minor=self.numbers[1])
        bind = dataclasses.replace(parent, mount_point=self.settings.media_root,
                                   filesystem_root=expected.filesystem_root / relative)
        mounts = [Mount(parent, 10, True), Mount(bind, 11, False)]
        store = self.store(mounts=lambda: mounts, mount_id=lambda _fd: 11)
        self.assertTrue(store.device_numbers_stale)
        # A parent on another device does not approve the bind.
        mounts[0] = Mount(dataclasses.replace(parent, minor=self.numbers[1] + 7), 10, True)
        with self.assertRaisesRegex(StorageRefused, "mount_identity_mismatch"):
            store.check()

    def test_backing_topology_is_revalidated_at_every_check(self):
        # A stale dm device first rests on a hardware disk; a live table
        # reload then moves it onto a loop device without changing its own
        # number or the mount ID (Codex P1). The next admission must refuse.
        disk = self.sysfs.device(os.makedev(8, 240), "sdz")
        loop = self.sysfs.device(os.makedev(7, 9), "loop9", loop=True)
        dm = self.sysfs.device(self.device, "dm-stale", dm=True, slaves=(disk,))
        self.renumbered()
        store = self.store()
        self.assertTrue(store.device_numbers_stale)
        first = uuid4()
        store.write_segment(first, b"synthetic hardware-backed capture")
        (dm / "slaves" / disk.name).unlink()
        (dm / "slaves" / loop.name).symlink_to(loop)
        with self.assertRaises(StorageRefused) as raised:
            store.write_segment(uuid4(), b"synthetic loop-backed capture")
        self.assertEqual((str(raised.exception), raised.exception.diagnostic),
                         ("mount_identity_mismatch", "mount_device_mismatch"))
        with self.assertRaises(StorageRefused):
            store.check()
        self.assertEqual(sorted(path.name for path in self.settings.media_root.iterdir()),
                         [f"{first}.segment"])

    def test_bind_with_another_source_than_its_parent_is_refused(self):
        self.hardware()
        self.renumbered()
        expected = self.settings.expected_mount
        relative = self.settings.media_root.relative_to(expected.mount_point)
        parent = dataclasses.replace(expected, filesystem_uuid=None,
                                     major=self.numbers[0], minor=self.numbers[1])
        bind = dataclasses.replace(parent, mount_point=self.settings.media_root,
                                   source="synthetic-other-source",
                                   filesystem_root=expected.filesystem_root / relative)
        mounts = [Mount(parent, 10, True), Mount(bind, 11, False)]
        with self.assertRaises(StorageRefused) as raised:
            self.store(mounts=lambda: mounts, mount_id=lambda _fd: 11)
        self.assertEqual((str(raised.exception), raised.exception.diagnostic),
                         ("mount_identity_mismatch", "mount_source_mismatch"))
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_runtime_mount_replacement_still_refuses_when_stale(self):
        self.hardware()
        self.renumbered()
        expected = dataclasses.replace(self.settings.expected_mount, filesystem_uuid=None,
                                       major=self.numbers[0], minor=self.numbers[1])
        current = [Mount(expected, 1, False)]
        store = self.store(mounts=lambda: current, mount_id=lambda _fd: current[0].mount_id)
        self.assertTrue(store.device_numbers_stale)
        current[0] = dataclasses.replace(current[0], mount_id=2)
        with self.assertRaisesRegex(StorageRefused, "mount_replaced"):
            store.write_segment(uuid4(), b"synthetic")
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_unmounted_media_root_creates_no_fallback(self):
        self.hardware()
        self.renumbered()
        store = self.store()
        self.settings.media_root.rmdir()
        with self.assertRaises(StorageRefused):
            store.write_segment(uuid4(), b"synthetic")
        self.assertFalse(self.settings.media_root.exists())

    def test_pinned_directory_must_be_on_the_device_mountinfo_reports(self):
        # mountinfo claims the recorded numbers while the pinned directory is
        # on another device: a stacked/replaced mount, never a renumbering.
        self.hardware()
        self.renumbered()
        expected = self.settings.expected_mount
        claimed = dataclasses.replace(expected, filesystem_uuid=None)
        self.sysfs.device(os.makedev(expected.major, expected.minor), "claimed")
        for mount in (claimed, dataclasses.replace(claimed, minor=self.numbers[1] + 5)):
            with self.subTest(minor=mount.minor - self.numbers[1]):
                with self.assertRaises(StorageRefused) as raised:
                    self.store(mounts=lambda mount=mount: [Mount(mount, 1, False)])
                self.assertEqual((str(raised.exception), raised.exception.diagnostic),
                                 ("mount_device_mismatch", "mount_replaced"))
        self.assertEqual(list(self.settings.media_root.iterdir()), [])


@unittest.skipIf(os.geteuid() == 0, "the Agent refuses root by design")
class SourceRenameTests(RenumberingCase):
    """sd derives name and minor from one index: `8:16` -> `8:0` renames
    `/dev/sdb1` to `/dev/sda1` (Issue #324 review, important 1)."""

    RECORDED, CURRENT = "/dev/sdb1", "/dev/sda1"

    def setUp(self):
        super().setUp()
        self.hardware()
        self.renumbered()
        self.settings = dataclasses.replace(self.settings, expected_mount=dataclasses.replace(
            self.settings.expected_mount, source=self.RECORDED))
        self.rename(self.CURRENT)
        self.nodes = {self.CURRENT: self.device}

    def rename(self, source, **numbers):
        self.mounts = [Mount(dataclasses.replace(self.mounts[0].identity, source=source,
                                                 **numbers), 1, False)]

    def store(self, **kwargs):
        kwargs.setdefault("block_device", self.nodes.get)
        return super().store(**kwargs)

    def assert_refused(self, diagnostic, **kwargs):
        with self.assertRaises(StorageRefused) as raised:
            self.store(**kwargs)
        self.assertEqual(raised.exception.diagnostic, diagnostic)
        self.assertEqual(list(self.settings.media_root.iterdir()), [])

    def test_sd_rename_with_minor_renumbering_is_accepted_as_stale(self):
        store = self.store()
        self.assertTrue(store.device_numbers_stale)
        identity = uuid4()
        store.write_segment(identity, b"synthetic renamed capture")
        self.assertIn(identity, store.list_segments())

    def test_rename_through_narrow_service_bind_is_accepted(self):
        expected = self.settings.expected_mount
        parent = self.mounts[0].identity
        bind = dataclasses.replace(
            parent, mount_point=self.settings.media_root,
            filesystem_root=expected.filesystem_root
            / self.settings.media_root.relative_to(expected.mount_point))
        mounts = [Mount(parent, 10, True), Mount(bind, 11, False)]
        store = self.store(mounts=lambda: mounts, mount_id=lambda _fd: 11)
        self.assertTrue(store.device_numbers_stale)

    def test_non_kernel_name_shapes_are_refused(self):
        for recorded, current in (("UUID=synthetic", self.CURRENT),
                                  ("/dev/disk/by-uuid/synthetic", self.CURRENT),
                                  (self.RECORDED, "/dev/mapper/synthetic-volume"),
                                  (self.RECORDED, "/dev/../dev/sda1"),
                                  (self.RECORDED, "synthetic-source")):
            with self.subTest(recorded=recorded, current=current):
                self.settings = dataclasses.replace(
                    self.settings, expected_mount=dataclasses.replace(
                        self.settings.expected_mount, source=recorded))
                self.rename(current)
                self.nodes[current] = self.device
                self.assert_refused("mount_source_mismatch")

    def test_current_source_node_must_be_the_mounted_device(self):
        for node in (None, self.device + 1):
            with self.subTest(node=node):
                self.assert_refused("mount_source_mismatch",
                                    block_device=lambda _path, node=node: node)

    def test_rename_with_major_change_is_refused(self):
        self.settings = dataclasses.replace(self.settings, expected_mount=dataclasses.replace(
            self.settings.expected_mount, major=self.numbers[0] + 1, minor=self.numbers[1]))
        self.assert_refused("mount_device_mismatch")

    def test_rename_without_renumbering_is_refused(self):
        self.settings = dataclasses.replace(self.settings, expected_mount=dataclasses.replace(
            self.settings.expected_mount, minor=self.numbers[1]))
        self.assert_refused("mount_source_mismatch")

    def test_rename_without_hardware_evidence_is_refused(self):
        for entry in (self.sysfs.root / "dev").iterdir():
            entry.unlink()
        self.assert_refused("mount_device_mismatch")

    def test_uuid_mismatch_still_refuses_a_renamed_device(self):
        with self.assertRaisesRegex(StorageRefused, "stable_device_mismatch"):
            self.store(stable_device=lambda _expected: False)


@unittest.skipIf(os.geteuid() == 0, "the Agent refuses root by design")
class HeartbeatRenumberingTests(RenumberingCase):
    """The existing heartbeat storage/node fields carry the degraded state."""

    def test_stale_numbers_degrade_node_and_storage_without_values(self):
        self.hardware()
        self.renumbered()
        session = MockSession()
        agent = Agent(self.settings, self.store(), capture=SyntheticCapture(), session=session)
        self.addCleanup(agent.close)
        heartbeat = agent.tick()
        self.assertEqual(heartbeat["node_state"], "degraded")
        self.assertEqual(heartbeat["node_reasons"], ["storage_device_numbers_stale"])
        self.assertEqual(heartbeat["storage"]["state"], "degraded")
        self.assertEqual(heartbeat["storage"]["reason"], DEVICE_NUMBERS_STALE)
        self.assertIn("available_bytes", heartbeat["storage"])
        self.assertEqual(session.heartbeats[-1], heartbeat)
        text = json.dumps(heartbeat)
        for value in (f"{self.numbers[0]}:{self.numbers[1]}",
                      f"{self.numbers[0]}:{self.numbers[1] + 1}"):
            self.assertNotIn(value, text)

    def test_matching_numbers_keep_the_node_online(self):
        session = MockSession()
        agent = Agent(self.settings, self.store(), capture=SyntheticCapture(), session=session)
        self.addCleanup(agent.close)
        heartbeat = agent.tick()
        self.assertEqual((heartbeat["node_state"], heartbeat["storage"]["state"]),
                         ("online", "online"))
        self.assertNotIn("reason", heartbeat["storage"])


@unittest.skipIf(os.geteuid() == 0, "the Agent refuses root by design")
class CheckRenumberingTests(unittest.TestCase):
    """`--check`: an accepted renumbering passes with one value-free warning."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agent-device-numbers-check-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.value = configuration(self.root)
        self.device = os.stat(self.value["media_root"]).st_dev
        self.value["expected_mount"].update(mount_point=str(self.root), filesystem_root="/")
        mount = self.value["expected_mount"]
        self.mounts = [Mount(ExpectedMount(self.root, mount["filesystem"], mount["source"],
                                           os.major(self.device), os.minor(self.device),
                                           Path("/")), 1, False)]
        self.sysfs = FakeSysfs(self)
        self.root_device = self.device + 1

    def write(self, **mount):
        self.value["expected_mount"].update(mount)
        config = self.root / "deployment.json"
        config.write_text(json.dumps(self.value), encoding="utf-8")
        config.chmod(0o600)
        return config

    def run_check(self, config, *, json_output=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--config", str(config), "--check"] + (["--json"] if json_output else [])
        options = {"stable_device": lambda _expected: True,
                   "root_device": lambda: self.root_device,
                   "mounts": lambda: list(self.mounts), "mount_id": lambda _fd: 1}
        with patch.object(cli, "MediaStore", lambda value: MediaStore(value, **options)), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def forbidden(self, config):
        mount = self.value["expected_mount"]
        return {f"{mount['major']}:{mount['minor']}",
                f"{os.major(self.device)}:{os.minor(self.device)}",
                mount["filesystem_uuid"], mount["source"], str(self.root), str(config)}

    def test_stale_numbers_pass_with_fixed_warning(self):
        self.assertIn(DEVICE_NUMBERS_STALE, CHECK_WARNINGS)
        self.sysfs.device(self.device, "disk")
        config = self.write(minor=os.minor(self.device) + 1)
        code, stdout, stderr = self.run_check(config)
        self.assertEqual((code, stdout), (0, "media-capture-agent: local deployment "
                                             "validation passed\n"))
        self.assertEqual(stderr, "media-capture-agent: local deployment validation "
                                 "warning: device_numbers_stale\n")
        code, stdout, stderr = self.run_check(config, json_output=True)
        self.assertEqual((code, json.loads(stdout), stderr),
                         (0, {"ok": True, "warnings": ["device_numbers_stale"]}, ""))
        for output in (stdout, stderr):
            for value in self.forbidden(config):
                self.assertNotIn(value, output)

    def test_unacceptable_renumbering_fails_with_mount_device_mismatch(self):
        config = self.write(minor=os.minor(self.device) + 1)  # no sysfs evidence
        self.assertEqual(self.run_check(config)[0:2], (1, ""))
        self.assertTrue(self.run_check(config)[2].endswith(": mount_device_mismatch\n"))
        self.sysfs.device(self.device, "disk")
        config = self.write(major=os.major(self.device) + 1, minor=os.minor(self.device))
        code, stdout, _stderr = self.run_check(config, json_output=True)
        self.assertEqual((code, json.loads(stdout)),
                         (1, {"ok": False, "reason": "mount_device_mismatch"}))
        self.root_device = self.device
        config = self.write(major=os.major(self.device), minor=os.minor(self.device) + 1)
        code, stdout, _stderr = self.run_check(config, json_output=True)
        self.assertEqual((code, json.loads(stdout)),
                         (1, {"ok": False, "reason": "mount_device_mismatch"}))



class InstallerWarningTests(unittest.TestCase):
    """The installer forwards only the fixed, value-free `--check` warning lines."""

    def test_only_fixed_warning_lines_are_forwarded(self):
        from install import _forward_check_warnings
        warning = "media-capture-agent: local deployment validation warning: device_numbers_stale"
        stderr = "\n".join(["synthetic diagnostic /synthetic/path 8:16", warning,
                            warning + " /synthetic/path", "Traceback (most recent call last):",
                            ""]).encode()
        stream = io.StringIO()
        _forward_check_warnings(stderr, stream)
        self.assertEqual(stream.getvalue(), warning + "\n")
        stream = io.StringIO()
        _forward_check_warnings(b"\xff\xfe", stream)
        self.assertEqual(stream.getvalue(), "")

    def test_stage_forwards_only_fixed_warning_lines_from_check(self):
        import install
        warning = "media-capture-agent: local deployment validation warning: device_numbers_stale"
        temporary = tempfile.TemporaryDirectory(prefix="agent-installer-stage-")
        self.addCleanup(temporary.cleanup)
        destination = Path(temporary.name)
        args = type("Args", (), {"destination": destination, "version": "synthetic-1"})()
        account = type("Account", (), {"pw_uid": os.geteuid(), "pw_gid": os.getegid()})()
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            stderr = "\n".join(["synthetic diagnostic /synthetic/path 8:16", warning,
                                warning + " /synthetic/path", ""]).encode()
            return type("Completed", (), {"returncode": 0, "stderr": stderr})()

        stderr = io.StringIO()
        with patch.object(install.subprocess, "run", run), \
                contextlib.redirect_stderr(stderr):
            executable = install._stage(args, b"synthetic artifact", None, account,
                                        destination / "synthetic-config.json")
        self.assertEqual(stderr.getvalue(), warning + "\n")
        self.assertEqual(executable, destination / "synthetic-1" / "media-capture-agent")
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[-1], "--check")
        self.assertIs(kwargs["stderr"], install.subprocess.PIPE)
        self.assertIs(kwargs["stdout"], install.subprocess.DEVNULL)


class BlockDeviceNumberTests(unittest.TestCase):
    """The default `block_device_number` accepts only block device nodes."""

    def test_character_device_and_missing_path_are_refused(self):
        self.assertIsNone(block_device_number("/dev/null"))
        temporary = tempfile.TemporaryDirectory(prefix="agent-block-device-")
        self.addCleanup(temporary.cleanup)
        self.assertIsNone(block_device_number(str(Path(temporary.name) / "absent")))
        self.assertIsNone(block_device_number(temporary.name))  # a directory

    def test_real_block_device_node_returns_its_rdev_when_present(self):
        try:
            entries = sorted(Path("/dev").iterdir())
        except OSError:
            entries = []
        for entry in entries:
            try:
                info = os.stat(entry, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISBLK(info.st_mode):
                self.assertEqual(block_device_number(str(entry)), info.st_rdev)
                return
        self.skipTest("no block device node is visible in this environment")

    def test_block_device_returns_its_rdev_and_other_kinds_none(self):
        device = os.makedev(8, 1)
        for mode, expected in ((stat.S_IFBLK | 0o660, device),
                               (stat.S_IFCHR | 0o660, None),
                               (stat.S_IFREG | 0o600, None)):
            info = type("Info", (), {"st_mode": mode, "st_rdev": device})()
            with self.subTest(mode=oct(mode)), \
                    patch("media_capture_agent.storage.os.stat", return_value=info):
                self.assertEqual(block_device_number("/dev/synthetic"), expected)

    def test_stat_errors_are_refused(self):
        for error in (PermissionError(13, "synthetic"), ValueError("synthetic")):
            with self.subTest(error=type(error).__name__), \
                    patch("media_capture_agent.storage.os.stat", side_effect=error):
                self.assertIsNone(block_device_number("/dev/synthetic"))


if __name__ == "__main__":
    unittest.main()
