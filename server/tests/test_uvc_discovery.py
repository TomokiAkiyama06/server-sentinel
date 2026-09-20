import errno
import os
from pathlib import Path
import struct
import tempfile
import unittest

from app.cameras.uvc.discovery import (
    DEVICE_CAPS, ENUM_FMT, QUERYCAP, VIDEO_CAPTURE, LinuxDiscovery,
    ProbeError, VideoCapabilities, query_capabilities,
)


class CapabilityTests(unittest.TestCase):
    def fake_ioctl(self, flags, device_flags, formats):
        def ioctl(_fd, command, buffer, _mutate):
            if command == QUERYCAP:
                struct.pack_into("=II", buffer, 84, flags, device_flags)
            elif command == ENUM_FMT:
                index, capture_type = struct.unpack_from("=II", buffer)
                self.assertEqual(capture_type, 1)
                if index >= len(formats):
                    raise OSError(errno.EINVAL, "end")
                buffer[44:48] = formats[index]
            else:
                self.fail("unexpected ioctl")
        return ioctl

    def test_per_node_flags_exclude_metadata_sibling(self):
        result = query_capabilities(4, self.fake_ioctl(DEVICE_CAPS | VIDEO_CAPTURE, 0x00800000, []))
        self.assertIsNone(result)

    def test_video_formats_enumerated_without_audio_operations(self):
        result = query_capabilities(4, self.fake_ioctl(DEVICE_CAPS, VIDEO_CAPTURE, [b"MJPG", b"YUYV"]))
        self.assertEqual(result.formats, ("MJPG", "YUYV"))

    def test_invalid_descriptor_fails_closed(self):
        with self.assertRaises(ProbeError):
            query_capabilities(4, self.fake_ioctl(VIDEO_CAPTURE, 0, [b"bad\x00"]))

    def test_non_einval_driver_failure_not_treated_as_end(self):
        normal = self.fake_ioctl(VIDEO_CAPTURE, 0, [])
        def failed(fd, command, buffer, mutate):
            if command == ENUM_FMT:
                raise OSError(errno.EIO, "synthetic")
            normal(fd, command, buffer, mutate)
        with self.assertRaises(OSError):
            query_capabilities(4, failed)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.sys = root / "sys"
        self.dev = root / "dev"
        self.dev.mkdir()
        self.classes = self.sys / "class/video4linux"
        self.classes.mkdir(parents=True)
        self.usb = self.sys / "devices/synthetic-usb"
        self.usb.mkdir(parents=True)
        for name, value in {"idVendor": "0001", "idProduct": "0002", "serial": "synthetic-only"}.items():
            (self.usb / name).write_text(value)
        self.calls = []

    def add_node(self, name, index):
        node = self.usb / name
        node.mkdir()
        (node / "dev").write_text(f"81:{index}")
        (node / "index").write_text(str(index))
        (node / "device").symlink_to(self.usb, target_is_directory=True)
        (self.classes / name).symlink_to(node, target_is_directory=True)
        (self.dev / name).touch()

    def probe(self, path, device_number):
        self.calls.append((path.name, device_number))
        return VideoCapabilities(1, VIDEO_CAPTURE, ("MJPG",))

    def test_only_video_nodes_probed_and_physical_facts_retained(self):
        self.add_node("video0", 0)
        self.add_node("audio0", 1)
        result = LinuxDiscovery(sys_root=self.sys, dev_root=self.dev, probe=self.probe).scan()
        self.assertEqual(self.calls, [("video0", os.makedev(81, 0))])
        self.assertEqual(result.failures, 0)
        self.assertEqual(result.devices[0].serial, "synthetic-only")
        self.assertEqual(result.devices[0].formats, ("MJPG",))

    def test_one_disconnected_node_does_not_stop_other_discovery(self):
        self.add_node("video0", 0)
        self.add_node("video1", 1)
        def probe(path, number):
            if path.name == "video0":
                raise ProbeError("video descriptor unavailable")
            return self.probe(path, number)
        result = LinuxDiscovery(sys_root=self.sys, dev_root=self.dev, probe=probe).scan()
        self.assertEqual(result.failures, 1)
        self.assertEqual(len(result.devices), 1)

    def test_missing_serial_remains_weak(self):
        self.add_node("video0", 0)
        (self.usb / "serial").unlink()
        result = LinuxDiscovery(sys_root=self.sys, dev_root=self.dev, probe=self.probe).scan()
        self.assertIsNone(result.devices[0].strong_key)

    def test_recreated_sysfs_node_has_a_new_instance_not_a_durable_identity(self):
        self.add_node("video0", 0)
        (self.usb / "serial").unlink()
        discovery = LinuxDiscovery(sys_root=self.sys, dev_root=self.dev, probe=self.probe)
        before = discovery.scan().devices[0]
        (self.usb / "video0").rename(self.usb / "removed-video0")
        (self.classes / "video0").unlink()
        self.add_node("video0", 0)
        after = discovery.scan().devices[0]
        self.assertEqual(before.device_path, after.device_path)
        self.assertNotEqual(before.instance_token, after.instance_token)
        self.assertIsNone(after.strong_key)

    def test_missing_sysfs_tree_is_empty(self):
        result = LinuxDiscovery(sys_root=self.sys / "absent", dev_root=self.dev, probe=self.probe).scan()
        self.assertEqual(result.devices, ())
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
