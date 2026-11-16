"""Issue #301 / #405: the LXD host's read-only USB camera check (`infra/lxd/usb_repass.py`).

Owner decision 2026-11-16 (Issue #405): the check never removes or adds a
device; it reports a camera that looks not passed and the re-pass is done by
hand. Synthetic only: a fake sysfs and /proc tree in a temporary directory,
an in-memory LXD and, for the REST client, a local unix-socket HTTP server.
No real LXD, camera or host is touched. Serials and ids below are invented.
"""

import contextlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("usb_repass", ROOT / "infra/lxd/usb_repass.py")
repass = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repass)

VENDOR, PRODUCT = "1d50", "6089"
SERIAL_1, SERIAL_2 = "SYNTH0001", "SYNTH0002"
PID = 4242
ATTENTION = "usb_repass_attention see=infra/lxd/README.md#manual-re-pass"


def camera(serial, **extra):
    return {"type": "usb", "vendorid": VENDOR, "productid": PRODUCT, "serial": serial, **extra}


class FakeLxd:
    """In-memory, read-only LXD: only the two reads the check may make.

    Any other attribute (a write of any kind) raises AttributeError, so a
    code path that tried to change the instance would fail the test.
    """

    def __init__(self, devices):
        self.devices = devices
        self.status = "Running"
        self.reads = []
        self.unreachable = 0  # instance reads that fail with `read_failure`
        self.read_failure = "usb_repass_lxd_unreachable"
        self.pid = PID

    def __call__(self, socket_path):
        return self

    def instance(self, name):
        self.reads.append(("instance", name))
        if self.unreachable:
            self.unreachable -= 1
            raise repass.Failure(self.read_failure)
        return {"status": self.status, "devices": json.loads(json.dumps(self.devices)),
                "config": {}, "profiles": ["default"]}

    def state(self, name):
        self.reads.append(("state", name))
        return {"pid": self.pid, "status": self.status}


class Host:
    """A fake sysfs and /proc for one QEMU process."""

    def __init__(self, base):
        self.sysfs = base / "sys"
        self.proc = base / "proc"
        self.sysfs.mkdir()
        (self.proc / str(PID) / "fd").mkdir(parents=True)
        self.uptime = 100000.0
        (self.proc / "uptime").write_text(f"{self.uptime:.2f} 1.00\n")
        self.set_age(3600)
        self.nodes = {}
        self.fd = 3

    def set_age(self, seconds):
        ticks = os.sysconf("SC_CLK_TCK")
        start = int((self.uptime - seconds) * ticks)
        fields = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 10
        (self.proc / str(PID) / "stat").write_text(f"{PID} (qemu-system-x86) " + " ".join(fields))

    def boot(self, uptime):
        """The host booted `uptime` seconds ago; QEMU started with it."""
        self.uptime = uptime
        (self.proc / "uptime").write_text(f"{uptime:.2f} 1.00\n")
        self.set_age(uptime)

    def plug(self, serial, bus, dev, entry=None, vendor=VENDOR):
        path = self.sysfs / (entry or f"{bus}-{dev}")
        path.mkdir(exist_ok=True)
        for name, value in (("idVendor", vendor), ("idProduct", PRODUCT), ("serial", serial),
                            ("busnum", str(bus)), ("devnum", str(dev))):
            (path / name).write_text(value + "\n")
        self.nodes[serial] = f"/dev/bus/usb/{bus:03d}/{dev:03d}"

    def link(self, target):
        os.symlink(target, self.proc / str(PID) / "fd" / str(self.fd))
        self.fd += 1

    def hold(self, serial, deleted=False):
        self.link(self.nodes[serial] + (" (deleted)" if deleted else ""))


def snapshot(directory):
    """Every file under `directory` with its bytes and mtime."""
    found = {}
    for path in sorted(Path(directory).rglob("*")):
        if path.is_file():
            found[str(path)] = (path.read_bytes(), path.stat().st_mtime_ns)
    return found


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, True)
        self.host = Host(self.base)
        self.state = self.base / "state"
        self.state.mkdir()
        self.config = self.base / "config.json"
        self.write_config({"instance": "vm", "devices": ["cam1", "cam2"]})
        self.lxd = FakeLxd({"cam1": camera(SERIAL_1), "cam2": camera(SERIAL_2),
                            "eth0": {"type": "nic"}})
        self.clock = [1_000_000.0]
        self.sleeps = []

    def write_config(self, value, mode=0o600):
        self.config.write_text(json.dumps(value))
        os.chmod(self.config, mode)

    def write_state(self, pending, history=None):
        (self.state / "state.json").write_text(json.dumps({"pending": pending, "history": history or {}}))

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.clock[0] += seconds

    def run_once(self, check=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = repass.run(str(self.config), str(self.state), check=check, lxd_factory=self.lxd,
                              sleep=self.sleep, monotonic=lambda: self.clock[0],
                              sysfs=str(self.host.sysfs), proc=str(self.host.proc),
                              config_owner=os.getuid())
        return code, output.getvalue().splitlines()

    def looks_unpassed(self):
        """cam1 re-enumerated: QEMU holds only its deleted old node (2026-11-08)."""
        self.host.plug(SERIAL_1, 1, 15)
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.write_config({"instance": "vm", "devices": ["cam1"]})

    def test_held_cameras_are_reported_held_without_a_settle(self):
        self.host.plug(SERIAL_1, 1, 15)
        self.host.plug(SERIAL_2, 9, 4)
        self.host.hold(SERIAL_1)
        self.host.hold(SERIAL_2)
        held = ["usb_repass_held device=cam1", "usb_repass_held device=cam2"]
        self.assertEqual((0, held), self.run_once())
        # Issue #402 (9): every camera held in one sample.
        self.assertEqual([], self.sleeps)
        self.assertEqual((0, held), self.run_once(check=True))

    def test_a_camera_not_held_is_reported_after_the_settle_and_two_samples(self):
        self.host.plug(SERIAL_1, 1, 15)
        self.host.plug(SERIAL_2, 9, 4)
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.host.hold(SERIAL_2)
        code, lines = self.run_once()
        self.assertEqual([repass.SETTLE_SECONDS, repass.STABLE_GAP_SECONDS], self.sleeps)
        self.assertEqual((1, ["usb_repass_looks_unpassed device=cam1", "usb_repass_held device=cam2",
                              "usb_repass_qemu_usb_fds live=1 deleted=1", ATTENTION]), (code, lines))
        # Only reads, and cam1 is still configured as it was.
        self.assertEqual({"instance", "state"}, {kind for kind, _ in self.lxd.reads})
        self.assertEqual(camera(SERIAL_1), self.lxd.devices["cam1"])

    def test_check_reports_the_same_without_the_settle_and_exits_zero(self):
        self.looks_unpassed()
        self.assertEqual((0, ["usb_repass_looks_unpassed device=cam1",
                              "usb_repass_qemu_usb_fds live=0 deleted=1", ATTENTION]),
                         self.run_once(check=True))
        self.assertEqual([repass.STABLE_GAP_SECONDS], self.sleeps)

    def test_the_judgement_is_repeated_and_never_acts(self):
        # Every run reports again (nothing is remembered or rate limited) and
        # the instance and the state directory never change.
        self.looks_unpassed()
        before = snapshot(self.state)
        for _ in range(3):
            self.assertEqual(1, self.run_once()[0])
        self.assertEqual(camera(SERIAL_1), self.lxd.devices["cam1"])
        self.assertEqual(before, snapshot(self.state))
        self.assertEqual([], os.listdir(self.state))

    def test_logs_hold_no_identifier(self):
        self.looks_unpassed()
        self.write_state({"cam1": camera(SERIAL_1)})
        del self.lxd.devices["cam1"]
        _, lines = self.run_once()
        self.lxd.devices["cam1"] = camera(SERIAL_1)
        _, more = self.run_once()
        text = "\n".join(lines + more)
        for value in (SERIAL_1, VENDOR, PRODUCT, "/dev/bus", "001", "015"):
            self.assertNotIn(value, text)

    def test_absent_ambiguous_unsettled_and_unidentified_ask_for_nothing(self):
        self.write_config({"instance": "vm", "devices": ["cam1", "cam2", "cam3", "cam4"]})
        self.lxd.devices["cam3"] = {"type": "usb", "vendorid": VENDOR, "productid": PRODUCT}
        self.lxd.devices["cam4"] = camera("SYNTH0004")
        # cam1 absent; cam2 twice on the host (duplicate serial); cam3 has no
        # serial and its camera is present; cam4 re-numbers between samples.
        self.host.plug(SERIAL_2, 2, 5, entry="2-1")
        self.host.plug(SERIAL_2, 3, 6, entry="3-1")
        self.host.plug("", 4, 7, entry="4-1")
        self.host.plug("SYNTH0004", 5, 8, entry="5-1")
        original = self.sleep

        def renumber(seconds):
            original(seconds)
            if seconds == repass.STABLE_GAP_SECONDS:
                self.host.plug("SYNTH0004", 5, 9, entry="5-1")
        self.sleep = renumber
        self.assertEqual((0, ["usb_repass_absent device=cam1", "usb_repass_ambiguous device=cam2",
                              "usb_repass_unidentified device=cam3", "usb_repass_unsettled device=cam4",
                              "usb_repass_qemu_usb_fds live=0 deleted=0"]), self.run_once())

    def test_a_configured_device_missing_from_the_instance_asks_for_attention(self):
        # e.g. a manual re-pass whose add did not happen.
        self.write_config({"instance": "vm", "devices": ["eth0", "camX"]})
        self.assertEqual((1, ["usb_repass_unidentified device=eth0", "usb_repass_not_configured device=camX",
                              "usb_repass_qemu_usb_fds live=0 deleted=0", ATTENTION]), self.run_once())

    def test_pinned_or_duplicate_devices_are_not_judged(self):
        self.host.plug(SERIAL_1, 1, 15)
        self.host.plug(SERIAL_2, 9, 4)
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.lxd.devices["cam1"] = camera(SERIAL_1, busnum="1")
        self.lxd.devices["cam2"] = camera(SERIAL_2, devnum="2")
        _, lines = self.run_once()
        self.assertEqual(["usb_repass_unidentified device=cam1", "usb_repass_unidentified device=cam2"],
                         lines[:2])
        self.lxd.devices["cam1"] = camera(SERIAL_1)
        self.lxd.devices["cam2"] = camera(SERIAL_1)
        _, lines = self.run_once()
        self.assertEqual(["usb_repass_ambiguous device=cam1", "usb_repass_ambiguous device=cam2"], lines[:2])

    def test_not_running_or_starting_vm_is_not_judged(self):
        self.looks_unpassed()
        self.lxd.status = "Stopped"
        self.assertEqual((0, ["usb_repass_instance_not_running"]), self.run_once())
        self.lxd.status = "Running"
        # Issue #405: the VM start's own USB resets came after 120 s.
        self.assertGreaterEqual(repass.MIN_QEMU_AGE_SECONDS, 300)
        self.host.set_age(repass.MIN_QEMU_AGE_SECONDS - 1)
        self.assertEqual((0, ["usb_repass_instance_starting"]), self.run_once())
        self.host.set_age(repass.MIN_QEMU_AGE_SECONDS + 1)
        self.assertEqual(1, self.run_once()[0])
        # No usable QEMU pid: a fixed failure, never a judgement.
        for pid in (None, 0, "4242"):
            with self.subTest(pid=pid):
                self.lxd.pid = pid
                with self.assertRaisesRegex(repass.Failure, "usb_repass_qemu_unreadable"):
                    self.run_once()

    def test_pending_records_are_reported_and_never_restored(self):
        # 2026-11-08: the old automatic re-pass left records behind.
        self.host.plug(SERIAL_1, 1, 15)
        self.host.plug(SERIAL_2, 9, 4)
        self.host.hold(SERIAL_1)
        self.host.hold(SERIAL_2)
        self.write_state({"cam1": camera(SERIAL_1), "cam2": camera(SERIAL_2, required="false"),
                          "cam9": camera("SYNTH0009")}, {"cam1": [1.0]})
        before = snapshot(self.state)
        code, lines = self.run_once()
        self.assertEqual((1, ["usb_repass_pending_record device=cam1",
                              "usb_repass_pending_record device=cam2",
                              "usb_repass_pending_record device=cam9",
                              "usb_repass_pending_device_present device=cam1",
                              "usb_repass_pending_device_differs device=cam2",
                              "usb_repass_pending_device_missing device=cam9",
                              "usb_repass_held device=cam1", "usb_repass_held device=cam2",
                              ATTENTION]), (code, lines))
        # Not added back, and the record is kept for the manual step.
        self.assertNotIn("cam9", self.lxd.devices)
        self.assertEqual(before, snapshot(self.state))
        # A stale record alone (the device is there as recorded) asks for nothing.
        self.write_state({"cam1": camera(SERIAL_1)})
        self.assertEqual((0, ["usb_repass_pending_record device=cam1",
                              "usb_repass_pending_device_present device=cam1",
                              "usb_repass_held device=cam1", "usb_repass_held device=cam2"]),
                         self.run_once())

    def test_pending_records_are_reported_while_the_vm_is_stopped_and_lxd_is_not_ready(self):
        self.write_state({"cam1": camera(SERIAL_1)})
        del self.lxd.devices["cam1"]
        self.lxd.status = "Stopped"
        self.assertEqual((0, ["usb_repass_pending_record device=cam1",
                              "usb_repass_pending_device_missing device=cam1",
                              "usb_repass_instance_not_running", ATTENTION]), self.run_once(check=True))
        self.assertEqual(1, self.run_once()[0])
        # Shown before anything that needs LXD (PR #419 review).
        self.host.boot(30)
        self.lxd.unreachable = 1000
        self.assertEqual((0, ["usb_repass_pending_record device=cam1", "usb_repass_lxd_not_ready"]),
                         self.run_once(check=True))

    def test_an_unreadable_state_is_reported_kept_and_the_cameras_are_still_judged(self):
        self.host.plug(SERIAL_1, 1, 15)
        self.host.hold(SERIAL_1)
        self.write_config({"instance": "vm", "devices": ["cam1"]})
        for content in (b"{not json", b'{"pending": [], "history": {}}',
                        b'{"pending": {"../x": {}}, "history": {}}', b'[]'):
            with self.subTest(content=content):
                (self.state / "state.json").write_bytes(content)
                self.assertEqual((1, ["usb_repass_state_unreadable", "usb_repass_held device=cam1",
                                      ATTENTION]), self.run_once())
                self.assertEqual(content, (self.state / "state.json").read_bytes())
        # The history the old version wrote is ignored, whatever it holds.
        self.write_state({}, {"cam1": "not a list"})
        self.assertEqual((0, ["usb_repass_held device=cam1"]), self.run_once())

    def test_lxd_not_answering_right_after_boot_is_waited_for(self):
        # Issue #402 (7).
        self.looks_unpassed()
        self.host.boot(30)
        self.lxd.unreachable = 2
        self.assertEqual((0, ["usb_repass_instance_starting"]), self.run_once())
        self.assertEqual([repass.LXD_WAIT_GAP_SECONDS] * 2, self.sleeps)

    def test_lxd_still_not_answering_after_boot_ends_the_run_without_failing(self):
        self.looks_unpassed()
        self.host.boot(30)
        self.lxd.unreachable = 1000
        self.assertEqual((0, ["usb_repass_lxd_not_ready"]), self.run_once())
        self.assertLessEqual(sum(self.sleeps), repass.LXD_WAIT_SECONDS)

    def test_lxd_not_answering_later_than_boot_still_fails(self):
        self.looks_unpassed()
        self.host.boot(repass.BOOT_GRACE_SECONDS + 1)
        self.lxd.unreachable = 1000
        with self.assertRaisesRegex(repass.Failure, "usb_repass_lxd_unreachable"):
            self.run_once()
        self.assertEqual([], self.sleeps)
        self.host.boot(30)
        self.lxd.unreachable = 1
        self.lxd.read_failure = "usb_repass_instance_unreadable"
        with self.assertRaisesRegex(repass.Failure, "usb_repass_instance_unreadable"):
            self.run_once()
        self.assertEqual([], self.sleeps)

    def test_configuration_is_validated(self):
        self.write_config({"instance": "vm", "devices": ["cam1"]}, mode=0o620)
        with self.assertRaisesRegex(repass.Failure, "usb_repass_config_unsafe"):
            self.run_once()
        self.write_config({"instance": "vm", "devices": ["cam1"]})
        with self.assertRaisesRegex(repass.Failure, "usb_repass_config_unsafe"):
            repass.load_config(str(self.config), owner=os.getuid() + 1)
        for value in ({"instance": "vm"}, {"instance": "vm", "devices": []},
                      {"instance": "vm", "devices": ["a", "a"]},
                      {"instance": "vm", "devices": ["c1", "c2", "c3", "c4", "c5"]},
                      {"instance": "vm;rm", "devices": ["cam1"]},
                      {"instance": "vm", "devices": ["../cam"]},
                      {"instance": "vm", "devices": ["cam1"], "socket": "relative"},
                      {"instance": "vm", "devices": ["cam1"], "extra": 1}, ["cam1"]):
            with self.subTest(value=value):
                self.write_config(value)
                with self.assertRaisesRegex(repass.Failure, "usb_repass_config_invalid"):
                    self.run_once()
        os.unlink(self.config)
        os.symlink(self.base / "missing", self.config)
        with self.assertRaisesRegex(repass.Failure, "usb_repass_config_unreadable"):
            self.run_once()

    def test_identity_needs_all_three_values(self):
        self.assertEqual((VENDOR, PRODUCT, SERIAL_1), repass.identity(camera(SERIAL_1)))
        self.assertEqual(("1d50", "abcd", "S"), repass.identity(camera("S", productid="ABCD")))
        for device in ({"type": "usb", "vendorid": VENDOR, "productid": PRODUCT},
                       camera(""), camera(SERIAL_1, vendorid="zz"), {**camera(SERIAL_1), "type": "disk"},
                       "usb"):
            with self.subTest(device=device):
                self.assertIsNone(repass.identity(device))

    def test_deleted_nodes_are_counted_not_held(self):
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.host.link("/dev/bus/usb/001/004 (deleted)")
        self.host.link("/dev/kvm")
        self.host.link("/dev/bus/usb/009/004")
        self.host.link("/dev/bus/usb/009/004")
        self.assertEqual(({"/dev/bus/usb/009/004"}, 2), repass.usb_fds(PID, str(self.host.proc)))
        self.assertEqual({"/dev/bus/usb/009/004"}, repass.held_nodes(PID, str(self.host.proc)))

    def test_main_requires_root_and_reports_failures_with_a_fixed_word(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(repass.os, "geteuid", return_value=1000):
            self.assertEqual(2, repass.main(["--config", str(self.config)]))
        self.assertEqual("usb_repass_requires_root\n", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(repass.os, "geteuid", return_value=0):
            self.assertEqual(1, repass.main(["--config", str(self.base / "missing.json"), "--check"]))
        self.assertEqual("usb_repass_config_unreadable\n", output.getvalue())


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def address_string(self):
        return "local"

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("ETag", "etag-1")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        server = self.server
        server.seen.append(("GET", self.path))
        if self.path == "/1.0/instances/vm":
            self._reply(200, server.instance_body or {"type": "sync", "metadata": server.instance})
        elif self.path == "/1.0/instances/vm/state":
            self._reply(200, {"type": "sync", "metadata": {"pid": PID, "status": "Running"}})
        else:
            self._reply(404, {"error": "not found"})

    def _write(self):
        self.server.seen.append((self.command, self.path))
        self._reply(500, {"error": "the check must never write"})

    do_PUT = do_POST = do_DELETE = do_PATCH = _write


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class LxdClientTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        self.path = os.path.join(directory, "unix.socket")
        self.server = _Server(self.path, _Handler)
        self.server.seen = []
        self.server.instance_body = None
        self.server.instance = {"architecture": "x86_64", "config": {}, "devices":
                                {"cam1": camera(SERIAL_1), "root": {"type": "disk"}},
                                "status": "Running", "name": "vm"}
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_a_camera_that_looks_unpassed_is_judged_with_get_requests_only(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        host = Host(base)
        host.plug(SERIAL_1, 1, 15)
        host.link("/dev/bus/usb/001/003 (deleted)")
        config = base / "config.json"
        config.write_text(json.dumps({"instance": "vm", "devices": ["cam1"], "socket": self.path}))
        os.chmod(config, 0o600)
        state = base / "state"
        state.mkdir()
        (state / "state.json").write_text(json.dumps({"pending": {"cam1": camera(SERIAL_1)}}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = repass.run(str(config), str(state), sleep=lambda s: None, sysfs=str(host.sysfs),
                              proc=str(host.proc), config_owner=os.getuid())
        self.assertEqual(1, code)
        self.assertIn("usb_repass_looks_unpassed device=cam1", output.getvalue())
        self.assertIn("usb_repass_pending_device_present device=cam1", output.getvalue())
        self.assertEqual({"GET"}, {method for method, _ in self.server.seen})
        self.assertEqual({"/1.0/instances/vm", "/1.0/instances/vm/state"},
                         {path for _, path in self.server.seen})

    def test_unreadable_answers_raise_fixed_words(self):
        client = repass.Lxd(self.path)
        self.server.instance_body = ["not", "an", "object"]
        with self.assertRaisesRegex(repass.Failure, "usb_repass_lxd_invalid"):
            client.instance("vm")
        self.server.instance_body = {"type": "sync", "metadata": {"devices": ["x"]}}
        with self.assertRaisesRegex(repass.Failure, "usb_repass_instance_unreadable"):
            client.instance("vm")
        with self.assertRaisesRegex(repass.Failure, "usb_repass_instance_unreadable"):
            client.instance("other")
        with self.assertRaisesRegex(repass.Failure, "usb_repass_lxd_unreachable"):
            repass.Lxd(self.path + ".missing").instance("vm")


class PackagingTests(unittest.TestCase):
    def test_the_script_has_no_write_path(self):
        # Owner decision 2026-11-16 (Issue #405): no remove, add or restore.
        source = (ROOT / "infra/lxd/usb_repass.py").read_text()
        for word in ('"PUT"', '"POST"', '"DELETE"', '"PATCH"', "put_devices", "remove_device",
                     "add_device", "If-Match", "os.replace", "O_WRONLY", "O_CREAT", "makedirs",
                     "fcntl"):
            with self.subTest(word=word):
                self.assertNotIn(word, source)
        self.assertFalse(hasattr(repass.Lxd, "request"))
        self.assertEqual(1, source.count('connection.request("GET", url)'))
        self.assertEqual(1, source.count("connection.request("))

    def test_units_have_no_udev_trigger_and_nothing_writable(self):
        directory = ROOT / "infra/lxd"
        self.assertEqual([], sorted(p.name for p in directory.glob("*.rules*")))
        service = (directory / "server-sentinel-usb-repass.service").read_text()
        timer = (directory / "server-sentinel-usb-repass.timer").read_text()
        self.assertIn("/usr/bin/python3 -I -S /usr/local/lib/server-sentinel-usb-repass/usb_repass.py", service)
        for line in ("RestrictAddressFamilies=AF_UNIX", "PrivateNetwork=yes", "ProtectSystem=strict",
                     "CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH", "NoNewPrivileges=yes",
                     "Type=oneshot", f"TimeoutStartSec={repass.UNIT_TIMEOUT_SECONDS}"):
            with self.subTest(line=line):
                self.assertIn(f"\n{line}\n", service)
        for word in ("StateDirectory", "ReadWritePaths", "OnFailure", "Environment"):
            self.assertNotIn(word, service)
        self.assertLess(repass.RUN_WORST_SECONDS + 60, repass.UNIT_TIMEOUT_SECONDS)
        self.assertIn("WantedBy=timers.target", timer)
        self.assertIn("\nOnUnitActiveSec=5min\n", timer)
        self.assertNotIn("OnUnitInactiveSec", timer)
        # The first timer run comes after the boot grace (Issue #402 (7)).
        self.assertIn("\nOnBootSec=10min\n", timer)
        self.assertLess(repass.BOOT_GRACE_SECONDS, 600)
        example = json.loads((directory / "usb-repass.example.json").read_text())
        self.assertEqual({"instance", "devices"}, set(example))

    def test_standard_library_only(self):
        source = (ROOT / "infra/lxd/usb_repass.py").read_text()
        imports = {line.split()[1].split(".")[0] for line in source.splitlines()
                   if line.startswith(("import ", "from "))}
        self.assertLessEqual(imports, {"argparse", "http", "json", "os", "re", "socket",
                                       "stat", "sys", "time"})


if __name__ == "__main__":
    unittest.main()
