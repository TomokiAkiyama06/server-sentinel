"""Issue #301 item 1: the LXD host's USB camera re-pass (`infra/lxd/usb_repass.py`).

Synthetic only: a fake sysfs and /proc tree in a temporary directory, an
in-memory LXD and, for the REST client, a local unix-socket HTTP server. No
real LXD, camera or host is touched. Serials and ids below are invented.
"""

import contextlib
import http.server
import importlib.util
import io
import json
import os
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("usb_repass", ROOT / "infra/lxd/usb_repass.py")
repass = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repass)

VENDOR, PRODUCT = "1d50", "6089"
SERIAL_1, SERIAL_2 = "SYNTH0001", "SYNTH0002"
PID = 4242


def camera(serial, **extra):
    return {"type": "usb", "vendorid": VENDOR, "productid": PRODUCT, "serial": serial, **extra}


class FakeLxd:
    """In-memory LXD: the instance's devices, an ETag and the QEMU fd tree."""

    def __init__(self, devices, host):
        self.devices = devices
        self.status = "Running"
        self.etag = 0
        self.puts = []
        self.fail = []  # "remove" / "add" outcomes to fail, in order
        self.before_put = []  # edits made just before the next PUT's GET
        self.host = host

    def __call__(self, socket_path):
        return self

    def instance(self, name):
        return {"status": self.status, "devices": json.loads(json.dumps(self.devices)),
                "config": {}, "profiles": ["default"]}, str(self.etag)

    def state(self, name):
        return {"pid": PID, "status": self.status}

    def put_devices(self, name, change, require=None):
        if self.before_put:
            self.before_put.pop(0)()
        current = json.loads(json.dumps(self.devices))
        if require is not None and not require(current):
            raise repass.Failure("usb_repass_changed")
        new = change(current)
        kind = "add" if len(new) > len(self.devices) else "remove"
        if self.fail and self.fail[0] == kind:
            self.fail.pop(0)
            raise repass.Failure("usb_repass_update_failed")
        added = set(new) - set(self.devices)
        self.devices = new
        self.etag += 1
        self.puts.append((kind, sorted(new)))
        for label in added:
            # QEMU opens the current node of a passed device.
            self.host.hold(new[label]["serial"])


class Host:
    """A fake sysfs and /proc for one QEMU process."""

    def __init__(self, base):
        self.sysfs = base / "sys"
        self.proc = base / "proc"
        self.sysfs.mkdir()
        (self.proc / str(PID) / "fd").mkdir(parents=True)
        (self.proc / "uptime").write_text("100000.00 1.00\n")
        ticks = os.sysconf("SC_CLK_TCK")
        self.set_age(3600, ticks)
        self.nodes = {}
        self.fd = 3

    def set_age(self, seconds, ticks=None):
        ticks = ticks or os.sysconf("SC_CLK_TCK")
        start = int((100000.0 - seconds) * ticks)
        fields = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 10
        (self.proc / str(PID) / "stat").write_text(f"{PID} (qemu-system-x86) " + " ".join(fields))

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

    def held(self):
        return repass.held_nodes(PID, str(self.proc))


class RepassTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.base, ignore_errors=True))
        self.host = Host(self.base)
        self.state = self.base / "state"
        self.state.mkdir()
        self.config = self.base / "config.json"
        self.write_config({"instance": "vm", "devices": ["cam1", "cam2"]})
        self.lxd = FakeLxd({"cam1": camera(SERIAL_1), "cam2": camera(SERIAL_2),
                            "eth0": {"type": "nic"}}, self.host)
        self.clock = [1_000_000.0]
        self.sleeps = []

    def write_config(self, value, mode=0o600):
        self.config.write_text(json.dumps(value))
        os.chmod(self.config, mode)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.clock[0] += seconds

    def run_once(self, check=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = repass.run(str(self.config), str(self.state), check=check, lxd_factory=self.lxd,
                              sleep=self.sleep, now=lambda: self.clock[0],
                              sysfs=str(self.host.sysfs), proc=str(self.host.proc),
                              config_owner=os.getuid())
        return code, output.getvalue().splitlines()

    def test_held_cameras_are_left_alone(self):
        self.host.plug(SERIAL_1, 1, 15)
        self.host.plug(SERIAL_2, 9, 4)
        self.host.hold(SERIAL_1)
        self.host.hold(SERIAL_2)
        self.assertEqual((0, ["usb_repass_held device=cam1", "usb_repass_held device=cam2"]),
                         self.run_once())
        self.assertEqual([], self.lxd.puts)
        # The host was sampled after the settle and twice.
        self.assertEqual([repass.SETTLE_SECONDS, repass.STABLE_GAP_SECONDS], self.sleeps)

    def test_a_re_enumerated_camera_is_removed_and_added_with_its_configuration(self):
        # 2026-11-08 on the real host: QEMU still held the deleted old node.
        self.lxd.devices["cam1"] = camera(SERIAL_1, required="false")
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.host.plug(SERIAL_1, 1, 15, entry="1-2")
        self.host.plug(SERIAL_2, 9, 4)
        self.host.hold(SERIAL_2)
        code, lines = self.run_once()
        self.assertEqual(0, code)
        self.assertEqual([("remove", ["cam2", "eth0"]), ("add", ["cam1", "cam2", "eth0"])], self.lxd.puts)
        self.assertEqual(camera(SERIAL_1, required="false"), self.lxd.devices["cam1"])
        self.assertEqual(["usb_repass_done device=cam1", "usb_repass_held device=cam2"], lines)
        saved = json.loads((self.state / "state.json").read_text())
        self.assertEqual({}, saved["pending"])
        self.assertEqual(1, len(saved["history"]["cam1"]))
        self.assertEqual(0o600, os.stat(self.state / "state.json").st_mode & 0o777)

    def needs_repass(self):
        self.host.plug(SERIAL_1, 1, 15)
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.write_config({"instance": "vm", "devices": ["cam1"]})

    def test_logs_hold_no_identifier(self):
        self.needs_repass()
        _, lines = self.run_once()
        text = "\n".join(lines)
        for value in (SERIAL_1, VENDOR, PRODUCT, "/dev/bus", "001", "015"):
            self.assertNotIn(value, text)

    def test_absent_ambiguous_unsettled_and_unidentified_are_never_changed(self):
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
        code, lines = self.run_once()
        self.assertEqual(0, code)
        self.assertEqual(["usb_repass_absent device=cam1", "usb_repass_ambiguous device=cam2",
                          "usb_repass_unidentified device=cam3", "usb_repass_unsettled device=cam4"], lines)
        self.assertEqual([], self.lxd.puts)

    def test_a_device_not_named_or_not_usb_is_never_touched(self):
        self.write_config({"instance": "vm", "devices": ["eth0", "camX"]})
        self.needs_repass()
        self.write_config({"instance": "vm", "devices": ["eth0", "camX"]})
        code, lines = self.run_once()
        self.assertEqual(["usb_repass_unidentified device=eth0", "usb_repass_not_configured device=camX"], lines)
        self.assertEqual([], self.lxd.puts)

    def test_rate_limit(self):
        self.needs_repass()
        self.lxd.host = type("NoHold", (), {"hold": lambda self, serial: None})()
        self.run_once()
        self.assertEqual(2, len(self.lxd.puts))
        _, lines = self.run_once()
        self.assertEqual(["usb_repass_rate_limited device=cam1"], lines)
        self.assertEqual(2, len(self.lxd.puts))
        for _ in range(repass.MAX_PER_HOUR - 1):
            self.clock[0] += repass.MIN_INTERVAL_SECONDS
            self.run_once()
        self.assertEqual(2 * repass.MAX_PER_HOUR, len(self.lxd.puts))
        self.clock[0] += repass.MIN_INTERVAL_SECONDS
        _, lines = self.run_once()
        self.assertEqual(["usb_repass_rate_limited device=cam1"], lines)
        self.clock[0] += 3600
        _, lines = self.run_once()
        self.assertEqual(["usb_repass_unverified device=cam1"], lines)

    def test_a_failed_add_keeps_the_configuration_and_the_next_run_restores_it(self):
        self.needs_repass()
        self.lxd.fail = ["add"] * repass.ADD_ATTEMPTS
        code, lines = self.run_once()
        self.assertEqual(1, code)
        self.assertIn("usb_repass_add_failed device=cam1", lines)
        self.assertNotIn("cam1", self.lxd.devices)
        saved = json.loads((self.state / "state.json").read_text())
        self.assertEqual(camera(SERIAL_1), saved["pending"]["cam1"])
        code, lines = self.run_once()
        self.assertEqual("usb_repass_restored device=cam1", lines[0])
        self.assertEqual(camera(SERIAL_1), self.lxd.devices["cam1"])
        self.assertEqual({}, json.loads((self.state / "state.json").read_text())["pending"])

    def test_a_retried_add_succeeds(self):
        self.needs_repass()
        self.lxd.fail = ["add"]
        code, lines = self.run_once()
        self.assertEqual(0, code)
        self.assertEqual(["usb_repass_update_failed step=add device=cam1", "usb_repass_done device=cam1"], lines)

    def test_a_failed_remove_leaves_the_device_and_clears_the_pending_record(self):
        self.needs_repass()
        self.lxd.fail = ["remove"]
        code, lines = self.run_once()
        self.assertEqual((1, ["usb_repass_update_failed step=remove device=cam1"]), (code, lines))
        self.assertIn("cam1", self.lxd.devices)
        self.clock[0] += repass.MIN_INTERVAL_SECONDS
        self.run_once()
        self.assertEqual([("remove", ["cam2", "eth0"]), ("add", ["cam1", "cam2", "eth0"])], self.lxd.puts)

    def test_a_device_changed_after_the_snapshot_is_neither_removed_nor_overwritten(self):
        # PR #399 Codex P2: the Owner edits cam1 during the settle.
        self.needs_repass()
        original = self.sleep

        def edit_during_settle(seconds):
            original(seconds)
            if seconds == repass.SETTLE_SECONDS:
                self.lxd.devices["cam1"] = camera("SYNTH0009")
        self.sleep = edit_during_settle
        code, lines = self.run_once()
        self.assertEqual((0, ["usb_repass_changed step=remove device=cam1"]), (code, lines))
        self.assertEqual([], self.lxd.puts)
        self.assertEqual(camera("SYNTH0009"), self.lxd.devices["cam1"])
        saved = json.loads((self.state / "state.json").read_text())
        self.assertEqual(({}, []), (saved["pending"], saved["history"]["cam1"]))
        # Removed by the Owner meanwhile: not added back either.
        self.sleep = original
        self.lxd.devices["cam1"] = camera(SERIAL_1)

        def owner_removes():
            del self.lxd.devices["cam1"]
        self.lxd.before_put = [owner_removes]
        code, lines = self.run_once()
        self.assertEqual((0, ["usb_repass_changed step=remove device=cam1"]), (code, lines))
        self.assertNotIn("cam1", self.lxd.devices)

    def test_a_device_added_again_before_the_add_is_not_overwritten(self):
        self.needs_repass()
        self.lxd.before_put = [lambda: None,
                               lambda: self.lxd.devices.__setitem__("cam1", camera("SYNTH0009"))]
        code, lines = self.run_once()
        self.assertEqual((0, ["usb_repass_changed step=add device=cam1"]), (code, lines))
        self.assertEqual(camera("SYNTH0009"), self.lxd.devices["cam1"])
        self.assertEqual({}, json.loads((self.state / "state.json").read_text())["pending"])

    def test_not_running_or_starting_vm_is_not_judged(self):
        self.needs_repass()
        self.lxd.status = "Stopped"
        self.assertEqual((0, ["usb_repass_instance_not_running"]), self.run_once())
        self.lxd.status = "Running"
        self.host.set_age(repass.MIN_QEMU_AGE_SECONDS - 1)
        self.assertEqual((0, ["usb_repass_instance_starting"]), self.run_once())
        self.assertEqual([], self.lxd.puts)

    def test_check_changes_nothing(self):
        self.needs_repass()
        self.assertEqual((0, ["usb_repass_needs_repass device=cam1"]), self.run_once(check=True))
        self.assertEqual([], self.lxd.puts)
        self.assertFalse((self.state / "state.json").exists())

    def test_configuration_is_validated(self):
        self.write_config({"instance": "vm", "devices": ["cam1"]}, mode=0o620)
        with self.assertRaisesRegex(repass.Failure, "usb_repass_config_unsafe"):
            self.run_once()
        # Owned by another account than the expected one (root on the host).
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

    def test_deleted_nodes_are_not_held(self):
        self.host.link("/dev/bus/usb/001/003 (deleted)")
        self.host.link("/dev/kvm")
        self.host.link("/dev/bus/usb/009/004")
        self.assertEqual({"/dev/bus/usb/009/004"}, self.host.held())


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def address_string(self):
        return "local"

    def _reply(self, status, body, etag=None):
        data = json.dumps(body).encode()
        self.send_response(status)
        if etag:
            self.send_header("ETag", etag)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        server = self.server
        server.seen.append(("GET", self.path, None, None))
        if self.path == "/1.0/instances/vm":
            self._reply(200, {"type": "sync", "metadata": server.instance}, etag="etag-1")
        elif self.path.startswith("/1.0/operations/op1/wait"):
            self._reply(200, {"metadata": {"status": server.outcome}})
        else:
            self._reply(404, {"error": "not found"})

    def do_PUT(self):
        server = self.server
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        server.seen.append(("PUT", self.path, self.headers.get("If-Match"), body))
        self._reply(server.put_status, {"type": "async", "operation": "/1.0/operations/op1"})


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class LxdClientTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.mkdtemp()
        self.path = os.path.join(directory, "unix.socket")
        self.server = _Server(self.path, _Handler)
        self.server.seen = []
        self.server.outcome = "Success"
        self.server.put_status = 202
        self.server.instance = {"architecture": "x86_64", "config": {"k": "v"}, "devices":
                                {"cam1": camera(SERIAL_1), "root": {"type": "disk"}},
                                "ephemeral": False, "profiles": ["default"], "stateful": False,
                                "description": "", "status": "Running", "expanded_devices": {},
                                "name": "vm"}
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_put_uses_the_etag_and_sends_only_writable_fields(self):
        client = repass.Lxd(self.path)
        client.put_devices("vm", lambda devices: {k: v for k, v in devices.items() if k != "cam1"})
        put = [entry for entry in self.server.seen if entry[0] == "PUT"]
        self.assertEqual(1, len(put))
        _, path, etag, body = put[0]
        self.assertEqual(("/1.0/instances/vm", "etag-1"), (path, etag))
        self.assertEqual({"root": {"type": "disk"}}, body["devices"])
        self.assertEqual(set(repass.PUT_KEYS), set(body))
        self.assertEqual("GET", self.server.seen[-1][0])
        self.assertTrue(self.server.seen[-1][1].startswith("/1.0/operations/op1/wait?timeout="))

    def test_require_sees_the_fresh_devices_and_blocks_the_put(self):
        client = repass.Lxd(self.path)
        with self.assertRaisesRegex(repass.Failure, "usb_repass_changed"):
            client.put_devices("vm", dict, require=lambda d: d.get("cam1") == camera("OTHER"))
        self.assertEqual([], [entry for entry in self.server.seen if entry[0] == "PUT"])
        client.put_devices("vm", dict, require=lambda d: d.get("cam1") == camera(SERIAL_1))
        self.assertEqual(1, len([entry for entry in self.server.seen if entry[0] == "PUT"]))

    def test_refused_or_failed_updates_raise(self):
        client = repass.Lxd(self.path)
        self.server.outcome = "Failure"
        with self.assertRaisesRegex(repass.Failure, "usb_repass_update_failed"):
            client.put_devices("vm", dict)
        self.server.put_status = 412
        with self.assertRaisesRegex(repass.Failure, "usb_repass_update_refused"):
            client.put_devices("vm", dict)
        with self.assertRaisesRegex(repass.Failure, "usb_repass_instance_unreadable"):
            client.instance("other")
        with self.assertRaisesRegex(repass.Failure, "usb_repass_lxd_unreachable"):
            repass.Lxd(self.path + ".missing").instance("vm")


class PackagingTests(unittest.TestCase):
    def test_units_and_rule_agree(self):
        directory = ROOT / "infra/lxd"
        service = (directory / "server-sentinel-usb-repass.service").read_text()
        rule = (directory / "90-server-sentinel-usb-repass.rules").read_text()
        timer = (directory / "server-sentinel-usb-repass.timer").read_text()
        self.assertIn('ENV{SYSTEMD_WANTS}+="server-sentinel-usb-repass.service"', rule)
        self.assertIn('ENV{DEVTYPE}=="usb_device"', rule)
        self.assertIn("/usr/bin/python3 -I -S /usr/local/lib/server-sentinel-usb-repass/usb_repass.py", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX\n", service)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("Type=oneshot", service)
        self.assertIn("WantedBy=timers.target", timer)
        example = json.loads((directory / "usb-repass.example.json").read_text())
        self.assertEqual({"instance", "devices"}, set(example))

    def test_standard_library_only(self):
        source = (ROOT / "infra/lxd/usb_repass.py").read_text()
        imports = {line.split()[1].split(".")[0] for line in source.splitlines()
                   if line.startswith(("import ", "from "))}
        self.assertLessEqual(imports, {"argparse", "fcntl", "http", "json", "os", "re", "socket",
                                       "stat", "sys", "time"})


if __name__ == "__main__":
    unittest.main()
