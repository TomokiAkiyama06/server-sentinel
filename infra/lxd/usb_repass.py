#!/usr/bin/python3 -I
"""Host-side re-pass of serial-identified USB cameras to the LXD VM (Issue #301 item 1).

Runs as root on the LXD host, never inside ServerSentinel. Standard library
only. LXD (5.21 on the real host, 2026-10-19 and 2026-11-08) does not pass a
camera that the host re-enumerated back to the running VM: QEMU keeps the
deleted `/dev/bus/usb` node open and the guest keeps a device that no longer
delivers frames. This script decides from host facts only:

- the instance's own `usb` devices named in the configuration, each with
  `vendorid`, `productid` and `serial` (a device without all three is never
  touched: identical non-serial cameras are not rebound automatically);
- exactly one host USB device with those three values (none: the camera is
  absent; more than one: ambiguous, refused);
- whether the VM's QEMU process holds that device's current node open.

Only a held-elsewhere node is re-passed, as the documented recovery does
(`lxc config device remove` then `add` with the same configuration), through
the LXD REST API on its unix socket with the instance ETag. Before the remove
the device configuration is written to the state directory, so a run that
dies between remove and add restores it on the next run. Each device is
re-passed at most once per `MIN_INTERVAL_SECONDS` and `MAX_PER_HOUR` times an
hour. Journal lines are fixed words plus the configured device label; no
serial, vendor/product id, bus or device number is printed.
"""

import argparse
import fcntl
import http.client
import json
import os
import re
import socket
import stat
import sys
import time

DEFAULT_SOCKET = "/var/snap/lxd/common/lxd/unix.socket"
DEFAULT_STATE_DIR = "/var/lib/server-sentinel-usb-repass"
SYSFS_USB = "/sys/bus/usb/devices"
PROC = "/proc"
# The two C960 on the real host reset each other about a second apart
# (2026-09-30), so the host is sampled after a settle and twice.
SETTLE_SECONDS = 5.0
STABLE_GAP_SECONDS = 2.0
# QEMU opens the passed devices while the VM starts; a younger process is not
# judged.
MIN_QEMU_AGE_SECONDS = 120.0
MIN_INTERVAL_SECONDS = 60.0
MAX_PER_HOUR = 5
OPERATION_TIMEOUT_SECONDS = 60
REQUEST_TIMEOUT_SECONDS = 70
ADD_ATTEMPTS = 3
VERIFY_SECONDS = 10.0
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
HEX4 = re.compile(r"[0-9a-fA-F]{4}\Z")
IDENTITY_KEYS = ("vendorid", "productid", "serial")
# The writable instance fields a PUT takes (as `lxc config device` sends).
PUT_KEYS = ("architecture", "config", "devices", "ephemeral", "profiles", "stateful", "description")


class Failure(Exception):
    """A fixed, value-free reason."""


def log(event, device=None):
    print(event if device is None else f"{event} device={device}", flush=True)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("lxd", timeout=REQUEST_TIMEOUT_SECONDS)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(REQUEST_TIMEOUT_SECONDS)
            sock.connect(self._path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


class Lxd:
    """The few LXD REST calls this needs, over the local unix socket."""

    def __init__(self, path):
        self.path = path

    def request(self, method, url, body=None, etag=None):
        connection = _UnixConnection(self.path)
        try:
            headers = {"Content-Type": "application/json"}
            if etag:
                headers["If-Match"] = etag
            payload = None if body is None else json.dumps(body).encode()
            connection.request(method, url, body=payload, headers=headers)
            response = connection.getresponse()
            data = json.loads(response.read() or b"{}")
            return response.status, response.getheader("ETag"), data
        except (OSError, ValueError, http.client.HTTPException):
            raise Failure("usb_repass_lxd_unreachable") from None
        finally:
            connection.close()

    def instance(self, name):
        status, etag, data = self.request("GET", f"/1.0/instances/{name}")
        if status != 200 or not isinstance(data.get("metadata"), dict):
            raise Failure("usb_repass_instance_unreadable")
        return data["metadata"], etag

    def state(self, name):
        status, _, data = self.request("GET", f"/1.0/instances/{name}/state")
        if status != 200 or not isinstance(data.get("metadata"), dict):
            raise Failure("usb_repass_instance_unreadable")
        return data["metadata"]

    def put_devices(self, name, devices):
        """Replace the instance's own devices (fresh GET + ETag), wait for it."""
        metadata, etag = self.instance(name)
        body = {key: metadata[key] for key in PUT_KEYS if key in metadata}
        body["devices"] = devices(dict(metadata.get("devices") or {}))
        status, _, data = self.request("PUT", f"/1.0/instances/{name}", body, etag)
        if status == 200 and data.get("type") == "sync":
            return
        operation = data.get("operation")
        if status != 202 or not isinstance(operation, str) or not operation.startswith("/1.0/operations/"):
            raise Failure("usb_repass_update_refused")
        status, _, data = self.request("GET", f"{operation}/wait?timeout={OPERATION_TIMEOUT_SECONDS}")
        metadata = data.get("metadata") if isinstance(data, dict) else None
        if status != 200 or not isinstance(metadata, dict) or metadata.get("status") != "Success":
            raise Failure("usb_repass_update_failed")


def load_config(path, owner=0):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Failure("usb_repass_config_unreadable") from None
    try:
        info = os.fstat(fd)
        # root-owned and not writable by anyone else: it decides what root changes.
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise Failure("usb_repass_config_unsafe")
        with os.fdopen(os.dup(fd), "rb") as handle:
            raw = json.loads(handle.read(65536))
    except (OSError, ValueError):
        raise Failure("usb_repass_config_invalid") from None
    finally:
        os.close(fd)
    if not isinstance(raw, dict) or set(raw) - {"instance", "devices", "socket"}:
        raise Failure("usb_repass_config_invalid")
    instance, devices = raw.get("instance"), raw.get("devices")
    sock = raw.get("socket", DEFAULT_SOCKET)
    if (not isinstance(instance, str) or not LABEL.match(instance)
            or not isinstance(devices, list) or not 1 <= len(devices) <= 4
            or len(set(devices)) != len(devices)
            or not all(isinstance(d, str) and LABEL.match(d) for d in devices)
            or not isinstance(sock, str) or not sock.startswith("/")):
        raise Failure("usb_repass_config_invalid")
    return instance, devices, sock


def identity(device):
    """`(vendor, product, serial)` of a fully serial-identified usb device, else None."""
    if not isinstance(device, dict) or device.get("type") != "usb":
        return None
    values = [device.get(key) for key in IDENTITY_KEYS]
    if not all(isinstance(v, str) and v for v in values):
        return None
    vendor, product, serial = values
    if not HEX4.match(vendor) or not HEX4.match(product):
        return None
    return vendor.lower(), product.lower(), serial


def _read(path):
    try:
        with open(path, encoding="ascii", errors="strict") as handle:
            return handle.read(256).strip()
    except (OSError, ValueError):
        return None


def host_nodes(sysfs=SYSFS_USB):
    """`{(vendor, product, serial): [node, ...]}` of the host USB devices with a serial."""
    found = {}
    try:
        entries = sorted(os.listdir(sysfs))
    except OSError:
        raise Failure("usb_repass_sysfs_unreadable") from None
    for entry in entries:
        base = os.path.join(sysfs, entry)
        vendor, product = _read(os.path.join(base, "idVendor")), _read(os.path.join(base, "idProduct"))
        serial = _read(os.path.join(base, "serial"))
        bus, dev = _read(os.path.join(base, "busnum")), _read(os.path.join(base, "devnum"))
        if not (vendor and product and serial and bus and dev):
            continue
        try:
            node = f"/dev/bus/usb/{int(bus):03d}/{int(dev):03d}"
        except ValueError:
            continue
        found.setdefault((vendor.lower(), product.lower(), serial), []).append(node)
    return found


def held_nodes(pid, proc=PROC):
    """The live `/dev/bus/usb` nodes the process holds open (deleted ones excluded)."""
    base = os.path.join(proc, str(pid), "fd")
    try:
        entries = os.listdir(base)
    except OSError:
        raise Failure("usb_repass_qemu_unreadable") from None
    held = set()
    for entry in entries:
        try:
            target = os.readlink(os.path.join(base, entry))
        except OSError:
            continue
        if target.startswith("/dev/bus/usb/") and not target.endswith(" (deleted)"):
            held.add(target)
    return held


def process_age(pid, proc=PROC):
    """Seconds since the process started (`stat` field 22 against `/proc/uptime`)."""
    try:
        with open(os.path.join(proc, str(pid), "stat"), "rb") as handle:
            fields = handle.read(4096).rsplit(b")", 1)[1].split()
        with open(os.path.join(proc, "uptime"), "rb") as handle:
            uptime = float(handle.read(64).split()[0])
        # After "pid (comm)" the third field is index 0, so field 22 is 19.
        return uptime - int(fields[19]) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        raise Failure("usb_repass_qemu_unreadable") from None


class State:
    """Pending device configurations and re-pass times, root-only, in the state directory."""

    def __init__(self, directory):
        self.path = os.path.join(directory, "state.json")
        self.pending, self.history = {}, {}
        try:
            with open(self.path, "rb") as handle:
                raw = json.loads(handle.read(1 << 20))
            pending, history = raw.get("pending", {}), raw.get("history", {})
            if isinstance(pending, dict) and all(isinstance(v, dict) for v in pending.values()):
                self.pending = pending
            if isinstance(history, dict):
                self.history = {k: [t for t in v if isinstance(t, (int, float))]
                                for k, v in history.items() if isinstance(v, list)}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError):
            log("usb_repass_state_unreadable")

    def save(self):
        temporary = self.path + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"pending": self.pending, "history": self.history}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def allowed(self, device, now):
        times = [t for t in self.history.get(device, []) if now - t < 3600]
        self.history[device] = times
        return not times or (now - max(times) >= MIN_INTERVAL_SECONDS and len(times) < MAX_PER_HOUR)


def classify(devices, names, nodes_first, nodes_second, held):
    """Per configured label: held, needs_repass, absent, ambiguous, unsettled, unidentified, not_configured."""
    result = {}
    for name in names:
        if name not in devices:
            result[name] = ("not_configured", None)
            continue
        key = identity(devices[name])
        if key is None:
            result[name] = ("unidentified", None)
            continue
        first, second = nodes_first.get(key, []), nodes_second.get(key, [])
        if not second:
            result[name] = ("absent", None)
        elif len(second) > 1 or len(first) > 1:
            result[name] = ("ambiguous", None)
        elif first != second:
            result[name] = ("unsettled", None)
        elif second[0] in held:
            result[name] = ("held", second[0])
        else:
            result[name] = ("needs_repass", second[0])
    return result


def run(config_path, state_dir, check=False, lxd_factory=Lxd, sleep=time.sleep, now=time.time,
        sysfs=SYSFS_USB, proc=PROC, config_owner=0):
    instance, names, sock = load_config(config_path, config_owner)
    lxd = lxd_factory(sock)
    state = None if check else State(state_dir)
    failed = False
    metadata, _ = lxd.instance(instance)
    if metadata.get("status") != "Running":
        log("usb_repass_instance_not_running")
        return 0
    if state is not None:
        # A run that died between remove and add left the configuration here.
        for name, config in sorted(state.pending.items()):
            if name in (metadata.get("devices") or {}):
                del state.pending[name]
                continue
            try:
                lxd.put_devices(instance, lambda d, n=name, c=config: {**d, n: c})
                del state.pending[name]
                log("usb_repass_restored", name)
            except Failure as error:
                log(f"{error.args[0]} step=restore", name)
                failed = True
        state.save()
        metadata, _ = lxd.instance(instance)
    pid = lxd.state(instance).get("pid")
    if not isinstance(pid, int) or pid <= 0:
        raise Failure("usb_repass_qemu_unreadable")
    if process_age(pid, proc) < MIN_QEMU_AGE_SECONDS:
        log("usb_repass_instance_starting")
        return 1 if failed else 0
    if not check:
        sleep(SETTLE_SECONDS)
    first = host_nodes(sysfs)
    sleep(STABLE_GAP_SECONDS)
    second = host_nodes(sysfs)
    devices = metadata.get("devices") or {}
    verdicts = classify(devices, names, first, second, held_nodes(pid, proc))
    for name in names:
        verdict, node = verdicts[name]
        if check or verdict != "needs_repass":
            log(f"usb_repass_{verdict}", name)
            continue
        moment = now()
        if not state.allowed(name, moment):
            log("usb_repass_rate_limited", name)
            state.save()
            continue
        config = dict(devices[name])
        state.pending[name] = config
        state.history.setdefault(name, []).append(moment)
        state.save()
        try:
            lxd.put_devices(instance, lambda d, n=name: {k: v for k, v in d.items() if k != n})
        except Failure as error:
            # Not removed (or unknown): the next run restores it if it is gone.
            log(f"{error.args[0]} step=remove", name)
            failed = True
            continue
        added = False
        for attempt in range(ADD_ATTEMPTS):
            try:
                lxd.put_devices(instance, lambda d, n=name, c=config: {**d, n: c})
                added = True
                break
            except Failure as error:
                log(f"{error.args[0]} step=add", name)
                if attempt + 1 < ADD_ATTEMPTS:
                    sleep(2.0)
        if not added:
            log("usb_repass_add_failed", name)
            failed = True
            continue
        del state.pending[name]
        state.save()
        deadline = now() + VERIFY_SECONDS
        while node not in held_nodes(pid, proc) and now() < deadline:
            sleep(1.0)
        log("usb_repass_done" if node in held_nodes(pid, proc) else "usb_repass_unverified", name)
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/server-sentinel-usb-repass.json")
    parser.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", DEFAULT_STATE_DIR))
    parser.add_argument("--check", action="store_true",
                        help="report each device's state; change nothing")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        log("usb_repass_requires_root")
        return 2
    lock = None
    try:
        if not args.check:
            os.makedirs(args.state_dir, mode=0o700, exist_ok=True)
            lock = os.open(os.path.join(args.state_dir, "lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                log("usb_repass_busy")
                return 0
        return run(args.config, args.state_dir, check=args.check)
    except Failure as error:
        log(error.args[0])
        return 1
    except OSError:
        log("usb_repass_state_unwritable")
        return 1
    finally:
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    sys.exit(main())
