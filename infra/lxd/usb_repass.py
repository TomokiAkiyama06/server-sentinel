#!/usr/bin/python3 -I
"""Host-side re-pass of serial-identified USB cameras to the LXD VM (Issue #301 item 1).

Runs as root on the LXD host, never inside ServerSentinel. Standard library
only. LXD (5.21 on the real host, 2026-10-19 and 2026-11-08) does not pass a
camera that the host re-enumerated back to the running VM: QEMU keeps the
deleted `/dev/bus/usb` node open and the guest keeps a device that no longer
delivers frames. This script decides from host facts only:

- the instance's own `usb` devices named in the configuration, each with
  `vendorid`, `productid` and `serial` and no `busnum` / `devnum` (any other
  device is never touched: identical non-serial cameras are not rebound
  automatically); two configured devices for one camera are both refused;
- exactly one host USB device with those three values (none: the camera is
  absent; more than one: ambiguous, refused);
- whether the VM's QEMU process holds that device's current node open.

Only a camera whose current node QEMU does not hold is re-passed, as the
documented recovery does (`lxc config device remove` then `add` with the same
configuration), through the LXD REST API on its unix socket with the instance
ETag, and only while the device is still exactly as judged. Before the remove
the device configuration is written to the state directory, so a run that
dies between remove and add restores it on the next run (also while the VM is
stopped). All cameras found not passed are re-passed in one pass and then
verified together. A run ends within `RUN_LIMIT_SECONDS`: a remove starts only
while it, its add and the verification still fit. Each device is re-passed at
most once per `MIN_INTERVAL_SECONDS` and `MAX_PER_HOUR` times an hour. Journal
lines are fixed words plus the configured device label; no serial,
vendor/product id, bus or device number is printed.
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
VERIFY_SECONDS = 10.0
ADD_ATTEMPTS = 3
ADD_RETRY_GAP_SECONDS = 2.0
# One LXD request (socket timeout), the server-side wait of one operation
# poll, and how long an operation is polled before it counts as not finished.
REQUEST_TIMEOUT_SECONDS = 30
OPERATION_POLL_SECONDS = 20
OPERATION_LIMIT_SECONDS = 60
# Worst cases, derived (PR #399 review): a PUT is its GET, the PUT and polls
# until OPERATION_LIMIT_SECONDS, the last poll starting just before it.
PUT_WORST_SECONDS = 2 * REQUEST_TIMEOUT_SECONDS + OPERATION_LIMIT_SECONDS + REQUEST_TIMEOUT_SECONDS
# A remove, and the re-read that decides an ambiguous failure.
REMOVE_WORST_SECONDS = PUT_WORST_SECONDS + REQUEST_TIMEOUT_SECONDS
# Each add attempt reads the device first; one more read after the last.
ADD_WORST_SECONDS = (ADD_ATTEMPTS * (REQUEST_TIMEOUT_SECONDS + PUT_WORST_SECONDS)
                     + (ADD_ATTEMPTS - 1) * ADD_RETRY_GAP_SECONDS + REQUEST_TIMEOUT_SECONDS)
REPASS_WORST_SECONDS = REMOVE_WORST_SECONDS + ADD_WORST_SECONDS
# The final settle and verification of the re-passed devices.
VERIFY_WORST_SECONDS = SETTLE_SECONDS + VERIFY_SECONDS + 5.0
# A run ends within this: a remove (or a restore) starts only while a whole
# remove + add (or add) and the verification still fit, so a run never stops
# between a remove and its add. The unit's TimeoutStartSec is this plus
# STARTUP_MARGIN_SECONDS (interpreter start, the first reads before the
# first deadline check are inside the limit).
RUN_LIMIT_SECONDS = 900
STARTUP_MARGIN_SECONDS = 60
UNIT_TIMEOUT_SECONDS = RUN_LIMIT_SECONDS + STARTUP_MARGIN_SECONDS
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
HEX4 = re.compile(r"[0-9a-fA-F]{4}\Z")
IDENTITY_KEYS = ("vendorid", "productid", "serial")
PINNED_KEYS = ("busnum", "devnum")
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

    def __init__(self, path, monotonic=time.monotonic):
        self.path = path
        self.monotonic = monotonic

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

    def put_devices(self, name, devices, require=None):
        """Replace the instance's own devices (fresh GET + ETag), wait for it.

        ``require`` sees the devices of that same GET; when it is false the
        instance changed since the caller's snapshot and nothing is sent
        (`usb_repass_changed`). An edit between the GET and the PUT makes LXD
        refuse the PUT on the ETag (`usb_repass_update_refused`).
        """
        metadata, etag = self.instance(name)
        current = dict(metadata.get("devices") or {})
        if require is not None and not require(current):
            raise Failure("usb_repass_changed")
        body = {key: metadata[key] for key in PUT_KEYS if key in metadata}
        body["devices"] = devices(current)
        status, _, data = self.request("PUT", f"/1.0/instances/{name}", body, etag)
        if status == 200 and data.get("type") == "sync":
            return
        operation = data.get("operation")
        if status != 202 or not isinstance(operation, str) or not operation.startswith("/1.0/operations/"):
            raise Failure("usb_repass_update_refused")
        # Polled until it finishes or OPERATION_LIMIT_SECONDS pass (PR #399
        # review): one wait that timed out is not a failed update.
        deadline = self.monotonic() + OPERATION_LIMIT_SECONDS
        while True:
            wait = max(1, min(OPERATION_POLL_SECONDS, int(deadline - self.monotonic())))
            status, _, data = self.request("GET", f"{operation}/wait?timeout={wait}")
            metadata = data.get("metadata") if isinstance(data, dict) else None
            outcome = metadata.get("status") if isinstance(metadata, dict) else None
            if status == 200 and outcome == "Success":
                return
            if status == 200 and outcome in ("Running", "Pending"):
                if self.monotonic() < deadline:
                    continue
                raise Failure("usb_repass_update_unfinished")
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
    # A device pinned to a bus or device number would be re-added with the
    # numbers of the enumeration that is gone (PR #399 review): refused.
    if any(device.get(key) not in (None, "") for key in PINNED_KEYS):
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
        self.directory = directory
        self.path = os.path.join(directory, "state.json")
        self.pending, self.history = {}, {}
        try:
            with open(self.path, "rb") as handle:
                raw = json.loads(handle.read(1 << 20))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            raw = None
        # An unreadable state may hold a removed device's only configuration
        # (PR #399 review): the run is refused and the file is kept as it is.
        pending = raw.get("pending") if isinstance(raw, dict) else None
        history = raw.get("history") if isinstance(raw, dict) else None
        if (not isinstance(pending, dict) or not isinstance(history, dict)
                or not all(isinstance(k, str) and LABEL.match(k) and isinstance(v, dict)
                           for k, v in pending.items())
                or not all(isinstance(v, list) and all(isinstance(t, (int, float)) for t in v)
                           for v in history.values())):
            raise Failure("usb_repass_state_unreadable")
        self.pending, self.history = pending, history

    def save(self):
        temporary = self.path + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"pending": self.pending, "history": self.history}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def allowed(self, device, now):
        times = [t for t in self.history.get(device, []) if now - t < 3600]
        self.history[device] = times
        return not times or (now - max(times) >= MIN_INTERVAL_SECONDS and len(times) < MAX_PER_HOUR)


def classify(devices, names, nodes_first, nodes_second, held):
    """Per configured label: held, needs_repass, absent, ambiguous, unsettled, unidentified, not_configured."""
    result = {}
    keys = {name: identity(devices[name]) for name in names if name in devices}
    counts = {}
    for key in keys.values():
        if key is not None:
            counts[key] = counts.get(key, 0) + 1
    for name in names:
        if name not in devices:
            result[name] = ("not_configured", None)
            continue
        key = keys[name]
        if key is None:
            result[name] = ("unidentified", None)
            continue
        first, second = nodes_first.get(key, []), nodes_second.get(key, [])
        if counts[key] > 1:
            # Two configured devices for one camera (PR #399 review): neither.
            result[name] = ("ambiguous", None)
        elif not second:
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


def device_state(lxd, instance, name, config):
    """`absent`, `same` (exactly `config`) or `other` for the instance's device `name` now."""
    metadata, _ = lxd.instance(instance)
    devices = metadata.get("devices") or {}
    if name not in devices:
        return "absent"
    return "same" if devices[name] == config else "other"


def add_device(lxd, instance, name, config, sleep, step):
    """Add `config` as `name` unless a device of that name exists.

    `added` (this call put it there), `present` (it was there before any
    PUT), `changed` (another configuration of that name, an Owner edit: left
    as it is) or `failed`. A PUT whose outcome is unknown (an operation still
    running, a lost answer) is decided by reading the device again, so this
    call's own add is never reported as an Owner change (PR #399 review).
    """
    for attempt in range(ADD_ATTEMPTS + 1):
        try:
            current = device_state(lxd, instance, name, config)
        except Failure as error:
            log(f"{error.args[0]} step={step}", name)
            current = None
        if current == "same":
            return "added" if attempt else "present"
        if current == "other":
            return "changed"
        if attempt == ADD_ATTEMPTS:
            return "failed"
        if current == "absent":
            try:
                lxd.put_devices(instance, lambda d: {**d, name: config},
                                require=lambda d: name not in d)
                return "added"
            except Failure as error:
                if error.args[0] != "usb_repass_changed":
                    log(f"{error.args[0]} step={step}", name)
        if attempt + 1 < ADD_ATTEMPTS:
            sleep(ADD_RETRY_GAP_SECONDS)
    return "failed"


def remove_device(lxd, instance, name, config):
    """Remove `name` only if it is exactly `config`.

    `removed`, `kept` (still there unchanged: nothing lost), `changed` (an
    Owner edit since the snapshot, PR #399 Codex P2) or `unknown` (the state
    could not be read; the pending record restores it on a later run). An
    ambiguous failure is decided by reading the device again (PR #399 review).
    """
    try:
        lxd.put_devices(instance, lambda d: {k: v for k, v in d.items() if k != name},
                        require=lambda d: d.get(name) == config)
        return "removed"
    except Failure as error:
        if error.args[0] == "usb_repass_changed":
            return "changed"
        log(f"{error.args[0]} step=remove", name)
    try:
        current = device_state(lxd, instance, name, config)
    except Failure as error:
        log(f"{error.args[0]} step=remove", name)
        return "unknown"
    return {"absent": "removed", "same": "kept", "other": "changed"}[current]


def run(config_path, state_dir, check=False, lxd_factory=Lxd, sleep=time.sleep, now=time.time,
        monotonic=time.monotonic, sysfs=SYSFS_USB, proc=PROC, config_owner=0):
    started = monotonic()

    def fits(seconds):
        # Whether `seconds` more and the final verification end within the limit.
        return monotonic() - started + seconds + VERIFY_WORST_SECONDS <= RUN_LIMIT_SECONDS

    instance, names, sock = load_config(config_path, config_owner)
    lxd = lxd_factory(sock)
    state = None if check else State(state_dir)
    failed = False
    if state is not None and state.pending:
        # A run that died between remove and add left the configuration here;
        # restored whether or not the VM runs (PR #399 review).
        for name, config in sorted(state.pending.items()):
            if not fits(ADD_WORST_SECONDS):
                log("usb_repass_deferred step=restore", name)
                failed = True
                continue
            outcome = add_device(lxd, instance, name, config, sleep, "restore")
            if outcome == "failed":
                log("usb_repass_restore_failed", name)
                failed = True
                continue
            del state.pending[name]
            if outcome == "added":
                log("usb_repass_restored", name)
            elif outcome == "changed":
                log("usb_repass_changed step=restore", name)
        state.save()
    metadata, _ = lxd.instance(instance)
    if metadata.get("status") != "Running":
        log("usb_repass_instance_not_running")
        return 1 if failed else 0
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
    repassed = []
    # Every device found not passed is re-passed in this one pass, then all
    # are verified together against a fresh sample (PR #399 review: the two
    # C960 reset each other, so judging one before the other is re-passed
    # would re-pass back and forth). Each counts once against the rate limit.
    for name in names:
        verdict, _ = verdicts[name]
        if check or verdict != "needs_repass":
            log(f"usb_repass_{verdict}", name)
            continue
        if not fits(REPASS_WORST_SECONDS):
            # The timer runs again in about two minutes.
            log("usb_repass_deferred", name)
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
        removed = remove_device(lxd, instance, name, config)
        if removed in ("changed", "kept"):
            del state.pending[name]
            if removed == "changed":
                # The Owner's edit stands; judged again next run, not counted.
                state.history[name].remove(moment)
                log("usb_repass_changed step=remove", name)
            else:
                failed = True
            state.save()
            continue
        if removed == "unknown":
            failed = True
            continue
        # Removed: the add always follows (fits() left room for it).
        outcome = add_device(lxd, instance, name, config, sleep, "add")
        if outcome == "failed":
            log("usb_repass_add_failed", name)
            failed = True
            continue
        del state.pending[name]
        state.save()
        if outcome == "changed":
            log("usb_repass_changed step=add", name)
            continue
        repassed.append(name)
    if repassed:
        sleep(SETTLE_SECONDS)
        deadline = monotonic() + VERIFY_SECONDS
        while True:
            nodes, held = host_nodes(sysfs), held_nodes(pid, proc)
            verified = {name for name in repassed
                        if len(nodes.get(identity(devices[name]), [])) == 1
                        and nodes[identity(devices[name])][0] in held}
            if len(verified) == len(repassed) or monotonic() >= deadline:
                break
            sleep(1.0)
        for name in repassed:
            if name in verified:
                log("usb_repass_done", name)
            else:
                # The unit fails, so `systemctl --failed` shows it (PR #399 review).
                log("usb_repass_unverified", name)
                failed = True
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
