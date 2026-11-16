#!/usr/bin/python3 -I
"""Host-side check for USB cameras that look not passed to the LXD VM (Issue #301, #405).

Runs as root on the LXD host, never inside ServerSentinel. Standard library
only. Read-only: it sends only GET requests to LXD and never removes, adds or
changes a device (Owner decision 2026-11-16, Issue #405: the automatic
remove / add of PR #399 removed healthy cameras on the real host, and QEMU
then refused the add). The re-pass itself is done by hand
(`infra/lxd/README.md`, "Manual re-pass").

LXD (5.21 on the real host) does not pass a camera that the host
re-enumerated back to the running VM: QEMU keeps the deleted
`/dev/bus/usb` node open and the guest keeps a device that no longer delivers
frames. For each LXD `usb` device named in the configuration this decides
only from host facts (never `/dev/videoN`, never the guest):

- the instance's own device, with `vendorid`, `productid` and `serial` and no
  `busnum` / `devnum` (any other device is `unidentified`); two configured
  devices for one camera are both `ambiguous`;
- exactly one host USB device with those three values (none: `absent`; more
  than one: `ambiguous`; changed between two samples: `unsettled`);
- whether the VM's QEMU process holds that device's current node open
  (`held`); otherwise the camera *looks* not passed
  (`usb_repass_looks_unpassed`). The judgement can be wrong (Issue #405: it
  reported healthy cameras), so it is a prompt to verify by hand, never a
  reason to change anything by itself.

A run whose result needs the Owner's attention (a camera that looks not
passed, a configured device missing from the instance, a pending record of
the old automatic re-pass whose device is missing, or a state file that
cannot be read) prints `usb_repass_attention` and exits 1, so the unit shows
in `systemctl --failed`. Journal lines are fixed words plus the configured
device label and counts; no serial, vendor/product id, bus or device number
is printed. Nothing is written anywhere.
"""

import argparse
import http.client
import json
import os
import re
import socket
import stat
import sys
import time

DEFAULT_SOCKET = "/var/snap/lxd/common/lxd/unix.socket"
# Only read: the pending records the automatic re-pass of PR #399 left
# (2026-11-08 on the real host). Nothing writes here any more.
DEFAULT_STATE_DIR = "/var/lib/server-sentinel-usb-repass"
SYSFS_USB = "/sys/bus/usb/devices"
PROC = "/proc"
# The two C960 on the real host reset each other about a second apart
# (2026-09-30), so the host is sampled after a settle and twice.
SETTLE_SECONDS = 5.0
STABLE_GAP_SECONDS = 2.0
# QEMU opens the passed devices while the VM starts, and the guest's USB
# resets after the start re-enumerate on the host for a while (Issue #405:
# events past 120 s); a younger process is not judged.
MIN_QEMU_AGE_SECONDS = 300.0
REQUEST_TIMEOUT_SECONDS = 30
# Host boot (Issue #402 (7)): a run that starts within BOOT_GRACE_SECONDS of
# the host's boot waits up to LXD_WAIT_SECONDS for LXD to answer; if it still
# does not, the run ends without failing (`usb_repass_lxd_not_ready`) and the
# timer runs it again. A later run fails on `usb_repass_lxd_unreachable`.
BOOT_GRACE_SECONDS = 180.0
LXD_WAIT_SECONDS = 60.0
LXD_WAIT_GAP_SECONDS = 5.0
# The longest run: the boot wait (its last attempt starts before
# LXD_WAIT_SECONDS end), the instance and state reads, the settle and the
# second sample. The unit's TimeoutStartSec leaves a margin above it for the
# interpreter start.
RUN_WORST_SECONDS = (LXD_WAIT_SECONDS + REQUEST_TIMEOUT_SECONDS + 2 * REQUEST_TIMEOUT_SECONDS
                     + SETTLE_SECONDS + STABLE_GAP_SECONDS)
UNIT_TIMEOUT_SECONDS = 300
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
HEX4 = re.compile(r"[0-9a-fA-F]{4}\Z")
IDENTITY_KEYS = ("vendorid", "productid", "serial")
PINNED_KEYS = ("busnum", "devnum")
ATTENTION = "usb_repass_attention see=infra/lxd/README.md#manual-re-pass"


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
    """The two LXD REST reads this needs, over the local unix socket.

    Only GET is ever sent (Issue #405): there is no method parameter and no
    request with a body.
    """

    def __init__(self, path):
        self.path = path

    def get(self, url):
        connection = _UnixConnection(self.path)
        try:
            connection.request("GET", url)
            response = connection.getresponse()
            data = json.loads(response.read() or b"{}")
            status = response.status
        except (OSError, ValueError, http.client.HTTPException):
            raise Failure("usb_repass_lxd_unreachable") from None
        finally:
            connection.close()
        if not isinstance(data, dict):
            raise Failure("usb_repass_lxd_invalid")
        return status, data

    def instance(self, name):
        status, data = self.get(f"/1.0/instances/{name}")
        if status != 200 or not isinstance(data.get("metadata"), dict):
            raise Failure("usb_repass_instance_unreadable")
        metadata = data["metadata"]
        if not isinstance(metadata.get("devices", {}), dict):
            raise Failure("usb_repass_instance_unreadable")
        return metadata

    def state(self, name):
        status, data = self.get(f"/1.0/instances/{name}/state")
        if status != 200 or not isinstance(data.get("metadata"), dict):
            raise Failure("usb_repass_instance_unreadable")
        return data["metadata"]


def load_config(path, owner=0):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Failure("usb_repass_config_unreadable") from None
    try:
        info = os.fstat(fd)
        # root-owned and not writable by anyone else: root acts on it.
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
    # A device pinned to a bus or device number names an enumeration, not a
    # camera (PR #399 review): not judged.
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


def usb_fds(pid, proc=PROC):
    """`(live nodes, open fds on deleted nodes)` of the process's `/dev/bus/usb` fds."""
    base = os.path.join(proc, str(pid), "fd")
    try:
        entries = os.listdir(base)
    except OSError:
        raise Failure("usb_repass_qemu_unreadable") from None
    held, deleted = set(), 0
    for entry in entries:
        try:
            target = os.readlink(os.path.join(base, entry))
        except OSError:
            continue
        if not target.startswith("/dev/bus/usb/"):
            continue
        if target.endswith(" (deleted)"):
            deleted += 1
        else:
            held.add(target)
    return held, deleted


def held_nodes(pid, proc=PROC):
    """The live `/dev/bus/usb` nodes the process holds open (deleted ones excluded)."""
    return usb_fds(pid, proc)[0]


def host_uptime(proc=PROC):
    """Seconds since the host booted, or None when `/proc/uptime` cannot be read."""
    try:
        with open(os.path.join(proc, "uptime"), "rb") as handle:
            return float(handle.read(64).split()[0])
    except (OSError, ValueError, IndexError):
        return None


def wait_for_lxd(lxd, instance, sleep, monotonic):
    """Whether LXD answers within LXD_WAIT_SECONDS (Issue #402 (7)).

    Only `usb_repass_lxd_unreachable` is waited for; any other failure is
    raised as it is.
    """
    deadline = monotonic() + LXD_WAIT_SECONDS
    while True:
        try:
            lxd.instance(instance)
            return True
        except Failure as error:
            if error.args[0] != "usb_repass_lxd_unreachable":
                raise
        if monotonic() + LXD_WAIT_GAP_SECONDS > deadline:
            return False
        sleep(LXD_WAIT_GAP_SECONDS)


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


def read_pending(directory):
    """The pending device configurations the old automatic re-pass left, read only.

    A run of PR #399 wrote a device's configuration here before removing it
    and dropped it after the add. A record left behind (2026-11-08) may be
    the only copy of a removed device's configuration, so the file is never
    changed here; restoring it is a manual step (README).
    """
    try:
        with open(os.path.join(directory, "state.json"), "rb") as handle:
            raw = json.loads(handle.read(1 << 20))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raw = None
    pending = raw.get("pending") if isinstance(raw, dict) else None
    if (not isinstance(pending, dict)
            or not all(isinstance(k, str) and LABEL.match(k) and isinstance(v, dict)
                       for k, v in pending.items())):
        raise Failure("usb_repass_state_unreadable")
    return pending


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
            result[name] = "not_configured"
            continue
        key = keys[name]
        if key is None:
            result[name] = "unidentified"
            continue
        first, second = nodes_first.get(key, []), nodes_second.get(key, [])
        if counts[key] > 1:
            result[name] = "ambiguous"
        elif not second:
            result[name] = "absent"
        elif len(second) > 1 or len(first) > 1:
            result[name] = "ambiguous"
        elif first != second:
            result[name] = "unsettled"
        elif second[0] in held:
            result[name] = "held"
        else:
            result[name] = "needs_repass"
    return result


# Verdicts that make the run ask for the Owner's attention. `absent` (the
# host itself lost the camera) is not: ServerSentinel's camera_offline notice
# covers it and no re-pass can help.
ATTENTION_VERDICTS = {"needs_repass": "usb_repass_looks_unpassed",
                      "not_configured": "usb_repass_not_configured"}


def run(config_path, state_dir, check=False, lxd_factory=Lxd, sleep=time.sleep,
        monotonic=time.monotonic, sysfs=SYSFS_USB, proc=PROC, config_owner=0):
    """Judge every configured camera; 1 when one needs the Owner's attention (0 under --check)."""
    instance, names, sock = load_config(config_path, config_owner)
    lxd = lxd_factory(sock)
    attention = False

    def finish():
        if attention:
            log(ATTENTION)
        return 1 if attention and not check else 0

    try:
        pending = read_pending(state_dir)
    except Failure as error:
        # Kept as it is: it may hold a removed device's only configuration.
        log(error.args[0])
        pending, attention = {}, True
    # Reported before anything that needs LXD (PR #419 review).
    for name in sorted(pending):
        log("usb_repass_pending_record", name)
    uptime = host_uptime(proc)
    if (uptime is not None and uptime < BOOT_GRACE_SECONDS
            and not wait_for_lxd(lxd, instance, sleep, monotonic)):
        log("usb_repass_lxd_not_ready")
        return finish()
    metadata = lxd.instance(instance)
    devices = metadata.get("devices") or {}
    for name, config in sorted(pending.items()):
        if name not in devices:
            # Removed by the old re-pass and never added back: restore by hand.
            log("usb_repass_pending_device_missing", name)
            attention = True
        elif devices[name] == config:
            # The device is there as recorded: the record is stale.
            log("usb_repass_pending_device_present", name)
        else:
            log("usb_repass_pending_device_differs", name)
    if metadata.get("status") != "Running":
        log("usb_repass_instance_not_running")
        return finish()
    pid = lxd.state(instance).get("pid")
    if not isinstance(pid, int) or pid <= 0:
        raise Failure("usb_repass_qemu_unreadable")
    if process_age(pid, proc) < MIN_QEMU_AGE_SECONDS:
        log("usb_repass_instance_starting")
        return finish()
    # Issue #402 (9): one sample finding every camera held is the normal
    # state and needs no settle or second sample.
    nodes = host_nodes(sysfs)
    quick = classify(devices, names, nodes, nodes, held_nodes(pid, proc))
    if all(verdict == "held" for verdict in quick.values()):
        for name in names:
            log("usb_repass_held", name)
        return finish()
    if not check:
        sleep(SETTLE_SECONDS)
    first = host_nodes(sysfs)
    sleep(STABLE_GAP_SECONDS)
    second = host_nodes(sysfs)
    held, deleted = usb_fds(pid, proc)
    verdicts = classify(devices, names, first, second, held)
    for name in names:
        verdict = verdicts[name]
        if verdict in ATTENTION_VERDICTS:
            log(ATTENTION_VERDICTS[verdict], name)
            attention = True
        else:
            log(f"usb_repass_{verdict}", name)
    # Counts only, for the manual verification (Issue #405 compared them by
    # hand): how many /dev/bus/usb fds QEMU holds on live and deleted nodes.
    log(f"usb_repass_qemu_usb_fds live={len(held)} deleted={deleted}")
    return finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/server-sentinel-usb-repass.json")
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    parser.add_argument("--check", action="store_true",
                        help="the same judgement without the settle; always exits 0")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        log("usb_repass_requires_root")
        return 2
    try:
        return run(args.config, args.state_dir, check=args.check)
    except Failure as error:
        log(error.args[0])
        return 1


if __name__ == "__main__":
    sys.exit(main())
