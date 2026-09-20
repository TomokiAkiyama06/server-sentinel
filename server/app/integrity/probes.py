"""Read-only Linux probes. Never run these probes implicitly on import/startup.

Only explicitly injected LinuxProbe.collect() touches the host. Tests use an
isolated synthetic sysfs/proc tree and an injected command runner.
"""

from dataclasses import dataclass, field
from pathlib import Path
import csv
import io
import json
import os
import re
import select
import signal
import subprocess
import time

from .model import Component, Inventory, Kind


class ProbeUnavailable(Exception):
    def __init__(self):
        super().__init__("PROBE_UNAVAILABLE")


class CommandRunner:
    """Fixed read-only command allowlist, no shell, inherited secrets or sudo."""

    def run(self, command: tuple[str, ...]) -> bytes:
        permitted = command in {
            ("dmidecode", "--type", "17"),
            ("nvidia-smi", "--query-gpu=pci.bus_id,uuid,serial", "--format=csv,noheader,nounits"),
        } or (len(command) == 4 and command[:3] == ("smartctl", "--json", "--health")
              and re.fullmatch(r"/dev/[A-Za-z0-9_-]+", command[3]))
        if not permitted:
            raise ProbeUnavailable()
        process = None
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            data = bytearray()
            deadline = time.monotonic() + 5
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise ProbeUnavailable()
                block = os.read(process.stdout.fileno(), min(65536, 1048577 - len(data)))
                if not block:
                    break
                data.extend(block)
                if len(data) > 1048576:
                    raise ProbeUnavailable()
            status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            # smartctl returns a bitmask: health warnings are useful output.
            if status and not (command[0] == "smartctl" and status >= 0 and not status & 7):
                raise ProbeUnavailable()
            return bytes(data)
        except (OSError, subprocess.SubprocessError):
            raise ProbeUnavailable() from None
        finally:
            if process is not None:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                process.stdout.close()


def _read(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            data = stream.read(1048577)
        if len(data) > 1048576:
            raise ProbeUnavailable()
        return data.decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeError):
        raise ProbeUnavailable() from None


def _optional(path: Path) -> str:
    try:
        return _read(path)
    except ProbeUnavailable:
        return ""


def _identity(value: str) -> str:
    value = value.strip()
    if value.lower() in {"", "unknown", "not specified", "none", "n/a", "[n/a]", "to be filled by o.e.m."} or (value and set(value) == {"0"}):
        return ""
    return value


def _pairs(values: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((key, value) for key, value in values.items() if value))


@dataclass
class LinuxProbe:
    root: Path = field(default=Path("/"), repr=False)
    runner: CommandRunner = field(default_factory=CommandRunner, repr=False)

    def collect(self) -> Inventory:
        components = []
        unavailable = set()
        for kind, probe in ((Kind.CPU, self._cpu), (Kind.MEMORY, self._memory),
                            (Kind.STORAGE, self._storage), (Kind.GPU, self._gpu)):
            try:
                components.extend(probe())
            except (ProbeUnavailable, ValueError, KeyError, TypeError, OSError):
                unavailable.add(kind)
        return Inventory(tuple(components), frozenset(unavailable))

    def _cpu(self):
        text = _read(self.root / "proc/cpuinfo")
        sockets = {}
        for block in text.split("\n\n"):
            fields = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
            fields = {key.strip(): value.strip() for key, value in fields.items()}
            if "processor" not in fields:
                continue
            location = fields.get("physical id", "unreported-socket")
            properties = {key: fields[key] for key in ("model name", "vendor_id", "cpu family", "model", "stepping", "cpu cores") if key in fields}
            if not properties:
                raise ProbeUnavailable()
            prior, count = sockets.get(location, (properties, 0))
            if prior != properties:
                raise ProbeUnavailable()
            sockets[location] = (properties, count + 1)
        if not sockets:
            raise ProbeUnavailable()
        return tuple(Component(Kind.CPU, location, _pairs({**props, "logical_cpus": str(count)}))
                     for location, (props, count) in sorted(sockets.items()))

    def _memory(self):
        text = self.runner.run(("dmidecode", "--type", "17")).decode("utf-8")
        components = []
        for block in re.split(r"\n(?=Handle )", text):
            if "\nMemory Device\n" not in block:
                continue
            fields = dict(line.strip().split(": ", 1) for line in block.splitlines() if ": " in line)
            if fields.get("Size") == "No Module Installed":
                continue
            location = fields.get("Locator")
            if not location or not fields.get("Size"):
                raise ProbeUnavailable()
            bank = fields.get("Bank Locator", "")
            properties = _pairs({key: fields.get(key, "") for key in ("Size", "Type", "Manufacturer", "Part Number")})
            serial = _identity(fields.get("Serial Number", ""))
            components.append(Component(Kind.MEMORY, bank + ":" + location, properties,
                                        _pairs({"serial": serial})))
        if not components:
            raise ProbeUnavailable()
        return tuple(components)

    def _storage(self):
        components = []
        for device in sorted((self.root / "sys/class/block").iterdir()):
            if (device / "partition").exists() or device.name.startswith(("loop", "ram", "zram")):
                continue
            sectors = int(_read(device / "size"))
            if sectors <= 0:
                continue
            properties = _pairs({"capacity_bytes": str(sectors * 512),
                                 "model": _optional(device / "device/model")})
            identifiers = _pairs({"serial": _identity(_optional(device / "device/serial")),
                                  "wwid": _identity(_optional(device / "wwid"))})
            components.append(Component(Kind.STORAGE, device.name, properties, identifiers))
        return tuple(components)

    def _gpu(self):
        components = []
        gpu_ids = {}
        try:
            output = self.runner.run(("nvidia-smi", "--query-gpu=pci.bus_id,uuid,serial", "--format=csv,noheader,nounits"))
            for row in csv.reader(io.StringIO(output.decode("utf-8"))):
                if len(row) != 3:
                    raise ProbeUnavailable()
                slot, uuid, serial = (value.strip() for value in row)
                gpu_ids[slot.lower()[-12:]] = _pairs({"uuid": _identity(uuid), "serial": _identity(serial)})
        except (ProbeUnavailable, UnicodeError):
            pass
        for device in sorted((self.root / "sys/bus/pci/devices").iterdir()):
            class_id = int(_read(device / "class"), 16)
            if class_id >> 16 != 3:
                continue
            properties = _pairs({key: _read(device / key) for key in ("vendor", "device", "subsystem_vendor", "subsystem_device")})
            components.append(Component(Kind.GPU, device.name, properties, gpu_ids.get(device.name.lower(), ())))
        return tuple(components)

    def storage_health(self, devices: tuple[str, ...]) -> tuple[str, ...]:
        """One sanitized status per configured backing device; never guess life."""
        result = []
        for device in devices:
            try:
                data = json.loads(self.runner.run(("smartctl", "--json", "--health", device)))
                passed = data.get("smart_status", {}).get("passed")
                warning = data.get("nvme_smart_health_information_log", {}).get("critical_warning")
                if passed is False or (type(warning) is int and warning != 0):
                    result.append("CRITICAL")
                elif passed is True or (type(warning) is int and warning == 0):
                    result.append("OK")
                else:
                    result.append("UNVERIFIABLE")
            except (ProbeUnavailable, ValueError, TypeError, AttributeError):
                result.append("UNVERIFIABLE")
        return tuple(result)
