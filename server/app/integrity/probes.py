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
            # Cleanup must be total and bounded. A failed signal must not skip
            # closing the pipe, and a command wedged in uninterruptible I/O on a
            # failing disk must never block the integrity worker: an abandoned
            # child is reaped by subprocess later instead of stalling the
            # startup/daily check (SPECIFICATION 10.2, REQUIREMENTS INTEGRITY-002).
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except OSError:
                            # The child may have exited between poll() and the
                            # signal. Reap it anyway; a skipped wait() leaves a
                            # zombie until an unrelated spawn or backend exit.
                            pass
                        process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
                finally:
                    process.stdout.close()


def _read_bytes(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(1048577)
    except OSError:
        raise ProbeUnavailable() from None
    if len(data) > 1048576:
        raise ProbeUnavailable()
    return data


def _read(path: Path) -> str:
    try:
        return _read_bytes(path).decode("utf-8", errors="strict").strip()
    except UnicodeError:
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


# Identity values must fit Component's per-value bound; a longer value is
# treated as unavailable instead of making the whole STORAGE probe fail.
_IDENTITY_LIMIT = 1024


def _bounded(value: str) -> str:
    return value if len(value) <= _IDENTITY_LIMIT else ""


def _vpd_page(data: bytes, page: int) -> bytes:
    """Return the payload of one SPC VPD page, or raise on any framing fault.

    Header: peripheral qualifier/type, page code, 16-bit big-endian page
    length. A truncated page, a different page code or a logical unit that is
    not connected (non-zero peripheral qualifier) is malformed, never partial.
    """
    if len(data) < 4 or data[1] != page or data[0] >> 5 != 0:
        raise ProbeUnavailable()
    length = int.from_bytes(data[2:4], "big")
    if 4 + length > len(data):
        raise ProbeUnavailable()
    return data[4:4 + length]


def _ascii(value: bytes) -> str:
    """Printable ASCII with padding (spaces/NULs) removed from both ends."""
    value = value.strip(b" \x00")
    if any(byte < 0x20 or byte > 0x7e for byte in value):
        raise ProbeUnavailable()
    return value.decode("ascii")


def _vpd_unit_serial(data: bytes) -> str:
    """VPD page 0x80 (Unit Serial Number); empty/placeholder is unavailable."""
    return _bounded(_identity(_ascii(_vpd_page(data, 0x80))))


# VPD page 0x83 designator types accepted as a logical-unit identity, best
# first. Vendor-specific (0), port/group (4-7) designators are not globally
# unique logical-unit names and are ignored.
_DESIGNATOR_RANK = {0x3: "naa", 0x2: "eui", 0x8: "name", 0x1: "t10"}
# SPC NAA field -> required designator length: IEEE Extended (2), Locally
# Assigned (3) and IEEE Registered (5) are 8 bytes, IEEE Registered Extended
# (6) is 16 bytes. Any other NAA field or length is nonconforming.
_NAA_LENGTH = {0x2: 8, 0x3: 8, 0x5: 8, 0x6: 16}


def _designator(code_set: int, kind: int, value: bytes) -> str:
    """Canonical text for one conforming designator, or "" when unusable."""
    if kind in (0x2, 0x3):
        # Binary identifiers: NAA with a defined NAA field and that field's
        # length, EUI-64 based 8/12/16 bytes. All-zero values identify nothing.
        if code_set != 0x1 or not any(value):
            return ""
        if kind == 0x3 and _NAA_LENGTH.get(value[0] >> 4) != len(value):
            return ""
        if kind == 0x2 and len(value) not in (8, 12, 16):
            return ""
        return value.hex()
    if kind == 0x8:
        # SCSI name string: UTF-8, NUL terminated/padded to a multiple of 4.
        if code_set != 0x3 or len(value) % 4:
            return ""
        text = value.rstrip(b"\x00")
        try:
            decoded = text.decode("utf-8", errors="strict")
        except UnicodeError:
            return ""
        return decoded if decoded.isprintable() and decoded.strip() else ""
    # T10 vendor ID: 8-byte vendor field plus a non-blank vendor-specific part.
    if code_set != 0x2 or len(value) <= 8 or not value[8:].strip(b" \x00"):
        return ""
    try:
        return _ascii(value)
    except ProbeUnavailable:
        return ""


def _vpd_designator(data: bytes) -> str:
    """Best logical-unit designator from VPD page 0x83 (Device Identification).

    Every descriptor is bounds-checked against the page length; any framing
    fault makes the whole page unavailable rather than partially trusted.
    """
    payload = _vpd_page(data, 0x83)
    best = None
    offset = 0
    while offset < len(payload):
        if offset + 4 > len(payload):
            raise ProbeUnavailable()
        header, length = payload[offset:offset + 4], payload[offset + 3]
        end = offset + 4 + length
        if end > len(payload):
            raise ProbeUnavailable()
        code_set, association, kind = header[0] & 0x0F, (header[1] >> 4) & 0x3, header[1] & 0x0F
        if association == 0 and kind in _DESIGNATOR_RANK:
            text = _designator(code_set, kind, payload[offset + 4:end])
            rank = list(_DESIGNATOR_RANK).index(kind)
            if text and (best is None or rank < best[0]):
                best = (rank, _DESIGNATOR_RANK[kind] + "." + text)
        offset = end
    return _bounded(_identity(best[1])) if best else ""


def _optional_vpd(path: Path, parse) -> str:
    """Absent, unreadable or malformed VPD is unavailable, never an identity."""
    try:
        return parse(_read_bytes(path))
    except ProbeUnavailable:
        return ""


def _pci_slot(value: str) -> str:
    match = re.fullmatch(r"([0-9a-fA-F]{4,8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if match is None:
        raise ProbeUnavailable()
    domain, bus, device, function = match.groups()
    return f"{int(domain, 16):04x}:{bus.lower()}:{device.lower()}.{function}"


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
            try:
                sectors = int(_read(device / "size"))
            except (ProbeUnavailable, ValueError):
                sectors = 0
            # Preserve other disks when e.g. an empty optical drive reports 0.
            # This location is observed but its capacity cannot be verified.
            properties = _pairs({"capacity_bytes": str(sectors * 512) if sectors > 0 else "",
                                 "model": _optional(device / "device/model")})
            identifiers = _pairs(self._storage_identity(device))
            components.append(Component(Kind.STORAGE, device.name, properties, identifiers, complete=sectors > 0))
        return tuple(components)

    @staticmethod
    def _storage_identity(device: Path) -> dict[str, str]:
        """Per-family identity sources in fixed precedence (Issue #23).

        Each family contributes at most one key, named after its source, so a
        value from one source is never compared with another source's format:

        - unit serial: ``device/serial`` (NVMe/MMC and others; unchanged key
          ``serial``), else SCSI/SATA VPD page 0x80 (``vpd_pg80_serial``);
        - logical-unit name: block ``wwid`` (NVMe; unchanged key ``wwid``),
          else the kernel's SCSI ``device/wwid`` (``scsi_wwid``), else the
          best VPD page 0x83 designator (``vpd_pg83_designator``).

        Devices whose existing sources are present keep exactly their prior
        identity. A device that previously exposed none gains new keys, which
        compare as UNVERIFIABLE against the old baseline until the Owner
        approves a new one; nothing is silently accepted. All sources are
        world-readable sysfs attributes; no source requires root.
        """
        serial = _identity(_optional(device / "device/serial"))
        wwid = _identity(_optional(device / "wwid"))
        identity = {"serial": serial, "wwid": wwid}
        if not serial:
            identity["vpd_pg80_serial"] = _optional_vpd(device / "device/vpd_pg80", _vpd_unit_serial)
        if not wwid:
            scsi_wwid = _bounded(_identity(_optional(device / "device/wwid")))
            if scsi_wwid:
                identity["scsi_wwid"] = scsi_wwid
            else:
                identity["vpd_pg83_designator"] = _optional_vpd(device / "device/vpd_pg83", _vpd_designator)
        return identity

    def _gpu(self):
        components = []
        gpu_ids = {}
        try:
            output = self.runner.run(("nvidia-smi", "--query-gpu=pci.bus_id,uuid,serial", "--format=csv,noheader,nounits"))
            for row in csv.reader(io.StringIO(output.decode("utf-8"))):
                if len(row) != 3:
                    raise ProbeUnavailable()
                slot, uuid, serial = (value.strip() for value in row)
                normalized = _pci_slot(slot)
                if normalized in gpu_ids:
                    raise ProbeUnavailable()
                gpu_ids[normalized] = _pairs({"uuid": _identity(uuid), "serial": _identity(serial)})
        except (ProbeUnavailable, UnicodeError):
            gpu_ids = {}
        for device in sorted((self.root / "sys/bus/pci/devices").iterdir()):
            class_id = int(_read(device / "class"), 16)
            if class_id >> 16 != 3:
                continue
            properties = _pairs({key: _read(device / key) for key in ("vendor", "device", "subsystem_vendor", "subsystem_device")})
            components.append(Component(Kind.GPU, device.name, properties, gpu_ids.get(_pci_slot(device.name), ())))
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
