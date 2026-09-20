# Main-host hardware integrity

Issue #23's comparison, approval boundary, local persistence and startup/daily
coordinator add no HTTP endpoint. The closed backend launcher does not enable
them. Approved human authorization, production configuration and notification
wiring remain prerequisites; physical acceptance remains open under #23.

`LinuxProbe.collect()` reads CPU signatures/topology from procfs, block-device
size/model/available serial/WWID from sysfs, and display-controller PCI fields.
Optional host-provided `dmidecode --type 17` supplies DIMM slot/capacity/part/serial;
optional `nvidia-smi` supplies exposed GPU UUID/serial. Missing permissions/tools
or malformed data produce `UNVERIFIABLE`, not invented unique identities or proof
that all devices vanished. CPU model/topology or PCI location alone cannot prove
that the physical device is unchanged.

`storage_health()` reads `smartctl --json --health` for explicitly configured
backing block-device paths and returns `OK`, `CRITICAL` or `UNVERIFIABLE`, without
lifetime prediction. Commands have a fixed read-only allowlist, five-second
timeout, one-MiB stdout cap, no shell/sudo, discarded stderr and a minimal
environment without inherited secrets. Utilities/drivers are not installed or
bundled. Keep deployment permissions narrow; never run the backend as root for
inventory. CI does not invoke these host utilities.

Interfaces follow the published [Linux block sysfs ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-block),
[PCI sysfs ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-pci)
and [SMBIOS type-17 interface](https://manpages.debian.org/bookworm/dmidecode/dmidecode.8.en.html).
No Python dependency, downloaded model or redistributed utility is added. Record
host tool versions/availability and driver-specific limits deployment-locally.

`IntegrityStore` receives a deployment-local SQLite connection. Assign
`integrity_migration(version)` the next unused contiguous application schema
slot. The database and journals belong in the private runtime directory, outside
checkout and media export paths. Raw baseline observations are local only and
omit private values from repr; notifications contain no raw inventory.

`OwnerApproval.require_owner()` denies by default. Its trusted implementation
returns a validated application-principal UUID, never a caller-controlled owner
boolean. Approval checks the expected revision and atomically updates/audits the
baseline. Polling never updates it. This domain boundary does not decide the
pending bootstrap/session/recovery policy or expose a human route.

`IntegrityService.startup()` always compares. The owning worker calls `tick()`
regularly; monotonic timing enforces the 24-hour interval despite wall-clock
rollback. This is a coordinator, not an installed timer. The #21 integration
owns scheduling and notification delivery. Faults persist before sink delivery.

The sink receives `(event_id, aware_time, immediate, findings)`, with fixed
categories/states/reasons only. `CHANGED`, `MISSING` and storage-assurance-blocking
`UNVERIFIABLE` are immediate; other unknown/new devices are visible warnings.
The #21 bridge maps immediate faults to `HARDWARE_INTEGRITY_FAILURE`, retaining
local/UI state independently of optional Slack. Pending sink events retry each
tick; delivery is at least once, so consumers can deduplicate by event ID. Status,
approval audit and outbox need #21 retention integration before deployment.

Tests only read generated procfs/sysfs fixtures in temporary directories and
inject command output. They never inspect the test runner's real inventory.
Actual probes/permissions/substitution/notifications remain unchecked in
`MANUAL_TEST.md` S. Recording self-tests belong in `../media/health/`.
