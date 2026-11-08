# Main-host hardware integrity

Issue #23's comparison, approval boundary, local persistence and startup/daily
coordinator add no HTTP endpoint. The closed backend launcher does not enable
them. Approved human authorization, production configuration and notification
wiring remain prerequisites; physical acceptance remains open under #23.

`LinuxProbe.collect()` reads CPU signatures/topology from procfs, block-device
size/model/available serial/WWID from sysfs, and display-controller PCI fields.

Storage identity uses two source families, each in fixed precedence and each
contributing at most one key named after its source: unit serial from
`device/serial` (`serial`, e.g. NVMe) else SCSI VPD page 0x80
(`vpd_pg80_serial`); logical-unit name from block `wwid` (`wwid`, e.g. NVMe)
else the kernel's SCSI `device/wwid` (`scsi_wwid`) else the best logical-unit
VPD page 0x83 designator, NAA > EUI-64 > SCSI name string > T10 vendor ID
(`vpd_pg83_designator`). Vendor-specific and port/group designators are
ignored, as are nonconforming designators (e.g. an NAA whose length does not
match its NAA field). VPD pages are bounds-checked; a wrong page code,
disconnected qualifier, truncated page or overrunning descriptor makes that page
unavailable, and empty/placeholder/non-printable values are never identities.
All sources are world-readable sysfs attributes; no root is needed. Devices
whose earlier sources exist (NVMe) keep an identical identity. SATA/SCSI disks
approved before this precedence recorded no identity: they now compare as
immediate `UNVERIFIABLE` (`IDENTIFIERS_OR_PROPERTIES_INCOMPLETE`) until the
Owner approves a new baseline; the baseline is never updated automatically.
USB bridges that expose no conforming serial/designator stay `UNVERIFIABLE`.
Optional host-provided `dmidecode --type 17` supplies DIMM slot/capacity/part/serial;
optional `nvidia-smi` supplies exposed GPU UUID/serial. Missing permissions/tools
or malformed data produce `UNVERIFIABLE`, not invented unique identities or proof
that all devices vanished. CPU model/topology or PCI location alone cannot prove
that the physical device is unchanged.

Comparison resolves the complete inventory in phases: full identities, globally
unique partial identity links, then all compatible weak links. Missing fields
are not contradictions. Shared/duplicate candidates stay `UNVERIFIABLE`; a weak
match cannot consume another baseline's only possible observation and turn it
into `MISSING`. Kernel/baseline enumeration order is not replacement evidence.

`storage_health()` reads `smartctl --json --health` for explicitly configured
backing block-device paths and returns `OK`, `CRITICAL` or `UNVERIFIABLE`, without
lifetime prediction. Commands have a fixed read-only allowlist, five-second
timeout, one-MiB stdout cap, no shell/sudo, discarded stderr and a minimal
environment without inherited secrets. A command that does not end in time is
killed and waited for at most five more seconds, then abandoned. Issue #385:
once the Main shutdown began (`interrupted`), no further probe starts and a
command in flight is killed within 0.25 s and waited for at most 1 s (a stop
during the normal five-second reap cuts what is left of it to 1 s too); the
collection then raises `StopInterrupted` instead of returning a partial
inventory, and `IntegrityService` records nothing (no change, warning, notice
or baseline update; `monitoring_check_interrupted` is logged). The next start's
startup check runs it. A command ended by SIGTERM is treated the same way only
when the stop begins within `SIGTERM_STOP_WAIT_SECONDS` (6 s: the systemd stop
signals the whole control group before `begin_stop()` runs, which follows the
5 s HTTP graceful wait); a SIGTERM from anything else (an operator's `pkill`, a
watchdog) and any other signal are a failed probe, so the check records it
(PR #389 review). An interrupted check returns `INTERRUPTED`, so the
monitoring runtime keeps the step's degraded flag and retry. Utilities/drivers are not installed or
bundled. Keep deployment permissions narrow; never run the backend as root for
inventory. CI does not invoke these host utilities.

Interfaces follow the published [Linux block sysfs ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-block),
[PCI sysfs ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-pci)
and [SMBIOS type-17 interface](https://manpages.debian.org/bookworm/dmidecode/dmidecode.8.en.html).
No Python dependency, downloaded model or redistributed utility is added. Record
host tool versions/availability and driver-specific limits deployment-locally.

`IntegrityStore` requires an autocommit deployment-local SQLite connection,
an explicit metadata-reservation context factory and a pending-event limit.
All access stays on the creating worker. Every approval, status/outbox and
acknowledgement transaction holds the metadata reservation through commit; a
hard-reserve denial propagates. Assign
`integrity_migration(version)` the next unused contiguous application schema
slot. The database and journals belong in the private runtime directory, outside
checkout and media export paths. Raw baseline observations are local only and
omit private values from repr; notifications contain no raw inventory.

`OwnerApproval.require_owner()` denies by default. Its trusted implementation
returns a validated application-principal UUID, never a caller-controlled owner
boolean. Approval checks the expected revision and atomically updates/audits the
baseline. `approve_on()` is the only approval primitive and opens no transaction
of its own: the audited boundary
`app.audit.integration.OwnerAdministration.approve_integrity_baseline()`
authorizes the Owner, holds the storage reservation and commits the new
baseline, its integrity approval row and the `approve_hardware_baseline`
security audit record in one transaction, so a baseline change cannot commit
without its durable audit record. Polling never updates it. This domain boundary does not decide the
pending bootstrap/session/recovery policy or expose a human route.

`admin_cli.py` (Issue #390, Owner decision 2026-11-05) is the only caller of
that boundary: a local Owner command with the camera command's D3 trust model
(`server/docs/DEPLOYMENT.md`, "Approving the hardware baseline locally").
`show` compares a fresh `LinuxProbe` inventory with the baseline; `approve`
refuses while the service runs, shows the same comparison, asks for `APPROVE` on the controlling
terminal (no bypass flag), re-collects and refuses an inventory that differs
from the one shown, and approves it with the revision read before the prompt.
The store's `OwnerApproval` there is armed only by the one console grant the
audit boundary consumed and returns the fixed `LOCAL_CONSOLE_OWNER_ID` as the
`integrity_audit` actor (the console Owner has no application principal). Its
output is fixed kind/state/reason words and counts only: raw observations,
model strings, PCI ids and paths are never printed. Inside a VM the probe and
the baseline cover only the VM's virtual and passed-through hardware (Owner
decision 2026-10-22).

`IntegrityService.startup()` always compares. The owning worker calls `tick()`
regularly; monotonic timing enforces the 24-hour interval despite wall-clock
rollback. This is a coordinator, not an installed timer. The #21 integration
owns scheduling and notification delivery. Faults persist before sink delivery.

The sink receives `(event_id, aware_time, immediate, findings)`, with fixed
categories/states/reasons only. `CHANGED`, `MISSING` and storage-assurance-blocking
`UNVERIFIABLE` are immediate; other unknown/new devices are visible warnings.
The #21 bridge maps immediate faults to `HARDWARE_INTEGRITY_FAILURE`, retaining
local/UI state independently of optional Slack. Pending sink events retry each
tick; delivery is at least once, so consumers deduplicate by monotonically
increasing event ID. Acknowledged outbox rows are removed after durable sink
acceptance. Pending rows have an explicit capacity limit. Saturation also has
sixteen bounded durable overflow slots (four hardware kinds by four non-OK
states), coalescing repeated observations of the same category/state and
retaining their first observation time. It sets `delivery_blocked` and raises
`IntegrityOutboxFull` (`INTEGRITY_OUTBOX_FULL`). The service catches only this
committed-overflow condition, preserves daily probe cadence, and keeps retrying
delivery each worker tick; storage transaction failures still propagate.
A later healthy status cannot erase these warnings.
Reserved acknowledgement transactions promote overflow into the normal outbox
with the fixed `COALESCED_PENDING_WARNING` reason and fresh monotonic event IDs;
the sink must continue draining on subsequent ticks. Retry drains pending events
before another observation. The durable #21 sink owns fault history and its retention. Hardware
approval rows in `integrity_audit` use the Main audit runtime's 90-day cleanup;
that cleanup never changes the approved baseline, current status or fault outbox.

Tests only read generated procfs/sysfs fixtures in temporary directories and
inject command output. They never inspect the test runner's real inventory.
Actual probes/permissions/substitution/notifications remain unchecked in
`MANUAL_TEST.md` S. Recording self-tests belong in `../media/health/`. `../monitoring/` runs the
startup and 24-hour coordinator and the durable #21 bridge in the application
lifespan when monitoring storage is configured.
