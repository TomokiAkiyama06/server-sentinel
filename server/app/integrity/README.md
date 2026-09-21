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

Comparison resolves the complete inventory in phases: full identities, globally
unique partial identity links, then all compatible weak links. Missing fields
are not contradictions. Shared/duplicate candidates stay `UNVERIFIABLE`; a weak
match cannot consume another baseline's only possible observation and turn it
into `MISSING`. Kernel/baseline enumeration order is not replacement evidence.

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
before another observation. The durable #21 sink owns fault history and its retention; approval
audit retention also needs that integration before deployment.

Tests only read generated procfs/sysfs fixtures in temporary directories and
inject command output. They never inspect the test runner's real inventory.
Actual probes/permissions/substitution/notifications remain unchecked in
`MANUAL_TEST.md` S. Recording self-tests belong in `../media/health/`.
