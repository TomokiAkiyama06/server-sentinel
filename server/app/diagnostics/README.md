# Diagnostic export

This package prepares a deployment-local support bundle in two stages. It first
collects and sanitizes local scalar fields into a value-free confirmation with
included categories, exclusion reasons and individually selected media IDs. It
writes a bundle and resolves selected media only after the injected Owner
authorization boundary approves that exact confirmation and action. The internal
writer is not part of the package API; `DiagnosticExportService.export` is the
only supported creation path. There is no network, upload, share, or scheduled
export primitive.

Only the deployment Owner may reach this package. `require_owner_caller` runs
before collection and before any selected-media lookup, so an invited non-Owner
who passes the generic human/system boundary cannot probe selected-media IDs for
existence or error timing. The later `require_owner_export` step still confirms
the exact sanitized contents. The service refuses to construct without both
gates, and `app.api.diagnostics` additionally depends on the Owner-only route
boundary.

The service dispatches collection through a one-slot worker boundary so the ASGI
event loop is not blocked. Before releasing that slot after caller cancellation,
it shields and drains the active worker so no second export can overlap its files
or storage reservation. Whenever a caller will not receive a bundle name — after
cancellation, or when releasing the reservation fails after publication — a bundle
the worker had already published, including any Owner-selected raw media, is
durably unlinked and directory-fsynced instead of accumulating on disk. The
publication directory's device and inode are recorded with the result, so
cancellation cleanup verifies it reopened the same directory; a renamed or
replaced directory means the archive is unreachable, an absent file is not
accepted as deletion, and the service blocks later exports instead.

Every submitted call is checked against the worker's first observed thread, so
a worker that drifted onto another thread is refused before admission instead of
splitting admission, bundle I/O and release across threads or letting two
operations share one reservation slot. Concurrent owner-worker work queues
behind an export rather than colliding with its reservation.

Admission uses the explicit non-reclaiming `admit_external` contract. A support
bundle is optional convenience data, not monitoring evidence, so reserving space
for it must never run retention or delete recordings to make room; a deployment
without free space is refused with its current state instead. A policy that only
offers reclaiming admission is rejected when the service is constructed.

Admission, bundle I/O and release are submitted as one unit to the storage
policy's owning worker. `MainStoragePolicy` admits, releases and serializes every
filesystem writer on the thread that constructed it and otherwise reports
`STORAGE_POLICY_UNAVAILABLE`, so running the reservation elsewhere would reject
every export or hold a reservation across an unrelated owner-worker operation.
Before opening a temporary bundle, the service reserves the exact `ZIP_STORED`
byte count through that policy; the policy owns filesystem allocation and
metadata overhead, pressure/hard-stop state and the deployment hard reserve. A
composed policy denies with its own error type and a fixed reason code, so
admission translates that into this package's value-free error: reviewed codes
such as `STORAGE_PRESSURE` and `STORAGE_HARD_STOP` are preserved and any other
message is replaced rather than relayed to the caller.

Admission covers the approved storage filesystem, so the export directory is
pinned first. The configured target must be absolute and normalized, and every
path component is opened without following symlinks, including parents: a
replaced parent would otherwise redirect the bundle into another directory on
the same admitted device, and `O_NOFOLLOW` alone protects only the final
component. No fallback directory is created. The pinned directory must be
private and owned by the service account, and its device must match the approved
`RootIdentity` that composition also configured the storage policy with. Because
an open descriptor's device cannot change and the approved identity is a fixed
configured value, that check is atomic with admission — it is not a second
pathname sample that a mount substituted and restored around `admit()` could
race. A substituted approved root is refused by the policy itself, which hard
stops rather than reserving space on a replacement filesystem. Every create,
rename, unlink and fsync then uses that single verified descriptor, so a mount
swapped after admission cannot redirect the bundle or its cleanup.

Before ordinary success is reported, the configured pathname is reopened and
must still name the directory that received the archive. A directory renamed or
replaced mid-export keeps receiving writes through the pinned descriptor while
the reported bundle name would no longer be found where the Owner configured it,
so that archive is removed through the same descriptor and the export fails
closed instead of reporting a name the Owner cannot act on.

Admission remains held through publication and directory fsync. Failure removes
and directory-fsyncs the temporary file, or an already-renamed bundle when final
directory fsync fails, before releasing the reservation. If durable cleanup
cannot be confirmed, the service retains the reservation and blocks later
exports for its lifetime rather than admitting writes against uncertain space.

Every diagnostic producer must use an allowlisted category, label scalar fields,
and use a centrally reviewed `SafeDiagnosticFieldName` for included fields.
Unknown names fail closed rather than relying on secret-name pattern matching.
Allowlisted names are not free-form value channels: state/health, component and
reason fields require reviewed enums; versions use a bounded numeric form;
counts and enabled flags require bounded integer and strict boolean values.
Private hostnames, identifiers or secrets therefore cannot be placed in a
generic `status` or `component` string.
Credentials, pairing
secrets, private keys, sensitive headers, Owner biometric data, and embedded raw
media are always excluded. Hardware serials/UUIDs receive a keyed per-bundle
digest; the ephemeral key is never exported. Raw monitoring media uses a separate resolver which cannot enumerate
media and is called only for IDs individually selected in the authorized action.
Selected metadata is sized before admission; after approval each item is
re-checked on the owning worker immediately before its copy, then opened, type
checked, copied through a bounded 64 KiB reader and released before the next
item is opened. The re-check catches a concurrent retention delete or an item
still being written before any byte is copied, so a doomed copy does not hold
the owning worker away from recording work; a change that appears mid-copy still
fails the export closed. Individual media is capped at 512 MiB and the complete diagnostic
bundle at 1 GiB. These are defensive implementation upper bounds; the
deployment-configured storage maximum request size stays authoritative and
refuses anything larger, and both bounds also limit how long one export can
occupy the storage policy's owning worker. Short, growing, or contract-breaking
streams fail closed.

`app.api.diagnostics` provides the prepared integration route. Application
composition accepts only a `DiagnosticExportEndpoint` with a fixed local output
directory. Production keeps the human surface closed until Issue #10 lands; when
mounted, the route requires the existing human access boundary, the Owner-only
route boundary, and the service's exact Owner confirmation. It reports fixed
statuses only: a rejected selection never echoes the submitted identifiers, and a
failure reports one reviewed fixed code. Only the two deployment storage
conditions an Owner acts on, `STORAGE_PRESSURE` and `STORAGE_HARD_STOP`, keep
their code so the Owner is not shown a silent generic error. Internal
reservation and policy-binding faults describe composition state rather than a
deployment condition, so they and every other failure become
`DIAGNOSTIC_EXPORT_UNAVAILABLE`.

The manifest reports included categories, counts, exclusion reasons and the
identifier transformation. It contains no excluded value, media ID, path,
deployment hostname, or other private deployment value.

## Production producers (`app.diagnostics.sources`)

`compose_diagnostic_sources(...)` builds the production `DiagnosticSource` and,
when the monitoring runtime and its owning worker are supplied, the
recording-backed `MediaSource`. It mounts no route and changes no application
composition; wiring it to `DiagnosticExportService` is a later slice.

Each adapter reads an existing bounded, value-free health surface and maps it
onto the reviewed field names and enums in `export.py`; every name is bound to
exactly one value type (state enum, reason-code enum or bounded count), so no
adapter can place a free-form string in the bundle. `CompositeDiagnosticSource`
additionally refuses any field that is not of the SAFE kind, so the production
producers contribute no value the export would have to hash or exclude.

| Category | Adapter | Reads |
| --- | --- | --- |
| `runtime` | `VersionAdapter`, `MonitoringRuntimeAdapter` | `app.__version__`; `MonitoringRuntime.status` runtime state and retention / daily-summary / notification job flags |
| `camera_health` | `CameraRegistryAdapter` | counts of sources by type and, for enabled sources, by health, plus the active-source limit |
| `recording_health` | `RecordingHealthAdapter` | latest daily recording self-test verdict and self-test job health |
| `storage` | `StorageAdapter` | storage state (`STORAGE_PRESSURE` / `STORAGE_HARD_STOP`), storage-audit delivery and recording filesystem verdict |
| `hardware_inventory` | `IntegrityAdapter` | Hardware Integrity verdict per category (CPU / memory / storage / GPU) as fixed reason codes, check and delivery health |
| `security` | `AuditDeliveryAdapter` x3, `AuditRetentionAdapter` | `audit_delivery_failed` / `undelivered_audit_records` of the Owner audit service, access store and pairing ledger; audit-retention health |

Nothing else is read. Camera names, role labels, capability documents, serials,
device paths, capture-node names, image-quality text, integrity baseline
observations and finding reason text, pairing codes and digests, Slack endpoint
values, credentials, WebAuthn material and the Owner template store are never
touched, so they cannot reach a bundle even hashed.

A subsystem that is not composed reports `unavailable` with `not_configured`
and contributes no counts. A subsystem that raises reports `unavailable` with
`dependency_unavailable`; its exception text is discarded. A monitoring job flag
defaults to "not degraded" before the worker runs, so job states are reported
`ok` only while the monitoring runtime is `running`; a missing verdict is
`unknown`, and an integrity category the check did not report is
`hardware_unverifiable`. A category with several baseline components (DIMMs,
disks) reports its most severe component finding. A runtime whose startup
failed keeps its explicit storage hard stop (`failed` / `storage_hard_stop`);
a stopped or starting runtime reports storage `unavailable`. No absent or
failing subsystem is ever reported `ok`.

`RecordingStore` and `IntegrityStore` refuse calls off the monitoring worker, so
`OwnerWorkerCalls` submits their reads to that worker with a bounded wait and
refuses a worker that drifts to another thread. The supplied worker must be the
same one the export service admits storage through.

`RecordingSegmentMediaSource` cannot enumerate media. It resolves only IDs of
the form `segment.<32 lowercase hex>` naming one published recording segment;
no other namespace, including Owner biometric template/embedding, face crop or
self-test artifact, is resolvable, so biometric data can never be selected. The
segment is opened by `RecordingStore.open_segment` relative to the pinned,
verified recording root without following symlinks, and must be a single-link
regular file whose size matches the journal. The exporter hashes exactly the
bytes it copies into the bundle and compares them with the journaled SHA-256
before publishing, so a same-length rewrite, including one made after the file
was opened, fails the export and no bundle is published. It is opened only on the owning
worker, during the export's copy, after the Owner confirmed the selection.

None of these producers opens a socket, schedules work or writes. Tests seed
synthetic canary camera names, serials, device paths, a Slack webhook URL, a
pairing code and Owner template bytes, and verify none appear in the bundle,
that media is absent unless individually selected, and that no network call is
attempted during export.
