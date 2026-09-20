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
Selected metadata is sized before admission; after approval each item is opened,
type checked, copied through a bounded 64 KiB reader and released before the next
item is opened. Individual media is capped at 512 MiB and the complete diagnostic
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
failure reports one reviewed fixed code. Explicit deployment conditions such as
`STORAGE_PRESSURE` and `STORAGE_HARD_STOP` keep their code so the Owner is not
shown a silent generic error; anything else becomes
`DIAGNOSTIC_EXPORT_UNAVAILABLE`.

The manifest reports included categories, counts, exclusion reasons and the
identifier transformation. It contains no excluded value, media ID, path,
deployment hostname, or other private deployment value.
