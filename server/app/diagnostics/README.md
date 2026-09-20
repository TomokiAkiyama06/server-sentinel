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
or storage reservation. A cancelled caller never receives a bundle name, so a
bundle the drained worker had already published — including any Owner-selected
raw media — is durably unlinked and directory-fsynced instead of accumulating on
disk across repeated disconnects.

Admission, bundle I/O and release are submitted as one unit to the storage
policy's owning worker. `MainStoragePolicy` admits, releases and serializes every
filesystem writer on the thread that constructed it and otherwise reports
`STORAGE_POLICY_UNAVAILABLE`, so running the reservation elsewhere would reject
every export or hold a reservation across an unrelated owner-worker operation.
Before opening a temporary bundle, the service reserves the exact `ZIP_STORED`
byte count through that policy; the policy owns filesystem allocation and
metadata overhead, pressure/hard-stop state and the deployment hard reserve.

Admission covers the approved storage filesystem, so the export directory is
pinned first: it is opened without following symlinks, must be a private
directory owned by the service account, and must report the same device as the
approved storage root. A target on another filesystem, or a missing or
substituted approved root, is refused before any reservation rather than spending
another volume's hard reserve. Every create, rename, unlink and fsync then uses
that single verified descriptor, so a mount swapped after admission cannot
redirect the bundle or its cleanup.

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
bundle at 1 GiB; short, growing, or contract-breaking streams fail closed.

`app.api.diagnostics` provides the prepared integration route. Application
composition accepts only a `DiagnosticExportEndpoint` with a fixed local output
directory. Production keeps the human surface closed until Issue #10 lands; when
mounted, the route requires the existing human access boundary, the Owner-only
route boundary, and the service's exact Owner confirmation.

The manifest reports included categories, counts, exclusion reasons and the
identifier transformation. It contains no excluded value, media ID, path,
deployment hostname, or other private deployment value.
