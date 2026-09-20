# Diagnostic export

This package prepares a deployment-local support bundle in two stages. It first
collects and sanitizes local scalar fields into a value-free confirmation with
included categories, exclusion reasons and individually selected media IDs. It
writes a bundle and resolves selected media only after the injected Owner
authorization boundary approves that exact confirmation and action. The internal
writer is not part of the package API; `DiagnosticExportService.export` is the
only supported creation path. There is no network, upload, share, or scheduled
export primitive.

The service dispatches collection, selected-media access, ZIP writing and fsync
through a one-slot worker boundary so the ASGI event loop is not blocked. Before
opening a temporary bundle, it reserves the exact `ZIP_STORED` byte count through
the shared storage admission policy; the policy owns filesystem allocation and
metadata overhead, pressure/hard-stop state and the deployment hard reserve.
Admission remains held through publication and directory fsync. Failure removes
the temporary file, or removes and fsyncs an already-renamed bundle when final
directory fsync fails, before releasing the reservation.

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
size/type checked, written and released before the next item is opened.

`app.api.diagnostics` provides the prepared integration route. Application
composition accepts only a `DiagnosticExportEndpoint` with a fixed local output
directory. Production keeps the human surface closed until Issue #10 lands; when
mounted, the route requires both the existing human access boundary and the
service's exact Owner confirmation.

The manifest reports included categories, counts, exclusion reasons and the
identifier transformation. It contains no excluded value, media ID, path,
deployment hostname, or other private deployment value.
