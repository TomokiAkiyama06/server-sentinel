# Security/admin audit boundary

This package stores deployment-local security and administrative audit records.
It is deliberately separate from `app/events`, which owns factual monitoring
timeline observations. Audit retention never calls recording or capture-agent
protected-incident lifecycle code.

Records contain only a generated record UUID, actor category, a fixed action,
target kind, an application logical UUID, UTC occurrence time, and outcome. The
model has no arbitrary metadata, message, request, exception, media, or device
evidence field. Raw credentials, biometric material, serials/UUIDs from
hardware, monitoring media, network values, and submitted setting values must
not be passed as logical IDs.

`OwnerAdministration` is the runtime-facing integration boundary for privileged
registry, UVC approval, and recording-state mutations, and for audit reading
through `list_audit_records()`. Its injected authorizer must fail closed unless
the current deployment Owner is established, and `create_app()` installs
`DenyAllOwners` until a deployment supplies one. The actor context is used only
by that authorizer and is never stored or represented. A denied operation is not
run, and its caller always receives the denial itself: if the denial record
cannot be written, the loss becomes bounded health rather than a storage error
that would disclose deployment state to a denied actor. Successful and failed
operations are recorded without their result or exception details. `execute_transactional()` places the domain mutation and
successful audit append in the same SQLite transaction, so an audit write
failure rolls the mutation back. Plain `PermissionError` denial from an injected
authorizer is safely classified without inspecting its detail.

Reading audit history is itself a privileged security operation and passes the
same Owner authorizer through `OwnerAuditService.list_records()`. A refused read
writes nothing, so an unauthorized caller cannot grow the audit table.
`AuditStore` is a process-internal primitive with no authorization of its own;
it is called by that Owner boundary and by retention, and is not an API. This
tree publishes no audit HTTP route. Any future route must be served only by the
human dashboard listener behind the Owner boundary — never by the capture
ingest listener — so that an invited `live:view` / `recordings:view` principal
and a capture-node credential cannot read, alter, or delete audit records.

Hardware baseline approval runs through
`OwnerAdministration.approve_integrity_baseline()`, which commits the Issue #23
integrity store's new baseline and its `approve_hardware_baseline` record on
the store's own connection, inside the store's storage reservation. The
underlying `approve_hardware_baseline()` contract stays available for any other
baseline owner: it takes a fixed logical baseline UUID and a transaction-aware
mutation callback, and prevents a baseline from committing without its
successful audit record. The logical ID names the single Main Server baseline
and carries no hardware serial, device identifier or inventory value.

`RecordingBrowser` in `app/storage/retention.py` performs Owner star/delete
only through an injected `OwnerAdministration`; without one it refuses with
`RECORDING_AUDIT_UNAVAILABLE` instead of mutating the store directly, and
`LocalUvcAdapter` exposes no public unaudited camera approval. `CameraRegistry`
refuses its own privileged write wrappers with `UnauditedWriteError` unless it
was explicitly constructed for non-runtime fixtures or bootstrap, while reads
and runtime health observations stay available. An Owner change therefore
cannot reach a recording, a camera approval or privileged registry
configuration without its record.

Owner recording deletion commits its `deleting` journal transition and
`delete_recording` audit together. Media cleanup then follows the recording
store's existing recoverable deletion lifecycle. A cleanup interruption leaves
the durable deletion journal for startup recovery rather than restoring a
recording whose links may already have been reclaimed. It also appends a fixed
`delete_recording_cleanup` failure outcome for the same logical recording ID;
the earlier immutable success continues to mean that the Owner-authorized
deletion journal committed, not that physical cleanup completed.

`AuditStore.cleanup_expired()` defaults to 90 days and deletes only rows from
the security/admin and hardware-baseline approval audit tables that are strictly
older than one cutoff computed for the whole run. The private Owner-template
store exposes the same bounded cleanup contract and is supplied to
`create_app(audit_retention_stores=...)` when that optional store is active;
its database remains separately verified and is never attached to the Main DB.
Expired rows are removed oldest first in bounded transactions, so a large
backlog never grows one rollback journal beyond the configured write overhead.
Each committed batch is durable on its own: an interrupted run leaves a
consistent store, the next run resumes, and repeating a completed run deletes
nothing more. The Main Server runs one bounded batch at startup and drains any
backlog through `AuditRetentionRuntime` on bounded worker threads, yielding
between batches so the asyncio request loop stays responsive. Cancellation
waits for the current SQLite transaction to finish before shutdown. A failed
run sets bounded degraded health and is
retried on a shorter interval, so a transient fault cannot delay expired-row
deletion by a whole day; exception details are not retained. A degraded startup
run is reported as `audit_retention_degraded` and does not stop the Main Server
from monitoring, because a storage or database fault in retention must not take
physical-security monitoring offline. Audit
browsing uses `AuditCursor`, whose timestamp plus record UUID matches the stable
descending database order so equal-timestamp records remain reachable across
pages.

Every audit write — success, failure, denial and retention cleanup — is admitted
through an injected storage reservation, so audit rows, their rollback journal
and this subsystem's transaction metadata can never spend the hard filesystem
reserve. `create_app(storage_reservation=...)` receives the deployment's Main
Server storage admission, which this subsystem consumes rather than defines: it
never invents a numeric filesystem reserve of its own. Until the Main Server
binds that policy, `create_app()` installs `UnboundStorageAdmission`, which
refuses audit writes instead of admitting them against a reserve this process
cannot verify — the same default-deny posture as `DenyAllOwners`. That state is
explicit in `application.state.audit_storage_admitted`, retention health is
degraded rather than silently healthy, and Owner-only reading stays available. Owner
operations that already own an admitted reservation, such as the recording
store's starred/delete transactions, pass it as `reservation=` so the shared
transaction stays admitted until it commits or rolls back. A refused admission
records no row: the storage owner's bounded error propagates, and an outcome
that could not be delivered is counted in `OwnerAuditService`'s
`audit_delivery_failed` / `undelivered_audit_records` health instead of being
silently dropped. Reading audit records never reserves storage.
