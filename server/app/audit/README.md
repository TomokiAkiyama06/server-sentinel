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
registry, UVC approval, and recording-state mutations. Its injected authorizer
must fail closed unless the current deployment Owner is established. The actor
context is used only by that authorizer and is never stored or represented. A
denied operation is not run; successful and failed operations are recorded
without their result or exception details. `execute_transactional()` places the
domain mutation and successful audit append in the same SQLite transaction, so
an audit write failure rolls the mutation back. Plain `PermissionError` denial
from an injected authorizer is safely classified without inspecting its detail.

Hardware baseline inventory/approval is not implemented in this tree. Plan 23
must call `OwnerAdministration.approve_hardware_baseline()` with its logical
baseline UUID and a transaction-aware mutation callback. That contract fixes
the action to `approve_hardware_baseline` and prevents baseline approval from
committing without its successful audit record; it is not evidence that the
hardware baseline service or probes already exist.

Owner recording deletion commits its `deleting` journal transition and
`delete_recording` audit together. Media cleanup then follows the recording
store's existing recoverable deletion lifecycle. A cleanup interruption leaves
the durable deletion journal for startup recovery rather than restoring a
recording whose links may already have been reclaimed. It also appends a fixed
`delete_recording_cleanup` failure outcome for the same logical recording ID;
the earlier immutable success continues to mean that the Owner-authorized
deletion journal committed, not that physical cleanup completed.

`AuditStore.cleanup_expired()` defaults to 90 days and deletes only rows from
the audit table that are strictly older than the cutoff. The Main Server runs it
at startup and every 24 hours through `AuditRetentionRuntime`. Scheduled
failures set bounded degraded health and are retried at the next interval;
exception details are not retained. Audit browsing uses `AuditCursor`, whose
timestamp plus record UUID matches the stable descending database order so
equal-timestamp records remain reachable across pages.
