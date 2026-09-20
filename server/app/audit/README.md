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

`AuditStore.cleanup_expired()` defaults to 90 days and deletes only rows from
the audit table that are strictly older than the cutoff. The Main Server runs it
at startup and every 24 hours through `AuditRetentionRuntime`.
