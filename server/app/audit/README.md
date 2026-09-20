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

`OwnerAuditService.execute()` is the integration boundary for privileged
mutations. Its injected authorizer must fail closed unless the current
deployment Owner is established. The actor context is used only by that
authorizer and is never stored or represented. A denied operation is not run;
successful and failed operations are recorded without their result or exception
details. Integrations that need atomic mutation plus audit must use a shared
transactional adapter rather than treating an audit success as authorization.

`AuditStore.cleanup_expired()` defaults to 90 days and deletes only rows from
the audit table that are strictly older than the cutoff. Scheduling belongs to
the future Main Server runtime supervisor.
