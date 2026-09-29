# Main Server monitoring runtime

Issues #21/#23 lifespan wiring. No HTTP route, listener or human surface is
added; `ClosedHumanSurface` stays installed. Python stdlib only.

`config.parse_monitoring()` validates the deployment configuration's optional
`monitoring` object (see `server/docs/DEPLOYMENT.md`). It is standard-library
only so the standalone installer validates it too. `storage_limits`,
`recording_limits` and `recording_filesystem` are all-or-nothing; without them
`create_app()` keeps `UnboundStorageAdmission` semantics and reports the
explicit `unconfigured` runtime state.

`runtime.MonitoringRuntime` creates every thread-owned component on one
dedicated worker thread: SQLite connection, `MainStoragePolicy` over
`IdentifiedRecordingFilesystem.snapshot`, `StorageAudit` as the policy's
transition sink, a `RecordingStore` bound as inventory/reclaimer (its default
validator refuses every segment until a production codec validator exists),
`NotificationService` with the durable `NotificationEventStore` sink,
`DailySummaryScheduler`, `IntegrityStore`/`IntegrityService` and
`RecordingHealthService`. `reservation()` admits writes from other threads by
parking the worker inside `policy.control()` until the caller exits;
`main.RuntimeStorageAdmission` hands this to the security audit store once the
runtime is running.

Startup: open components, sample storage, run retention, integrity
`startup()`, recording-health `startup()`. Each tick: poll notification
completions, re-verify the recording filesystem, `policy.status()`, expire
recordings (starred never), `storage_state_audit` and 90-day fault history, run
the integrity/health `tick()` and the daily summary. A failing step sets its
status flag and retries after `retry_seconds`; other steps continue. Status is a
frozen `MonitoringStatus` with fixed values only; logs use fixed `Event` codes.

Bridges: integrity outbox rows map to deterministic event IDs, are recorded as
`hardware_integrity_failure` (immediate) or `hardware_integrity_warning`
(local), and are acknowledged only after the local row exists. Recording-health
results persist in `recording_health_status` before notification;
`FAILED` → `recording_health_failure`, `UNAVAILABLE` →
`recording_health_warning`. A recording filesystem mismatch raises one
immediate `recording_health_failure` per episode. A failed startup open is
retried every `retry_seconds` from the tick against the same declared identity;
only the first failure of the episode alerts, and a successful retry runs the
startup steps and binds admission. Slack remains optional and
never determines local state.

`MonitoringDependencies` injects the probe, recorder self-test adapter factory,
segment validator, Slack opener, clocks and intervals. Tests use a synthetic
probe, disposable directories, a test clock and an intercepted transport; they
are not deployment, hardware or configured-Slack acceptance (`MANUAL_TEST.md`
Q/S).
