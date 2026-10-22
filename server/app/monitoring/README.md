# Main Server monitoring runtime

Issues #21/#23 lifespan wiring. No HTTP route, listener or human surface is
added; `ClosedHumanSurface` stays installed. Python stdlib only.

`config.parse_monitoring()` validates the deployment configuration's
`monitoring` object (see `server/docs/DEPLOYMENT.md`). It is standard-library
only so the standalone installer validates it too. `storage_limits`,
`recording_limits` and `recording_filesystem` are all-or-nothing. The production launcher and
`python -m app` refuse to run without them, because the mandatory
startup/daily integrity check and recording self-test would not run; an
embedded `create_app()` without them keeps `UnboundStorageAdmission` semantics
and reports the explicit `unconfigured` fault at error level; it also runs no
schema migration unless the embedder injects a `storage_reservation`.

Schema migrations are metadata writes: the runtime applies pending
`APPLICATION_MIGRATIONS` on its worker inside `policy.control()`, after the
recording filesystem identity and the hard reserve (plus `write_overhead_bytes`)
were verified. A denial is a startup failure (immediate alert, retry every
`retry_seconds`) with no tables created meanwhile; an invalid schema history or
failed DDL on the first attempt still aborts application startup. An absent
database file is created only after the same identity check, a private database
directory on that filesystem and free space above the hard reserve plus
`write_overhead_bytes`; otherwise no file is created and the startup-failure
alert is sent through Slack (local persistence refused).

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
The lifespan refreshes `application.state.monitoring_state` and
`audit_storage_admitted` after every tick, so they follow a recovered startup.

Bridges: integrity outbox rows map to deterministic event IDs, are recorded as
`hardware_integrity_failure` (immediate) or `hardware_integrity_warning`
(local), and are acknowledged only after the local row exists. Recording-health
results persist in `recording_health_status` before notification;
`FAILED` → `recording_health_failure`, `UNAVAILABLE` →
`recording_health_warning`. A refused status write (e.g. `STORAGE_HARD_STOP`)
still updates the in-memory state and attempts the alert, then marks the step
degraded for retry; while the write keeps failing the same verdict re-alerts at
most once per day. A recording filesystem mismatch raises one
immediate `recording_health_failure` per episode. The recorded major/minor
numbers only corroborate the UUID (Issue #321): when they no longer name the
verified device, storage is admitted, `recording_device_numbers_stale` is set
(degraded in the daily summary and diagnostics) and one immediate
`recording_device_numbers_changed` attention notice is sent per boot and device
numbers (event ID from `/proc/sys/kernel/random/boot_id`; per process start
without it). Only a changed minor of the same kind of device is accepted: a
changed major, a loop device or a device without a sysfs entry refuses
(`renumbered_device_acceptable`). A failed startup open is
retried every `retry_seconds` from the tick against the same declared identity;
a failed database open (e.g. SQLite I/O error or permission change) takes the
same alerting startup-failure path. Only the first failure of the episode alerts, and a successful retry runs the
startup steps and binds admission. Slack remains optional and
never determines local state.

Human access (Issue #232 item 4): `MonitoringDependencies(access_faults=)`
takes the `AccessFaultMonitor` the composition root also passes to the
`HostnameReservationCheck` (`sink=`) and `PasskeyCeremonies` (`findings=`).
Every tick, also while the runtime is `failed` (Slack still receives the
alert), drains it: transitions become the immediate `human_access_fault` /
`human_access_recovered` and the `credential_finding` notifications (one
immediate notification per finding, up to four per rolling hour, the ones over
that cap batched; a budget separate from the access one), and
`MonitoringStatus.human_access_degraded` / `credential_finding_degraded`
follow it; both count as degraded in the daily summary. Both rolling hours continue across a restart: the first running tick re-seeds them from the accepted (non-`pending`) notification rows of the last hour by the wall-clock time since their acceptance (`notification_events.accepted_at`, the row's latest local write, migration 25; a row written before it counts from its event time), filtering the hour before taking the newest rows and ignoring a row stamped in the future, so a restored row counts for at most an hour after the restart (Issue #281 item 2, Issue #287). A notification retried long after its event therefore counts from the retry. When the process started with monitoring `failed` and notified before storage recovered, the stored rows are merged into its window by event ID, so its own rows are not counted twice and the earlier process's rows are not skipped (Issue #287). Once per process,
the first running tick recovers a credential finding whose notification was
lost to a restart: each `credential_finding` event ID names the immutable id
of the newest (highest-rowid) finding audit record it covers; the newest retained finding always restores the one-day hold and is notified once unless that row exists
with a final delivery state. Several findings lost to one crash are thus
recovered as one notification, not one each, and all stay in the audit log
(Issue #281 item 4, Owner decision 2026-10-16 in Issue #287). A fault episode whose newest access row (by
rowid) is `human_access_fault` continues after the restart, so its recovery
is still announced. The rowid, not the wall clock, orders
them, so a clock rollback cannot hide a finding; only the audit action, time
and rowid are read. See
`../auth/README.md` "Owner notification of access faults".

`MonitoringDependencies` injects the probe, recorder self-test adapter factory,
segment validator, Slack opener, clocks and intervals. Tests use a synthetic
probe, disposable directories, a test clock and an intercepted transport; they
are not deployment, hardware or configured-Slack acceptance (`MANUAL_TEST.md`
Q/S).
