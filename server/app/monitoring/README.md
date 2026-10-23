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
changed major, a device that does not rest only on hardware disks (every
leaf disk, through a partition's parent disk or dm/md `slaves/`, needs a
sysfs `device` bus link; loop/nbd/zram lack it) or a device without a
readable sysfs entry refuses (`renumbered_device_acceptable`). A failed startup open is
retried every `retry_seconds` from the tick against the same declared identity;
a failed database open (e.g. SQLite I/O error or permission change) takes the
same alerting startup-failure path. Only the first failure of the episode alerts, and a successful retry runs the
startup steps and binds admission. Slack remains optional and
never determines local state.

Camera offline (Issue #301 item 2, Owner decision 2026-10-22):
`create_app` builds one `cameras.CameraOfflineMonitor` for the configured
local UVC sources and hands it to the runtime as
`MonitoringDependencies(camera_offline=)` (an embedder may not supply its
own). It is fed by the capture runtime's health sink and the application
capture watcher's status poll, and drained every tick, also while `failed`:
a source not online for `camera_offline_notification.after_seconds` (default
300 s) is one confirmed `camera_offline` notification per episode, at most
`hourly_limit` (default 4) per rolling hour, re-seeded from the accepted rows
of the last hour on the first running tick. An episode in progress is named
`uuid5(EVENT_NAMESPACE, "camera-offline:<source>:<last_seen_at>")` from the
registry, so a restart during the same outage finds the row and does not
notify again when its delivery is final (`sent`, `failed`, `disabled`). A
`pending` row (the stopped process never stored the Slack outcome) is not
confirmed: the first running tick submits the newest confirmed pending rows
whose event time is less than 24 h old (at most `hourly_limit`) again under
their stored ID and time, also when the outage has recovered (Issue #336).
The cap stays absolute (PR #339): a resend whose row still holds a slot of the
restored hour waits for that slot to expire (up to about an hour), and live
alerts go before resends. A row of that name accepted more than
24 h earlier no longer counts (Owner decision 2026-10-22): the next name
`…:repeat:N` of a deterministic chain is then used and the outage is notified
again under the cap. Intermittent outages (Refs #301): a source not online for
`flapping_offline_seconds` (default 300 s) in total within the last
`flapping_window_seconds` (default 900 s), over at least two not-online
periods, is one more `camera_offline` under the same cap, once per flapping
period: a sent notification of a source opens its alerted period, which
closes after a whole window online; while it is open the ratio rule stays
silent, and in a period a ratio alert opened only the first outage that
stays offline for `after_seconds` after a short online is notified once more
(at most two per flapping period, Owner decision 2026-10-23); an outage after
an online of at least `after_seconds` is an ordinary episode. A ratio alert is named
`uuid5(EVENT_NAMESPACE, "camera-offline-flapping:<source>:<window>:<bucket>")`
after the wall-clock window bucket, so a restart within a window of it sends
nothing again. See SPECIFICATION §9 for the full rules and the known limits.

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
