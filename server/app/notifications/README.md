# Optional deployment notifications

This internal module introduces no listener, session or public route. Python
stdlib only: no new package or license obligations. Slack is disabled when no
`SlackEndpoint` is injected. The Owner configures a secret incoming webhook at
deployment time; never place its value in repository files, diagnostics or UI.
The current adapter supports Slack's documented `hooks.slack.com` HTTPS incoming
webhooks, posts directly with certificate verification, disables environment
proxies and redirects, limits response reads and timeout, and never returns or
logs the URL, response body or exception. HTTP error streams are explicitly closed.
See [Slack's incoming webhook contract](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).

`NotificationService(local_sink, slack=None).record(kind, at=aware_datetime,
confirmed=False)` first delivers a fixed-category local event. Confirmed server
movement/camera tamper and hardware-integrity/recording-health failures also enqueue
an immediate fixed-category Slack message, independently of presence. Ordinary
person/motion/entry/camera-offline observations stay local until the summary.
`local_delivery_failed`, `delivery_failed` and `last_delivery` expose failures
without sensitive exception content. Production must supply a durable local sink
that upserts `NotificationEvent` by its generated `event_id`. Initial `pending`
and completed `sent`/`failed` events share that ID. This module does not substitute
Slack delivery for authoritative local state.

Both critical and daily calls return without network IO on the recorder thread.
One lazy daemon delivery thread owns network IO only; `poll()` on the owning
worker performs local persistence/completion callbacks. Queue capacity (default
16, configurable 1–1024) includes deliveries still awaiting local acknowledgement,
so neither work nor completion results grow without bound. A full/closed queue
produces a local failed event and visible sticky failure, never silent success.
If a full disk prevents local persistence, critical delivery may still proceed;
the visible failure remains and completion is retained for local persistence retry
without resending. Call `poll()` on each worker timer tick, not just at 23:00.
Critical `record` also accepts an upstream `event_id: UUID` and an optional
`on_complete(result)` callback. Repeated submissions of that ID coalesce while
pending; the callback runs on `poll`'s owning thread. The upstream durable outbox
must reconcile already-persisted IDs after restart and must not treat `pending`
as confirmed delivery. This in-memory queue does not promise exactly-once Slack
delivery across a crash; retrying an uncertain external POST may duplicate it.
`close()` stops new submissions without waiting for a blocked transport/DNS call;
in-flight/queued events remain durably pending or locally failed as recorded.
After a process crash, the integration outbox owns reconciliation; the service
does not automatically resend uncertain deliveries. No worker thread touches
SQLite, calls the local sink or logs transport exceptions.

`DailySummary` permits only validated aggregate counts/durations/bytes and storage
state, never arbitrary text, source names, host details, credentials or media.
`DailySummaryScheduler(db, ZoneInfo(...), service, reservation=policy.control)`
defaults to 23:00 deployment local time. Call `tick` from the owning worker timer.
Its injected metadata reservation covers claim/result writes; network delivery
runs asynchronously outside that reservation, with completion persisted by
`poll()` on the same owning thread. The caller supplies an autocommit SQLite
connection and assigns the provisional `notification_migration(version)` a
nonconflicting version after other installed migrations.

The persisted local-date claim prevents duplicate sends after process restart,
DST folds and backward clock movement. A skipped wall time sends on the first
tick later that date. Dates missed while offline are not replayed. Failed delivery
is recorded once; no automatic network retries can flood the channel. A crash after the
claim leaves `pending` (uncertain delivery), never a false success. Production
scheduler, health/presence outbox integration and configured Slack acceptance
remain pending; transport and DST tests use generated fixtures and no network.
