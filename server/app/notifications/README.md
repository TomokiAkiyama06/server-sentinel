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
movement/camera tamper and hardware-integrity/recording-health failures also send
an immediate fixed-category Slack message, independently of presence. Ordinary
person/motion/entry/camera-offline observations stay local until the summary.
`local_delivery_failed` and `last_delivery` expose delivery failures without
sensitive exception content. Production must supply a durable local sink/outbox;
this module does not substitute Slack delivery for authoritative local state.

`DailySummary` permits only validated aggregate counts/durations/bytes and storage
state, never arbitrary text, source names, host details, credentials or media.
`DailySummaryScheduler(db, ZoneInfo(...), service, reservation=policy.control)`
defaults to 23:00 deployment local time. Call `tick` from the owning worker timer.
Its injected metadata reservation covers claim/result writes; network delivery
runs outside that reservation. The caller supplies an autocommit SQLite
connection and assigns the provisional `notification_migration(version)` a
nonconflicting version after other installed migrations.

The persisted local-date claim prevents duplicate sends after process restart,
DST folds and backward clock movement. A skipped wall time sends on the first
tick later that date. Dates missed while offline are not replayed. Failed delivery
is recorded once; no automatic retries can flood the channel. A crash after the
claim leaves `pending` (uncertain delivery), never a false success. Production
scheduler, health/presence outbox integration and configured Slack acceptance
remain pending; transport and DST tests use generated fixtures and no network.
