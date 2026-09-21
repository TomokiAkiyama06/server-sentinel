# Human Web Dashboard

Owns responsive phone/Mac/desktop viewing and owner configuration through the Main Server. `src/` separates dashboard, access, recordings, timeline, setup, and shared UI responsibilities.

Private-network reachability and ServerSentinel invitation/permission are independent gates. `live:view` and `recordings:view` are independent; historical events/timeline require `recordings:view`. The server enforces every permission, including playback assets.

Browsers are viewers in MVP: no browser/iPhone camera capture, audio controls, direct agent viewing, or non-owner download/export feature. Browser playback does not prevent screen recording/client capture. Do not claim network concealment with unchanged Tailnet policy or show unreliable detection as a trustworthy negative.

## Foundation implemented for #8

The React/TypeScript shell defaults to Japanese and includes an English catalog,
responsive navigation, and placeholders for Overview, Camera Sources, Capture
Nodes, Live, and Access. Camera summaries are an ID-keyed collection
with independent type/role, never fixed camera slots. These are foundation
screens, not implemented live playback or access management.

`src/domain.ts` defines an injectable session/source provider. The production
entry uses `deniedServices`, makes no API requests, and grants no access.
`tests/harness.tsx` supplies synthetic providers only in tests, never in `dist`.
URL parameters/local storage cannot activate them. UI checks hide owner-only
metadata from viewers and keep live/recordings permissions independent; they are
not an authorization boundary.

`src/api.ts` supplies an injectable same-origin GET client for future integration.
It rejects non-API/external paths, forbids redirects/caching, passes abort signals,
and returns fixed local errors without logging response bodies. No authentication
method or session endpoint is chosen here. #6/#10 must supply the accepted
identity/session contract and server-side invitation/permission enforcement.

All generated HTML, JavaScript, CSS, icons, license files and future maps,
worker/config files must be served through the protected human listener after
#10. Do not publish them on an independent unauthenticated static host or expose
the preview server as a deployment dashboard. This change mounts no assets on
the backend or ingest listener.

## Timeline and presence screens for #26

`src/views/timeline.tsx` lists one observation per row with its time, kind dot,
neutral text, source attribution and confidence/quality. Only a detector result
is attributed to a detector; status and control events report their kind.

Unreliable or unavailable results stay `unknown`: a quality-gated negative is
never shown as "no person", and a low-quality detector observation (person,
motion, owner and anonymous entry/exit, server movement, camera tamper) is never
shown as a factual detection, including the detector contract's `degraded`
quality. Status and configuration events, whose reported state is not
image-quality gated, keep their value with the quality shown beside it, and the
value labels cover every source/node health transition, including
`manual_intervention_required` and `revoked`. The `critical` badge names the
detector category, not a confirmed event, and a result is labelled confirmed
only when it also meets the core's confirmation prerequisites: sufficient
quality, an observed value and a reported confidence.

Rows follow the Main Server receipt order the core reports, and each row also
shows its own observation time. The core pages forward in that order, so
`next_cursor` leads to *newer* observations; the load-more control is labelled
accordingly, and a failed page keeps the history already loaded and reports the
failure beside the retry. A cursor that stops advancing means the tail of what
the core has received, not a permanent end: the control stays as a check for
newer observations, so an append-only timeline can be re-read without leaving
the screen.
Clock skew or timestamp discontinuity is reported per span and by the ordering
notice; the UI does not present that order as established causality, cause or
culpability. A kind filter selects all, people/motion, critical, device and
recording, or configuration entries.

`src/views/presence.tsx` shows the current state, its basis, manual-override
expiry and cancel affordance, the fact that only `PRESENT` suppresses ordinary
occupancy automation, and the audited Owner control history, which explains the
Owner critical-recovery actions, including that an approved requeue accepts a
possible duplicate preservation or notification. A recovery entry also names
the critical path it applied to and, for a requeue, the observation identifier
the core recorded. Identifiers are shown in full, in the control history and in
timeline attribution, because no prefix length is guaranteed to be unique. The timing trust of the record
behind the current basis is reported separately from the timing trust of
observation receipt.

Suppression is judged against the state *and* clock trust, because the core
suppresses ordinary automation only for a trusted `PRESENT`; a report that
disagrees raises a degraded alert with the reported suppression instead of a
contradictory statement. The four critical paths (detection, persistence,
evidence, notification) are shown with their reported `armed` / `unavailable` /
`unknown` state, a known failure is never merged with an unreported one, and
the continuity statement appears only while every path is armed and
`critical_paths_degraded` is false; aggregate degradation with every path armed
gets its own wording rather than contradicting the breakdown. An evidence or
notification path also reports `unavailable` while a submission is in flight or
accepted but unconfirmed.

An incomplete override expiry (`override_expiry_pending`) is reported so an
expired override cannot look active, and an override the core still applies
past its stated expiry under degraded timing says so rather than looking
ordinary. The snapshot is not left stale: the screen shows when it was fetched,
offers an explicit refresh, and re-reads itself once a known future override
expiry passes (checked at most hourly and re-armed until that expiry is
actually reached, never rescheduling an expiry that already passed). That
automatic re-read defers while a control operation is in flight, a read that a
newer control result superseded is discarded, and a failed refresh keeps the
last known status, its fetch time and the retry control. Override cancellation
is serialized, so a second click cannot start a duplicate audited control
operation. Read and control failures live in the loaded status itself, so an
authoritative report clears them: a cancellation that timed out after the core
applied it cannot leave its alert beside a refreshed state that shows no
override.

`canVisit()` keeps the timeline with `recordings:view` and presence with the
Owner. This remains UI projection only: the production entry still denies
access, these screens make no request without an injected provider, and #10
must supply server-side authorization before any human route is published.
The projections follow the presence/timeline core contract (Issue #26 core PR):
receipt-ordered pages with a `next_cursor`, the presence snapshot's three-valued
critical paths, and the audited Owner control history. Timeline and presence
data are loaded through optional `DashboardServices` providers that only tests
supply, using synthetic observations. Providers are invoked bound to their
service, so a class-based implementation keeps its receiver; the browser
harness is class-based to hold that contract.
## Recording browser and storage/notification screens for #21

`src/recordings/view.tsx` lists authorized recordings with time, camera, type
(event / manual / critical evidence), coverage state, length, size and remaining
Main retention. The type follows the recorder: manual recordings are the rows
`RecordingStore` starts without an `event_id`, and there is no `continuous`
recorder kind. The store's `active`, `complete`, `gapped` and `interrupted`
status is carried through and shown, a known coverage gap is called out instead
of being presented as a complete recording, and an active recording offers no
delete control because `delete_recording()` always refuses one. Starring stays
available for an active recording because the store permits it. Starred
recordings are shown as never auto-deleted instead of a day count.

Opening Recordings obtains a new server snapshot, so an active recording that
later completes, is interrupted, or acquires known coverage loss is not kept as
an earlier session-wide state.

Playback is in-browser only: there is no download, export, media link or
embedded media element for any role, and the screen states plainly that
in-browser playback does not prevent screen recording or client-side copying.
Star, unstar and delete controls render only for an owner session that also has
an authorized mutation provider, and deletion needs a second confirmation in the
same row. The server repeats every one of these checks. `src/shared/mutations.ts`
allows only one in-flight write per recording, so a repeated click cannot issue a
second conflicting mutation; that row's owner controls are disabled and marked
`aria-busy` while the write runs. Replacing the provider or the session aborts
outstanding mutations, and an aborted write is reported as neither a result nor
an error. A rejected write reports itself in its own alert and does not replace
the loaded list with a read-failure banner, because the server-side result of
that write is unknown rather than the list being unavailable. Those unknown
results are tracked per recording and the affected rows are marked. Only a
recording-list reload that actually succeeds clears them, and reloading the list never
clears one. A rejected write may still be applied by the server afterwards, and
`DashboardServices` carries no operation id and no causal ordering between a
write and a later read, so no snapshot can prove what became of it. A marker is
resolved only by a terminal outcome the client actually observed — a later
successful write to the same recording — or by the owner acknowledging that they
checked. The alert says so rather than telling the owner that reloading settles
it, and it names the affected recordings itself: a row marker only shows while
that recording is in the filtered view, and a deleted one may not be listed at
all. Requesting a reload never
clears anything by itself: if the reload fails, the list-unavailable notice
still reports the unknown results. A write that succeeds drops the list in the
same commit as its reload request, so a deleted row cannot briefly stay
interactive and a star cannot briefly show its previous state.

`src/setup/storage.tsx` is owner-only. It shows the three backend storage states
(`NORMAL`, `STORAGE_PRESSURE`, `STORAGE_HARD_STOP`), marks the current one, and
states that recovery uses hysteresis. The disk breakdown meters unstarred
recordings, starred recordings, free space and the hard filesystem reserve
separately, with tabular numerals, and notes that other processes' usage is part
of the admission decision. Only capacity remaining after in-flight
recording-write reservations is metered: the backend sends raw filesystem
availability and `reserved_bytes`, and the view subtracts the latter before
showing free or reserve capacity. If external consumption has already eaten
into the configured reserve, the reserve
bar shows just the remaining part, the configured target is listed as a separate
figure, and the missing amount is reported as an alert instead of being drawn as
capacity. The three retention periods are displayed as separate
lifecycles: Main recordings 20 days, audit 90 days, and agent protected
incidents 60 days, with an explicit note that Main retention and cleanup never
shorten or delete the agent-owned incidents. Slack is shown as disabled until
configured, with the 23:00 local daily summary, immediate critical/hardware/
self-test alerts, and ordinary person/motion aggregated into the summary. No
Slack credential is rendered.

Backend faults stay visible instead of being smoothed over: a lost storage
transition audit, an unfinished retention cleanup, an undelivered Slack
notification and an unrecorded notification each raise their own owner-visible
alert, even once capacity has recovered to `NORMAL` and even while Slack still
reads as configured. Opening the Storage screen always obtains a fresh
operational snapshot, an explicit refresh control re-reads it without
navigating away, and returning to the screen does not reuse an earlier
healthy state, so a backend that later enters `STORAGE_HARD_STOP` cannot stay
hidden behind a stale `NORMAL`. Re-opening Storage or Recordings drops the
previous snapshot during render, before the reload is requested, so a re-opened
screen cannot briefly paint the health or coverage it held last time.

Replacing the provider or retrying the session resets the cached session,
sources, recordings, storage and pending writes during render rather than in a
passive effect, so the previous session's rows are never committed to the screen
under a new provider.

### How these types relate to the backend

No route serves these screens yet, so `src/domain.ts` holds UI projections, not
a mirror of a payload some endpoint already returns. Checked against
`server/app/storage/policy.py`, `server/app/storage/retention.py`,
`server/app/notifications/` and `server/app/media/recording/` on main:

- Same name, same meaning as `StorageStatus`: `state`, `recording_bytes`,
  `starred_bytes`, `reserved_bytes`, `available_bytes`, `hard_reserve_bytes`,
  `recording_limit_bytes`, `critical_allowance_bytes`, `audit_delivery_failed`,
  `cleanup_failed`.
- Renamed from another backend object: `recording_retention_days` and
  `audit_retention_days` are `RetentionPeriods.recording_days` / `.audit_days`;
  `slack_configured` is `SlackDelivery.configured`;
  `notification_delivery_failed` and `notification_log_failed` are
  `NotificationService.delivery_failed` / `.local_delivery_failed`, renamed
  because "delivery failed" is ambiguous inside a storage payload.
- Derived, with no backend field of that name: `daily_summary_local_time`
  (formatted from the daily scheduler's hour, minute and zone) and, on
  `RecordingSummary`, `source_name` (joined from the camera registry), `kind`
  (no `event_id` is manual, the `critical` flag is critical evidence),
  `duration_ms`, `size_bytes` (summed from linked segments) and
  `retention_days_left`.
- **No backend source at all**: `agent_incident_retention_days`. The 60-day
  protected-incident default is documented policy (`agent/storage/README.md`,
  `AGENTS.md`) owned by Plan 9A; nothing on the Main Server produces it today,
  so the screen shows the documented default.

Straight from the `recordings` table: `id`, `source_id`, `status` and `starred`.
`status` uses the store's `active` / `complete` / `gapped` / `interrupted`;
`deleting` never reaches a client because `list_recordings()` excludes it.

`canVisit` keeps `storage` owner-only and `recordings` behind `recordings:view`;
`live:view` alone reaches neither the recording list nor historical metadata.
The production entry still uses `deniedServices`, which supplies no recording,
storage or mutation provider. #21's server-side storage, retention and
notification core landed with #42; the authorized human provider that would feed
these screens is still #10's human-access work, so no deployment serves them yet.

## Local build and tests

Use Node 24 and the committed lockfile:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run lint
npm test
npm run test:browser
npm run preview
```

`preview` binds only `127.0.0.1:4173`, serves the denied shell, and returns empty
404 responses for all API/unknown paths. It is a local development tool.
Browser tests require installed Chrome (`google-chrome` by default;
`SERVERSENTINEL_BROWSER_EXECUTABLE` overrides its path). Absence fails the test;
no browser is downloaded. Tests execute the built production bundle and a
separate synthetic harness.

Node tests cover API failure/redirect/path restrictions, independent permissions,
localization keys, the denied default, production bundle isolation, and the
timeline/presence screens rendered from synthetic observations (permission
separation, kind filtering, `unknown` handling, degraded timing spans, manual
override precedence and always-armed critical work).
Chrome CDP tests cover phone/Mac-sized/desktop viewports, zero through four
synthetic sources, all eight screens, locale switching, session permission
combinations, and normal/error paths with hostile opt-in configuration.
localization keys, the denied default, and production bundle isolation. Rendered
component tests cover owner-only star/delete, the absence of any download,
export or media element, starred recordings shown as never auto-deleted, the
three separate retention periods, storage state display, and Slack disabled
until configured. Mutation tests cover the one-write-per-recording guard,
independent recordings, session abort reported as `aborted`, and rejection
reported as `failed`.
Chrome CDP tests cover phone/Mac-sized/desktop viewports, zero through four
synthetic sources, all seven screens, locale switching, session permission
combinations, synthetic recording lists with owner star/delete confirmation,
each storage state, and normal/error paths with hostile opt-in configuration.
Every page request is intercepted and fulfilled locally or rejected. CSP
violations and WebSocket attempts fail tests. A dedicated external `.invalid`
positive-control request proves interception detects/aborts attempted egress;
no actual external probe is delivered.

Container smoke starts the local preview and checks normal assets/invalid
requests with network disabled, non-root, read-only root, no host mounts, and no
deployment configuration. Browser-page interception does not establish absence
of browser-process/OS background egress. Viewport emulation is not physical
phone, Safari/Mac, private network, camera, or playback acceptance; these remain
#19/#28 and `MANUAL_TEST.md`.

No reporting/advertising SDK, crash uploader, opt-in switch, external font/CDN,
camera/microphone API, or diagnostics export is implemented. See
[dependency notices](THIRD_PARTY_NOTICES.md).
