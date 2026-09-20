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

## Recording browser and storage/notification screens for #21

`src/recordings/view.tsx` lists authorized recordings with time, camera, type
(event / manual / critical evidence), recording coverage state, length, size and remaining Main
retention. Starred recordings are shown as never auto-deleted instead of a day
count. Playback is in-browser only: there is no download, export, media link or
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
that write is unknown rather than the list being unavailable.

`src/setup/storage.tsx` is owner-only. It shows the three backend storage states
(`NORMAL`, `STORAGE_PRESSURE`, `STORAGE_HARD_STOP`), marks the current one, and
states that recovery uses hysteresis. The disk breakdown meters unstarred
recordings, starred recordings, free space and the hard filesystem reserve
separately, with tabular numerals, and notes that other processes' usage is part
of the admission decision. Only space the filesystem still holds is metered: if
external consumption has already eaten into the configured reserve, the reserve
bar shows just the remaining part, the configured target is listed as a separate
figure, and the missing amount is reported as an alert instead of being drawn as
capacity. The three retention periods are displayed as separate
lifecycles: Main recordings 20 days, audit 90 days, and agent protected
incidents 60 days, with an explicit note that Main retention and cleanup never
shorten or delete the agent-owned incidents. Slack is shown as disabled until
configured, with the 23:00 local daily summary, immediate critical/hardware/
self-test alerts, and ordinary person/motion aggregated into the summary. No
Slack credential is rendered.

`canVisit` keeps `storage` owner-only and `recordings` behind `recordings:view`;
`live:view` alone reaches neither the recording list nor historical metadata.
The production entry still uses `deniedServices`, which supplies no recording,
storage or mutation provider. Server wiring for these screens is #42.

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
