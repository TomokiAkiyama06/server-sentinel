# Human Web Dashboard

Owns responsive phone/Mac/desktop viewing and owner configuration through the Main Server. `src/` separates dashboard, access, recordings, timeline, setup, and shared UI responsibilities.

Private-network reachability and ServerSentinel invitation/permission are independent gates. `live:view` and `recordings:view` are independent; historical events/timeline require `recordings:view`. The server enforces every permission, including playback assets.

Browsers are viewers in MVP: no browser/iPhone camera capture, audio controls, direct agent viewing, or non-owner download/export feature. Browser playback does not prevent screen recording/client capture. Do not claim network concealment with unchanged Tailnet policy or show unreliable detection as a trustworthy negative.

## Foundation implemented for #8

The React/TypeScript shell defaults to Japanese and includes an English catalog,
responsive navigation, and six placeholders: Overview, Camera Sources, Capture
Nodes, Live, Recordings, and Access. Camera summaries are an ID-keyed collection
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
neutral text, source/detector attribution and confidence/quality. Unreliable or
unavailable results stay `unknown` and are never shown as "no person". Clock
skew or timestamp discontinuity is reported per span and by an ordering notice;
the UI does not present that order as established causality, cause or
culpability. A kind filter selects all, people/motion, critical, device and
recording, or configuration entries. `src/views/presence.tsx` shows the current
state, its basis, manual-override expiry and cancel affordance, the fact that
only `PRESENT` suppresses ordinary occupancy automation, that critical work
continues in every state, and today's transitions.

`canVisit()` keeps the timeline with `recordings:view` and presence with the
Owner. This remains UI projection only: the production entry still denies
access, these screens make no request without an injected provider, and #10
must supply server-side authorization before any human route is published.
Timeline and presence data are loaded through optional `DashboardServices`
providers that only tests supply, using synthetic observations.

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
