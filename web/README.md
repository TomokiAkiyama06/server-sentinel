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
neutral text, source attribution and confidence/quality. Only a detector result
is attributed to a detector; status and control events report their kind. Unreliable or
unavailable results stay `unknown`: a quality-gated negative is never shown as
"no person", and a low-quality detector observation (person, motion, owner and
anonymous entry/exit, server movement, camera tamper) is never shown as a
factual detection, including the detector contract's `degraded` quality. Status
and configuration events, whose reported state is not image-quality gated, keep
their value with the quality shown beside it, and the value labels cover every
source/node health transition, including `manual_intervention_required` and
`revoked`. The `critical` badge names the detector category, not a confirmed
event, and a quality-gated result is never labelled confirmed. Rows follow the
Main Server receipt order the core reports and each row also shows its own
observation time, and a `next_cursor` offers the older part of the window
through a load-more control so a limited response cannot hide older events; a
failed page keeps the history already loaded and reports the failure beside the
retry. The ordering statement follows `ordering_basis` while
`ordering_degraded` adds the warning. Clock skew or timestamp discontinuity is
reported per span and by that ordering notice;
the UI does not present that order as established causality, cause or
culpability. A kind filter selects all, people/motion, critical, device and
recording, or configuration entries. `src/views/presence.tsx` shows the current
state, its basis, manual-override expiry and cancel affordance, the fact that
only `PRESENT` suppresses ordinary occupancy automation, and today's
audited Owner control history. Suppression is judged against the state *and*
clock trust, because the core suppresses ordinary automation only for a trusted
`PRESENT`; a report that disagrees raises a degraded alert with the reported
suppression instead of a contradictory statement. The four critical paths
(detection, persistence, evidence, notification) are shown with their reported
`armed` / `unavailable` / `unknown` state, a known failure is never merged with
an unreported one, and the continuity statement appears only while every path is
armed and `critical_paths_degraded` is false; aggregate degradation with every
path armed gets its own wording rather than contradicting the breakdown; an evidence or notification path
also reports `unavailable` while a submission is in flight or accepted but
unconfirmed. An incomplete override expiry (`override_expiry_pending`) is
reported so an expired override cannot look active. The snapshot is not left stale: the screen shows when it was fetched,
offers an explicit refresh, and re-reads itself once a known future override
expiry passes (at most hourly, and never rescheduling an expiry that already
passed); that automatic re-read defers while a control operation is in flight,
and a read that a newer control result superseded is discarded. A failed
refresh keeps the last known status, its fetch time and the retry control. Override cancellation is serialized, so a second click cannot start a
duplicate audited control operation. The control history
explains the Owner critical-recovery actions, including that an approved
requeue accepts a possible duplicate preservation or notification. The critical-continuity statement is shown only while every
reported `critical_*_armed` flag is true; otherwise the screen raises a degraded
alert instead of reassuring the Owner.

`canVisit()` keeps the timeline with `recordings:view` and presence with the
Owner. This remains UI projection only: the production entry still denies
access, these screens make no request without an injected provider, and #10
must supply server-side authorization before any human route is published.
The projections follow the presence/timeline core contract (Issue #26 core PR):
receipt-ordered pages with a `next_cursor`, the presence snapshot's three-valued
critical paths, and the audited Owner control history. Timeline and presence
data are loaded through optional `DashboardServices` providers that only tests
supply, using synthetic observations. Providers are
invoked bound to their service, so a class-based implementation keeps its
receiver; the browser harness is class-based to hold that contract. A
quality-gated result is never labelled confirmed.

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
