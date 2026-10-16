# Live viewer session core

This directory contains the transport-neutral backend slice for Issue #19. A
future human route can use `LiveViewerSessions` only after it has resolved an
application principal and the `live:view` permission. The injected validator is
called again for every caller-facing use, and sessions are bound to the logical
principal, source, and authorization revision. Possession of a copied session ID
is therefore insufficient.

The manager applies explicit total and per-source viewer limits and delegates
viewer demand to `SourcePipeline`. The first pipeline subscriber starts its
viewer adapter; removing the last closes it. Revocation and trusted transport
disconnects release the same demand. A failed cleanup remains visible and can be
retried instead of being reported as successfully idle. Once cleanup starts, the
session never becomes usable again; a later lookup retries idempotent source
removal and still fails closed.

The module is owned by the same single scheduler thread as its pipelines. It does
not add a lock that could suggest codec operations are safe on request threads.
An HTTP/WebSocket/WebRTC/HLS route must dispatch work to that scheduler.

No browser protocol, route, media URL, codec adapter, or deployment default is
selected in `sessions.py`; the S7 interim frame pull below is the only
transport, pending #19. Browser playback,
reconnect/adaptation measurements, private-network authorization, and phone/Mac/
desktop acceptance remain required before Issue #19 can close.

## Local UVC preview wiring (Issue #11)

`local_preview.py` connects the local UVC adapter's frame sink to this session
layer without a route. `LocalPreviewHub.on_frame` runs on capture worker
threads, is lock-protected and never raises into capture; it keeps at most one
latest frame per configured source (bounded by `max_frame_bytes`) and only while
that source has viewer demand, so zero subscribers retain nothing.
`LocalPreviewHub.on_health` is wired to the runtime's in-memory camera state
listener (`on_camera_state`): any non-`online` transition (disconnect, capture
failure, frame stall, manual intervention) drops the retained frame and
refuses new frames until the camera is `online` again, so a pre-loss image is
never served as current live video. It runs in transition order with the
runtime's in-memory health record, not behind the optional downstream health
sink, so a slow or hung sink cannot delay the invalidation.
`LocalPreviewHub.clear()` runs when capture stops and permanently marks every
source non-live, so a worker still finishing a read after a timed-out stop
(`stop_failed`) cannot publish a late frame or re-enable a source.
`AuthorizedLocalPreview` wraps `LiveViewerSessions`: every `open` and `read`
re-runs the validator. The route obtains a `BoundLiveAccess` through
`app.auth.live_access.authorize_live_access`, which runs
`AccessStore.authorize(..., Permission.LIVE_VIEW)` and binds the result to that
caller's human access session. `live_view_validator` reads current state from
SQLite and admits only a bound human session that is not invalidated, expired
or on a revoked credential, of an active principal at the exact bound
authorization revision holding `live:view` (the Owner implicitly); an unbound
`LiveAccess`, `recordings:view` alone, a stale revision, a revoked principal or
credential, an idle/absolute-expired session, a copied session identifier or a
storage error all fail with the same generic refusal and release demand. The
validator does not refresh the idle deadline, so a long-lived transport must
re-authorize through `authorize_live_access` to keep its session current. Browser
transport and codec remain #19 decisions.

## S7 interim frame pull (Issue #10 S7, Owner decision D10)

`frame_pull.LiveFrameService` owns one `AuthorizedLocalPreview` on a
single-thread executor (every open, read, close, disconnect, revalidation and
lease sweep runs there) and is the only reader of the hub. The human surface
mounts it through `HumanAccess.attach_live` (routes and authorization order:
`server/app/auth/README.md`, "S7 interim live frame pull"). A viewer pulls
"the newest frame after sequence n": one native camera JPEG, never transcoded,
or nothing yet. Limits (D10 and the D5 defaults): 4 sessions in total, 2 per
source, 2 per person, at most 5 served frames per second per session, 8 MiB per
frame, a 15 s lease and at most one idle extension of the human session per
60 s per live session. A session whose viewer stops polling is disconnected by
the sweeper (released demand, so the hub retains nothing), as is every session
while human access is closed or the composition is stopped. Nothing is written
per frame. Mock verified only; a browser decoding real MJPG frames is a manual
check.
