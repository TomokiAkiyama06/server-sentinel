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
selected here. FastAPI's human surface remains closed. Browser playback,
reconnect/adaptation measurements, private-network authorization, and phone/Mac/
desktop acceptance remain required before Issue #19 can close.

## Local UVC preview wiring (Issue #11)

`local_preview.py` connects the local UVC adapter's frame sink to this session
layer without a route. `LocalPreviewHub.on_frame` runs on capture worker
threads, is lock-protected and never raises into capture; it keeps at most one
latest frame per configured source (bounded by `max_frame_bytes`) and only while
that source has viewer demand, so zero subscribers retain nothing.
`LocalPreviewHub.on_health` is wired to the runtime's camera health: any
non-`online` transition (disconnect, capture failure, manual intervention)
drops the retained frame and refuses new frames until the camera is `online`
again, so a pre-loss image is never served as current live video.
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
transport, codec and viewer limits remain #19 decisions; the human surface stays
closed.
