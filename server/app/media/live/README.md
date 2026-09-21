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
