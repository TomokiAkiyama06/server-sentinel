# Web UI

Planned stack:
- React
- TypeScript

The web project is the **human dashboard/viewer**. Browser/iPhone camera capture is not required in the current MVP.

## Human Dashboard

Primary design target: responsive/mobile-first, usable from phone, Mac, and desktop browsers.

Core views:
- overview/status;
- Camera Sources;
- Capture Nodes;
- 1–4 source live grid;
- events/timeline;
- recordings/playback;
- presence/manual override;
- owner verification settings;
- access/invitations;
- storage/retention;
- Slack;
- audit;
- setup/security.

## Private remote access

Human remote reachability is expected through Tailscale or an equivalent private path.

Access requires **both**:

1. network-level permission to the ServerSentinel node; and
2. an active ServerSentinel application principal/invitation.

Tailnet membership alone grants nothing.

The preferred Tailscale path places the human backend behind Tailscale Serve/equivalent trusted proxy with the application listener bound to loopback/non-bypassable local scope. Proxy-provided identity headers are trusted only on that path.

ServerSentinel does not require changing Tailscale ACLs/Grants. With existing Tailnet policy unchanged, the Main Server node/service may remain visible or reachable, but every application request is still checked against the ServerSentinel invitation/permission list. Uninvited identities receive generic/non-branding denial and no ServerSentinel deployment/media metadata.

## Invited-user permissions

Minimum independent permissions:

```text
live:view
recordings:view
```

- `live:view` grants current live streams only;
- `recordings:view` grants recording list/browser playback and historical timeline/events;
- neither implies owner/admin capabilities;
- non-owner download/export is not provided in MVP;
- historical timeline/event access is included with `recordings:view` and must not leak through `live:view`.

## Live view

Responsive layout:

```text
1 source -> one large tile
2 sources -> split/two-up
3–4 sources -> responsive grid
```

Each tile shows source name/type/role, camera health, capture-node health where applicable, negotiated viewer quality, and image-quality/degraded state.

Viewer media always comes through the main ServerSentinel host. Browsers do not connect directly to `media-capture-agent`.

Viewer-only transcoding/packaging should be demand-driven and release resources when subscriber count returns to zero.

## Recordings

Authorized playback routes remain server-side permission checked. A copied playback URL must not become public access.

No DRM guarantee is implied: browser playback cannot technically prevent screen recording or advanced client-side capture.

## Video-only MVP

The web UI does not expose monitoring-audio controls in MVP because capture/recording is video-only.

## Quality honesty

If a detector cannot operate reliably because of darkness, blur, low target resolution, or other insufficient input, the UI shows `unknown`/unavailable instead of a forced positive/negative result. In particular, skipped/failed person inference must not be presented as `no person`.
