# Web UI

Planned stack:
- React
- TypeScript

The web project serves two user-facing roles:

1. **Owner Dashboard**
2. **Remote Web Camera Node**

## Owner Dashboard

Primary design target: responsive/mobile-first.

Core views:
- overview/status;
- Camera Sources;
- 1–4 source live grid;
- events/timeline;
- recordings/playback;
- presence/inference/manual override;
- owner verification settings;
- storage/retention;
- Slack;
- audit;
- setup/security.

Remote dashboard reachability is expected through Tailscale or an equivalent private path in MVP, plus the separate deployment-owner authorization boundary.

## Web Camera Node

The Camera Node is browser-based in MVP and must work without native iOS/App Store distribution.

Responsibilities:
- secure-context `getUserMedia()` capture;
- selected camera only (simultaneous phone front/rear is not required);
- microphone separate and default OFF;
- pairing/session bootstrap;
- visible monitoring/connection state;
- heartbeat/reconnect;
- browser lifecycle state where detectable;
- optional Screen Wake Lock best effort;
- negotiated capture settings.

It must not:
- auto-enable phone torch/flash/screen light;
- claim guaranteed background capture;
- claim browser local storage is guaranteed durable critical evidence;
- expose privileged owner/admin controls merely because the node is paired.

Camera/low-light insufficiency is represented as degraded/unknown, not solved by automatic visible illumination.
