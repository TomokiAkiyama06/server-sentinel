# ServerSentinel

ServerSentinel is a free, self-hosted physical-security monitoring system for valuable servers and workstations. It combines multiple camera sources, local recording, computer vision, event correlation, and a web dashboard without requiring a developer-operated cloud.

## Core principles

1. **No developer-operated cloud**
2. **No telemetry, ads, or developer-side user-data collection**
3. **Self-hosted storage and AI analysis**
4. **Camera-source agnostic architecture**
5. **Agent-friendly development with strict security/review gates**

## Current project status

The repository is in the specification/bootstrap stage. Runtime implementation has not started yet.

## Camera-source model

The MVP supports **1 to 4 active video sources** per deployment. Four is an MVP operational limit, not a topology assumption that should be hard-coded throughout the implementation.

Supported MVP source types:

- **Local UVC / USB webcam** connected directly to the Ubuntu host.
- **Remote Web Camera Node** opened in a modern browser on a phone, tablet, laptop, or other camera-capable device.

Camera type and camera role are separate. A deployment may use only one webcam, several webcams, only a Web Camera Node, or a mixture.

Example deployment:

```text
USB Webcam A  ── Server side/overview ──┐
USB Webcam B  ── Server rear/cables  ───┼── Ubuntu ServerSentinel
                                         │     ├─ FastAPI
Phone browser ─ Entrance Web Camera ─────┘     ├─ Recording/storage
                                               ├─ Detection workers
                                               ├─ Event timeline
                                               ├─ SQLite
                                               └─ React web UI
                                                        │
                                                        └─ Tailscale (recommended remote reachability)
```

The example above is not required. A single webcam is a valid deployment.

## Detection model

Detection features are assigned per camera source rather than being inferred from hardware type. Initial profiles include:

- general motion;
- person detection;
- server ROI / movement detection;
- camera tamper / occlusion;
- entrance crossing;
- owner-only face verification;
- low-light / image-quality gating.

ServerSentinel may verify the explicitly enrolled deployment owner, but it does **not** maintain a named face database for everyone observed. Other people remain anonymous observations/tracks such as `Person #A` and must not be labelled as a culprit by the system.

## Presence and timeline

An entrance camera may infer owner presence from owner verification plus entry/exit direction. Presence inference is uncertainty-aware and manual override remains available.

The dashboard correlates observations into a factual timeline, for example:

```text
17:20 Owner exited
17:43 Anonymous person entered
17:55 Server movement detected
17:56 Rear camera offline
17:57 Server became unreachable
18:03 Anonymous person exited
```

The system reports observations and timing; it does not make guilt/culprit determinations.

## Web Camera Node

The mobile Camera Node is web-based in the MVP. No Apple Developer Program or App Store distribution is required.

- camera access uses browser `getUserMedia()` in a secure context;
- microphone is optional and **OFF by default**;
- PWA/home-screen installation may be offered where supported but is not required;
- monitoring is expected to remain foreground/active;
- background capture after browser suspension, screen lock, process termination, or device shutdown is **not guaranteed**;
- automatic torch/light control is **not part of the MVP**.

If an image is too dark for reliable analysis, ServerSentinel reports a degraded/unknown state instead of automatically turning on a phone light or forcing a face/person conclusion.

## Primary priorities

1. Remote multi-camera live viewing.
2. Evidence preservation for theft/tampering while the self-hosted recorder is available.
3. Server movement/camera tamper detection.
4. Entrance/person/presence timeline correlation.
5. Unified ServerSentinel service/camera/storage status.

ServerSentinel does not guarantee that browser camera footage survives theft/destruction/power loss of the Ubuntu recording host. Strong independent off-host evidence storage is a separate future architecture decision.

## Default operating assumptions

- Ubuntu is the primary recorder and analysis host.
- Default recording retention: **20 days**.
- Default audit-log retention: **90 days**.
- Manual recording maximum: **20 minutes**.
- Automatic event recording target: **30 seconds before + 120 seconds after**, extendable while activity continues, maximum **20 minutes**.
- Audio exists but is **OFF by default**.
- Remote dashboard access should use Tailscale or an equivalent private reachability layer; public Internet port exposure is not the default.

## Planned stack

- Backend: Python / FastAPI
- Web dashboard + Web Camera Node: React / TypeScript
- Local camera ingest: Linux UVC/V4L2-compatible path
- Metadata: SQLite
- Deployment: Docker Compose
- Remote access: Tailscale recommended
- Notifications: Slack optional
- Vision: pluggable permissively licensed detectors/models; source-code and model-weight licenses are reviewed separately

## Core documents

- [REQUIREMENTS.md](REQUIREMENTS.md) — product requirements
- [SPECIFICATION.md](SPECIFICATION.md) — technical contracts
- [AGENTS.md](AGENTS.md) — mandatory rules for coding agents
- [MANUAL_TEST.md](MANUAL_TEST.md) — real-hardware/browser test plan
- [SECURITY.md](SECURITY.md) — security model
- [PRIVACY.md](PRIVACY.md) — privacy/biometric model
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — architecture
- [docs/SETUP.md](docs/SETUP.md) — intended setup UX
- [docs/THIRD_PARTY_POLICY.md](docs/THIRD_PARTY_POLICY.md) — dependency/model licensing

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Non-goals for the initial release

- developer-hosted account/video service;
- advertising, analytics, telemetry, subscriptions;
- native iOS/App Store application;
- automatic phone torch/visible-light activation;
- named identification database for non-owner people;
- public Internet exposure by default;
- ESP32/environment sensor integration;
- full CPU/GPU observability suite;
- guaranteed recording after the Ubuntu host/storage is physically removed or destroyed.
