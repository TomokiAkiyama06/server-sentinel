# ServerSentinel

ServerSentinel is a self-hosted server security monitoring system that turns an iPhone into a dedicated camera node and stores/analyses all monitoring data on the user's own Ubuntu server.

The project is designed around four principles:

1. **No developer-operated cloud**
2. **No telemetry, ads, or developer-side user data collection**
3. **Self-hosted storage and AI analysis**
4. **Agent-friendly development with strict safety and review gates**

## Current project status

This repository is in the specification/bootstrap stage. The initial goal is to complete the software up to the point where only real-device validation remains.

## Product shape

```text
iPhone Camera Node
  - Native iOS app
  - Rear + front camera when MultiCam is supported
  - Microphone (default OFF)
  - Accelerometer / gyroscope
  - Torch control
  - Local emergency buffer
          |
          | Local LAN / encrypted session
          v
Ubuntu ServerSentinel Server
  - FastAPI backend
  - React web dashboard
  - SQLite metadata
  - Recording storage on user-selected disk
  - Person / motion / server-movement / tamper detection
  - Slack integration
          |
          | Tailscale (recommended)
          v
Remote browser / phone
```

## Primary priorities

1. View live video from outside the local network.
2. Preserve evidence of theft/tampering.
3. Show ServerSentinel service/camera/storage status in one dashboard.

General CPU/GPU/environment sensor monitoring is outside the first release.

## Default operating assumptions

- Dedicated iPhone is continuously powered.
- Camera Node remains in the foreground while monitoring.
- Ubuntu server stores recordings.
- Default recording retention: **20 days**
- Default audit-log retention: **90 days**
- Manual recording maximum: **20 minutes**
- Automatic event recording: **30 seconds before detection + 120 seconds after detection**, extendable while activity continues, with a maximum event duration of 20 minutes.
- Critical local iPhone emergency storage target: **500 MB**, ring-buffered.
- Audio functionality exists but is **OFF by default**.
- Remote access uses Tailscale by default; ServerSentinel is not intended to expose its dashboard directly to the public Internet.

## Repository license

Apache License 2.0. See [LICENSE](LICENSE).

Third-party dependencies and model weights must be independently license-compatible. See [docs/THIRD_PARTY_POLICY.md](docs/THIRD_PARTY_POLICY.md).

## Core documents

- [REQUIREMENTS.md](REQUIREMENTS.md) — product requirements
- [SPECIFICATION.md](SPECIFICATION.md) — technical specification
- [AGENTS.md](AGENTS.md) — mandatory rules for coding agents
- [MANUAL_TEST.md](MANUAL_TEST.md) — real-device test plan
- [SECURITY.md](SECURITY.md) — security model and secret-handling policy
- [PRIVACY.md](PRIVACY.md) — project privacy model
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system architecture
- [docs/SETUP.md](docs/SETUP.md) — intended setup experience
- [docs/APP_REVIEW.md](docs/APP_REVIEW.md) — App Store review requirements
- [docs/THIRD_PARTY_POLICY.md](docs/THIRD_PARTY_POLICY.md) — dependency/model licensing policy

## Development workflow

- No direct commits to `main`.
- One GitHub Issue per unit of work.
- One feature branch per Issue.
- Pull request required.
- CI must pass.
- Automated review must complete before merge.
- Unresolved automated-review findings block merge.
- Agents may create Issues/PRs and may merge after all gates are satisfied.
- Hardware-dependent items must continue with mocks/fixtures and leave explicit manual-test work rather than blocking unrelated software work.

See [AGENTS.md](AGENTS.md).

## Planned stack

- iOS: Swift / SwiftUI / AVFoundation / CoreMotion
- Backend: Python / FastAPI
- Web: React + TypeScript
- Metadata: SQLite
- Deployment: Docker Compose
- Remote access: Tailscale
- Notifications: Slack
- AI/person detection: pluggable permissively licensed detector; YOLOX is the initial evaluation candidate, with model-weight licensing verified separately

## Non-goals for the initial release

- Developer-hosted account system
- Developer-hosted video storage
- Advertising
- Analytics/telemetry
- Payment/subscription
- Public Internet port exposure as the default
- ESP32/environment-sensor integration
- Full server CPU/GPU observability suite
- Guaranteed physical prevention of iPhone shutdown
- Face recognition / identity recognition
