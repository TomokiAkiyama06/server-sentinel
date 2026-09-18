# ServerSentinel

ServerSentinel is a free, self-hosted physical-security monitoring system for valuable servers and workstations. It combines heterogeneous camera sources, local recording, computer vision, event correlation, and a private web dashboard without a developer-operated cloud.

## Core principles

1. **No developer-operated cloud, telemetry, ads, or analytics**
2. **Self-hosted recording and AI analysis**
3. **Camera-source agnostic design**
4. **Private-by-default remote access**
5. **Least-privilege capture agents and strict review gates**

## Current project status

The repository is in the specification/bootstrap stage. Runtime implementation has not started yet.

## Camera-source model

The MVP supports **1 to 4 active video sources**. Four is a configurable MVP limit, not a fixed schema assumption.

MVP source types:

- **`local_uvc`** — UVC/V4L2-compatible USB camera connected directly to the main Ubuntu ServerSentinel host.
- **`remote_agent`** — UVC/V4L2-compatible camera connected to another owner-authorized Linux machine running `media-capture-agent`, with video forwarded over a private LAN to the main host.

Browser/iPhone capture is outside the current ServerSentinel product scope. Phone/Mac/desktop browsers are viewer clients; adding browser-camera capture again would require a new explicit product decision/ADR.

Example deployment:

```text
USB Webcam A ───────────────────────────────┐
USB Webcam B ───────────────────────────────┤
                                            │
Yamaha CS-800                               │
    │ USB                                   │
    v                                       │
Research-room Ubuntu                        │
media-capture-agent                         │
    │ authenticated private-LAN stream      │
    └───────────────────────────────────────┤
                                            v
                                  Main ServerSentinel
                                  ├─ recording/storage
                                  ├─ detection workers
                                  ├─ event timeline
                                  ├─ SQLite
                                  └─ React web dashboard
                                             │
                                      Tailscale/private access
                                             │
                                      invited phone / Mac
```

Camera type and semantic role are separate. The room-overview camera, server-side camera, rear/cable camera, or any custom role may use either source type.

## `media-capture-agent`

`media-capture-agent` is a lightweight Linux capture service for cameras that are physically closer to another Linux machine than to the main ServerSentinel host.

Initial rules:

- runs as a background systemd service with no tray/window requirement;
- uses a truthful functional process/service name: `media-capture-agent`;
- normally runs as a dedicated non-root service account;
- captures video only in the MVP; microphone/audio capture is not required;
- initiates the connection toward the main host; the main host does not need SSH/admin access to the capture machine;
- pairs using a short-lived owner-approved code and then uses a revocable cryptographic node identity;
- long-lived agent-to-main transport must be mutually authenticated and encrypted, with mTLS as the default design target;
- the capture machine does **not** need to join the owner's Tailnet when it can reach the main host on the same private LAN;
- camera unplug/replug is reported as source health state; the agent process itself remains alive;
- a reconnect is automatic only when the physical camera can be matched unambiguously; ambiguous device identity requires owner intervention rather than silently binding a different camera.

Development may run the agent from a repository clone. A later stable release should provide a standalone release artifact/installer so production operation does not depend on a development checkout.

## Video-only MVP

Audio is not required for the MVP. Camera microphones, including microphones integrated into conference cameras, are not captured by default and no monitoring feature depends on audio.

## Detection model

Detection features are assigned per Camera Source. Initial profiles include:

- general motion;
- person detection;
- server ROI / movement detection;
- camera tamper / occlusion;
- room/entrance crossing where configured;
- owner-only 1:1 face verification;
- detector-specific image-quality / low-light gating.

Insufficient image quality never becomes a reliable negative observation. If a person detector cannot operate reliably because the image is too dark/blurred, the result is `unknown`/unavailable rather than `no person`.

ServerSentinel may verify one explicitly enrolled deployment owner, but it does **not** maintain a named face database for other observed people. Non-owner people remain anonymous observations/tracks. Timeline correlation must not label a person as a culprit, thief, attacker, or cause.

## Live viewing from phone and Mac

Invited users can view live video from a normal browser on a phone or Mac through the main ServerSentinel host. Viewer devices never connect directly to `media-capture-agent`.

```text
Phone / Mac
    │ Tailscale/private network
    v
Main ServerSentinel
    │
    └─ live stream already received from local/remote Camera Sources
```

The dashboard adapts to 1–4 sources. Viewer streaming should be demand-driven: when nobody is watching, ServerSentinel should not perform unnecessary viewer-only transcoding.

## Private access and invitations

**Tailnet membership is not ServerSentinel authorization.** Access requires both:

1. network-level permission to reach the ServerSentinel node; and
2. an active ServerSentinel invitation/allowlist entry.

ServerSentinel does not require changing existing Tailscale ACLs/Grants and does not store Tailscale administrative credentials. Tailnet membership alone still grants no ServerSentinel application data: every human request must pass the ServerSentinel invitation/permission check. With unchanged Tailnet policy, the underlying Main Server node may remain visible/reachable to other Tailnet members, so node-level concealment is not guaranteed. Uninvited users receive generic/non-branding denial and no ServerSentinel deployment metadata.

The dashboard itself should bind only to a trusted local proxy path (for example loopback behind Tailscale Serve). LAN camera ingestion uses a **separate** narrowly exposed endpoint and must not expose dashboard routes.

Invited-user permissions are granular:

- `live:view` — view current live video in the browser;
- `recordings:view` — browse/play past recordings and view historical timeline/events in the browser.

These permissions are independent. Non-owner invited users do not receive an official recording-download/export function in the MVP. Browser-only playback cannot technically prevent screen recording or advanced client-side capture, so the product must not claim DRM-style prevention.

## Recording and storage

Ubuntu remains the primary durable evidence store.

Agent-side storage is limited to the bounded compressed disk ring buffer and protected critical incidents. Agent-side protected critical incidents are retained for **30 days** and then automatically deleted.

Defaults:

- recording retention: **20 days**;
- audit retention: **90 days**;
- automatic event target: **30 s pre + 120 s post**, extendable while activity continues, maximum **20 minutes**;
- manual recording maximum: **20 minutes**;
- starred recordings are protected from automatic deletion;
- recording allocation and a hard filesystem safety reserve are separate;
- explicit `STORAGE_PRESSURE` and `STORAGE_HARD_STOP` states prevent unsafe writes.

Compressed media should be buffered/recorded where practical rather than retaining large decoded frame histories in RAM.

## Performance model

Capture, inference, recording, and viewer profiles are separate.

A high-resolution room-overview source may be captured/recorded at a higher resolution while person/ROI inference samples only a few frames per second and remote viewers receive an adaptive browser-compatible live profile. Exact resolution, FPS, bitrate, and encode path are benchmark-derived rather than hard-coded.

When overloaded, ServerSentinel first keeps health state truthful and preserves critical monitoring/evidence, then reduces expensive inference cadence and viewer quality before silently dropping sources.

## Planned stack

- Backend: Python / FastAPI
- Dashboard: React / TypeScript
- Local/agent capture: Linux UVC/V4L2
- Remote capture service: `media-capture-agent` + systemd
- Metadata: SQLite
- Main deployment: Docker Compose where appropriate
- Private remote access: Tailscale recommended
- Notifications: Slack optional
- Vision: pluggable permissively licensed detectors/models; source-code and model/weight licenses reviewed separately

## Core documents

- [REQUIREMENTS.md](REQUIREMENTS.md) — product requirements
- [SPECIFICATION.md](SPECIFICATION.md) — technical contracts
- [AGENTS.md](AGENTS.md) — mandatory rules for coding agents
- [MANUAL_TEST.md](MANUAL_TEST.md) — real-hardware/network/browser test plan
- [SECURITY.md](SECURITY.md) — security model
- [PRIVACY.md](PRIVACY.md) — privacy/biometric model
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — architecture
- [docs/SETUP.md](docs/SETUP.md) — intended setup UX

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Non-goals for the initial release

- developer-hosted account/video service;
- advertising, analytics, telemetry, subscriptions;
- native iOS/App Store camera application;
- phone-camera monitoring requirement;
- audio surveillance;
- named identification database for non-owner people;
- public Internet exposure by default;
- cross-camera biometric re-identification;
- guaranteed concealment from Tailnet/infrastructure administrators;
- guaranteed recording after the main recording host/storage is physically removed or destroyed.
