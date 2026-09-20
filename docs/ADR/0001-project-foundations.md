# ADR-0001: Project foundations

Status: Accepted

## Context

ServerSentinel protects valuable self-hosted servers/workstations through camera monitoring, recording, computer vision, and event correlation.

The architecture evolved through requirements refinement:

1. initial native iOS Camera Node concept;
2. browser-based phone camera concept;
3. final MVP direction: first-class UVC cameras, including cameras physically connected to another Linux machine and forwarded over the same private LAN by a lightweight capture agent.

The deployment also needs private phone/Mac viewing for explicitly invited people without exposing ServerSentinel to every member of the Tailnet.

## Decision

Project foundations:

- project name: ServerSentinel;
- public GitHub repository;
- Apache-2.0;
- free, no ads/payment;
- no telemetry/analytics;
- no developer-operated user-data cloud;
- main self-hosted Ubuntu host;
- FastAPI backend;
- React/TypeScript human dashboard;
- SQLite metadata;
- Docker Compose where appropriate on the main host;
- Slack optional;
- heavy CV inference runs on the main host by default;
- model code/weights licenses reviewed separately;
- MVP monitoring is video-only.

Camera architecture:

- common Camera Source abstraction;
- MVP source types: `local_uvc` and `remote_agent`;
- `remote_agent` uses a Linux service named `media-capture-agent`;
- 1–4 active sources in arbitrary supported composition;
- source type, role, and Detection Profiles are separate;
- capture agent normally runs non-root, without GUI/tray, and initiates its connection to the main host;
- capture-node pairing uses short-lived owner approval followed by revocable mutually authenticated encryption, with mTLS as the default target;
- capture machine does not need to join Tailscale when private-LAN reachability exists;
- browser/iPhone camera capture is outside the current product scope; phone/Mac/desktop browsers are viewers;
- ambiguous UVC reconnect does not silently substitute a different camera.

Human-access architecture:

- Tailscale/private network is recommended for human remote reachability;
- Tailnet membership is not ServerSentinel authorization;
- ServerSentinel does not modify Tailscale ACLs/Grants and stores no Tailscale admin credential; policy administration remains outside the application;
- human backend is reached through a trusted Tailscale Serve/equivalent proxy path and remains non-bypassable from ordinary LAN clients;
- ServerSentinel additionally maintains its own owner-managed invitation/allowlist;
- minimum non-owner permissions are independent `live:view` and `recordings:view`;
- non-owner recording access is browser playback only; no official download/export function in MVP;
- with unchanged Tailnet policy, node-level concealment from other Tailnet members is not promised; uninvited users still receive no ServerSentinel application data.

Detection/privacy architecture:

- general motion/person detection;
- per-source server ROI/movement and camera-tamper profiles;
- detector-specific image-quality gating;
- insufficient person quality becomes `unknown`/unavailable, never trustworthy `no person`;
- optional entrance/zone logic;
- optional owner-only 1:1 face verification;
- non-owner people remain anonymous observations/tracks;
- named non-owner face database and cross-camera biometric re-identification are not MVP;
- event timeline correlates observations but does not determine guilt/culpability.

## Alternatives considered

### Native iOS-first Camera Node

Rejected for MVP because it forces signing/App Store/device-specific lifecycle complexity and is unnecessary when UVC cameras are available.

### Browser phone as the primary remote camera

Rejected from the current product scope because a permanently running Linux capture machine with UVC camera provides a cleaner always-on path, avoids browser lifecycle constraints, and can forward video over the existing private LAN.

Browser/iPhone camera capture is outside the current product scope. Any reintroduction requires a new explicit Owner decision/ADR, as clarified by ADR 0002.

### Put the capture machine in the owner's Tailnet

Not required for the current deployment because the capture machine and main host share a private LAN. Keeping capture transport on LAN avoids extending Tailnet membership to the capture machine solely for media forwarding.

### Main host connects inbound/SSH to capture machine

Rejected as the default. `media-capture-agent` initiates its own authenticated outbound connection, so the main host does not need administrator access to the capture machine.

### Tailnet membership as application authorization

Rejected. Network reachability and ServerSentinel authorization are separate gates. Existing Tailnet policy may remain unchanged; optional restrictive policy is configured separately by the Owner outside ServerSentinel.

### Fixed two-webcam layout

Rejected because deployments may use one to four sources and mix local/remote-agent cameras.

### General face identification

Rejected because owner presence only needs optional 1:1 owner verification and general named biometric identity would materially expand privacy/security scope.

## Consequences

Advantages:

- local and physically remote UVC cameras share one logical event/storage model;
- room-overview camera can be located near another Ubuntu machine without long USB cabling to main host;
- no phone battery/browser lifecycle dependency;
- no Apple Developer/App Store dependency;
- capture machines need no Tailnet membership when LAN is available;
- invited phone/Mac viewers remain simple browsers;
- access is narrower than whole-Tailnet visibility;
- biometric scope remains narrow.

Costs/limitations:

- a new Linux capture-agent component must be packaged, paired, updated, and monitored;
- agent-to-main transport requires its own ADR/benchmark;
- LAN ingest and human dashboard must have distinct security boundaries;
- Tailscale ACL/Grant management remains outside ServerSentinel; in-app invitation/permissions are authoritative for application data;
- UVC identity can be inherently ambiguous on identical devices without unique serials, requiring manual re-approval;
- high-resolution room-overview capture needs encode/network/resource benchmarks;
- ADR 0002 defines the Agent ring buffer and protected incidents as current secondary evidence after Main Server loss; general-purpose recording replication remains outside MVP.

## Validation

Before production-ready status:

- test 1–4 active local/remote-agent sources;
- test multiple UVC devices/reordering/reconnect/ambiguous substitution;
- test agent pairing/revocation/mTLS and LAN interruption;
- test agent-online/camera-offline separation;
- test clock offset handling;
- benchmark room-overview high-resolution capture and inference/view profiles;
- test phone/Mac live viewing;
- test Tailscale network permission + application invitation isolation;
- test `live:view` / `recordings:view` separation;
- test detector-specific low-light/quality failure semantics;
- test storage pressure/failure behavior;
- test owner verification/timeline without publishing real-person media.

## Follow-up ADRs / decisions

Required before relevant implementation:

- exact `media-capture-agent` -> main media transport;
- exact main -> browser live transport and latency target;
- exact room-overview capture/record/inference/view profiles after benchmark;
- agent filesystem safety-reserve/warning thresholds;
- final owner face-verification model/weights/threshold;
- server-movement algorithm;
