# Initial Issue Plan

This file is a planning sequence for creating GitHub Issues after the bootstrap specification PR is merged.

**`Plan N` is not a GitHub Issue number.** Actual GitHub Issue numbers are assigned by GitHub and may differ. In particular, existing repository Issue #4 is the review-gate hardening Issue and must not be confused with Plan 4 below.

Suggested labels:

```text
backend
web
camera-source
uvc
web-camera
detection
media
storage
security
privacy
architecture
hardware-required
webcam-required
browser-camera-required
server-required
manual-test-required
decision-needed
proposal
```

## Plan 1 — Bootstrap CI and repository quality gates

Scope:
- Python/web formatting/lint/test skeleton;
- secret scanning;
- dependency/license reporting;
- Docker/Compose validation placeholder;
- synthetic fixture policy enforcement where practical.

Acceptance:
- CI runs on PR;
- secret scan catches an isolated known test pattern;
- no platform-specific native-mobile build is required.

## Plan 2 — Backend foundation

Scope:
- FastAPI project;
- config model;
- SQLite migrations;
- health API;
- structured local logging;
- Docker image/Compose skeleton.

Acceptance:
- `/api/v1/health` tested;
- migration test;
- no secret logging;
- container starts in CI.

## Plan 3 — React web foundation

Scope:
- React/TypeScript;
- responsive/mobile-first shell;
- API client abstraction;
- dashboard status cards;
- Camera Node route/shell;
- Japanese-default localization structure.

Acceptance:
- build/typecheck/test;
- mocked server/camera state shown;
- Camera Node route does not require real camera hardware in CI.

## Plan 4 — Camera Source abstraction and registry

Scope:
- `camera_sources` data model;
- source type enum (`local_uvc`, `remote_web`);
- stable UUIDs;
- names/roles/enabled state;
- capability model;
- health model;
- detection-profile bindings;
- configurable `max_active_video_sources`, default 4.

Acceptance:
- 1, 2, 3, and 4-source configurations tested;
- fifth active source rejected cleanly under default limit;
- no fixed `front/rear` schema;
- source type and semantic role remain separate.

## Blocking prerequisite before privileged pairing — Deployment-owner authorization ADR/bootstrap

Labels: `architecture`, `security`, `backend`, `web`, `decision-needed`

This work MUST be completed before remote Web Camera Node pairing/owner-biometric enrollment is considered complete. Tailnet membership provides reachability only and is not sufficient owner authorization.

Scope:
- select MVP deployment-owner authorization mechanism by ADR;
- trusted local bootstrap;
- remote privileged-operation authorization;
- recovery/revocation;
- session lifetime/rotation and CSRF/browser considerations;
- pairing approval/revocation owner proof;
- biometric enroll/delete authorization;
- setup/API documentation.

Acceptance:
- ADR accepted;
- privileged operations fail closed without valid owner authorization;
- non-owner Tailnet member is denied;
- recovery/revocation tested;
- no developer-operated identity/cloud introduced.

## Plan 5 — Local UVC discovery and ingest

Labels: `camera-source`, `uvc`, `backend`, `webcam-required`, `server-required`, `manual-test-required`

Scope:
- Linux UVC/V4L2 discovery;
- stable device identity (`/dev/v4l/by-id`/USB metadata where available);
- owner enable/disable flow;
- capability negotiation;
- preview/health;
- disconnect/reconnect;
- narrowly scoped device access from deployment/container.

Acceptance:
- mocked device discovery unit/integration tests;
- `/dev/videoN` ordering alone is not durable identity;
- disconnect creates offline state;
- reconnect does not silently bind a different physical camera;
- real webcam verification tracked in `MANUAL_TEST.md`.

## Plan 6 — Web Camera Node pairing and capture foundation

Labels: `camera-source`, `web-camera`, `web`, `backend`, `security`, `browser-camera-required`, `manual-test-required`

Scope:
- secure-context Camera Node page;
- `getUserMedia()` camera selection;
- microphone separate/default OFF;
- short-lived one-time pairing token/QR/manual flow;
- revocable browser node identity;
- browser capability/permission state;
- heartbeat/reconnect;
- foreground/lifecycle state;
- optional Screen Wake Lock where supported;
- no automatic torch/light.

Acceptance:
- pairing requires valid owner authorization;
- expired/reused tokens rejected;
- tokens redacted from logs;
- mock browser source can connect/reconnect;
- camera permission denial handled;
- browser suspension/track-ended becomes visible degraded/offline state;
- no native iOS/App Store dependency.

## Plan 7 — Live media transport PoC + ADR

Labels: `architecture`, `media`, `camera-source`

Compare WebRTC-first against credible browser-compatible alternatives.

Measure/document:
- LAN latency;
- Tailscale/private-network latency;
- reconnect;
- CPU/GPU;
- browser compatibility;
- 1–4 concurrent source behavior;
- bitrate/quality adaptation;
- recording extraction/chunk implications;
- dependency licenses;
- secure-origin/TLS setup implications.

Acceptance:
- ADR committed;
- selected transport justified by measurements/constraints;
- UVC local path and remote web path share one logical live-source API.

## Plan 8 — Durable recording and server ring buffers

Scope:
- generic source-ID recording model;
- bounded per-source pre-event buffers;
- chunk metadata/checksum/retry/idempotency for remote sources;
- local UVC recording integration;
- multi-source event manifest;
- 30s pre / 120s post defaults;
- 20-minute event/manual maxima.

Acceptance:
- duplicate remote chunk does not duplicate recording;
- interrupted upload resumes safely;
- integrity failure detected;
- one event can reference multiple source files;
- no `rear.mp4/front.mp4` assumption.

## Plan 9 — Person/motion detector evaluation

Labels: `detection`, `architecture`

Scope:
- general motion baseline;
- YOLOX-first person-detector evaluation;
- pluggable detector interface;
- source-code and model-weight license review separately;
- CPU/GPU benchmark;
- per-source inference cadence.

Acceptance:
- no AGPL dependency merged by default;
- license evidence documented;
- synthetic/generated fixture tests;
- capture FPS and inference FPS are independent.

## Plan 10 — Server ROI calibration and movement detection

Scope:
- ROI/polygon setup UI/API per Camera Source;
- reference capture;
- global camera-transform compensation;
- occlusion handling;
- temporal confirmation;
- movement confidence/event.

Acceptance:
- synthetic occlusion fixture does not become confirmed movement;
- displacement fixture does;
- same event may link evidence from other cameras;
- thresholds documented.

## Plan 11 — Camera tamper / source-health correlation

Scope:
- global scene transform;
- persistent occlusion/lens-cover detection;
- source disconnect/reconnect;
- correlation of scene shift + disconnect;
- confidence/event;
- no IMU requirement.

Acceptance:
- mock/synthetic tests;
- false-positive guard tests;
- UVC and Web Camera Node health paths both supported;
- real-device behavior tracked manually.

## Plan 12 — Image quality / low-light gating

Scope:
- luminance/underexposure metrics;
- blur/sharpness/face-size quality signals where needed;
- `sufficient/degraded/insufficient` state;
- detector-specific gating;
- recovery event/hysteresis;
- **no automatic torch/light activation**.

Acceptance:
- very dark fixture does not force owner match/non-match;
- dependent detector reports unknown/unavailable;
- live/recording continues when technically possible;
- no torch API required.

## Plan 13 — Owner-only face verification evaluation + enrollment

Labels: `detection`, `privacy`, `security`, `architecture`, `decision-needed`

Scope:
- evaluate permissively licensed face-detection/embedding candidates;
- verify code and weight/model licenses independently;
- 1:1 owner verification only;
- explicit owner enrollment/delete/re-enroll;
- local template storage/access boundary;
- threshold/quality model;
- synthetic/publicly licensed benchmark fixtures;
- no non-owner named face database.

Acceptance:
- model/license decision documented before bundling;
- raw owner embedding never logged/general-exported;
- low-quality result becomes `unknown`;
- deletion removes active owner template;
- non-owner named enrollment API does not exist;
- real-owner/manual verification left in `MANUAL_TEST.md`.

## Plan 14 — Entrance crossing and anonymous tracking

Scope:
- entrance line/polygon calibration;
- inside/outside direction;
- same-camera temporal tracking;
- anonymous track IDs;
- `anonymous_person_entered/exited`;
- `owner_entered/exited` when owner verification is sufficient;
- debounce/occlusion handling.

Acceptance:
- direction tested with synthetic sequences;
- two-person sequence does not collapse to one track trivially;
- unknown people receive no real-world names;
- cross-camera biometric re-identification is not introduced.

## Plan 15 — Presence inference

Scope:
- `PRESENT`, `PROBABLY_PRESENT`, `ABSENT`, `UNKNOWN`;
- owner entrance/exit observations;
- manual override precedence;
- schedule hints;
- uncertainty handling;
- security automation effects.

Acceptance:
- manual override wins;
- low-light/ambiguous owner result does not force present/absent;
- only `PRESENT` suppresses ordinary person/motion automation by default;
- `server_movement` / `camera_tamper` detection, evidence, and critical alerts remain armed during presence;
- expiry/cancellation restores automatic inference.

## Plan 16 — Unified security timeline/event correlator

Scope:
- chronological event feed;
- source attribution;
- event links;
- relevant observation window around critical events;
- entry/exit/person/camera/server events;
- playback links/thumbnails;
- neutral wording.

Acceptance:
- synthetic scenario can show entry -> server movement -> camera disconnect timeline;
- linked observations preserve source/time/confidence;
- UI never labels an observed person as culprit/attacker from temporal correlation alone.

## Plan 17 — Recording/event/storage UX and retention

Scope:
- event/history UI;
- playback;
- star/unstar/delete;
- storage allocation;
- 20-day default retention;
- 90-day audit retention;
- `STORAGE_PRESSURE` / `STORAGE_HARD_STOP`;
- bounded critical allowance/hard filesystem reserve.

Acceptance:
- starred never auto-deleted;
- external filesystem consumption triggers reclaim/pressure logic;
- hard reserve never intentionally crossed;
- source-specific recordings visible under one event.

## Plan 18 — Slack notifications and daily summary

Scope:
- optional configuration;
- confirmed server movement/camera tamper immediate alerts only by default;
- 23:00 default daily summary;
- source health/counts, entrance/person counts, storage/errors;
- threaded thumbnails where configured;
- no developer relay.

Acceptance:
- ordinary person/motion/entry does not spam main channel;
- webhook/credentials never logged;
- failure is audited without breaking monitoring.

## Plan 19 — Full mock E2E and failure scenarios

Scope:
- 1–4 mixed mock sources;
- reconnect;
- browser source drop;
- UVC reordering/substitution protection;
- AI worker failure;
- low light;
- storage pressure/full;
- owner-verifier unavailable;
- backend restart;
- timeline correlation.

Acceptance:
- mock E2E passes without real hardware;
- no silent healthy state after known capture loss;
- unrelated critical monitoring survives owner-verifier failure.

## Plan 20 — Real-hardware/browser acceptance

Labels: `hardware-required`, `webcam-required`, `browser-camera-required`, `server-required`, `manual-test-required`

Scope is defined by `MANUAL_TEST.md`.

Minimum environments:
- one UVC webcam;
- two UVC webcams;
- four active mixed-source stress test where hardware is available;
- Web Camera Node on iPhone Safari;
- at least one non-iPhone browser/device where available;
- entrance crossing/owner presence;
- low-light degraded behavior;
- long-duration run.

Acceptance:
- manual checklist results recorded without committing real monitoring media;
- measured performance/quality defaults fed back into specs/config;
- unsupported browser/hardware limits documented truthfully.
