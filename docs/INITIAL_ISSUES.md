# Initial Implementation Issues / Plan

This file is the implementation sequence for the bootstrap PR. Individual plans may become separate GitHub Issues.

## Plan 1 — CI / repository guardrails

Scope:
- Python/TypeScript lint/test skeleton;
- secret scan;
- synthetic/generated fixture guard;
- Docker/Compose validation where relevant;
- no real-person/real-room media in repository/CI artifacts.

Acceptance:
- failing secret/fixture guard blocks CI;
- repository media fixtures are synthetic/generated only.

## Plan 2 — Backend foundation

Scope:
- FastAPI application skeleton;
- config/settings model;
- SQLite + migrations;
- health/version endpoints;
- structured logging/redaction.

Acceptance:
- migration test;
- typed config validation;
- no secrets in logs.

## Plan 3 — React dashboard foundation

Scope:
- Japanese-default localization-ready UI;
- responsive layout;
- API client/session shell;
- Overview/Camera Sources/Capture Nodes/Live/Recordings/Access placeholders.

Acceptance:
- phone/Mac/desktop responsive smoke tests;
- no fixed camera slot assumptions.

## Plan 4 — Camera Source registry

Scope:
- collection-based source schema;
- `local_uvc` / `remote_agent` types;
- stable UUID;
- name/role/enabled/capabilities/health;
- profile bindings;
- configurable `max_active_video_sources`, default 4.

Acceptance:
- 1/2/3/4-source configs tested;
- fifth source rejected under default limit;
- source type and role remain separate;
- no fixed `front/rear` schema.

## Blocking prerequisite — Owner authorization / trusted Tailscale identity ADR

Scope:
- trusted local owner bootstrap;
- human dashboard path through Tailscale Serve/equivalent trusted proxy;
- loopback/non-bypassable backend listener;
- application principal/allowlist;
- session/revocation/recovery;
- exact handling of verified external identity headers;
- clarify manual Tailnet Grant management in MVP.

Acceptance:
- Tailnet membership alone is insufficient;
- uninvited identity receives no deployment metadata;
- owner can revoke app access;
- backend rejects spoofed identity headers from untrusted LAN paths;
- no developer-operated identity/cloud.

## Plan 5 — Local UVC discovery and stable identity

Scope:
- Linux UVC/V4L2 discovery;
- `/dev/v4l/by-id`, serial/udev/topology/capability identity evidence;
- owner enable/disable;
- preview/capture negotiation;
- disconnect/reconnect;
- ambiguous identical-device handling.

Acceptance:
- `/dev/videoN` alone not durable identity;
- disconnect -> offline;
- unique reconnect may auto-return online;
- indistinguishable reconnect -> `manual_intervention_required`;
- owner re-approval required before healthy state;
- real webcam verification in `MANUAL_TEST.md`.

## Plan 6 — `media-capture-agent` foundation

Labels: `camera-source`, `remote-agent`, `backend`, `security`, `server-required`, `manual-test-required`

Scope:
- Linux native agent executable/service;
- process/systemd name `media-capture-agent`;
- dedicated non-root service account;
- UVC discovery/capture;
- video-only operation;
- node heartbeat + camera health separation;
- development-from-clone workflow;
- later release-artifact installer path.

Acceptance:
- agent runs without GUI/tray;
- microphone is not opened;
- camera unplug leaves agent online/source offline;
- service does not impersonate unrelated software;
- no unnecessary root runtime.

## Plan 7 — Capture-node pairing + mTLS trust

Scope:
- owner-generated short-lived one-time pairing code;
- node keypair/credential issuance;
- mTLS or equivalent mutually authenticated transport;
- revocation;
- credential file permissions;
- capture-node protocol authorization separate from human API.

Acceptance:
- expired/reused pairing rejected;
- unpaired LAN host cannot submit media;
- revoked node cannot reconnect;
- capture-node credential cannot call human/admin endpoints;
- secrets redacted.

## Plan 8 — LAN ingest boundary

Scope:
- dedicated LAN-facing agent ingest listener;
- no dashboard routes on ingest listener;
- interface/firewall guidance;
- rate/size/backpressure limits;
- optional source-address restriction when stable addressing permits;
- IP never sufficient authentication.

Acceptance:
- dashboard cannot be reached through ingest port/path;
- unauthorized media rejected;
- bounded queues under slow consumer/load;
- private LAN operation does not require agent Tailscale membership.

## Plan 9 — Agent/main transport PoC + ADR

Compare realistic options (e.g. WebRTC/SRT/QUIC/authenticated HTTP streaming) against requirements.

Measure:
- LAN latency;
- reconnect/gap behavior;
- backpressure;
- CPU/GPU/VRAM;
- bitrate;
- 1–4 source behavior;
- codec/container handling;
- dependency licenses;
- recording extraction implications.

Acceptance:
- ADR selects transport based on measurements/constraints;
- authenticated encrypted node session preserved;
- no silent healthy state during known media loss.

## Plan 9A — Agent disk ring buffer + autonomous incident evidence

Scope:
- compressed-video disk ring buffer on `media-capture-agent`;
- owner-selectable **duration mode** or **capacity mode**;
- UI estimates equivalent capacity/duration and shows current usage/free space/safety reserve;
- 10-minute pre-loss target validation;
- automatic Main Server communication-loss protection: 10 minutes before + 10 minutes after;
- critical-event preserve command while Main Server is reachable;
- protected incidents retained on Agent for 30 days, then auto-deleted;
- agent storage-pressure/hard-stop behavior.

Acceptance:
- only owner can change mode/value;
- unsafe settings rejected before filesystem safety reserve is crossed;
- capacity mode remains within selected byte limit;
- duration mode reports projected/actual disk footprint;
- full 20-minute incident is preserved when resources/stream continuity allow;
- shortened/gapped protection is reported truthfully;
- reconnect does not erase protected incident;
- protected incident expires automatically at 30 days;
- unexpired protected incident is not silently overwritten by ordinary ring-buffer pressure.

## Plan 10 — Capture/record/inference/view profile separation

Scope:
- independent profiles;
- high-resolution room-overview capture option;
- downscaled/sampled inference path;
- adaptive browser live profile;
- compatible stream-copy vs transcode decision;
- hardware acceleration optional.

Acceptance:
- inference FPS independent from capture FPS;
- viewer quality independent from durable recording quality;
- no-viewer state avoids unnecessary viewer-only transcode;
- measured resource use recorded.

## Plan 11 — Durable recording + main-host compressed pre-roll

Scope:
- source-ID recording model;
- bounded compressed pre-event buffers;
- recording metadata/integrity/gap reporting;
- 30 s pre / 120 s post defaults;
- 20-minute maxima;
- multi-source event manifest.

Acceptance:
- no fixed role filename contract;
- no unnecessary long decoded-frame RAM history;
- one event can link multiple sources;
- restart/gap behavior explicit.

## Plan 12 — Person/motion detector evaluation

Scope:
- motion baseline;
- YOLOX-first person-detector evaluation;
- pluggable detector interface;
- code/weight license review separately;
- CPU/GPU benchmark;
- per-source inference cadence.

Acceptance:
- permissive licensing evidence documented;
- synthetic/generated fixtures only in repo;
- capture/inference FPS independent.

## Plan 13 — Detector-specific image-quality / low-light gating

Scope:
- luminance/blur/saturation/resolution/target-size quality signals;
- per-detector prerequisites;
- `sufficient/degraded/insufficient` state;
- recovery hysteresis;
- fail-unknown semantics.

Acceptance:
- very dark/blurred person fixture does **not** become trustworthy `no person`;
- owner verification low quality -> `unknown`;
- dependent presence/entrance does not infer absence from skipped detector;
- live/recording continues where frames remain.

## Plan 14 — Server ROI movement + camera tamper

Scope:
- ROI/polygon/reference capture;
- global transform compensation;
- occlusion handling;
- temporal confirmation;
- camera scene-shift/occlusion/disconnect correlation.

Acceptance:
- synthetic occlusion does not become server movement;
- controlled displacement does;
- camera/global movement distinguished where practical;
- local and remote-agent sources supported.

## Plan 15 — Owner-only verification / anonymous tracking / entrance

Scope:
- permissively licensed face model evaluation;
- code and weights license review independently;
- owner-only 1:1 enrollment/delete/re-enroll;
- anonymous same-camera track IDs;
- entrance/zone crossing;
- no named non-owner database;
- no cross-camera biometric re-identification.

Acceptance:
- raw owner embedding absent from logs/general APIs;
- low-quality result -> unknown;
- non-owner enrollment API does not exist;
- repository fixtures synthetic/generated only;
- any external real-person benchmark stays local and is not committed/attached.

## Plan 16 — Presence + unified factual timeline

Scope:
- `PRESENT/PROBABLY_PRESENT/ABSENT/UNKNOWN`;
- manual override precedence;
- owner entry/exit observations;
- source/node health events;
- relevant observation windows;
- neutral timeline language.

Acceptance:
- only `PRESENT` suppresses ordinary occupancy automation by default;
- critical server movement/camera tamper always armed;
- synthetic scenario can show entry -> movement -> camera offline;
- UI never labels a person culprit/attacker from temporal correlation.

## Plan 17 — Tailscale/private access + granular permissions

Scope:
- do not require ServerSentinel to modify Tailscale ACLs/Grants;
- trusted proxy identity;
- app principal allowlist;
- generic/non-branding denial for uninvited users;
- independent `live:view` and `recordings:view`;
- `recordings:view` includes historical timeline/events;
- owner access-management UI;
- prompt application revocation;
- non-owner browser-only recording playback.

Acceptance:
- Tailnet membership without app invitation receives no ServerSentinel application data;
- existing Tailnet policy may remain unchanged;
- docs do not promise Main Server node invisibility when Tailnet policy exposes it;
- uninvited identity receives no product/version/API schema/camera/count/thumbnail/timeline metadata;
- `live:view` cannot list/play recordings or historical timeline;
- `recordings:view` includes browser playback and historical timeline but does not imply live;
- no official non-owner recording download/export route/button;
- ServerSentinel stores no Tailscale admin credential and performs no automatic policy mutation.

## Plan 18 — Main-to-browser live transport

Scope:
- browser-compatible low-latency transport PoC/ADR;
- phone + Mac browser support;
- adaptive 1–4 source layout;
- direct relay/stream copy where compatible;
- demand-driven transcoding/packaging;
- multiple viewer limits.

Acceptance:
- authorized phone and Mac can view live sources;
- unauthorized identity cannot obtain media;
- viewer URL is not public bearer access;
- zero viewers releases viewer-only processing resources;
- latency/reconnect measured.

## Plan 19 — Storage UX / retention / Slack

Scope:
- event/recording browser;
- star/unstar/delete owner actions;
- 20-day recording retention;
- 90-day audit retention;
- `STORAGE_PRESSURE` / `STORAGE_HARD_STOP`;
- bounded critical allowance/hard reserve;
- optional Slack alerts + 23:00 default daily summary.

Acceptance:
- starred never auto-delete;
- external filesystem consumption triggers admission logic;
- hard reserve not intentionally crossed;
- Slack credentials never logged;
- ordinary person/motion does not spam main channel by default.

## Plan 20 — Full mock E2E + failure scenarios

Scope:
- 1–4 mixed local/remote-agent mock sources;
- agent reconnect/revocation;
- UVC substitution ambiguity;
- clock skew;
- AI worker failure;
- low light;
- storage pressure/full;
- backend restart;
- access permission isolation;
- timeline correlation.

Acceptance:
- mock E2E passes without real hardware;
- no silent healthy state after known capture loss;
- unrelated critical monitoring survives owner-verifier failure.

## Plan 21 — Real hardware/network/browser acceptance

Scope is defined by `MANUAL_TEST.md`.

Minimum intended environments:
- one local UVC webcam;
- two local UVC webcams where available;
- remote Linux `media-capture-agent` with room-overview UVC camera;
- 1–4 mixed-source stress run;
- phone browser live view;
- Mac browser live view;
- restrictive Tailnet/app authorization test identities;
- low-light/degraded behavior;
- long-duration run.

Acceptance:
- results recorded without publishing real monitoring media/private infrastructure values;
- performance/quality defaults fed back into specs/config;
- unsupported hardware/network limits documented truthfully.

## Explicitly pending product decisions

Do not silently decide these during implementation:

1. exact `media-capture-agent` -> Main Server media protocol/reconnection behavior after real LAN testing;
2. exact Main Server -> browser live protocol after PoC, with stability prioritized over minimum latency;
3. exact room-overview capture/record/inference/view profiles after the real camera/model benchmark;
4. exact agent filesystem safety-reserve and warning thresholds after measuring the capture host;
5. final owner face-verification model/weights/license/threshold after the target hardware is available.
