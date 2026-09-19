# Initial Implementation Issues / Plan

This file is the implementation plan and GitHub Issue index. Plan IDs are stable document identifiers, not GitHub Issue numbers. Each plan below links to its registered Issue, direct prerequisites, labels, and physical acceptance requirements; implementation remains open until its Acceptance Criteria are verified.

Dependencies describe completion order, not a requirement to delay independent mock/contract work. Human-facing routes must remain unavailable until the authorization prerequisite and Plan 17 enforcement are complete. Hardware flags describe the acceptance of each Issue; mockable portions may proceed first, and Plan 21 records final deployment acceptance.

Existing Issues are separate: [#1](https://github.com/TomokiAkiyama06/server-sentinel/issues/1) tracks specification/bootstrap, [#3](https://github.com/TomokiAkiyama06/server-sentinel/issues/3) tracks Claude authentication setup (already closed), and [#4](https://github.com/TomokiAkiyama06/server-sentinel/issues/4) tracks hardened review enforcement. Plan 1 adds CI lint/test and secret/fixture guards rather than duplicating #4.

Label meanings: `server-required` means a Main Server or Capture Node is needed; `hardware-required` means physical camera/GPU/storage/probe validation; `manual-test-required` means manual host/browser/network acceptance. The per-plan Main Server / Capture Node / UVC fields identify the actual environment.

## Plan 1 — CI / repository guardrails

GitHub Issue: [#5](https://github.com/TomokiAkiyama06/server-sentinel/issues/5)

Depends on: None

Labels: `ci`, `security`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#7](https://github.com/TomokiAkiyama06/server-sentinel/issues/7)

Depends on: [#5](https://github.com/TomokiAkiyama06/server-sentinel/issues/5) (Plan 1)

Labels: `backend`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#8](https://github.com/TomokiAkiyama06/server-sentinel/issues/8)

Depends on: [#5](https://github.com/TomokiAkiyama06/server-sentinel/issues/5) (Plan 1)

Labels: `frontend`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

Scope:
- Japanese-default localization-ready UI;
- responsive layout;
- API client/session shell;
- Overview/Camera Sources/Capture Nodes/Live/Recordings/Access placeholders.

Acceptance:
- phone/Mac/desktop responsive smoke tests;
- no fixed camera slot assumptions.

## Plan 4 — Camera Source registry

GitHub Issue: [#9](https://github.com/TomokiAkiyama06/server-sentinel/issues/9)

Depends on: [#7](https://github.com/TomokiAkiyama06/server-sentinel/issues/7) (Plan 2)

Labels: `camera-source`, `backend`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#6](https://github.com/TomokiAkiyama06/server-sentinel/issues/6)

Depends on: None

Labels: `documentation`, `security`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

Scope:
- trusted local owner bootstrap;
- human dashboard path through Tailscale Serve/equivalent trusted proxy;
- loopback/non-bypassable backend listener;
- application principal/allowlist;
- session/revocation/recovery;
- exact handling of verified external identity headers;
- keep Tailnet policy separately Owner-managed outside ServerSentinel; existing ACLs/Grants may remain unchanged, and ServerSentinel performs no policy mutation or admin-credential storage.

Acceptance:
- Tailnet membership alone is insufficient;
- uninvited identity receives no deployment metadata;
- owner can revoke app access;
- backend rejects spoofed identity headers from untrusted LAN paths;
- no developer-operated identity/cloud.

## Plan 5 — Local UVC discovery and stable identity

GitHub Issue: [#11](https://github.com/TomokiAkiyama06/server-sentinel/issues/11)

Depends on: [#9](https://github.com/TomokiAkiyama06/server-sentinel/issues/9) (Plan 4), [#6](https://github.com/TomokiAkiyama06/server-sentinel/issues/6) (Auth prerequisite)

Labels: `camera-source`, `backend`, `server-required`, `hardware-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 不要; UVC Camera: 必要; Manual test: 必要

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

GitHub Issue: [#12](https://github.com/TomokiAkiyama06/server-sentinel/issues/12)

Depends on: [#11](https://github.com/TomokiAkiyama06/server-sentinel/issues/11) (Plan 5)

Labels: `camera-source`, `remote-agent`, `backend`, `security`, `server-required`, `hardware-required`, `manual-test-required`

実機要件: Main Server: 不要; Capture Node: 必要; UVC Camera: 必要; Manual test: 必要

Scope:
- Linux native agent executable/service;
- process/systemd name `media-capture-agent`;
- dedicated non-root service account;
- UVC discovery/capture;
- video-only operation;
- node heartbeat + camera health separation;
- development-from-clone workflow;
- later release-artifact installer path;
- configurable Agent media root on a dedicated data filesystem where available;
- installer/startup validation of expected media-root mount identity, ownership, writability, free space, and safety reserve;
- fail-safe behavior that refuses to spill buffer/incidents onto the root filesystem if the intended media mount disappears.

Acceptance:
- agent runs without GUI/tray;
- microphone is not opened;
- camera unplug leaves agent online/source offline;
- service does not impersonate unrelated software;
- no unnecessary root runtime;
- expected media-root mount loss/substitution is explicit degraded/failed state rather than silent fallback.

## Plan 7 — Capture-node pairing + mTLS trust

GitHub Issue: [#13](https://github.com/TomokiAkiyama06/server-sentinel/issues/13)

Depends on: [#12](https://github.com/TomokiAkiyama06/server-sentinel/issues/12) (Plan 6), [#6](https://github.com/TomokiAkiyama06/server-sentinel/issues/6) (Auth prerequisite)

Labels: `remote-agent`, `backend`, `security`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

Scope:
- owner-generated short-lived one-time pairing code;
- non-echoing pairing-code input, never secret-bearing argv/environment/URL; protected input channel for any later installer automation;
- node keypair/credential issuance;
- mTLS or equivalent mutually authenticated transport;
- revocation;
- credential file permissions;
- capture-node protocol authorization separate from human API.

Acceptance:
- expired/reused pairing rejected;
- pairing code absent from process argv, shell history, environment, URLs, and logs;
- unpaired LAN host cannot submit media;
- revoked node cannot reconnect;
- capture-node credential cannot call human/admin endpoints;
- secrets redacted.

## Plan 8 — LAN ingest boundary

GitHub Issue: [#14](https://github.com/TomokiAkiyama06/server-sentinel/issues/14)

Depends on: [#13](https://github.com/TomokiAkiyama06/server-sentinel/issues/13) (Plan 7)

Labels: `remote-agent`, `backend`, `security`, `server-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 必要; UVC Camera: 不要; Manual test: 必要

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

GitHub Issue: [#15](https://github.com/TomokiAkiyama06/server-sentinel/issues/15)

Depends on: [#14](https://github.com/TomokiAkiyama06/server-sentinel/issues/14) (Plan 8)

Labels: `remote-agent`, `camera-source`, `backend`, `documentation`, `server-required`, `hardware-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 必要; UVC Camera: 必要; Manual test: 必要

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

GitHub Issue: [#16](https://github.com/TomokiAkiyama06/server-sentinel/issues/16)

Depends on: [#15](https://github.com/TomokiAkiyama06/server-sentinel/issues/15) (Plan 9), [#8](https://github.com/TomokiAkiyama06/server-sentinel/issues/8) (Plan 3), [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17)

Labels: `remote-agent`, `storage`, `backend`, `frontend`, `security`, `server-required`, `hardware-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 必要; UVC Camera: 必要; Manual test: 必要

Scope:
- compressed-video disk ring buffer on `media-capture-agent`;
- owner-selectable **duration mode** or **capacity mode**;
- UI estimates equivalent capacity/duration and shows current usage/free space/safety reserve;
- 10-minute pre-loss target validation;
- automatic Main Server communication-loss protection: 10 minutes before + 10 minutes after;
- critical-event preserve command while Main Server is reachable;
- protected incidents retained on Agent for 60 days by default, then auto-deleted;
- agent storage-pressure/hard-stop behavior.

Acceptance:
- only owner can change mode/value;
- unsafe settings rejected before filesystem safety reserve is crossed;
- capacity mode remains within selected byte limit;
- duration mode reports projected/actual disk footprint;
- full 20-minute incident is preserved when resources/stream continuity allow;
- shortened/gapped protection is reported truthfully;
- reconnect does not erase protected incident;
- protected incident expires automatically at 60 days;
- unexpired protected incident is not silently overwritten by ordinary ring-buffer pressure.

## Plan 10 — Capture/record/inference/view profile separation

GitHub Issue: [#17](https://github.com/TomokiAkiyama06/server-sentinel/issues/17)

Depends on: [#15](https://github.com/TomokiAkiyama06/server-sentinel/issues/15) (Plan 9), [#9](https://github.com/TomokiAkiyama06/server-sentinel/issues/9) (Plan 4)

Labels: `camera-source`, `backend`, `server-required`, `hardware-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 必要; UVC Camera: 必要; Manual test: 必要

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

GitHub Issue: [#18](https://github.com/TomokiAkiyama06/server-sentinel/issues/18)

Depends on: [#17](https://github.com/TomokiAkiyama06/server-sentinel/issues/17) (Plan 10), [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17)

Labels: `backend`, `storage`, `camera-source`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#20](https://github.com/TomokiAkiyama06/server-sentinel/issues/20)

Depends on: [#17](https://github.com/TomokiAkiyama06/server-sentinel/issues/17) (Plan 10), [#18](https://github.com/TomokiAkiyama06/server-sentinel/issues/18) (Plan 11)

Labels: `ai`, `backend`, `server-required`, `manual-test-required`, `hardware-required`

実機要件: Main Server: 必要; Capture Node: 不要; UVC Camera: 不要; Manual test: 必要

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

GitHub Issue: [#22](https://github.com/TomokiAkiyama06/server-sentinel/issues/22)

Depends on: [#20](https://github.com/TomokiAkiyama06/server-sentinel/issues/20) (Plan 12)

Labels: `ai`, `backend`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#24](https://github.com/TomokiAkiyama06/server-sentinel/issues/24)

Depends on: [#18](https://github.com/TomokiAkiyama06/server-sentinel/issues/18) (Plan 11), [#22](https://github.com/TomokiAkiyama06/server-sentinel/issues/22) (Plan 13)

Labels: `ai`, `backend`, `camera-source`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#25](https://github.com/TomokiAkiyama06/server-sentinel/issues/25)

Depends on: [#22](https://github.com/TomokiAkiyama06/server-sentinel/issues/22) (Plan 13), [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17)

Labels: `ai`, `backend`, `security`, `server-required`, `manual-test-required`, `hardware-required`

実機要件: Main Server: 必要; Capture Node: 不要; UVC Camera: 不要; Manual test: 必要

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

GitHub Issue: [#26](https://github.com/TomokiAkiyama06/server-sentinel/issues/26)

Depends on: [#24](https://github.com/TomokiAkiyama06/server-sentinel/issues/24) (Plan 14), [#25](https://github.com/TomokiAkiyama06/server-sentinel/issues/25) (Plan 15), [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17)

Labels: `backend`, `frontend`, `security`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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

GitHub Issue: [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10)

Depends on: [#6](https://github.com/TomokiAkiyama06/server-sentinel/issues/6) (Auth prerequisite), [#7](https://github.com/TomokiAkiyama06/server-sentinel/issues/7) (Plan 2), [#8](https://github.com/TomokiAkiyama06/server-sentinel/issues/8) (Plan 3)

Labels: `backend`, `frontend`, `security`, `server-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 不要; UVC Camera: 不要; Manual test: 必要

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

GitHub Issue: [#19](https://github.com/TomokiAkiyama06/server-sentinel/issues/19)

Depends on: [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17), [#17](https://github.com/TomokiAkiyama06/server-sentinel/issues/17) (Plan 10), [#8](https://github.com/TomokiAkiyama06/server-sentinel/issues/8) (Plan 3)

Labels: `frontend`, `backend`, `security`, `server-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 不要; UVC Camera: 不要; Manual test: 必要

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

GitHub Issue: [#21](https://github.com/TomokiAkiyama06/server-sentinel/issues/21)

Depends on: [#18](https://github.com/TomokiAkiyama06/server-sentinel/issues/18) (Plan 11), [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17), [#8](https://github.com/TomokiAkiyama06/server-sentinel/issues/8) (Plan 3)

Labels: `backend`, `frontend`, `storage`, `security`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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
- ordinary person/motion does not spam main channel by default;
- expired unstarred recordings are deleted first, then oldest eligible unstarred recordings are reclaimed as needed;
- pressure rejects/suppresses ordinary/manual recording admission;
- only confirmed critical evidence can use the bounded critical allowance, without crossing hard reserve;
- unsafe writes enter `STORAGE_HARD_STOP`, with audit/UI state transitions;
- recovery uses hysteresis rather than oscillating at the threshold.

## Plan 19A — Main-host hardware integrity + recording-health self-test

GitHub Issue: [#23](https://github.com/TomokiAkiyama06/server-sentinel/issues/23)

Depends on: [#21](https://github.com/TomokiAkiyama06/server-sentinel/issues/21) (Plan 19), [#18](https://github.com/TomokiAkiyama06/server-sentinel/issues/18) (Plan 11), [#10](https://github.com/TomokiAkiyama06/server-sentinel/issues/10) (Plan 17)

Labels: `backend`, `storage`, `security`, `server-required`, `hardware-required`, `manual-test-required`

実機要件: Main Server: 必要; Capture Node: 不要; UVC Camera: 不要; Manual test: 必要

Scope:
- Owner-approved hardware baseline for CPU / RAM / NVMe(M.2) / HDD / GPU;
- strongest available stable local identifiers with explicit `UNVERIFIABLE` handling;
- startup inventory comparison;
- at-least-daily inventory comparison;
- no silent baseline rewrite;
- Owner-only approval of deliberate hardware changes;
- daily recorder self-test covering source freshness, recorder/encoder, expected recording filesystem identity, free space/safety reserve, bounded temporary write + fsync + reopen/decode;
- SMART/NVMe health collection where available;
- immediate Owner notification for missing/changed baseline hardware and recording-health failures;
- local-only/redacted handling of raw serials/UUIDs.

Acceptance:
- baseline drift reports `CHANGED`/`MISSING`/`NEW_DEVICE`/`UNVERIFIABLE` as appropriate;
- startup and daily checks both execute;
- baseline never updates automatically;
- same-model hardware with no exposed unique identifier is not falsely claimed as distinguishable;
- unexpected/unmounted recording filesystem does not silently fall back while reporting healthy;
- test segment write/fsync/reopen/readability failure is detected;
- successful temporary self-test media is deleted locally;
- immediate alert does not wait only for daily summary;
- Slack alert works when configured, while dashboard/audit remains authoritative when Slack is disabled;
- raw hardware identifiers and real monitoring media are absent from repo/CI/public diagnostics.

## Plan 20 — Full mock E2E + failure scenarios

GitHub Issue: [#27](https://github.com/TomokiAkiyama06/server-sentinel/issues/27)

Depends on: [#16](https://github.com/TomokiAkiyama06/server-sentinel/issues/16) (Plan 9A), [#26](https://github.com/TomokiAkiyama06/server-sentinel/issues/26) (Plan 16), [#19](https://github.com/TomokiAkiyama06/server-sentinel/issues/19) (Plan 18), [#23](https://github.com/TomokiAkiyama06/server-sentinel/issues/23) (Plan 19A)

Labels: `backend`, `frontend`, `ci`

実機要件: Main Server: 不要; Capture Node: 不要; UVC Camera: 不要; Manual test: 不要

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
- timeline correlation;
- hardware baseline drift/missing-device scenarios;
- recording-filesystem substitution/unmount;
- recording-health self-test failure and immediate alerting.

Acceptance:
- mock E2E passes without real hardware;
- no silent healthy state after known capture loss;
- unrelated critical monitoring survives owner-verifier failure.

## Plan 21 — Real hardware/network/browser acceptance

GitHub Issue: [#28](https://github.com/TomokiAkiyama06/server-sentinel/issues/28)

Depends on: [#27](https://github.com/TomokiAkiyama06/server-sentinel/issues/27) (Plan 20)

Labels: `camera-source`, `remote-agent`, `server-required`, `hardware-required`, `manual-test-required`, `documentation`

実機要件: Main Server: 必要; Capture Node: 必要; UVC Camera: 必要; Manual test: 必要

Scope is defined by `MANUAL_TEST.md`.

Minimum intended environments:
- one local UVC webcam;
- two local UVC webcams where available;
- remote Linux `media-capture-agent` with room-overview UVC camera;
- 1–4 mixed-source stress run;
- phone browser live view;
- Mac browser live view;
- unchanged Tailnet policy with uninvited/live-only/recordings-only/both/revoked application test identities;
- low-light/degraded behavior;
- long-duration run;
- startup + daily hardware-integrity verification;
- daily recording-health self-test.

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
