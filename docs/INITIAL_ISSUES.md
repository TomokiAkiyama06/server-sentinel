# Initial GitHub Issue Plan

This file is a bootstrap plan. Once Issues are created, GitHub becomes the execution source of truth.

> **Important:** The `Plan N` headings below are planning sequence labels, **not GitHub Issue numbers**. Do not assume `Plan 4 == Issue #4` or preserve these numbers when creating Issues. Actual GitHub Issue numbers are assigned by GitHub and are the source of truth after creation.
>
> Repository review-gate hardening is already tracked in **GitHub Issue #4 — `Ruleset / 専用GitHub Appで自動レビューゲートを強制する`**. Do not create a duplicate from this plan. Issue #4 must be completed before granting same-repository write access to additional collaborators.

## Recommended labels

Type:
- `bug`
- `enhancement`
- `documentation`
- `architecture`
- `security`
- `privacy`
- `ci`

Hardware:
- `hardware-required`
- `iphone-required`
- `server-required`
- `manual-test-required`

Component:
- `ios`
- `backend`
- `web`
- `media`
- `detection`
- `storage`
- `notifications`

Decision:
- `decision-needed`
- `proposal`

## Plan 1 — Bootstrap CI and repository quality gates

Scope:
- formatting/lint skeleton;
- secret scanning;
- dependency/license reporting approach;
- Docker/Compose validation placeholder;
- web/backend/iOS job skeletons where projects exist.

Acceptance:
- CI runs on PR;
- direct implementation does not require real hardware;
- secret scan catches a known test pattern in an isolated test.

## Plan 2 — Backend foundation

Scope:
- FastAPI project;
- config model;
- SQLite migrations;
- health API;
- local structured logging;
- Docker image.

Acceptance:
- `/api/v1/health` tested;
- migration test;
- no secret logging;
- container starts in CI.

## Plan 3 — React dashboard foundation

Scope:
- React/TypeScript;
- mobile-first shell;
- API client abstraction;
- dashboard status cards;
- Japanese default localization structure.

Acceptance:
- build/typecheck/test;
- mocked health state shown.

## Plan 4 — iOS Camera Node foundation

Labels: `ios`, `iphone-required`, `manual-test-required`

Scope:
- SwiftUI shell;
- onboarding;
- permission explanation;
- capability model;
- hardware interfaces/protocols;
- Demo Mode skeleton;
- dim monitoring screen state machine.

Acceptance:
- non-hardware logic unit-tested;
- real capture verification deferred to manual test Issue.

## Blocking prerequisite before Pairing protocol — Deployment-owner authorization ADR/bootstrap

Labels: `architecture`, `security`, `backend`, `web`, `decision-needed`

This work MUST be completed before the pairing protocol is considered implementable/complete. Tailnet membership provides reachability only and is not sufficient owner authorization.

Scope:
- choose the MVP deployment-owner authorization mechanism by ADR;
- compare a locally managed owner credential/session against explicit binding to one verified Tailscale identity/ACL or another self-hosted equivalent;
- define trusted local bootstrap flow;
- define remote privileged-operation authorization checks;
- define recovery/revocation;
- define session lifetime/rotation and CSRF/browser considerations where applicable;
- define how pairing approval/revocation proves deployment-owner authorization;
- update setup documentation and API contracts.

Acceptance:
- ADR accepted before pairing implementation is merged;
- privileged dashboard/API operations fail closed when owner authorization is absent/invalid;
- another member of the same Tailnet is denied unless explicitly bound/authorized as the deployment owner by the selected mechanism;
- pairing approval and Camera Node revocation require deployment-owner authorization;
- recovery/revocation path is tested;
- no developer-operated account/cloud service is introduced;
- negative authorization tests run without real hardware.

Blocking relationship:
- the **Pairing protocol** Issue MUST depend on this prerequisite and MUST NOT be closed until the selected owner authorization boundary is enforced in pairing approval/revocation.

## Plan 5 — Pairing protocol

Scope:
- one-time token;
- 5-minute expiry;
- QR payload schema;
- owner-authorized approval/revocation;
- iOS Keychain abstraction;
- mDNS discovery proposal/implementation if suitable.

Acceptance:
- deployment-owner authorization prerequisite/ADR is complete;
- expired token rejected;
- token reuse rejected;
- token redacted from logs;
- pairing approval without valid deployment-owner authorization is rejected;
- Camera Node revocation without valid deployment-owner authorization is rejected;
- a non-owner Tailnet member cannot approve/revoke pairing merely because network reachability exists;
- mock iOS client pairs/revokes when valid owner authorization is present.

## Plan 6 — Live media transport PoC + ADR

Labels: `architecture`, `media`, `iphone-required`, `server-required`

Compare WebRTC-first against credible alternatives.

Measure/document:
- latency;
- reconnect;
- CPU;
- thermal impact;
- browser support;
- Tailscale behavior;
- dependency licenses.

Acceptance:
- ADR committed;
- selected transport justified by measurements/constraints.

## Plan 7 — Durable recording chunk protocol

Scope:
- chunk metadata;
- checksum;
- retry;
- idempotency;
- out-of-order handling;
- session manifest;
- pre/post ring-buffer architecture.

Acceptance:
- duplicate upload does not duplicate recording;
- interrupted upload resumes safely;
- integrity failure detected.

## Plan 8 — Person/motion detector evaluation

Labels: `detection`, `architecture`

Scope:
- general motion baseline;
- evaluate YOLOX first as the initial permissively licensed detector candidate;
- keep the detector interface pluggable;
- verify source-code and model-weight licenses independently;
- compare at least one credible permissive alternative if YOLOX is unsuitable;
- CPU/GPU benchmark on available Ubuntu hardware when possible.

Acceptance:
- no AGPL dependency merged by default;
- license evidence documented;
- detector interface remains pluggable;
- synthetic fixture tests.

## Plan 9 — Server ROI calibration and movement detection

Scope:
- ROI setup UI/API;
- reference capture;
- camera-global-transform compensation;
- occlusion handling;
- movement confidence/event.

Acceptance:
- fixture for person occlusion does not become movement;
- fixture for server displacement does;
- threshold configuration documented.

## Plan 10 — Camera tamper detection

Scope:
- IMU telemetry;
- scene transform;
- occlusion;
- disconnect correlation;
- confidence/event;
- critical local evidence trigger.

Acceptance:
- mock sensor tests;
- false-positive guard tests;
- real-device behavior left in MANUAL_TEST.

## Plan 11 — Recording/event/storage UX

Scope:
- event list;
- thumbnail;
- playback;
- star/unstar;
- manual delete;
- 20-day retention;
- max capacity;
- 90-day audit retention;
- disk safety reserve.

Acceptance:
- starred recordings survive cleanup;
- oldest eligible recordings cleaned first;
- storage-full tests.

## Plan 12 — Presence and schedule

Scope:
- one-click presence;
- quick time choices;
- until-clock-time;
- weekly schedule;
- override priority;
- Shortcuts-compatible check-in/out endpoints.

Acceptance:
- live/manual recording remain available during presence;
- automatic monitoring resumes at expiry.

## Plan 13 — Slack integration

Scope:
- optional configuration;
- immediate critical alerts only;
- 23:00 configurable daily summary;
- thumbnail thread replies;
- retry/audit.

Acceptance:
- normal motion does not spam main channel;
- Slack failure never blocks recording;
- secrets redacted.

## Plan 14 — Thermal/quality policy

Labels: `ios`, `iphone-required`, `manual-test-required`

Scope:
- thermal state pipeline;
- adaptive capture policy;
- local audit events;
- benchmark harness/logging.

Software acceptance:
- policy state machine unit-tested.

Manual acceptance:
- 1h/8h/24h iPhone 14 runs documented.

## Plan 15 — Full mock E2E and failure tests

Scope:
- mock camera pair;
- fixture stream;
- detection;
- recording;
- thumbnail;
- web event;
- Slack stub;
- retention;
- reconnect;
- backend restart.

Acceptance:
- end-to-end test reproducible in CI without real hardware.

## Plan 16 — Real-device acceptance

Labels: `hardware-required`, `iphone-required`, `server-required`, `manual-test-required`

Execute `MANUAL_TEST.md`, including the 24-hour run.
