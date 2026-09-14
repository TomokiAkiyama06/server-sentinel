# Initial GitHub Issue Plan

This file is a bootstrap plan. Once Issues are created, GitHub becomes the execution source of truth.

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

## #1 Bootstrap CI and repository quality gates

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

## #2 Backend foundation

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

## #3 React dashboard foundation

Scope:
- React/TypeScript;
- mobile-first shell;
- API client abstraction;
- dashboard status cards;
- Japanese default localization structure.

Acceptance:
- build/typecheck/test;
- mocked health state shown.

## #4 iOS Camera Node foundation

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

## #5 Pairing protocol

Scope:
- one-time token;
- 5-minute expiry;
- QR payload schema;
- approval/revocation;
- iOS Keychain abstraction;
- mDNS discovery proposal/implementation if suitable.

Acceptance:
- expired token rejected;
- token reuse rejected;
- token redacted from logs;
- mock iOS client pairs/revokes.

## #6 Live media transport PoC + ADR

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

## #7 Durable recording chunk protocol

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

## #8 Person/motion detector evaluation

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

## #9 Server ROI calibration and movement detection

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

## #10 Camera tamper detection

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

## #11 Recording/event/storage UX

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

## #12 Presence and schedule

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

## #13 Slack integration

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

## #14 Thermal/quality policy

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

## #15 Full mock E2E and failure tests

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

## #16 Real-device acceptance

Labels: `hardware-required`, `iphone-required`, `server-required`, `manual-test-required`

Execute `MANUAL_TEST.md`, including the 24-hour run.
