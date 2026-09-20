# Roadmap

This roadmap is intentionally high-level. GitHub Issues are the execution source of truth. `docs/INITIAL_ISSUES.md` contains the current bootstrap sequence.

Phases group capabilities rather than imposing a strict completion order. The dependency graph in `docs/INITIAL_ISSUES.md` governs acceptance: the authorization ADR precedes Backend endpoint contracts, Plan 17 enforcement precedes human-facing media/UI acceptance, negotiated profiles precede Agent buffer configuration acceptance, and Agent preservation plus notification contracts precede Presence integration. Mock/contract work can proceed independently.

## Phase 0 — Bootstrap

- [ ] public repository / Apache-2.0
- [ ] specifications committed
- [ ] issue/PR templates
- [x] CI/repository guards, synthetic regression tests, and conditional component checks (#5; see `docs/CI.md`)
- [ ] dependency/model license policy
- [ ] hardened review gate #4: capability assessment, offline policy tests and disabled ruleset generator prepared; Owner App setup, trusted publisher/collector and GitHub enforcement acceptance remain open (see `docs/REVIEW_GATE_SETUP.md`)

Issue #1 closed when PR #2 merged after documentation/bootstrap acceptance and current HEAD/base reviews plus CI passed. CI foundation #5 is implemented. The backend and dashboard foundations have synthetic coverage; their authorization prerequisites remain separate. Runtime/ADR progress for Issues #6–#28 and the separately tracked #4 is tracked below and in GitHub.

## Phase 1 — Main server and web foundation

- [x] closed FastAPI foundation (human routes await #6/#10)
- [x] SQLite migration foundation
- [x] validated deployment settings and database abstraction
- [ ] health endpoints
- [x] React responsive dashboard shell (#8; synthetic/mock foundation, production access integration remains #10)
- [ ] Docker Compose where appropriate
- [ ] deployment-owner authorization ADR/bootstrap
- [ ] trusted Tailscale/private-proxy identity boundary

## Phase 2 — Camera Source + Capture Node platform

- [x] generic Camera Source registry
- [x] `local_uvc` / `remote_agent`
- [x] active-source limit default 4
- [x] capabilities/health/profile model
- [ ] local UVC discovery/ingest
- [ ] stable/ambiguous UVC identity handling

Issue #11 now has a V4L2 discovery/MMAP adapter, durable approval latch and
registry integration with synthetic tests. The UVC items remain unchecked until
Owner management/worker integration and real-webcam acceptance are complete;
no browser preview or physical device result is claimed.
- [ ] `media-capture-agent` native service — #12 foundation implemented; capture/paired transport integration and physical acceptance pending
- [ ] video-only capture
- [ ] one-time pairing + mTLS/revocation
- [ ] separate LAN ingest listener
- [ ] node health vs camera health
- [ ] clock offset monitoring
- [ ] deployment-configured Agent media root with expected-mount validation and no silent fallback

## Phase 3 — Media

- [ ] agent->main transport PoC + ADR
- [ ] Agent compressed disk ring buffer with Owner-selected duration/capacity modes
- [ ] autonomous T-10/T+10 incident protection, critical preserve command, and 60-day default expiry
- [ ] Agent storage pressure/hard stop without deleting unexpired protected evidence
- [ ] capture/record/inference/view profile separation
- [ ] high-resolution room-overview benchmark
- [ ] passthrough/hardware/software encode paths
- [ ] main-host compressed pre/post ring buffer
- [ ] generic source-ID recording manifest
- [ ] manual recording
- [ ] main->browser live transport PoC + ADR
- [ ] phone/Mac/desktop 1–4 source live grid, with stability/reconnect prioritized over minimum latency
- [ ] demand-driven viewer transcoding/packaging

Issue #18 now has bounded compressed storage primitives, source/event manifests,
application migration v4 integration, and synthetic crash/integrity coverage. Its
runtime worker, codec adapter, shared storage guard and authorization integration
remain open; these primitives do not establish playable-video or hardware
acceptance.

## Phase 4 — Human private access

- [ ] unchanged-Tailnet-policy compatible application authorization
- [ ] application invitation/allowlist
- [ ] independent `live:view` / `recordings:view`
- [ ] browser-only non-owner playback
- [ ] prompt revocation
- [ ] generic/non-branding denial and no deployment metadata leakage to unauthorized identity
- [ ] `recordings:view` includes historical timeline/events

## Phase 5 — Physical-security detection

- [ ] general motion
- [ ] permissively licensed person-detector evaluation
- [ ] detector-specific image-quality gating
- [ ] no false `no person` when quality is insufficient
- [ ] per-source inference cadence
- [ ] server ROI calibration/movement
- [ ] camera tamper/occlusion/source-health correlation

## Phase 6 — Entrance / owner / presence intelligence

- [ ] owner-only face-verification model/license evaluation
- [ ] explicit owner enrollment/delete flow
- [ ] anonymous same-camera tracking
- [ ] entrance/zone calibration where geometry supports it
- [ ] anonymous/owner entry-exit observations
- [ ] `PRESENT / PROBABLY_PRESENT / ABSENT / UNKNOWN`
- [ ] manual presence override/schedule
- [ ] no non-owner enrollment or persistent face-crop/template/embedding/profile library, whether named or anonymous
- [ ] no cross-camera biometric re-identification

## Phase 7 — Timeline, recordings, storage, notifications

- [ ] unified factual timeline
- [ ] neutral wording/no culprit inference
- [ ] recording browser/playback
- [ ] star/delete owner actions
- [ ] storage/retention UX
- [ ] `STORAGE_PRESSURE` / `STORAGE_HARD_STOP`
- [ ] Slack optional summary/threading
- [ ] Main Server Owner-approved hardware baseline and startup/daily comparison
- [ ] daily recording-health self-test, expected-filesystem validation, and bounded write/read/decode verification
- [ ] immediate Owner alerts for changed/missing hardware and recording-health failures

## Phase 8 — Hardening / real environment

- [ ] UVC disconnect/reorder/substitution ambiguity tests
- [ ] capture-agent LAN interruption/revocation tests
- [ ] clock-skew tests
- [ ] 1–4 source stress tests
- [ ] phone/Mac/desktop private live-view tests, including copied-URL authorization
- [ ] unchanged-Tailnet-policy reachability + application-permission isolation tests
- [ ] storage-full and Agent/Main media-mount loss/substitution tests
- [ ] startup/daily hardware-integrity and daily recording-health failure/notification tests
- [ ] low-light detector-gating tests
- [ ] security/privacy/biometric/license review
- [ ] 24-hour mixed-source run

## Explicit pending decisions

Issue #23 has an independent comparison/approval/outbox core and recording-health
worker adapter with disposable-file cleanup/recovery tests. Authorization,
actual codec/source wiring, notifications and physical acceptance remain open;
see the integrity and media/health module READMEs.

- [ ] exact agent->main transport;
- [ ] exact main->browser live transport/target latency;
- [ ] room-overview capture/record/inference/view defaults after benchmark;
- [ ] agent filesystem safety-reserve/warning thresholds after capture-host measurement;

## Future — not MVP

- RTSP/IP camera source;
- Raspberry Pi/other edge node packaging;
- general-purpose replication of all Main Server recordings to another host;
- native mobile app if later justified;
- cross-camera re-identification (privacy review required);
- audio surveillance;
- environment sensors;
- NAS/off-host storage targets;
- broader server observability.
