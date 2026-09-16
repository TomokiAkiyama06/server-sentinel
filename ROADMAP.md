# Roadmap

This roadmap is intentionally high-level. GitHub Issues are the execution source of truth. `docs/INITIAL_ISSUES.md` contains the current bootstrap execution sequence.

## Phase 0 — Bootstrap

- [ ] public repository
- [ ] Apache-2.0 license
- [ ] specifications committed
- [ ] issue/PR templates
- [ ] CI skeleton
- [ ] secret scan
- [ ] dependency/model license policy
- [ ] hardened review-gate follow-up (Issue #4)

## Phase 1 — Server and web foundation

- [ ] FastAPI service
- [ ] SQLite migrations
- [ ] settings/config
- [ ] recording storage abstraction
- [ ] health endpoints
- [ ] React dashboard shell
- [ ] Web Camera Node route/shell
- [ ] Docker Compose
- [ ] deployment-owner authorization ADR/bootstrap

## Phase 2 — Camera Source platform

- [ ] generic Camera Source registry
- [ ] configurable active-source limit (default 4)
- [ ] capabilities/health/detection-profile model
- [ ] local UVC discovery/ingest
- [ ] stable UVC device identity/reconnect
- [ ] secure Web Camera Node pairing
- [ ] browser `getUserMedia()` capture
- [ ] audio default OFF
- [ ] browser lifecycle/reconnect state
- [ ] no automatic torch/light behavior

## Phase 3 — Media

- [ ] live transport PoC + ADR
- [ ] secure-origin/TLS setup decision
- [ ] multi-source live grid
- [ ] durable remote recording chunks
- [ ] local UVC recording path
- [ ] checksums/retry/idempotency
- [ ] server pre/post ring buffers
- [ ] generic source-ID recording manifest
- [ ] manual recording

## Phase 4 — Physical-security detection

- [ ] general motion
- [ ] permissively licensed person-detector evaluation
- [ ] per-source inference cadence
- [ ] server ROI calibration
- [ ] server movement
- [ ] camera tamper/occlusion/source-health correlation
- [ ] low-light/image-quality gating

## Phase 5 — Entrance and presence intelligence

- [ ] owner-only face-verification model/license evaluation
- [ ] explicit owner enrollment/delete flow
- [ ] anonymous same-camera tracking
- [ ] entrance line/direction calibration
- [ ] anonymous entry/exit observations
- [ ] owner entry/exit observations
- [ ] `PRESENT / PROBABLY_PRESENT / ABSENT / UNKNOWN`
- [ ] manual presence override/schedule
- [ ] no non-owner named face database
- [ ] no cross-camera biometric re-identification in MVP

## Phase 6 — Timeline and user experience

- [ ] unified security timeline
- [ ] relevant observation window around critical events
- [ ] neutral observation wording/no culprit inference
- [ ] events/thumbnails/playback
- [ ] star/delete
- [ ] storage/retention UX
- [ ] camera-source configuration UX
- [ ] Slack summary/threading

## Phase 7 — Hardening

- [ ] chaos/network tests
- [ ] UVC disconnect/reorder/substitution tests
- [ ] browser suspend/reconnect tests
- [ ] 1–4 source stress tests
- [ ] storage-full tests
- [ ] security review
- [ ] privacy/biometric review
- [ ] dependency/model/weight license review
- [ ] low-light tests with no automatic illumination
- [ ] 24-hour mixed-source run

## Future — not MVP

Potential future work requires separate Issues/ADRs:
- RTSP/IP camera source;
- Raspberry Pi/edge Camera Node;
- strong independent/off-host evidence storage;
- native mobile app if later justified;
- cross-camera re-identification (privacy review required);
- environment sensors;
- NAS/off-host storage targets;
- broader server observability.
