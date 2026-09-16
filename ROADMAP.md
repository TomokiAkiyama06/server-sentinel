# Roadmap

This roadmap is intentionally high-level. GitHub Issues are the execution source of truth.

## Phase 0 — Bootstrap

- [ ] Public repository
- [ ] Apache-2.0 license
- [ ] specifications committed
- [ ] issue/PR templates
- [ ] CI skeleton
- [ ] secret scan
- [ ] dependency/license policy

## Phase 1 — Server foundation

- [ ] FastAPI service
- [ ] SQLite migrations
- [ ] settings
- [ ] local storage abstraction
- [ ] health endpoints
- [ ] React dashboard shell
- [ ] Docker Compose
- [ ] mock Camera Node protocol

## Phase 2 — Pairing

- [ ] local discovery
- [ ] one-time pairing token
- [ ] QR pairing
- [ ] manual pairing fallback
- [ ] Camera Node identity/revocation

## Phase 3 — iOS Camera Node

- [ ] SwiftUI shell
- [ ] permissions
- [ ] capability diagnostics
- [ ] AVFoundation rear capture
- [ ] MultiCam front/rear
- [ ] microphone default OFF
- [ ] CoreMotion
- [ ] thermal/power state
- [ ] monitoring/dim UI
- [ ] reconnect state machine
- [ ] emergency local evidence store

## Phase 4 — Media transport

- [ ] live transport PoC + ADR
- [ ] recording chunk protocol
- [ ] checksums/retry/idempotency
- [ ] manual recording
- [ ] pre/post ring buffer

## Phase 5 — Detection

- [ ] general motion
- [ ] YOLOX-first person-detector evaluation with independent weight-license review
- [ ] ROI calibration
- [ ] server movement
- [ ] camera tamper
- [ ] low-light/torch automation

## Phase 6 — User experience

- [ ] events
- [ ] thumbnails/playback
- [ ] star/delete
- [ ] storage/retention
- [ ] presence
- [ ] schedule
- [ ] optional Shortcuts endpoints
- [ ] Slack summary/threading

## Phase 7 — Hardening

- [ ] chaos/network tests
- [ ] storage-full tests
- [ ] security review
- [ ] dependency/license review
- [ ] real-device thermal tests
- [ ] 24-hour run

## Phase 8 — App Store

- [ ] privacy-policy hosting
- [ ] app metadata/screenshots
- [ ] Demo Mode
- [ ] reviewer instructions
- [ ] public App Store submission
