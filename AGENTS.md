# AGENTS.md — Mandatory Rules for Coding Agents

This file is normative. Agents working in this repository MUST follow it unless the repository owner explicitly overrides a rule for a specific task.

## 1. Mission

Build ServerSentinel as a free, self-hosted, privacy-first physical-security monitor consisting of:

- a main Ubuntu backend;
- a React web dashboard;
- a generic Camera Source layer;
- local UVC capture;
- remote Linux `media-capture-agent` capture over a private LAN;
- private phone/Mac/desktop live viewing for explicitly invited users.

The MVP supports 1–4 active video sources. It does not require an iPhone/browser to act as a camera source, a native iOS app, Apple Developer Program membership, or App Store distribution.

## 2. Authoritative documents

Priority order:

1. explicit repository-owner instruction for the current task/Issue;
2. `REQUIREMENTS.md`;
3. `SPECIFICATION.md`;
4. accepted ADRs;
5. this file;
6. existing implementation.

Ask the owner before inventing a security/privacy/biometric/access-control product decision.

## 3. Work/merge policy

For non-trivial changes:

1. map work to an Issue;
2. branch from the intended base;
3. implement/test/document;
4. open/update PR;
5. wait for CI;
6. wait for Codex and Claude review of the current PR **HEAD against the current base/diff context**;
7. fix blocking findings and resolve/respond to threads;
8. rerun reviews after material HEAD/base changes;
9. merge only when gates pass.

Never commit directly to `main`.

Until Issue #4 hardens repository-level enforcement, same-repository write access is a trusted-maintainer capability and the merge actor manually verifies review provenance/current HEAD+base context.

## 4. Hardware-unavailable policy

Use mocks, synthetic/generated fixtures, dependency injection, virtual sources, and transport mocks. Do not claim hardware/network/browser behavior was verified when it was not. Exact physical tests belong in `MANUAL_TEST.md`.

## 5. Privacy/security invariants

Default invariants:

- no developer-operated account/video service;
- no telemetry/analytics/ads/tracking;
- no developer relay for Slack;
- no hidden data upload;
- video-only monitoring in MVP;
- owner face verification optional/local;
- no named non-owner face database;
- no cross-camera biometric re-identification;
- no automatic culprit/guilt inference;
- no public Internet dashboard exposure by default;
- Tailnet membership alone never authorizes ServerSentinel;
- uninvited ordinary Tailnet members should receive no ServerSentinel-node Grant where the deployment uses Tailscale access policy;
- do not promise concealment from Tailnet Owners/Admins or infrastructure administrators.

## 6. Secret/sensitive-data handling

Never commit/log real:

- `.env` secrets;
- Slack webhook/token;
- Tailscale auth/admin key;
- private keys/certificates;
- private deployment IP/hostname/SSID/Tailnet values;
- owner biometric templates/embeddings;
- recordings or real-person/real-room monitoring media.

Repository/CI media fixtures MUST be synthetic/generated only. Publicly licensed real-person images are still not repository fixtures. External benchmark datasets may be used locally under their terms and never attached to GitHub PR/issues/actions artifacts.

## 7. Camera Source invariants

MVP source types:

- `local_uvc`;
- `remote_agent`.

Rules:

- system works with one active source;
- default active limit four;
- no fixed `front/rear` schema;
- source type and role remain separate;
- profiles configured per source;
- `/dev/videoN` alone is not durable identity;
- do not auto-bind an ambiguous identical non-serial UVC candidate after reconnect;
- ambiguous reconnect => `manual_intervention_required` until explicit owner re-approval;
- audio is not captured in MVP;
- browser/iPhone camera capture is outside the current product scope; phone/Mac/desktop browsers are viewers.

## 8. `media-capture-agent` invariants

- service/process name: `media-capture-agent`;
- no impersonation of unrelated system/vendor software;
- no desktop UI/tray requirement;
- normal runtime under dedicated non-root account;
- capture video only in MVP;
- agent initiates connection to main host;
- one-time owner-approved pairing then revocable mutually authenticated encrypted identity;
- capture-node credential grants no human/admin API rights;
- agent does not need Tailscale when private LAN reachability exists;
- agent health and camera health are separate;
- capture ingest listener is separate from human dashboard listener;
- main host does not SSH/admin into the capture machine merely to receive video;
- agent keeps a compressed-video disk ring buffer; owner selects duration or capacity mode; unexpected Main Server loss protects T-10/T+10 minutes; protected incidents expire from the agent after 30 days.

## 9. Human-access invariants

Human remote access has two independent gates:

1. network-level private/Tailscale permission;
2. ServerSentinel application invitation/permission.

Initial non-owner permissions:

```text
live:view
recordings:view
```

They are independent.

Non-owner recording access is browser playback only in MVP; do not add a download/export route/button unless the owner explicitly changes the requirement. Do not claim browser playback prevents screen recording/client capture.

Historical timeline/event access is included with `recordings:view`; never expose it to `live:view` alone.

If trusted proxy/Tailscale identity headers are used, backend access to that listener must be non-bypassable from ordinary LAN clients.

## 10. Detection invariants

- person detection != server movement proof;
- compensate global camera motion where relevant;
- handle occlusion/temporal persistence;
- confidence is not certainty;
- image-quality gating is detector-specific;
- if person detection cannot run reliably, result is `unknown`/unavailable, never a trustworthy `no person`;
- low-quality owner verification => `unknown`;
- no named non-owner identities;
- timeline reports observations, not guilt/causality.

## 11. Presence invariants

States: `PRESENT`, `PROBABLY_PRESENT`, `ABSENT`, `UNKNOWN`.

Manual override has precedence. Only explicit/high-confidence `PRESENT` suppresses ordinary occupancy automation by default. Server movement/camera tamper remain armed in all states.

## 12. Media/storage invariants

- capture, recording, inference, and viewer profiles are independent;
- prefer compatible stream copy before unnecessary transcoding;
- viewer-only processing should stop/scale down with zero subscribers;
- remote viewers connect to the main host, never directly to capture agent;
- default event target 30 s pre + 120 s post, max 20 min;
- manual recording max 20 min;
- use bounded compressed pre-roll where practical rather than long decoded-frame histories;
- recording retention default 20 days;
- audit retention default 90 days;
- starred recordings never auto-delete;
- preserve hard filesystem safety reserve;
- explicit `STORAGE_PRESSURE` / `STORAGE_HARD_STOP`;
- no silent healthy state during known loss/overload.

## 13. Dependency/model licenses

Verify upstream, exact license, material transitive obligations, and pinning. For ML, review implementation code and model/weights separately.

Preferred: Apache-2.0, MIT, BSD-2/3-Clause, similarly permissive after review.

Blocked by default without explicit owner approval: AGPL, incompatible GPL obligations, SSPL, BSL/source-available/non-OSI, ambiguous licensing.

YOLOX is an initial person-detector evaluation candidate only. Owner face-verification model/weights need separate review.

## 14. Destructive-operation policy

Without explicit owner approval never:

- wipe/format disks;
- delete all recordings/database/tables;
- destroy data-bearing volumes;
- disable firewall globally or expose service publicly;
- modify Tailscale Grants/ACLs using administrative credentials;
- rotate unrelated credentials;
- change SSH rules that could lock out owner;
- force-push protected/shared history.

## 15. Logging/API rules

Do not log raw pairing credentials, agent keys/certs, Tailscale/Slack secrets, biometric templates, sensitive headers, or media content.

Every media/API route enforces server-side authorization. Capture ingest accepts only agent protocol actions. Human UI routes are not reachable through the ingest listener.

## 16. Testing

As applicable cover:

- 1–4 source topology;
- local UVC stable identity/reconnect;
- ambiguous identical non-serial camera reconnect;
- agent pairing/revocation/mTLS;
- agent-online/camera-offline separation;
- clock skew;
- LAN interruption/backpressure;
- phone/Mac live viewing;
- Tailscale/private reachability + ServerSentinel application authorization;
- `live:view` vs `recordings:view` isolation, including historical timeline only with `recordings:view`;
- duration/capacity ring-buffer modes, T-10/T+10 protection, 30-day expiry, and agent disk pressure;
- detector-specific quality gate including person false-negative prevention;
- owner verification/anonymous tracking/presence;
- storage pressure;
- migrations/mock E2E.

## 17. Documentation discipline

When behavior changes update:

- `REQUIREMENTS.md` — product decisions;
- `SPECIFICATION.md` — technical contracts;
- ADR — architectural decisions;
- `MANUAL_TEST.md` — real-hardware/network/browser checks;
- `SECURITY.md` / `PRIVACY.md` — security/data behavior;
- `docs/INITIAL_ISSUES.md` / `ROADMAP.md` — implementation sequence.

## 18. Stop conditions

Stop and request explicit owner decision before:

- developer-hosted cloud;
- analytics/ads/payment;
- project license change;
- incompatible/uncertain dependency/model license;
- default public Internet exposure;
- weakening two-gate access control or capture-node authentication;
- automatically storing powerful Tailscale admin credentials;
- collecting audio;
- enrolling/naming non-owner faces;
- cross-camera biometric re-identification;
- automatic culprit/guilt inference;
- introducing browser/iPhone camera capture without a new explicit product decision/ADR;
- adding a non-owner recording download/export function;
- changing the established `recordings:view` -> historical timeline permission mapping without owner approval;
- weakening the 10-minute pre/10-minute post agent protection or 30-day agent expiry without owner approval.
