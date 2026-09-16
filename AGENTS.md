# AGENTS.md — Mandatory Rules for Coding Agents

This file is normative. Agents working in this repository MUST follow it unless the repository owner explicitly overrides a rule for a specific task.

## 1. Project mission

Build ServerSentinel as a free, self-hosted, privacy-first physical-security monitor consisting of:
- an Ubuntu ServerSentinel backend;
- a React web dashboard;
- a generic Camera Source layer supporting local UVC webcams and browser-based Web Camera Nodes.

The MVP supports 1–4 active video sources in arbitrary supported combinations. It does not require a native iOS application, Apple Developer Program membership, or App Store distribution.

The developer must not become a custodian of users' recordings, biometric templates, or operational data.

## 2. Authoritative documents

Priority order when requirements conflict:

1. Explicit repository-owner instruction in the current task/Issue
2. `REQUIREMENTS.md`
3. `SPECIFICATION.md`
4. Accepted ADRs in `docs/ADR/`
5. `AGENTS.md`
6. Existing implementation details

If a security/privacy-sensitive conflict cannot be resolved from these sources, ask the repository owner rather than inventing the product decision. Track unresolved decisions in an Issue and continue independent work where possible.

## 3. Work unit policy

Every non-trivial change MUST map to a GitHub Issue.

Workflow:
1. Read Issue + relevant specs.
2. Confirm acceptance criteria.
3. Create/use issue branch.
4. Implement smallest complete scope.
5. Add/update tests.
6. Update documentation when behavior changes.
7. Run required checks.
8. Open/update PR referencing the Issue.
9. Wait for CI.
10. Wait for both Codex and Claude review of the current HEAD.
11. Fix actionable blocking findings and respond to review threads.
12. Re-run checks/reviews after material HEAD changes.
13. Merge only when all gates are satisfied.

## 4. Branch and merge rules

- NEVER commit directly to `main`.
- One Issue per feature/fix unit unless explicitly grouped.
- Preferred branches: `feat/<issue>-<slug>`, `fix/<issue>-<slug>`, `docs/<issue>-<slug>`, `chore/<issue>-<slug>`.
- PR mandatory.
- Codex and Claude MUST both cover the current PR HEAD before merge.
- Required CI must pass.
- No unresolved blocking review threads.
- Prefer squash merge.
- NEVER rewrite `main` history.

### Current trust model for review gates

Until Issue #4 (`Ruleset / 専用GitHub Appで自動レビューゲートを強制する`) is completed:
- Codex + Claude is a mandatory operational merge policy enforced by the owner/merge agent;
- same-repository write access is limited to trusted maintainers;
- untrusted/external contributors use fork PRs;
- ordinary `GITHUB_TOKEN` statuses/check names are not an unforgeable boundary against a malicious same-repository writer;
- the merge actor explicitly compares current HEAD SHA with the HEAD reviewed by both integrations;
- any new commit after review makes that review stale;
- stronger Ruleset/required-workflow/dedicated-issuer enforcement must be established before broadening same-repository write access.

## 5. Scope discipline

Do not implement unrequested nice-to-have features. Track them in `docs/proposals/` and/or an Issue with motivation, cost, privacy/security impact, and alternatives.

Refactors are allowed only when necessary for the current Issue or separately tracked.

## 6. Unknown requirements

When behavior is unspecified:
- do not guess security/privacy/biometric product intent;
- ask the repository owner when the decision blocks safe implementation;
- otherwise create/update a decision Issue;
- use the safest non-destructive temporary behavior if work must proceed;
- continue unrelated work.

## 7. Hardware-unavailable policy

Hardware unavailability MUST NOT block all software work.

Use mocks, synthetic/generated fixtures, dependency injection, virtual source adapters, and browser mocks where meaningful. Complete software-verifiable work and add exact real-hardware steps to `MANUAL_TEST.md`.

Suggested labels:
- `hardware-required`
- `webcam-required`
- `browser-camera-required`
- `server-required`
- `manual-test-required`

Never claim hardware/browser behavior was verified when it was not.

## 8. Definition of software-side done

As applicable:
- unit tests pass;
- backend/API integration tests pass;
- web typecheck/lint/tests pass;
- Camera Source mocks cover relevant 1–4 source topologies;
- local UVC logic tested without falsely claiming physical-device verification;
- Web Camera Node state/protocol tests pass with mocks;
- Docker build/Compose validation passes;
- core mock E2E passes;
- docs updated;
- security/privacy impact reviewed;
- remaining hardware/browser checks explicitly tracked.

## 9. Dependency and model license rules

Before adding a dependency/model:
1. verify active upstream source;
2. verify exact license and material transitive obligations;
3. justify it;
4. pin/lock appropriately;
5. record material dependency;
6. for ML, verify implementation code and weights/model artifacts separately.

Preferred licenses: Apache-2.0, MIT, BSD-2/3-Clause, or similarly permissive after review.

Blocked by default without explicit owner approval: AGPL, GPL where obligations conflict with distribution goals, SSPL, BSL/source-available/non-OSI terms, or ambiguous licensing.

YOLOX is only the initial person-detector evaluation candidate because its source code is Apache-2.0. Weight/model licensing still needs independent verification.

Owner face-verification models/weights require the same independent license review. Do not introduce an identity model merely because it is convenient.

## 10. Privacy invariants

Default product invariants:
- no developer-operated account service;
- no developer media/biometric storage;
- no telemetry/analytics/advertising/tracking;
- no developer relay for Slack;
- no hidden data upload;
- owner face verification is optional/local;
- no named non-owner face database in MVP;
- no cross-camera biometric re-identification in MVP;
- no automatic culprit/guilt determination.

Violating any invariant requires explicit owner approval plus updated requirements/privacy/security/ADR.

Automated Claude review may send PR/repository review context to Anthropic as development tooling. Contributors MUST NOT place user recordings, real-person monitoring media, biometric templates, secrets, or private infrastructure data in PRs.

## 11. Secret and sensitive-data handling

NEVER commit or log real:
- `.env` secrets;
- Slack webhook/token;
- Tailscale auth key;
- private keys/certificates/credentials;
- private deployment IP/hostname/SSID/Tailnet values;
- owner biometric templates/embeddings;
- recordings or real-person/real-environment monitoring media.

Use `.env.example`, obvious fake values, redaction, and browser/server secure credential storage appropriate to the component.

Repository fixtures MUST be synthetic/generated only. Real-device/manual-test media stays local and is not attached to PRs even with consent.

If real secrets are discovered in repository history, treat it as a security incident and stop normal work.

## 12. Personal-data rules

Public examples use synthetic values. Do not insert the repository owner's legal name, student ID, school/lab details, exact physical location, private server values, Tailnet, Slack workspace, or personal email unless explicitly requested for a specific public purpose.

## 13. Destructive-operation policy

Agents may use Ubuntu, Docker, systemd, Tailscale commands, and `sudo` when required, but without explicit owner approval NEVER:
- run broad `rm -rf`;
- wipe/format disks;
- delete all recordings/database/tables;
- destroy data-bearing Docker volumes;
- disable firewall globally or expose service publicly;
- modify Tailscale ACLs;
- rotate unrelated credentials;
- reset networking;
- change SSH rules that can lock out owner;
- force-push shared/protected branches;
- rewrite history.

Temporary deletion uses verified exact project/temp paths only.

## 14. Database/API changes

DB/API may evolve before 1.0. Use migrations, preserve data where reasonable, document breaking changes, test migrations, version public routes, update typed schemas/clients, and avoid destructive migration by default.

Camera schema MUST be collection-based (`camera_sources`, profile bindings, capabilities), never fixed columns such as `front_camera`/`rear_camera`.

## 15. Camera Source invariants

MVP source types:
- local UVC/V4L2;
- remote Web Camera Node.

Rules:
- system works with one active source;
- default active-source limit is four;
- do not hard-code exactly two/four cameras throughout internals;
- source type and semantic role are separate;
- detection profiles are configured per source;
- local UVC identity must not rely solely on `/dev/videoN` ordering;
- local discovery does not auto-enable a camera;
- remote Web Camera Node requires secure browser context and pairing;
- browser node must not gain privileged admin API rights simply because it is paired;
- audio defaults OFF independently per source;
- no motion-triggered automatic torch/flash/screen-light behavior;
- browser background capture is not guaranteed;
- browser-local storage is not guaranteed critical-evidence storage.

Read `REQUIREMENTS.md` / `SPECIFICATION.md` before camera work.

## 16. Web Camera Node rules

- use standard browser camera APIs in a secure context;
- no native iOS/App Store dependency for MVP;
- do not bypass TLS/browser security as normal setup;
- camera/microphone permissions must be explicit;
- monitoring/connection state visible;
- Screen Wake Lock may be best-effort only;
- handle `track ended`, permission revocation, network loss, page reload, suspension/reconnect;
- never claim continuous capture after browser/OS termination or device shutdown;
- no automatic torch control.

## 17. Detection rules

- person detection != server movement proof;
- compensate camera-global motion where relevant;
- handle occlusion/temporal persistence;
- benchmark/document thresholds;
- confidence is not certainty;
- low-light/poor-quality frames gate dependent inference;
- insufficient quality -> `unknown`/unavailable, not forced owner match/non-match;
- owner verification is 1:1 against one explicitly enrolled owner;
- do not create named non-owner identities;
- anonymous tracks are scope-limited and must not silently become cross-camera biometric re-identification;
- event timeline reports observations, not guilt/culpability.

## 18. Presence rules

Initial inferred states:
- `PRESENT`;
- `PROBABLY_PRESENT`;
- `ABSENT`;
- `UNKNOWN`.

Manual override has precedence.

Only explicit/high-confidence `PRESENT` suppresses ordinary occupancy-related automation by default. `PROBABLY_PRESENT`/`UNKNOWN` must not silently disarm security automation.

Presence NEVER disables confirmed server-movement or camera-tamper detection/evidence handling.

## 19. Media and storage rules

- live and durable recording should not share an unnecessary single point of failure;
- remote durable uploads retry, are idempotent, integrity-checked, and source-attributed;
- local UVC uses the same logical recording/event model;
- no `rear.mp4/front.mp4` contract; use source IDs;
- manual recording max 20 minutes by default;
- automatic event target 30s pre + 120s post, max 20 min;
- auto-cleanup never auto-deletes starred recordings;
- recording retention default 20 days;
- audit retention default 90 days;
- configured capacity plus actual filesystem free space control admission;
- preserve hard filesystem safety reserve;
- storage pressure/hard stop are explicit states;
- bulk delete requires dedicated tests.

## 20. Testing

Minimum categories as applicable:
- unit;
- API integration;
- web component/integration;
- Camera Source 1–4 topology;
- UVC stable-device/reconnect;
- browser pairing/reconnect;
- media retry/idempotency;
- multi-source event manifests;
- retention/storage pressure;
- owner authorization;
- person/motion/ROI/tamper fixtures;
- low-light gating;
- owner-verification match/no-match/unknown using synthetic/generated or appropriately licensed benchmark assets;
- anonymous tracking/entrance crossing;
- presence/timeline;
- migrations;
- mock E2E.

Real hardware/browser checks live in `MANUAL_TEST.md`.

## 21. CI

CI should eventually cover:
- formatting/lint;
- Python static checks/tests;
- React/TypeScript typecheck/lint/tests/build;
- Docker/Compose validation;
- secret scan;
- dependency/model license checks where automatable;
- synthetic fixture privacy guardrails.

There is no native-iOS CI requirement in MVP.

## 22. Logging

Structured logs MUST NOT contain raw pairing/auth tokens, Slack secrets, private keys, owner biometric templates, raw media/audio content, sensitive headers, or unnecessary face crops.

Use stable event/error codes and redact sensitive values.

## 23. User-facing language

Primary UI language is Japanese with localization-friendly architecture. Do not bind logic to Japanese string comparisons.

Repository owner-facing Issue/PR titles/bodies, agent-authored PR comments, review responses, and merge summaries should be primarily Japanese except technical identifiers/quoted upstream text.

## 24. Notifications

Avoid alert fatigue.

Default Slack:
- immediate: confirmed server movement / camera tamper;
- daily parent summary: 23:00 default;
- event details/thumbnails: thread replies where configured;
- ordinary person/motion/entry: summarized, not individual main-channel alerts.

Frequency increases require explicit acceptance criteria.

## 25. Automated review merge policy

The owner requires two independent automated review passes: **Codex and Claude**.

Agent MUST:
- wait for Codex review of current PR HEAD;
- wait for Claude review of current PR HEAD;
- read both findings;
- fix actionable `重大` / `重要` findings or explicitly document non-applicability;
- respond/resolve relevant threads;
- rerun checks and both reviews after material HEAD changes;
- verify no unresolved blocking findings before merge.

Until Issue #4 completes, current-HEAD verification by the merge actor enforces this policy. If either integration is unavailable/failing/missing current-HEAD review, DO NOT merge.

## 26. Commit/PR quality

Commits: concise, no secrets, no unrelated formatting floods.

PR body should cover Issue link, what/why, tests, security/privacy/biometric impact, hardware/browser test need, limitations, Codex status, Claude status.

PR screenshots/media must be synthetic/generated/demo only. Never attach real monitoring/real-person/real-environment media.

## 27. Documentation discipline

When behavior changes, update the source of truth:
- `REQUIREMENTS.md` — product decisions;
- `SPECIFICATION.md` — technical contracts;
- ADR — meaningful architecture decisions;
- `MANUAL_TEST.md` — real-hardware/browser validation;
- `PRIVACY.md` / `SECURITY.md` — data/security behavior;
- `docs/INITIAL_ISSUES.md` / `ROADMAP.md` — implementation sequence.

## 28. Stop conditions

Stop and request explicit owner decision before:
- developer-hosted cloud;
- analytics/ads/payment;
- project license change;
- incompatible/uncertain dependency/model license;
- default public Internet exposure;
- destructive migration;
- weakening owner authorization/pairing;
- deleting protected/starred evidence automatically;
- collecting data the developer previously did not receive;
- enrolling/naming non-owner faces;
- adding cross-camera biometric re-identification;
- adding automatic culprit/guilt inference;
- changing browser-local buffering into a claimed durable independent evidence guarantee;
- introducing a native mobile/App Store requirement into MVP.
