# AGENTS.md — Mandatory Rules for Coding Agents

This file is normative. Agents working in this repository MUST follow it unless the repository owner explicitly overrides a rule for a specific task.

## 1. Project mission

Build ServerSentinel as a free, self-hosted, privacy-first server security monitor consisting of:
- a native iOS Camera Node;
- an Ubuntu ServerSentinel backend;
- a React dashboard.

The developer must not become a custodian of users' recordings or operational data.

## 2. Authoritative documents

Priority order when requirements conflict:

1. Explicit instructions from the repository owner in the current task/Issue
2. `REQUIREMENTS.md`
3. `SPECIFICATION.md`
4. Accepted ADRs in `docs/ADR/`
5. `AGENTS.md`
6. Existing implementation details

If a conflict cannot be resolved safely, create/update a GitHub Issue, do not invent a product decision, and continue unrelated work.

## 3. Work unit policy

Every non-trivial change MUST map to a GitHub Issue.

Agent workflow:
1. Read the Issue and relevant specs.
2. Confirm acceptance criteria.
3. Create/use a feature branch.
4. Implement the smallest complete scope.
5. Add/update tests.
6. Update documentation if behavior changed.
7. Run required checks.
8. Open a PR referencing the Issue.
9. Wait for CI.
10. Wait for both configured automated reviews: Codex and Claude.
11. Resolve actionable findings from both reviews.
12. Re-run checks and re-request both reviews after material HEAD changes.
13. Merge only when all merge gates are satisfied.

## 4. Branch and merge rules

- NEVER commit directly to `main`.
- One Issue per feature/fix unit unless explicitly grouped.
- Preferred branches: `feat/<issue>-<slug>`, `fix/<issue>-<slug>`, `docs/<issue>-<slug>`, `chore/<issue>-<slug>`.
- PR is mandatory.
- Codex and Claude review MUST both cover the current PR HEAD before merge.
- All required CI checks MUST pass.
- No unresolved blocking review threads.
- Prefer squash merge.
- NEVER rewrite `main` history.

### Current trust model for review gates

Until Issue #4 (`Ruleset / 専用GitHub Appで自動レビューゲートを強制する`) is completed:

- the Codex + Claude requirement is a **mandatory operational merge policy**, enforced by the repository owner / merge agent;
- same-repository write access MUST be limited to trusted maintainers;
- untrusted/external contributors MUST use fork PRs;
- a workflow job name, commit status, or check run emitted with an ordinary repository `GITHUB_TOKEN` MUST NOT be treated as an unforgeable security boundary against a malicious or compromised same-repository writer;
- the merge actor MUST explicitly compare the PR current HEAD SHA with the HEAD reviewed by Codex and Claude before merge;
- if a new commit is added after either review, that review is stale and MUST be rerun;
- before granting write access to additional collaborators, Issue #4 MUST establish stronger repository-level enforcement such as Ruleset Required workflows or a dedicated issuer/GitHub App that a PR branch cannot impersonate.

This clarification does **not** weaken the requirement to obtain both reviews. It defines who enforces it until hardened repository-level enforcement exists.

## 5. Scope discipline

Do not implement unrequested nice-to-have features. Track them in `docs/proposals/` and/or an Issue with motivation, cost, risks, privacy impact, and alternatives.

Refactors are allowed only when necessary for the current Issue or separately tracked.

## 6. Unknown requirements

When behavior is unspecified:
- do not guess security/privacy-sensitive product intent;
- create a decision/question Issue;
- use the safest non-destructive temporary behavior if implementation must proceed;
- continue independent work.

## 7. Hardware-unavailable policy

Hardware unavailability MUST NOT block all software work.

Use mocks, fixtures, dependency injection, and simulators where meaningful. Complete software-verifiable work, add exact real-device steps to `MANUAL_TEST.md`, and track hardware work with appropriate labels:
- `hardware-required`
- `iphone-required`
- `server-required`
- `manual-test-required`

Never claim hardware behavior was verified when it was not.

## 8. Definition of software-side done

As applicable before closing an implementation Issue:
- unit tests pass;
- backend/API integration tests pass;
- web typecheck/lint/tests pass;
- iOS non-hardware logic tests pass;
- Docker build/Compose validation passes;
- core mock E2E passes;
- docs are updated;
- security/privacy implications are reviewed;
- hardware-only checks are explicit manual-test tasks.

## 9. Dependency and model license rules

Before adding a dependency:
1. verify active upstream source;
2. verify exact license and relevant transitive obligations;
3. justify the dependency;
4. pin/lock appropriately;
5. record material dependencies.

Preferred: Apache-2.0, MIT, BSD-2/3-Clause, similarly permissive licenses after review.

Blocked by default without explicit owner approval: AGPL, GPL where obligations could affect distribution, SSPL, BSL/source-available/non-OSI terms, unknown/ambiguous licenses.

Model code and model weights MUST be reviewed separately.

The initial person-detector evaluation candidate is **YOLOX** because its source implementation is Apache-2.0. Exact pretrained weight/model licenses MUST be independently verified before bundling or redistribution.

Do NOT introduce Ultralytics YOLO or other AGPL/GPL/unclear-licensed detector packages/models without explicit owner approval and a documented license decision. The detector interface MUST remain pluggable.

## 10. Privacy invariants

Default product invariants:
- no developer-operated user account service;
- no developer video/audio storage;
- no telemetry;
- no analytics;
- no advertising/tracking SDK;
- no developer relay for Slack;
- no hidden data upload.

Violating an invariant requires an explicit architecture decision and owner approval.

Development tooling is separate from product telemetry: automated Claude review may send PR diff/repository review context to Anthropic as documented in `docs/CLAUDE_REVIEW_SETUP.md`. Contributors MUST NOT place user recordings, real monitoring images, secrets, or private infrastructure data in PRs.

## 11. Secret handling

NEVER commit or log real:
- `.env`;
- Slack webhook/token;
- Tailscale auth key;
- Apple signing certificates, `.p12`, `.mobileprovision`;
- private keys or access tokens;
- private Wi-Fi SSIDs/hostnames/deployment IPs;
- recordings or real person monitoring images;
- Apple device identifiers unless explicitly intended for public documentation.

Use `.env.example`, obvious fake values, iOS Keychain for persistent Camera Node credentials, and redaction in logs.

Secrets discovered in repository history are a security incident. Stop normal work and report.

## 12. Personal-data rules

Public examples must use synthetic values. Do not insert the repository owner's legal name, student ID, school details, physical location, private server IP, Tailnet, Slack workspace, or personal email unless explicitly requested.

## 13. Destructive-operation policy

Agents may use Ubuntu, Docker, systemd, Tailscale commands, and `sudo` when required, but without explicit owner approval NEVER:
- run broad `rm -rf`;
- wipe/format disks;
- delete all recordings/database/tables;
- destroy data-bearing Docker volumes;
- disable firewall globally or expose the service publicly;
- modify Tailscale ACLs;
- rotate unrelated credentials;
- reset networking;
- change SSH rules that can lock out the owner;
- force-push shared/protected branches;
- rewrite history.

Temporary-file deletion must use verified exact project/temp paths.

## 14. Database/API changes

DB schema/API may evolve before 1.0. Use migrations, preserve data where reasonable, document breaking changes, test migrations, version public routes, update typed schemas/tests/clients, and avoid destructive migration by default.

## 15. Security defaults

- no public Internet listener exposure by default;
- Tailscale recommended for reachability, but Tailnet membership alone is not deployment-owner authorization;
- one-time short-lived pairing tokens;
- no arbitrary shell execution from API;
- no user-controlled raw filesystem paths;
- sanitize upload names and validate media size/content;
- rate-limit pairing/auth-sensitive endpoints;
- redact secrets.

Read `SECURITY.md` before networking/pairing/storage work.

## 16. Logging

Logs should be structured and MUST NOT contain raw pairing/auth tokens, Slack secrets, media/microphone content, private keys, or sensitive headers. Use stable event/error codes.

## 17. User-facing language

Primary UI language is Japanese, with localization-friendly architecture. Do not bind logic to Japanese string comparisons. Owner-facing errors should be understandable Japanese by default.

Repository owner-facing Issue/PR content MUST also be primarily Japanese, except technical identifiers/quoted upstream text.

## 18. Notifications

Avoid alert fatigue. Default Slack behavior:
- immediate: confirmed server movement / camera tamper;
- daily parent summary: 23:00 default;
- event details/thumbnails: thread replies;
- ordinary person/motion: summarized, not individual main-channel alerts.

Frequency increases require explicit acceptance criteria.

## 19. iOS rules

- capability-check before MultiCam;
- do not hard-code iPhone 14 as the only device;
- audio default OFF;
- monitoring/recording state visible;
- do not claim survival after app kill/device shutdown;
- Keychain for long-lived credentials;
- hardware APIs behind protocols where practical;
- carefully restore brightness/idle state;
- thermal state observable/tested;
- heavy CV inference on Ubuntu unless benchmarks justify local work.

## 20. Detection rules

- person detection != server movement proof;
- compensate camera-global motion;
- consider occlusion;
- benchmark/document thresholds;
- confidence is not certainty; UI must not overclaim.

## 21. Media and storage rules

- live view and durable recording should not share an unnecessary single point of failure;
- uploads retry, are idempotent, and use integrity metadata;
- manual recording max 20 minutes by default;
- automatic event: 30s pre + 120s post, max 20 min unless spec changes;
- auto-cleanup may delete unstarred data but MUST NOT auto-delete starred recordings;
- recording retention defaults to 20 days;
- audit retention defaults to 90 days;
- capacity ceiling configurable;
- preserve filesystem safety margin;
- bulk-delete implementations require dedicated tests.

## 22. Testing

Minimum categories as applicable:
- unit;
- API integration;
- web component/integration;
- mock E2E;
- media retry/idempotency;
- retention;
- pairing expiry;
- reconnect;
- detection fixtures;
- permission/capability logic;
- migrations.

Real hardware checks live in `MANUAL_TEST.md`. Repository fixtures MUST be synthetic/generated only; do not commit real-person or real-environment monitoring media as fixtures, even with consent. Real-device/manual-test media must remain local and must not be attached to PRs or committed.

## 23. CI

CI should eventually cover formatting/lint, Python static checks/tests, React typecheck/lint/tests/build, Docker/Compose validation, secret scan, dependency/license checks, and iOS build/test where practical. Document unavailable platform checks.

## 24. Automated review merge policy

The owner requires two independent automated review passes: **Codex and Claude**.

Agent MUST:
- wait for Codex review of the current PR HEAD;
- wait for Claude review of the current PR HEAD;
- read both findings;
- fix all actionable `重大` / `重要` findings or explicitly document why a finding is not applicable;
- respond to/resolve relevant review threads;
- rerun checks and both reviews after material HEAD changes;
- verify no unresolved blocking finding before merge.

Until Issue #4 is complete, this policy is enforced by explicit current-HEAD verification by the merge actor, not by claiming an ordinary workflow status/check is unforgeable.

If either integration is unavailable, credentials are missing, it fails, or the current HEAD review has not completed, the PR MUST NOT be merged. Track the integration problem in an Issue and continue only independent work.

No "review hasn't arrived yet, so merge anyway."

## 25. Commit/PR quality

Commits: concise messages, no secrets, no unrelated formatting floods.

Issue titles/bodies, PR titles/bodies, agent-authored PR comments, review responses, and merge summaries should be primarily Japanese.

PR body should include Issue link, what/why, tests, screenshots where useful, security/privacy impact, hardware-test need, limitations, Codex status, Claude status.

## 26. App Store constraints

Do not implement hidden surveillance behavior. Explain permissions, show monitoring state, support Demo Mode/review flow, keep privacy docs accurate, and do not create secret review-only behavior.

## 27. Documentation discipline

When behavior changes, update the appropriate source of truth:
- `REQUIREMENTS.md` for product decisions;
- `SPECIFICATION.md` for technical contracts;
- ADR for meaningful architecture decisions;
- `MANUAL_TEST.md` for real-device validation;
- `PRIVACY.md` / `SECURITY.md` for data/security behavior.

## 28. Stop conditions

Stop and request owner decision before:
- developer-hosted cloud;
- analytics/ads/payment;
- project license change;
- incompatible/uncertain dependency license;
- default public Internet exposure;
- destructive migration;
- weakening pairing/authentication;
- deleting protected recordings;
- collecting data the developer previously did not receive.