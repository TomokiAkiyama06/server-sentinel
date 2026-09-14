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

If a conflict cannot be resolved safely:
- create/update a GitHub Issue describing the ambiguity;
- do not invent a product decision;
- continue unrelated work that is not blocked.

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
10. Wait for the configured automated review.
11. Resolve all actionable review findings.
12. Re-run checks after fixes.
13. Merge only when all merge gates are satisfied.

## 4. Branch and merge rules

- NEVER commit directly to `main`.
- One Issue per feature/fix unit unless explicitly grouped.
- Preferred branch names:
  - `feat/<issue>-<slug>`
  - `fix/<issue>-<slug>`
  - `docs/<issue>-<slug>`
  - `chore/<issue>-<slug>`
- PR is mandatory.
- Automated review MUST be present before merge.
- All required CI checks MUST pass.
- No unresolved blocking review threads.
- Agent may merge after all gates pass.
- Prefer squash merge unless repository policy later specifies otherwise.
- NEVER rewrite `main` history.

## 5. Scope discipline

Agents MUST NOT implement features merely because they appear useful.

If a useful unrequested feature is discovered:
1. create a proposal in `docs/proposals/` and/or GitHub Issue;
2. explain motivation, cost, risks, privacy impact, and alternatives;
3. continue the requested scope without silently adding the feature.

Refactors are allowed only when necessary for the Issue or when separately tracked.

## 6. Unknown requirements

When behavior is unspecified:

- Do not guess user intent for security/privacy-sensitive behavior.
- Create an Issue marked as a decision/question.
- Use the safest non-destructive temporary behavior if implementation must proceed.
- Add TODO references to the Issue only where needed.
- Continue other independent tasks.

## 7. Hardware-unavailable policy

Lack of a real iPhone/Ubuntu target MUST NOT become an excuse to stop all work.

When hardware is required:
- create/use mocks, fixtures, dependency injection, simulators where meaningful;
- complete all software-verifiable work;
- add the exact real-device steps to `MANUAL_TEST.md`;
- create an Issue with the appropriate hardware label.

Expected labels:
- `hardware-required`
- `iphone-required`
- `server-required`
- `manual-test-required`

Do not claim hardware behavior was verified when it was not.

## 8. Definition of software-side done

Before marking an implementation Issue complete, as applicable:

- unit tests pass;
- backend/API integration tests pass;
- web typecheck/lint/tests pass;
- iOS testable non-hardware logic passes;
- Docker build/Compose validation passes;
- core mock E2E passes;
- documentation updated;
- security/privacy implications reviewed;
- hardware items moved to explicit manual-test tasks.

## 9. Dependency rules

OSS dependencies may be added when justified.

Before adding any dependency:
1. verify active upstream source;
2. verify exact license;
3. verify transitive/license implications;
4. explain why stdlib/existing dependencies are insufficient;
5. pin/lock appropriately;
6. record material dependencies.

Preferred licenses:
- Apache-2.0
- MIT
- BSD-2-Clause / BSD-3-Clause
- similarly permissive licenses after review.

Blocked by default without explicit owner approval:
- AGPL
- GPL when linkage/distribution obligations could affect this project
- SSPL
- Business Source License
- source-available/non-OSI terms
- unknown/ambiguous licenses

### Model/weight rule

Model code license and model-weight license MUST be reviewed independently.

Do not assume pretrained weights inherit the repository license.

### Detection-model licensing rule

The initial person-detector evaluation candidate is **YOLOX**, because its source implementation is Apache-2.0. This is not blanket approval for arbitrary pretrained weights: the exact weight/model license MUST be verified and documented independently before bundling or redistribution.

Do NOT introduce Ultralytics YOLO packages/models, or any other AGPL/GPL/unclear-licensed detector, without explicit owner approval and a documented license decision. The repository remains Apache-2.0 by default.

The detector architecture MUST remain pluggable so a different permissively licensed implementation/model can replace YOLOX if benchmarks or licensing require it.

## 10. Privacy rules

The following are product invariants:

- no developer-operated user account system;
- no developer video/audio storage;
- no telemetry;
- no analytics;
- no advertising SDK;
- no tracking SDK;
- no developer relay for Slack;
- no hidden data upload.

Any change that would violate an invariant requires an explicit architecture decision and owner approval before implementation.

## 11. Secret handling

NEVER commit or log:
- `.env`
- Slack webhook/token
- Tailscale auth key
- Apple signing certificates
- `.p12`
- `.mobileprovision`
- private keys
- real access tokens
- real Wi-Fi SSIDs when private
- private hostnames
- real deployment IPs
- recordings
- real person images used for monitoring
- Apple device identifiers if not explicitly intended for public documentation

Use:
- `.env.example`
- obvious fake example values
- iOS Keychain for persistent Camera Node credentials
- redaction in logs

Secrets discovered in repository history are a security incident. Stop normal work and report.

## 12. Personal-data rules

Public examples must use synthetic values.

Do not insert the repository owner's:
- legal name;
- student ID;
- school details;
- physical location;
- private server IP;
- Tailnet name;
- Slack workspace;
- personal email unless explicitly requested.

## 13. Destructive-operation policy

Agents are allowed to use the Ubuntu environment, Docker, systemd, Tailscale commands, and `sudo` when the task requires it, but destructive actions are tightly restricted.

Without explicit owner approval, NEVER:

- run broad `rm -rf` operations;
- wipe disks/partitions;
- format filesystems;
- delete all recordings;
- delete the SQLite database;
- drop all tables;
- destroy Docker volumes containing user data;
- disable firewall globally;
- expose the service publicly;
- modify Tailscale ACLs;
- rotate/revoke unrelated credentials;
- reset network configuration;
- change SSH access rules in a way that could lock out the owner;
- force-push protected/shared branches;
- rewrite repository history.

When deleting project-owned temporary files:
- use exact paths;
- verify path is inside the project/temp area;
- log the intended scope before executing.

## 14. Database changes

Agents MAY change the DB schema/API when needed.

Requirements:
- use migrations;
- preserve existing user data where reasonable;
- document breaking changes;
- add migration tests;
- no destructive migration by default;
- provide rollback/recovery guidance for risky changes.

## 15. API changes

APIs may evolve before 1.0, but:
- version public routes;
- update typed schemas;
- update tests;
- update iOS/web clients in the same PR or provide compatibility;
- document any temporary incompatibility.

## 16. Security requirements

Default stance:
- no public Internet listener exposure;
- Tailscale recommended for remote use;
- pairing tokens are one-time and short-lived;
- no arbitrary shell execution from API;
- no user-controlled raw filesystem access;
- sanitize upload names;
- validate media size/content;
- rate-limit pairing/auth-sensitive endpoints;
- secrets redacted.

Read `SECURITY.md` before implementing networking/pairing/storage.

## 17. Logging rules

Logs MUST be structured where practical and MUST NOT contain:
- raw pairing token;
- auth token;
- Slack secret;
- media content;
- microphone content;
- private key;
- unredacted sensitive headers.

Use stable event/error codes so the UI can show Japanese messages while logs remain machine-readable.

## 18. User-facing language

Primary intended UI language: Japanese.

Architecture should allow localization. Do not hard-wire operational logic to Japanese string comparisons.

Errors shown to the owner should be understandable Japanese by default.

## 19. Notifications

Do not create noisy immediate alerts.

Default Slack behavior:
- immediate: confirmed server movement, confirmed camera tamper;
- daily parent summary at 23:00 default;
- event thumbnails/details in thread replies;
- normal person/motion events summarized, not individually blasted to the main channel.

A change that increases notification frequency needs explicit Issue acceptance criteria.

## 20. iOS-specific rules

- Check capabilities before MultiCam.
- Do not assume iPhone 14 is the only device.
- Audio default OFF.
- Monitoring/recording state must remain visible.
- Do not claim capture can survive app kill/device shutdown.
- Use Keychain for long-lived credentials.
- Abstract hardware APIs behind protocols so logic is testable.
- Preserve/recover screen-brightness/idle state carefully.
- Thermal state must be observable and tested.
- Heavy CV inference belongs on Ubuntu unless a benchmark proves a local operation is justified.

## 21. Detection-specific rules

- Person detection and server movement are separate problems.
- Generic person/object detection must not be treated as proof the server moved.
- Camera global movement must not be confused with server movement.
- Occlusion must be considered.
- Thresholds must be benchmarked and documented.
- Confidence values are not certainty; UI language must not overclaim.

## 22. Media rules

- Live viewing and durable recording must not share a single point of failure unnecessarily.
- Evidence upload must retry.
- Chunk uploads must be idempotent.
- Use checksums/integrity metadata.
- Manual recording has a 20-minute maximum by default.
- Automatic events use 30s pre + 120s post, max 20 min, unless settings/spec later change.

## 23. Retention rules

Automatic cleanup:
- may delete unstarred data;
- MUST NOT auto-delete starred recordings;
- audit retention defaults to 90 days;
- recording retention defaults to 20 days;
- capacity ceiling configurable;
- preserve a disk safety margin.

Any bulk-delete implementation requires dedicated tests.

## 24. Testing rules

Minimum testing categories:
- unit;
- API integration;
- web component/integration;
- mock E2E;
- media retry/idempotency;
- retention;
- pairing expiry;
- reconnect;
- detection fixture tests;
- permission/capability logic;
- migration tests.

Real hardware:
- documented in `MANUAL_TEST.md`.

Do not use real non-consenting person recordings as repository fixtures.

## 25. CI requirements

CI should eventually run:
- formatting/lint;
- Python type/static checks;
- Python tests;
- React typecheck/lint/tests/build;
- Docker build;
- Compose config validation;
- secret scan;
- dependency/license checks where practical;
- iOS build/test on macOS runner where practical.

If CI is unavailable for a platform, document the gap.

## 26. Automated review merge gate

The owner uses an automated review.

Agent MUST:
- wait until automated review is posted;
- read it;
- fix actionable issues;
- respond/resolve as appropriate;
- re-run checks.

No "review hasn't arrived yet, so merge anyway."

## 27. Commit/PR quality

Commits:
- concise imperative messages;
- no generated secrets;
- no unrelated formatting floods.

PR body should include:
- Issue link;
- what changed;
- why;
- tests run;
- screenshots for UI changes where useful;
- security/privacy impact;
- hardware test needed? yes/no;
- known limitations.

## 28. App Store constraints

Do not implement hidden surveillance behavior.

The app must:
- explain permissions;
- show monitoring state;
- support review/demo flow;
- keep privacy documentation accurate;
- avoid code paths that differ secretly only for review.

## 29. Documentation discipline

When behavior changes, update:
- REQUIREMENTS if product decision changed;
- SPECIFICATION if technical contract changed;
- ADR for meaningful architecture choice;
- MANUAL_TEST for real-device validation;
- PRIVACY/SECURITY if data/security behavior changed.

## 30. Stop conditions

Stop and request owner decision before:
- introducing developer-hosted cloud;
- adding analytics/ads;
- adding payment;
- changing project license;
- choosing a dependency with incompatible/uncertain license;
- exposing a public Internet service by default;
- destructive migration;
- weakening pairing/authentication;
- deleting protected recordings;
- collecting data the developer previously did not receive.
