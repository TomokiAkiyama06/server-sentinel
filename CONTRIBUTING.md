# Contributing

Thank you for contributing to ServerSentinel.

## Before coding

Read:

1. `REQUIREMENTS.md`
2. `SPECIFICATION.md`
3. `AGENTS.md`
4. `SECURITY.md`
5. `PRIVACY.md`
6. `CLAUDE.md`
7. `docs/THIRD_PARTY_POLICY.md`
8. `docs/CLAUDE_REVIEW_SETUP.md`

## Workflow

- Create or reference an Issue.
- Do not work directly on `main`.
- Create a focused branch.
- Add tests.
- Open a PR.
- Record the current 40-character PR HEAD and base SHAs in the review request and PR review record. Request both Codex + Claude to review that fixed HEAD/base diff, and wait for CI.
- At review completion and immediately before merge, compare both reviewed SHAs with the current PR HEAD/base. For Codex, verify `Reviewed commit` plus the base recorded in its pinned review request; HEAD alone is insufficient.
- Resolve blocking review findings before merge.
- If either HEAD or base changes after the review request, request both reviews again on the latest fixed HEAD/base diff, including a base-only change. A review without verifiable base provenance is not a final approval.

Until Issue #4 establishes hardened repository-level review enforcement, same-repository write access is reserved for trusted maintainers. External/untrusted contributors should submit from a fork.

## Current architecture assumptions

Do not reintroduce the superseded iOS-first design without an explicit owner/ADR decision.

MVP assumptions:
- 1–4 active Camera Sources;
- source types `local_uvc` and `remote_agent`;
- no fixed front/rear camera pair;
- remote Linux Camera Source runs through `media-capture-agent`; phone/Mac/desktop browsers are viewer clients;
- no native App Store client required;
- audio capture is outside the MVP; `media-capture-agent` does not open microphones;
- no automatic motion/low-light torch/light activation;
- optional owner-only face verification;
- no named non-owner face database;
- no cross-camera biometric re-identification or culprit inference in MVP.

## Privacy

Never attach or commit:
- real monitoring footage;
- any real-person image/video/audio fixture, even with consent;
- any real-environment monitoring media fixture;
- owner face template/embedding;
- private server IPs/hostnames;
- private Tailnet/SSID names;
- Slack webhook URLs;
- credentials/tokens;
- private deployment configuration.

Repository fixtures must be synthetic/generated. Real-device/manual tests involving real people/environments keep media artifacts local and do not attach/commit them.

Automated Claude review sends the fixed PR diff and repository context needed for review to Anthropic's Claude service. This is development tooling, not product telemetry. Do not include user monitoring data or secrets in PR content.

## New dependencies / AI models

Include in the PR:
- package/model project URL;
- exact source-code license;
- exact model/weight license where separate;
- reason;
- alternatives considered;
- security/privacy implications.

## Architecture changes

Add/update an ADR for material changes affecting:
- Camera Source model/source types;
- media transport;
- authentication/pairing;
- persistent storage;
- biometric/identity behavior;
- privacy model;
- license strategy;
- remote-access model;
- cross-component protocol.

## Hardware/browser changes

If verification requires hardware/browser conditions you do not have:
- finish mockable work;
- add exact checks to `MANUAL_TEST.md`;
- open/use a hardware/manual-test Issue;
- never claim the unperformed real-device check passed.
