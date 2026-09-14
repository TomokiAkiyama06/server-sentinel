# Contributing

Thank you for contributing to ServerSentinel.

## Before coding

Read:

1. `REQUIREMENTS.md`
2. `SPECIFICATION.md`
3. `AGENTS.md`
4. `SECURITY.md`
5. `PRIVACY.md`
6. `CLAUDE.md` if present
7. `docs/THIRD_PARTY_POLICY.md`
8. `docs/CLAUDE_REVIEW_SETUP.md`

## Workflow

- Create or reference an Issue.
- Do not work directly on `main`.
- Create a focused branch.
- Add tests.
- Open a PR.
- Wait for CI and both Codex + Claude review of the current PR HEAD.
- Resolve blocking review findings before merge.
- If the PR HEAD changes materially after review, request both reviews again.

Until Issue #4 establishes hardened repository-level review enforcement, same-repository write access is reserved for trusted maintainers. External/untrusted contributors should submit from a fork.

## Privacy

Never attach or commit:
- real monitoring footage;
- non-consenting person images;
- private server IPs/hostnames;
- private Tailnet names;
- Slack webhook URLs;
- credentials or tokens;
- private deployment configuration.

Use synthetic fixtures.

Automated Claude PR review sends the fixed PR diff and repository context needed for review to Anthropic's Claude service. This is a development-process integration, not ServerSentinel product telemetry. Do not include user monitoring data or secrets in PR content.

## New dependencies

Include in the PR:
- package/project URL;
- exact license;
- reason;
- alternatives considered;
- whether model weights have a separate license.

## Architecture changes

Add an ADR for changes that affect:
- media transport;
- authentication/pairing;
- persistent storage;
- privacy model;
- license strategy;
- remote-access model;
- cross-component protocol.

## Hardware changes

If verification requires hardware you do not have:
- finish mockable work;
- add to `MANUAL_TEST.md`;
- open a hardware/manual-test Issue.