# Contributing

Thank you for contributing to ServerSentinel.

## Before coding

Read:

1. `REQUIREMENTS.md`
2. `SPECIFICATION.md`
3. `AGENTS.md`
4. `SECURITY.md`
5. `docs/THIRD_PARTY_POLICY.md`

## Workflow

- Create or reference an Issue.
- Do not work directly on `main`.
- Create a focused branch.
- Add tests.
- Open a PR.
- Wait for CI and automated review.
- Resolve review findings before merge.

## Privacy

Never attach:
- real monitoring footage;
- non-consenting person images;
- private server IPs;
- private Tailnet names;
- Slack webhook URLs;
- credentials.

Use synthetic fixtures.

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
