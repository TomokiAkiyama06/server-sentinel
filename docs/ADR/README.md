# Architecture Decision Records

Use ADRs for decisions that materially affect:
- protocol;
- storage;
- privacy/biometrics;
- security;
- licensing;
- Camera Source architecture;
- media transport;
- cross-component architecture.

## Current ADRs

- `0001-project-foundations.md` — Accepted. Defines the current heterogeneous Camera Source foundation around `local_uvc` + `remote_agent` and rejects the earlier iOS/browser-camera-first bootstrap concept.
- `0002-remote-agent-buffer-and-viewer-access.md` — Accepted. Defines the remote Agent disk ring buffer, protected incident behavior, live-view stability priority, and invited-viewer access model.
- `0003-owner-authentication-and-trusted-proxy.md` — Proposed, awaiting Owner decision. Specifies local Owner bootstrap/recovery, trusted proxy/session boundaries, and an executable synthetic design model for Issue #6. It does not enable human access or close #6.
- `0005-native-main-server-release-lifecycle.md` — Accepted. Makes the versioned native release/systemd lifecycle the only implemented and advertised Main Server deployment path, and records its privileged-installer, artifact-hash, external-runtime and administrator-owned-configuration assumptions.

ADR-0004 is reserved for the shared Tailnet account authorization decision,
which arrives in its own pull request. Do not reuse that number, and do not
link to its file until it is merged.

## Template

```markdown
# ADR-NNNN: Title

Status: Proposed | Accepted | Superseded

## Context

## Decision

## Alternatives

## Consequences

## Validation

## Follow-up
```
