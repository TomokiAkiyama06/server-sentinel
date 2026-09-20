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
- `0004-capture-node-bootstrap-trust.md` — Proposed (#13). Makes Owner-controlled initial Main trust, single-use enrollment, revocation and real TLS negative tests reviewable; no runtime authentication decision is activated.

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
