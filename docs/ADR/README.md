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

`0003` is reserved for the Owner-authentication / trusted-proxy boundary record of Issue #6, which arrives with its own pull request. The gap below is intentional until that record lands.

- `0001-project-foundations.md` — Accepted. Defines the current heterogeneous Camera Source foundation around `local_uvc` + `remote_agent` and rejects the earlier iOS/browser-camera-first bootstrap concept.
- `0002-remote-agent-buffer-and-viewer-access.md` — Accepted. Defines the remote Agent disk ring buffer, protected incident behavior, live-view stability priority, and invited-viewer access model.
- `0004-shared-tailnet-account-authorization.md` — Accepted. Records the shared research-room Tailscale account, per-person ServerSentinel credentials (WebAuthn/passkey) with required authenticator user verification, and what device approval and network reachability do not prove. The owner-authentication and trusted-proxy boundary it sits on belongs to the reserved `0003` record above.

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
