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
- `0003-owner-authentication-and-trusted-proxy.md` — Proposed, awaiting Owner decision. Specifies local Owner bootstrap/recovery, trusted proxy/session boundaries, the reserved human-listener hostname, and an executable synthetic design model for Issue #6. It does not enable human access or close #6.
- `0004-shared-tailnet-account-authorization.md` — Proposed, awaiting Owner decision. Records the shared research-room Tailscale account, per-person ServerSentinel credentials (WebAuthn/passkey) with required authenticator user verification, and what device approval and network reachability do not prove.

`0003` and `0004` are a pair for Issue #6. `0004` proposes the deployment constraint and the credential mechanism, which is the decision `0003` defers; `0003` proposes the boundary around it — bootstrap and recovery mechanics, session lifetimes, the step-up freshness window and identity-header handling — and neither adopts the other's parameters. Issue #6 closes when both are accepted and Issue #10 implements them.

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
