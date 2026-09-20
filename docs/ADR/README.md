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
- `0004-shared-tailnet-account-authorization.md` — Accepted. Records the shared research-room Tailscale account, per-person ServerSentinel credentials (WebAuthn/passkey) with required authenticator user verification, and what device approval and network reachability do not prove. It sits on the owner-authentication and trusted-proxy boundary of `0003`.

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
