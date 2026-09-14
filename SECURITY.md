# Security Policy

## Security philosophy

ServerSentinel is security-sensitive software. It handles camera/microphone streams, private network endpoints, physical-security events, and persistent recordings.

The safest default is:
- local/self-hosted;
- no developer cloud;
- no public Internet exposure;
- least privilege;
- explicit pairing;
- explicit deployment-owner authorization;
- no secrets in source control.

## Threat model

Primary threats:

1. Unauthorized remote dashboard access.
2. Unauthorized Camera Node pairing.
3. Theft of Ubuntu server.
4. Theft/tampering of Camera Node.
5. Secret leakage through logs/Git.
6. Malicious upload/path traversal.
7. Storage exhaustion.
8. Dependency/supply-chain compromise.
9. Slack/Tailscale token disclosure.
10. Misclassification causing false confidence.

Out of scope as a guaranteed prevention:
- physical destruction of hardware;
- attacker physically forcing iPhone shutdown;
- compromise of the user's Apple ID/Tailnet/admin host;
- nation-state level endpoint compromise.

## Development-repository trust boundary

The product threat model above is separate from the GitHub development workflow.

Until Issue #4 establishes hardened repository-level enforcement:
- same-repository write access is treated as a trusted-maintainer capability;
- external/untrusted contributors use fork PRs;
- Codex + Claude current-HEAD review is a mandatory merge policy enforced by the repository owner / merge agent;
- a status/check emitted with an ordinary repository `GITHUB_TOKEN` is not treated as an unforgeable boundary against a malicious or compromised same-repository writer;
- the merge actor explicitly verifies that both reviews cover the current PR HEAD;
- before additional write collaborators are granted access, a Ruleset Required workflow or dedicated GitHub App/issuer that PR branches cannot impersonate must be evaluated and configured under Issue #4.

Claude review receives PR diff/repository review context as part of the GitHub development process. Contributors must never place product-user recordings, real monitoring images, secrets, or private deployment data in PR content.

## Network defaults

- Do not recommend router port forwarding as normal setup.
- Remote dashboard access should use Tailscale.
- Camera/server traffic should remain local where possible.
- Bind services to the smallest necessary interfaces.
- Document firewall requirements instead of disabling firewalls.

## Deployment-owner authorization

Tailscale/Tailnet membership provides network reachability; it is **not by itself sufficient authorization** to operate a ServerSentinel deployment.

MVP requirements:
- privileged dashboard/API operations must verify the deployment owner, not merely that a request came from a Tailnet member;
- acceptable implementation families include a locally managed owner credential/session or an explicitly configured binding to a specific verified Tailscale identity/ACL;
- the exact mechanism must be locked by ADR before implementation;
- first-run bootstrap must establish the owner boundary before remote privileged access is enabled;
- destructive operations such as recording deletion, retention changes, pairing/revocation, Slack configuration, and security settings require owner authorization;
- owner credentials/bindings must support revocation or recovery without a developer-operated account system;
- do not trust identity headers forwarded by arbitrary clients; any proxy-derived identity must be accepted only from a verified trusted proxy/path.

## Pairing

Pairing tokens:
- random;
- single use;
- short lived;
- redacted from logs.

Long-term device credentials:
- unique per Camera Node;
- revocable;
- stored in Keychain on iOS;
- never hard-coded.

## Secrets

Repository must never contain:
- `.env`
- real Slack secrets
- Tailscale auth keys
- signing certificates
- private keys
- provisioning profiles
- private deployment credentials.

Run secret scanning in CI.

## Media upload

Server must enforce:
- authenticated node;
- expected media/session id;
- size limits;
- allowed format/container;
- safe generated filenames;
- checksum/integrity;
- no client-controlled arbitrary output path.

## Web/API

- typed validation;
- deployment-owner authorization for privileged operations;
- CSRF considerations for browser mutating actions;
- safe CORS configuration;
- no wildcard credentials policy;
- rate limiting for pairing/security endpoints;
- strict path validation;
- no shell interpolation from request values.

## Filesystem

Recording root is configured, but API users must never be allowed to choose arbitrary absolute paths per request.

Resolve/validate paths against configured roots before write/delete.

## Docker

Avoid privileged containers unless absolutely necessary and explicitly approved.

Mount only required paths.

Do not mount Docker socket into application containers.

## Dependency security

See `docs/THIRD_PARTY_POLICY.md`.

Automated vulnerability scanning is encouraged, but findings must be triaged rather than blindly upgrading security-sensitive dependencies.

## Reporting a vulnerability

Before a public release process is established, use a private contact method defined by the repository owner rather than opening an Issue containing exploit details.

A public `SECURITY.md` release-contact address should be added before broad adoption.