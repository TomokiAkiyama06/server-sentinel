# Security Policy

## Security philosophy

ServerSentinel is security-sensitive software. It handles camera/microphone streams, private network endpoints, physical-security events, and persistent recordings.

The safest default is:
- local/self-hosted;
- no developer cloud;
- no public Internet exposure;
- least privilege;
- explicit pairing;
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

## Network defaults

- Do not recommend router port forwarding as normal setup.
- Remote dashboard access should use Tailscale.
- Camera/server traffic should remain local where possible.
- Bind services to the smallest necessary interfaces.
- Document firewall requirements instead of disabling firewalls.

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
