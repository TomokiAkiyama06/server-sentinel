# Owner Setup

Owns source/node registration, profile settings, owner verification, retention, agent duration/capacity buffer settings, hardware-baseline approval, recording-health status, and security/notification configuration.

Show buffer limits, equivalent duration/capacity, usage, protected-incident expiry, safety reserve, and actual T-10/T+10 protection. Settings remain owner-authorized on the server. Do not hard-code deployment paths, silently approve hardware drift, expose secrets/raw identifiers in public diagnostics, or manage Tailscale ACLs/Grants.

`wizard.tsx` is the first-run wizard shell (#48). It renders step order and
status only — never setting values, secrets, raw hardware identifiers or
biometric data — and never shows a pending, unavailable or skipped step as
completed. Only Welcome is completed by the shell; other steps are completed by
their own integrations, and until then can be deferred as unavailable (optional
steps can also be skipped). Owner controls render only with an authorized
transition provider; the server authorizes and audits each transition through
`server/app/setup_wizard/service.py`. The private-access step keeps Tailnet /
private-network reachability and the ServerSentinel invitation/permissions as
two separate approvals.
