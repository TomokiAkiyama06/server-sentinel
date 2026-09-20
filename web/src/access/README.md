# Access Management

Owns owner-facing invitations, allowlist status, independent `live:view` / `recordings:view` grants, and revocation controls.

Explain private-network reachability separately from application permission. Do not modify Tailscale ACLs/Grants, request Tailscale administrative credentials, imply Tailnet membership grants access, or rely on client-side checks to protect data.

The deployment shares one Tailscale account, so the UI lists each person's own ServerSentinel credentials with their label and last-used time and offers revocation per credential and per principal. Do not present a Tailscale login or an approved device as proof of who is using the dashboard.

Revocation is credential-scoped. A synced passkey can exist on several of its owner's devices, so do not label the control "revoke this device" or imply that one credential equals one device; the label is a hint entered at registration.

Invitations hand out a short-lived single-use enrollment code; the redemption screen registers one credential and shows nothing about cameras, recordings or the deployment.

Owner-only actions follow the server's step-up contract: on a step-up-required response, prompt for a fresh assertion and retry the original request; on cancellation or failure, report the generic failure and leave the action unperformed. Do not decide freshness in the client or retry silently.
