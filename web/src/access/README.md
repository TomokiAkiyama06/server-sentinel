# Access Management

Owns owner-facing invitations, allowlist status, independent `live:view` / `recordings:view` grants, and revocation controls.

Explain private-network reachability separately from application permission. Do not modify Tailscale ACLs/Grants, request Tailscale administrative credentials, imply Tailnet membership grants access, or rely on client-side checks to protect data.

The deployment shares one Tailscale account, so the UI lists each person's own ServerSentinel credentials with their label and last-used time and offers revocation per credential and per principal. Do not present a Tailscale login or an approved device as proof of who is using the dashboard.

Invitations hand out a short-lived single-use enrollment code; the redemption screen registers one credential and shows nothing about cameras, recordings or the deployment. Owner-only actions prompt for a fresh user verification and stay unperformed when it is cancelled.
