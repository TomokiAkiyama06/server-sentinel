# Access Management

Owns owner-facing invitations, allowlist status, independent `live:view` / `recordings:view` grants, and revocation controls.

Explain private-network reachability separately from application permission. Do not modify Tailscale ACLs/Grants, request Tailscale administrative credentials, imply Tailnet membership grants access, or rely on client-side checks to protect data.

The deployment shares one Tailscale account, so the UI lists each person's own ServerSentinel credentials with their label and last-used time and offers revocation per credential and per principal. Do not present a Tailscale login or an approved device as proof of who is using the dashboard.

Revocation is credential-scoped. A synced passkey can exist on several of its owner's devices, so do not label the control "revoke this device" or imply that one credential equals one device; the label is a hint entered at registration. Show the backup-eligibility and backup state the server recorded instead of inferring them, remembering that backup state follows the latest sign-in and can change after registration, and when a deployment configured for device-bound credentials refuses a registration, say what to use instead rather than showing a generic failure.

Where the screen shows the Tailscale login/device last observed for a person, show it as context and not as identification, keep it owner-only, and expect it to disappear when the principal is revoked or deleted.

Invitations hand out a short-lived single-use enrollment code; the redemption screen registers one credential and shows nothing about cameras, recordings or the deployment.

Owner-only actions follow the server's step-up contract: on a step-up-required response, prompt for a fresh assertion and retry the original request; on cancellation or failure, report the generic failure and leave the action unperformed. Do not decide freshness in the client or retry silently.

The server issues the step-up challenge for the current session's own credential, so pass it through unchanged and expect a refusal when a different passkey answers. Do not offer an account picker or fall back to another credential there; a refusal means this session cannot be refreshed, not that the person should try a different key.
