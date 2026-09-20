# Human Authorization

Owns owner invitations/allowlists, independent `live:view` and `recordings:view` permissions, owner-only operations, and prompt revocation.

- Accepts Tailscale/trusted-proxy identity only through a non-bypassable local listener boundary; ordinary LAN clients cannot supply trusted identity headers directly.
- Requires application authorization in addition to private-network reachability. Tailnet membership alone grants no access.
- Treats a verified Tailscale/trusted-proxy identity as supplementary: the deployment shares one Tailscale account, so authorization requires the requesting principal's own ServerSentinel credential (WebAuthn/passkey, ADR 0003) on every human route. No route authorizes on an identity header alone.
- Stores only public credential material and owner-visible metadata; authenticator user verification stays on the viewer's device and no viewer biometric template reaches the server.
- Supports revoking a single credential and revoking a whole principal, and binds sessions to the credential that created them.
- Keeps historical events/timeline under `recordings:view` and provides generic, non-branding denial for uninvited identities.
- Does not modify Tailscale ACLs/Grants, store Tailscale administrative credentials, or treat an agent identity as a human/admin identity.
