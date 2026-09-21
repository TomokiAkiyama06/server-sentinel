# Human Authorization

Owns owner invitations/allowlists, independent `live:view` and `recordings:view` permissions, owner-only operations, and prompt revocation.

- Accepts Tailscale/trusted-proxy identity only through a non-bypassable local listener boundary; ordinary LAN clients cannot supply trusted identity headers directly.
- Requires application authorization in addition to private-network reachability. Tailnet membership alone grants no access.
- Keeps historical events/timeline under `recordings:view` and provides generic, non-branding denial for uninvited identities.
- Does not modify Tailscale ACLs/Grants, store Tailscale administrative credentials, or treat an agent identity as a human/admin identity.
- Separates general human/system access from Owner-only access. `require_owner_access` is an independent gate for Owner-only routes such as diagnostic export; an authorizer that implements no Owner check is denied rather than treated as the Owner.

## Current foundation

`store.py` persists application principals, independent viewer permissions,
opaque credential records, single-use enrollment authorization digests, and
opaque server-side session digests. It deliberately has no HTTP route, proxy
header adapter, cookie, WebAuthn parser, signature verifier, or browser
ceremony. A future ceremony verifies its input before calling enrollment/session
methods; every request integration must still validate current state and its
required permission.
