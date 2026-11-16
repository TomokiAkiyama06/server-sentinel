# Infrastructure

Owns deployment packaging: `systemd/` for native service definitions and `docker/` for appropriate Main Server container/Compose assets. Shared installer/update/check tooling belongs in `scripts/`.

`lxd/` holds the optional LXD host-side check for USB cameras not passed to the VM (Issue #301 item 1, #405): a timer and a read-only root oneshot the Owner installs on the LXD host, outside ServerSentinel; it never changes the VM and the re-pass is done by hand; see `lxd/README.md`.

Keep configuration paths and deployment values configurable. Do not commit secrets/private deployment data, expose human services publicly by default, change Tailscale ACLs/Grants, or bypass media-mount and least-privilege safeguards.
