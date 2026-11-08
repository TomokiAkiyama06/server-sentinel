# Infrastructure

Owns deployment packaging: `systemd/` for native service definitions and `docker/` for appropriate Main Server container/Compose assets. Shared installer/update/check tooling belongs in `scripts/`.

`lxd/` holds the optional LXD host-side USB camera re-pass (Issue #301 item 1): a udev rule, a timer and a root oneshot the Owner installs on the LXD host, outside ServerSentinel; see `lxd/README.md`.

Keep configuration paths and deployment values configurable. Do not commit secrets/private deployment data, expose human services publicly by default, change Tailscale ACLs/Grants, or bypass media-mount and least-privilege safeguards.
