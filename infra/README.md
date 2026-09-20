# Infrastructure

Owns deployment packaging: `systemd/` for native service definitions and `docker/` for appropriate Main Server container/Compose assets. Shared installer/update/check tooling belongs in `scripts/`.

Keep configuration paths and deployment values configurable. Do not commit secrets/private deployment data, expose human services publicly by default, change Tailscale ACLs/Grants, or bypass media-mount and least-privilege safeguards.
