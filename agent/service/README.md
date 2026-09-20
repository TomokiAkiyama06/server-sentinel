# Agent Service Lifecycle

Owns native `media-capture-agent` startup/shutdown, configuration validation, and integration with the systemd packaging in `infra/systemd/` and installer/update tooling in `scripts/`.

Run under a dedicated non-root account with narrowly scoped device, configuration, credential, and media permissions. At startup coordinate expected media mount/filesystem/device, writability, free-space, and safety-reserve checks with `../storage/`; refuse unsafe writes on failure. Never create a fallback recording directory on the root filesystem after mount loss, impersonate an unrelated service, or hard-code a deployment path.
