# Main Server Storage

Owns durable metadata/audit storage, configurable recording roots, retention, capacity accounting, and write admission. Default recording retention is 20 days and audit retention is 90 days; starred recordings never auto-delete.

Validate expected filesystem/mount/device, writability, free space, and an independent hard safety reserve. Reclaim eligible unstarred data first; expose `STORAGE_PRESSURE` / `STORAGE_HARD_STOP` and refuse unsafe writes. Missing/substituted media mounts must not silently redirect writes to the root filesystem.

Keep databases, recordings, credentials, biometrics, inventory, and deployment paths outside source control. Agent ring-buffer and protected-incident lifecycles belong in `agent/storage/`.
