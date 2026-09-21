# Main Server

Owns the authoritative configuration, human authorization, Camera Source registry, recording, analysis, events, storage, and notifications.

- `app/` separates these responsibilities, including Main Server hardware integrity and recording-health checks.
- Supports 1–4 active `local_uvc` / `remote_agent` sources through one Camera Source abstraction; source type and role are independent.
- Keeps agent ingest separate from the trusted-proxy human dashboard/API listener. Agent credentials grant no human/admin rights.
- Stores deployment data outside the checkout at configurable paths; no private deployment values, media, credentials, or raw hardware identifiers belong here.
- Captures video only; heavy inference belongs on the Main Server by default.

The Issue #7 foundation now provides configuration, SQLite migrations, safe
structured logs and an entirely closed FastAPI surface. Capture and human
authorization remain pending. See [the runtime contract and local commands](docs/FOUNDATION.md),
[the stable release lifecycle](docs/DEPLOYMENT.md), and
[reviewed dependencies](docs/DEPENDENCIES.md).
