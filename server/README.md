# Main Server

Owns the authoritative configuration, human authorization, Camera Source registry, recording, analysis, events, storage, and notifications.

- `app/` separates these responsibilities, including Main Server hardware integrity and recording-health checks.
- Supports 1–4 active `local_uvc` / `remote_agent` sources through one Camera Source abstraction; source type and role are independent.
- Keeps agent ingest separate from the trusted-proxy human dashboard/API listener. Agent credentials grant no human/admin rights.
- Stores deployment data outside the checkout at configurable paths; no private deployment values, media, credentials, or raw hardware identifiers belong here.
- Captures video only; heavy inference belongs on the Main Server by default.
