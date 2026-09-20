# Human API

Owns validated human-facing routes for configuration, live viewing, recordings, events, and owner operations; delegates authorization to `auth/` and domain work to the owning module.

Every media/API request requires server-side authorization. Historical events/timeline require `recordings:view`; `live:view` alone is insufficient. Do not expose human routes on agent ingest, non-owner download/export routes, or deployment metadata through unauthenticated responses.
