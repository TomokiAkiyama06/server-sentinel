# Dashboard Source

- `dashboard/`: current overview, live grid, and source/node status.
- `access/`: owner-managed invitations and permissions.
- `recordings/`: authorized recording list and browser playback.
- `timeline/`: historical events, observations, and evidence links.
- `setup/`: owner-managed sources, agents, profiles, storage, integrity, and security settings.
- `shared/`: reusable UI and authenticated API/media integration.
- `views/`: screen components composed by `App.tsx`, including the timeline and presence screens.

Keep deployment secrets out of browser bundles. UI visibility is not a substitute for server-side authorization.
