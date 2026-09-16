# Ubuntu Server

Planned stack:
- Python
- FastAPI
- SQLite
- recording/media workers
- detection workers
- Docker Compose

Responsibilities:
- deployment-owner authorization;
- Camera Source registry/capabilities/health;
- local UVC/V4L2 discovery and ingest;
- Web Camera Node pairing/session/media ingest;
- live-media routing;
- durable recording/ring buffers;
- person/motion/server-movement/camera-tamper analysis;
- low-light/image-quality gating;
- optional owner-only face verification;
- entrance crossing/anonymous tracking;
- presence inference;
- unified event timeline/correlation;
- retention/storage safety;
- Slack notifications;
- audit;
- dashboard API.

Heavy CV inference belongs here by default.

The backend must support 1–4 active sources without fixed front/rear columns. UVC device identity must not rely solely on `/dev/videoN` ordering. Browser Camera Nodes are remote, revocable source identities and do not inherit owner/admin authorization.

The server is primary durable evidence storage in MVP. Browser-local storage is best-effort only and must not be represented as guaranteed independent evidence preservation.
