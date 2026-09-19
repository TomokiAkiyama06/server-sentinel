# Ubuntu Server

Planned stack:
- Python
- FastAPI
- SQLite
- recording/media workers
- detection workers
- Docker Compose where appropriate

Responsibilities:
- deployment-owner authorization and invited-user permissions;
- trusted Tailscale/private-proxy identity handling;
- Camera Source / Capture Node registry and health;
- local UVC/V4L2 discovery and ingest;
- `media-capture-agent` pairing/revocation and LAN media ingest;
- live-media routing to authorized phone/Mac/desktop browsers;
- durable recording / compressed pre-event buffers;
- person/motion/server-movement/camera-tamper analysis;
- detector-specific image-quality gating;
- optional owner-only face verification;
- entrance/anonymous tracking and presence inference;
- unified factual event timeline;
- retention/storage safety;
- Slack notifications;
- audit.

Heavy CV inference belongs on the main host by default. Capture agents remain lightweight unless a future approved architecture introduces edge inference.

The backend supports 1–4 active sources without fixed front/rear columns. MVP source types are `local_uvc` and `remote_agent`.

A capture-node credential is not a human/admin credential. LAN capture ingest is separated from the human dashboard listener. Human access requires both private-network permission and ServerSentinel application authorization.

UVC identity never relies solely on `/dev/videoN`. Ambiguous reconnect of indistinguishable physical devices fails to `manual_intervention_required`.

ServerSentinel is video-only in MVP. The main Ubuntu host is authoritative durable evidence storage for normal operation. A paired `media-capture-agent` keeps a bounded compressed-video disk ring buffer and preserves critical/unexpected-disconnect incident windows as secondary evidence; the default protected-incident retention on the agent is 60 days.
