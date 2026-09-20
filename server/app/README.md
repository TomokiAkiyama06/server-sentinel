# Main Server Application

- `api/`: human API boundaries and request validation.
- `auth/`: invitations, permissions, and trusted-proxy identity.
- `cameras/`: common Camera Source registry and local/remote adapters.
- `detection/`: detector profiles, quality gates, and optional owner verification.
- `diagnostics/`: Owner-authorized, deployment-local privacy-safe support bundles.
- `events/`: factual event correlation, presence, and historical timeline.
- `integrity/`: Main Server hardware baseline and drift checks.
- `media/`: ingest, recording, viewer delivery, and recording-health self-tests.
- `notifications/`: owner alerts and summaries.
- `storage/`: durable metadata, retention, and write admission.

Do not mix human authorization with capture-node credentials or embed deployment-specific paths/data.
