# Agent and Source Health

Owns separate capture-node process/connection and per-camera health, heartbeat/clock-skew reporting, negotiated profiles, storage pressure, and actual incident-window/gap coverage.

Report offline/degraded/manual-intervention states honestly, including an online agent with an offline camera. Never claim full protection when segments are missing or include secrets/raw device identifiers in ordinary diagnostics. Main Server hardware integrity and daily recording-health self-tests belong under `server/app/`.
