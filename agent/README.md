# media-capture-agent

Owns the remote Linux capture-node service: video-only UVC capture, owner-approved pairing, outbound authenticated transport, bounded disk buffering, protected incidents, and separate node/camera health.

- `capture/`, `pairing/`, `transport/`, `service/`, `storage/`, and `health/` separate these responsibilities.
- Runs natively as `media-capture-agent` under a dedicated non-root account; no GUI/tray or Tailnet membership is required for private-LAN capture.
- Keeps runtime configuration, credentials, buffer, and incidents outside the checkout at configurable paths.
- Does not own human authorization, heavy inference, Main Server hardware integrity, or Main Server recording-health self-tests. No audio capture or direct browser viewing.
