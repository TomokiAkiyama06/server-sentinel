# Native Service Packaging

Owns systemd service/lifecycle packaging, especially the native dedicated-non-root `media-capture-agent`, with narrowly scoped device and runtime-directory access.

Coordinate configurable runtime paths and expected media-mount checks with installer/service validation. Never start unsafe media writes after mount loss, disguise the service name, require a desktop session, or run the whole application as root.

The Main Server unit is rendered by `server/install.py` so its version pointer,
private configuration, dedicated account, runtime mount, and loopback-only
launcher remain one validated lifecycle. See `server/docs/DEPLOYMENT.md`.

`server-sentinel-upstream.socket` is the Owner-installed socket unit that
creates the loopback human upstream as root and passes it to the unprivileged
`server-sentinel.service` (`Sockets=` in the rendered unit; Issue #126). The
backend gets no capability for it; the hostname reservation check verifies
through unprivileged sock_diag that the upstream was created by this unit.
Installation steps are in `server/docs/DEPLOYMENT.md`.
