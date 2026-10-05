# Native Service Packaging

Owns systemd service/lifecycle packaging, especially the native dedicated-non-root `media-capture-agent`, with narrowly scoped device and runtime-directory access.

Coordinate configurable runtime paths and expected media-mount checks with installer/service validation. Never start unsafe media writes after mount loss, disguise the service name, require a desktop session, or run the whole application as root.

The Main Server unit is rendered by `server/install.py` so its version pointer,
private configuration, dedicated account, runtime mount, and loopback-only
launcher remain one validated lifecycle. See `server/docs/DEPLOYMENT.md`.

`server-sentinel-socket-owner.socket` and `.service` (Issue #126) are the
static units of the listener socket-owner helper: a socket-activated,
transient non-root service holding only `CAP_DAC_READ_SEARCH` and
`CAP_SYS_PTRACE`, which reports listener ownership to the non-root Main
Server. The Owner installs them by hand following the helper section of
`server/docs/DEPLOYMENT.md`; the release installer does not install or enable
them.
