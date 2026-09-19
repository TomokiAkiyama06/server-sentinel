# Native Service Packaging

Owns systemd service/lifecycle packaging, especially the native dedicated-non-root `media-capture-agent`, with narrowly scoped device and runtime-directory access.

Coordinate configurable runtime paths and expected media-mount checks with installer/service validation. Never start unsafe media writes after mount loss, disguise the service name, require a desktop session, or run the whole application as root.
