# Main Server Container Packaging

Owns future Main Server container/Compose definitions where appropriate, including explicit configuration/media mounts and separated human/agent listener exposure.

Do not embed credentials or private deployment paths in images, expose the dashboard publicly by default, or silently substitute an unintended filesystem for missing recording storage. The capture agent runs natively; do not require a privileged container for UVC/udev handling.

No Main Server Compose path is currently implemented or documented as an
available installation method. A future path must match the native versioned
install/update/rollback and external-runtime guarantees before it is advertised.
