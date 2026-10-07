"""Release capabilities that ``install.py`` reads as text and never imports.

The installer checks a release it is about to start for these exact lines, so
an update or rollback never switches to a release that cannot start under the
host's current service configuration (Issue #126). A release without this
file predates them. Keep each capability on its own line, spelled exactly.
"""

# This release accepts the human upstream created by systemd through
# ``server-sentinel-upstream.socket`` (``LISTEN_FDS`` / ``LISTEN_PID``).
HUMAN_UPSTREAM_SOCKET_ACTIVATION = True

# This release requires ``capture_ca_directory`` in the deployment
# configuration (a path, or null); earlier releases refuse the key (Issue #109).
CAPTURE_CA_DIRECTORY_SETTING = True
