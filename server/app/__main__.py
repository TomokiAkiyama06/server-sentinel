"""Run the closed Main Server foundation on loopback only."""

import logging

from app.logging import Event, configure_logging
from app.main import create_app
from app.settings import ConfigurationError, Settings


def run(settings: Settings, monitoring=None, local_uvc=None) -> int:
    """Serve the closed foundation; `monitoring` comes from the deployment.

    Without a storage-configured monitoring section the mandatory startup/daily
    hardware integrity check and daily recording self-test cannot run, so the
    service refuses to start (non-zero exit) instead of running without them.
    `local_uvc` names the deployment-approved local UVC sources; without it the
    backend reports an explicit `unconfigured` local capture state.
    """
    configure_logging(settings.log_level)
    if monitoring is None or not monitoring.storage_configured:
        logging.getLogger(__name__).error(Event.MONITORING_UNCONFIGURED)
        return 1
    from app.systemd import SocketActivationError, activated_listener, build_server
    try:
        # Production: systemd creates the loopback upstream as root through
        # server-sentinel-upstream.socket and passes it here (Issue #126); the
        # backend stays unprivileged. Without activation it binds the port
        # itself, which the reservation check treats as unverified.
        listener = activated_listener(settings.human_host, settings.human_port)
    except SocketActivationError:
        logging.getLogger(__name__).error(Event.HUMAN_LISTENER_ACTIVATION_INVALID)
        return 1
    options = dict(server_header=False, date_header=False, access_log=False, log_config=None,
                   proxy_headers=False, forwarded_allow_ips="", ws="none")
    application = create_app(settings, monitoring=monitoring, local_uvc=local_uvc)
    if listener is None:
        build_server(application, host=settings.human_host, port=settings.human_port, **options).run()
    else:
        build_server(application, **options).run(sockets=[listener])
    return 0


def main() -> int:
    configure_logging()
    try:
        settings = Settings.from_env()
    except ConfigurationError:
        logging.getLogger(__name__).error(Event.STARTUP_FAILED)
        return 1
    return run(settings)


if __name__ == "__main__":
    raise SystemExit(main())
