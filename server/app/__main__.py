"""Run the closed Main Server foundation on loopback only."""

import logging

from app.logging import Event, configure_logging
from app.main import HumanAccessCompositionRefused, create_app
from app.settings import ConfigurationError, Settings


def run(settings: Settings, monitoring=None, local_uvc=None, *, human_access=None,
        human_access_unavailable: bool = False) -> int:
    """Serve the Main Server; `monitoring` comes from the deployment.

    Without a storage-configured monitoring section the mandatory startup/daily
    hardware integrity check and daily recording self-test cannot run, so the
    service refuses to start (non-zero exit) instead of running without them.
    `local_uvc` names the deployment-approved local UVC sources; without it the
    backend reports an explicit `unconfigured` local capture state.

    `human_access` is the deployment's validated `human_access` section
    (`app.auth.access_config`). Absent or disabled, every human path stays
    closed. Enabled, the production composition (`app.auth.composition`) is
    built with one `AccessFaultMonitor` as the reservation check's fault sink,
    the passkey ceremonies' finding sink and the monitoring runtime's
    `access_faults` (Issue #232 item 4). If any part of it cannot be built,
    `create_app` refuses it (`HumanAccessCompositionRefused`; any other
    exception propagates, Issue #283 item 2), or the launcher already found
    the host's Tailscale CLI unusable (`human_access_unavailable`, Issue #283
    item 1), the value-free `human_access_composition_failed`
    event is logged and the service runs with every human path closed (never
    a partial surface) while that monitor, still handed to the monitoring
    runtime, notifies the Owner immediately (`human_access_fault`) and keeps
    the monitoring health degraded until a restart composes access (Codex
    PR #282, REQUIREMENTS NOTIFY-002): recording and the integrity and
    recording-health checks keep running.
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
    composed, closed = {}, None
    if human_access is not None and human_access.enabled:
        from app.auth.composition import build_human_access
        from app.auth.human_surface import HumanAccessUnavailable
        from app.monitoring.access import AccessFaultMonitor
        from app.monitoring.runtime import MonitoringDependencies
        from app.storage.database import Database
        faults = AccessFaultMonitor()
        database = Database(settings.database_path)
        closed = dict(monitoring_dependencies=MonitoringDependencies(access_faults=faults))
        if human_access_unavailable:
            # Issue #283 item 1: the section is valid but the host's
            # Tailscale CLI failed the launcher's check; nothing is built.
            composed = None
        else:
            try:
                composed = dict(
                    database=database,
                    human_access=build_human_access(human_access, settings, database,
                                                    faults=faults, monitoring=monitoring),
                    **closed,
                )
            except HumanAccessUnavailable:
                composed = None
    application = None
    if composed is not None:
        try:
            application = create_app(settings, monitoring=monitoring, local_uvc=local_uvc,
                                     **composed)
        except HumanAccessCompositionRefused:
            # create_app refused the composition (for example a Web build or
            # fault monitor that does not match): handled like a failed build.
            # Any other error, a bug included, propagates (Issue #283 item 2).
            if not composed:
                raise
    if application is None:
        # Value-free; every human path stays closed and the monitor, drained
        # by the monitoring runtime, notifies the Owner (Codex PR #282).
        logging.getLogger(__name__).error(Event.HUMAN_ACCESS_COMPOSITION_FAILED)
        faults.composition_failed()
        application = create_app(settings, monitoring=monitoring, local_uvc=local_uvc, **closed)
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
