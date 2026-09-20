"""Run the closed Main Server foundation on loopback only."""

import logging

from app.logging import Event, configure_logging
from app.main import create_app
from app.settings import ConfigurationError, Settings


def run(settings: Settings) -> int:
    configure_logging(settings.log_level)
    import uvicorn
    uvicorn.run(
        create_app(settings), host=settings.human_host, port=settings.human_port,
        server_header=False, date_header=False, access_log=False, log_config=None,
        proxy_headers=False, forwarded_allow_ips="", ws="none",
    )
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
