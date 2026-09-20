"""Native CLI. Secrets, paths and configuration values never appear in diagnostics."""

import argparse
import json
from pathlib import Path
import signal
import sys
import threading

from .config import ConfigurationError, Settings
from .runtime import Agent
from .storage import MediaStore, StorageRefused


def main(argv=None):
    parser = argparse.ArgumentParser(prog="media-capture-agent")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="validate local deployment and exit")
    args = parser.parse_args(argv)
    agent = None
    store = None
    stopped = threading.Event()
    previous = {}
    try:
        # For checkout execution exclude the complete repository; for a zipapp
        # exclude the versioned installation directory containing the executable.
        location = Path(__file__).absolute()
        code_root = location.parents[2]
        settings = Settings.load(args.config, code_root=code_root)
        store = MediaStore(settings)
        agent = Agent(settings, store)
        if args.check:
            store.check()
            print("media-capture-agent: local deployment validation passed")
            return 0
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stopped.set())
        while not stopped.is_set():
            heartbeat = agent.tick()
            # Operational status only; no media, device paths or raw exceptions.
            print(json.dumps({"service": "media-capture-agent",
                              "node_state": heartbeat["node_state"],
                              "reasons": heartbeat["node_reasons"]}), flush=True)
            stopped.wait(settings.heartbeat_seconds)
    except (ConfigurationError, StorageRefused, OSError, ValueError):
        print("media-capture-agent: local deployment validation failed", file=sys.stderr)
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if agent is not None:
            agent.close()
        elif store is not None:
            store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
