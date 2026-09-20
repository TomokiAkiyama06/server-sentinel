"""Real core smoke with synthetic capture/session and socket-attempt observation."""

import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

from media_capture_agent.runtime import Agent
from media_capture_agent.storage import MediaStore, StorageRefused
from tests.support import MockSession, SyntheticCapture, settings


ATTEMPTS = []


def observe(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn"}:
        ATTEMPTS.append(event)
        raise AssertionError("unexpected network or child-process attempt")


def run(scenario):
    if scenario not in {"normal", "error"}:
        raise ValueError("unknown synthetic scenario")
    sys.addaudithook(observe)
    from tests.ring_smoke import run_ring
    with tempfile.TemporaryDirectory(prefix="agent-smoke-") as temporary:
        config = settings(Path(temporary))
        store = MediaStore(config)
        capture, session = SyntheticCapture(), MockSession()
        agent = Agent(config, store, capture=capture, session=session)
        try:
            if scenario == "normal":
                assert agent.tick()["node_state"] == "online"
                store.write_segment(uuid4(), b"synthetic-geometric-video-payload")
                capture.online = False
                heartbeat = agent.tick()
                assert heartbeat["node_state"] == "online"
                assert heartbeat["sources"][0]["state"] == "offline"
            else:
                session.fail = True
                assert "main_unavailable" in agent.tick()["node_reasons"]
                config.media_root.rmdir()
                heartbeat = agent.tick()
                assert heartbeat["storage"]["state"] == "failed"
                try:
                    store.write_segment(uuid4(), b"synthetic-geometric-video-payload")
                except StorageRefused:
                    pass
                else:
                    raise AssertionError("missing mount admitted unsafe write")
                assert not config.media_root.exists()
        finally:
            agent.close()
    run_ring(scenario)
    assert not ATTEMPTS
    print("agent synthetic " + scenario + ": core passed; zero socket/subprocess attempts")


if __name__ == "__main__":
    if os.environ.get("SERVERSENTINEL_CI_SYNTHETIC_ONLY") != "1":
        raise SystemExit("explicit synthetic-only environment required")
    run(sys.argv[1])
