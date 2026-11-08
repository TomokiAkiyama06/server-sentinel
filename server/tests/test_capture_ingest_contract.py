"""Issue #14 (PR #401 review): the Main parses what the real Agent sends.

Every heartbeat here is produced by the Agent's own ``Agent.tick`` (the code
that builds the schema-1 heartbeat), with synthetic storage, capture and
session stand-ins, and is then parsed by the Main's ``parse_heartbeat``. A
change on either side that breaks the contract fails here. The Agent's
constructor (which checks a real runtime root) is skipped; ``tick`` is not.
"""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from uuid import UUID

from app.cameras.remote_agent.ingest_config import CaptureIngestLimits
from app.cameras.remote_agent.ingest_wire import parse_heartbeat


AGENT = str(Path(__file__).resolve().parents[2] / "agent")
NODE = UUID("00000000-0000-4000-8000-000000000001")
SOURCE = UUID("00000000-0000-4000-8000-000000000002")
agent = None


def setUpModule():
    # Issue #284: a module adds a path only while its tests run.
    global agent
    sys.path.insert(0, AGENT)
    unittest.addModuleCleanup(lambda: sys.path.remove(AGENT))
    from media_capture_agent import config, health, runtime, storage
    agent = SimpleNamespace(config=config, health=health, runtime=runtime, storage=storage)


class Store:
    def __init__(self, failure=None, stale=False):
        self.failure = failure
        self.device_numbers_stale = stale

    def check(self):
        if self.failure is not None:
            raise agent.storage.StorageRefused(self.failure)
        return 10 ** 9


class Capture:
    def __init__(self, *sources):
        self.sources = sources

    def poll(self):
        return self.sources


class Session:
    authenticated = True

    def __init__(self, exchange=None, unreachable=False):
        self.exchange = exchange
        self.unreachable = unreachable
        self.sent = []

    def exchange_clock(self):
        if self.unreachable:
            raise ConnectionError("synthetic")
        return self.exchange

    def send_heartbeat(self, heartbeat):
        self.sent.append(json.loads(json.dumps(heartbeat)))


def real_heartbeat(*, store=None, capture=None, session=None):
    instance = agent.runtime.Agent.__new__(agent.runtime.Agent)
    instance.settings = SimpleNamespace(
        node_id=NODE, safety_reserve_bytes=4096, clock_offset_limit_seconds=2,
        clock_uncertainty_limit_seconds=0.5, clock_step_limit_seconds=0.1)
    instance.store = store or Store()
    instance.capture = capture or Capture()
    instance.session = session or Session(agent.health.ClockExchange(
        1000.0, 5.0, 1000.01, 1000.011, 1000.02, 5.02))
    instance.utc = lambda: 1_800_000_000.0
    instance.monotonic = lambda: 12.5
    instance.sequence = 0
    heartbeat = instance.tick()
    # What the session client would send (the Agent's own JSON).
    return json.dumps(heartbeat).encode()


class AgentHeartbeatContractTests(unittest.TestCase):
    def test_a_healthy_node_with_a_camera(self):
        source = agent.health.SourceHealth(SOURCE, "online", "video_ready")
        parsed = parse_heartbeat(real_heartbeat(capture=Capture(source)))
        self.assertEqual((parsed.node_id, parsed.node_state, parsed.storage_state,
                          parsed.source_count), (NODE, "online", "online", 1))

    def test_storage_hard_stop_and_other_refusal_codes(self):
        for code in ("STORAGE_HARD_STOP", "media_root_readonly", "mount_identity_mismatch"):
            with self.subTest(code=code):
                parsed = parse_heartbeat(real_heartbeat(store=Store(failure=code)))
                self.assertEqual((parsed.node_state, parsed.storage_state, parsed.reasons),
                                 ("degraded", "failed", ("storage_unavailable",)))

    def test_renumbered_media_disk(self):
        parsed = parse_heartbeat(real_heartbeat(store=Store(stale=True)))
        self.assertEqual(parsed.storage_state, "degraded")
        self.assertIn("storage_device_numbers_stale", parsed.reasons)

    def test_unconfigured_capture_unreachable_main_and_clock_reasons(self):
        parsed = parse_heartbeat(real_heartbeat(
            capture=agent.runtime.UnconfiguredCapture(), session=Session(unreachable=True)))
        self.assertEqual(parsed.node_state, "degraded")
        self.assertTrue({"capture_unconfigured", "main_unavailable", "clock_unavailable"}
                        <= set(parsed.reasons))
        skewed = agent.health.ClockExchange(1000.0, 5.0, 1010.0, 1010.001, 1000.02, 5.02)
        self.assertIn("clock_offset",
                      parse_heartbeat(real_heartbeat(session=Session(skewed))).reasons)

    def test_every_source_state_and_reason(self):
        for state in sorted(agent.health.SOURCE_STATES):
            for reason in sorted(agent.health.SOURCE_REASONS):
                with self.subTest(state=state, reason=reason):
                    source = agent.health.SourceHealth(SOURCE, state, reason)
                    parse_heartbeat(real_heartbeat(capture=Capture(source)))

    def test_the_main_idle_timeout_covers_the_longest_agent_interval(self):
        # The heartbeat contract: Main closes a session after its idle timeout
        # without a frame, so it must allow several of the longest Agent
        # intervals plus time for a slow tick (storage check, clock exchange).
        longest = agent.config.MAXIMUM_HEARTBEAT_SECONDS
        idle = CaptureIngestLimits().idle_timeout_seconds
        self.assertGreaterEqual(idle, 3 * longest + 15)


if __name__ == "__main__":
    unittest.main()
