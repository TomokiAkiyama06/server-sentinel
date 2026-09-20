"""Real segment/SQLite writes under a synthetic accelerated timeline."""

import os
from pathlib import Path
import tempfile
import zlib

from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import POST, PRE, SECOND, RingConfig, RingRefused, SegmentProfile
from media_capture_agent.storage import MediaStore
from tests.support import SOURCE, settings


class SyntheticAuthority:
    def require_owner(self, operation):
        pass

    def require_preserve(self):
        pass


def run_ring(scenario):
    with tempfile.TemporaryDirectory(prefix="agent-ring-smoke-") as temporary:
        config = settings(Path(temporary))
        with MediaStore(config, stable_device=lambda _expected: True) as store:
            with DiskRing(config, store, ledger_maximum_bytes=128 * 1024, authority=SyntheticAuthority()) as ring:
                profile = SegmentProfile(SOURCE, 800, 400, 60 * SECOND, 100)
                now = 3600 * SECOND
                ring.configure(RingConfig("duration", 600), (profile,), now_us=now,
                               clock_trusted=True)
                payload = zlib.compress(b"generated-smoke-pattern" * 8)
                for start in range(now - PRE, now, 60 * SECOND):
                    ring.append(SOURCE, start, start + 60 * SECOND, payload,
                                now_us=start + 60 * SECOND, clock_trusted=True)
                ring.observe_connection(authenticated=True, connected=True, unexpected=False,
                                         now_us=now, clock_trusted=True)
                incident = ring.observe_connection(authenticated=True, connected=False, unexpected=True,
                                                    now_us=now, clock_trusted=True)
                if scenario == "normal":
                    for start in range(now, now + POST, 60 * SECOND):
                        ring.append(SOURCE, start, start + 60 * SECOND, payload,
                                    now_us=start + 60 * SECOND, clock_trusted=True)
                    result = ring.incident(incident, now_us=now + POST)
                    assert result["state"] == "complete" and not result["has_gaps"]
                else:
                    def shortage(descriptor):
                        values = list(os.fstatvfs(descriptor))
                        values[4] = config.safety_reserve_bytes // values[1]
                        return os.statvfs_result(values)
                    store.space = shortage
                    before = store.segment_allocations()
                    try:
                        ring.append(SOURCE, now, now + 60 * SECOND, payload,
                                    now_us=now + 60 * SECOND, clock_trusted=True)
                    except RingRefused:
                        pass
                    else:
                        raise AssertionError("unsafe post-loss allocation accepted")
                    assert store.segment_allocations() == before
                    ring.tick(now_us=now + POST, clock_trusted=True)
                    result = ring.incident(incident, now_us=now + POST)
                    assert result["state"] == "partial" and result["has_gaps"]
