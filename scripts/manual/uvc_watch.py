"""Manual-test helper: watch real local UVC sources while a person replugs cameras.

MANUAL TEST ONLY. Never use against a production runtime root. It creates two
logical local_uvc sources in a throwaway state directory, approves them through
the real audited approval path with a stand-in Owner authorizer (the Owner
WebAuthn route is not wired yet), and runs the real Main startup, discovery and
capture code. Frames are counted and discarded; nothing is written except the
private SQLite state in --state-dir. Output contains only logical labels
(src1/src2), health states, reasons, fps and descriptor counts — no serials,
device paths, by-id names or USB ports.

Usage (normal non-root user in group `video`, from the repository root;
SERVER_DIR is optional and defaults to this checkout's server directory):
  SERVER_DIR=server python scripts/manual/uvc_watch.py --state-dir DIR [--approve] [--seconds N]

--state-dir must be OUTSIDE the repository; keep it between runs to test
restart/re-enumeration, then delete it. --approve binds src1/src2 to the
currently discovered cameras (ordered by hashed serial, so it is stable).
See MANUAL_TEST.md section A.
"""
import argparse
import asyncio
from contextlib import closing, contextmanager
import hashlib
import os
from pathlib import Path
import queue
import sys
import time

sys.path.insert(0, os.environ.get("SERVER_DIR", str(Path(__file__).resolve().parents[2] / "server")))
from app.audit import AuditStore, OwnerAuditService  # noqa: E402
from app.audit.integration import OwnerAdministration  # noqa: E402
from app.cameras.registry import CameraRegistry, CaptureProfile, SourceType  # noqa: E402
from app.cameras.uvc.config import LocalUvcConfiguration  # noqa: E402
from app.cameras.uvc.discovery import LinuxDiscovery  # noqa: E402
from app.cameras.uvc.runtime import LocalUvcDependencies  # noqa: E402
from app.main import create_app  # noqa: E402
from app.settings import Settings  # noqa: E402
from app.storage.database import Database  # noqa: E402
from app.storage.migrations import migrate  # noqa: E402
from app.storage.schema import APPLICATION_MIGRATIONS  # noqa: E402


class Owner:
    def require_owner(self, actor):
        if actor != "hw-owner":
            raise PermissionError()


@contextmanager
def admitted():
    yield


class HealthEventLog:
    """Receives every health transition through the runtime's health sink.

    recent_health_events() is a bounded deque that evicts old entries once
    full, so its length is not a usable cursor during a long flapping run.
    The sink sees each event exactly once; drain() returns what arrived since
    the previous call. The queue is drained every second, so it stays small.
    """

    def __init__(self):
        self._queue = queue.SimpleQueue()

    def sink(self, event):
        self._queue.put(event)

    def drain(self):
        events = []
        while True:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                return events


def fds():
    video = audio = 0
    for e in os.listdir("/proc/self/fd"):
        try:
            t = os.readlink(f"/proc/self/fd/{e}")
        except OSError:
            continue
        video += t.startswith("/dev/video")
        audio += t.startswith("/dev/snd")
    return video, audio


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", required=True, type=Path)
    p.add_argument("--approve", action="store_true")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--profile", default="1920x1080@30/MJPG")
    a = p.parse_args()
    size, rest = a.profile.split("@")
    fps, fourcc = rest.split("/")
    w, h = map(int, size.split("x"))
    profile = CaptureProfile(w, h, int(fps), fourcc)
    a.state_dir.mkdir(mode=0o700, exist_ok=True)
    settings = Settings(a.state_dir)
    db = Database(settings.database_path)
    with closing(db.connect()) as c:
        migrate(c, APPLICATION_MIGRATIONS)
    ids_file = a.state_dir / "source_ids"
    fixture = CameraRegistry(db, unaudited_writes=True)
    if ids_file.exists():
        from uuid import UUID
        ids = [UUID(x) for x in ids_file.read_text().split()]
    else:
        ids = [fixture.create_source(source_type=SourceType.LOCAL_UVC, name=f"src{i}", enabled=True,
                                     desired_capture_profile=profile).id for i in (1, 2)]
        ids_file.write_text("\n".join(map(str, ids)))
    registry = CameraRegistry(db)
    admin = OwnerAdministration(OwnerAuditService(AuditStore(db), Owner()), CameraRegistry(db))
    counts = {i: 0 for i in ids}
    log = HealthEventLog()
    app = create_app(settings, storage_reservation=admitted,
                     local_uvc=LocalUvcConfiguration(tuple(ids), retry_delay_seconds=0.5),
                     local_uvc_dependencies=LocalUvcDependencies(health_sink=log.sink))
    async with app.router.lifespan_context(app):
        rt = app.state.local_uvc
        original = rt.adapter.on_frame

        def tap(source_id, frame):
            counts[source_id] += 1
            original(source_id, frame)
        rt.adapter.on_frame = tap
        if a.approve:
            devs = sorted(LinuxDiscovery().scan().devices,
                          key=lambda d: hashlib.sha256((d.serial or "").encode()).hexdigest())
            for sid, dev in zip(ids, devs):
                rt.reapprove(admin, "hw-owner", sid, dev)
        end = time.monotonic() + a.seconds
        while time.monotonic() < end:
            before = dict(counts)
            await asyncio.sleep(1.0)
            for e in log.drain():
                print(f"  event src{ids.index(e.source_id) + 1}: {e.state.value} ({e.reason})", flush=True)
            parts = []
            for n, sid in enumerate(ids, 1):
                s = registry.get_source(sid)
                parts.append(f"src{n}={s.health_state.value} {counts[sid] - before[sid]}fps")
            v, au = fds()
            print(time.strftime("%H:%M:%S"), " ".join(parts), f"video_fds={v} audio_fds={au}",
                  f"service={rt.status().state.value}", flush=True)
    print("stopped:", app.state.local_uvc_state.value, "video_fds=%d audio_fds=%d" % fds())



if __name__ == "__main__":
    asyncio.run(main())
