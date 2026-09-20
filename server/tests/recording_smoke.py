"""Exercise the actual storage path in the installed CI container layout."""

from uuid import uuid4
import zlib

from app.media.recording import Limits, RecordingError, RecordingStore, RootIdentity, Segment
from app.media.recording.schema import recording_migration
from app.storage.database import Database
from app.storage.migrations import BUILTIN_MIGRATIONS, migrate
from tests.test_recording import Reservation, SyntheticValidator


def run_recording_smoke(base, scenario):
    root = base / "recording-media"
    root.mkdir(mode=0o700)
    info = root.stat()
    connection = Database(base / "recording-metadata.sqlite").connect()
    policy = Reservation()
    try:
        migrate(connection, BUILTIN_MIGRATIONS + (recording_migration(2),))
        limits = Limits(pre_roll_bytes=4096, max_segment_bytes=512,
                        max_segment_ms=30_000, max_active_recordings=4,
                        max_spool_segments=16, max_segments_per_recording=100)
        source = uuid4()
        with RecordingStore(connection, root, RootIdentity(info.st_dev, info.st_ino),
                            limits, policy, SyntheticValidator()) as store:
            segment = Segment(source, uuid4(), 0, 30_000, 40_000, "synthetic", "deflate",
                              zlib.compress(b"generated geometric test payload" * 4))
            if scenario == "normal":
                recording = store.start_manual(source, 30_000, duration_ms=10_000)
                store.append(segment)
                result = store.finish(recording)
                assert result["status"] == "complete"
                assert result["segments"][0]["integrity"] == "verified"
            elif scenario == "error":
                policy.denial = "STORAGE_HARD_STOP"
                try:
                    store.append(segment)
                except RecordingError as exc:
                    assert str(exc) == "STORAGE_HARD_STOP"
                else:
                    raise AssertionError("unsafe storage admission accepted")
                assert not list(root.iterdir())
                policy.denial = None
                root.rename(base / "detached-recording-media")
                try:
                    store.append(segment)
                except RecordingError as exc:
                    assert str(exc) == "RECORDING_ROOT_UNAVAILABLE"
                else:
                    raise AssertionError("missing media root accepted")
                assert not root.exists()
            else:
                raise AssertionError("unknown scenario")
    finally:
        connection.close()
