"""Self-test artifacts owned by the existing serialized recording worker.

This module is part of the recording storage implementation: it deliberately
shares the store's pinned directory, thread check, transactions and reservation.
It never appends to, releases, or deletes ordinary recording/spool references.
"""

from dataclasses import replace
from uuid import uuid4
import os
import stat
import threading

from app.media.recording.model import RecordingError
from app.storage.migrations import Migration


def recording_health_migration(version: int) -> Migration:
    return Migration(version, "recording_health", (
        "CREATE TABLE recording_selftest (singleton INTEGER PRIMARY KEY CHECK(singleton=1), id TEXT NOT NULL)",
    ))


class RecorderSelfTestProbe:
    def __init__(self, store, pipeline_status, sample, storage_health, *,
                 max_bytes: int, max_duration_ms: int):
        if (type(max_bytes) is not int or not 0 < max_bytes <= store.limits.max_segment_bytes
                or type(max_duration_ms) is not int or not 0 < max_duration_ms <= store.limits.max_segment_ms):
            raise ValueError("INVALID_SELFTEST_LIMITS")
        self.store = store
        self._pipeline_status = pipeline_status
        self._sample_provider = sample
        self._storage_health = storage_health
        self.max_bytes = max_bytes
        self.max_duration_ms = max_duration_ms
        self._reserved = False
        self._sample = None

    def _pending(self):
        return self.store.db.execute("SELECT id FROM recording_selftest WHERE singleton=1").fetchone()

    def cleanup(self):
        store = self.store
        if threading.get_ident() != store._owner:
            raise RecordingError("RECORDING_WRITER_UNAVAILABLE")
        try:
            store._check(allow_failed=True)
            with store._control_reservation():
                row = self._pending()
                if row is not None:
                    name = store._name(row["id"], ".selftest")
                    store._verify_root()
                    try:
                        info = os.stat(name, dir_fd=store._fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                            raise RecordingError("SELFTEST_ARTIFACT_UNVERIFIABLE")
                        store._verify_root()
                        os.unlink(name, dir_fd=store._fd)
                        os.fsync(store._fd)
                    with store._transaction():
                        store.db.execute("DELETE FROM recording_selftest WHERE singleton=1")
        finally:
            self._sample = None
            if self._reserved:
                self._reserved = False
                store._release_reservation()

    def pipeline_status(self):
        self.store._check()
        return self._pipeline_status()

    def check_storage(self):
        store = self.store
        store._check()
        if self._pending() is not None:
            raise RecordingError("SELFTEST_CLEANUP_REQUIRED")
        if self._reserved or store._reservation_active:
            raise RecordingError("RECORDING_WRITER_BUSY")
        # Admission includes the configured metadata/temp overhead. Hold the
        # maximum encoded-segment budget through reopen/decode and cleanup.
        store.policy.admit(self.max_bytes, critical=False)
        store._reservation_active = True
        self._reserved = True

    def write_test_segment(self):
        store = self.store
        store._check()
        if not self._reserved or self._pending() is not None:
            raise RecordingError("SELFTEST_ADMISSION_REQUIRED")
        sample = self._sample_provider()
        sample.validate(store.limits)
        if len(sample.data) > self.max_bytes or sample.end_ms - sample.start_ms > self.max_duration_ms:
            raise RecordingError("SELFTEST_LIMIT_EXCEEDED")
        store.validator.validate(sample)
        self._sample = sample
        artifact_id = str(uuid4())
        with store._transaction():
            store.db.execute("INSERT INTO recording_selftest VALUES(1,?)", (artifact_id,))
        store._verify_root()
        descriptor = os.open(store._name(artifact_id, ".selftest"),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=store._fd)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(sample.data)
            stream.flush()
            store._verify_root()
            os.fsync(stream.fileno())
        store._verify_root()
        os.fsync(store._fd)

    def reopen_and_decode(self):
        store = self.store
        store._check()
        row = self._pending()
        if self._sample is None or row is None or not self._reserved:
            raise RecordingError("SELFTEST_SAMPLE_UNAVAILABLE")
        descriptor = os.open(store._name(row["id"], ".selftest"),
                             os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=store._fd)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or info.st_size != len(self._sample.data) or info.st_size > self.max_bytes):
                raise RecordingError("SELFTEST_SEGMENT_INVALID")
            data = stream.read(self.max_bytes + 1)
        store._verify_root()
        if data != self._sample.data:
            raise RecordingError("SELFTEST_SEGMENT_CORRUPT")
        # This is the mandatory audited codec validator, including decode and
        # container/duration checks. The byte comparison above is not playback.
        store.validator.validate(replace(self._sample, data=data))

    def storage_health(self):
        self.store._check(allow_failed=True)
        return self._storage_health()
