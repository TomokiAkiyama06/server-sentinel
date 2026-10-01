"""Private durable UVC approval evidence and ambiguity latch under ``runtime_root``.

The semantics mirror the Main Server ``ApprovalStore``: a session marker is
armed before identity decisions are trusted, an unclean session requires Owner
re-approval on restart, and storage errors never degrade into an empty store.
The file holds private hardware evidence; it is never logged or transmitted.
"""

from dataclasses import dataclass, field
import fcntl
import json
import os
import stat
import threading
from uuid import UUID, uuid4

from .storage import StorageRefused, open_directory
from .uvc_identity import DeviceEvidence


FILENAME = "uvc-approvals.json"
LOCKNAME = "uvc-approvals.lock"
TEMPORARY_PREFIX = FILENAME + ".tmp-"
MAX_FILE_BYTES = 1024 * 1024
MAX_RECORDS = 64
VERSION = 1


class ApprovalStorageError(RuntimeError):
    """A fixed safe message, without physical identifiers or file contents."""


@dataclass(frozen=True)
class ApprovalState:
    approved: DeviceEvidence | None = field(repr=False)
    requires_approval: bool
    session_token: str | None = field(default=None, repr=False)
    serial_ambiguous: bool = False


def _record(value):
    if (not isinstance(value, dict)
            or set(value) != {"evidence", "requires_approval", "serial_ambiguous", "session"}):
        raise ValueError("invalid approval record")
    if type(value["requires_approval"]) is not bool or type(value["serial_ambiguous"]) is not bool:
        raise ValueError("invalid approval record")
    session = value["session"]
    if session is not None:
        UUID(session)
    evidence = value["evidence"]
    approved = None if evidence is None else DeviceEvidence.from_record(evidence)
    return ApprovalState(approved, value["requires_approval"], session, value["serial_ambiguous"])


class ApprovalStore:
    """One writer per runtime root; every change is an fsynced atomic replace."""

    def __init__(self, settings):
        self.service_uid = settings.service_uid
        self._lock = threading.Lock()
        self.fd = None
        self._lock_fd = None
        try:
            self.fd = open_directory(settings.runtime_root)
            info = os.fstat(self.fd)
            if info.st_uid != settings.service_uid or info.st_mode & 0o077:
                raise ApprovalStorageError("approval root ownership is unsafe")
            self._lock_fd = os.open(LOCKNAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=self.fd)
            self._check_private(self._lock_fd)
            # Lifetime lock: two Agents must not interleave approval sessions.
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._remove_stale_temporaries()
            self._read()
        except (OSError, StorageRefused, ValueError) as error:
            self.close()
            raise ApprovalStorageError("UVC approval state is unavailable") from error
        except BaseException:
            self.close()
            raise

    def _check_private(self, descriptor):
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.service_uid
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ApprovalStorageError("approval file ownership is unsafe")
        return info

    def _remove_stale_temporaries(self):
        for name in os.listdir(self.fd):
            if name.startswith(TEMPORARY_PREFIX):
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if stat.S_ISREG(info.st_mode) and info.st_uid == self.service_uid:
                    os.unlink(name, dir_fd=self.fd)

    def _read(self):
        try:
            descriptor = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=self.fd)
        except FileNotFoundError:
            return {}
        try:
            info = self._check_private(descriptor)
            if info.st_size > MAX_FILE_BYTES:
                raise ApprovalStorageError("approval file exceeds bound")
            chunks, remaining = [], MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        data = b"".join(chunks)
        if len(data) > MAX_FILE_BYTES:
            raise ApprovalStorageError("approval file exceeds bound")
        value = json.loads(data.decode("utf-8"))
        if (not isinstance(value, dict) or set(value) != {"version", "sources"}
                or value["version"] != VERSION or not isinstance(value["sources"], dict)
                or len(value["sources"]) > MAX_RECORDS):
            raise ValueError("invalid approval file")
        return {str(UUID(key)): _record(record) for key, record in value["sources"].items()}

    def _write(self, records):
        if len(records) > MAX_RECORDS:
            raise ApprovalStorageError("approval record bound reached")
        document = {"version": VERSION, "sources": {
            key: {"evidence": None if state.approved is None else state.approved.to_record(),
                  "requires_approval": state.requires_approval,
                  "serial_ambiguous": state.serial_ambiguous, "session": state.session_token}
            for key, state in sorted(records.items())
        }}
        data = json.dumps(document, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise ApprovalStorageError("approval file exceeds bound")
        name = TEMPORARY_PREFIX + uuid4().hex
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.fd)
        renamed = False
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(name, FILENAME, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            renamed = True
            os.fsync(self.fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if not renamed:
                try:
                    os.unlink(name, dir_fd=self.fd)
                except OSError:
                    pass

    def _transaction(self, change):
        with self._lock:
            if self.fd is None:
                raise ApprovalStorageError("UVC approval store is closed")
            try:
                records = self._read()
                result = change(records)
                self._write(records)
                return result
            except ApprovalStorageError:
                raise
            except (OSError, ValueError, UnicodeError) as error:
                raise ApprovalStorageError("UVC approval state could not be saved") from error

    def load(self, source_id):
        with self._lock:
            if self.fd is None:
                raise ApprovalStorageError("UVC approval store is closed")
            try:
                return self._read().get(str(UUID(str(source_id))))
            except ApprovalStorageError:
                raise
            except (OSError, ValueError, UnicodeError) as error:
                raise ApprovalStorageError("UVC approval state is unavailable") from error

    def start_session(self, source_id):
        key = str(UUID(str(source_id)))

        def change(records):
            prior = records.get(key)
            token = str(uuid4())
            if prior is None:
                state = ApprovalState(None, True, token, False)
            else:
                # A still-armed marker proves the prior session did not shut
                # down cleanly; its latch writes may have been lost.
                state = ApprovalState(prior.approved,
                                      prior.requires_approval or prior.session_token is not None
                                      or prior.approved is None,
                                      token, prior.serial_ambiguous)
            records[key] = state
            return state
        return self._transaction(change)

    def save(self, source_id, approved, requires_approval, *, session_token, serial_ambiguous,
             release=False):
        key = str(UUID(str(source_id)))
        if session_token is None:
            raise ApprovalStorageError("UVC approval session is not active")
        if approved is not None and not isinstance(approved, DeviceEvidence):
            raise ApprovalStorageError("invalid approval evidence")
        if type(requires_approval) is not bool or type(serial_ambiguous) is not bool:
            raise ApprovalStorageError("invalid approval flags")

        def change(records):
            prior = records.get(key)
            if prior is None or prior.session_token != session_token:
                raise ApprovalStorageError("UVC approval session was superseded")
            # A known duplicated serial stays latched for the same strong identity.
            ambiguous = serial_ambiguous or (
                prior.serial_ambiguous and prior.approved is not None and approved is not None
                and prior.approved.strong_key == approved.strong_key)
            records[key] = ApprovalState(approved, requires_approval or approved is None,
                                         None if release else session_token, ambiguous)
        self._transaction(change)

    def close(self):
        for name in ("_lock_fd", "fd"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                try:
                    os.close(descriptor)
                except OSError:
                    pass
