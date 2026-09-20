"""Private singleton Owner template database, separate from diagnostic data."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
import fcntl
import json
import os
import sqlite3
import stat
import threading

from app.storage.migrations import Migration, MigrationError, migrate
from .contracts import DenyOwner, ModelProvenance, Operation, OwnerError


_MIGRATIONS = (Migration(1, "private_owner_template", (
    "CREATE TABLE owner_template (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "generation INTEGER NOT NULL, template BLOB, provenance TEXT)",
    "INSERT INTO owner_template VALUES(1,0,NULL,NULL)",
    "CREATE TABLE owner_template_audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, "
    "actor TEXT NOT NULL, operation TEXT NOT NULL, generation INTEGER NOT NULL)",
)),)


@dataclass(frozen=True)
class EnrollmentStatus:
    enrolled: bool
    generation: int


@dataclass(frozen=True)
class _Template:
    generation: int
    data: bytes = field(repr=False)
    provenance: ModelProvenance = field(repr=False)


def _unsubstitutable(descriptor):
    """Refuse a path component that another user could rename or replace.

    SQLite canonicalizes the connection filename and derives auxiliary names
    such as the rollback journal from it, so binding only the opened database
    is not enough: every ancestor must be owned by this service or root and
    must not be writable by others unless it is sticky, where only an entry's
    own owner may rename or unlink it.
    """
    info = os.fstat(descriptor)
    if (info.st_uid not in (0, os.geteuid())
            or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
        raise OwnerError("PRIVATE_TEMPLATE_ROOT_UNSAFE_PATH")


def _directory(path: Path):
    if not path.is_absolute() or ".." in path.parts:
        raise OwnerError("PRIVATE_TEMPLATE_ROOT_UNAVAILABLE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        _unsubstitutable(descriptor)
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            _unsubstitutable(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class OwnerTemplateStore:
    """Single worker, private pre-created runtime root, no template export API."""
    def __init__(self, root: Path, *, max_template_bytes: int, reservation, authorizer=None):
        if type(max_template_bytes) is not int or not 0 < max_template_bytes <= 1048576:
            raise ValueError("INVALID_TEMPLATE_LIMIT")
        if any((parent / ".git").is_file() or (parent / ".git/HEAD").is_file() for parent in (root, *root.parents)):
            raise OwnerError("PRIVATE_TEMPLATE_ROOT_INSIDE_CHECKOUT")
        code_root = Path(__file__).resolve().parents[2]
        if root == code_root or code_root in root.parents:
            raise OwnerError("PRIVATE_TEMPLATE_ROOT_INSIDE_CHECKOUT")
        self._root = root
        self._fd = -1
        self._db = None
        self._owner = threading.get_ident()
        self._identity = None
        self._file_identity = None
        self._max_bytes = max_template_bytes
        if not callable(reservation):
            raise ValueError("TEMPLATE_STORAGE_RESERVATION_REQUIRED")
        self._reservation = reservation
        self._authorizer = authorizer or DenyOwner()
        try:
            self._fd = _directory(root)
            info = os.fstat(self._fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise OwnerError("PRIVATE_TEMPLATE_ROOT_PERMISSIONS")
            self._identity = (info.st_dev, info.st_ino)
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self._reservation():
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                descriptor = os.open("owner-template.sqlite3", flags | os.O_CREAT, 0o600, dir_fd=self._fd)
                try:
                    file_info = os.fstat(descriptor)
                    if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1
                            or file_info.st_uid != os.geteuid() or file_info.st_mode & 0o077):
                        raise OwnerError("PRIVATE_TEMPLATE_FILE_PERMISSIONS")
                    self._file_identity = (file_info.st_dev, file_info.st_ino)
                finally:
                    os.close(descriptor)
                self._check()
                self._db = sqlite3.connect(self._verified_database_path(), isolation_level=None)
                self._db.row_factory = sqlite3.Row
                self._db.execute("PRAGMA journal_mode=DELETE")
                self._db.execute("PRAGMA synchronous=FULL")
                self._db.execute("PRAGMA secure_delete=ON")
                # Re-verify before any schema write, so a root/file swap racing
                # the open cannot leave a connection bound elsewhere.
                self._check()
                migrate(self._db, _MIGRATIONS)
                os.fsync(self._fd)
        except (OSError, sqlite3.Error, MigrationError):
            # Edited/newer migration history and failed DDL are storage
            # unavailability too; callers see one fixed non-sensitive error.
            self.close()
            raise OwnerError("PRIVATE_TEMPLATE_STORAGE_UNAVAILABLE") from None
        except BaseException:
            self.close()
            raise

    def _verified_database_path(self) -> str:
        """Bind the connection to the already verified directory descriptor.

        Reopening by plain path would resolve every component again and follow
        a symlink or substituted directory installed after the `O_NOFOLLOW`
        checks above. `/proc/self/fd/<dirfd>` is the kernel's handle for the
        directory this store verified, so those components cannot be swapped.
        A missing handle or a changed directory/file identity fails closed;
        there is no silent fallback to the re-resolved path.
        """
        directory = f"/proc/self/fd/{self._fd}"
        info = os.stat(directory)
        if (info.st_dev, info.st_ino) != self._identity:
            raise OwnerError("PRIVATE_TEMPLATE_ROOT_UNAVAILABLE")
        path = f"{directory}/owner-template.sqlite3"
        entry = os.stat(path, follow_symlinks=False)
        if ((entry.st_dev, entry.st_ino) != self._file_identity or not stat.S_ISREG(entry.st_mode)
                or entry.st_nlink != 1 or entry.st_uid != os.geteuid() or entry.st_mode & 0o077):
            raise OwnerError("PRIVATE_TEMPLATE_FILE_UNAVAILABLE")
        return path

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def _check(self):
        if threading.get_ident() != self._owner or self._fd < 0:
            raise OwnerError("PRIVATE_TEMPLATE_STORE_UNAVAILABLE")
        descriptor = -1
        try:
            descriptor = _directory(self._root)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != self._identity or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise OwnerError("PRIVATE_TEMPLATE_ROOT_UNAVAILABLE")
            file_info = os.stat("owner-template.sqlite3", dir_fd=descriptor, follow_symlinks=False)
            if ((file_info.st_dev, file_info.st_ino) != self._file_identity
                    or not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1
                    or file_info.st_uid != os.geteuid() or file_info.st_mode & 0o077):
                raise OwnerError("PRIVATE_TEMPLATE_FILE_UNAVAILABLE")
        except OSError:
            raise OwnerError("PRIVATE_TEMPLATE_ROOT_UNAVAILABLE") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def status(self) -> EnrollmentStatus:
        self._check()
        try:
            row = self._db.execute("SELECT generation,template IS NOT NULL AS enrolled FROM owner_template WHERE singleton=1").fetchone()
            if row is None:
                raise OwnerError("PRIVATE_TEMPLATE_STATE_INVALID")
            return EnrollmentStatus(bool(row["enrolled"]), row["generation"])
        except sqlite3.Error:
            raise OwnerError("PRIVATE_TEMPLATE_STORAGE_UNAVAILABLE") from None

    def diagnostic_snapshot(self) -> dict:
        """The same strict allowlist applies even to explicit Owner exports."""
        return asdict(self.status())

    def _load_for_verification(self) -> _Template | None:
        self._check()
        try:
            row = self._db.execute("SELECT generation,template,provenance FROM owner_template WHERE singleton=1").fetchone()
            if row is None or row["template"] is None:
                return None
            data = json.loads(row["provenance"])
            data["review_id"] = UUID(data["review_id"])
            if type(row["template"]) is not bytes or not 0 < len(row["template"]) <= self._max_bytes:
                raise OwnerError("PRIVATE_TEMPLATE_STATE_INVALID")
            return _Template(row["generation"], row["template"], ModelProvenance(**data))
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            raise OwnerError("PRIVATE_TEMPLATE_STATE_INVALID") from None

    def _authorize(self, operation: Operation) -> UUID:
        self._check()
        actor = self._authorizer.require_owner(operation)
        if not isinstance(actor, UUID):
            raise OwnerError("OWNER_AUTHORIZATION_REQUIRED")
        return actor

    def _replace(self, template: bytes | None, provenance: ModelProvenance | None, *,
                 operation: Operation, actor: UUID, expected_generation: int, at: datetime):
        self._check()
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("AWARE_TIME_REQUIRED")
        # A null template means deletion only. A verifier that returns no
        # template must fail enrollment instead of silently clearing the
        # current one, advancing the generation and auditing it as ENROLL.
        if operation is Operation.DELETE:
            if template is not None or provenance is not None:
                raise OwnerError("INVALID_OWNER_TEMPLATE")
        elif (type(template) is not bytes or not 0 < len(template) <= self._max_bytes
                or not isinstance(provenance, ModelProvenance)):
            raise OwnerError("INVALID_OWNER_TEMPLATE")
        encoded = None
        if provenance is not None:
            payload = asdict(provenance)
            payload["review_id"] = str(provenance.review_id)
            encoded = json.dumps(payload, separators=(",", ":"))
        with self._reservation():
            try:
                self._db.execute("BEGIN IMMEDIATE")
                current = self.status()
                if current.generation != expected_generation:
                    raise OwnerError("TEMPLATE_GENERATION_CHANGED")
                generation = current.generation + 1
                self._db.execute("UPDATE owner_template SET generation=?,template=?,provenance=? WHERE singleton=1",
                                 (generation, template, encoded))
                self._db.execute("INSERT INTO owner_template_audit(at,actor,operation,generation) VALUES(?,?,?,?)",
                                 (at.astimezone(timezone.utc).isoformat(), str(actor), operation.value, generation))
                self._db.commit()
            except BaseException as exc:
                self._db.rollback()
                if isinstance(exc, sqlite3.Error):
                    raise OwnerError("PRIVATE_TEMPLATE_STORAGE_UNAVAILABLE") from None
                raise
        return self.status()

    def delete(self, *, expected_generation: int, at: datetime) -> EnrollmentStatus:
        actor = self._authorize(Operation.DELETE)
        return self._replace(None, None, operation=Operation.DELETE, actor=actor,
                             expected_generation=expected_generation, at=at)
