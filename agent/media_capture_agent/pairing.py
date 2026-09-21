"""Fail-closed local primitives for capture-node pairing.

This module deliberately performs no network or cryptographic protocol work.
The future TLS adapter supplies generated credential bytes only after it has
validated the accepted ADR-0006 enrollment response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import errno
import fcntl
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, TextIO
from uuid import UUID, uuid4
import warnings

from .storage import StorageRefused, open_directory


_CODE_LENGTH = 26
_MAX_MATERIAL_BYTES = 256 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024
_CREDENTIAL_DIRECTORY = "node-credentials"
_CURRENT_MANIFEST = "current.json"
_FILES = {
    "private_key": "private-key",
    "client_certificate": "client-certificate",
    "ca_certificate": "ca-certificate",
}


class PairingRefused(RuntimeError):
    """A fixed pairing failure safe to expose without secret material."""


@dataclass(frozen=True)
class PairingCode:
    """A short-lived code whose representation never reveals its value."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.value, str) or len(self.value) != _CODE_LENGTH
                or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                       for character in self.value)):
            raise PairingRefused("invalid_pairing_code")

    def __repr__(self) -> str:
        return "PairingCode(<redacted>)"


def prompt_pairing_code(*, prompt: str = "Pairing code: ",
                        opener: Callable[..., int] = os.open,
                        reader: Callable[..., str] = getpass.getpass) -> PairingCode:
    """Read a code only from a non-echoing controlling terminal.

    Pairing has no argv, environment, URL, or ordinary-stdin code input.  The
    explicit ``/dev/tty`` check also prevents ``getpass`` from falling back to
    echoed stdin when no controlling terminal exists.
    """
    descriptor = None
    stream: TextIO | None = None
    try:
        descriptor = opener("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        if not os.isatty(descriptor):
            raise PairingRefused("secure_pairing_input_unavailable")
        stream = os.fdopen(descriptor, "r+", encoding="utf-8", closefd=True)
        descriptor = None
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = reader(prompt, stream=stream)
    except (EOFError, OSError, UnicodeError, getpass.GetPassWarning):
        raise PairingRefused("secure_pairing_input_unavailable") from None
    finally:
        if stream is not None:
            stream.close()
        elif descriptor is not None:
            os.close(descriptor)
    return PairingCode(value)


@dataclass(frozen=True)
class NodeCredentialMaterial:
    """Opaque signer output; all secret-bearing fields redact their repr."""

    deployment_id: UUID
    node_id: UUID
    server_name: str
    private_key: bytes = field(repr=False)
    client_certificate: bytes = field(repr=False)
    ca_certificate: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.deployment_id, UUID) or not isinstance(self.node_id, UUID):
            raise PairingRefused("invalid_credential_metadata")
        if not _valid_server_name(self.server_name):
            raise PairingRefused("invalid_credential_metadata")
        for value in (self.private_key, self.client_certificate, self.ca_certificate):
            if (not isinstance(value, bytes) or not value
                    or len(value) > _MAX_MATERIAL_BYTES):
                raise PairingRefused("invalid_credential_material")

    def __repr__(self) -> str:
        return (
            "NodeCredentialMaterial(deployment_id=<redacted>, node_id=<redacted>, "
            "server_name=<redacted>, private_key=<redacted>, "
            "client_certificate=<redacted>, ca_certificate=<redacted>)"
        )


class NodeCredentialStore:
    """Install one credential generation under a pinned private runtime root.

    Material files are written and fsynced first.  A no-replace hard link to a
    manifest is the atomic commit point.  Readers must ignore every generation
    unless ``current.json`` names and hashes it.  An existing marker is never
    replaced, including after a competing process bypasses the advisory lock.
    """

    def __init__(self, runtime_root: Path, *, owner_uid: int | None = None):
        self.runtime_root = Path(runtime_root)
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid

    def install(self, material: NodeCredentialMaterial) -> None:
        if not isinstance(material, NodeCredentialMaterial):
            raise PairingRefused("invalid_credential_material")
        root_fd = credentials_fd = lock_fd = None
        created: list[str] = []
        committed = False
        try:
            root_fd = open_directory(self.runtime_root)
            self._validate_directory(root_fd, "runtime_root_rejected")
            credentials_fd = self._open_credentials_directory(root_fd)
            lock_fd = self._open_lock(credentials_fd)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if self._entry_exists(credentials_fd, _CURRENT_MANIFEST):
                raise PairingRefused("node_identity_already_exists")

            generation = uuid4().hex
            values = {
                "private_key": material.private_key,
                "client_certificate": material.client_certificate,
                "ca_certificate": material.ca_certificate,
            }
            manifest_files: dict[str, dict[str, str | int]] = {}
            for kind, value in values.items():
                name = f"{_FILES[kind]}-{generation}.pem"
                self._write_file(credentials_fd, name, value)
                created.append(name)
                manifest_files[kind] = {
                    "name": name,
                    "size": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }

            manifest = json.dumps({
                "format_version": 1,
                "deployment_id": str(material.deployment_id),
                "node_id": str(material.node_id),
                "server_name": material.server_name,
                "files": manifest_files,
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")
            temporary_manifest = f"manifest-{generation}.json"
            self._write_file(credentials_fd, temporary_manifest, manifest)
            created.append(temporary_manifest)
            try:
                os.link(temporary_manifest, _CURRENT_MANIFEST,
                        src_dir_fd=credentials_fd, dst_dir_fd=credentials_fd,
                        follow_symlinks=False)
            except FileExistsError:
                raise PairingRefused("node_identity_already_exists") from None
            committed = True
            os.fsync(credentials_fd)
        except PairingRefused:
            raise
        except (OSError, StorageRefused, ValueError, TypeError):
            raise PairingRefused("credential_storage_unavailable") from None
        finally:
            if credentials_fd is not None and not committed:
                for name in reversed(created):
                    try:
                        os.unlink(name, dir_fd=credentials_fd)
                    except OSError:
                        pass
                try:
                    os.fsync(credentials_fd)
                except OSError:
                    pass
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            if credentials_fd is not None:
                os.close(credentials_fd)
            if root_fd is not None:
                os.close(root_fd)

    def installed(self) -> bool:
        root_fd = credentials_fd = None
        try:
            root_fd = open_directory(self.runtime_root)
            self._validate_directory(root_fd, "runtime_root_rejected")
            credentials_fd = os.open(
                _CREDENTIAL_DIRECTORY,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            self._validate_directory(credentials_fd, "credential_directory_rejected")
            manifest = self._read_file(credentials_fd, _CURRENT_MANIFEST,
                                       maximum=_MAX_MANIFEST_BYTES,
                                       expected_links=2)
            try:
                value = json.loads(manifest.decode("utf-8"))
                if (not isinstance(value, dict)
                        or set(value) != {"format_version", "deployment_id", "node_id",
                                          "server_name", "files"}
                        or value["format_version"] != 1
                        or not _valid_server_name(value["server_name"])
                        or not isinstance(value["files"], dict)
                        or set(value["files"]) != set(_FILES)):
                    raise ValueError
                UUID(value["deployment_id"])
                UUID(value["node_id"])
                generations = set()
                for kind, prefix in _FILES.items():
                    entry = value["files"][kind]
                    if (not isinstance(entry, dict)
                            or set(entry) != {"name", "size", "sha256"}
                            or type(entry["size"]) is not int
                            or not 0 < entry["size"] <= _MAX_MATERIAL_BYTES
                            or not isinstance(entry["sha256"], str)
                            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                        raise ValueError
                    match = re.fullmatch(re.escape(prefix) + r"-([0-9a-f]{32})\.pem",
                                         entry["name"])
                    if match is None:
                        raise ValueError
                    generations.add(match.group(1))
                    content = self._read_file(credentials_fd, entry["name"],
                                              maximum=_MAX_MATERIAL_BYTES,
                                              expected_size=entry["size"])
                    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(),
                                               entry["sha256"]):
                        raise ValueError
                if len(generations) != 1:
                    raise ValueError
                generation = generations.pop()
                current = os.stat(_CURRENT_MANIFEST, dir_fd=credentials_fd,
                                  follow_symlinks=False)
                generation_manifest = os.stat(
                    f"manifest-{generation}.json", dir_fd=credentials_fd,
                    follow_symlinks=False,
                )
                if ((current.st_dev, current.st_ino) !=
                        (generation_manifest.st_dev, generation_manifest.st_ino)
                        or generation_manifest.st_nlink != 2):
                    raise ValueError
            except (KeyError, TypeError, ValueError, UnicodeError):
                raise PairingRefused("credential_identity_rejected") from None
            return True
        except FileNotFoundError:
            return False
        except (OSError, StorageRefused):
            raise PairingRefused("credential_storage_unavailable") from None
        finally:
            if credentials_fd is not None:
                os.close(credentials_fd)
            if root_fd is not None:
                os.close(root_fd)

    def _open_credentials_directory(self, root_fd: int) -> int:
        try:
            os.mkdir(_CREDENTIAL_DIRECTORY, mode=0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError:
            pass
        descriptor = os.open(
            _CREDENTIAL_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            self._validate_directory(descriptor, "credential_directory_rejected")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _open_lock(self, directory_fd: int) -> int:
        descriptor = os.open(
            ".pairing.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                or info.st_mode & 0o077 or info.st_nlink != 1):
            os.close(descriptor)
            raise PairingRefused("credential_lock_rejected")
        return descriptor

    def _validate_directory(self, descriptor: int, reason: str) -> None:
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid
                or info.st_mode & 0o077 or not info.st_mode & stat.S_IWUSR
                or not info.st_mode & stat.S_IXUSR):
            raise PairingRefused(reason)

    @staticmethod
    def _entry_exists(directory_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def _write_file(directory_fd: int, name: str, value: bytes) -> None:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError(errno.EIO, "credential write failed")
                remaining = remaining[written:]
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_size != len(value)):
                raise PairingRefused("credential_file_rejected")
        except Exception:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)

    def _read_file(self, directory_fd: int, name: str, *, maximum: int,
                   expected_size: int | None = None,
                   expected_links: int = 1) -> bytes:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self.owner_uid
                    or before.st_mode & 0o077 or before.st_nlink != expected_links
                    or not 0 < before.st_size <= maximum
                    or expected_size is not None and before.st_size != expected_size):
                raise PairingRefused("credential_file_rejected")
            content = os.read(descriptor, maximum + 1)
            after = os.fstat(descriptor)
            if (len(content) != before.st_size
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise PairingRefused("credential_file_rejected")
            return content
        finally:
            os.close(descriptor)


def _valid_server_name(value: object) -> bool:
    return (isinstance(value, str) and bool(value) and len(value) <= 253
            and value.isascii()
            and not any(character in value for character in "\x00\r\n/\\"))
