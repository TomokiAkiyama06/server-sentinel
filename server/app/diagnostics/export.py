"""Privacy-safe support bundles with no network or upload capability."""

from collections import Counter
from collections.abc import Iterable
from concurrent.futures import Future
from dataclasses import dataclass, field as dataclass_field
from enum import StrEnum
import asyncio
from functools import partial
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import BinaryIO, Callable, ContextManager, Protocol, TypeAlias
from zipfile import ZIP64_LIMIT, ZIP_STORED, ZipFile, ZipInfo

from app.media.recording.model import StoragePolicy


JsonScalar: TypeAlias = str | int | float | bool | None
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MEDIA_CHUNK_BYTES = 64 * 1024
_MAX_MEDIA_ITEM_BYTES = 512 * 1024 * 1024
_MAX_DIAGNOSTIC_BUNDLE_BYTES = 1024 * 1024 * 1024


class DiagnosticExportError(RuntimeError):
    """A value-free export failure safe to show to an authorized Owner."""


class _DiagnosticCleanupUncertain(RuntimeError):
    """Internal signal that storage reservation must remain held."""


class DiagnosticFieldKind(StrEnum):
    SAFE = "safe"
    HARDWARE_IDENTIFIER = "hardware_identifier"
    CREDENTIAL = "credential"
    PAIRING_SECRET = "pairing_secret"
    PRIVATE_KEY = "private_key"
    SENSITIVE_HEADER = "sensitive_header"
    OWNER_BIOMETRIC = "owner_biometric"
    RAW_MONITORING_MEDIA = "raw_monitoring_media"


class DiagnosticCategory(StrEnum):
    RUNTIME = "runtime"
    CAMERA_HEALTH = "camera_health"
    RECORDING_HEALTH = "recording_health"
    STORAGE = "storage"
    HARDWARE_INVENTORY = "hardware_inventory"
    SECURITY = "security"


class SafeDiagnosticFieldName(StrEnum):
    """Centrally reviewed names which may carry non-sensitive scalar values."""

    STATUS = "status"
    STATE = "state"
    HEALTH = "health"
    VERSION = "version"
    COMPONENT = "component"
    REASON_CODE = "reason_code"
    COUNT = "count"
    ENABLED = "enabled"


class SafeDiagnosticState(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
    READY = "ready"
    ONLINE = "online"
    OFFLINE = "offline"
    DISABLED = "disabled"


class SafeDiagnosticComponent(StrEnum):
    MAIN_SERVER = "main_server"
    DATABASE = "database"
    CAMERA_REGISTRY = "camera_registry"
    UVC_CAPTURE = "uvc_capture"
    MEDIA_PIPELINE = "media_pipeline"
    RECORDER = "recorder"
    STORAGE = "storage"
    DIAGNOSTICS = "diagnostics"


class SafeDiagnosticReasonCode(StrEnum):
    NONE = "none"
    NOT_CONFIGURED = "not_configured"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    SOURCE_OFFLINE = "source_offline"
    STORAGE_PRESSURE = "storage_pressure"
    STORAGE_HARD_STOP = "storage_hard_stop"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    SELF_TEST_FAILED = "self_test_failed"


_SAFE_FIELD_NAMES = frozenset(item.value for item in SafeDiagnosticFieldName)
_SAFE_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\."
    r"(?:0|[1-9][0-9]{0,5})$"
)
_CLASSIFIED_FIELD_NAMES = {
    "hardware_identifier.camera_serial": DiagnosticFieldKind.HARDWARE_IDENTIFIER,
    "hardware_identifier.device_serial": DiagnosticFieldKind.HARDWARE_IDENTIFIER,
    "hardware_identifier.filesystem_uuid": DiagnosticFieldKind.HARDWARE_IDENTIFIER,
    "hardware_identifier.gpu_uuid": DiagnosticFieldKind.HARDWARE_IDENTIFIER,
    "hardware_identifier.hardware_uuid": DiagnosticFieldKind.HARDWARE_IDENTIFIER,
    "credential.access_key": DiagnosticFieldKind.CREDENTIAL,
    "credential.api_key": DiagnosticFieldKind.CREDENTIAL,
    "credential.password": DiagnosticFieldKind.CREDENTIAL,
    "credential.token": DiagnosticFieldKind.CREDENTIAL,
    "pairing_secret.code": DiagnosticFieldKind.PAIRING_SECRET,
    "pairing_secret.secret": DiagnosticFieldKind.PAIRING_SECRET,
    "private_key.key": DiagnosticFieldKind.PRIVATE_KEY,
    "private_key.pem": DiagnosticFieldKind.PRIVATE_KEY,
    "sensitive_header.authorization": DiagnosticFieldKind.SENSITIVE_HEADER,
    "sensitive_header.cookie": DiagnosticFieldKind.SENSITIVE_HEADER,
    "sensitive_header.proxy_identity": DiagnosticFieldKind.SENSITIVE_HEADER,
    "owner_biometric.embedding": DiagnosticFieldKind.OWNER_BIOMETRIC,
    "owner_biometric.template": DiagnosticFieldKind.OWNER_BIOMETRIC,
    "raw_monitoring_media.face_crop": DiagnosticFieldKind.RAW_MONITORING_MEDIA,
    "raw_monitoring_media.frame": DiagnosticFieldKind.RAW_MONITORING_MEDIA,
    "raw_monitoring_media.media": DiagnosticFieldKind.RAW_MONITORING_MEDIA,
    "raw_monitoring_media.video": DiagnosticFieldKind.RAW_MONITORING_MEDIA,
}


def _validate_safe_value(name: str, value: object) -> None:
    if name in {SafeDiagnosticFieldName.STATUS, SafeDiagnosticFieldName.STATE,
                SafeDiagnosticFieldName.HEALTH}:
        if not isinstance(value, SafeDiagnosticState):
            raise TypeError("diagnostic state must use the reviewed enum")
        return
    if name == SafeDiagnosticFieldName.COMPONENT:
        if not isinstance(value, SafeDiagnosticComponent):
            raise TypeError("diagnostic component must use the reviewed enum")
        return
    if name == SafeDiagnosticFieldName.REASON_CODE:
        if not isinstance(value, SafeDiagnosticReasonCode):
            raise TypeError("diagnostic reason must use the reviewed enum")
        return
    if name == SafeDiagnosticFieldName.VERSION:
        if type(value) is not str or not _SAFE_VERSION.fullmatch(value):
            raise ValueError("diagnostic version is invalid")
        return
    if name == SafeDiagnosticFieldName.COUNT:
        if type(value) is not int or not 0 <= value <= 1_000_000_000:
            raise ValueError("diagnostic count is invalid")
        return
    if name == SafeDiagnosticFieldName.ENABLED:
        if type(value) is not bool:
            raise TypeError("diagnostic enabled value must be boolean")
        return
    raise ValueError("safe diagnostic field is unsupported")


@dataclass(frozen=True)
class DiagnosticField:
    name: str
    value: JsonScalar
    kind: DiagnosticFieldKind = dataclass_field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _SAFE_NAME.fullmatch(self.name):
            raise ValueError("diagnostic field name is invalid")
        if self.name in _SAFE_FIELD_NAMES:
            derived_kind = DiagnosticFieldKind.SAFE
            _validate_safe_value(self.name, self.value)
        else:
            derived_kind = _CLASSIFIED_FIELD_NAMES.get(self.name)
            if derived_kind is None:
                raise ValueError("diagnostic field name is not allowlisted")
        object.__setattr__(self, "kind", derived_kind)
        if type(self.value) is float and not math.isfinite(self.value):
            raise ValueError("diagnostic field value is invalid")
        if not (self.value is None or type(self.value) in {str, int, float, bool}
                or isinstance(self.value, (SafeDiagnosticState,
                                           SafeDiagnosticComponent,
                                           SafeDiagnosticReasonCode))):
            raise TypeError("diagnostic fields must be scalar")


@dataclass(frozen=True)
class DiagnosticDocument:
    category: DiagnosticCategory
    fields: tuple[DiagnosticField, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.category, DiagnosticCategory):
            raise TypeError("diagnostic category must be allowlisted")
        if type(self.fields) is not tuple or not all(
                isinstance(field, DiagnosticField) for field in self.fields):
            raise TypeError("diagnostic fields must use validated records")
        if len({field.name for field in self.fields}) != len(self.fields):
            raise ValueError("diagnostic field names must be unique")


@dataclass(frozen=True)
class MediaAsset:
    """Bounded reader for one individually selected raw media item."""

    reader: BinaryIO = dataclass_field(repr=False)
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        if not callable(getattr(self.reader, "readinto", None)):
            raise TypeError("media reader must support bounded readinto")
        if not isinstance(self.media_type, str) or not _SAFE_NAME.fullmatch(
                self.media_type.replace("/", ".")):
            raise ValueError("media type is invalid")


@dataclass(frozen=True)
class MediaDescriptor:
    size_bytes: int
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        if (type(self.size_bytes) is not int or self.size_bytes <= 0
                or self.size_bytes > _MAX_MEDIA_ITEM_BYTES):
            raise ValueError("media size is invalid")
        if not isinstance(self.media_type, str) or not _SAFE_NAME.fullmatch(
                self.media_type.replace("/", ".")):
            raise ValueError("media type is invalid")


class DiagnosticSource(Protocol):
    def collect(self) -> Iterable[DiagnosticDocument]:
        """Return typed deployment-local diagnostic fields."""


class MediaSource(Protocol):
    def describe_selected(self, media_id: str) -> MediaDescriptor:
        """Return bounded size/type metadata for one selected item."""

    def open_selected(self, media_id: str) -> ContextManager[MediaAsset]:
        """Open exactly one selected item and release it when the context exits."""


@dataclass(frozen=True)
class DiagnosticExportAction:
    """Parameters presented to the Owner authorization boundary."""

    output_directory: Path
    selected_media_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.output_directory, Path):
            raise TypeError("output_directory must be a path")
        if len(self.selected_media_ids) > 100:
            raise ValueError("too many selected media IDs")
        if len(set(self.selected_media_ids)) != len(self.selected_media_ids):
            raise ValueError("selected media IDs must be unique")
        if any(not isinstance(item, str) or not _SAFE_NAME.fullmatch(item)
               for item in self.selected_media_ids):
            raise ValueError("selected media ID is invalid")


class OwnerDiagnosticExportAuthorizer(Protocol):
    async def require_owner_caller(self, action: DiagnosticExportAction) -> None:
        """Deny a non-Owner caller before any diagnostic or selected-media lookup.

        The generic human/system access boundary is not an Owner check. This runs
        before collection so an invited non-Owner cannot reach a diagnostic
        producer or probe selected-media IDs for existence or error timing.
        """

    async def require_owner_export(
            self, action: DiagnosticExportAction,
            confirmation: "DiagnosticExportConfirmation") -> None:
        """Confirm the sanitized contents and deny unless the Owner approves."""


class StorageWorker(Protocol):
    def submit(self, call: Callable[[], object]) -> Future:
        """Schedule one bounded call on the thread that owns the storage policy.

        `MainStoragePolicy` admits, releases and serializes every filesystem
        writer on the thread that constructed it. Admission, bundle I/O and
        release therefore run as one submitted unit there, so the reservation is
        never held across an unrelated owner-worker operation and the ASGI event
        loop is never blocked by ZIP writing or fsync.
        """


@dataclass(frozen=True)
class DiagnosticExclusion:
    category: str
    reason: str
    count: int | None = None


@dataclass(frozen=True)
class DiagnosticIncludedCategory:
    category: str
    item_count: int


@dataclass(frozen=True)
class DiagnosticExportConfirmation:
    """Value-free summary shown before the authorized local write."""

    included_categories: tuple[DiagnosticIncludedCategory, ...]
    exclusions: tuple[DiagnosticExclusion, ...]
    selected_media_ids: tuple[str, ...]


@dataclass(frozen=True)
class DiagnosticExportResult:
    bundle_path: Path
    included_categories: tuple[str, ...]
    included_media_count: int


_EXCLUDED_KINDS = {
    DiagnosticFieldKind.CREDENTIAL,
    DiagnosticFieldKind.PAIRING_SECRET,
    DiagnosticFieldKind.PRIVATE_KEY,
    DiagnosticFieldKind.SENSITIVE_HEADER,
    DiagnosticFieldKind.OWNER_BIOMETRIC,
    DiagnosticFieldKind.RAW_MONITORING_MEDIA,
}


@dataclass(frozen=True)
class _PreparedBundle:
    output_directory: Path
    confirmation: DiagnosticExportConfirmation
    static_entries: tuple[tuple[str, bytes], ...]
    selected_media: tuple[tuple[str, MediaDescriptor], ...]
    reserved_bytes: int


def _zip_size(entries: Iterable[tuple[str, int]]) -> int:
    """Exact ZIP_STORED size for ASCII names and default ZipInfo metadata."""
    total = 22  # end of central directory
    count = 0
    for name, content_size in entries:
        if not 0 <= content_size < ZIP64_LIMIT:
            raise DiagnosticExportError("diagnostic bundle is too large")
        name_size = len(name.encode("ascii"))
        total += content_size + 76 + 2 * name_size
        count += 1
    if (count > 65535 or total >= ZIP64_LIMIT
            or total > _MAX_DIAGNOSTIC_BUNDLE_BYTES):
        raise DiagnosticExportError("diagnostic bundle is too large")
    return total


class _DiagnosticBundleWriter:
    """Internal writer reachable only through the authorizing service."""

    def __init__(self, source: DiagnosticSource, media_source: MediaSource | None = None) -> None:
        self._source = source
        self._media_source = media_source

    def _collect_validated(self) -> tuple[DiagnosticDocument, ...]:
        try:
            supplied = tuple(self._source.collect())
            validated = []
            for document in supplied:
                if not isinstance(document, DiagnosticDocument):
                    raise TypeError
                rebuilt_fields = []
                for supplied_field in document.fields:
                    if not isinstance(supplied_field, DiagnosticField):
                        raise TypeError
                    rebuilt = DiagnosticField(
                        supplied_field.name, supplied_field.value)
                    if rebuilt.kind is not supplied_field.kind:
                        raise ValueError
                    rebuilt_fields.append(rebuilt)
                validated.append(DiagnosticDocument(
                    document.category, tuple(rebuilt_fields)))
            return tuple(validated)
        except Exception:
            raise DiagnosticExportError(
                "diagnostic source returned invalid data") from None

    def prepare(self, action: DiagnosticExportAction) -> _PreparedBundle:
        try:
            output = action.output_directory.resolve(strict=True)
        except (OSError, RuntimeError):
            raise DiagnosticExportError(
                "diagnostic output directory is unavailable") from None
        if not output.is_dir():
            raise DiagnosticExportError("diagnostic output directory is unavailable")
        documents = self._collect_validated()
        if len({item.category for item in documents}) != len(documents):
            raise DiagnosticExportError("diagnostic categories must be unique")

        identifier_key = secrets.token_bytes(32)
        exclusions: Counter[tuple[str, str]] = Counter()
        included: dict[str, dict[str, JsonScalar]] = {}
        for document in documents:
            values: dict[str, JsonScalar] = {}
            for field in document.fields:
                kind = field.kind
                if kind in _EXCLUDED_KINDS:
                    exclusions[(document.category.value, kind.value)] += 1
                elif kind is DiagnosticFieldKind.HARDWARE_IDENTIFIER:
                    encoded = json.dumps(field.value, separators=(",", ":"), ensure_ascii=True)
                    output_name = field.name.partition(".")[2]
                    values[output_name] = "hmac-sha256:" + hmac.new(
                        identifier_key, encoded.encode("ascii"), hashlib.sha256
                    ).hexdigest()
                else:
                    values[field.name] = field.value
            if values:
                included[document.category.value] = values

        exclusion_summary = [
            DiagnosticExclusion(category, reason, count)
            for (category, reason), count in sorted(exclusions.items())
        ]
        if not action.selected_media_ids:
            exclusion_summary.append(DiagnosticExclusion(
                "raw_monitoring_media", "not_owner_selected"))
        categories = tuple(DiagnosticIncludedCategory(category, len(values))
                           for category, values in sorted(included.items()))
        if action.selected_media_ids:
            categories += (DiagnosticIncludedCategory(
                "raw_monitoring_media", len(action.selected_media_ids)),)
        confirmation = DiagnosticExportConfirmation(
            included_categories=categories,
            exclusions=tuple(exclusion_summary),
            selected_media_ids=action.selected_media_ids,
        )
        selected_media: list[tuple[str, MediaDescriptor]] = []
        if action.selected_media_ids:
            if self._media_source is None:
                raise DiagnosticExportError("selected diagnostic media is unavailable")
            try:
                for media_id in action.selected_media_ids:
                    supplied = self._media_source.describe_selected(media_id)
                    if not isinstance(supplied, MediaDescriptor):
                        raise TypeError
                    selected_media.append((media_id, MediaDescriptor(
                        supplied.size_bytes, supplied.media_type)))
            except Exception:
                raise DiagnosticExportError(
                    "selected diagnostic media is unavailable") from None

        static_entries = [
            (f"diagnostics/{category}.json", self._json_bytes(values))
            for category, values in sorted(included.items())
        ]
        exclusion_manifest = [
            ({"category": item.category, "reason": item.reason,
              **({"count": item.count} if item.count is not None else {})})
            for item in confirmation.exclusions
        ]
        manifest = {
            "format": 1,
            "transfer": "none_local_bundle_only",
            "included_categories": [
                {"category": item.category, "item_count": item.item_count}
                for item in confirmation.included_categories
            ],
            "exclusions": exclusion_manifest,
            "identifier_transform": "ephemeral_keyed_sha256",
        }
        static_entries.append(("manifest.json", self._json_bytes(manifest)))
        sized_entries = [(name, len(value)) for name, value in static_entries]
        sized_entries.extend(
            (f"media/{index:04d}.bin", descriptor.size_bytes)
            for index, (_, descriptor) in enumerate(selected_media, start=1)
        )
        return _PreparedBundle(
            output, confirmation, tuple(static_entries), tuple(selected_media),
            _zip_size(sized_entries),
        )

    def write(self, prepared: _PreparedBundle,
              directory_fd: int) -> DiagnosticExportResult:
        """Write, publish and fsync entirely through the verified directory fd.

        Every create, rename, unlink and fsync is relative to the descriptor the
        caller pinned and verified against the admitting filesystem, so a mount
        substituted after admission cannot redirect the bundle or its cleanup.
        """
        bundle_name = f"serversentinel-diagnostics-{secrets.token_hex(12)}.zip"
        temporary_name = f".{bundle_name}.part"
        owned_name: str | None = None
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=directory_fd)
            owned_name = temporary_name
            with os.fdopen(descriptor, "w+b") as stream:
                with ZipFile(stream, "w", compression=ZIP_STORED) as archive:
                    for name, value in prepared.static_entries:
                        self._write_bytes(archive, name, value)
                    if prepared.selected_media and self._media_source is None:
                        raise DiagnosticExportError(
                            "selected diagnostic media is unavailable")
                    for index, (media_id, expected) in enumerate(
                            prepared.selected_media, start=1):
                        with self._media_source.open_selected(media_id) as supplied:
                            if not isinstance(supplied, MediaAsset):
                                raise TypeError
                            asset = MediaAsset(supplied.reader, supplied.media_type)
                            if asset.media_type != expected.media_type:
                                raise ValueError
                            self._write_stream(
                                archive, f"media/{index:04d}.bin", asset.reader,
                                expected.size_bytes)
                            del asset
                        del supplied
                # Flush after the central directory is written, so the fsync
                # covers the complete archive rather than its entries alone.
                stream.flush()
                os.fsync(stream.fileno())
                written_bytes = os.fstat(stream.fileno()).st_size
            if written_bytes != prepared.reserved_bytes:
                raise OSError("unexpected diagnostic bundle size")
            os.replace(temporary_name, bundle_name,
                       src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            owned_name = bundle_name
            os.fsync(directory_fd)
        except Exception:
            cleanup_durable = True
            if owned_name is not None:
                try:
                    os.unlink(owned_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    cleanup_durable = False
                try:
                    os.fsync(directory_fd)
                except OSError:
                    cleanup_durable = False
            if not cleanup_durable:
                raise _DiagnosticCleanupUncertain from None
            raise DiagnosticExportError("diagnostic bundle write failed") from None
        return DiagnosticExportResult(
            bundle_path=prepared.output_directory / bundle_name,
            included_categories=tuple(
                item.category for item in prepared.confirmation.included_categories),
            included_media_count=len(prepared.selected_media),
        )

    @staticmethod
    def _json_bytes(value: object) -> bytes:
        return json.dumps(value, separators=(",", ":"), sort_keys=True,
                          ensure_ascii=True).encode("ascii")

    @staticmethod
    def _write_bytes(archive: ZipFile, name: str, value: bytes) -> None:
        info = ZipInfo(name)
        info.external_attr = 0o600 << 16
        info.compress_type = ZIP_STORED
        archive.writestr(info, value)

    @staticmethod
    def _write_stream(archive: ZipFile, name: str, reader: BinaryIO,
                      expected_size: int) -> None:
        info = ZipInfo(name)
        info.external_attr = 0o600 << 16
        info.compress_type = ZIP_STORED
        info.file_size = expected_size
        buffer = bytearray(_MEDIA_CHUNK_BYTES)
        remaining = expected_size
        with archive.open(info, "w") as target:
            while remaining:
                view = memoryview(buffer)[:min(len(buffer), remaining)]
                count = reader.readinto(view)
                if type(count) is not int or not 0 < count <= len(view):
                    raise ValueError("selected media size changed")
                target.write(view[:count])
                remaining -= count
        extra = bytearray(1)
        if reader.readinto(extra) != 0:
            raise ValueError("selected media size changed")


class DiagnosticExportService:
    """The sole public bundle creation path, with pre-write confirmation."""

    def __init__(self, authorizer: OwnerDiagnosticExportAuthorizer,
                 source: DiagnosticSource, storage_policy: StoragePolicy,
                 storage_worker: StorageWorker, storage_root: Path,
                 media_source: MediaSource | None = None) -> None:
        for gate in ("require_owner_caller", "require_owner_export"):
            if not callable(getattr(authorizer, gate, None)):
                raise TypeError("owner export authorization is incomplete")
        if not callable(getattr(storage_worker, "submit", None)):
            raise TypeError("storage worker must schedule owning-thread calls")
        if not isinstance(storage_root, Path):
            raise TypeError("storage_root must be a path")
        self._authorizer = authorizer
        self.__storage_policy = storage_policy
        self.__storage_worker = storage_worker
        self.__storage_root = storage_root
        self.__writer = _DiagnosticBundleWriter(source, media_source)
        self.__worker_slot = asyncio.Semaphore(1)
        self.__storage_uncertain = False

    def __open_admitted_output(self, output_directory: Path) -> int:
        """Pin the export directory and refuse a target the policy cannot admit.

        The injected policy samples free space on the approved storage root, so a
        bundle written to another filesystem would spend space that was never
        reserved and could consume that volume's hard safety reserve. A missing or
        substituted approved root fails closed instead of falling back.
        """
        descriptor = -1
        try:
            descriptor = os.open(
                output_directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(descriptor)
            admitted = os.stat(self.__storage_root)
            if (not stat.S_ISDIR(admitted.st_mode)
                    or info.st_dev != admitted.st_dev
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or not info.st_mode & stat.S_IWUSR
                    or not info.st_mode & stat.S_IXUSR):
                raise OSError("unadmitted diagnostic output directory")
            return descriptor
        except OSError:
            if descriptor >= 0:
                os.close(descriptor)
            raise DiagnosticExportError(
                "diagnostic output directory is not admitted") from None

    def __write_reserved(self, prepared: _PreparedBundle) -> DiagnosticExportResult:
        """Verify, admit, write and release on the storage policy's owning thread."""
        admitted = False
        retain_reservation = False
        directory_fd = -1
        try:
            if self.__storage_uncertain:
                raise DiagnosticExportError("diagnostic storage state is uncertain")
            directory_fd = self.__open_admitted_output(prepared.output_directory)
            self.__storage_policy.admit(prepared.reserved_bytes, critical=False)
            admitted = True
            return self.__writer.write(prepared, directory_fd)
        except _DiagnosticCleanupUncertain:
            self.__storage_uncertain = True
            retain_reservation = True
            raise DiagnosticExportError(
                "diagnostic storage state is uncertain") from None
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)
            if admitted and not retain_reservation:
                try:
                    self.__storage_policy.release()
                except Exception:
                    self.__storage_uncertain = True
                    raise DiagnosticExportError(
                        "diagnostic storage state is uncertain") from None

    def __remove_published(self, result: DiagnosticExportResult) -> bool:
        """Durably drop a bundle whose Owner request no longer receives its name."""
        directory_fd = -1
        try:
            directory_fd = self.__open_admitted_output(result.bundle_path.parent)
            try:
                os.unlink(result.bundle_path.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.fsync(directory_fd)
            return True
        except (OSError, DiagnosticExportError):
            return False
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def __submit_storage(self, call):
        try:
            scheduled = self.__storage_worker.submit(call)
        except Exception:
            raise DiagnosticExportError(
                "diagnostic storage worker is unavailable") from None
        if not isinstance(scheduled, Future):
            raise DiagnosticExportError(
                "diagnostic storage worker is unavailable")
        return asyncio.wrap_future(scheduled)

    @staticmethod
    async def __drain(worker) -> None:
        """Settle an in-flight worker even while this caller is being cancelled."""
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if worker.done() and not worker.cancelled():
            try:
                worker.exception()
            except BaseException:
                pass

    @staticmethod
    def __completed(worker):
        if not worker.done() or worker.cancelled():
            return None
        try:
            if worker.exception() is not None:
                return None
        except BaseException:
            return None
        return worker.result()

    @classmethod
    async def __run_worker(cls, call):
        worker = asyncio.create_task(asyncio.to_thread(call))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            await cls.__drain(worker)
            raise

    async def __discard_published(self, published: DiagnosticExportResult) -> None:
        try:
            worker = self.__submit_storage(
                partial(self.__remove_published, published))
        except DiagnosticExportError:
            self.__storage_uncertain = True
            return
        await self.__drain(worker)
        if self.__completed(worker) is not True:
            self.__storage_uncertain = True

    async def __write_bundle(self, prepared: _PreparedBundle) -> DiagnosticExportResult:
        worker = self.__submit_storage(partial(self.__write_reserved, prepared))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            await self.__drain(worker)
            published = self.__completed(worker)
            if published is not None:
                # The cancelled caller never receives this bundle name, so the
                # archive - including any Owner-selected raw media - must not
                # survive on disk for a later reader.
                await self.__discard_published(published)
            raise

    async def export(self, action: DiagnosticExportAction) -> DiagnosticExportResult:
        await self._authorizer.require_owner_caller(action)
        async with self.__worker_slot:
            if self.__storage_uncertain:
                raise DiagnosticExportError("diagnostic storage state is uncertain")
            prepared = await self.__run_worker(
                partial(self.__writer.prepare, action))
            await self._authorizer.require_owner_export(action, prepared.confirmation)
            return await self.__write_bundle(prepared)


class DiagnosticExportEndpoint:
    """Future human-route integration with a fixed local output directory."""

    def __init__(self, service: DiagnosticExportService, output_directory: Path) -> None:
        if not isinstance(output_directory, Path):
            raise TypeError("output_directory must be a path")
        self.__service = service
        self.__output_directory = output_directory

    async def export(self, selected_media_ids: tuple[str, ...]) -> DiagnosticExportResult:
        return await self.__service.export(DiagnosticExportAction(
            self.__output_directory, selected_media_ids))
