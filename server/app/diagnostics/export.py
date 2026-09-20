"""Privacy-safe support bundles with no network or upload capability."""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field as dataclass_field
from enum import StrEnum
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
from typing import Protocol, TypeAlias
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


JsonScalar: TypeAlias = str | int | float | bool | None
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class DiagnosticExportError(RuntimeError):
    """A value-free export failure safe to show to an authorized Owner."""


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


_SAFE_FIELD_NAMES = frozenset(item.value for item in SafeDiagnosticFieldName)
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
        else:
            derived_kind = _CLASSIFIED_FIELD_NAMES.get(self.name)
            if derived_kind is None:
                raise ValueError("diagnostic field name is not allowlisted")
        object.__setattr__(self, "kind", derived_kind)
        if type(self.value) is float and not math.isfinite(self.value):
            raise ValueError("diagnostic field value is invalid")
        if not (self.value is None or type(self.value) in {str, int, float, bool}):
            raise TypeError("diagnostic fields must be scalar")


@dataclass(frozen=True)
class DiagnosticDocument:
    category: DiagnosticCategory
    fields: tuple[DiagnosticField, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.category, DiagnosticCategory):
            raise TypeError("diagnostic category must be allowlisted")
        if len({field.name for field in self.fields}) != len(self.fields):
            raise ValueError("diagnostic field names must be unique")


@dataclass(frozen=True)
class MediaAsset:
    """One raw media item resolved only after individual Owner selection."""

    content: bytes
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise TypeError("media content must be bytes")
        if not isinstance(self.media_type, str) or not _SAFE_NAME.fullmatch(
                self.media_type.replace("/", ".")):
            raise ValueError("media type is invalid")


class DiagnosticSource(Protocol):
    def collect(self) -> Iterable[DiagnosticDocument]:
        """Return typed deployment-local diagnostic fields."""


class MediaSource(Protocol):
    def resolve_selected(self, media_id: str) -> MediaAsset:
        """Resolve exactly one Owner-selected media ID; never enumerate media."""


@dataclass(frozen=True)
class DiagnosticExportAction:
    """Parameters presented to the Owner authorization boundary."""

    output_directory: Path
    selected_media_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.output_directory, Path):
            raise TypeError("output_directory must be a path")
        if len(set(self.selected_media_ids)) != len(self.selected_media_ids):
            raise ValueError("selected media IDs must be unique")
        if any(not isinstance(item, str) or not _SAFE_NAME.fullmatch(item)
               for item in self.selected_media_ids):
            raise ValueError("selected media ID is invalid")


class OwnerDiagnosticExportAuthorizer(Protocol):
    async def require_owner_export(
            self, action: DiagnosticExportAction,
            confirmation: "DiagnosticExportConfirmation") -> None:
        """Confirm the sanitized contents and deny unless the Owner approves."""


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
    included: dict[str, dict[str, JsonScalar]]
    confirmation: DiagnosticExportConfirmation


class _DiagnosticBundleWriter:
    """Internal writer reachable only through the authorizing service."""

    def __init__(self, source: DiagnosticSource, media_source: MediaSource | None = None) -> None:
        self._source = source
        self._media_source = media_source

    def prepare(self, action: DiagnosticExportAction) -> _PreparedBundle:
        try:
            output = action.output_directory.resolve(strict=True)
        except (OSError, RuntimeError):
            raise DiagnosticExportError(
                "diagnostic output directory is unavailable") from None
        if not output.is_dir():
            raise DiagnosticExportError("diagnostic output directory is unavailable")
        documents = tuple(self._source.collect())
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
        return _PreparedBundle(output, included, confirmation)

    def write(self, action: DiagnosticExportAction,
              prepared: _PreparedBundle) -> DiagnosticExportResult:
        media: list[MediaAsset] = []
        if action.selected_media_ids:
            if self._media_source is None:
                raise DiagnosticExportError("selected diagnostic media is unavailable")
            media = [self._media_source.resolve_selected(media_id)
                     for media_id in action.selected_media_ids]

        bundle_name = f"serversentinel-diagnostics-{secrets.token_hex(12)}.zip"
        temporary_name = f".{bundle_name}.part"
        temporary_path = prepared.output_directory / temporary_name
        bundle_path = prepared.output_directory / bundle_name
        try:
            descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w+b") as stream, ZipFile(
                    stream, "w", compression=ZIP_DEFLATED) as archive:
                for category, values in sorted(prepared.included.items()):
                    self._write_json(archive, f"diagnostics/{category}.json", values)
                for index, asset in enumerate(media, start=1):
                    self._write_bytes(archive, f"media/{index:04d}.bin", asset.content)
                exclusion_manifest = [
                    ({"category": item.category, "reason": item.reason,
                      **({"count": item.count} if item.count is not None else {})})
                    for item in prepared.confirmation.exclusions
                ]
                manifest = {
                    "format": 1,
                    "transfer": "none_local_bundle_only",
                    "included_categories": [
                        {"category": item.category, "item_count": item.item_count}
                        for item in prepared.confirmation.included_categories
                    ],
                    "exclusions": exclusion_manifest,
                    "identifier_transform": "ephemeral_keyed_sha256",
                }
                self._write_json(archive, "manifest.json", manifest)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, bundle_path)
            directory_fd = os.open(
                prepared.output_directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
            raise
        return DiagnosticExportResult(
            bundle_path=bundle_path,
            included_categories=tuple(
                item.category for item in prepared.confirmation.included_categories),
            included_media_count=len(media),
        )

    @staticmethod
    def _write_json(archive: ZipFile, name: str, value: object) -> None:
        _DiagnosticBundleWriter._write_bytes(
            archive, name,
            json.dumps(value, separators=(",", ":"), sort_keys=True,
                       ensure_ascii=True).encode("ascii"),
        )

    @staticmethod
    def _write_bytes(archive: ZipFile, name: str, value: bytes) -> None:
        info = ZipInfo(name)
        info.external_attr = 0o600 << 16
        info.compress_type = ZIP_DEFLATED
        archive.writestr(info, value)


class DiagnosticExportService:
    """The sole public bundle creation path, with pre-write confirmation."""

    def __init__(self, authorizer: OwnerDiagnosticExportAuthorizer,
                 source: DiagnosticSource,
                 media_source: MediaSource | None = None) -> None:
        self._authorizer = authorizer
        self.__writer = _DiagnosticBundleWriter(source, media_source)

    async def export(self, action: DiagnosticExportAction) -> DiagnosticExportResult:
        prepared = self.__writer.prepare(action)
        await self._authorizer.require_owner_export(action, prepared.confirmation)
        return self.__writer.write(action, prepared)


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
