"""Privacy-safe support bundles with no network or upload capability."""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
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


_INFERRED_KINDS = (
    (re.compile(r"(^|[._-])(serial|uuid)([._-]|$)"),
     DiagnosticFieldKind.HARDWARE_IDENTIFIER),
    (re.compile(r"(^|[._-])(biometric|embedding|face[._-]?template)([._-]|$)"),
     DiagnosticFieldKind.OWNER_BIOMETRIC),
    (re.compile(r"(^|[._-])(private[._-]?key)([._-]|$)"),
     DiagnosticFieldKind.PRIVATE_KEY),
    (re.compile(r"(^|[._-])(pairing)([._-]|$)"),
     DiagnosticFieldKind.PAIRING_SECRET),
    (re.compile(r"(^|[._-])(authorization|cookie|sensitive[._-]?header)([._-]|$)"),
     DiagnosticFieldKind.SENSITIVE_HEADER),
    (re.compile(r"(^|[._-])(credential|password|secret|token|api[._-]?key)([._-]|$)"),
     DiagnosticFieldKind.CREDENTIAL),
    (re.compile(r"(^|[._-])(raw[._-]?(media|frame|video)|face[._-]?crop)([._-]|$)"),
     DiagnosticFieldKind.RAW_MONITORING_MEDIA),
)


def _effective_kind(field: "DiagnosticField") -> DiagnosticFieldKind:
    if field.kind is not DiagnosticFieldKind.SAFE:
        return field.kind
    return next((kind for pattern, kind in _INFERRED_KINDS
                 if pattern.search(field.name)), DiagnosticFieldKind.SAFE)


@dataclass(frozen=True)
class DiagnosticField:
    name: str
    value: JsonScalar
    kind: DiagnosticFieldKind

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DiagnosticFieldKind):
            raise TypeError("diagnostic field kind is required")
        if not isinstance(self.name, str) or not _SAFE_NAME.fullmatch(self.name):
            raise ValueError("diagnostic field name is invalid")
        if type(self.value) is float and not math.isfinite(self.value):
            raise ValueError("diagnostic field value is invalid")
        if not (self.value is None or type(self.value) in {str, int, float, bool}):
            raise TypeError("diagnostic fields must be scalar")


@dataclass(frozen=True)
class DiagnosticDocument:
    category: str
    fields: tuple[DiagnosticField, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.category, str) or not _SAFE_NAME.fullmatch(self.category):
            raise ValueError("diagnostic category is invalid")
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
    async def require_owner_export(self, action: DiagnosticExportAction) -> None:
        """Deny unless this exact export is an explicit Owner action."""


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


class DiagnosticExporter:
    """Writes one local archive. It has no transport, share or upload hook."""

    def __init__(self, source: DiagnosticSource, media_source: MediaSource | None = None) -> None:
        self._source = source
        self._media_source = media_source

    def write(self, action: DiagnosticExportAction) -> DiagnosticExportResult:
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
                kind = _effective_kind(field)
                if kind in _EXCLUDED_KINDS:
                    exclusions[(document.category, kind.value)] += 1
                elif kind is DiagnosticFieldKind.HARDWARE_IDENTIFIER:
                    encoded = json.dumps(field.value, separators=(",", ":"), ensure_ascii=True)
                    values[field.name] = "hmac-sha256:" + hmac.new(
                        identifier_key, encoded.encode("ascii"), hashlib.sha256
                    ).hexdigest()
                else:
                    values[field.name] = field.value
            if values:
                included[document.category] = values

        media: list[tuple[str, MediaAsset]] = []
        if action.selected_media_ids:
            if self._media_source is None:
                raise DiagnosticExportError("selected diagnostic media is unavailable")
            for media_id in action.selected_media_ids:
                media.append((media_id, self._media_source.resolve_selected(media_id)))

        bundle_name = f"serversentinel-diagnostics-{secrets.token_hex(12)}.zip"
        temporary_name = f".{bundle_name}.part"
        temporary_path = output / temporary_name
        bundle_path = output / bundle_name
        try:
            descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w+b") as stream, ZipFile(
                    stream, "w", compression=ZIP_DEFLATED) as archive:
                for category, values in sorted(included.items()):
                    self._write_json(archive, f"diagnostics/{category}.json", values)
                for index, (_, asset) in enumerate(media, start=1):
                    self._write_bytes(archive, f"media/{index:04d}.bin", asset.content)
                exclusion_manifest = [
                    {"category": category, "reason": reason, "count": count}
                    for (category, reason), count in sorted(exclusions.items())
                ]
                if not media:
                    exclusion_manifest.append({
                        "category": "raw_monitoring_media",
                        "reason": "not_owner_selected",
                    })
                manifest = {
                    "format": 1,
                    "transfer": "none_local_bundle_only",
                    "included_categories": [
                        {"category": category, "field_count": len(values)}
                        for category, values in sorted(included.items())
                    ] + ([{"category": "raw_monitoring_media", "item_count": len(media)}]
                         if media else []),
                    "exclusions": exclusion_manifest,
                    "identifier_transform": "ephemeral_keyed_sha256",
                }
                self._write_json(archive, "manifest.json", manifest)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, bundle_path)
            directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
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
            included_categories=tuple(sorted(included)),
            included_media_count=len(media),
        )

    @staticmethod
    def _write_json(archive: ZipFile, name: str, value: object) -> None:
        DiagnosticExporter._write_bytes(
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
    """Fail-closed orchestration for the future Owner-authorized API."""

    def __init__(self, authorizer: OwnerDiagnosticExportAuthorizer,
                 exporter: DiagnosticExporter) -> None:
        self._authorizer = authorizer
        self._exporter = exporter

    async def export(self, action: DiagnosticExportAction) -> DiagnosticExportResult:
        await self._authorizer.require_owner_export(action)
        return self._exporter.write(action)
