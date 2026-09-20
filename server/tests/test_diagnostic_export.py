import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from app.diagnostics import (
    DiagnosticDocument,
    DiagnosticExportAction,
    DiagnosticExportService,
    DiagnosticExporter,
    DiagnosticField,
    DiagnosticFieldKind,
    MediaAsset,
)


class SyntheticDiagnostics:
    marker = "SYNTHETIC_PRIVATE_VALUE"

    def collect(self):
        kinds = (
            DiagnosticFieldKind.CREDENTIAL,
            DiagnosticFieldKind.PAIRING_SECRET,
            DiagnosticFieldKind.PRIVATE_KEY,
            DiagnosticFieldKind.SENSITIVE_HEADER,
            DiagnosticFieldKind.OWNER_BIOMETRIC,
            DiagnosticFieldKind.RAW_MONITORING_MEDIA,
        )
        return (
            DiagnosticDocument("runtime", (
                DiagnosticField("status", "degraded", DiagnosticFieldKind.SAFE),
                DiagnosticField("camera_serial", self.marker,
                                DiagnosticFieldKind.HARDWARE_IDENTIFIER),
                DiagnosticField("forged_token", self.marker, DiagnosticFieldKind.SAFE),
                DiagnosticField("pairing_code", self.marker, DiagnosticFieldKind.SAFE),
                DiagnosticField("owner_embedding", self.marker, DiagnosticFieldKind.SAFE),
            )),
            DiagnosticDocument("private", tuple(
                DiagnosticField(f"item_{index}", self.marker, kind)
                for index, kind in enumerate(kinds)
            )),
        )


class SelectedMedia:
    def __init__(self):
        self.resolved = []

    def resolve_selected(self, media_id):
        self.resolved.append(media_id)
        return MediaAsset(("SYNTHETIC_MEDIA_" + media_id).encode())


class DiagnosticExportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.source = SyntheticDiagnostics()
        self.media = SelectedMedia()

    def read_bundle(self, result):
        with ZipFile(result.bundle_path) as archive:
            return ({name: archive.read(name) for name in archive.namelist()},
                    json.loads(archive.read("manifest.json")))

    async def test_denial_writes_nothing_and_does_not_collect_or_resolve(self):
        class Deny:
            async def require_owner_export(inner_self, action):
                raise PermissionError("denied")

        class MustNotCollect:
            def collect(inner_self):
                raise AssertionError("collection before authorization")

        service = DiagnosticExportService(
            Deny(), DiagnosticExporter(MustNotCollect(), self.media))
        with self.assertRaises(PermissionError):
            await service.export(DiagnosticExportAction(self.output, ("clip_a",)))
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.media.resolved, [])

    async def test_authorized_default_bundle_excludes_and_hashes_sensitive_values(self):
        seen = []

        class Permit:
            async def require_owner_export(inner_self, action):
                seen.append(action)

        action = DiagnosticExportAction(self.output)
        result = await DiagnosticExportService(
            Permit(), DiagnosticExporter(self.source, self.media)).export(action)
        files, manifest = self.read_bundle(result)
        runtime = json.loads(files["diagnostics/runtime.json"])

        self.assertEqual(seen, [action])
        self.assertEqual(self.media.resolved, [])
        self.assertFalse(any(self.source.marker.encode() in value
                             for value in files.values()))
        self.assertEqual(runtime["status"], "degraded")
        self.assertRegex(runtime["camera_serial"], r"^hmac-sha256:[0-9a-f]{64}$")
        self.assertNotIn("forged_token", runtime)
        self.assertEqual(manifest["transfer"], "none_local_bundle_only")
        self.assertEqual({item["reason"] for item in manifest["exclusions"]}, {
            "credential", "pairing_secret", "private_key", "sensitive_header",
            "owner_biometric", "raw_monitoring_media", "not_owner_selected",
        })
        self.assertNotIn("identifier_salt", manifest)
        self.assertNotIn("private", result.included_categories)
        self.assertEqual(result.bundle_path.stat().st_mode & 0o777, 0o600)

    async def test_only_individually_selected_raw_media_is_resolved_and_included(self):
        class Permit:
            async def require_owner_export(inner_self, action):
                return None

        action = DiagnosticExportAction(self.output, ("clip_b", "clip_a"))
        result = await DiagnosticExportService(
            Permit(), DiagnosticExporter(self.source, self.media)).export(action)
        files, manifest = self.read_bundle(result)

        self.assertEqual(self.media.resolved, ["clip_b", "clip_a"])
        self.assertEqual(result.included_media_count, 2)
        self.assertEqual(len([name for name in files if name.startswith("media/")]), 2)
        self.assertFalse(any(media_id.encode() in result.bundle_path.read_bytes()
                             for media_id in action.selected_media_ids))
        media_entry = next(item for item in manifest["included_categories"]
                           if item["category"] == "raw_monitoring_media")
        self.assertEqual(media_entry["item_count"], 2)

    def test_invalid_or_duplicate_selection_is_rejected_before_authorization(self):
        for selected in (("clip_a", "clip_a"), ("../clip",), ("",)):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                DiagnosticExportAction(self.output, selected)

    def test_non_scalar_values_require_explicit_flattening(self):
        with self.assertRaises(TypeError):
            DiagnosticField("headers", {"authorization": self.source.marker},
                            DiagnosticFieldKind.SAFE)
