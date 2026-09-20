import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from fastapi import FastAPI, Request

from app.api.diagnostics import router
from app.diagnostics import (
    DiagnosticCategory,
    DiagnosticDocument,
    DiagnosticExportAction,
    DiagnosticExportEndpoint,
    DiagnosticExportError,
    DiagnosticExportService,
    DiagnosticField,
    DiagnosticFieldKind,
    MediaAsset,
    SafeDiagnosticState,
)
from tests.asgi import request


class SyntheticDiagnostics:
    marker = "SYNTHETIC_PRIVATE_VALUE"

    def collect(self):
        return (
            DiagnosticDocument(DiagnosticCategory.RUNTIME, (
                DiagnosticField("status", SafeDiagnosticState.DEGRADED),
                DiagnosticField("hardware_identifier.camera_serial", self.marker),
            )),
            DiagnosticDocument(DiagnosticCategory.SECURITY, tuple(
                DiagnosticField(name, self.marker) for name in (
                    "credential.access_key",
                    "pairing_secret.code",
                    "private_key.pem",
                    "sensitive_header.authorization",
                    "owner_biometric.embedding",
                    "raw_monitoring_media.frame",
                )
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

    async def test_denial_gets_safe_confirmation_but_writes_and_resolves_nothing(self):
        confirmations = []

        class Deny:
            async def require_owner_export(inner_self, action, confirmation):
                confirmations.append(confirmation)
                raise PermissionError("denied")

        service = DiagnosticExportService(Deny(), self.source, self.media)
        with self.assertRaises(PermissionError):
            await service.export(DiagnosticExportAction(self.output, ("clip_a",)))
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.media.resolved, [])
        self.assertEqual(
            [(item.category, item.item_count)
             for item in confirmations[0].included_categories],
            [("runtime", 2), ("raw_monitoring_media", 1)],
        )
        self.assertEqual(confirmations[0].selected_media_ids, ("clip_a",))
        self.assertFalse(hasattr(confirmations[0], "included_values"))

    async def test_authorized_default_bundle_excludes_and_hashes_sensitive_values(self):
        seen = []

        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                seen.append((action, confirmation))

        action = DiagnosticExportAction(self.output)
        result = await DiagnosticExportService(
            Permit(), self.source, self.media).export(action)
        files, manifest = self.read_bundle(result)
        runtime = json.loads(files["diagnostics/runtime.json"])

        self.assertEqual(seen[0][0], action)
        self.assertEqual(
            [(item.category, item.item_count)
             for item in seen[0][1].included_categories], [("runtime", 2)])
        self.assertEqual(seen[0][1].selected_media_ids, ())
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
        self.assertNotIn("security", result.included_categories)
        self.assertEqual(result.bundle_path.stat().st_mode & 0o777, 0o600)

    async def test_only_individually_selected_raw_media_is_resolved_and_included(self):
        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                return None

        action = DiagnosticExportAction(self.output, ("clip_b", "clip_a"))
        result = await DiagnosticExportService(
            Permit(), self.source, self.media).export(action)
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
            DiagnosticField("status", {"authorization": self.source.marker})

    def test_allowlisted_names_cannot_carry_secrets_or_private_deployment_values(self):
        invalid = (
            ("status", "SYNTHETIC_SECRET"),
            ("component", "private-host-42"),
            ("reason_code", "credential_leaked"),
            ("version", "1.2.3-private-host-42"),
            ("count", "123456"),
            ("enabled", 1),
        )
        for name, value in invalid:
            with self.subTest(name=name), self.assertRaises((TypeError, ValueError)):
                DiagnosticField(name, value)

    def test_unrecognized_safe_names_fail_closed_instead_of_using_regex(self):
        for name in ("access_key", "client_cert", "pairing_code", "owner_vector",
                     "x_forwarded_user", "monitoring_payload"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                DiagnosticField(name, self.source.marker)

        with self.assertRaises(TypeError):
            DiagnosticField("hardware_identifier.access_key", self.source.marker,
                            DiagnosticFieldKind.CREDENTIAL)
        with self.assertRaises(ValueError):
            DiagnosticField("hardware_identifier.access_key", self.source.marker)

    def test_categories_are_allowlisted_before_reaching_manifest_or_confirmation(self):
        with self.assertRaises(TypeError):
            DiagnosticDocument("private-hostname", ())

    async def test_prepared_route_uses_fixed_endpoint_and_both_authorizers(self):
        observed = []

        class SystemPermit:
            async def require_system_access(inner_self, route_request: Request):
                observed.append("system")

        class OwnerPermit:
            async def require_owner_export(inner_self, action, confirmation):
                observed.append((action.output_directory, confirmation))

        application = FastAPI()
        application.state.human_authorizer = SystemPermit()
        application.state.diagnostic_export_endpoint = DiagnosticExportEndpoint(
            DiagnosticExportService(OwnerPermit(), self.source, self.media), self.output)
        application.include_router(router)
        body = json.dumps({"selected_media_ids": []}).encode()
        result = await request(
            application, "/diagnostics/export", method="POST", body=body,
            headers=((b"content-type", b"application/json"),))

        self.assertEqual(result[0]["status"], 200)
        self.assertEqual(observed[0], "system")
        self.assertEqual(observed[1][0], self.output)
        self.assertEqual(
            [(item.category, item.item_count)
             for item in observed[1][1].included_categories], [("runtime", 2)])

    async def test_writer_revalidates_duck_types_and_mutated_dtos_before_owner(self):
        authorized = []

        class MustNotAuthorize:
            async def require_owner_export(inner_self, action, confirmation):
                authorized.append(confirmation)

        class DuckField:
            name = "status"
            value = self.source.marker
            kind = DiagnosticFieldKind.SAFE

        class DuckDocument:
            category = DiagnosticCategory.RUNTIME
            fields = (DuckField(),)

        class DuckSource:
            def collect(inner_self):
                return (DuckDocument(),)

        duck_fields_document = DiagnosticDocument(
            DiagnosticCategory.RUNTIME,
            (DiagnosticField("status", SafeDiagnosticState.OK),))
        object.__setattr__(duck_fields_document, "fields", (DuckField(),))

        class DuckFieldsSource:
            def collect(inner_self):
                return (duck_fields_document,)

        mutated_field = DiagnosticField("status", SafeDiagnosticState.OK)
        object.__setattr__(mutated_field, "value", self.source.marker)
        mutated_document = DiagnosticDocument(
            DiagnosticCategory.RUNTIME, (mutated_field,))

        class MutatedSource:
            def collect(inner_self):
                return (mutated_document,)

        for source in (DuckSource(), DuckFieldsSource(), MutatedSource()):
            with self.subTest(source=type(source).__name__), self.assertRaises(
                    DiagnosticExportError):
                await DiagnosticExportService(
                    MustNotAuthorize(), source).export(
                        DiagnosticExportAction(self.output))
        self.assertEqual(authorized, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_public_package_has_no_unconditionally_writable_exporter(self):
        import app.diagnostics as diagnostics

        self.assertFalse(hasattr(diagnostics, "DiagnosticExporter"))
