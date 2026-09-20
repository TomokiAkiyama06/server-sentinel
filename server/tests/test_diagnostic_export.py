from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
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
    MediaDescriptor,
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
        self.released = []
        self.active = 0
        self.max_active = 0
        self.worker_threads = []

    @staticmethod
    def content(media_id):
        values = {
            "clip_a": b"SYNTHETIC_MEDIA_ALPHA",
            "clip_b": b"SYNTHETIC_MEDIA_BRAVO",
        }
        return values[media_id]

    def describe_selected(self, media_id):
        self.worker_threads.append(threading.get_ident())
        return MediaDescriptor(len(self.content(media_id)))

    @contextmanager
    def open_selected(self, media_id):
        self.worker_threads.append(threading.get_ident())
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        if self.active != 1:
            raise AssertionError("selected media retained across writes")
        self.resolved.append(media_id)
        try:
            yield MediaAsset(self.content(media_id))
        finally:
            self.active -= 1
            self.released.append(media_id)


class StorageAdmission:
    def __init__(self):
        self.reservations = []
        self.active = False
        self.releases = 0
        self.denial = None

    def admit(self, media_bytes, *, critical):
        if self.denial:
            raise DiagnosticExportError(self.denial)
        if self.active or type(media_bytes) is not int or media_bytes <= 0 or critical:
            raise AssertionError("invalid diagnostic storage admission")
        self.reservations.append(media_bytes)
        self.active = True

    def release(self):
        if not self.active:
            raise AssertionError("diagnostic reservation is not active")
        self.active = False
        self.releases += 1


class DiagnosticExportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.source = SyntheticDiagnostics()
        self.media = SelectedMedia()
        self.policy = StorageAdmission()

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

        service = DiagnosticExportService(
            Deny(), self.source, self.policy, self.media)
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
            Permit(), self.source, self.policy, self.media).export(action)
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
        self.assertEqual(self.policy.reservations, [result.bundle_path.stat().st_size])
        self.assertEqual(self.policy.releases, 1)
        self.assertFalse(self.policy.active)

    async def test_only_individually_selected_raw_media_is_resolved_and_included(self):
        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                return None

        action = DiagnosticExportAction(self.output, ("clip_b", "clip_a"))
        result = await DiagnosticExportService(
            Permit(), self.source, self.policy, self.media).export(action)
        files, manifest = self.read_bundle(result)

        self.assertEqual(self.media.resolved, ["clip_b", "clip_a"])
        self.assertEqual(self.media.released, ["clip_b", "clip_a"])
        self.assertEqual(self.media.max_active, 1)
        self.assertEqual(self.media.active, 0)
        self.assertEqual(result.included_media_count, 2)
        self.assertEqual(len([name for name in files if name.startswith("media/")]), 2)
        self.assertFalse(any(media_id.encode() in result.bundle_path.read_bytes()
                             for media_id in action.selected_media_ids))
        media_entry = next(item for item in manifest["included_categories"]
                           if item["category"] == "raw_monitoring_media")
        self.assertEqual(media_entry["item_count"], 2)

    async def test_pressure_and_hard_stop_deny_before_file_or_media_open(self):
        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                return None

        for reason in ("STORAGE_PRESSURE", "STORAGE_HARD_STOP"):
            with self.subTest(reason=reason):
                self.policy.denial = reason
                service = DiagnosticExportService(
                    Permit(), self.source, self.policy, self.media)
                with self.assertRaisesRegex(DiagnosticExportError, reason):
                    await service.export(DiagnosticExportAction(
                        self.output, ("clip_a",)))
                self.assertEqual(list(self.output.iterdir()), [])
                self.assertEqual(self.media.resolved, [])
                self.assertEqual(self.policy.releases, 0)
                self.policy.denial = None

    async def test_media_zip_and_fsync_run_in_bounded_worker(self):
        event_loop_thread = threading.get_ident()
        zip_threads = []
        fsync_threads = []
        original_writestr = ZipFile.writestr
        original_fsync = os.fsync

        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                self.assertEqual(threading.get_ident(), event_loop_thread)

        def observed_writestr(archive, *args, **kwargs):
            zip_threads.append(threading.get_ident())
            return original_writestr(archive, *args, **kwargs)

        def observed_fsync(descriptor):
            fsync_threads.append(threading.get_ident())
            return original_fsync(descriptor)

        with patch("app.diagnostics.export.ZipFile.writestr", new=observed_writestr), \
                patch("app.diagnostics.export.os.fsync", side_effect=observed_fsync):
            await DiagnosticExportService(
                Permit(), self.source, self.policy, self.media).export(
                    DiagnosticExportAction(self.output, ("clip_a",)))

        worker_threads = self.media.worker_threads + zip_threads + fsync_threads
        self.assertTrue(worker_threads)
        self.assertTrue(all(item != event_loop_thread for item in worker_threads))
        self.assertEqual(self.media.max_active, 1)

    async def test_directory_fsync_failure_removes_published_bundle_and_releases(self):
        calls = []

        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                return None

        def fail_publication_fsync(descriptor):
            calls.append(descriptor)
            self.assertTrue(self.policy.active)
            if len(calls) == 2:
                raise OSError("synthetic directory fsync failure")

        with patch("app.diagnostics.export.os.fsync",
                   side_effect=fail_publication_fsync):
            with self.assertRaisesRegex(
                    DiagnosticExportError, "diagnostic bundle write failed"):
                await DiagnosticExportService(
                    Permit(), self.source, self.policy).export(
                        DiagnosticExportAction(self.output))

        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.policy.releases, 1)
        self.assertFalse(self.policy.active)

    async def test_media_size_change_removes_partial_bundle_and_releases_each_item(self):
        class Permit:
            async def require_owner_export(inner_self, action, confirmation):
                return None

        class ChangedMedia(SelectedMedia):
            def describe_selected(inner_self, media_id):
                described = super().describe_selected(media_id)
                return MediaDescriptor(described.size_bytes + 1, described.media_type)

        media = ChangedMedia()
        with self.assertRaisesRegex(
                DiagnosticExportError, "diagnostic bundle write failed"):
            await DiagnosticExportService(
                Permit(), self.source, self.policy, media).export(
                    DiagnosticExportAction(self.output, ("clip_a",)))

        self.assertEqual(media.resolved, ["clip_a"])
        self.assertEqual(media.released, ["clip_a"])
        self.assertEqual(media.active, 0)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.policy.releases, 1)

    def test_invalid_or_duplicate_selection_is_rejected_before_authorization(self):
        for selected in (("clip_a", "clip_a"), ("../clip",), ("",),
                         tuple(f"clip_{index}" for index in range(101))):
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
            DiagnosticExportService(
                OwnerPermit(), self.source, self.policy, self.media), self.output)
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
                    MustNotAuthorize(), source, self.policy).export(
                        DiagnosticExportAction(self.output))
        self.assertEqual(authorized, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_public_package_has_no_unconditionally_writable_exporter(self):
        import app.diagnostics as diagnostics

        self.assertFalse(hasattr(diagnostics, "DiagnosticExporter"))
