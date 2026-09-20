from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import asyncio
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from fastapi import FastAPI, HTTPException, Request

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
from app.media.recording.model import RecordingError
from app.media.recording.store import RootIdentity
from app.storage.policy import FilesystemSpace, MainStoragePolicy, StorageLimits
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


class OwnerAuthorization:
    """Owner boundary: a caller gate plus the exact-contents confirmation."""

    def __init__(self):
        self.caller_actions = []
        self.confirmations = []

    async def require_owner_caller(self, action):
        self.caller_actions.append(action)

    async def require_owner_export(self, action, confirmation):
        self.confirmations.append((action, confirmation))


class Permit(OwnerAuthorization):
    pass


class DenyContents(OwnerAuthorization):
    async def require_owner_export(self, action, confirmation):
        await super().require_owner_export(action, confirmation)
        raise PermissionError("denied")


class DenyCaller(OwnerAuthorization):
    async def require_owner_caller(self, action):
        raise PermissionError("not the deployment owner")


class SelectedMedia:
    def __init__(self):
        self.resolved = []
        self.released = []
        self.active = 0
        self.max_active = 0
        self.worker_threads = []
        self.read_requests = []

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
            source = BytesIO(self.content(media_id))

            class ObservedReader:
                def readinto(inner_self, buffer):
                    self.read_requests.append(len(buffer))
                    return source.readinto(buffer)

            yield MediaAsset(ObservedReader())
        finally:
            self.active -= 1
            self.released.append(media_id)


class StorageAdmission:
    """Synthetic policy reproducing MainStoragePolicy's owning-thread affinity.

    The real policy raises STORAGE_POLICY_UNAVAILABLE when admit()/release() run
    off the thread that constructed it, so every test admits through the same
    owning worker the service must use.
    """

    def __init__(self):
        self.owner = threading.get_ident()
        self.reservations = []
        self.active = False
        self.releases = 0
        self.denial = None
        self.release_failure = None
        self.admit_threads = []
        self.release_threads = []

    def admit(self, media_bytes, *, critical):
        raise AssertionError("diagnostics must never use reclaiming admission")

    def admit_external(self, media_bytes):
        self.admit_threads.append(threading.get_ident())
        if threading.get_ident() != self.owner:
            raise AssertionError("STORAGE_POLICY_UNAVAILABLE")
        if self.denial is not None:
            # MainStoragePolicy denies with RecordingError, not with this
            # package's error type.
            raise self.denial
        if self.active or type(media_bytes) is not int or media_bytes <= 0:
            raise AssertionError("invalid diagnostic storage admission")
        self.reservations.append(media_bytes)
        self.active = True

    def release(self):
        self.release_threads.append(threading.get_ident())
        if threading.get_ident() != self.owner:
            raise AssertionError("STORAGE_POLICY_UNAVAILABLE")
        if not self.active:
            raise AssertionError("diagnostic reservation is not active")
        if self.release_failure:
            raise RuntimeError(self.release_failure)
        self.active = False
        self.releases += 1


class DiagnosticExportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name).resolve()
        self.source = SyntheticDiagnostics()
        self.media = SelectedMedia()
        # One serialized worker owns the storage policy, exactly as the recording
        # store's owning worker does in a composed deployment.
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.worker.shutdown)
        self.policy = self.worker.submit(StorageAdmission).result()
        # The approved storage filesystem identity the policy is configured with.
        admitted = os.stat(self.output)
        self.storage_filesystem = RootIdentity(admitted.st_dev, admitted.st_ino)

    def make_service(self, authorizer, *, source=None, media=None, policy=None,
                     storage_filesystem=None):
        return DiagnosticExportService(
            authorizer, source or self.source, policy or self.policy,
            self.worker, storage_filesystem or self.storage_filesystem, media)

    def read_bundle(self, result):
        with ZipFile(result.bundle_path) as archive:
            return ({name: archive.read(name) for name in archive.namelist()},
                    json.loads(archive.read("manifest.json")))

    async def test_denial_gets_safe_confirmation_but_writes_and_resolves_nothing(self):
        authorizer = DenyContents()
        service = self.make_service(authorizer, media=self.media)
        with self.assertRaises(PermissionError):
            await service.export(DiagnosticExportAction(self.output, ("clip_a",)))
        confirmation = authorizer.confirmations[0][1]
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.media.resolved, [])
        self.assertEqual(
            [(item.category, item.item_count)
             for item in confirmation.included_categories],
            [("runtime", 2), ("raw_monitoring_media", 1)],
        )
        self.assertEqual(confirmation.selected_media_ids, ("clip_a",))
        self.assertFalse(hasattr(confirmation, "included_values"))

    async def test_authorized_default_bundle_excludes_and_hashes_sensitive_values(self):
        authorizer = Permit()
        action = DiagnosticExportAction(self.output)
        result = await self.make_service(authorizer, media=self.media).export(action)
        files, manifest = self.read_bundle(result)
        runtime = json.loads(files["diagnostics/runtime.json"])

        self.assertEqual(authorizer.confirmations[0][0], action)
        self.assertEqual(
            [(item.category, item.item_count)
             for item in authorizer.confirmations[0][1].included_categories],
            [("runtime", 2)])
        self.assertEqual(authorizer.confirmations[0][1].selected_media_ids, ())
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
        action = DiagnosticExportAction(self.output, ("clip_b", "clip_a"))
        result = await self.make_service(Permit(), media=self.media).export(action)
        files, manifest = self.read_bundle(result)

        self.assertEqual(self.media.resolved, ["clip_b", "clip_a"])
        self.assertEqual(self.media.released, ["clip_b", "clip_a"])
        self.assertEqual(self.media.max_active, 1)
        self.assertEqual(self.media.active, 0)
        self.assertTrue(self.media.read_requests)
        self.assertLessEqual(max(self.media.read_requests), 64 * 1024)
        self.assertEqual(result.included_media_count, 2)
        self.assertEqual(len([name for name in files if name.startswith("media/")]), 2)
        self.assertFalse(any(media_id.encode() in result.bundle_path.read_bytes()
                             for media_id in action.selected_media_ids))
        media_entry = next(item for item in manifest["included_categories"]
                           if item["category"] == "raw_monitoring_media")
        self.assertEqual(media_entry["item_count"], 2)

    async def test_pressure_and_hard_stop_deny_before_file_or_media_open(self):
        for reason in ("STORAGE_PRESSURE", "STORAGE_HARD_STOP",
                       "STORAGE_INVALID_RESERVATION"):
            with self.subTest(reason=reason):
                self.policy.denial = RecordingError(reason)
                service = self.make_service(Permit(), media=self.media)
                with self.assertRaisesRegex(DiagnosticExportError, reason):
                    await service.export(DiagnosticExportAction(
                        self.output, ("clip_a",)))
                self.assertEqual(list(self.output.iterdir()), [])
                self.assertEqual(self.media.resolved, [])
                self.assertEqual(self.policy.releases, 0)
                self.policy.denial = None

    async def test_policy_denial_never_relays_its_own_message_to_the_caller(self):
        """Regression: a composed policy's error type/value stays off the boundary."""
        private = "/private/deployment/mount SYNTHETIC_PRIVATE_VALUE"
        self.policy.denial = RecordingError(private)
        service = self.make_service(Permit(), media=self.media)
        with self.assertRaises(DiagnosticExportError) as raised:
            await service.export(DiagnosticExportAction(self.output, ("clip_a",)))

        self.assertEqual(str(raised.exception),
                         "diagnostic storage admission was denied")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.media.resolved, [])

    async def test_media_zip_and_fsync_run_in_bounded_worker(self):
        event_loop_thread = threading.get_ident()
        zip_threads = []
        fsync_threads = []
        original_writestr = ZipFile.writestr
        original_fsync = os.fsync
        test_case = self

        class LoopBoundOwner(OwnerAuthorization):
            async def require_owner_caller(inner_self, action):
                test_case.assertEqual(threading.get_ident(), event_loop_thread)
                await super().require_owner_caller(action)

            async def require_owner_export(inner_self, action, confirmation):
                test_case.assertEqual(threading.get_ident(), event_loop_thread)
                await super().require_owner_export(action, confirmation)

        def observed_writestr(archive, *args, **kwargs):
            zip_threads.append(threading.get_ident())
            return original_writestr(archive, *args, **kwargs)

        def observed_fsync(descriptor):
            fsync_threads.append(threading.get_ident())
            return original_fsync(descriptor)

        with patch("app.diagnostics.export.ZipFile.writestr", new=observed_writestr), \
                patch("app.diagnostics.export.os.fsync", side_effect=observed_fsync):
            await self.make_service(LoopBoundOwner(), media=self.media).export(
                DiagnosticExportAction(self.output, ("clip_a",)))

        worker_threads = self.media.worker_threads + zip_threads + fsync_threads
        self.assertTrue(worker_threads)
        self.assertTrue(all(item != event_loop_thread for item in worker_threads))
        self.assertEqual(self.media.max_active, 1)

    async def test_admission_release_and_bundle_io_use_the_policy_owning_worker(self):
        """Regression: admission off the owning worker is rejected by the policy."""
        result = await self.make_service(Permit(), media=self.media).export(
            DiagnosticExportAction(self.output, ("clip_a",)))

        self.assertTrue(result.bundle_path.exists())
        self.assertEqual(set(self.policy.admit_threads), {self.policy.owner})
        self.assertEqual(set(self.policy.release_threads), {self.policy.owner})
        self.assertNotIn(threading.get_ident(), self.policy.admit_threads)
        # The reservation is held across the write, so the archive itself is
        # produced on the same owning worker rather than a detached thread.
        self.assertIn(self.policy.owner, self.media.worker_threads)

    async def test_repository_main_storage_policy_admits_diagnostic_bundles(self):
        """Regression: the composed MainStoragePolicy must not reject every export."""
        limits = StorageLimits(
            recording_limit_bytes=10_000_000, critical_allowance_bytes=1_000_000,
            hard_reserve_bytes=1_000_000, pressure_free_bytes=2_000_000,
            recovery_free_bytes=3_000_000, recovery_allocation_bytes=5_000_000,
            write_overhead_bytes=100_000, max_request_bytes=5_000_000,
            cleanup_batch_size=10)

        class SyntheticInventory:
            def usage_bytes(inner_self, *, starred_only=False, critical_only=False):
                return 0

        class RecordingReclaimer:
            def __init__(inner_self):
                inner_self.calls = []

            def expired(inner_self, now_ms, limit):
                inner_self.calls.append("expired")
                return 0

            def oldest(inner_self, limit):
                inner_self.calls.append("oldest")
                return 0

        reclaimer = RecordingReclaimer()

        def build_on_owning_worker():
            policy = MainStoragePolicy(
                limits, lambda: FilesystemSpace(50_000_000, 100_000_000),
                lambda: 0, lambda transition: None)
            policy.bind(SyntheticInventory(), reclaimer)
            return policy

        policy = self.worker.submit(build_on_owning_worker).result()
        with self.assertRaisesRegex(RecordingError, "STORAGE_POLICY_UNAVAILABLE"):
            await asyncio.to_thread(policy.admit_external, 1)

        result = await self.make_service(
            Permit(), media=self.media, policy=policy).export(
                DiagnosticExportAction(self.output, ("clip_a",)))
        self.assertTrue(result.bundle_path.exists())
        self.assertEqual(
            0, self.worker.submit(lambda: policy.status().reserved_bytes).result())
        # A support bundle must never delete monitoring evidence to fit.
        self.assertEqual(reclaimer.calls, [])

    async def test_output_outside_the_admitted_filesystem_is_refused_before_admission(self):
        admitted = self.storage_filesystem
        foreign = (RootIdentity(admitted.device + 1, admitted.inode),
                   RootIdentity(admitted.device + 7, 0))
        for identity in foreign:
            with self.subTest(device=identity.device):
                service = self.make_service(
                    Permit(), media=self.media, storage_filesystem=identity)
                with self.assertRaisesRegex(DiagnosticExportError, "not admitted"):
                    await service.export(
                        DiagnosticExportAction(self.output, ("clip_a",)))

        os.chmod(self.output, 0o777)
        try:
            service = self.make_service(Permit(), media=self.media)
            with self.assertRaisesRegex(DiagnosticExportError, "not admitted"):
                await service.export(DiagnosticExportAction(self.output, ("clip_a",)))
        finally:
            os.chmod(self.output, 0o700)

        self.assertEqual(self.policy.reservations, [])
        self.assertEqual(self.media.resolved, [])
        self.assertEqual(list(self.output.iterdir()), [])

    async def test_symlinked_output_path_components_are_refused(self):
        """Regression: a replaced parent must not redirect the published bundle."""
        real = self.output / "real"
        real.mkdir(mode=0o700)
        leaf_link = self.output / "leaf"
        leaf_link.symlink_to(real, target_is_directory=True)
        parent_link = self.output / "parent"
        parent_link.symlink_to(self.output, target_is_directory=True)

        for target in (leaf_link, parent_link / "real"):
            with self.subTest(target=str(target.relative_to(self.output))):
                service = self.make_service(Permit(), media=self.media)
                with self.assertRaisesRegex(DiagnosticExportError, "not admitted"):
                    await service.export(
                        DiagnosticExportAction(target, ("clip_a",)))

        self.assertEqual(self.policy.reservations, [])
        self.assertEqual(self.media.resolved, [])
        self.assertEqual(list(real.iterdir()), [])

        # The real directory itself is still accepted.
        result = await self.make_service(Permit()).export(
            DiagnosticExportAction(real))
        self.assertEqual(result.bundle_path.parent, real)

    def test_output_directory_must_be_absolute_and_normalized(self):
        for path in (Path("relative/bundles"),
                     self.output / ".." / self.output.name,
                     Path(".")):
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                DiagnosticExportAction(path)

    async def test_admission_binds_the_pinned_descriptor_without_resampling_a_path(self):
        """Regression: no pathname sample may race admission on the owning worker."""
        real_stat = os.stat
        sampled_on_owning_worker = []

        def observed_stat(path, *args, **kwargs):
            # Only deployment paths matter; stdlib traceback/linecache machinery
            # also stats source files on whichever thread raises.
            if (threading.get_ident() == self.policy.owner
                    and str(path).startswith(str(self.output))):
                sampled_on_owning_worker.append(str(path))
            return real_stat(path, *args, **kwargs)

        service = self.make_service(Permit(), media=self.media)
        with patch("app.diagnostics.export.os.stat", side_effect=observed_stat):
            result = await service.export(
                DiagnosticExportAction(self.output, ("clip_a",)))

        self.assertTrue(result.bundle_path.exists())
        self.assertEqual(sampled_on_owning_worker, [])
        self.assertEqual(set(self.policy.admit_threads), {self.policy.owner})

    async def test_release_failure_after_publication_removes_the_bundle(self):
        """Regression: a caller that receives no bundle name leaves no archive."""
        self.policy.release_failure = "synthetic release failure"
        service = self.make_service(Permit(), media=self.media)
        with self.assertRaisesRegex(
                DiagnosticExportError, "diagnostic storage state is uncertain"):
            await service.export(DiagnosticExportAction(self.output, ("clip_a",)))

        self.assertEqual(len(self.policy.reservations), 1)
        self.assertEqual(self.policy.releases, 0)
        self.assertEqual(list(self.output.iterdir()), [])
        with self.assertRaisesRegex(
                DiagnosticExportError, "diagnostic storage state is uncertain"):
            await service.export(DiagnosticExportAction(self.output))
        self.assertEqual(len(self.policy.reservations), 1)

    async def test_directory_fsync_failure_removes_published_bundle_and_releases(self):
        calls = []

        def fail_publication_fsync(descriptor):
            calls.append(descriptor)
            self.assertTrue(self.policy.active)
            if len(calls) == 2:
                raise OSError("synthetic directory fsync failure")

        with patch("app.diagnostics.export.os.fsync",
                   side_effect=fail_publication_fsync):
            with self.assertRaisesRegex(
                    DiagnosticExportError, "diagnostic bundle write failed"):
                await self.make_service(Permit()).export(
                    DiagnosticExportAction(self.output))

        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.policy.releases, 1)
        self.assertFalse(self.policy.active)

    async def test_cleanup_fsync_failure_retains_reservation_and_blocks_service(self):
        calls = []

        def fail_publication_and_cleanup_fsync(descriptor):
            calls.append(descriptor)
            if len(calls) in {2, 3}:
                raise OSError("synthetic directory fsync failure")

        service = self.make_service(Permit())
        with patch("app.diagnostics.export.os.fsync",
                   side_effect=fail_publication_and_cleanup_fsync):
            with self.assertRaisesRegex(
                    DiagnosticExportError, "diagnostic storage state is uncertain"):
                await service.export(DiagnosticExportAction(self.output))

        self.assertEqual(len(calls), 3)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(len(self.policy.reservations), 1)
        self.assertEqual(self.policy.releases, 0)
        self.assertTrue(self.policy.active)
        with self.assertRaisesRegex(
                DiagnosticExportError, "diagnostic storage state is uncertain"):
            await service.export(DiagnosticExportAction(self.output))
        self.assertEqual(len(self.policy.reservations), 1)

    @staticmethod
    def blocking_media_class(entered, proceed):
        class BlockingMedia(SelectedMedia):
            @contextmanager
            def open_selected(inner_self, media_id):
                inner_self.worker_threads.append(threading.get_ident())
                inner_self.active += 1
                inner_self.max_active = max(inner_self.max_active, inner_self.active)
                inner_self.resolved.append(media_id)
                source = BytesIO(inner_self.content(media_id))

                class BlockingReader:
                    def readinto(reader_self, buffer):
                        entered.set()
                        if not proceed.wait(timeout=5):
                            raise AssertionError("timed out waiting to continue")
                        inner_self.read_requests.append(len(buffer))
                        return source.readinto(buffer)

                try:
                    yield MediaAsset(BlockingReader())
                finally:
                    inner_self.active -= 1
                    inner_self.released.append(media_id)

        return BlockingMedia

    async def test_cancelled_export_durably_removes_its_published_bundle(self):
        """Regression: a cancelled caller never leaves a readable archive behind."""
        entered = threading.Event()
        proceed = threading.Event()
        media = self.blocking_media_class(entered, proceed)()
        service = self.make_service(Permit(), media=media)

        export = asyncio.create_task(service.export(
            DiagnosticExportAction(self.output, ("clip_a",))))
        while not entered.is_set():
            await asyncio.sleep(0)
        export.cancel()
        proceed.set()
        with self.assertRaises(asyncio.CancelledError):
            await export

        self.assertEqual(media.released, ["clip_a"])
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.policy.reservations and self.policy.releases, 1)
        self.assertFalse(self.policy.active)

        later = await service.export(DiagnosticExportAction(self.output))
        self.assertTrue(later.bundle_path.exists())
        self.assertEqual([item.name for item in self.output.iterdir()],
                         [later.bundle_path.name])

    async def test_cancellation_cleanup_refuses_a_replaced_publication_directory(self):
        """Regression: an absent file in a different directory is not deletion."""
        entered = threading.Event()
        proceed = threading.Event()
        target = self.output / "bundles"
        target.mkdir(mode=0o700)
        moved = self.output / "bundles-renamed"
        media = self.blocking_media_class(entered, proceed)()

        class RenamingWorker:
            def __init__(inner_self, executor):
                inner_self.executor = executor
                inner_self.calls = 0

            def submit(inner_self, call):
                inner_self.calls += 1
                if inner_self.calls == 2:
                    # Rename the publication directory away and put another
                    # valid private directory on the same device at its path,
                    # just before cancellation cleanup reopens that pathname.
                    target.rename(moved)
                    target.mkdir(mode=0o700)
                return inner_self.executor.submit(call)

        worker = RenamingWorker(self.worker)
        service = DiagnosticExportService(
            Permit(), self.source, self.policy, worker,
            self.storage_filesystem, media)
        export = asyncio.create_task(service.export(
            DiagnosticExportAction(target, ("clip_a",))))
        while not entered.is_set():
            await asyncio.sleep(0)
        export.cancel()
        proceed.set()
        with self.assertRaises(asyncio.CancelledError):
            await export

        self.assertEqual(worker.calls, 2)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(
            len([item for item in moved.iterdir() if item.suffix == ".zip"]), 1)
        with self.assertRaisesRegex(
                DiagnosticExportError, "diagnostic storage state is uncertain"):
            await service.export(DiagnosticExportAction(target))

    async def test_cancelled_write_drains_worker_before_next_export(self):
        entered = threading.Event()
        proceed = threading.Event()
        media = self.blocking_media_class(entered, proceed)()
        service = self.make_service(Permit(), media=media)

        first = asyncio.create_task(service.export(
            DiagnosticExportAction(self.output, ("clip_a",))))
        while not entered.is_set():
            await asyncio.sleep(0)
        first.cancel()
        second = asyncio.create_task(service.export(
            DiagnosticExportAction(self.output, ("clip_b",))))
        await asyncio.sleep(0.01)
        self.assertEqual(len(self.policy.reservations), 1)
        self.assertEqual(media.max_active, 1)
        self.assertEqual(media.resolved, ["clip_a"])

        proceed.set()
        with self.assertRaises(asyncio.CancelledError):
            await first
        second_result = await second
        self.assertTrue(second_result.bundle_path.exists())
        self.assertEqual(media.max_active, 1)
        self.assertEqual(media.released, ["clip_a", "clip_b"])
        self.assertEqual(self.policy.releases, 2)
        self.assertFalse(self.policy.active)
        # Only the export whose caller received a bundle name survives.
        self.assertEqual([item.name for item in self.output.iterdir()],
                         [second_result.bundle_path.name])

    async def test_cancelled_prepare_drains_worker_and_repeated_cancel_keeps_slot(self):
        entered = threading.Event()
        proceed = threading.Event()

        class BlockingDiagnostics(SyntheticDiagnostics):
            def __init__(inner_self):
                inner_self.calls = 0
                inner_self.active = 0
                inner_self.max_active = 0

            def collect(inner_self):
                inner_self.calls += 1
                inner_self.active += 1
                inner_self.max_active = max(
                    inner_self.max_active, inner_self.active)
                try:
                    entered.set()
                    if not proceed.wait(timeout=5):
                        raise AssertionError("timed out waiting to continue")
                    return super().collect()
                finally:
                    inner_self.active -= 1

        source = BlockingDiagnostics()
        service = self.make_service(Permit(), source=source)
        first = asyncio.create_task(service.export(DiagnosticExportAction(self.output)))
        while not entered.is_set():
            await asyncio.sleep(0)
        first.cancel()
        await asyncio.sleep(0)
        first.cancel()
        second = asyncio.create_task(service.export(DiagnosticExportAction(self.output)))
        await asyncio.sleep(0.01)
        self.assertEqual(source.calls, 1)
        self.assertEqual(source.max_active, 1)
        self.assertFalse(first.done())

        proceed.set()
        with self.assertRaises(asyncio.CancelledError):
            await first
        second_result = await second
        self.assertTrue(second_result.bundle_path.exists())
        self.assertEqual(source.calls, 2)
        self.assertEqual(source.max_active, 1)

    async def test_owner_biometric_template_and_embedding_never_reach_a_bundle(self):
        """Issue #25 enrolls an Owner template locally; export is never its exit."""
        template = b"SYNTHETIC_OWNER_TEMPLATE_BYTES"
        encoded = template.hex()

        class OwnerVerificationDiagnostics:
            def collect(inner_self):
                return (
                    DiagnosticDocument(DiagnosticCategory.SECURITY, (
                        DiagnosticField("owner_biometric.template", encoded),
                        DiagnosticField("owner_biometric.embedding", encoded),
                        DiagnosticField("status", SafeDiagnosticState.OK),
                    )),
                )

        source = OwnerVerificationDiagnostics()
        result = await self.make_service(Permit(), source=source).export(
            DiagnosticExportAction(self.output))
        files, manifest = self.read_bundle(result)

        self.assertNotIn(encoded.encode(), result.bundle_path.read_bytes())
        self.assertNotIn(template, result.bundle_path.read_bytes())
        self.assertEqual(json.loads(files["diagnostics/security.json"]),
                         {"status": "ok"})
        self.assertEqual(
            [item for item in manifest["exclusions"]
             if item["reason"] == "owner_biometric"],
            [{"category": "security", "reason": "owner_biometric", "count": 2}])

        # Owner-selected raw media is not an exception for biometric material.
        selected = await self.make_service(
            Permit(), source=source, media=self.media).export(
                DiagnosticExportAction(self.output, ("clip_a",)))
        self.assertNotIn(encoded.encode(), selected.bundle_path.read_bytes())
        self.assertEqual(selected.included_media_count, 1)

        # A producer cannot smuggle a template through another field name.
        for name in ("status", "component", "version", "reason_code",
                     "owner_template", "owner_biometric.vector",
                     "hardware_identifier.owner_face"):
            with self.subTest(name=name), self.assertRaises((TypeError, ValueError)):
                DiagnosticField(name, encoded)
        for value in (template, bytearray(template), memoryview(template),
                      [encoded]):
            with self.subTest(value=type(value).__name__), self.assertRaises(
                    TypeError):
                DiagnosticField("owner_biometric.template", value)

    async def test_media_stream_is_generated_and_copied_in_bounded_chunks(self):
        media_size = 3 * 64 * 1024 + 17
        requests = []

        class GeneratedMedia:
            def describe_selected(inner_self, media_id):
                return MediaDescriptor(media_size)

            @contextmanager
            def open_selected(inner_self, media_id):
                remaining = media_size

                class GeneratedReader:
                    def readinto(reader_self, buffer):
                        nonlocal remaining
                        requests.append(len(buffer))
                        count = min(len(buffer), remaining)
                        buffer[:count] = b"x" * count
                        remaining -= count
                        return count

                yield MediaAsset(GeneratedReader())

        result = await self.make_service(Permit(), media=GeneratedMedia()).export(
            DiagnosticExportAction(self.output, ("clip_a",)))
        with ZipFile(result.bundle_path) as archive:
            with archive.open("media/0001.bin") as stored:
                self.assertEqual(len(stored.read()), media_size)
        self.assertGreater(len(requests), 3)
        self.assertLessEqual(max(requests), 64 * 1024)

    async def test_media_stream_size_and_bundle_caps_fail_before_authorization(self):
        class OversizedMedia(SelectedMedia):
            def describe_selected(inner_self, media_id):
                return MediaDescriptor(512 * 1024 * 1024 + 1)

        authorizer = Permit()
        with self.assertRaises(DiagnosticExportError):
            await self.make_service(authorizer, media=OversizedMedia()).export(
                DiagnosticExportAction(self.output, ("clip_a",)))

        class ExcessiveAggregateMedia(SelectedMedia):
            def describe_selected(inner_self, media_id):
                return MediaDescriptor(400 * 1024 * 1024)

        with self.assertRaisesRegex(DiagnosticExportError, "too large"):
            await self.make_service(
                authorizer, media=ExcessiveAggregateMedia()).export(
                    DiagnosticExportAction(
                        self.output, ("clip_a", "clip_b", "clip_c")))
        self.assertEqual(authorizer.confirmations, [])
        self.assertEqual(self.policy.reservations, [])

    async def test_media_size_change_removes_partial_bundle_and_releases_each_item(self):
        class ChangedMedia(SelectedMedia):
            def describe_selected(inner_self, media_id):
                described = super().describe_selected(media_id)
                return MediaDescriptor(described.size_bytes + 1, described.media_type)

        media = ChangedMedia()
        with self.assertRaisesRegex(
                DiagnosticExportError, "diagnostic bundle write failed"):
            await self.make_service(Permit(), media=media).export(
                DiagnosticExportAction(self.output, ("clip_a",)))

        self.assertEqual(media.resolved, ["clip_a"])
        self.assertEqual(media.released, ["clip_a"])
        self.assertEqual(media.active, 0)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.policy.releases, 1)

    async def test_non_owner_caller_is_refused_before_collection_or_media_lookup(self):
        """Regression: a non-Owner cannot probe selected-media IDs for existence."""
        collected = []

        class WatchedSource(SyntheticDiagnostics):
            def collect(inner_self):
                collected.append(threading.get_ident())
                return super().collect()

        authorizer = DenyCaller()
        service = self.make_service(
            authorizer, source=WatchedSource(), media=self.media)
        for selected in ((), ("clip_a",), ("unknown_clip",)):
            with self.subTest(selected=selected), self.assertRaises(PermissionError):
                await service.export(DiagnosticExportAction(self.output, selected))
        self.assertEqual(collected, [])
        self.assertEqual(self.media.worker_threads, [])
        self.assertEqual(self.media.resolved, [])
        self.assertEqual(authorizer.confirmations, [])
        self.assertEqual(self.policy.reservations, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_service_requires_a_complete_owner_boundary_and_storage_worker(self):
        class ContentsOnly:
            async def require_owner_export(inner_self, action, confirmation):
                return None

        class ReclaimingPolicyOnly:
            def admit(inner_self, media_bytes, *, critical):
                raise AssertionError("reclaiming admission must not be reachable")

            def release(inner_self):
                return None

        with self.assertRaises(TypeError):
            DiagnosticExportService(
                Permit(), self.source, ReclaimingPolicyOnly(), self.worker,
                self.storage_filesystem)

        cases = (
            ("incomplete-owner-boundary", ContentsOnly(), self.worker,
             self.storage_filesystem),
            ("no-owner-boundary", object(), self.worker, self.storage_filesystem),
            ("no-storage-worker", Permit(), object(), self.storage_filesystem),
            ("path-instead-of-identity", Permit(), self.worker, self.output),
            ("non-numeric-identity", Permit(), self.worker,
             RootIdentity("device", "inode")),
        )
        for label, authorizer, worker, filesystem in cases:
            with self.subTest(case=label), self.assertRaises(TypeError):
                DiagnosticExportService(
                    authorizer, self.source, self.policy, worker, filesystem)

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

    def prepared_route_application(self, human_authorizer, authorizer, media=None):
        application = FastAPI()
        application.state.human_authorizer = human_authorizer
        application.state.diagnostic_export_endpoint = DiagnosticExportEndpoint(
            self.make_service(authorizer, media=media), self.output)
        application.include_router(router)
        return application

    @staticmethod
    def response_body(messages):
        return b"".join(message.get("body", b"") for message in messages
                        if message["type"] == "http.response.body")

    @staticmethod
    async def post_export(application, selected_media_ids=()):
        body = json.dumps({"selected_media_ids": list(selected_media_ids)}).encode()
        return await request(
            application, "/diagnostics/export", method="POST", body=body,
            headers=((b"content-type", b"application/json"),))

    async def test_prepared_route_uses_fixed_endpoint_and_both_authorizers(self):
        observed = []

        class SystemAndOwnerPermit:
            async def require_system_access(inner_self, route_request: Request):
                observed.append("system")

            async def require_owner_access(inner_self, route_request: Request):
                observed.append("owner")

        authorizer = Permit()
        application = self.prepared_route_application(
            SystemAndOwnerPermit(), authorizer, self.media)
        result = await self.post_export(application)

        self.assertEqual(result[0]["status"], 200)
        self.assertEqual(observed, ["system", "owner"])
        self.assertEqual(authorizer.confirmations[0][0].output_directory, self.output)
        self.assertEqual(
            [(item.category, item.item_count)
             for item in authorizer.confirmations[0][1].included_categories],
            [("runtime", 2)])

    async def test_prepared_route_reports_fixed_statuses_without_failure_detail(self):
        """Regression: a denial or rejected selection never echoes local values."""
        class OwnerRoutePermit:
            async def require_system_access(inner_self, route_request: Request):
                return None

            async def require_owner_access(inner_self, route_request: Request):
                return None

        application = self.prepared_route_application(
            OwnerRoutePermit(), Permit(), self.media)

        rejected = await self.post_export(application, ("../clip",))
        self.assertEqual(rejected[0]["status"], 400)
        self.assertNotIn(b"../clip", self.response_body(rejected))

        self.policy.denial = RecordingError(
            "/private/deployment/mount SYNTHETIC_PRIVATE_VALUE")
        denied = await self.post_export(application, ("clip_a",))
        body = self.response_body(denied)
        self.assertEqual(denied[0]["status"], 503)
        self.assertNotIn(b"SYNTHETIC_PRIVATE_VALUE", body)
        self.assertNotIn(b"/private/deployment/mount", body)
        self.assertNotIn(b"clip_a", body)
        self.assertEqual(list(self.output.iterdir()), [])

    async def test_prepared_route_denies_an_invited_non_owner_before_the_endpoint(self):
        """Regression: system access alone must not reach a selected-media lookup."""
        observed = []

        class InvitedNonOwner:
            async def require_system_access(inner_self, route_request: Request):
                observed.append("system")

            async def require_owner_access(inner_self, route_request: Request):
                raise HTTPException(status_code=404, detail="Not Found")

        authorizer = Permit()
        application = self.prepared_route_application(
            InvitedNonOwner(), authorizer, self.media)
        result = await self.post_export(application, ("clip_a", "clip_b"))

        self.assertEqual(result[0]["status"], 404)
        self.assertEqual(observed, ["system"])
        self.assertEqual(authorizer.caller_actions, [])
        self.assertEqual(authorizer.confirmations, [])
        self.assertEqual(self.media.worker_threads, [])
        self.assertEqual(self.policy.reservations, [])
        self.assertEqual(list(self.output.iterdir()), [])

    async def test_prepared_route_fails_closed_without_a_composed_owner_gate(self):
        class SystemOnlyAuthorizer:
            async def require_system_access(inner_self, route_request: Request):
                return None

        authorizer = Permit()
        application = self.prepared_route_application(
            SystemOnlyAuthorizer(), authorizer, self.media)
        result = await self.post_export(application)

        self.assertEqual(result[0]["status"], 404)
        self.assertEqual(authorizer.caller_actions, [])
        self.assertEqual(self.media.worker_threads, [])
        self.assertEqual(list(self.output.iterdir()), [])

    async def test_writer_revalidates_duck_types_and_mutated_dtos_before_owner(self):
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

        authorizer = Permit()
        for source in (DuckSource(), DuckFieldsSource(), MutatedSource()):
            with self.subTest(source=type(source).__name__), self.assertRaises(
                    DiagnosticExportError):
                await self.make_service(authorizer, source=source).export(
                    DiagnosticExportAction(self.output))
        self.assertEqual(authorizer.confirmations, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_public_package_has_no_unconditionally_writable_exporter(self):
        import app.diagnostics as diagnostics

        self.assertFalse(hasattr(diagnostics, "DiagnosticExporter"))
