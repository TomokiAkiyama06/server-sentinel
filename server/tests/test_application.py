import asyncio
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi import FastAPI, Request

from app.api.system import router
from app.auth.boundary import DenyAll
from app.audit import (
    ActorCategory, AuditAction, AuditOutcome, AuditStorageError, AuditStore,
    OwnerAuthorizationError,
    TargetKind,
)
from app.audit.runtime import AuditRetentionHealth, AuditRetentionRuntime
from app.cameras.registry import CameraRegistry, SourceType
from app.main import create_app
from app.settings import Settings
from app.storage.schema import APPLICATION_MIGRATIONS
from app.storage.migrations import migrate
from tests.asgi import request


@contextmanager
def synthetic_admission():
    """Stands in for a bound Main Server storage admission reservation."""
    yield


class ApplicationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.settings = Settings(Path(self.temporary.name))
        self.application = create_app(self.settings,
                                      storage_reservation=synthetic_admission)

    async def test_lifespan_migrates_and_clears_readiness_at_shutdown(self):
        self.assertFalse(self.application.state.ready)
        async with self.application.router.lifespan_context(self.application):
            self.assertTrue(self.application.state.ready)
            with closing(self.application.state.database.connect()) as connection:
                count = connection.execute(
                    "SELECT count(*) FROM schema_migrations"
                ).fetchone()[0]
                self.assertEqual(count, len(APPLICATION_MIGRATIONS))
                # The health and integrity workers are constructed after
                # application startup.  Their durable journals must already
                # exist in the production migration catalog, not only in
                # isolated feature tests.
                tables = {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                self.assertTrue({
                    "recording_selftest", "integrity_baseline", "integrity_audit",
                    "integrity_status", "integrity_outbox", "integrity_overflow",
                    "security_admin_audit_records",
                } <= tables)
            registry = CameraRegistry(
                self.application.state.database, unaudited_writes=True,
            )
            source = registry.create_source(source_type=SourceType.LOCAL_UVC, name="Synthetic",
                                            enabled=True)
            self.assertEqual(source, registry.get_source(source.id))
        self.assertFalse(self.application.state.ready)

    async def test_lifespan_runs_audit_retention_cleanup(self):
        with closing(self.application.state.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        old = datetime(2020, 1, 1, tzinfo=timezone.utc)
        audit = AuditStore(self.application.state.database, clock=lambda: old,
                           reservation=synthetic_admission)
        audit.append(
            actor_category=ActorCategory.SYSTEM,
            action=AuditAction.CHANGE_ADMIN_SETTING,
            target_kind=TargetKind.ADMIN_SETTINGS,
            target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
        )
        self.assertEqual(1, len(audit.list_records()))
        async with self.application.router.lifespan_context(self.application):
            self.assertEqual((), self.application.state.audit_store.list_records())

    async def test_runtime_periodically_cleans_expired_audit_records(self):
        application = create_app(self.settings, audit_cleanup_interval_seconds=0.01,
                                 storage_reservation=synthetic_admission)
        async with application.router.lifespan_context(application):
            old = datetime(2020, 1, 1, tzinfo=timezone.utc)
            AuditStore(application.state.database, clock=lambda: old,
                       reservation=synthetic_admission).append(
                actor_category=ActorCategory.SYSTEM,
                action=AuditAction.CHANGE_ADMIN_SETTING,
                target_kind=TargetKind.ADMIN_SETTINGS,
                target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
            )
            await asyncio.sleep(0.03)
            self.assertEqual((), application.state.audit_store.list_records())

    async def test_scheduled_cleanup_retries_and_reports_transient_failure(self):
        class TransientStore:
            def __init__(self):
                self.calls = 0

            def cleanup_expired(self):
                self.calls += 1
                if self.calls == 1:
                    raise AuditStorageError("synthetic transient failure")
                return 2

        store = TransientStore()
        runtime = AuditRetentionRuntime(store, interval_seconds=0.001)
        task = asyncio.create_task(runtime.run())
        try:
            for _ in range(100):
                if store.calls >= 2:
                    break
                await asyncio.sleep(0.001)
            self.assertGreaterEqual(store.calls, 2)
            self.assertEqual(1, runtime.total_failures)
            self.assertEqual(0, runtime.consecutive_failures)
            self.assertEqual(AuditRetentionHealth.HEALTHY, runtime.health)
            self.assertEqual(2, runtime.last_deleted_count)
            self.assertIsNotNone(runtime.last_success_at)
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_runtime_owner_admin_defaults_to_denial_with_audit(self):
        async with self.application.router.lifespan_context(self.application):
            with self.assertRaises(OwnerAuthorizationError):
                self.application.state.owner_administration.create_capture_node(
                    {"synthetic": "untrusted"}, "Denied node",
                )
            self.assertEqual(
                AuditOutcome.DENIED,
                self.application.state.audit_store.list_records()[0].outcome,
            )
            with closing(self.application.state.database.connect()) as connection:
                self.assertEqual(0, connection.execute(
                    "SELECT count(*) FROM capture_nodes"
                ).fetchone()[0])

    async def test_startup_and_scheduled_audit_cleanup_use_storage_admission(self):
        acquired = []

        @contextmanager
        def reservation():
            acquired.append(True)
            yield

        application = create_app(self.settings, storage_reservation=reservation,
                                 audit_cleanup_interval_seconds=0.01)
        self.assertTrue(application.state.audit_storage_admitted)

        with closing(application.state.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        old = datetime(2020, 1, 1, tzinfo=timezone.utc)
        AuditStore(application.state.database, clock=lambda: old,
                   reservation=reservation).append(
            actor_category=ActorCategory.SYSTEM,
            action=AuditAction.CHANGE_ADMIN_SETTING,
            target_kind=TargetKind.ADMIN_SETTINGS,
            target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
        )
        seeded = len(acquired)
        async with application.router.lifespan_context(application):
            # Startup retention cleanup runs inside the storage reservation.
            self.assertGreater(len(acquired), seeded)
            self.assertEqual((), application.state.audit_store.list_records())

    async def test_degraded_audit_retention_does_not_block_monitoring_startup(self):
        application = create_app(self.settings, audit_cleanup_interval_seconds=1000,
                                 storage_reservation=synthetic_admission)
        with closing(application.state.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        with patch.object(application.state.audit_store, "cleanup_expired_batch",
                          side_effect=AuditStorageError("synthetic unavailable")):
            async with application.router.lifespan_context(application):
                # A refused retention run is visible as degraded health, not as
                # an offline physical-security monitor.
                self.assertTrue(application.state.ready)
                self.assertEqual(AuditRetentionHealth.DEGRADED,
                                 application.state.audit_retention.health)
                self.assertEqual(1, application.state.audit_retention.total_failures)

    async def test_degraded_startup_cleanup_is_retried_on_the_short_interval(self):
        class FailingOnceStore:
            def __init__(self):
                self.calls = 0

            def cleanup_expired(self):
                self.calls += 1
                if self.calls == 1:
                    raise AuditStorageError("synthetic startup failure")
                return 0

        store = FailingOnceStore()
        runtime = AuditRetentionRuntime(store, interval_seconds=1000,
                                        retry_seconds=0.001)
        with self.assertRaises(AuditStorageError):
            await runtime.startup_cleanup()
        self.assertEqual(AuditRetentionHealth.DEGRADED, runtime.health)
        task = asyncio.create_task(runtime.run())
        try:
            for _ in range(200):
                if store.calls >= 2:
                    break
                await asyncio.sleep(0.001)
            # Retention is not delayed by a whole interval after a failure.
            self.assertGreaterEqual(store.calls, 2)
            self.assertEqual(AuditRetentionHealth.HEALTHY, runtime.health)
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_cleanup_batch_runs_off_event_loop_and_cancellation_joins_worker(self):
        started = threading.Event()
        release = threading.Event()
        event_thread = threading.get_ident()

        class BlockingStore:
            cleanup_batch_size = 1

            def cleanup_expired_batch(self):
                self.worker_thread = threading.get_ident()
                started.set()
                release.wait(2)
                return 0

        store = BlockingStore()
        runtime = AuditRetentionRuntime(store)
        task = asyncio.create_task(runtime.startup_cleanup())
        try:
            for _ in range(100):
                if started.is_set():
                    break
                await asyncio.sleep(0.001)
            self.assertTrue(started.is_set())
            self.assertNotEqual(event_thread, store.worker_thread)
            # The cleanup is still blocked, but the asyncio thread can run.
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_application_schedules_additional_private_audit_store(self):
        class PrivateAuditStore:
            cleanup_batch_size = 2

            def __init__(self):
                self.results = [2, 1]

            def cleanup_expired_batch(self):
                return self.results.pop(0) if self.results else 0

        private = PrivateAuditStore()
        application = create_app(
            self.settings, storage_reservation=synthetic_admission,
            audit_cleanup_interval_seconds=1000,
            audit_retention_stores=(private,),
        )
        async with application.router.lifespan_context(application):
            for _ in range(100):
                if not private.results:
                    break
                await asyncio.sleep(0.001)
            self.assertEqual([], private.results)
            self.assertEqual(AuditRetentionHealth.HEALTHY,
                             application.state.audit_retention.health)

    async def test_unbound_storage_admission_refuses_audit_writes(self):
        application = create_app(self.settings, audit_cleanup_interval_seconds=1000)
        # Without a bound Main Server storage policy the deployment cannot
        # verify the hard filesystem reserve, so audit writes fail closed
        # instead of being admitted against an unknown reserve.
        self.assertFalse(application.state.audit_storage_admitted)
        async with application.router.lifespan_context(application):
            self.assertTrue(application.state.ready)
            self.assertEqual(AuditRetentionHealth.DEGRADED,
                             application.state.audit_retention.health)
            with self.assertRaises(AuditStorageError):
                application.state.audit_store.append(
                    actor_category=ActorCategory.SYSTEM,
                    action=AuditAction.CHANGE_ADMIN_SETTING,
                    target_kind=TargetKind.ADMIN_SETTINGS,
                    target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
                )
            # The default authorizer still denies, and an unwritable denial
            # record never becomes a storage error for the denied caller.
            with self.assertRaises(OwnerAuthorizationError):
                application.state.owner_administration.create_capture_node(
                    {"synthetic": "untrusted"}, "Refused node",
                )
            self.assertTrue(
                application.state.owner_administration.service.audit_delivery_failed,
            )
            # Nothing was written, and reading audit history still works.
            self.assertEqual((), application.state.audit_store.list_records())
            with closing(application.state.database.connect()) as connection:
                self.assertEqual(0, connection.execute(
                    "SELECT count(*) FROM capture_nodes"
                ).fetchone()[0])

    async def test_invalid_database_fails_startup_without_leaking_exception_values(self):
        self.settings.database_path.write_text("SYNTHETIC_PRIVATE_VALUE")
        with self.assertRaisesRegex(RuntimeError, "^application startup failed$"):
            async with self.application.router.lifespan_context(self.application):
                self.fail("must not start")
        self.assertFalse(self.application.state.ready)

    async def test_all_human_paths_methods_and_forged_headers_get_same_generic_denial(self):
        expected = await request(self.application)
        for path in ("/health", "/version", "/openapi.json", "/docs", "/redoc", "/api/live/1",
                     "/api/sources", "/api/capture-nodes", "/missing/"):
            for method in ("GET", "POST", "HEAD", "OPTIONS", "DELETE"):
                with self.subTest(path=path, method=method):
                    actual = await request(self.application, path, method=method, headers=[
                        (b"tailscale-user-login", b"synthetic@example.invalid"),
                        (b"authorization", b"synthetic-credential"),
                    ])
                    self.assertEqual(actual, expected)
        self.assertEqual(expected[0]["status"], 404)
        self.assertEqual(expected[1]["body"], b'{"detail":"Not Found"}')
        self.assertFalse(self.application.routes)

    async def test_injected_allow_authorizer_still_cannot_enable_human_surface(self):
        class Permit:
            async def require_system_access(self, request: Request) -> None:
                raise AssertionError("unmounted authorization must not run")
        application = create_app(self.settings, human_authorizer=Permit())
        result = await request(application, "/health")
        self.assertEqual(result[0]["status"], 404)

    async def test_websocket_never_accepts_connection(self):
        result = await request(self.application, "/api/live/1", kind="websocket")
        self.assertEqual(result, [{"type": "websocket.close", "code": 1008}])

    async def test_prepared_system_routes_deny_without_future_authorizer(self):
        # An isolated test app verifies the DI boundary, not production exposure.
        application = FastAPI()
        application.state.human_authorizer = DenyAll()
        application.include_router(router)
        for path in ("/health", "/version"):
            result = await request(application, path)
            self.assertEqual(result[0]["status"], 404)

    async def test_prepared_handlers_behind_injected_test_authorization(self):
        class Permit:
            async def require_system_access(self, request: Request) -> None:
                return None
        application = FastAPI()
        application.state.human_authorizer = Permit()
        application.state.ready = False
        application.include_router(router)
        result = await request(application, "/health")
        self.assertEqual(result[1]["body"], b'{"foundation":"unavailable"}')
        result = await request(application, "/version")
        self.assertEqual(result[0]["status"], 200)
