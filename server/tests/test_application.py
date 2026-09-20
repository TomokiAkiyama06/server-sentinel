import asyncio
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from fastapi import FastAPI, Request

from app.api.system import router
from app.auth.boundary import DenyAll
from app.audit import (
    ActorCategory, AuditAction, AuditOutcome, AuditStore, OwnerAuthorizationError,
    TargetKind,
)
from app.cameras.registry import CameraRegistry, SourceType
from app.main import create_app
from app.settings import Settings
from app.storage.schema import APPLICATION_MIGRATIONS
from app.storage.migrations import migrate
from tests.asgi import request


class ApplicationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.settings = Settings(Path(self.temporary.name))
        self.application = create_app(self.settings)

    async def test_lifespan_migrates_and_clears_readiness_at_shutdown(self):
        self.assertFalse(self.application.state.ready)
        async with self.application.router.lifespan_context(self.application):
            self.assertTrue(self.application.state.ready)
            with closing(self.application.state.database.connect()) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0],
                                 len(APPLICATION_MIGRATIONS))
            registry = CameraRegistry(self.application.state.database)
            source = registry.create_source(source_type=SourceType.LOCAL_UVC, name="Synthetic", enabled=True)
            self.assertEqual(source, registry.get_source(source.id))
        self.assertFalse(self.application.state.ready)

    async def test_lifespan_runs_audit_retention_cleanup(self):
        with closing(self.application.state.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        old = datetime(2020, 1, 1, tzinfo=timezone.utc)
        audit = AuditStore(self.application.state.database, clock=lambda: old)
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
        application = create_app(self.settings, audit_cleanup_interval_seconds=0.01)
        async with application.router.lifespan_context(application):
            old = datetime(2020, 1, 1, tzinfo=timezone.utc)
            AuditStore(application.state.database, clock=lambda: old).append(
                actor_category=ActorCategory.SYSTEM,
                action=AuditAction.CHANGE_ADMIN_SETTING,
                target_kind=TargetKind.ADMIN_SETTINGS,
                target_logical_id=uuid4(), outcome=AuditOutcome.SUCCEEDED,
            )
            await asyncio.sleep(0.03)
            self.assertEqual((), application.state.audit_store.list_records())

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
