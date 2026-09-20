from contextlib import closing
from pathlib import Path
import tempfile
import unittest

from fastapi import FastAPI, Request

from app.api.system import router
from app.auth.boundary import DenyAll
from app.main import create_app
from app.settings import Settings
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
                self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0], 1)
        self.assertFalse(self.application.state.ready)

    async def test_invalid_database_fails_startup_without_leaking_exception_values(self):
        self.settings.database_path.write_text("SYNTHETIC_PRIVATE_VALUE")
        with self.assertRaisesRegex(RuntimeError, "^application startup failed$"):
            async with self.application.router.lifespan_context(self.application):
                self.fail("must not start")
        self.assertFalse(self.application.state.ready)

    async def test_all_human_paths_methods_and_forged_headers_get_same_generic_denial(self):
        expected = await request(self.application)
        for path in ("/health", "/version", "/openapi.json", "/docs", "/redoc", "/api/live/1", "/missing/"):
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
