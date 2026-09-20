"""Synthetic ASGI normal/error smoke with outbound-attempt observation.

Docker additionally blocks network delivery. The audit hook observes Python
socket/DNS and process-spawn attempts during imports, startup, requests and
shutdown. This is bounded evidence for these scenarios, not all future code.
"""

import sys


attempts = []


def observe(event, arguments):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto",
                 "subprocess.Popen", "os.system", "os.posix_spawn"}:
        attempts.append(event)
        raise RuntimeError("unexpected outbound or process-spawn attempt")


sys.addaudithook(observe)

import asyncio  # noqa: E402
import io  # noqa: E402
from pathlib import Path  # noqa: E402
import tempfile  # noqa: E402

from app.logging import configure_logging  # noqa: E402
from app.main import create_app  # noqa: E402
from app.settings import Settings  # noqa: E402
from tests.asgi import request  # noqa: E402


async def run(scenario):
    output = io.StringIO()
    configure_logging(stream=output)
    with tempfile.TemporaryDirectory(prefix="synthetic-server-") as temporary:
        settings = Settings(Path(temporary))
        if scenario == "error":
            settings.database_path.write_bytes(b"SYNTHETIC_PRIVATE_VALUE")
        application = create_app(settings)
        if scenario == "normal":
            async with application.router.lifespan_context(application):
                assert application.state.ready
                for path in ("/health", "/version", "/openapi.json", "/api/live/synthetic"):
                    messages = await request(application, path)
                    assert messages[0]["status"] == 404
                    assert messages[1]["body"] == b'{"detail":"Not Found"}'
            assert not application.state.ready
        elif scenario == "error":
            try:
                async with application.router.lifespan_context(application):
                    raise AssertionError("corrupt database was accepted")
            except RuntimeError as exc:
                assert str(exc) == "application startup failed"
            assert not application.state.ready
        else:
            raise AssertionError("unknown scenario")
        assert temporary not in output.getvalue()
        assert "SYNTHETIC_PRIVATE_VALUE" not in output.getvalue()
    assert not attempts, "unexpected network/process operation"
    print(f"synthetic {scenario}: assertions passed; no Python outbound attempts observed")


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
