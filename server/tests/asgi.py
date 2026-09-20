"""Tiny in-process ASGI driver, without a network client dependency."""


async def request(application, path="/", *, method="GET", headers=(), kind="http"):
    messages = []
    scope = {
        "type": kind, "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "http", "method": method, "path": path,
        "raw_path": path.encode(), "query_string": b"", "root_path": "",
        "headers": list(headers), "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await application(scope, receive, send)
    return messages
