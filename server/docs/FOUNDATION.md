# Main Server foundation (Issue #7)

The runnable foundation contains configuration validation, SQLite migrations,
structured logging and a FastAPI lifespan. It does not capture, record, infer,
pair agents or authenticate people. Issue #6's Owner-approved authorization ADR
and Issue #10's enforcement are prerequisites to opening human routes.

## Running locally

Use the reviewed wheels in `requirements-ci.lock` with CPython 3.12 on Linux
x86_64, the platform CI uses. That lock also includes the optional Issue #20
detector lock, whose reviewed wheels exist only for CPython 3.12 on Linux
x86_64, so the commands below require exactly that combination. The base
`requirements.lock` still resolves with CPython 3.12 on Linux x86_64/aarch64
or CPython 3.14 on Linux x86_64, but the detector tests import the detector
runtime, so the full suite below does not run on those other platforms.
CPython 3.13 is not supported by the current reviewed wheel hashes and is
explicitly excluded by the project metadata.

```sh
cd server
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -m tests.lint
python -m unittest discover -s tests -p 'test_*.py' -v
python -m tests.smoke normal
python -m tests.smoke error
```

To run `python -m app`, the deployment operator must set
`SERVERSENTINEL_DATA_DIRECTORY` to an existing absolute directory outside the
checkout. Keep that directory private to the dedicated service account. The
application creates only `state.sqlite3`, with mode `0600`, and SQLite's own
journal files. It does not create a missing parent or migrate into a source-tree
directory. This is not the Agent media-root/mount enforcement from #12/#16.
Production environments may install `requirements.lock` without the two lint
tools or the optional detector runtime. Preserve
`docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md` with deployments.

Optional settings are `SERVERSENTINEL_HUMAN_HOST` (default `127.0.0.1`, literal
loopback addresses only), `SERVERSENTINEL_HUMAN_PORT` (default `8000`, 1–65535),
and `SERVERSENTINEL_LOG_LEVEL` (`INFO`, `WARNING`, `ERROR`). Unknown application
settings and invalid values fail startup without echoing the input. The CI
runner's two synthetic-scenario environment markers are accepted but do not
alter application behavior. No environment option opens human routes.

## Closed HTTP surface and logging

Every HTTP path/method receives the same generic `404` response with `no-store`.
WebSocket requests are never accepted. `/health`, `/version`, `/docs`, `/redoc`
and `/openapi.json` are unavailable. The prepared health/version router uses an
injectable, deny-all system-access dependency and is deliberately not mounted.
Its health value describes only foundation lifecycle readiness, never monitoring
or recording health. No proxy identity header is trusted by this implementation.
The documented launcher disables Uvicorn access logs, forwarded-header parsing
and the product server header. Do not bypass it with a generic `uvicorn` command
that restores those defaults.

The formatter admits checked-in event enums and bounded numeric status/duration
fields. It drops arbitrary message text, interpolation arguments, extra fields,
tracebacks and exception values rather than attempting to recognize every secret
format. Future events must extend this reviewed vocabulary. Operator-facing
errors intentionally omit private paths, SQL values and request contents.

## Persistence contract

`Database(path).connect()` returns an autocommit SQLite connection with
`sqlite3.Row`, foreign keys enabled and a five-second busy timeout. Callers close
connections explicitly and use explicit transactions for multi-statement writes.

`migrate(connection, migrations=BUILTIN_MIGRATIONS)` takes ordered immutable
`Migration(version, name, statements)` entries. Versions start at one and are
contiguous. A `BEGIN IMMEDIATE` transaction serializes startup migration;
pending schema changes and their history commit together or roll back together.
Checksums reject edited or mismatched history; a database from a newer release
blocks startup. There is no automatic downgrade/reset. SQL is checked-in trusted
code, never an input from an HTTP client. This history check is not a general
database corruption or schema-tampering detector.

## Validation limits

Tests cover rollback, persistence, concurrent migration, foreign keys, invalid
settings, log-value suppression, closed routes and the authorization injection
contract using temporary SQLite files and generated values. Smoke executes
the actual ASGI application lifespan and request handling in-process. A Python
audit hook observes socket connections, DNS, datagram sends and subprocess
launches during imports/startup/normal/error/shutdown; no such attempt is allowed.
Docker additionally denies network delivery, runs non-root/read-only and gives
only bounded temporary storage. The smoke does not use a browser, real camera,
private network, trusted proxy, HTTP listener or deployment database, and does
not prove the absence of every possible native-code network operation.
