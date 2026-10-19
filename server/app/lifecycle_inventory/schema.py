"""Schema section of the lifecycle inventory (#47, split in #256).

The applied migration history the next startup would still accept, and the
schema objects that history creates, replayed into an in-memory database.
"""

from __future__ import annotations

import functools
import sqlite3

from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS


def _schema_objects(connection) -> dict:
    return {(row[0], row[1]): row[2] for row in connection.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'trigger') AND name NOT LIKE 'sqlite_%'")}


@functools.lru_cache(maxsize=8)
def _catalog_schema(count: int) -> tuple:
    """The schema objects the first ``count`` catalog migrations create."""
    expected_db = sqlite3.connect(":memory:")
    try:
        migrate(expected_db, APPLICATION_MIGRATIONS[:count])
        return tuple(sorted(_schema_objects(expected_db).items()))
    finally:
        expected_db.close()


def _schema_drift(connection, migrations: list | None) -> dict:
    """Compare the database's schema with what its applied migrations create.

    The applied history must be a prefix of this release's catalog; that
    prefix is replayed into an in-memory database, and every table, index
    and trigger it creates must exist here with the same definition (SQLite
    keeps the CREATE text, ALTERs included). Extra objects are ignored.
    A future migration using ALTER TABLE ... RENAME (or other DDL whose
    stored text depends on the SQLite version or legacy_alter_table) must
    re-validate this comparison.
    """
    code = [[migration.version, migration.name, migration.checksum]
            for migration in APPLICATION_MIGRATIONS]
    if migrations is None or migrations != code[:len(migrations)]:
        return {"history_matches": False, "missing": [], "changed": []}
    expected = dict(_catalog_schema(len(migrations)))
    actual = _schema_objects(connection)
    return {"history_matches": True,
            "missing": sorted(f"{kind}:{name}" for kind, name in expected
                              if (kind, name) not in actual),
            "changed": sorted(f"{kind}:{name}" for (kind, name), sql in expected.items()
                              if (kind, name) in actual and actual[(kind, name)] != sql)}


def _compare_migrations(baseline: list | None, current: list | None) -> dict:
    """The applied migration history the next startup would still accept.

    migrate() reads the history ordered by version, refuses one longer than
    the code's migrations, and requires each row to equal the code's
    migration at the same position (version, name, checksum); it then only
    appends the code's later ones. Migrations are forward-only, so a
    rollback removes none. verify runs after the release has started, so
    the current history must start with the recorded rows unchanged and
    equal this release's whole APPLICATION_MIGRATIONS: no gap, reorder,
    foreign row or missing tail.
    """
    if baseline is None:
        return {"status": "failed" if current is None else "empty",
                "failed": [{"id": None, "reason": "unverifiable"}] if current is None else [],
                "appended": []}
    if current is None:
        return {"status": "failed", "failed": [{"id": None, "reason": "table_missing"}],
                "appended": []}
    failed = []
    by_version = {row[0]: row for row in current}
    for position, row in enumerate(baseline):
        if row[0] not in by_version:
            failed.append({"id": row[0], "reason": "missing"})
        elif position >= len(current) or current[position] != row:
            failed.append({"id": row[0], "reason": "changed"})
    code = [[migration.version, migration.name, migration.checksum]
            for migration in APPLICATION_MIGRATIONS]
    # The exact check migrate() runs on startup.
    if len(current) > len(code) or any(row != expected for row, expected in zip(current, code)):
        failed.append({"id": None, "reason": "history_rejected"})
    elif len(current) < len(code):
        # verify runs after the release started (systemd readiness follows
        # migrate()), so its full catalog is applied. A shorter history means
        # applied rows were removed and the next start would re-run DDL.
        failed.append({"id": None, "reason": "not_migrated"})
    recorded = {row[0] for row in baseline}
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "appended": [row[0] for row in current if row[0] not in recorded]}
