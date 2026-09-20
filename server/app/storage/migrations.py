"""Transactional, append-only SQLite schema migrations with drift checks."""

from dataclasses import dataclass
import hashlib
import json
import re
import sqlite3


class MigrationError(RuntimeError):
    """Migration refused or failed, without database paths or SQL values."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self) -> str:
        content = json.dumps([self.version, self.name, self.statements], separators=(",", ":"))
        return hashlib.sha256(content.encode()).hexdigest()


BUILTIN_MIGRATIONS = (
    Migration(1, "foundation", (
        "CREATE TABLE application_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    )),
)


def migrate(connection: sqlite3.Connection,
            migrations: tuple[Migration, ...] = BUILTIN_MIGRATIONS) -> None:
    """Apply all pending migrations atomically, serializing competing startups.

    Migration statements are trusted checked-in DDL. Do not pass user SQL.
    A future schema, edited history, missing entry or failed statement blocks
    startup. No implicit downgrade or destructive reset is available.
    """
    for expected, migration in enumerate(migrations, start=1):
        if (type(migration.version) is not int or migration.version != expected
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", migration.name)
                or not migration.statements):
            raise MigrationError("invalid migration sequence")
    if connection.in_transaction:
        raise MigrationError("migration requires an idle connection")
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL)"
        )
        history = connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        if len(history) > len(migrations):
            raise MigrationError("database schema is newer than this application")
        for row, migration in zip(history, migrations):
            if tuple(row) != (migration.version, migration.name, migration.checksum):
                raise MigrationError("database migration history does not match")
        for migration in migrations[len(history):]:
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)",
                (migration.version, migration.name, migration.checksum),
            )
        connection.commit()
    except (sqlite3.Error, MigrationError) as exc:
        connection.rollback()
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError("database migration failed") from None
