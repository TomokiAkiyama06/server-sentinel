"""Append-only schema for private physical identity approval evidence."""

from app.storage.migrations import Migration
from .persistence import EXPLICIT_BINDING_SCHEMA, SCHEMA


UVC_MIGRATION = Migration(3, "uvc_identity", (SCHEMA,))


def uvc_explicit_binding_migration(version: int) -> Migration:
    """Place the explicit-binding column at a caller-assigned slot."""
    return Migration(version, "uvc_explicit_binding", (EXPLICIT_BINDING_SCHEMA,))
