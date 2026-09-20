"""Append-only schema for private physical identity approval evidence."""

from app.storage.migrations import Migration
from .persistence import SCHEMA


UVC_MIGRATION = Migration(3, "uvc_identity", (SCHEMA,))
