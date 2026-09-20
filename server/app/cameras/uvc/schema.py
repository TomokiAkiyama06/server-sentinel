"""Append-only schema for private physical identity approval evidence."""

from app.storage.migrations import Migration
from .persistence import EXPLICIT_BINDING_SCHEMA, SCHEMA


UVC_MIGRATION = Migration(3, "uvc_identity", (SCHEMA,))
UVC_EXPLICIT_BINDING_MIGRATION = Migration(
    6, "uvc_explicit_binding", (EXPLICIT_BINDING_SCHEMA,),
)
