"""Owner-template section of the lifecycle inventory (#47, split in #256).

For a configured Owner-template store: whether it exists, its generation,
keyed digests of the template and provenance (never template bytes or
embeddings) and its audit rows / chain, read only through a layout the
store itself would load.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3

from app.detection.owner import store as owner_store
from app.detection.owner.contracts import Operation

from ._common import InventoryError, _absolute, _blob_hex, _connect_read_only, _keyed, _tables
from .audit import _audit_table, _compare_audit


def _owner_template_row_valid(row) -> bool:
    """Whether the store's read model loads the singleton row.

    owner_store.read_template_row() is the check
    OwnerTemplateStore._load_for_verification() applies (generation,
    template type and size, provenance), here under the largest template
    size any store accepts: a deployment's stricter configured limit is not
    read. A missing singleton row is refused by OwnerTemplateStore.status().
    """
    if row is None:
        return False
    try:
        owner_store.read_template_row(row["generation"], row["template"], row["provenance"],
                                      max_bytes=owner_store.MAX_TEMPLATE_BYTES_CEILING)
    except owner_store.OwnerError:
        return False
    return True


def _owner_template(root: Path | None, salt: str, owner: int) -> dict:
    """The separate private Owner-template store, as digests only.

    Records whether the store was configured for this run and whether its
    database exists, so its appearance or disappearance is a change; the
    enrollment generation and enrolled flag; keyed digests of the template
    and its model provenance (never the template bytes or any embedding);
    and per-row / chained evidence over owner_template_audit.

    The store is accepted only under the filesystem invariants
    OwnerTemplateStore enforces, checked by the store's own
    open_private_root() against ``owner`` (the service account owning the
    state database; this tool usually runs as root). A layout that would
    expose the biometric template is recorded as ``unsafe`` and never read.
    """
    if root is None:
        return {"configured": False}
    root = _absolute(root, "owner template root")
    try:
        descriptor, exists = owner_store.open_private_root(root, owner=owner)
    except FileNotFoundError:
        return {"configured": True, "state": "absent"}
    except (OSError, owner_store.OwnerError):
        return {"configured": True, "state": "unsafe"}
    try:
        if not exists:
            return {"configured": True, "state": "absent"}
        # Bound to the verified directory, so no component can be swapped
        # between the check and the open.
        connection = _connect_read_only(
            Path(f"/proc/self/fd/{descriptor}/owner-template.sqlite3"))
    except InventoryError:
        raise InventoryError("owner template database is unavailable") from None
    finally:
        os.close(descriptor)
    try:
        connection.execute("BEGIN")
        tables = _tables(connection)
        if not {"owner_template", "owner_template_audit"} <= tables:
            return {"configured": True, "state": "uninitialized"}
        row = connection.execute(
            "SELECT generation, template, provenance FROM owner_template "
            "WHERE singleton = 1").fetchone()
        template = None if row is None else row["template"]
        result = {
            "configured": True, "state": "present",
            "generation": None if row is None else row["generation"],
            "enrolled": template is not None,
            # Owner verification reads the row through the store's own read
            # model; a row it refuses (PRIVATE_TEMPLATE_STATE_INVALID) leaves
            # verification unusable, so it is never healthy here (#159).
            "template_state": "valid" if _owner_template_row_valid(row) else "invalid",
            # _blob_hex(), never bytes(): bytes() of an integer would stand
            # for a zero-filled template.
            "template_digest": None if template is None
            else _keyed(salt, ["owner-template-v1", _blob_hex(template)]),
            "provenance_digest": None if row is None or row["provenance"] is None
            else _keyed(salt, ["owner-provenance-v1", row["provenance"]]),
            "audit": _audit_table(connection, tables, "owner_template_audit",
                                  ("id", "at", "actor", "operation", "generation"), "id", "at"),
            # OwnerTemplateStore writes Operation values and a non-negative
            # generation.
            "invalid_audit": sorted(
                str(row[0]) for row in connection.execute(
                    "SELECT id, operation, generation FROM owner_template_audit")
                if row[1] not in {item.value for item in Operation}
                or type(row[2]) is not int or row[2] < 0),
        }
        connection.execute("COMMIT")
        return result
    except sqlite3.Error:
        raise InventoryError("owner template database could not be read") from None
    finally:
        connection.close()


def _compare_owner_template(baseline: dict | None, current: dict | None,
                            expired=None, fresh=None) -> dict:
    baseline = baseline or {"configured": False}
    current = current or {"configured": False}
    if not baseline["configured"] and not current["configured"]:
        return {"status": "not_configured", "failed": []}
    # An unsafe layout exposes the template: never preserved, even unchanged.
    unsafe = "unsafe" in (baseline.get("state"), current.get("state"))
    failed = [{"id": "state", "reason": "unsafe"}] if unsafe else []
    failed += [{"id": key, "reason": "changed"}
              for key in ("configured", "state", "generation", "enrolled",
                          "template_digest", "provenance_digest")
              if baseline.get(key) != current.get(key)]
    audit = None
    if baseline.get("audit") is not None or current.get("audit") is not None:
        # OwnerTemplateStore.cleanup_expired_batch() runs at startup when the
        # store is registered for audit retention.
        audit = _compare_audit(baseline.get("audit"), current.get("audit"), expired, fresh)
        failed.extend({"id": f"audit:{item['id']}", "reason": item["reason"]}
                      for item in audit["failed"])
    return {"status": "failed" if failed else "preserved", "failed": failed,
            "audit": audit}
