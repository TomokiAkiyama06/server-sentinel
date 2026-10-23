"""Camera-registry section of the lifecycle inventory (#47, split in #256).

Registered camera sources (keyed digests of Owner-entered names and the
durable UVC approval identity, never device facts), the registry's
source limit and the append-only ROI calibration history.
"""

from __future__ import annotations

from app.cameras.uvc.persistence import ApprovalStore
from app.detection.roi.calibration import without_reference_digest

from ._common import _compare_keyed, _digest, _keyed


UNREADABLE_APPROVAL = "unreadable"


def _approval_digest(row, salt: str) -> str:
    """A keyed digest of the durable UVC approval, never the device facts.

    The stored evidence is parsed exactly as ApprovalStore._state() restores
    it (every required key, DeviceEvidence validation), so evidence the
    service could not load raises instead of hashing. The digest covers the
    identity identity.same_physical_camera() compares and the durable latch
    flags: a unique serial binds by its strong key (vendor, product, serial,
    interface), so a new device node or port is the same camera; without a
    serial, or when the serial is ambiguous, only the live instance names the
    camera, so its node, topology, device number and instance marker are
    covered and a swap to another same-model camera is a change. By-id
    aliases, advertised formats and the session token are mutable or
    per-session and excluded.
    """
    state = ApprovalStore._state(
        (row["evidence"], row["requires_approval"], None, row["serial_ambiguous"], 0))
    evidence = state.approved
    identity = (evidence.strong_key
                if evidence.strong_key is not None and not state.serial_ambiguous
                else evidence.live_instance_key)
    return _keyed(salt, ["uvc-approval-v3", list(identity), state.requires_approval,
                         state.serial_ambiguous])


def _sources(connection, tables, salt: str) -> dict | None:
    """Stable operational configuration per source; volatile health is excluded."""
    if "camera_sources" not in tables:
        return None
    approvals, latched = {}, {}
    if "uvc_approvals" in tables:
        for row in connection.execute(
                "SELECT source_id, evidence, requires_approval, serial_ambiguous "
                "FROM uvc_approvals"):
            try:
                approvals[row["source_id"]] = _approval_digest(row, salt)
            except (ValueError, TypeError, KeyError, AttributeError):
                # Never comparable as preserved; see compare().
                approvals[row["source_id"]] = UNREADABLE_APPROVAL
            # The durable Owner re-approval latch (already inside the digest),
            # kept apart so a latch-only difference can be named.
            latched[row["source_id"]] = bool(row["requires_approval"])
    bindings = {}
    if "detection_bindings" in tables:
        for row in connection.execute(
                "SELECT source_id, binding_id, kind, version, enabled, thresholds, config "
                "FROM detection_bindings ORDER BY source_id, binding_id"):
            bindings.setdefault(row["source_id"], []).append(
                [row["binding_id"], row["kind"], row["version"], bool(row["enabled"]),
                 row["thresholds"], row["config"]])
    return {row["id"]: {
        "source_type": row["source_type"],
        "enabled": bool(row["enabled"]),
        "capture_node_id": row["capture_node_id"],
        # Owner-entered text (name, role label) may name a person or place,
        # so only keyed digests are kept; capabilities (advertised formats,
        # video-only flag, written at Owner approval) are non-identifying.
        "name_digest": _keyed(salt, ["source-name-v1", row["name"]]),
        "role_digest": _keyed(salt, ["source-role-v1", row["role_label"]]),
        "capabilities_sha256": _digest(row["capabilities"]),
        "desired_capture_profile_sha256": _digest(row["desired_capture_profile"]),
        "detection_bindings_sha256": _digest(bindings.get(row["id"], [])),
        "uvc_approval_sha256": approvals.get(row["id"]),
        "uvc_requires_approval": latched.get(row["id"]),
    } for row in connection.execute(
        "SELECT id, source_type, name, role_label, enabled, capture_node_id, capabilities, "
        "desired_capture_profile FROM camera_sources ORDER BY id")}


def _registry_settings(connection, tables) -> dict | None:
    if "camera_registry_settings" not in tables:
        return None
    row = connection.execute(
        "SELECT max_active_video_sources FROM camera_registry_settings WHERE id = 1").fetchone()
    return {"max_active_video_sources": None if row is None else row[0]}


def _roi_history(connection, tables, salt: str) -> dict | None:
    """Every ROI calibration version as a keyed digest (#132).

    CalibrationArchive is append-only: a version is never rewritten or
    removed. The identifier and metadata (geometry, polygon, policy and
    reader of a calibration) are kept only as keyed digests.

    The one approved rewrite is the #205 scrub of a legacy
    ``reference.sha256`` (``scrub_legacy_reference_digests``, Codex P1 on
    PR #330): the metadata is digested without that key, in the exact
    serialization the archive writes, so a scrubbed version stays preserved
    against a baseline recorded with this rule, and a version that never had
    the key keeps the digest earlier releases recorded. Metadata that is not
    such a JSON object is digested as stored.
    """
    if "roi_calibration_history" not in tables:
        return None
    return {f"{row[0]}/{row[1]}/{row[2]}": _keyed(salt, ["roi-calibration-v1", row[3],
                                                        without_reference_digest(row[4]) or row[4]])
            for row in connection.execute(
                "SELECT source_id, profile_id, version, identifier, metadata "
                "FROM roi_calibration_history")}


_UVC_APPROVAL_FIELDS = frozenset({"uvc_approval_sha256", "uvc_requires_approval"})


def _compare_sources(baseline: dict | None, current: dict | None) -> dict:
    """Keyed comparison; approval evidence the service cannot load never passes.

    ReconnectController latches Owner re-approval for a camera without a
    unique serial on every restart (only a live descriptor proves the same
    camera), so such a source that differs only in its approval now held
    for re-approval is reported ``reapproval_required``: still a failure,
    resolved by the Owner re-approving and a new record.
    """
    result = _compare_keyed(baseline, current)
    current = current or {}
    for entry in result["failed"]:
        before, after = (baseline or {}).get(entry["id"]), current.get(entry["id"])
        if entry["reason"] != "changed" or before is None or after is None:
            continue
        differing = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
        if (differing and differing <= _UVC_APPROVAL_FIELDS
                and after.get("uvc_requires_approval") is True
                and after.get("uvc_approval_sha256") != UNREADABLE_APPROVAL):
            entry["reason"] = "reapproval_required"
    for key in list(result["preserved"]):
        if current[key].get("uvc_approval_sha256") == UNREADABLE_APPROVAL:
            result["preserved"].remove(key)
            result["failed"].append({"id": key, "reason": "unreadable_approval_evidence"})
    if result["status"] != "empty":
        result["status"] = "failed" if result["failed"] else "preserved"
    return result
