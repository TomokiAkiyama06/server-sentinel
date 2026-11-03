"""Deployment-local preservation inventory for update / rollback (Issue #47).

``record`` captures, from a read-only view of the Main Server runtime tree:

- per-recording content evidence keyed by the recording logical ID: a SHA-256,
  size and hard-link count of every linked segment file as stored on disk
  (the recording store serves only single-link files) with the segment's
  source, catalog bounds and the catalog fields that control integrity,
  playback or retention (byte length, stream / sequence, codec, container,
  capture node, critical flag), the starred and critical flags, and the catalog
  start, target end and ended boundaries (the manifest clips playback to the
  target end), the event link and the explicit discontinuity markers;
- a per-row and a chained SHA-256 over every retained audit row
  (``security_admin_audit_records``, ``integrity_audit``, ``presence_audit``
  and ``storage_state_audit``), so a rewritten middle row is detected even
  when counts and boundary timestamps match;
- the open presence timeline gap, which may only grow, and the durable
  presence state (tombstones, unresolved markers, retained observations as
  keyed digests, delivery jobs, source facts, clocks, outbox sessions, the
  Owner override) under the transitions the presence service performs;
- the Owner-approved hardware baseline revision and a keyed inventory digest;
- per registered camera source: type, keyed digests of the Owner-entered
  name and role label, capabilities digest, enabled flag, capture node, digests of
  the desired capture profile and detection bindings, and a keyed digest of
  the durable UVC approval identity (never device facts; volatile health
  excluded); the registry's ``max_active_video_sources``;
- for a configured Owner-template store: whether it exists, its generation,
  keyed digests of the template and provenance (never template bytes or
  embeddings) and its audit rows / chain;
- Owner presence and, per nonidentifying principal / invitation logical ID,
  the independent ``live:view`` / ``recordings:view`` grants, revocation
  state, authorization revision, a keyed digest and the (only rising)
  signature counter per usable (unrevoked and consistent) credential, every
  invitation validity field and a keyed digest of its secret digest.

- every ready pre-roll spool segment (its file must match its catalog) and
  the per-source publish cursor, the reference for the marker the first
  segment of a recording without evidence must bring;
- the session-revocation exposure marker (#134) and the staged renewal
  certificate (migration 21), checked as their services write them;
- (#132) the per-source pre-roll gap markers, which may leave only as the
  spool trim or a source release removes them; the append-only ROI
  calibration history as keyed digests; the notification history of every
  kind (kind, time, confirmed flag; only its retention removes a row); and
  the survival and readability of the recomputed integrity /
  recording-health status rows. Values the services legitimately rewrite
  are listed in DECLARED_MUTABLE and reported, never silently ignored.

Threat model (Owner decision 2026-10-07): a broken or buggy migration or
update. Deliberate tampering by someone with write access to the database
and full re-verification of every service's transition semantics are out of
scope (server/docs/DEPLOYMENT.md, "Scope, threat model and limits").

Structure (#256): the package root keeps the report contract (coverage,
the declared lists, exit codes), ``collect()``, ``compare()`` and the
command line; each section reads and compares one service's durable state
in its own module, re-implementing that service's read-side semantics:

- ``recordings``: RecordingStore (catalog, spool, cursors, pre-roll
  markers, segment hashing, growth and publication rules);
- ``access``: AccessStore principals, credentials and invitations;
- ``pairing``: PairingLedger and the other one-way security state;
- ``presence``: PresenceService state and the presence timeline gap;
- ``audit``, ``sources``, ``integrity``, ``template_store``: the audit
  chains, the camera registry, the integrity / notification / status rows
  and the Owner-template store;
- ``domain``: the current-state value checks across every section;
- ``timing``, ``schema``, ``output``: the retention and future-time rules,
  the migration and schema comparison, and the private output files;
- ``_common``: the read-only snapshot, digests and the ``_fail_closed``
  boundary every comparison rule shares.

The split moved code only; ``tests/test_lifecycle_inventory_contracts.py``
drives each section through its service's real transitions.

Keyed digests are HMAC-SHA-256 under a random per-baseline salt stored in the
baseline.

``verify`` recomputes the same inventory and compares it with a recorded one.
Rows or recordings that exist only in the current state are listed as
``appended`` and never counted as preserved. An inventory section that is empty
reports ``empty`` rather than success, so a comparison cannot pass vacuously.

Never written: principal external identities or display names, credential IDs,
public keys or labels, invitation / session secret or token digests, session
identity bindings, permission-bearing URLs, media bytes, or audit row contents (only their digests). Container
duration probing and decodable-playback samples need a codec and are left to
the manual procedure in ``MANUAL_TEST.md`` section V; the output marks them
``manual``. The output file is created exclusively with mode 0600 and is
refused inside the runtime root, the installed package / virtual environment,
the whole installation destination (``<destination>`` of
``<destination>/releases/<version>/venv``, including ``current``), or any Git
checkout. Keep it, including its digests and logical IDs,
deployment-local.
"""

from __future__ import annotations

import argparse
from collections import Counter
import os
import secrets
from pathlib import Path
import sqlite3
import sys

from . import _common
from ._common import (FORMAT, FORMAT_VERSION, InventoryError, RuntimeTree, _absolute,
                      _compare_keyed, _snapshot, _tables)
from .access import _access, _compare_invitations, _compare_principals, _usable_owner
from .audit import _audit, _compare_audit
from .domain import _domain_errors
from .integrity import (_compare_integrity_delivery, _compare_notification_events,
                        _compare_status_rows, _integrity_baseline, _integrity_delivery,
                        _notification_events, _status_rows)
from .output import read_private, safe_output_path, write_private
from .pairing import _compare_security_state, _security_state
from .presence import (_compare_presence, _compare_timeline_gap, _outbox_live, _presence,
                       _timeline_gap)
from .recordings import (_compare_recordings, _compare_source_discontinuities, _cursor_rows,
                         _hash_recordings, _hash_spool, _pending_segments, _publications_since,
                         _recordings, _servable, _source_cursors, _source_discontinuities,
                         _spool_segments)
from .schema import _compare_migrations, _schema_drift
from .sources import _compare_sources, _registry_settings, _roi_history, _sources
from .template_store import _compare_owner_template, _owner_template
from .timing import CLOCK_SKEW_ALLOWANCE, _future_times, _retention_rules, _written_after


# Coverage items that must be non-empty before a comparison can be a success.
COVERAGE = (
    "ordinary_recording", "starred_recording", "camera_source", "audit_record",
    "owner", "live_view_only_grant", "recordings_view_only_grant", "revocation",
)
NOT_APPLICABLE = {
    # No capture node exists in the Main-only lifecycle environment; the
    # complete deployment acceptance of Issue #28 verifies these.
    "capture_agent_protected_incidents": "not_applicable (#16 / #28)",
}
# Durable tables this tool does not inventory; the report lists them so a
# pass is never read as covering them. #132 covered the last ones: each is
# now compared or, for values its service legitimately rewrites, declared in
# DECLARED_MUTABLE below.
NOT_INVENTORIED: tuple = ()

# Why a listed table is not (fully) inventoried.
NOT_INVENTORIED_NOTES: dict = {}


def _not_inventoried() -> dict:
    return {name: NOT_INVENTORIED_NOTES.get(name, "not_inventoried")
            for name in NOT_INVENTORIED}


# Durable values a correct service rewrites across a restart or a daily run,
# so they are deliberately not compared for equality (#132). The report
# lists them, so a pass is never read as having compared them; what is
# checked instead is named here.
DECLARED_MUTABLE = {
    "notification_events.delivery": (
        "declared_mutable (#132): the delivery result is rewritten when a pending Slack "
        "delivery completes or a presence notification is retried; kind, time and "
        "confirmed flag never change and every row stays until its 90-day retention"),
    "notification_events.accepted_at": (
        "declared_mutable (#132, #287): the time of the row's latest local write, rewritten "
        "with every delivery result or retried write; it only re-seeds the hourly access and "
        "finding notification budgets after a restart, and is NULL on rows written before "
        "migration 25"),
    "notification_events.resent": (
        "declared_mutable (#351): set once when a start resubmits a recording_health_failure "
        "row an earlier process left pending, so each row is resent at most once; 0 on rows "
        "written before migration 26"),
    "uvc_approvals.session_token": (
        "declared_mutable (#132): a per-run marker, cleared at a clean stop and replaced at "
        "every start; the Owner re-approval latch it arms (requires_approval) is compared "
        "in camera_sources. A token cleared while the service was down after an unclean "
        "stop is indistinguishable from a clean stop and is not detected"),
    "integrity_status": (
        "declared_mutable (#132): the latest hardware-integrity verdict is recomputed at "
        "startup and daily; only the row's survival, the values the service reads back "
        "and delivery_blocked matching the overflow slots are checked"),
    "recording_health_status": (
        "declared_mutable (#132): the latest recording-health verdict is recomputed at "
        "startup and daily; only the row's survival and the values the service reads back "
        "are checked"),
}


# Every Main-database table the inventory reads. A table recorded present
# must still exist at verify time, whatever its comparator does with an
# empty or absent section (a table dropped while empty is still a loss);
# the schema comparison covers every other migration table.
INVENTORIED_TABLES = (
    "recordings", "recording_links", "recording_segments", "recording_discontinuities",
    "recording_source_cursors",
    "security_admin_audit_records", "integrity_audit", "presence_audit", "storage_state_audit",
    "camera_sources", "uvc_approvals", "detection_bindings", "camera_registry_settings",
    "access_principals", "access_principal_permissions", "access_credentials",
    "access_invitations", "access_deployment_state", "access_sessions",
    "presence_timeline_gap", "presence_clock", "presence_control_clock",
    "presence_source_clock", "presence_critical_source_clock", "presence_override",
    "presence_completed_events", "presence_expired_unresolved", "presence_observations",
    "presence_deliveries", "presence_source_facts", "presence_outbox_sessions",
    "pairing_node_credentials", "pairing_enrollments", "pairing_node_renewals",
    "pairing_key_bindings", "capture_nodes",
    "integrity_outbox", "integrity_overflow", "integrity_baseline",
    "schema_migrations",
    # #132
    "recording_source_discontinuities", "roi_calibration_history", "notification_events",
    "integrity_status", "recording_health_status",
)

# Migration-created tables deliberately left out: per-session or derived
# state whose loss replays nothing and hides no failure.
TRANSIENT_TABLES = {
    "access_webauthn_challenges": "short-lived single-use WebAuthn challenges",
    # Only its reservation exposure marker (#134) is state: it is read into
    # security_state (session_revocation_pending), not the table as a whole.
    "application_metadata": "key/value store; its session-revocation exposure marker "
                            "(#134) is checked in security_state",
    # Issue #351 (PR #366 review): not "replays nothing" like the others, but
    # its value changes at every start (a new random token) and a graceful
    # stop deletes it, so no baseline value could be compared across a stop.
    "monitoring_run_marker": "running marker of the monitoring runtime, rewritten at "
                             "every start",
    # Owner decision 2026-10-29 (PR #366): only the hourly cap of the
    # unclean-exit notices is counted from it; losing it lets more notices
    # through, never fewer, and the notices themselves are notification_events.
    "monitoring_unclean_exit_notices": "unclean-exit notices counted by their hourly cap",
    "notification_schedule": "daily-summary schedule cursor",
    "presence_delivery_fairness": "round-robin cursor between delivery classes",
    "presence_inputs": "live presence inputs with their own validity windows",
    "recording_selftest": "identifier of the current self-test artifact",
    "setup_wizard_steps": "setup wizard progress",
}

MANUAL = {
    "container_duration": "manual",
    "decode_verification": "manual",
}

EXIT_PRESERVED = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_EMPTY = 3
# preserved_except_declared_rewrites: everything else preserved, but the
# declared recordings still need manual re-verification, so never 0 (#161).
EXIT_DECLARED_REWRITES = 4


def _coverage(inventory: dict) -> dict:
    recordings = inventory["recordings"] or {}
    audit = inventory["audit"]["security_admin"] or {"rows": []}
    access = inventory["access"] or {"principals": {}, "invitations": {}}
    # A grant counts only on a principal that is not revoked.
    others = [item for item in access["principals"].values()
              if item["role"] != "owner" and not item["revoked"] and item["status"] != "revoked"]

    def present(flag: bool) -> str:
        return "present" if flag else "empty"
    return {
        "ordinary_recording": present(any(
            not r["starred"] and _servable(r) for r in recordings.values())),
        "starred_recording": present(any(
            r["starred"] and _servable(r) for r in recordings.values())),
        "camera_source": present(bool(inventory["camera_sources"])),
        "audit_record": present(bool(audit["rows"])),
        "owner": present(any(_usable_owner(item) for item in access["principals"].values())),
        "live_view_only_grant": present(any(
            item["permissions"] == ["live:view"] for item in others)),
        "recordings_view_only_grant": present(any(
            item["permissions"] == ["recordings:view"] for item in others)),
        "revocation": present(
            any(item["revoked"] for item in access["principals"].values())
            or any(item["revoked"] for item in access["invitations"].values())),
    }


def collect(runtime_root: Path, *, salt: str | None = None,
            owner_template_root: Path | None = None, since_cursors=None) -> dict:
    """Read the runtime tree without writing to it.

    ``salt`` is the baseline's approval-digest salt when verifying; a new
    random one is drawn when recording. ``since_cursors`` is the baseline's
    recorded source cursor map when verifying (_publications_since()).
    """
    salt = secrets.token_hex(32) if salt is None else salt
    tree = RuntimeTree(_absolute(runtime_root, "runtime root"))
    # Taken before the snapshot, so a row written in between counts as
    # written after the record.
    recorded_at = _common._utcnow().isoformat()
    # The outbox lock, the session rows and the timeline gap must be one
    # observation (#162): an outbox opening between the snapshot and a
    # single probe would convert the copied stale rows into a gap and still
    # make them look held. The probe runs before and after the snapshot; a
    # different answer means the outbox started or stopped in between.
    live_before = _outbox_live(tree.database)
    connection = _snapshot(tree.database)
    live_after = _outbox_live(tree.database)
    live_outbox = live_before if live_before == live_after else None
    try:
        tables = _tables(connection)
        schema_version, migrations = None, None
        if "schema_migrations" in tables:
            # The applied history migrate() checks entry by entry on startup.
            migrations = [[row[0], row[1], row[2]] for row in connection.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version")]
            schema_version = migrations[-1][0] if migrations else None
        inventory = {
            "format": FORMAT, "format_version": FORMAT_VERSION,
            # When this snapshot was taken, to tell rows written after it.
            "recorded_at": recorded_at,
            "schema_version": schema_version,
            "schema_migrations": migrations,
            "tables": sorted(name for name in INVENTORIED_TABLES if name in tables),
            # Schema objects the applied migration catalog creates that are
            # missing or differ here (any table the service needs, including
            # ones this tool does not inventory).
            "schema": _schema_drift(connection, migrations),
            # Values the services parse again later that no CHECK constraint
            # (guarded by the schema comparison) already limits.
            "domain_errors": _domain_errors(connection, tables),
            "recordings": _recordings(connection, tables),
            "spool_segments": _spool_segments(connection, tables),
            "recording_source_cursors": _source_cursors(connection, tables),
            "recording_source_cursor_rows": _cursor_rows(connection, tables),
            "pending_segments": _pending_segments(connection, tables),
            "publications_since_record": _publications_since(connection, tables,
                                                             since_cursors),
            "audit": _audit(connection, tables),
            "camera_sources": _sources(connection, tables, salt),
            "access": _access(connection, tables, salt),
            "camera_registry_settings": _registry_settings(connection, tables),
            "presence_timeline_gap": _timeline_gap(connection, tables),
            "presence": _presence(connection, tables, salt, live_outbox),
            "presence_outbox_settled": live_before == live_after,
            "integrity_baseline": _integrity_baseline(connection, tables, salt),
            "security_state": _security_state(connection, tables, salt),
            "integrity_delivery": _integrity_delivery(connection, tables, salt),
            "recording_source_discontinuities": _source_discontinuities(connection, tables),
            "roi_calibration_history": _roi_history(connection, tables, salt),
            "notification_events": _notification_events(connection, tables),
            "status_rows": _status_rows(connection, tables),
        }
    except sqlite3.Error:
        raise InventoryError("state database could not be read") from None
    finally:
        connection.close()
    digests: dict = {}
    _hash_recordings(inventory["recordings"], tree.recordings, tree.database, recorded_at,
                     digests)
    # A ready spool row whose file is missing or differs would hand the next
    # recording missing media: a current-state failure.
    for segment_id in _hash_spool(inventory["spool_segments"], tree.recordings, tree.database,
                                  digests):
        inventory["domain_errors"].append(
            ["recordings", f"spool:{segment_id}", "spool_file_mismatch"])
    inventory["owner_template"] = _owner_template(
        owner_template_root, salt, os.lstat(tree.database).st_uid)
    inventory["inventory_salt"] = salt
    inventory["coverage"] = _coverage(inventory)
    # Counted apart from coverage: a recording without evidence never makes
    # an ordinary / starred recording "present".
    inventory["coverage_counts"] = {
        "recordings_with_evidence": sum(
            1 for item in (inventory["recordings"] or {}).values() if item["segments"]),
        "recordings_without_evidence": sum(
            1 for item in (inventory["recordings"] or {}).values() if not item["segments"]),
    }
    inventory["not_applicable"] = dict(NOT_APPLICABLE)
    inventory["not_inventoried"] = _not_inventoried()
    inventory["declared_mutable"] = dict(DECLARED_MUTABLE)
    inventory["manual"] = dict(MANUAL)
    return inventory


_NOT_RECORDED = {"status": "not_recorded", "failed": []}


def compare(baseline: dict, current: dict, *, declared_rewrites=(), now=None) -> dict:
    if (not isinstance(baseline, dict) or baseline.get("format") != FORMAT
            or baseline.get("format_version") != FORMAT_VERSION):
        raise InventoryError("baseline is not a lifecycle inventory")
    declared = frozenset(str(item) for item in declared_rewrites)
    unknown = declared - set(baseline.get("recordings") or {})
    if unknown:
        raise InventoryError("declared rewrite is not a recorded recording logical ID")
    access_base = baseline.get("access") or {}
    access_now = current.get("access") or {}
    access_owner = any(_usable_owner(item)
                       for item in (access_now.get("principals") or {}).values())
    rules = _retention_rules(now or _common._utcnow())
    fresh = _written_after(baseline.get("recorded_at"))
    recorded_tables = baseline.get("tables")
    present = set(current.get("tables") or ())
    table_failures = ([{"id": None, "reason": "unverifiable"}] if recorded_tables is None else
                      [{"id": name, "reason": "table_missing"}
                       for name in recorded_tables if name not in present])
    # Every object the applied catalog creates, inventoried or not.
    schema = current.get("schema") or {}
    if schema.get("history_matches"):
        table_failures += [{"id": item, "reason": "table_missing"}
                           for item in schema.get("missing", ())
                           if item.split(":", 1)[1] not in (recorded_tables or ())]
        table_failures += [{"id": item, "reason": "schema_changed"}
                           for item in schema.get("changed", ())]
    sections = {
        "schema_migrations": _compare_migrations(baseline.get("schema_migrations"),
                                                 current.get("schema_migrations")),
        "tables": {"status": "failed" if table_failures else "preserved",
                   "failed": table_failures, "preserved": sorted(set(recorded_tables or ()) & present)},
        "recordings": _compare_recordings(
            baseline.get("recordings"), current.get("recordings"), declared=declared,
            retention_cutoff_ms=rules["recording_cutoff_ms"],
            context={"cursors": baseline.get("recording_source_cursors"),
                     "recordings": current.get("recordings"),
                     "spool": current.get("spool_segments"),
                     "published": current.get("publications_since_record"),
                     "pending": current.get("pending_segments"),
                     "current_cursors": current.get("recording_source_cursors"),
                     "cursor_rows": (baseline.get("recording_source_cursor_rows"),
                                     current.get("recording_source_cursor_rows")),
                     "recorded_spool": baseline.get("spool_segments")}),
        "audit_security_admin": _compare_audit(
            baseline["audit"].get("security_admin"), current["audit"].get("security_admin"),
            rules["security_admin"]),
        "audit_integrity": _compare_audit(
            baseline["audit"].get("integrity"), current["audit"].get("integrity"),
            rules["integrity"], fresh["iso"]),
        "audit_presence": _compare_audit(
            baseline["audit"].get("presence"), current["audit"].get("presence"),
            rules["presence_audit"]),
        "audit_storage_state": _compare_audit(
            baseline["audit"].get("storage_state"), current["audit"].get("storage_state"),
            rules["storage_state"], fresh["ms"]),
        "camera_sources": _compare_sources(baseline.get("camera_sources"),
                                           current.get("camera_sources")),
        "camera_registry_settings": _compare_keyed(
            baseline.get("camera_registry_settings"), current.get("camera_registry_settings")),
        "presence_timeline_gap": _compare_timeline_gap(
            baseline.get("presence_timeline_gap"), current.get("presence_timeline_gap")),
        "presence": _compare_presence(
            baseline.get("presence"), current.get("presence"),
            baseline.get("presence_timeline_gap"), current.get("presence_timeline_gap"),
            rules["presence_expiry"]),
        "integrity_baseline": _compare_keyed(
            {"baseline": baseline["integrity_baseline"]}
            if baseline.get("integrity_baseline") is not None else None,
            {"baseline": current["integrity_baseline"]}
            if current.get("integrity_baseline") is not None else None),
        "integrity_delivery": _compare_integrity_delivery(
            baseline.get("integrity_delivery"), current.get("integrity_delivery")),
        "security_state": _compare_security_state(
            baseline.get("security_state"), current.get("security_state")),
        "owner_template": _compare_owner_template(baseline.get("owner_template"),
                                                  current.get("owner_template"),
                                                  rules["owner_template"], fresh["iso"]),
        "access_principals": _compare_principals(access_base.get("principals"),
                                                 access_now.get("principals")),
        "access_invitations": _compare_invitations(access_base.get("invitations"),
                                                   access_now.get("invitations")),
        # #132; a baseline recorded before them reports not_recorded.
        "recording_source_discontinuities": (
            _compare_source_discontinuities(baseline["recording_source_discontinuities"],
                                            current.get("recording_source_discontinuities"),
                                            current.get("spool_segments"),
                                            current.get("recording_source_cursor_rows"))
            if "recording_source_discontinuities" in baseline else dict(_NOT_RECORDED)),
        "roi_calibration_history": (
            _compare_keyed(baseline["roi_calibration_history"],
                           current.get("roi_calibration_history"))
            if "roi_calibration_history" in baseline else dict(_NOT_RECORDED)),
        "notification_events": (
            _compare_notification_events(baseline["notification_events"],
                                         current.get("notification_events"),
                                         rules["notification_events_cutoff"])
            if "notification_events" in baseline else dict(_NOT_RECORDED)),
        "status_rows": (
            _compare_status_rows(baseline["status_rows"], current.get("status_rows"))
            if "status_rows" in baseline else dict(_NOT_RECORDED)),
    }
    # No time the services compare later may lie beyond the verify time
    # (plus a small clock-skew allowance): a far-future clock would refuse
    # every later operation.
    late_and_invalid = _future_times(current,
                                     (now or _common._utcnow()) + CLOCK_SKEW_ALLOWANCE)
    for name, item, reason in current.get("domain_errors") or ():
        late_and_invalid.setdefault(name, []).append({"id": item, "reason": reason})
    if (current.get("owner_template") or {}).get("template_state") == "invalid":
        late_and_invalid.setdefault("owner_template", []).append(
            {"id": "template", "reason": "invalid_value"})
    for item in (current.get("owner_template") or {}).get("invalid_audit") or ():
        late_and_invalid.setdefault("owner_template", []).append(
            {"id": f"audit:{item}", "reason": "invalid_value"})
    for name, items in late_and_invalid.items():
        section = sections[name]
        known = section.setdefault("failed", [])
        known.extend(item for item in items if item not in known)
        section["status"] = "failed"
    empty_coverage = sorted(key for key, value in baseline["coverage"].items()
                            if value != "present")
    failed = any(section["status"] == "failed" for section in sections.values())
    if baseline["coverage"].get("owner") == "present" and not access_owner:
        failed = True
    if failed:
        status = "failed"
    elif empty_coverage or any(section["status"] == "empty" and name in {
            "recordings", "audit_security_admin", "camera_sources",
            "access_principals", "access_invitations"}
            for name, section in sections.items()):
        status = "empty"
    elif sections["recordings"]["declared_rewrites"]:
        status = "preserved_except_declared_rewrites"
    else:
        status = "preserved"
    return {
        "format": FORMAT + "-verification", "format_version": FORMAT_VERSION,
        "status": status,
        "schema_version": {"baseline": baseline.get("schema_version"),
                           "current": current.get("schema_version")},
        "owner_present": access_owner,
        "empty_coverage": empty_coverage,
        "sections": sections,
        "not_applicable": dict(NOT_APPLICABLE),
        "not_inventoried": _not_inventoried(),
        "declared_mutable": dict(DECLARED_MUTABLE),
        "manual": dict(MANUAL),
    }


def _summary_record(inventory: dict) -> list[str]:
    recordings = inventory["recordings"] or {}
    lines = [f"lifecycle inventory recorded: {len(recordings)} recording(s), "
             f"{len((inventory['audit']['security_admin'] or {'rows': []})['rows'])} "
             "security/admin audit row(s)"]
    mismatched = sum(1 for item in recordings.values()
                     if not all(segment["catalog_match"] for segment in item["segments"]))
    if mismatched:
        lines.append(f"warning: {mismatched} recording(s) have segment files that are "
                     "missing or differ from the catalog digest")
    for key, value in inventory["coverage"].items():
        lines.append(f"coverage {key}: {value}")
    without = inventory.get("coverage_counts", {}).get("recordings_without_evidence", 0)
    lines.append(f"coverage recordings_without_evidence: {without} "
                 "(row only, not counted as preserved evidence)")
    for key, value in {**inventory["not_applicable"], **inventory["not_inventoried"],
                       **inventory["declared_mutable"], **inventory["manual"]}.items():
        lines.append(f"{key}: {value}")
    return lines


def _summary_verify(report: dict) -> list[str]:
    # Value-free: statuses and counts only, never IDs or digests.
    lines = [f"lifecycle inventory verification: {report['status']}"]
    for name, section in report["sections"].items():
        preserved = section.get("preserved_rows", len(section.get("preserved", [])))
        lines.append(
            f"{name}: {section['status']} preserved={preserved} "
            f"failed={len(section['failed'])} appended={len(section.get('appended', []))} "
            f"declared_rewrites={len(section.get('declared_rewrites', []))} "
            f"retention_expired={len(section.get('retention_expired', []) or (section.get('audit') or {}).get('retention_expired', []))} "
            f"released={len(section.get('released', []))}"
            + (f" no_evidence={len(section['no_evidence'])}" if "no_evidence" in section
               else "")
            + (f" trimmed={len(section['trimmed'])}" if "trimmed" in section else ""))
    for key in report["empty_coverage"]:
        lines.append(f"coverage {key}: empty (not counted as preserved)")
    for key, value in {**report["not_applicable"], **report["not_inventoried"],
                       **report.get("declared_mutable", {}), **report["manual"]}.items():
        lines.append(f"{key}: {value}")
    return lines


def _baseline_salt(baseline) -> str:
    salt = baseline.get("inventory_salt") if isinstance(baseline, dict) else None
    if not isinstance(salt, str) or len(salt) != 64 or any(
            character not in "0123456789abcdef" for character in salt):
        raise InventoryError("baseline is not a lifecycle inventory")
    return salt


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.lifecycle_inventory",
        description="Record or verify a deployment-local preservation inventory.")
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    record.add_argument("--runtime-root", type=Path, required=True)
    record.add_argument("--output", type=Path, required=True)
    owner_help = ("the private Owner-template store directory, when the deployment configures "
                  "one; give it to both record and verify")
    record.add_argument("--owner-template-root", type=Path, help=owner_help)
    verify = commands.add_parser("verify")
    verify.add_argument("--runtime-root", type=Path, required=True)
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument("--report", type=Path)
    verify.add_argument("--owner-template-root", type=Path, help=owner_help)
    verify.add_argument("--declared-rewrite", action="append", default=[],
                        metavar="RECORDING_LOGICAL_ID")
    args = parser.parse_args(arguments)
    try:
        if args.command == "record":
            # Validate the destination before reading anything.
            safe_output_path(args.output, args.runtime_root)
            inventory = collect(args.runtime_root, owner_template_root=args.owner_template_root)
            schema = inventory.get("schema") or {}
            if not schema.get("history_matches") or schema.get("missing") or schema.get("changed"):
                # A baseline of a database the service cannot run on would
                # hide what is already lost; nothing is written.
                raise InventoryError(
                    "runtime database schema does not match the applied migrations "
                    f"(missing {len(schema.get('missing') or ())}, "
                    f"changed {len(schema.get('changed') or ())}, "
                    f"history {'ok' if schema.get('history_matches') else 'mismatch'})")
            if not inventory["presence_outbox_settled"]:
                # The lock probe and the copied session rows / gap would be
                # two observations; their pairing is what the baseline relies on.
                raise InventoryError(
                    "the presence outbox started or stopped while the state was read; "
                    "run record again")
            if any(error[0] == "integrity_baseline" for error in inventory["domain_errors"]):
                # The service's startup integrity check would reject it too.
                raise InventoryError("approved hardware baseline cannot be read by the service")
            # A baseline is written only if verifying this very state,
            # unchanged, would pass: every current-state check runs here.
            self_check = compare(inventory, inventory)
            if self_check["status"] == "failed":
                findings = Counter()
                for name, section in self_check["sections"].items():
                    for item in section.get("failed", ()):
                        findings[f"{name}:{item['reason']}"] += 1
                if not self_check["owner_present"] and inventory["coverage"].get("owner") == "present":
                    findings["access:owner_unusable"] += 1
                print("lifecycle inventory refused: the current state fails verification "
                      "(" + ", ".join(f"{key}={count}" for key, count in sorted(findings.items()))
                      + "); no baseline written", file=sys.stderr)
                return EXIT_FAILED
            write_private(args.output, args.runtime_root, inventory)
            print("\n".join(_summary_record(inventory)))
            empty = any(value != "present" for value in inventory["coverage"].values())
            return EXIT_EMPTY if empty else EXIT_PRESERVED
        if args.report is not None:
            safe_output_path(args.report, args.runtime_root)
        baseline = read_private(_absolute(args.baseline, "baseline"))
        try:
            current = collect(args.runtime_root, salt=_baseline_salt(baseline),
                              owner_template_root=args.owner_template_root,
                              since_cursors=baseline.get("recording_source_cursors"))
            report = compare(baseline, current, declared_rewrites=args.declared_rewrite)
        except (TypeError, ValueError, OverflowError, KeyError, IndexError,
                AttributeError) as exc:
            # Last line of defence: a stored value no rule anticipated never
            # aborts verification; it is a failed, unverifiable state.
            report = {"format": FORMAT + "-verification", "format_version": FORMAT_VERSION,
                      "status": "failed", "unverifiable": type(exc).__name__, "sections": {},
                      "empty_coverage": [], "not_applicable": dict(NOT_APPLICABLE),
                      "not_inventoried": _not_inventoried(),
                      "declared_mutable": dict(DECLARED_MUTABLE),
                      "manual": dict(MANUAL)}
        if args.report is not None:
            write_private(args.report, args.runtime_root, report)
        print("\n".join(_summary_verify(report)))
        if report["status"] == "failed":
            return EXIT_FAILED
        if report["status"] == "empty":
            return EXIT_EMPTY
        if report["status"] == "preserved_except_declared_rewrites":
            return EXIT_DECLARED_REWRITES
        return EXIT_PRESERVED
    except InventoryError as exc:
        print(f"lifecycle inventory refused: {exc}", file=sys.stderr)
        return EXIT_USAGE
