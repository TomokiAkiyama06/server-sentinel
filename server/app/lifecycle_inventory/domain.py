"""Current-state value checks of the lifecycle inventory (#47, split in #256).

Values the services parse or compare later that no CHECK constraint
already limits, each validated as its owning service writes it; the
per-section row checks live with their sections and are combined here.
"""

from __future__ import annotations

import json

from app.audit.store import AuditStore
from app.auth.reservation_store import REVOCATION_PENDING_KEY
from app.auth.store import AccessStore
from app.cameras.registry.repository import CameraRegistry
from app.integrity.model import Component, Finding, Inventory, Kind, State
from app.presence.models import Observation, PresenceState, timestamp as presence_timestamp
from app.storage.policy import StorageState

from ._common import _canonical_uuid, _int
from .access import _WEBAUTHN_CREDENTIAL_DEFAULTS, _access_row_errors
from .integrity import _status_domain_errors
from .pairing import _pairing_row_errors
from .presence import _DELIVERY_STATES, _PRESENCE_AUDIT_ACTIONS
from .recordings import _RECORDING_STATUSES, _service_valid_segment_row


def _domain_errors(connection, tables) -> list:
    """Values the services parse or compare later, outside any CHECK.

    Each is validated as the owning service writes it: audit rows through
    AuditStore's record validation; integrity audit actors (UUID) and
    revisions; storage-state audit states; presence audit actions and
    actors, job states and counters, marker counts, the override state and
    actor, observation payloads (Observation.from_payload()); recording
    identities, statuses and boundaries, discontinuity bounds; integrity
    outbox findings and flag, the approved hardware baseline (as
    IntegrityStore.baseline() reads it); camera-source capability /
    profile and binding JSON; every recording segment row; and the rows
    with no read-model builder (invitations, sessions, grants, pairing).
    """
    errors = []

    def rows(table, sql):
        return connection.execute(sql).fetchall() if table in tables else ()

    def bad(section, item):
        errors.append([section, item, "invalid_value"])
    for row in rows("security_admin_audit_records", "SELECT * FROM security_admin_audit_records"):
        try:
            record = AuditStore._record(row)
            # AuditStore stores str() of the identities it validated.
            valid = (str(record.id) == row["id"]
                     and str(record.target_logical_id) == row["target_logical_id"])
        except (ValueError, TypeError, KeyError, OverflowError):
            valid = False
        if not valid:
            bad("audit_security_admin", str(row["id"]))
    for row in rows("integrity_audit", "SELECT id, actor, revision FROM integrity_audit"):
        if not _canonical_uuid(row[1]) or type(row[2]) is not int or row[2] < 1:
            bad("audit_integrity", str(row[0]))
    states = {item.value for item in StorageState}
    for row in rows("storage_state_audit",
                    "SELECT id, previous_state, current_state FROM storage_state_audit"):
        if row[1] not in states or row[2] not in states:
            bad("audit_storage_state", str(row[0]))
    for row in rows("presence_audit", "SELECT sequence, action, actor FROM presence_audit"):
        if row[1] not in _PRESENCE_AUDIT_ACTIONS or (row[2] is not None
                                                     and not _canonical_uuid(row[2])):
            bad("audit_presence", str(row[0]))
    for row in rows("presence_deliveries",
                    "SELECT observation, action, state, attempts, generation FROM presence_deliveries"):
        if (row[2] not in _DELIVERY_STATES or type(row[3]) is not int or row[3] < 0
                or type(row[4]) is not int or row[4] < 0):
            bad("presence", f"deliveries:{row[0]}:{row[1]}")
    for row in rows("presence_expired_unresolved",
                    "SELECT action, events FROM presence_expired_unresolved"):
        if type(row[1]) is not int or row[1] < 1:
            bad("presence", f"expired_unresolved:{row[0]}")
    presence_states = {item.value for item in PresenceState}
    for row in rows("presence_override", "SELECT state, actor FROM presence_override"):
        if row[0] not in presence_states or not _canonical_uuid(row[1]):
            bad("presence", "override:owner")
    for row in rows("presence_observations",
                    "SELECT id, kind, source, received, payload FROM presence_observations"):
        # PresenceService.record() stores these columns from the observation
        # it keeps as the payload.
        try:
            observation = Observation.from_payload(json.loads(row[4]))
            valid = (row[0] == str(observation.identifier)
                     and row[1] == observation.kind.value
                     and row[2] == (str(observation.source_id) if observation.source_id
                                    else None)
                     and row[3] == presence_timestamp(observation.received_at))
        except Exception:
            valid = False
        if not valid:
            bad("presence", f"observations:{row[0]}")
    # The boundary startup recovery writes for 'interrupted' (unknown when
    # the catalog tables it reads are gone; the schema check reports that).
    recovered = ("MIN(r.target_end_ms, COALESCE((SELECT MAX(s.end_ms) FROM recording_segments s "
                 "JOIN recording_links l ON l.segment_id = s.id WHERE l.recording_id = r.id), "
                 "r.start_ms))" if {"recording_segments", "recording_links"} <= tables else "NULL")
    for row in rows("recordings", "SELECT r.id, r.source_id, r.event_id, r.status, r.start_ms, "
                    f"r.target_end_ms, r.ended_ms, r.critical, {recovered} FROM recordings r"):
        ints = (row[4], row[5]) + (() if row[6] is None else (row[6],))
        status, ended = row[3], row[6]
        # finish() closes complete (re-labelled gapped) rows at their target;
        # recovery ends interrupted ones at the expression above; an active
        # row has no end; a deleting row keeps the end it had.
        ended_ok = {"active": ended is None,
                    "complete": ended == row[5], "gapped": ended == row[5],
                    "interrupted": ended == row[8],
                    "deleting": ended is not None}.get(status, False)
        if (not _canonical_uuid(row[0]) or not _canonical_uuid(row[1])
                or not (row[2] is None or _canonical_uuid(row[2]))
                or status not in _RECORDING_STATUSES or row[7] not in (0, 1)
                or any(type(value) is not int or value < 0 for value in ints)
                or not row[4] < row[5] or not ended_ok):
            bad("recordings", str(row[0]))
    # _publish() writes (cursor end, new segment start) and append() admits
    # a segment starting exactly at the cursor end, so a stream change with
    # no time gap leaves a zero-length marker.
    for row in rows("recording_discontinuities",
                    "SELECT recording_id, start_ms, end_ms FROM recording_discontinuities"):
        if type(row[1]) is not int or type(row[2]) is not int or not row[1] <= row[2]:
            bad("recordings", str(row[0]))
    for row in rows("integrity_outbox", "SELECT id, immediate, findings FROM integrity_outbox"):
        try:
            findings = [Finding(Kind(item["kind"]), State(item["state"]), item["reason"])
                        for item in json.loads(row[2])]
            # IntegrityStore.record() / promotion derive the flag this way.
            valid = bool(findings) and row[1] == int(any(item.immediate for item in findings))
        except Exception:
            valid = False
        if not valid:
            bad("integrity_delivery", f"pending:{row[0]}")
    for row in rows("integrity_baseline", "SELECT revision, inventory FROM integrity_baseline"):
        try:
            # Exactly what IntegrityStore.baseline() builds, aggregate
            # Inventory constraints (limit, unique kind / location) included.
            data = json.loads(row[1])
            Inventory(tuple(Component(Kind(item["kind"]), item["location"],
                                      tuple(tuple(pair) for pair in item["properties"]),
                                      tuple(tuple(pair) for pair in item["identity"]),
                                      item.get("complete", True))
                            for item in data["components"]),
                      frozenset(Kind(kind) for kind in data["unavailable"]))
            valid = type(row[0]) is int and row[0] >= 1
        except Exception:
            valid = False
        if not valid:
            bad("integrity_baseline", "baseline")
    # CameraRegistry rebuilds each source (capabilities, desired and
    # negotiated capture profiles, detection bindings, times) with
    # CameraRegistry._source(); a row it cannot rebuild breaks source
    # enumeration, so it is rebuilt here the same way.
    if {"camera_sources", "detection_bindings"} <= tables:
        for row in rows("camera_sources", "SELECT id FROM camera_sources"):
            try:
                source = CameraRegistry._source(connection, row[0])
                # And the registry's write-side validation of the same
                # configuration (json_object(), CaptureProfile, bindings).
                CameraRegistry._config(source.name, source.role_label, source.enabled,
                                       source.capabilities, source.desired_capture_profile,
                                       list(source.detection_bindings))
                valid = _canonical_uuid(row[0])
            except Exception:
                valid = False
            if not valid:
                bad("camera_sources", str(row[0]))
    # CameraRegistry._node() rebuilds every capture node it lists.
    for row in rows("capture_nodes", "SELECT id FROM capture_nodes"):
        try:
            valid = _canonical_uuid(row[0]) and bool(CameraRegistry._node(connection, row[0]))
        except Exception:
            valid = False
        if not valid:
            bad("security_state", f"capture_nodes:{row[0]}")
    # AccessStore._principal() / _credential() rebuild the access rows.
    for row in rows("access_principals", "SELECT * FROM access_principals"):
        try:
            valid = bool(AccessStore._principal(row)) and _canonical_uuid(row["id"])
        except Exception:
            valid = False
        if not valid:
            bad("access_principals", str(row["id"]))
    for row in rows("access_credentials", "SELECT * FROM access_credentials"):
        try:
            # A row stored before access_webauthn_migration is read with the
            # values that migration gives it (#114).
            valid = bool(AccessStore._credential(
                {**_WEBAUTHN_CREDENTIAL_DEFAULTS, **{key: row[key] for key in row.keys()}}))
        except Exception:
            valid = False
        if not valid:
            bad("access_principals", str(row["principal_id"]))
    # Every segment row, linked or only spooled (RecordingStore._start() links
    # overlapping spool rows without re-validating them): the file identity
    # RecordingStore._name() derives, the Segment.validate() bounds append()
    # enforced, the digest / length / state values the store writes, and the
    # source / stream position the publish cursor records.
    cursors = ({row[0]: row for row in connection.execute(
        "SELECT source_id, stream_id, sequence, end_ms FROM recording_source_cursors")}
        if "recording_source_cursors" in tables else None)
    # RecordingStore._publish() writes each source cursor from a validated
    # segment (UUID stream and capture node, its sequence and end).
    for row in rows("recording_source_cursors", "SELECT * FROM recording_source_cursors"):
        node = row["capture_node_id"]
        if not (_canonical_uuid(row["source_id"]) and _canonical_uuid(row["stream_id"])
                and _int(row["sequence"]) and _int(row["end_ms"]) and row["active"] in (0, 1)
                and (node is None or _canonical_uuid(node))):
            bad("recordings", f"cursor:{row['source_id']}")
    segment_rows = rows("recording_segments", "SELECT * FROM recording_segments")
    for row in segment_rows:
        if not _service_valid_segment_row(row, cursors):
            bad("recordings", f"segment:{row['id']}")
    # The cursor names the last published segment: while that ready row is
    # still catalogued (it ends exactly at the cursor end), the cursor's
    # stream and sequence are its own.
    last = {}
    for row in segment_rows:
        cursor = (cursors or {}).get(row["source_id"])
        if row["state"] == "ready" and cursor is not None and row["end_ms"] == cursor[3]:
            last.setdefault(row["source_id"], set()).add((row["stream_id"], row["sequence"]))
    for source_id, named in sorted(last.items()):
        cursor = cursors[source_id]
        if (cursor[1], cursor[2]) not in named:
            bad("recordings", f"cursor:{source_id}")
    # append() refuses while any pending row exists (RECORDING_RECOVERY_REQUIRED).
    pending = [row for row in segment_rows if row["state"] == "pending"]
    if len(pending) > 1:
        for row in pending:
            bad("recordings", f"segment:{row['id']}")
    for message in _access_row_errors(connection, tables):
        bad(*message)
    for message in _pairing_row_errors(connection, tables):
        bad(*message)
    # ReservationSessionRevocation.exposure_pending() accepts only '1'.
    for row in rows("application_metadata",
                    "SELECT value FROM application_metadata WHERE key = "
                    f"'{REVOCATION_PENDING_KEY}'"):
        if row[0] != "1":
            bad("security_state", "session_revocation_pending")
    errors.extend(_status_domain_errors(connection, tables))
    return errors
