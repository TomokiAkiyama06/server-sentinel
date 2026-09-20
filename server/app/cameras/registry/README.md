# Camera and Capture Node Registry

`CameraRegistry` is an in-process SQLite configuration service. Apply the
application migrations before constructing it. It opens and closes a connection
per operation, so independent callers can share one deployment database. No HTTP
route, device probing, capture process, or authentication grant is added here.
Issue #10 must provide the Owner authorization boundary before exposing human
management operations.

- Sources form a collection keyed by generated logical UUIDs. Name, custom role,
  configuration, health, and reconnect observations never replace that UUID.
- `local_uvc` has a null `capture_node_id`. `remote_agent` refers to an existing
  capture-node UUID distinct from the source UUID. Several sources may share a
  node. Creating a node record does not pair or authorize a capture machine.
- `SourceHealthState` and `NodeHealthState` are distinct types persisted with
  separate state sets. Nodes use online/degraded/offline/revoked; sources use
  online/degraded/offline/manual_intervention_required. A node heartbeat cannot make
  an offline or ambiguous camera healthy. The UVC adapter owns identity matching
  and the Owner re-approval required to resolve an ambiguous reconnect.
- `enabled` reserves an active-source slot even when health is offline,
  degraded, or `manual_intervention_required`. New sources default to disabled,
  offline, unknown image quality, and no negotiated profile.
- `max_active_video_sources` is a durable singleton setting, initially 4.
  `set_active_limit()` validates positive integers and refuses to lower the limit
  below the currently enabled count. Configuration updates and admission checks
  use `BEGIN IMMEDIATE`; concurrent callers cannot overbook capacity. Exceeding
  the limit raises `ActiveSourceLimitError` and rolls back the whole requested
  change, including metadata and bindings. Existing sources remain unchanged.
- Desired and negotiated `CaptureProfile` values are independent. The optional
  video fields are width, height, fps, pixel format, codec, and bitrate in bits
  per second. Unset fields have no hardware default; there is no audio setting.
- A source may have multiple `DetectionBinding` records, including different
  regions for the same detector kind. Each has a UUID, kind, positive version,
  enabled flag, finite numeric thresholds, and a JSON configuration object.
  Bindings do not start detectors or enroll identities.
- Capabilities and binding configurations accept bounded JSON objects, with
  finite numbers, string keys, at most 32 nesting levels / 8192 values / 64 KiB
  serialized per object. Returned JSON values are detached from persisted state.
- Observed last-seen timestamps require timezone information and are stored in
  UTC. Image-quality state is descriptive adapter metadata, initially `unknown`;
  the registry never converts unknown quality into a negative detection result.

The public contract is exported from `app.cameras.registry`. Privileged
configuration changes — creating or changing a source or capture node and
changing the active-source limit — run through the audited Owner boundary, so
each one commits with its durable security/admin audit record:

```python
from app.audit.integration import OwnerAdministration
from app.cameras.registry import CameraRegistry, SourceType

registry = CameraRegistry(database)
administration = OwnerAdministration(owner_audit_service, registry)
source = administration.create_source(
    actor_context,
    source_type=SourceType.LOCAL_UVC,
    name="Configured source",
    role_label="custom role",
    enabled=True,
)
administration.update_source(actor_context, source.id, role_label="another custom role")
```

The registry's own `set_active_limit`, `create_capture_node`,
`update_capture_node`, `create_source` and `update_source` wrappers commit
their own transaction with no authorization, audit record or storage
admission, so a runtime registry refuses them with `UnauditedWriteError`.
Fixture, bootstrap and migration tooling that is explicitly not the runtime
opts in with `CameraRegistry(database, unaudited_writes=True)`.

`get_capture_node`, `get_source` and `list_sources` read node and source
configuration. `update_source_health` accepts independent camera observations
and an optional negotiated profile; health is an observation rather than an
Owner decision, so it stays available without the audited boundary. `NotFoundError` and `ValidationError` give
explicit domain failures; storage exceptions expose a fixed message without
submitted configuration, SQL values, or private deployment paths.

`server/tests/test_registry.py` uses synthetic SQLite databases to verify mixed
1–4 source collections, the fifth-source rejection, concurrent admission/limit
changes, rollback, restart/migration persistence, separate identities/health,
profiles/bindings, and invalid configuration. No hardware, real media, network,
physical reconnect, or capture-node pairing is claimed by those tests.
