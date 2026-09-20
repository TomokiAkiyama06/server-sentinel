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
- Source and node health are persisted separately. A node heartbeat cannot make
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

The public contract is exported from `app.cameras.registry`:

```python
from app.cameras.registry import CameraRegistry, SourceType

registry = CameraRegistry(database)
source = registry.create_source(
    source_type=SourceType.LOCAL_UVC,
    name="Configured source",
    role_label="custom role",
    enabled=True,
)
registry.update_source(source.id, role_label="another custom role")
```

`create_capture_node`, `get_capture_node`, and `update_capture_node` handle node
records. `get_source`, `list_sources`, and `update_source` handle source
configuration. `update_source_health` accepts independent camera observations
and an optional negotiated profile. `NotFoundError` and `ValidationError` give
explicit domain failures; storage exceptions expose a fixed message without
submitted configuration, SQL values, or private deployment paths.

`server/tests/test_registry.py` uses synthetic SQLite databases to verify mixed
1–4 source collections, the fifth-source rejection, concurrent admission/limit
changes, rollback, restart/migration persistence, separate identities/health,
profiles/bindings, and invalid configuration. No hardware, real media, network,
physical reconnect, or capture-node pairing is claimed by those tests.
