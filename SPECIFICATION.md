# ServerSentinel Technical Specification

## 1. Architecture overview

ServerSentinel consists of four logical runtime areas:

1. **Main Ubuntu ServerSentinel Host** — authoritative configuration, recording, analysis, event correlation, retention, authorization, notifications.
2. **Local Camera Sources** — UVC/V4L2 cameras attached directly to the main host.
3. **Remote Capture Nodes** — owner-authorized Linux hosts running `media-capture-agent`, each exposing one or more locally attached UVC cameras to the main host over a private LAN.
4. **Human Web Clients** — invited phone/Mac/desktop browsers accessing the main host through Tailscale/private networking.

```text
Local UVC cameras                         Remote room-overview camera
┌───────────────┐                         ┌──────────────────────────┐
│ Webcam A/B    │                         │ Camera (e.g. CS-800)     │
└───────┬───────┘                         └────────────┬─────────────┘
        │ V4L2/UVC                                     │ USB/UVC
        │                                               v
        │                                  ┌──────────────────────────┐
        │                                  │ Linux capture machine    │
        │                                  │ media-capture-agent      │
        │                                  └────────────┬─────────────┘
        │                                   private LAN │ authenticated
        └───────────────────────────┬───────────────────┘
                                    v
                       ┌─────────────────────────────┐
                       │ Main ServerSentinel        │
                       │ source registry            │
                       │ ingest / recorder          │
                       │ detection workers          │
                       │ event/presence correlator  │
                       │ SQLite / file storage      │
                       │ authorization / Slack      │
                       └──────────────┬──────────────┘
                                      │ loopback/trusted proxy
                                      v
                       ┌─────────────────────────────┐
                       │ Tailscale Serve/private UI │
                       └──────────────┬──────────────┘
                                      v
                            invited phone / Mac
```

A deployment may contain 1–4 active video sources in any supported composition. No schema, algorithm, UI, or filesystem layout may assume fixed `front/rear` cameras or an iPhone.

Browser/iPhone camera capture is outside the current MVP. Human browsers are viewer clients.

## 2. Repository/runtime layout

Implementation directory skeleton (runtime behavior remains unimplemented):

```text
server/app/
├── api/
├── auth/
├── cameras/
│   ├── registry/
│   ├── uvc/
│   └── remote_agent/
├── detection/
├── events/
├── integrity/
├── media/
│   └── health/
├── notifications/
└── storage/

agent/
├── capture/
├── pairing/
├── transport/
├── service/
├── storage/
└── health/

web/src/
├── dashboard/
├── access/
├── recordings/
├── timeline/
├── setup/
└── shared/

tests/
├── unit/
├── integration/
├── e2e/
└── fixtures/
    └── synthetic/

infra/
├── systemd/
└── docker/

scripts/
```

`server/app/integrity/` owns Main Server hardware baseline checks; `server/app/media/health/` owns its recording-health self-test. Human authorization and trusted-proxy identity belong in `server/app/auth/`. Agent ring-buffer/protected-incident code belongs in `agent/storage/`; `agent/health/` tracks node/camera health. Runtime media, credentials, inventories, and databases live outside the source tree. Only synthetic/generated fixtures may be versioned under `tests/fixtures/synthetic/`.

The implemented #7 foundation uses explicit typed environment settings, an
existing deployment-local data directory, and transactional checksummed SQLite
migrations. Its human listener is loopback-only and all HTTP paths return a
generic denial; prepared health/version handlers are unmounted and schema/docs
routes are disabled until #6/#10 acceptance. No identity-header trust is
implemented by that shell. Its structured log formatter discards free-form
values and admits only reviewed event names and bounded numeric metadata.
The concrete settings, persistence and validation contract is documented in
[`server/docs/FOUNDATION.md`](server/docs/FOUNDATION.md).

The main application may use Docker Compose where appropriate. `media-capture-agent` is intended to run natively as a systemd service so UVC/udev/hotplug handling does not require a privileged container.

## 3. Camera Source domain model

### 3.1 Source types

MVP enum:

```text
local_uvc
remote_agent
```

Deferred/future candidates:

```text
rtsp
pi_node
```

### 3.2 Source record

Logical schema:

```text
camera_source
- id: UUID
- capture_node_id: nullable UUID
- source_type
- name
- role_label
- enabled
- capabilities
- desired_capture_profile
- negotiated_capture_profile
- health_state
- image_quality_state
- last_seen_at
- created_at
- updated_at
```

`capture_node_id = null` for main-host-local sources. Remote sources reference a separate capture-node UUID; one node may contain multiple source UUIDs. `role_label` is descriptive metadata, not a replacement for explicit profile configuration. Configuration and health updates preserve source UUIDs.

The in-process SQLite registry stores node health separately from source health. New source records start disabled, `offline`, with `unknown` image quality and no negotiated capture profile. Camera health supports `online`, `degraded`, `offline`, and `manual_intervention_required`; node liveness never implicitly changes camera health. Node health uses `online`, `degraded`, `offline`, and `revoked` as specified in section 5.8; the registry rejects node/source health types used interchangeably. Last-seen observations require timezone-aware timestamps and are normalized to UTC.

Desired and negotiated video profiles are independent optional records with width, height, fps, pixel format, codec, and bitrate fields. Unset fields do not select hardware defaults. `image_quality_state` stores the adapter's descriptive state; detector-specific quality gating remains the detector's responsibility. The registry does not interpret `unknown` as evidence that no person is present.

The implementation contract and bounded configuration validation are described in `server/app/cameras/registry/README.md`. Registry operations are internal only until the Owner authorization boundary in Issue #10 is implemented; no human management route is exposed by the registry.

### 3.3 Detection profile bindings

A source may have zero or more profiles:

```text
motion
person
server_roi
camera_tamper
entrance_crossing
owner_verification
image_quality
```

Each binding has its own UUID and contains a detector kind, JSON config, positive version, finite numeric thresholds, and enabled state. Multiple bindings may use the same detector kind, for example for distinct regions. Source type does not implicitly determine which profiles run.

### 3.4 Active-source limit

Initial `max_active_video_sources = 4`.

Activation that exceeds the configured limit returns an explicit validation error rather than silently replacing another source. The limit is persisted with registry configuration; lowering it below the current enabled count is rejected. Enabled sources continue to reserve capacity while offline or awaiting manual intervention. Admission, metadata changes, and binding updates are one serialized SQLite transaction, so concurrent requests cannot overbook or partially apply a rejected activation.

## 4. Physical UVC identity and reconnect

### 4.1 Discovery

On Linux enumerate V4L2/UVC-compatible devices. Persist a physical-device identity record from the strongest available stable evidence, for example:

- `/dev/v4l/by-id/` or equivalent stable symlink;
- USB serial number;
- udev properties;
- USB physical/topology path where appropriate;
- vendor/product IDs;
- negotiated capabilities/descriptors.

`/dev/videoN` alone is never durable identity.

### 4.2 Identity strength

Identity matching has an explicit confidence/strength result. A serial/by-id-backed match may be strong. Vendor/product/capabilities alone are insufficient to distinguish multiple otherwise identical non-serial devices.

Do not invent a synthetic fingerprint and treat it as unique when the underlying hardware exposes no unique data.

### 4.3 Ambiguous reconnect

If a previously approved source disappears:

```text
source -> offline
```

When devices reappear:

- if the prior physical camera can be matched unambiguously, reconnect automatically;
- if several candidates are indistinguishable, do **not** bind one automatically;
- transition to `manual_intervention_required` and show candidates to the owner for explicit re-approval;
- audit the decision and never report healthy monitoring against an unverified substitute.

This rule applies on both the main host and remote capture nodes.

### 4.4 Local adapter implementation boundary

The local adapter stores private approval evidence and a durable ambiguity latch
in the application database. A live approved weak binding does not constitute
proof for a subsequent reconnect or process restart. Discovery alone is never
`online`; successful frame capture is required. The initial implementation uses
bounded single-planar V4L2 MMAP on Linux x86_64/aarch64, reports the actual
negotiated dimensions/FPS/FourCC, and requires an explicit capture profile.
Unsupported multi-planar capture or codec/bitrate controls fail explicitly.
Source workers, Owner management and the preview frame sink are internal
interfaces; physical capture is not auto-started by the backend launcher and no
unauthenticated preview route is added. See `server/app/cameras/uvc/README.md`.

Identity reconciliation starts only after an active-session marker is durable.
An unclean session, including a failed ambiguity-latch write, requires Owner
reapproval at restart; it cannot fall back to an older clean approval record.
Clean shutdown releases this marker after closing capture while retaining any
manual-approval latch. A missing capture profile does not hide that latch.
Known duplicated serials remain unsuitable for automatic reconnect even after the current physical
candidate is explicitly approved. This confidence is stored separately from raw
device evidence. A different unique serial may establish a new strong identity.

## 5. `media-capture-agent`

### 5.1 Purpose

`media-capture-agent` captures video from UVC/V4L2 devices attached to another Linux machine and forwards it to the main ServerSentinel host.

The service/process/systemd unit uses the functional name `media-capture-agent` and does not masquerade as unrelated OS/vendor software.

### 5.2 Privilege model

Normal service execution:

```text
user: dedicated non-root account (e.g. mediacapture)
permissions: only required camera devices, config/credential path, bounded temp/buffer path, outbound network
GUI/tray: none required
```

Installation may require `sudo` to install the binary, create the account/unit, and configure narrow device permissions.

The Issue #12 native foundation uses Python 3.12+ standard-library modules under
`agent/media_capture_agent/`, with an executable zipapp release artifact and an
explicit systemd installer. Runtime/config/media directories are outside source
and installation trees. Until approved capture and authenticated transport adapters
are integrated, the production CLI remains visibly unconfigured and never starts
unauthenticated network communication. This foundation does not complete physical
Capture Node acceptance.

### 5.3 Audio

MVP agent capture is video-only. Do not open microphone/audio devices. No event/detection logic depends on audio.

### 5.4 Pairing

Preferred flow:

```text
Owner dashboard -> Add Capture Node
       |
       +-- short-lived one-time pairing code
       +-- public Main Server trust information via a trusted Owner channel
       |
Capture machine:
       +-- verify/configure intended Main Server trust through that channel
media-capture-agent pair --server <verified-LAN-endpoint>
       +-- authenticate Main Server and establish an encrypted channel
       +-- read pairing code through a non-echoing interactive prompt
       +-- send code only over that authenticated encrypted channel
       |
       +-- agent generates node keypair
       +-- main host validates current owner approval
       +-- revocable node credential/certificate established
```

Pairing credentials are cryptographically random, single-use, short-lived, and never logged plaintext. The CLI reads the code through a non-echoing interactive prompt; it does not accept the secret in command-line arguments, environment variables, or URLs. If a later installer needs non-interactive input, use a protected file descriptor/stdin channel without embedding the secret in shell command text, and preserve the same no-log boundary.

Before transmitting a pairing code, the Agent must authenticate the intended Main Server and establish confidentiality/integrity for the initial enrollment exchange. Private-LAN reachability or a short-lived code does not replace this server-authentication requirement. Public trust information must be obtained/verified through an Owner-controlled trusted local or out-of-band channel, independently of an unverified network endpoint. Missing/mismatched trust or certificate verification failure stops pairing without sending the code; plaintext or unverified-certificate fallback is forbidden.

The concrete bootstrap trust mechanism and initial encrypted transport remain PoC/ADR decisions before pairing implementation. These requirements do not select a particular certificate/pinning protocol. Post-pairing mTLS does not retroactively protect an insecure initial code exchange.

### 5.5 Long-lived trust

After pairing, use mutually authenticated encryption. mTLS with a deployment-local CA/issuer is the default target unless an ADR selects an equivalent mechanism.

Node identity is independent from source identity: one agent may later expose multiple cameras without gaining human/admin dashboard permissions.

### 5.6 Network direction

The agent initiates the long-lived connection toward the main host. The main host does not need inbound SSH/admin access to the capture machine.

The capture machine does not need Tailscale when it shares a private LAN with the main host.

### 5.7 Main-host ingest listener

Capture ingest is a dedicated LAN-facing service/route set, distinct from the human dashboard listener.

It accepts only agent protocol traffic and must not expose dashboard/settings/recording-browser endpoints.

Security layers:

1. mTLS/revocable agent credential — authoritative identity;
2. narrow bind/interface/firewall exposure;
3. optional source-address restriction when stable addressing is available;
4. rate/size/backpressure limits.

A LAN IP address alone never authenticates an agent.

### 5.8 Health model

Separate node and camera health:

```text
capture_node.health = online/degraded/offline/revoked
camera_source.health = online/degraded/offline/manual_intervention_required
```

Example: USB camera intentionally unplugged for another use:

```text
agent heartbeat: online
camera source: offline
camera_offline event: emitted
```

Reconnect is automatic only after unambiguous physical-device identity validation.

### 5.9 Clock synchronization

Node heartbeat carries monotonic/UTC timing information sufficient to estimate clock offset. Main and capture machines should use NTP/chrony or equivalent.

Excessive offset causes a visible degraded state/event because timeline ordering and media timestamps may be unreliable.

### 5.10 Configurable disk ring buffer

Each capture node maintains a rolling buffer of **compressed video segments on disk**. Configuration is owner-only and has two mutually exclusive modes:

```text
buffer_limit_mode = duration | capacity
```

**Duration mode**
- owner selects target rolling-buffer duration;
- UI derives/displays projected maximum and expected disk footprint from the configured/negotiated bounded media bitrate;
- runtime still obeys filesystem safety reserve.

**Capacity mode**
- owner selects maximum bytes/GiB usable by the rolling buffer;
- UI derives/displays estimated effective duration from the configured/negotiated bitrate;
- FIFO overwrite keeps ordinary ring-buffer data within the selected capacity.

In both modes the UI displays selected mode/value, estimated equivalent duration/capacity, current ring-buffer bytes, protected-incident bytes, filesystem free space, and safety reserve.

Configuration admission for the selected duration/capacity/profile checks both the **10-minute pre-loss window** and headroom for the **next 10 minutes while that window remains pinned**. Use bounded/negotiated bitrate and segment/container overhead to estimate the complete simultaneous 20-minute footprint on the expected filesystem, including existing protected-incident bytes, other filesystem use, and hard safety reserve. Count shared segments once; only eligible ordinary segments outside the required pre-loss window may be reclaimed for this check. The pinned pre-loss window and unexpired protected incidents are not reclaimable. Reject a determinably insufficient configuration before applying it: fitting 10 minutes plus reserve alone does not satisfy admission. The ordinary ring-buffer byte limit remains distinct from protected-incident usage; this check does not require changing duration/capacity mode or define a new numeric reserve.

Runtime uncertainty or later growth of protected/other filesystem usage may reduce post-loss headroom or pre-loss coverage. Reevaluate available headroom during storage admission and report degraded protection with actual coverage/gaps when it becomes insufficient; never claim a complete incident or permit writes across the safety reserve.

Normal unprotected segments are FIFO. Protected incident segments are not part of ordinary ring-buffer eviction.

### 5.11 Unexpected main-host communication loss

If the agent unexpectedly loses the authenticated connection/heartbeat to the main host, it automatically creates a temporary protected incident window:

```text
T-10 min                 T0                           T+10 min
|-------------------------|-----------------------------|
pre-loss ring buffer      connection/heartbeat lost     continue local capture
|<---------------------- protected 20 min ----------------------->|
```

Default behavior:

- pin the **10 minutes immediately preceding T0** from the disk ring buffer;
- continue writing locally for **10 minutes after T0**;
- protect the resulting default **20-minute** incident from ordinary ring-buffer overwrite;
- record why the protection was triggered and whether any segment gaps occurred.

This trigger is deliberately based on loss of the Main Server connection, because theft/disconnection may prevent the Main Server from issuing a final preserve command.

A later reconnect does not silently erase the protected incident. Its retention/deletion lifecycle is explicit.

### 5.12 Critical-event preserve command

If Main Server confirms `server_movement` or `camera_tamper` while the agent connection still exists, Main Server may request preservation of a relevant interval from the agent ring buffer. This complements—not replaces—the autonomous communication-loss protection.

The remote capture node is therefore a secondary evidence location for critical incidents, not a continuous mirror of all recordings.

### 5.13 Protected incident retention

Completed protected incidents remain on the capture agent for **60 days from incident completion by default** and are then automatically deleted from the agent.

The owner may explicitly delete a protected incident earlier. Reconnection to the Main Server, successful Main Server recording, or ordinary ring-buffer pressure does not by itself delete an unexpired protected incident.

Each protected incident records at minimum:

```text
incident_id
trigger_reason
started_at
ended_at
expires_at = ended_at + 60 days
byte_length
segment_gap/integrity state
```

### 5.14 Agent storage pressure

Agent-side disk safety is explicit. Track ordinary ring-buffer bytes, protected-incident bytes, selected ring-buffer limit, available filesystem capacity, and safety reserve.

If space becomes unsafe:

- reclaim eligible non-protected ring-buffer segments first;
- do not auto-delete a protected incident before its 60-day default expiry merely to satisfy ordinary buffer demand;
- surface `agent_storage_pressure`/equivalent state and an owner-visible warning;
- stop/refuse unsafe writes before crossing the filesystem safety reserve;
- if the full 10-minute pre-loss target or 10-minute post-loss continuation cannot be maintained, report the exact degraded/gap state rather than claiming complete protection.

### 5.15 Media-root mount safety

The Agent media root is a deployment-configured path outside the source tree that may live on a dedicated mounted filesystem. Public code/configuration must not embed an actual deployment path.

At install/startup/runtime admission, the Agent shall verify:
- the configured media root exists or can be created only by the intended installer/owner workflow;
- it resolves to the expected filesystem/mount/device and backing-filesystem-root identity; a narrow systemd namespace bind must map to the approved parent root plus the configured relative media path;
- sufficient free space and safety reserve remain;
- it is writable by the dedicated Agent service account;
- loss/unmount/substitution of the expected media filesystem does **not** silently redirect ring-buffer or incident writes into a directory on the root filesystem.

If the expected media filesystem is unavailable or resolves unexpectedly, Agent recording/buffering becomes explicit degraded/failed state and unsafe writes are refused until the Owner resolves or re-approves the target.

## 6. Media architecture

### 6.1 Separation of concerns

Treat these as separate profiles:

- **capture profile** — what the camera/agent obtains;
- **recording profile** — what is persisted;
- **inference profile** — resolution/FPS sampled by detectors;
- **viewer profile** — what a browser receives.

A room-overview source may use high-resolution capture/recording while inference uses downscaled 2–5 fps frames and viewers use adaptive 720p/1080p-class output.

### 6.2 Encode path

Preferred order:

1. passthrough/stream-copy compatible compressed video when safe/useful;
2. hardware encode/decode where available;
3. bounded software encode fallback.

Do not require a specific GPU vendor for correctness. Hardware acceleration is optimization.

### 6.3 Room-overview benchmark

For wide room coverage, real-hardware tests should compare at minimum:

- highest useful camera resolution at ~10–15 fps;
- 1080p/15 fps;
- resulting person/entrance detection accuracy;
- main/agent CPU, GPU, VRAM, LAN throughput, dropped frames;
- browser live latency/quality;
- ring-buffer disk throughput/capacity at candidate capture profiles.

Final defaults are measured, not guessed.

The transport-independent implementation in `server/app/media/profiles/` uses
explicit immutable profiles, conservative exact-descriptor copy eligibility,
bounded per-path compressed queues, and demand-driven viewer adapter lifetimes.
Before pipeline construction, scheduler-side admission can bind the complete
profile set to an exact allowlist discovered for that source and an explicit
active-source limit. Admission is atomic, does not infer profiles from source
type/role, and supplies no benchmark-derived defaults. The persisted Camera
Source registry remains authoritative for configuration. Successful admission
returns a generation-bound lease: profile adaptation must remain within its
complete-set allowlist and atomically updates the manager's selected profile set.
Pipeline construction atomically claims the lease only for that current selected
set and retains an opaque pipeline-specific ownership claim; a lease holder cannot
release or transition that claim, and the same lease cannot own two pipelines.
Stale generation teardown cannot release a later pipeline or the current source
reservation, and a released or superseded lease cannot construct or continue a
pipeline.
Inference sampling applies to presentation-ordered decoded frames, never to
compressed reference packets before decoding. Packet gaps reset dependency state
and require a keyframe; the capture profile also sets an explicit maximum forward
timestamp gap, independent of inference cadence. Known loss remains visible after
recovery. Source status combines capture continuity and mandatory recording with
viewer health only while viewers are subscribed; capture renegotiation or missing
recording capability is unavailable, and known loss/backpressure is degraded
rather than silently healthy. Missing codec
adapters report unavailable. Real codec/transport integration and measured
deployment defaults are still required; see that directory's integration contract.

### 6.4 Agent-to-main transport

Transport choice remains ADR/PoC work because the real network/camera environment is not yet available. Candidate technologies may include WebRTC, SRT, QUIC, or authenticated HTTP/streaming approaches.

Required behavior regardless of protocol:

- authenticated encrypted node session;
- bounded memory/queues;
- backpressure;
- reconnect;
- source/session identity;
- timestamp continuity/gap reporting;
- no arbitrary filesystem paths;
- no silent loss while reporting healthy.

### 6.5 Main-to-browser live transport

Phone/Mac/desktop users view live video **through the main host**, never directly from `media-capture-agent`.

The product goal is near-real-time viewing, but **stability, recovery, and continuous truthful state take priority over chasing the lowest possible latency**. No fixed sub-second target is required before PoC.

If an already encoded source can be safely relayed in a browser-compatible form, avoid unnecessary transcoding. Otherwise transcode/packetize on demand.

Viewer-only processing should scale down or stop when subscriber count is zero.

### 6.6 Durable recording

The main host is authoritative durable storage for normal operation. Recording metadata includes:

```text
recording_id
source_id
capture_node_id (nullable)
event_id (optional)
started_at
ended_at
codec/container
byte_length
checksum/integrity metadata
quality/gap metadata
```

Critical incident protection on `media-capture-agent` is a deliberate secondary-evidence exception, not a full mirror.

The internal `server/app/media/recording/` storage implementation uses generated
segment UUID filenames, byte digests, a pending-publication journal and per-source
event manifests. Its pre-roll has duration, byte and segment-count limits;
recording windows carry explicit clip intervals and integrity/gap/discontinuity
state. Restart retains committed media, cleans only journal-owned pending files
and marks active recordings interrupted. Runtime admission and codec validation
are mandatory injected boundaries; no human routes are enabled by this module.
See its README for the remaining worker integration and the distinction between
storage integrity and playable-media validation.

### 6.7 Main-host event ring buffer

Maintain recent **compressed** media where practical for pre-event evidence. Default target 30 s pre / 120 s post, max event 20 min.

Do not keep a long decoded-RGB frame history merely to implement pre-roll when compressed media can satisfy it.

## 7. Detection pipeline

### 7.1 General motion

Use lightweight temporal/background/flow methods as appropriate.

### 7.2 Person detection

Use a pluggable backend. Requirements: project-compatible license, CPU fallback, optional GPU acceleration, model/version metadata, code and weights license review separately.

YOLOX is an initial evaluation candidate only.

The Issue #20 foundation in `server/app/detection/foundation` uses transient grayscale frames, one bounded pending frame per source, independent Main-monotonic inference cadence, and an explicit worker entry point. Quality failure, missing models, stale observations, dropped frames, and evaluation failure produce `unknown`; known loss/throttling remains visible in health snapshots. No model is implicitly downloaded or enabled. The CPU motion baseline detects image change only. An optional RT-DETRv2 CPU adapter loads only a separately licensed, locally supplied, digest-pinned ONNX artifact on the audited Linux x86_64/CPython 3.12 runtime; no runtime model download or cloud/provider fallback is exposed. See `server/docs/DETECTOR_FOUNDATION.md` for limits and `server/docs/DETECTOR_MODEL_AUDIT.md` for separate code/weight evidence. Target-host performance and production worker isolation remain acceptance work.

### 7.3 Server movement

Per source/profile calibration stores server ROI/polygon, reference descriptors, background context, thresholds, and calibration version/time.

Runtime may combine global transform compensation, edges/contours, ROI similarity, temporal persistence, and person/occlusion masks.

### 7.4 Camera tamper

Candidate signals include global optical transform, persistent occlusion/near-black view, abrupt focus/exposure/scene-pose change, and disconnect closely following scene movement.

### 7.5 Detector-specific image-quality gate

Quality is not only for face verification. Every detector defines prerequisites required to make a trustworthy positive or negative conclusion.

Possible quality signals:

- luminance/underexposure;
- blur/sharpness;
- saturation;
- source resolution/crop size;
- target/face/person pixel size;
- obstruction;
- detector confidence/health.

A profile returns `sufficient`, `degraded`, or `insufficient` plus metrics/reasons.

If the person detector's prerequisites are insufficient, the result is `unknown`/unavailable. It is **not** converted to `no person`. The same fail-unknown principle applies to owner verification and dependent presence/entrance conclusions.

The internal implementation in `server/app/detection/quality/` uses explicit per-source/detector policy ranges and an explicit pixel budget; it provides no production thresholds. It measures bounded grayscale/RGB luminance, neighboring-pixel sharpness, clipping and resolution, and accepts frame-attributed calibrated target-size/obstruction/confidence context. Missing required context never defaults to adequate target size or zero obstruction. All configured prerequisites apply to both positive and negative conclusions.

Quality failure is immediate. Recovery requires the configured number of consecutive good frames (at least two); stream/sequence/geometry discontinuities and unavailable execution reset recovery. Reason codes, numeric metrics, profile version and source/stream/sequence are available for authorized UI integration. Detector stop/failure invalidates the last assessment without a new frame and, through the registered result sink, immediately replaces the source's published `present`/`absent` with `unknown`; an unusable frame, a pending recovery and an incomplete inference batch do the same. A stopped or failed detector never leaves a trustworthy conclusion readable until its observation age expires. The result guard rejects obsolete assessments and mismatched frame identities; the inference scheduler remains responsible for observation age. Live/recording delivery and unrelated critical detector profiles remain independent. Real-camera calibration is not established by synthetic quality tests.

### 7.6 Owner-only face verification

This is 1:1 verification against one explicitly enrolled deployment owner.

```text
person/face candidate
   -> detector-specific quality gate
   -> owner embedding comparison
   -> match / no-match / unknown
```

Owner biometric processing, including face-crop analysis/comparison, and template/model metadata stay deployment-local. External biometric processing/storage is not an opt-in MVP option, and configured third-party media infrastructure does not authorize sending faces/crops to a biometric service. Enrollment/delete/re-enroll require owner authorization; raw template/embedding is never logged or included in diagnostic exports, including explicit Owner-initiated exports. Persistent non-owner face-template/profile libraries are prohibited whether named or anonymous; ordinary authorized video recordings remain distinct from such a library.

### 7.7 Anonymous tracking and entrance

Non-owner observations may use ephemeral anonymous track IDs. Same-camera temporal tracking is allowed. Cross-camera biometric re-identification is not MVP.

Entrance/zone profile may emit anonymous/owner entry-exit observations only when direction/quality conditions are met.

## 8. Presence and timeline

Presence states:

```text
PRESENT
PROBABLY_PRESENT
ABSENT
UNKNOWN
```

Precedence:

1. explicit owner manual override;
2. high-confidence owner entrance/exit observations;
3. configured hints/schedules;
4. otherwise uncertain/unknown.

Only `PRESENT` suppresses ordinary occupancy automation by default. Server movement/camera tamper remain armed in every state.

Timeline correlation lists observations and relevant temporal context; it does not assert guilt/culpability/causality.

For invited non-owner users, historical timeline/event metadata is included with `recordings:view`. `live:view` alone exposes only current live/source-health information needed for live viewing.

## 9. Storage/admission

ServerSentinel distinguishes recording allocation from hard filesystem safety reserve.

Admission loop:

1. calculate recording use, starred use, filesystem free space, configured max, bounded critical allowance, hard reserve;
2. delete expired unstarred recordings;
3. reclaim oldest eligible unstarred recordings if allocation/free-space still unsafe;
4. enter `STORAGE_PRESSURE` and reject/suppress ordinary/manual disk recordings when necessary;
5. confirmed critical evidence may use only a bounded allowance that does not cross hard reserve;
6. enter `STORAGE_HARD_STOP` before any unsafe write;
7. starred recordings are not auto-deleted;
8. emit audit/UI state events;
9. recover with hysteresis.

Defaults: recording retention 20 days; audit retention 90 days.

Agent disk-buffer safety is tracked separately from Main Server storage because the two filesystems may be different machines.

The internal Issue #21 policy in `server/app/storage/` holds media plus configured
metadata/journal/temp reservations through the serialized recorder operation.
Physical-only control reservations cover startup recovery before inventory binding
and never recursively invoke retention. Expected media-root identity and the
private metadata file's filesystem are checked without symlink following or
fallback creation. All numeric reserve/quota/hysteresis/overhead limits are
explicit deployment configuration; only the specified retention defaults apply.
The critical allowance conservatively bounds resident critical evidence plus the
new reservation, surviving restart. Filesystem sampling includes other processes
but cannot prevent unrelated writes after the sample. A failed state-audit write
remains visible as a failure flag. The domain recording browser defaults to deny,
requires `recordings:view` for history and Owner for star/unstar/single deletion;
it mounts no human endpoint pending #10.

`server/app/notifications/` provides optional direct Slack incoming-webhook
delivery using verified HTTPS, no environment proxy/redirect, bounded timeout and
redacted failures. Unconfigured delivery performs no network operation. The
current payload is a fixed critical category or validated daily aggregate, with
no image/media, source identity or arbitrary probe details. Both immediate and
daily notifications enqueue on a bounded delivery worker; the recorder worker
never waits for network IO. Local pending/result events share an ID and are
persisted only on the owning worker. Full queues and failed persistence remain
visible; completion-persistence retry never resends a message. The persisted daily
scheduler defaults to 23:00 configured local time and claims one dispatch per
local date across restart/DST/clock rollback; missed dates are not replayed.
An uncertain crash remains `pending`, failed delivery is visible, and no implicit
retry floods the channel. Production timers, durable event-outbox integration,
human authorization and recording playback remain separate integration work.

## 10. Host hardware integrity and recording self-check

### 10.1 Hardware baseline

During setup, the Owner approves a baseline inventory for the main ServerSentinel host. Collect the strongest local identifiers available without pretending that unavailable identifiers exist.

Representative Linux data sources may include sysfs/udev, SMBIOS/DMI, `lsblk`/block-device metadata, NVMe identify/health data, SMART data, and NVIDIA GPU UUID/serial/PCI metadata where applicable.

Baseline categories:

```text
CPU
- model/signature/topology where available

Memory
- slot
- capacity
- part number
- serial where available

NVMe / M.2 / HDD
- model
- serial / WWN-style stable identity where available
- capacity
- expected mount/filesystem role

GPU
- model
- GPU UUID/serial where available
- PCI identity where useful
```

The UI/API must represent missing unique identifiers honestly. If the platform exposes no stable per-device identifier for a same-model replacement, ServerSentinel must not claim it can prove that the physical component is unchanged.

### 10.2 Inventory cadence and states

Run inventory comparison:
- at ServerSentinel startup; and
- at least once every 24 hours while running.

Per component/result, support at least:

```text
OK
CHANGED
MISSING
NEW_DEVICE
UNVERIFIABLE
```

Hardware drift never mutates the approved baseline automatically. The Owner must explicitly approve a new baseline/change. That approval is audited.

### 10.3 Recording-health self-test

At least once per day, run an end-to-end recording-health check. It should verify as much of the actual recording path as practical:

1. enabled Camera Sources have fresh frames or an explicit truthful offline/degraded state;
2. recorder/encoder pipeline is alive;
3. configured recording root resolves to the expected filesystem/device rather than an accidental fallback mount;
4. the expected target is writable and free-space/safety-reserve admission is valid;
5. write a short bounded temporary media segment through the recording path;
6. flush/fsync it;
7. reopen it and validate container/duration/size and decode/readability as appropriate;
8. clean up self-test-owned temporary/partial media whether validation succeeds, fails, or is cancelled;
9. read available SMART/NVMe health indicators without making unsupported lifetime predictions.

Missing/unmounted or substituted recording filesystems refuse recording and self-test media writes to that target. Do not create or use a replacement directory on the root filesystem or another unintended filesystem; reporting degradation does not permit fallback writes.

Run cleanup through the failure/cancellation path as well as the successful path. On startup, recover identified artifacts from interrupted tests and clean them before admitting another self-test segment. Cleanup verifies the expected filesystem and targets only self-test-owned artifacts; it never deletes ordinary recordings/protected incidents or creates a fallback on an unexpected mount. If cleanup fails (for example, a missing or read-only mount), record a recording-health failure, account for the leftovers in storage admission/safety-reserve checks, and block new self-test media writes until safe cleanup succeeds. Continue reporting the failed/blocked state rather than accumulating a new partial segment each day.

A self-test failure must not be hidden behind a generic healthy state.

### 10.4 Alerting

The following are immediate Owner-alert conditions rather than waiting only for the scheduled daily summary:

- approved CPU/RAM/NVMe/HDD/GPU baseline component becomes `CHANGED` or `MISSING`;
- recording storage resolves to an unexpected device/mount;
- recording-health write/reopen/decode test fails;
- storage health reports a material critical warning that threatens recording availability.

`NEW_DEVICE` and `UNVERIFIABLE` are at least warnings; escalate when they materially prevent assurance of the configured recording path.

Notification delivery follows configured local/UI/Slack channels. Slack remains optional; disabling Slack does not suppress the dashboard/audit fault state.

### 10.5 Privacy and privilege

Detailed hardware identifiers are deployment-local security metadata. Do not send raw serials/UUIDs through telemetry or developer infrastructure. Normal operational logs and general diagnostics must redact/hash them. A detailed diagnostic export requires an explicit Owner action and does not authorize automatic upload.

Hardware/SMART probing must use the least privilege practical. Do not run the whole ServerSentinel stack as root merely to obtain inventory/health data; use narrow host permissions/helper boundaries if privileged probes are required.

## 11. Human access architecture

### 11.1 Tailscale reachability vs application authorization

Tailscale provides private transport/reachability. ServerSentinel authorization is independent:

```text
Tailnet/private-network reachability
       +
ServerSentinel owner invitation
       +
verified ServerSentinel per-person credential
       +
per-user permission
       =
application access

supplementary, never sufficient:
verified Tailscale/trusted-proxy identity (account-level)
```

Tailnet membership by itself grants no ServerSentinel application data.

The two gates are unchanged: a network-level permission path and an application authorization. Inside the application gate the owner invitation names the principal and the per-person credential proves who is presenting it.

A verified Tailscale/trusted-proxy identity is handled per AUTH-005: where the deployment provides one it is accepted only on the trusted local path, and it may be recorded and additionally required. It is never a term that can grant access on its own. In this deployment the Tailnet account is shared by the research room, so that identity names the account the request arrived under, not the person; see §11.8.

### 11.2 Tailnet policy is not managed by ServerSentinel

ServerSentinel does **not** modify Tailscale ACLs/Grants or store Tailscale administrative credentials; policy administration remains outside the application. The owner's existing Tailnet policy may remain unchanged.

Important limitation: when Tailnet policy is left unchanged, ServerSentinel cannot promise network-level concealment of the **main Tailscale node itself** from other Tailnet members. Application authorization can prevent them from seeing ServerSentinel camera/media/deployment data, but Tailscale peer/device visibility is controlled by Tailscale policy, not by the ServerSentinel application.

If network-level node concealment is later required, it is an external deployment choice (for example restrictive Tailnet policy or a separate/private Tailnet architecture), not an in-app permission feature.

### 11.3 Trusted proxy boundary

Human UI/API should listen on loopback (or another non-bypassable trusted local boundary) behind Tailscale Serve/equivalent.

If proxy-supplied identity headers are used, accept them only from that path. LAN clients must not be able to reach the same backend listener and spoof identity headers.

### 11.4 In-app principals

Logical model:

```text
access_principal
- id
- display_name
- status: invited/active/revoked
- created_at
- revoked_at
- external_identity (optional, supplementary: verified Tailscale login/device
  as observed at authentication; not authoritative, see §11.8)

principal_credential
- id
- principal_id
- kind (WebAuthn/passkey, per ADR-0004)
- credential_id
- public_key (public material only; never a biometric template)
- user_verification: required (asserted at registration, verified again at
  every authentication)
- label (owner-visible hint, not proof of a device)
- created_at
- last_used_at
- revoked_at

principal_enrollment
- id
- principal_id
- code_hash (the raw enrollment code is never stored or logged)
- expires_at
- redeemed_at (single use)
- attempt_count (bounded; redemption is rate-limited)

principal_session
- id
- principal_id
- credential_id (the credential that created the session)
- created_at
- last_seen_at
- idle_expires_at / absolute_expires_at (server-enforced)
- last_user_verification_at (freshness source for owner step-up)
- revoked_at

principal_permission
- principal_id
- permission
```

Revocation cascades through these records: revoking a `principal_credential`
revokes the `principal_session` rows bound to it, and revoking the
`access_principal` revokes all of its credentials, enrollments and sessions.

A principal is created by an owner invitation that carries a short-lived,
single-use enrollment code; the invited person redeems it once to register a
credential. Credentials are revocable individually and with the principal.

Registration and every authentication require authenticator user verification,
and the authenticator must be one the invited person controls. A platform
authenticator kept inside a shared OS account or behind a shared device unlock
is a shared credential and does not satisfy §11.8; such a machine needs a
per-person OS account or a portable authenticator the person carries.

A session is a server-side record bound to one principal and to the credential
that created it. Sign-out, idle/absolute expiry and revocation invalidate that
record, so a retained cookie or token authorizes nothing afterwards; §11.5
authorization re-checks it on every human/media route and never relies on
client-side state. Idle and absolute lifetimes are deployment-configured and
server-enforced, an explicit sign-out is available for shared machines, and
owner-only routes require a fresh user-verification step rather than an older
session.

User verification runs on the viewer's own device, and its result reaches the
server only as the authenticator's user-verification flag. The WebAuthn protocol
data needed to check a registration or assertion — the server-issued challenge,
client data, authenticator data, the attestation or assertion signature, the
signature counter and the user-verification flag — is received and verified,
including the relying-party id and origin. That data is transient: only the
fields of `principal_credential` and `principal_session` persist, and the rest is
discarded once verified.

What never reaches ServerSentinel is biometric material. No fingerprint or face
template leaves the authenticator, so none is received, persisted or exportable
here. `principal_credential` is an access-control record, unrelated to the
optional owner face verification of §7.6 and never a non-owner identity or
biometric database (see `PRIVACY.md`).

Relying-party verification depends on ServerSentinel owning its browser origin:
the dashboard is served from an origin reserved for it, with no other
application sharing it, as ADR-0003 requires.

Initial non-owner permissions:

```text
live:view
recordings:view
```

They are independent.

### 11.5 Route authorization

Examples:

```text
GET /api/live/<source>                  -> live:view
GET /api/recordings                     -> recordings:view
GET /api/recordings/<id>/playback       -> recordings:view
GET /api/events                         -> recordings:view
GET /api/timeline                       -> recordings:view
POST/DELETE camera/agent/settings       -> owner + fresh user verification
POST access invitations/permissions     -> owner + fresh user verification
POST biometric enroll/delete            -> owner + fresh user verification
DELETE recording                         -> owner + fresh user verification
```

"Fresh" means a user verification newer than a bounded freshness window, so an
older or unattended owner session cannot perform an AUTH-008 operation by
itself. Freshness is evaluated server-side from
`principal_session.last_user_verification_at`; a client cannot assert it.

The main-to-Web contract for the step-up is explicit, because the dashboard has
to know when to prompt:

```text
owner route, session fresh      -> the operation runs
owner route, session stale      -> distinct step_up_required response, no other data
step-up assertion succeeds      -> last_user_verification_at updates; client retries
retry                           -> permission and freshness re-checked server-side
step-up cancelled/failed        -> generic failure; nothing executed, nothing changed
```

The `step_up_required` signal is returned only to an already authenticated
session that holds the required permission. Anything unauthenticated, uninvited
or revoked still receives the generic response below and learns nothing about
owner routes. Repeated failed step-ups are rate-limited and logged without
credential material, and a stale session never partially applies an operation.

Exactly three request classes run before a credential exists, and the set is
closed:

```text
local owner bootstrap      -> privileged local action on the main host, not a remote route
invitation redemption      -> valid, unexpired, unredeemed enrollment code only
credential authentication  -> the assertion route itself
```

Owner bootstrap is a privileged local administrative action on the Main Server;
there is no remote first-visitor setup. Invitation redemption is single-use and
rate-limited and registers exactly one `principal_credential` for the named
principal. It returns no camera, recording, timeline or deployment data and
grants no application access by itself: the invited person then authenticates
like anyone else. An absent, unknown, expired or already-redeemed code receives
the same generic response as an uninvited person, and logs record the attempt
without the raw code. Every other human/media route requires a verified
credential and an active session.

Unauthorized users get no ServerSentinel deployment metadata, camera names/counts, thumbnails, event details, or recordings. For an uninvited identity, prefer a generic/non-branding denial such as a not-found-style response and do not expose product/version headers, API schema, health details, or other ServerSentinel fingerprints. This does not claim that the underlying Tailscale node/service is network-invisible when Tailnet policy is unchanged.

### 11.6 Browser-only recording access

No official non-owner recording download/export route/button in MVP. Playback manifests/segments remain authorization-protected and short-lived/session-bound as practical; a copied URL does not become public.

This is not DRM. A user who can view video may still screen-record or use advanced client tooling, and the UI/docs must not claim otherwise.

### 11.7 Revocation

ServerSentinel permission revocation invalidates application access promptly. Tailnet membership/policy remains a separate Tailscale administrative concern.

Revocation is credential-scoped, not device-scoped. Revoking a single `principal_credential` invalidates that credential and the sessions bound to it; revoking the `access_principal` invalidates all of its credentials and active sessions.

A synced passkey is one credential that can exist on several of its owner's devices, so revoking it disables it everywhere it synced, and losing one device does not by itself isolate a credential to revoke. The UI and documentation therefore describe revocation as credential-scoped and treat the label as a hint. A deployment that needs device-scoped control configures device-bound authenticators and refuses backup-eligible credentials at registration; that choice is a deployment setting, not a promise the product makes by default.

### 11.8 Shared Tailnet account

The research-room Tailnet uses one shared Tailscale account for cost reasons, so
multiple people authenticate to Tailscale as the same login and any of them can
add devices.

Therefore:

- application authorization is decided by the ServerSentinel credential
  (`principal_credential`), not by the Tailscale login;
- a verified proxy identity header may be recorded and may be required in
  addition, but never substitutes for the credential check;
- device-scoped approval is supplementary. A shared lab PC is used by whoever
  sits at it, so device approval must not be described as identifying a person;
- unauthenticated requests receive the §11.5 generic response. The response for
  an uninvited person and for a revoked person is the same, and the
  authentication prompt carries no product/version string, camera information,
  or deployment metadata;
- reachability guarantees nothing here: everyone with the shared account can
  reach the listener, which is the expected state, not an incident;
- a credential is person-bound only under the §11.4 user-verification and
  authenticator-custody rules. Without them a passkey stored in a shared profile
  authorizes whoever uses that profile;
- ServerSentinel cannot observe a deliberately lent credential or a session left
  unlocked on an unattended machine. Documentation states this limit instead of
  claiming the application separates people who share a workstation.

## 12. Dashboard UI

The #8 foundation is a Japanese-default React/TypeScript shell with an English
catalog and six initial placeholders. Its production entry denies access and
makes no API calls; synthetic session/source providers exist only in tests.
The injectable GET client permits only same-origin `/api/` paths, disables
redirects/caching, and returns fixed local failure codes. This foundation
establishes no session endpoint or authentication method.

Until #10 supplies human-access integration, generated assets and loopback-only
preview are development/test artifacts. Production integration must protect the
full HTML/JS/CSS/icon/map/worker/config namespace through the human listener,
independent of UI visibility. Never mount these assets on the capture listener
or an unauthenticated static host. See `web/README.md`.

Primary views:

- Overview/status;
- Camera Sources;
- Capture Nodes;
- Live Grid;
- Events/Timeline;
- Recordings;
- Presence;
- Owner Verification;
- Access;
- Storage;
- Slack;
- Audit;
- Setup/security.

Live layout:
- 1 source: single large view;
- 2 sources: split/two-up;
- 3–4: responsive grid.

Camera/source cards show source name/type/role, capture node where applicable, source health, node health, negotiated capture/view quality, detector quality, and manual-intervention state.

Capture-node settings additionally show:

- ring-buffer mode: duration or disk capacity;
- configured value plus estimated equivalent duration/capacity;
- projected maximum/expected and current buffer usage;
- protected-incident usage and 60-day default expiry timestamps;
- agent filesystem free/safety state;
- whether the 10-minute pre-loss target and headroom for 10-minute post-loss continuation are currently satisfied;
- Main Server connection/heartbeat state.

## 13. Security boundaries

### 13.1 Capture node != human user

A paired `media-capture-agent` may send camera/health data and receive narrowly scoped media-preservation/control requests only. Its credential never grants dashboard/admin access.

### 13.2 Media validation

Validate authenticated node, expected source/session, rate/size bounds, allowed codecs/containers, generated safe filenames, integrity metadata, and bounded queues. No client-controlled arbitrary output paths.

### 13.3 Biometrics

Owner template is sensitive secret-adjacent data, excluded from logs/general APIs/diagnostics and limited to the verification/config path. Non-owner persistent biometric templates are prohibited.

A viewer's WebAuthn user verification is not ServerSentinel biometric processing: the fingerprint/face check happens on the viewer's own device and only public credential material reaches the server (§11.4). It creates no template, no enrollment and no identity database here.

## 14. Performance/overload policy

Four active sources are a test target, not a promise of maximum camera modes on all hardware.

Resource priority:

1. keep node/source health truthful;
2. preserve critical server movement/tamper processing/evidence where safe;
3. preserve recording/ring-buffer integrity and disk safety;
4. reduce expensive inference cadence;
5. reduce viewer bitrate/FPS/resolution;
6. report degraded state;
7. never silently drop a source while claiming healthy.

Measure USB controller bandwidth, agent/main CPU/GPU/VRAM, encode/decode capacity, LAN throughput, disk write rate, ring-buffer footprint, viewer latency, reconnect behavior, and dropped frames.

## 15. Testing and fixtures

Repository/CI media fixtures are **synthetic/generated only**.

Real-person/real-room/real-monitoring footage—including publicly licensed real-person benchmark media—is not committed or attached to GitHub PRs/issues/actions artifacts. External real-person datasets may be used only for local evaluation under their terms and are not repository fixtures.

Required test families include:

- source registry 1–4 cameras;
- UVC stable mapping/reconnect;
- two indistinguishable non-serial UVC devices and forced manual re-approval;
- capture-agent pairing/revocation/mTLS;
- camera-unplug while agent remains online;
- clock skew/health degradation;
- LAN interruption/reconnect/backpressure;
- configurable bounded disk ring buffer, including rejection of settings that fit pre-loss alone but not simultaneous T-10/T+10 protection with existing protected bytes, other filesystem use, and hard reserve;
- Main Server heartbeat loss pins previous 10 min and records next 10 min;
- reconnect does not silently delete protected incident;
- agent storage-pressure behavior and 60-day protected-incident expiry;
- configured Agent media-root mount loss/substitution refuses fallback writes;
- critical preserve command while connection remains available;
- multi-source recording/event linkage;
- detector-specific low-light gating, including person detector `unknown` rather than false negative;
- owner match/no-match/unknown with synthetic/generated assets;
- anonymous tracking/entrance;
- presence/timeline;
- storage pressure/hard stop;
- Main Server startup/daily hardware comparison and Owner-only baseline approval;
- daily recording-health self-test, mount fail-safe, and immediate failure notification;
- invited-user `live:view` / `recordings:view` boundaries;
- phone/Mac live-view authorization;
- mock E2E.

Real hardware/network/browser validation lives in `MANUAL_TEST.md`.

## 16. Deliberately unresolved decisions

Require explicit owner decision/ADR/Issue before implementation where material:

- exact `media-capture-agent` -> Main Server media transport/reconnection protocol after real LAN testing;
- exact Main Server -> browser live transport after PoC, with stability prioritized over minimum latency;
- exact capture/record/inference/view resolution/FPS/bitrate defaults after camera/model measurement;
- exact filesystem safety-reserve thresholds/warning thresholds for the agent buffer UI after measuring the target capture host;
- final owner face-verification model/weights/license/threshold after hardware is available.
