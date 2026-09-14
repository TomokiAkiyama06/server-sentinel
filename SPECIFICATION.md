# ServerSentinel Technical Specification

## 1. Architecture overview

ServerSentinel consists of three primary runtime components:

1. **iOS Camera Node**
2. **Ubuntu Server**
3. **Web Dashboard**

Optional integrations:
- Tailscale
- Slack
- iOS Shortcuts

```text
+----------------------+          +-----------------------------+
| iOS Camera Node      |          | Ubuntu ServerSentinel       |
|----------------------|   LAN    |-----------------------------|
| AVFoundation         |<-------->| API / Session Controller    |
| Front + Rear camera  |          | Recorder                    |
| Microphone           |          | Detection Workers           |
| CoreMotion           |          | SQLite                      |
| Thermal/Power state  |          | File Storage                |
| Local emergency buf  |          | Slack Integration           |
+----------------------+          +---------------+-------------+
                                                 |
                                                 | local HTTP(S)
                                                 v
                                      +--------------------------+
                                      | React Dashboard          |
                                      +--------------------------+
                                                 |
                                                 | Tailscale
                                                 v
                                      +--------------------------+
                                      | Remote owner browser     |
                                      +--------------------------+
```

## 2. Proposed repository layout

```text
server-sentinel/
├── README.md
├── REQUIREMENTS.md
├── SPECIFICATION.md
├── AGENTS.md
├── MANUAL_TEST.md
├── SECURITY.md
├── PRIVACY.md
├── CONTRIBUTING.md
├── ROADMAP.md
├── LICENSE
├── NOTICE
├── .gitignore
├── .env.example
├── ios/
│   └── README.md
├── server/
│   └── README.md
├── web/
│   └── README.md
├── infra/
│   └── README.md
├── tests/
│   └── fixtures/
│       └── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SETUP.md
│   ├── APP_REVIEW.md
│   ├── THIRD_PARTY_POLICY.md
│   ├── ADR/
│   │   ├── README.md
│   │   └── 0001-project-foundations.md
│   └── proposals/
│       └── README.md
└── .github/
    ├── pull_request_template.md
    └── ISSUE_TEMPLATE/
        ├── bug_report.md
        ├── feature_request.md
        └── hardware_test.md
```

Expected implementation expansion:

```text
server/
├── app/
│   ├── api/
│   ├── core/
│   ├── db/
│   ├── detection/
│   ├── media/
│   ├── notifications/
│   ├── pairing/
│   └── storage/
├── migrations/
└── tests/

web/
├── src/
└── tests/

ios/
├── ServerSentinelCamera/
├── ServerSentinelCameraTests/
└── ServerSentinelCameraUITests/
```

## 3. iOS Camera Node

### 3.1 Technology

- Swift
- SwiftUI
- AVFoundation
- CoreMotion
- Network framework as appropriate
- Keychain for long-lived credentials
- File protection APIs for emergency local clips

### 3.2 Capture graph

Preferred full-capability mode:

```text
Rear camera  --------\
                      +--> Encoder / Session transport
Front camera --------/
Microphone ---------/

Accelerometer ------\
Gyroscope -----------+--> Tamper telemetry
Thermal state -------/
```

The implementation MUST call/check MultiCam capability before attempting simultaneous capture.

### 3.3 Capture profile

Initial targets, not hard guarantees:

- Rear: up to 1080p, target 15–30 fps
- Front: lower-cost profile, initially 720p / 5–15 fps
- Remote dashboard live target: 720p / 15–30 fps

Exact profiles shall be benchmarked on iPhone 14 and adjusted by thermal/load policy.

### 3.4 Thermal policy

Suggested degradation order:

1. Lower front-camera FPS.
2. Lower front-camera resolution.
3. Reduce non-critical analysis preview rate.
4. Lower rear live-stream bitrate/FPS while preserving evidence recording.
5. Disable non-essential preview rendering.
6. If critical thermal state persists, surface degraded state and preserve the most important capture path possible.

Every thermal transition shall create an audit event.

### 3.5 Local emergency buffer

Maintain a bounded local critical-event store.

Initial target:
- 500 MB.

Critical event classes:
- server movement;
- camera tamper.

Behavior:
- preserve pre-event data if feasible;
- preserve post-event data;
- mark unsynchronized critical clips explicitly;
- retry upload after reconnect;
- reclaim synchronized/unprotected emergency data before any unsynchronized critical evidence;
- never silently overwrite an unsynchronized critical clip solely because local capacity was reached;
- evaluate **both** the configured ServerSentinel local-store bound and the iPhone's OS-reported currently available storage before admitting a new local clip;
- preserve a device-level safety reserve outside the ServerSentinel local-store budget so emergency evidence cannot intentionally drive the iPhone filesystem to exhaustion;
- avoid storing ordinary motion events locally unless needed by the media architecture.

Admission policy:
1. Before opening or extending a local emergency clip, estimate a conservative write budget for the next segment/clip finalization, including media, metadata, and container-finalization overhead.
2. Admission succeeds only when that projected write fits both:
   - the remaining configured ServerSentinel local-emergency-store budget; and
   - the current OS-reported available device capacity after subtracting the device safety reserve.
3. A low device-wide free-space condition can therefore block local evidence admission even when ServerSentinel itself is far below its 500 MB configured bound.
4. Storage-capacity queries and write failures are treated as security-relevant state; a failed capacity query must not be interpreted as unlimited free space.

Overflow / low-device-space policy:
1. Reclaim the oldest synchronized/unprotected local emergency data first.
2. If only unsynchronized critical clips remain and admitting a new local critical clip would exceed the configured local bound **or** violate the device-level safety reserve, enter `LOCAL_EVIDENCE_HARD_STOP` rather than deleting existing unsynchronized evidence or attempting a write expected to exhaust the filesystem.
3. While `LOCAL_EVIDENCE_HARD_STOP` is active:
   - continue critical detection;
   - continue live transport and direct server upload when available;
   - refuse only new **iPhone-local** emergency clip admission that cannot satisfy both storage constraints;
   - surface a persistent local/UI warning and audit state;
   - record minimal metadata for rejected local evidence when safely possible, including event type/time and reason (`local_evidence_capacity_exhausted` or `device_free_space_unsafe`), without claiming a clip exists.
4. Automatically leave `LOCAL_EVIDENCE_HARD_STOP` only after both the configured local-store headroom and OS-reported device free space are safely above their respective recovery thresholds; use hysteresis to avoid state flapping.

The exact device safety reserve, conservative projected-write budget, local recovery threshold, and any reserved metadata budget shall be finalized through real-device storage/thermal testing. Tests must include the case where ServerSentinel local usage is low but unrelated apps/system data consume most of the iPhone storage. Unsynchronized evidence loss must never be silent.

### 3.6 Monitoring UI

Armed screen:
- near-black background;
- visible monitoring state;
- visible recording state;
- visible microphone state;
- visible server connection state.

Tap:
- show controls;
- optionally raise brightness to a configured working level;
- auto-return to dim state after configurable timeout.

When app stops monitoring:
- restore prior brightness where safe;
- re-enable normal idle behavior.

### 3.7 Foreground expectation

The dedicated Camera Node is expected to remain foreground/active during monitoring.

The implementation must not assume that iOS permits indefinite camera capture after:
- app kill;
- device shutdown;
- unsupported background transition.

If capture cannot continue, state becomes disconnected/manual-intervention as appropriate.

## 4. Media transport

### 4.1 Separation of concerns

Live video and evidence recording are separate reliability problems.

- **Live transport**: low latency.
- **Recording transport**: durable, retryable, integrity-checked.

The implementation shall not make successful evidence retention depend solely on an uninterrupted live-view session.

### 4.2 Live transport decision

The first implementation Issue shall create a PoC comparing candidate transports, with WebRTC expected to be evaluated first.

The ADR shall record:
- measured LAN latency;
- reconnect behavior;
- CPU/GPU usage;
- iPhone thermal impact;
- browser compatibility;
- NAT/Tailscale behavior;
- maintenance burden;
- dependency licensing.

### 4.3 Recording chunks

Recommended behavior:
- media segmented into bounded chunks;
- chunk identifier;
- event/session identifier;
- start/end timestamps;
- sequence number;
- checksum;
- codec metadata;
- camera source;
- retry count.

Upload must be idempotent.

### 4.4 Codec

Do not hard-code final codec until iPhone and Ubuntu measurements exist.

Selection criteria:
- iOS hardware encode support;
- browser playback;
- storage size;
- Ubuntu decode/AI pipeline cost;
- license/patent considerations;
- App Store feasibility.

## 5. Server backend

### 5.1 Technology

- Python
- FastAPI
- SQLite
- background workers/processes for media/detection
- Docker Compose deployment

Heavy detection work should not run inside latency-sensitive API request handlers.

### 5.2 Logical services

- API service
- Pairing/session service
- Recorder
- Detection worker
- Event correlator
- Retention worker
- Thumbnail generator
- Slack notifier
- Audit logger
- Health/status aggregator

They may initially share one deployable service if separation would add unnecessary complexity, but internal interfaces should remain clear.

## 6. Detection pipeline

### 6.1 General motion

Use lightweight temporal image difference/flow/background methods as appropriate.

### 6.2 Person detection

Use a pluggable model/backend.

Requirements:
- permissive project-compatible license;
- server-side inference;
- CPU fallback;
- optional GPU acceleration;
- model/version recorded in metadata.

YOLOX is the initial evaluation candidate because its source implementation is Apache-2.0. The exact pretrained model/weight license MUST still be verified separately before bundling or redistribution. The detector remains replaceable.

Do not default to an AGPL component merely because it is popular.

### 6.3 Server movement

Calibration stores:
- server ROI/polygon;
- reference visual descriptors;
- background context;
- expected camera pose;
- thresholds.

Runtime correlation may use:
- feature points;
- homography/global scene transform;
- edges/contours;
- ROI similarity;
- temporal persistence;
- person occlusion mask;
- optional object detector/tracker.

A movement event should require temporal confirmation to reduce false positives.

### 6.4 Camera tamper

Candidate signals:
- IMU delta;
- global optical transform;
- abrupt focus/exposure/occlusion shift;
- camera orientation change;
- stream loss immediately following motion.

Tamper confidence should combine multiple inputs rather than using one fixed threshold when practical.

## 7. Events

Suggested event types:

```text
person_detected
motion_detected
server_movement
camera_tamper
camera_offline
camera_online
server_started
server_stopped
recording_started
recording_stopped
manual_recording_started
manual_recording_stopped
thermal_degraded
storage_warning
storage_pressure_entered
storage_pressure_cleared
storage_hard_stop_entered
storage_hard_stop_cleared
local_evidence_hard_stop_entered
local_evidence_hard_stop_cleared
local_evidence_capture_rejected
slack_error
pairing_created
pairing_revoked
presence_started
presence_ended
settings_changed
```

Storage state events must remain distinguishable in audit/UI. In particular, `storage_pressure_entered` and `storage_hard_stop_entered` are not interchangeable: the latter means new server-side recording writes are being refused. `local_evidence_capture_rejected` records an iPhone-local evidence admission failure and must not imply that the corresponding server-side event or detection failed.

Each event:
- UUID
- type
- severity
- started_at
- ended_at
- source_node
- confidence where applicable
- recording reference
- thumbnail reference
- metadata JSON
- acknowledged/starred state as applicable

## 8. Recording layout

Example filesystem structure:

```text
<recording_root>/
├── recordings/
│   └── 2026/
│       └── 09/
│           └── 14/
│               └── <event_uuid>/
│                   ├── rear.mp4
│                   ├── front.mp4
│                   ├── thumbnail.jpg
│                   └── manifest.json
├── manual/
├── temp/
└── diagnostics/
```

Exact naming may change. Filesystem paths must never include user secrets.

## 9. SQLite data model

Initial logical tables:

- `camera_nodes`
- `pairings`
- `events`
- `recordings`
- `recording_files`
- `settings`
- `schedules`
- `presence_sessions`
- `audit_logs`
- `notification_deliveries`
- `schema_migrations`

Important constraints:
- UUIDs preferred for externally referenced objects.
- Timestamps stored in UTC; UI renders local time.
- Settings changes audited.
- Audit logs immutable through normal API except retention worker.
- Destructive cascade behavior must be explicit.

## 10. Retention algorithm

ServerSentinel must distinguish between the configured recording allocation and a hard filesystem safety reserve. Starred recordings are protected from automatic deletion, but protection must never imply that ServerSentinel will intentionally fill the filesystem to 100%. Filesystem pressure can be caused by ServerSentinel or by unrelated services sharing the same volume, so admission decisions MUST consider actual filesystem free space independently of ServerSentinel's configured allocation.

At scheduled intervals and before admitting a new recording:

1. Calculate total recording usage, starred/preserved usage, filesystem free space, the configured recording maximum, the critical-evidence allowance, and the hard safety reserve.
2. Delete expired unstarred recordings older than retention.
3. Recompute recording usage and filesystem free space.
4. Reclaim oldest unstarred recordings when **either** condition is true:
   - ServerSentinel recording usage exceeds the configured recording maximum; or
   - actual filesystem free space is below the normal recording-admission target required to preserve both the bounded critical-evidence allowance and the hard safety reserve.
   Continue oldest-unstarred cleanup until both admission conditions are safe again or no deletable unstarred recordings remain. This cleanup applies even when low free space was caused by another process/service on the shared filesystem.
5. Never auto-delete starred recordings.
6. Only after step 4 reclamation has been attempted, if there is still insufficient room for normal recording while the hard safety reserve remains intact, enter `STORAGE_PRESSURE`:
   - reject new non-critical/manual recordings before they consume the protected capacity;
   - continue live viewing and detection;
   - keep critical-event detection armed;
   - emit `storage_pressure_entered` on transition and show a persistent UI warning requiring the owner to unstar/delete/offload data, free space used by other services, or increase storage.
7. Maintain a separately budgeted critical-evidence allowance above the normal recording-admission threshold so a limited amount of new `server_movement` / `camera_tamper` evidence can still be written during `STORAGE_PRESSURE`. This allowance must be bounded and must not consume the hard filesystem safety reserve.
8. Before entering `STORAGE_HARD_STOP`, re-evaluate filesystem free space and confirm that no eligible unstarred recording can be reclaimed to restore the required reserve. If the critical-evidence allowance is exhausted or any new disk write would cross the hard filesystem safety reserve, enter `STORAGE_HARD_STOP`:
   - refuse all new disk recordings rather than intentionally filling the filesystem;
   - continue live view/detection where possible;
   - preserve any iPhone local emergency evidence and retry server synchronization after capacity is restored;
   - emit `storage_hard_stop_entered`, raise the highest local storage warning state, and audit the transition.
9. Automatically leave pressure/stop states only after free space is safely above the corresponding recovery threshold (use hysteresis to avoid state flapping). Emit the matching `*_cleared` event on recovery.

The hard safety reserve, critical-evidence allowance, normal admission target, and recovery thresholds shall be configurable within safe bounds and finalized from storage/bitrate benchmarks. The implementation must test both (a) starred data alone exceeding the normal configured recording allocation and (b) an unrelated service consuming shared-filesystem space while reclaimable unstarred ServerSentinel recordings still exist.

## 11. Pairing

### 11.1 Discovery
- mDNS/Bonjour service advertisement on local network.
- QR pairing as primary deterministic flow.
- Manual URL/host fallback.

### 11.2 QR contents

QR payload should contain only what is needed, for example:
- server local endpoint;
- one-time pairing token;
- server public-key/fingerprint identifier;
- token expiry;
- protocol version.

Never include:
- Slack secret;
- Tailscale auth key;
- server admin secrets;
- filesystem credentials.

### 11.3 Pairing token
- CSPRNG-generated;
- target expiry: 5 minutes;
- one-time use;
- hashed at rest when practical;
- redacted from logs.

### 11.4 Long-term credential
After pairing, issue/establish per-device credentials stored in iOS Keychain and server-side secure configuration/DB.

Support revocation.

## 12. API design principles

- Version APIs (`/api/v1/...`).
- Use typed request/response schemas.
- Idempotency for retryable media/control operations.
- Never log secrets.
- Validate filenames/paths server-side.
- No arbitrary filesystem path APIs.
- Destructive actions require explicit scoped request.
- Privileged dashboard/API operations require deployment-owner authorization; Tailnet membership alone is not sufficient authorization.
- Return machine-readable error codes.

Indicative resource groups:

```text
/api/v1/health
/api/v1/setup
/api/v1/pairing
/api/v1/nodes
/api/v1/events
/api/v1/recordings
/api/v1/live
/api/v1/control
/api/v1/presence
/api/v1/schedules
/api/v1/settings
/api/v1/integrations/slack
/api/v1/audit
/api/v1/shortcuts
```

Exact endpoints are an implementation detail and may evolve through schema migrations/ADR.

## 13. Web dashboard

React + TypeScript.

Mobile-first screens:

1. Dashboard
2. Live
3. Events
4. Recording detail
5. Camera Node
6. Presence/schedule
7. Storage
8. Slack
9. Audit/logs
10. Settings
11. Setup/pairing

### Dashboard critical status

At a glance:
- ServerSentinel service online
- Camera online
- Monitoring active
- Presence active
- rear/front/mic state
- thermal state
- storage remaining
- last critical event
- manual intervention required indicator

## 14. Presence state machine

Conceptual priority:

```text
manual override (until expiry)
        >
explicit immediate state
        >
configured schedule
        >
default monitoring state
```

Presence mode does not block:
- live view;
- manual recording;
- health checks.

## 15. Slack integration

Server-side only.

Daily:
- one parent summary at configured time (default 23:00);
- thread replies containing selected event entries/thumbnails.

Immediate:
- confirmed server movement;
- confirmed camera tamper;
- other immediate alert types only if later explicitly approved.

Do not turn every motion event into a channel notification.

Slack failures:
- recorded in audit/event state;
- retry with bounded backoff;
- never block recording.

## 16. Security controls

See `SECURITY.md`.

Mandatory highlights:
- no public-port default;
- Tailscale provides network reachability but not sufficient deployment-owner authorization by itself;
- privileged operations require an explicit owner authorization boundary selected by ADR;
- no secrets in Git;
- no personal deployment values in example files;
- no shell command injection through paths/settings;
- no direct user-supplied path concatenation;
- strict upload size/type limits;
- pairing rate limits;
- session credential rotation/revocation;
- safe Docker permissions;
- least privilege.

## 17. App Review mode

Demo Mode shall:
- be visible/documented;
- not require a private Tailnet;
- let reviewer explore onboarding and main UI;
- show capability checks;
- exercise camera permission flow where possible;
- use clearly labelled synthetic/server-demo data for server-only functionality.

Demo Mode must not pretend synthetic data is real evidence.

## 18. Testing architecture

### 18.1 Mockable interfaces
iOS shall abstract:
- CameraSource
- AudioSource
- MotionSource
- ThermalSource
- ServerTransport
- LocalEvidenceStore

Server shall abstract:
- Detector
- MediaStore
- Notifier
- Clock where useful
- StorageStats
- CameraSession

### 18.2 Fixture video
Use synthetic/consented test assets only.

Fixtures should cover:
- empty scene;
- person enters;
- server occluded;
- server displaced;
- camera shifts;
- low light;
- abrupt disconnection.

### 18.3 E2E
Mock Camera Node:
1. pair;
2. send heartbeat;
3. stream fixture;
4. trigger detection;
5. produce event;
6. store recording;
7. generate thumbnail;
8. show web event;
9. send Slack request to stub;
10. enforce retention.

## 19. Observability

Local only by default.

Structured logs:
- JSON preferred on server;
- redact secrets;
- rotate logs.

Metrics shown locally:
- active camera;
- stream FPS/bitrate;
- dropped chunks;
- queue depth;
- detector latency;
- disk use;
- thermal state;
- reconnect count.

No metrics are sent to the developer.

## 20. Versioning

- Semantic Versioning where practical.
- Protocol version independently declared.
- GitHub Releases for server release notes.
- App Store for iOS distribution.
- Optional update-check may query public GitHub release metadata only; no telemetry payload.

## 21. Open technical decisions

The following require PoC/real-device data before final lock:

1. Live transport implementation.
2. Final recording codec/bitrate.
3. Rear/front capture profile.
4. Thermal thresholds and degradation curves.
5. Server-movement algorithm and thresholds.
6. Camera-tamper confidence model.
7. Recommended storage allocation from observed recording sizes.
8. Final person detector/model/weights after license and performance review.
9. Deployment-owner authorization mechanism (local credential/session vs explicit Tailscale identity binding or another self-hosted equivalent).

Each locked decision should receive an ADR.
