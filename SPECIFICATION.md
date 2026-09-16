# ServerSentinel Technical Specification

## 1. Architecture overview

ServerSentinel consists of three logical runtime areas:

1. **Ubuntu ServerSentinel Host** — authoritative configuration, recording, analysis, event correlation, retention, notifications.
2. **Camera Sources** — local UVC devices and remote browser-based Web Camera Nodes.
3. **Web UI** — dashboard, setup, live view, and the Web Camera Node capture page.

Optional integrations:
- Tailscale or equivalent private remote reachability;
- Slack.

```text
Local UVC cameras                       Remote Web Camera Nodes
┌───────────────┐                       ┌─────────────────────────┐
│ USB Webcam A  │                       │ iPhone / Android / PC   │
│ USB Webcam B  │                       │ Browser + getUserMedia  │
└───────┬───────┘                       └────────────┬────────────┘
        │ V4L2/UVC                                    │ secure session
        └──────────────────────┬──────────────────────┘
                               v
                  ┌───────────────────────────────┐
                  │ Ubuntu ServerSentinel        │
                  │ API / source registry        │
                  │ recorder / ring buffers      │
                  │ detection workers            │
                  │ event/timeline correlator    │
                  │ SQLite / file storage        │
                  │ Slack integration            │
                  └───────────────┬───────────────┘
                                  │
                                  v
                  ┌───────────────────────────────┐
                  │ React Web UI                 │
                  │ dashboard + camera-node UI  │
                  └───────────────────────────────┘
```

A deployment may contain 1–4 active video sources in any supported composition. No algorithm, schema, or filesystem layout may assume an iPhone `front`/`rear` pair.

## 2. Repository layout

```text
server-sentinel/
├── README.md
├── REQUIREMENTS.md
├── SPECIFICATION.md
├── AGENTS.md
├── CLAUDE.md
├── MANUAL_TEST.md
├── SECURITY.md
├── PRIVACY.md
├── CONTRIBUTING.md
├── ROADMAP.md
├── LICENSE
├── NOTICE
├── .gitignore
├── .env.example
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
│   ├── CLAUDE_REVIEW_SETUP.md
│   ├── THIRD_PARTY_POLICY.md
│   ├── INITIAL_ISSUES.md
│   ├── ADR/
│   │   ├── README.md
│   │   └── 0001-project-foundations.md
│   └── proposals/
│       └── README.md
└── .github/
    ├── workflows/
    ├── pull_request_template.md
    └── ISSUE_TEMPLATE/
```

Expected implementation expansion:

```text
server/app/
├── api/
├── auth/
├── cameras/
│   ├── registry/
│   ├── uvc/
│   └── remote_web/
├── detection/
├── events/
├── media/
├── notifications/
└── storage/

web/src/
├── dashboard/
├── camera-node/
├── setup/
└── shared/
```

## 3. Camera Source domain model

### 3.1 Source types

MVP enum:

```text
local_uvc
remote_web
```

Future types must fit the same logical source/event model, e.g. `rtsp`, `pi_node`.

### 3.2 Source record

Logical schema:

```text
camera_source
- id: UUID
- node_id: nullable UUID
- source_type
- name
- role_label
- enabled
- desired_capture_profile
- negotiated_capture_profile
- health_state
- last_seen_at
- created_at
- updated_at
```

`role_label` is descriptive metadata, not a replacement for explicit detection-profile configuration.

### 3.3 Capabilities

Capabilities are data, not assumptions derived from device name.

Examples:

```text
video
microphone
camera_switch
resolution_controls
frame_rate_controls
browser_wake_lock
local_direct_capture
```

No MVP detector requires IMU or torch capabilities.

### 3.4 Detection profile bindings

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

A profile contains its own config, version, thresholds, and enabled state.

### 3.5 Active-source limit

Initial `max_active_video_sources = 4`.

This is a configurable product limit. Database/API collection types must not encode four fixed columns or four fixed source names.

If enabling a source would exceed the configured limit, reject the activation with an explicit validation error rather than silently replacing another source.

## 4. Local UVC / USB ingest

### 4.1 Discovery

On Linux, enumerate V4L2/UVC-compatible devices. Prefer stable hardware identity where available:
- `/dev/v4l/by-id/` or equivalent stable symlink;
- USB vendor/product/serial metadata;
- negotiated video capabilities.

Do not persist `/dev/video0` alone as durable identity because enumeration order can change after reboot/replug.

### 4.2 Activation

Discovery does not automatically activate recording. The deployment owner explicitly selects the device, names it, chooses capture settings, and assigns detection profiles.

### 4.3 Container boundary

Do not require privileged Docker solely to access webcams. Mount/pass only explicitly configured video devices or use a narrowly scoped host capture design documented by ADR.

### 4.4 Disconnect/reconnect

A disappearing UVC device transitions to `offline` and emits a source-health event. Reappearance is matched by stable identity where possible and does not silently bind a different physical camera to the old source.

## 5. Remote Web Camera Node

### 5.1 Technology

MVP implementation target:
- React/TypeScript UI shared with the web application where practical;
- browser `navigator.mediaDevices.getUserMedia()`;
- WebRTC evaluated first for low-latency media;
- Web Crypto / browser-appropriate credential storage for paired identity;
- Screen Wake Lock API as optional best-effort support where available.

No native iOS/Android package is required.

### 5.2 Secure context

Camera/microphone capture requires a browser secure context except browser-defined localhost exceptions. Production/setup UX must provide a valid secure-origin path; it must not instruct the user to bypass browser TLS/security warnings as the normal solution.

The exact local HTTPS/Tailscale/reverse-proxy certificate approach shall be documented by setup/transport ADR work.

### 5.3 Camera selection

A browser node may expose one selected video track as one Camera Source. Device camera switching may be offered where the browser exposes multiple cameras, but the MVP does not require simultaneous front/rear capture from one phone.

### 5.4 Audio

Microphone capture is separate from video permission/state and defaults to OFF.

### 5.5 No automatic illumination

Do not call browser constraints or device APIs to automatically enable torch/flash/screen light on motion or low light. Low light is handled through quality gating and explicit degraded state.

### 5.6 Foreground/lifecycle model

The web node is expected to remain active and foreground while used as a camera source.

The implementation must surface/recover from:
- visibility/background suspension;
- track ended/muted;
- permission revocation;
- browser reload;
- network interruption;
- device sleep/lock where detectable.

No claim of uninterrupted background recording is allowed.

### 5.7 Browser-local buffer

Any MediaRecorder/IndexedDB/browser-side buffer is best-effort and non-authoritative in MVP. It may improve reconnect behavior, but MUST NOT be described as guaranteed independent critical-evidence storage.

## 6. Pairing and node trust

### 6.1 Local UVC

Local UVC sources are host-local devices selected by an owner-authorized dashboard session. They do not use remote pairing tokens.

### 6.2 Web Camera Node pairing

Preferred flow:

```text
Owner dashboard -> Add Web Camera
        |
        +-- one-time QR / short token (~5 min)
        |
Camera browser opens secure camera-node page
        |
server validates token + current owner approval
        |
revocable per-node identity/session established
```

Pairing token:
- cryptographically random;
- one-time;
- short-lived;
- never logged plaintext.

### 6.3 Browser credential

Prefer a browser-origin-bound, revocable credential. Where practical use Web Crypto-generated non-exportable key material persisted through IndexedDB rather than a long-lived bearer token in `localStorage`.

Exact authentication protocol must be covered by the deployment-owner authorization/pairing ADR before implementation.

## 7. Media architecture

### 7.1 Separation of concerns

Live video and durable recording are separate reliability problems.

- **Live**: optimize latency and recovery.
- **Recording**: optimize durability, ordering, retry, integrity, source attribution.

### 7.2 Local source path

Local UVC capture may feed both live-view encoder and recorder directly on the Ubuntu host.

### 7.3 Remote source path

The transport PoC shall compare realistic browser-compatible options, with WebRTC evaluated first.

Measure:
- LAN/Tailscale latency;
- reconnect behavior;
- browser compatibility;
- CPU/GPU cost;
- bitrate;
- four-source behavior;
- recording extraction/chunking options;
- dependency/license burden.

### 7.4 Recording segments

Logical chunk metadata:

```text
chunk_id
source_id
session_id
recording_id
event_id (optional)
sequence_number
started_at
ended_at
codec/container
byte_length
checksum
retry_count
```

Remote uploads must be idempotent.

### 7.5 Server ring buffers

Maintain recent per-source media on the server for pre-event capture. Memory/disk implementation is chosen by benchmark/ADR. The buffer must have explicit bounds.

### 7.6 Capture vs inference FPS

Do not couple inference rate to capture FPS. Each detector/profile can sample a source at a lower cadence.

Example benchmark starting points only:
- capture: 15 fps;
- person detector: 2–5 fps;
- server ROI/movement: 2–5 fps;
- owner verification: event/person-triggered rather than every frame.

Final values are benchmark-derived.

## 8. Detection pipeline

### 8.1 General motion

Use lightweight temporal difference/flow/background methods as appropriate.

### 8.2 Person detection

Use a pluggable backend.

Requirements:
- permissive project-compatible license;
- CPU fallback;
- optional GPU acceleration;
- model/version in metadata;
- source and pretrained weight licenses verified separately.

YOLOX is the initial person-detector evaluation candidate because its source implementation is Apache-2.0. This does not pre-approve every weight artifact.

### 8.3 Server movement

Per source/profile calibration stores:
- server ROI/polygon;
- reference frame/descriptors;
- background context;
- thresholds;
- calibration version/time.

Runtime may combine:
- feature points;
- global transform/homography compensation;
- edges/contours;
- ROI similarity;
- temporal persistence;
- person/occlusion mask.

### 8.4 Camera tamper

Candidate signals:
- global optical transform;
- persistent occlusion/near-black lens cover;
- abrupt focus/exposure change;
- source disconnect closely following scene movement;
- impossible/large scene pose shift.

UVC/Web Camera Node implementations do not depend on IMU.

### 8.5 Image-quality / low-light gate

Before identity-sensitive inference, derive quality indicators such as:
- luminance distribution;
- blur/sharpness;
- visible face size;
- detector confidence;
- excessive saturation/underexposure.

A profile returns `sufficient`, `degraded`, or `insufficient` plus metrics/reason. `insufficient` prevents owner match/non-match from being treated as reliable.

No motion-triggered torch operation exists in MVP.

### 8.6 Owner-only face verification

This is 1:1 verification against one explicitly enrolled deployment owner, not general named face identification.

Logical flow:

```text
person/face candidate
      -> quality gate
      -> owner embedding comparison
      -> match / no-match / unknown
```

Requirements:
- owner enrollment requires owner-authorized UI action;
- template/model metadata stored locally;
- threshold chosen through synthetic/public benchmark + real-device manual validation;
- result contains confidence/distance + quality state;
- low-quality result becomes `unknown`;
- enrollment can be deleted/replaced;
- model implementation/weights need license review.

Do not create persistent named templates for other people.

### 8.7 Anonymous tracking

Use ephemeral identifiers for non-owner observations, e.g. `anon_track_<uuid>`.

The initial tracking scope should be limited enough to avoid silently becoming a biometric re-identification system. Same-camera temporal tracking is allowed. Cross-camera re-identification is not an MVP requirement and requires a new privacy/architecture decision.

### 8.8 Entrance crossing

Entrance profile config:
- line or polygon;
- `inside` and `outside` side/direction;
- debounce/persistence threshold;
- optional owner-verification requirement.

Emitted observations may include:
- `anonymous_person_entered`;
- `anonymous_person_exited`;
- `owner_entered`;
- `owner_exited`.

## 9. Presence engine

Logical states:

```text
PRESENT
PROBABLY_PRESENT
ABSENT
UNKNOWN
```

Inputs may include:
- owner entrance/exit observations;
- recency/consistency;
- manual owner override;
- configured schedule hints.

Precedence:
1. explicit manual override;
2. high-confidence entrance-derived state;
3. schedule/hints;
4. otherwise unknown.

Only `PRESENT` suppresses ordinary occupancy automation by default. `PROBABLY_PRESENT`/`UNKNOWN` are displayed but do not silently disarm ordinary security automation.

Critical server movement/camera tamper remains armed in every presence state.

## 10. Event and timeline model

Suggested event/observation types:

```text
motion_detected
person_detected
anonymous_person_entered
anonymous_person_exited
owner_match
owner_entered
owner_exited
image_quality_degraded
image_quality_recovered
server_movement
camera_tamper
camera_offline
camera_online
web_camera_suspended
web_camera_reconnected
server_started
server_stopped
recording_started
recording_stopped
manual_recording_started
manual_recording_stopped
storage_warning
storage_pressure_entered
storage_pressure_cleared
storage_hard_stop_entered
storage_hard_stop_cleared
presence_changed
slack_error
pairing_created
pairing_revoked
settings_changed
```

Each event:
- UUID;
- type;
- severity;
- started_at / ended_at;
- source_id / node_id where applicable;
- confidence/quality where applicable;
- recording references;
- thumbnail references;
- metadata JSON;
- acknowledged/starred state where applicable.

### 10.1 Correlation

Critical-event view may query a configurable time window around the event and show relevant entry/exit/person/camera/server observations.

Correlation output MUST be phrased as observations, e.g. `Observed in relevant window`, not `suspect`/`culprit`.

## 11. Recording layout

Example:

```text
<recording_root>/
├── recordings/
│   └── 2026/09/17/<event_uuid>/
│       ├── source_<uuid-a>.mp4
│       ├── source_<uuid-b>.mp4
│       ├── thumbnail_<uuid-a>.jpg
│       └── manifest.json
├── manual/
├── temp/
└── diagnostics/
```

No `rear.mp4` / `front.mp4` contract.

Manifest records source IDs, source names at capture time, codecs, time ranges, checksums, gaps, and event links.

Filesystem paths must never contain secrets or raw user-provided traversal components.

## 12. SQLite logical model

Initial logical tables:

- `nodes`;
- `camera_sources`;
- `camera_capabilities`;
- `camera_profiles`;
- `pairings`;
- `owner_biometric_profile` (0 or 1 active logical owner profile in MVP);
- `person_tracks` / `person_observations`;
- `events`;
- `event_links`;
- `recordings`;
- `recording_files`;
- `settings`;
- `schedules`;
- `presence_state_history`;
- `audit_logs`;
- `notification_deliveries`;
- `schema_migrations`.

Important constraints:
- externally referenced objects use UUIDs where practical;
- timestamps stored UTC; UI renders local time;
- settings/biometric enrollment/deletion audited;
- audit logs immutable through normal API except retention worker;
- cascade/destructive behavior explicit;
- non-owner named identity schema is intentionally absent.

## 13. Retention and storage admission

ServerSentinel distinguishes configured recording allocation from hard filesystem safety reserve.

At scheduled intervals and before a new recording admission:

1. calculate recording use, starred use, filesystem free space, configured maximum, bounded critical allowance, hard reserve;
2. delete expired unstarred recordings;
3. if allocation/free-space admission remains unsafe, reclaim oldest eligible unstarred recordings even if they have not expired;
4. if normal admission is still unsafe, enter `STORAGE_PRESSURE` and suppress new non-critical/manual disk recordings;
5. confirmed critical server-movement/camera-tamper evidence may use only a bounded critical allowance that does not cross the hard reserve;
6. before any write that would cross the hard reserve, enter `STORAGE_HARD_STOP` and refuse the write;
7. starred recordings are never auto-deleted but also never justify intentional filesystem exhaustion;
8. emit audit/UI state events;
9. recover with hysteresis after free space is safely above recovery thresholds.

Exact thresholds are benchmark/config decisions, not hard-coded personal disk values.

## 14. Dashboard UI

Primary views:
- Overview/status;
- Camera Sources;
- Live Grid;
- Events/Timeline;
- Recordings;
- Presence;
- Owner Verification settings;
- Storage;
- Slack;
- Audit;
- Setup/security.

### 14.1 Live grid

Layout adapts to source count:
- 1 source: single view;
- 2 sources: two-up responsive layout;
- 3–4 sources: responsive 2×2-style grid where screen size permits.

Do not render empty hard-coded camera slots as a product assumption.

### 14.2 Camera source card

Display:
- source name/type/role;
- online/degraded/offline state;
- negotiated resolution/FPS;
- audio state;
- active detection profiles;
- low-light/image-quality state;
- reconnect/manual-intervention state.

## 15. Security boundaries

### 15.1 Deployment owner

Tailscale membership is reachability only. Privileged dashboard/API actions require separate deployment-owner authorization selected by ADR.

### 15.2 Media uploads

Validate:
- authenticated node;
- expected source/session;
- size/rate limits;
- allowed media/container;
- generated safe filenames;
- checksum/integrity;
- no arbitrary output paths.

### 15.3 Biometric data

Owner biometric template:
- treated as sensitive secret-adjacent data;
- excluded from logs/diagnostics by default;
- not returned from general settings APIs;
- deletion audited;
- access limited to required verification worker/config path.

Non-owner persistent biometric templates are prohibited by requirement.

## 16. Failure/health behavior

Explicit states should distinguish:
- UVC device disconnected;
- remote browser node offline;
- browser capture track ended;
- low-light/quality degradation;
- detector worker degraded;
- storage pressure/hard stop;
- server-side source overload;
- owner verification unavailable;
- manual intervention required.

A failed owner verifier does not disable unrelated server movement/tamper monitoring.

## 17. Performance and overload policy

Four active sources are a supported test target, not a promise that every camera can run its maximum advertised mode simultaneously on every host/USB topology.

Resource policy:
1. keep source health/heartbeat visible;
2. preserve critical server movement/tamper processing where configured;
3. reduce expensive analysis cadence;
4. reduce live preview bitrate/FPS/resolution where necessary;
5. report degraded state;
6. do not silently drop a source while claiming healthy monitoring.

USB controller bandwidth, CPU, GPU, encoder capacity, and network bandwidth must be measured.

## 18. Testing and fixtures

Repository media fixtures must be synthetic/generated only. Real monitoring footage, real-person media, and real-environment footage are not committed or attached to PRs even with consent.

Required test families include:
- source registry 1–4 cameras;
- UVC stable-device mapping/reconnect;
- remote Web Camera Node pairing/reconnect;
- media chunk retry/idempotency;
- multi-source event linkage;
- low-light gating;
- owner-verification match/no-match/unknown using synthetic/generated/publicly licensed fixtures where appropriate;
- anonymous tracking without named identities;
- entrance crossing/presence state;
- server ROI movement/occlusion;
- camera tamper;
- retention/storage pressure;
- owner authorization;
- migrations;
- mock E2E.

Real browser/hardware validation lives in `MANUAL_TEST.md`.

## 19. Deliberately deferred decisions

Require ADR/Issue before implementation where material:
- exact low-latency media transport;
- local HTTPS/certificate setup UX for Web Camera Node;
- final codecs/bitrates;
- final owner face-verification model/weights/license;
- exact owner-verification threshold/calibration method;
- cross-camera re-identification (not MVP);
- strong independent/off-host evidence storage;
- RTSP/IP/Raspberry Pi source support;
- any future native mobile application.
