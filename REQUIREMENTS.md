# ServerSentinel Requirements

## 1. Purpose

ServerSentinel shall provide a self-hosted physical-security monitoring system for valuable servers/workstations using one or more heterogeneous camera sources and an Ubuntu host for storage, analysis, event correlation, and the web dashboard.

The system is optimized for a single deployment owner while remaining installable by unrelated users without developer assistance.

No specific phone model, webcam model, room layout, IP address, filesystem path, or camera count is required.

## 2. Product priorities

Priority order:

1. **Remote multi-camera live viewing**
2. **Evidence preservation for theft/tampering while the recorder is available**
3. **Server movement and camera-tamper detection**
4. **Entrance/person/presence timeline correlation**
5. **Unified ServerSentinel operational status**

Continuity and trustworthy state reporting are more important than maximum image quality.

ServerSentinel MUST NOT claim that browser-origin footage is durably preserved after the Ubuntu recording host/storage is physically stolen, destroyed, or powered off. Strong independent off-host evidence storage is outside the MVP unless separately specified.

## 3. Privacy and ownership requirements

### PRIV-001 No developer cloud
The project shall not require a ServerSentinel-operated cloud service.

### PRIV-002 No developer-side user data
The developer shall not receive or retain users' video, audio, biometric templates, IP addresses, hostnames, Slack credentials, Tailscale information, event metadata, recordings, audit logs, or deployment configuration as part of normal operation.

### PRIV-003 No telemetry/analytics
The official project shall not include analytics, advertising SDKs, telemetry, developer-operated crash upload, or tracking SDKs by default.

### PRIV-004 Explicit diagnostic export
Diagnostics may leave the user's environment only after an explicit export/share action initiated by the deployment owner.

### PRIV-005 Self-hosted camera data path
Camera data shall flow directly from local cameras or user-owned Web Camera Nodes to the user's ServerSentinel host, except for explicitly enabled third-party services such as Tailscale or Slack.

### PRIV-006 Owner biometric data
Owner face verification is optional and requires explicit enrollment.

The enrolled owner face template/embedding:
- is sensitive biometric data;
- shall stay inside the deployment by default;
- shall not be sent to the ServerSentinel developer;
- shall be deletable and re-enrollable by the owner;
- shall not be included in diagnostics by default.

### PRIV-007 Non-owner identity minimization
The MVP shall not maintain a named biometric identity database for other observed people.

Non-owner observations may use anonymous tracking identifiers for event correlation. The system shall not assign real names to non-owner people unless a future explicit product decision changes this requirement.

### PRIV-008 Deployment responsibility
The deployment owner is responsible for complying with applicable laws, institutional policies, notice requirements, and rules governing camera/biometric use in the deployment environment.

## 4. Distribution and licensing requirements

### DIST-001 Web/self-hosted distribution
The MVP shall be distributed as self-hosted server/web software. A native iOS application and App Store distribution are not required.

The MVP shall not require Apple Developer Program membership.

### DIST-002 Open-source repository
The project repository shall be suitable for public GitHub hosting.

### DIST-003 License
Project source shall be licensed under Apache-2.0.

### DIST-004 Dependency compatibility
Dependencies, models, and weights must have licenses compatible with the project's distribution goals. Source-code licenses and model/weight licenses must be reviewed separately.

AGPL/GPL/SSPL/source-available/unclear components are blocked by default unless explicitly approved and documented.

## 5. Camera-source requirements

### CAM-001 Camera-source abstraction
All video inputs shall be represented through a common Camera Source abstraction rather than hard-coded `front`/`rear` iPhone cameras.

### CAM-002 MVP source types
The MVP shall support:
- `local_uvc`: UVC/V4L2-compatible USB camera attached to the Ubuntu host;
- `remote_web`: camera exposed by a user-owned browser through the Web Camera Node.

Future source types such as RTSP/IP cameras or Raspberry Pi nodes may be added without changing the core event/storage model.

### CAM-003 Source count
The MVP shall work with **one active video source** and shall support **up to four active video sources** in one deployment.

The limit of four is an MVP/configuration limit. Internal data models and APIs shall not assume exactly two or exactly four cameras.

### CAM-004 Free composition
Any supported source types may be mixed within the active-source limit. Valid examples include:
- one USB webcam;
- two USB webcams;
- one Web Camera Node only;
- two USB webcams + one phone browser;
- four mixed sources.

### CAM-005 User-defined source metadata
Each source shall have:
- stable source identifier;
- user-visible name;
- source type;
- enabled/disabled state;
- optional semantic role label;
- capabilities;
- health state;
- assigned detection profiles.

### CAM-006 Role is not hardware type
Role labels such as `server_overview`, `server_rear`, `entrance`, `room_overview`, or custom labels shall not be tied to a specific source type.

### CAM-007 Detection profiles are configurable
Detection behavior shall be assigned per source/profile, not inferred only from role or hardware.

Examples:
- motion;
- person;
- server ROI/movement;
- camera tamper;
- entrance crossing;
- owner verification;
- low-light/image-quality gating.

### CAM-008 Local UVC discovery
The server shall enumerate compatible local camera devices and allow the deployment owner to explicitly enable/configure them. Device ordering such as `/dev/video0` alone shall not be treated as a stable identity when better stable device identifiers are available.

### CAM-009 Remote Web Camera Node
A remote Web Camera Node shall run in a supported browser on a camera-capable device such as an iPhone, Android phone, tablet, laptop, or desktop.

The implementation shall not hard-code iPhone 14 or Safari as the only supported device/browser.

### CAM-010 Secure browser context
Web Camera Node camera/microphone access shall use a secure browser context as required by browser APIs. The normal setup shall not instruct users to disable browser security controls.

### CAM-011 Audio default OFF
Audio capture may be supported, but shall be OFF by default per source. Enabling it requires explicit deployment-owner action and visible state.

### CAM-012 No automatic torch/light
The MVP shall not automatically activate a phone torch, screen flash, or other visible light in response to motion or low light.

Torch control is not an MVP requirement.

### CAM-013 Browser lifecycle honesty
Web Camera Node monitoring is expected to remain foreground/active. ServerSentinel shall not claim guaranteed capture after browser suspension, tab termination, screen lock, OS process termination, device shutdown, or unsupported background transition.

Where wake-lock APIs are available they may be used as best-effort assistance, but capture correctness shall not depend on an unsupported background assumption.

### CAM-014 Camera health
The system shall report at minimum `online`, `degraded`, `offline`, and `manual_intervention_required` states where applicable and shall record camera disconnect/reconnect events.

### CAM-015 Browser-local evidence is non-authoritative
The MVP may experiment with short browser-side buffering, but browser storage shall not be described as guaranteed durable critical-evidence storage. Primary durable recording remains Ubuntu-side.

## 6. Capture and streaming requirements

### MEDIA-001 Multi-source live view
The owner shall be able to view all active camera sources from the web dashboard.

The UI shall adapt for 1–4 sources rather than assuming a fixed two-camera layout.

### MEDIA-002 Initial live profile
Initial live targets per source:
- 720p-class output where practical;
- approximately 15 fps normal target;
- optional higher FPS/quality when resources permit;
- adaptive degradation allowed under CPU/GPU/network/USB/browser constraints.

Exact defaults shall be benchmark-derived.

### MEDIA-003 Low-latency live transport
Low-latency remote Web Camera Node/live-dashboard transport shall be selected through a documented PoC/ADR. WebRTC is an expected candidate, not a pre-approved final answer.

### MEDIA-004 Durable recording transport
Durable recording shall not depend solely on an uninterrupted live-view session.

Remote-source recording transport shall support bounded chunks/segments, retry, idempotency, integrity metadata, and source identity.

Local UVC recording may use a direct server capture path while producing the same logical recording/event model.

### MEDIA-005 Manual recording
The owner shall be able to start/stop manual recording for a selected source set.

Default maximum manual session: **20 minutes**.

### MEDIA-006 Ring buffer
The server shall maintain enough recent media to preserve pre-event footage for configured sources where resource constraints permit.

Default automatic event window:
- pre-event: 30 seconds;
- post-event: 120 seconds;
- extend while qualifying activity continues;
- maximum event duration: 20 minutes.

### MEDIA-007 Multi-source event evidence
A single event may reference media from multiple camera sources. Recording filenames/schema shall use source IDs rather than semantic assumptions such as `rear.mp4` / `front.mp4`.

## 7. Detection requirements

### DET-001 General motion
General motion detection shall be available per configured source.

### DET-002 Person detection
Person detection shall be available per configured source from the initial release.

Heavy inference should run on Ubuntu by default.

### DET-003 Pluggable detector
Person/face-related detection implementations shall remain replaceable. Source-code and model-weight licensing must be verified separately.

YOLOX remains an initial permissively licensed person-detector evaluation candidate; it is not mandated as the final model.

### DET-004 Server ROI calibration
One or more sources may be configured with a server ROI/polygon/reference geometry for server movement/tamper analysis.

### DET-005 Server movement
The system shall detect meaningful displacement/rotation of the monitored server using configured ROI/scene information and temporal confirmation.

A generic person detector alone is insufficient proof of server movement.

### DET-006 Camera tamper
The system shall detect probable camera tampering using signals available to the source, including where applicable:
- sudden global scene transform;
- camera occlusion;
- stream interruption;
- abrupt orientation/pose change visible in the scene;
- source-health changes correlated with motion.

IMU is not required for the MVP because Web Camera Nodes are browser-based and UVC cameras generally do not expose it.

### DET-007 Occlusion tolerance
Temporary person occlusion of a server ROI shall not immediately become a confirmed server-movement event.

### DET-008 Low-light/image-quality gating
The system shall estimate whether a source/frame has sufficient visual quality for each dependent detector.

If conditions are too dark or otherwise inadequate:
- report a degraded/insufficient-quality state;
- dependent identity/presence conclusions shall become `unknown` or unavailable rather than forced positive/negative results;
- automatic torch/light activation shall not occur;
- recording/live view may continue if technically possible.

### DET-009 Owner-only face verification
The MVP may verify whether an observed face matches the explicitly enrolled deployment owner.

Requirements:
- enrollment is explicit and optional;
- threshold/confidence behavior is documented and benchmarked;
- low-quality/ambiguous frames do not force a match/non-match;
- owner template is stored locally under the privacy requirements;
- owner can delete/re-enroll the template;
- the feature shall be described as probabilistic verification, not certainty.

### DET-010 No named non-owner face database
The MVP shall not enroll, name, or persist a facial identity profile for other observed people.

### DET-011 Anonymous person tracking
Non-owner people may receive anonymous track/session identifiers to connect observations over time within a configured tracking scope.

The system shall not assert cross-camera identity equivalence unless an explicit future re-identification design is approved and documented.

### DET-012 Entrance crossing
A camera source may be configured with an entrance/exit line or zone and direction. When owner verification quality is sufficient, the system may emit `owner_entered` / `owner_exited` observations.

Anonymous entry/exit observations may be emitted without naming the person.

## 8. Event correlation and timeline requirements

### EVENT-001 Unified timeline
The dashboard shall correlate camera and server observations into one chronological security timeline.

Initial event/observation classes include:
- person/motion;
- anonymous entrance/exit;
- owner entrance/exit;
- server movement;
- camera tamper/occlusion;
- camera online/offline;
- server service start/stop/reachability state;
- recording events;
- storage state;
- presence state;
- configuration changes.

### EVENT-002 Relevant observation window
For a critical event, the UI may show people/entry/exit observations within a configurable relevant time window to help the owner review context.

### EVENT-003 No culprit inference
ServerSentinel shall not label a person as a thief, attacker, culprit, or cause of an event based solely on temporal/camera correlation. The UI shall distinguish observations from human conclusions.

### EVENT-004 Confidence/source attribution
Derived events shall include source attribution and confidence/quality metadata where applicable.

## 9. Recording and storage requirements

### STORE-001 Ubuntu primary storage
Recordings, thumbnails, metadata, audit logs, and owner biometric templates shall reside primarily on the self-hosted Ubuntu deployment, with biometric material logically separated/protected as sensitive configuration data.

### STORE-002 Configurable recording root
No recording path may be hard-coded to a specific personal disk/mount.

### STORE-003 Arbitrary valid user storage
The system shall support arbitrary valid user-selected recording volumes rather than requiring a particular HDD capacity.

### STORE-004 Retention
Default recording retention: **20 days**.

### STORE-005 Capacity ceiling
The owner shall configure a maximum recording-storage allocation. Cleanup triggers on whichever applies first:
- retention limit;
- allocation limit;
- actual filesystem safety pressure.

### STORE-006 Starred recordings
Starred recordings are excluded from automatic retention/capacity deletion but count toward disk usage. Starred protection must not intentionally fill the filesystem to 100%.

### STORE-007 Manual deletion
The deployment owner may explicitly delete recordings through the UI after authorization.

### STORE-008 Audit retention
Audit logs:
- default 90-day retention;
- append-only through normal application APIs;
- not individually deletable from normal UI;
- automatically expire by policy.

### STORE-009 Benchmark-derived defaults
Storage/bitrate/source-count recommendations shall be based on actual benchmarks rather than guessed constants.

### STORE-010 Filesystem safety reserve
ServerSentinel shall preserve a hard filesystem safety reserve independent of normal recording allocation.

When free space becomes unsafe:
1. reclaim eligible unstarred recordings;
2. reject/suppress ordinary non-critical/manual recording admission before protected capacity is exhausted;
3. retain a bounded critical-evidence allowance where safe;
4. never consume the hard safety reserve;
5. enter explicit `STORAGE_PRESSURE` / `STORAGE_HARD_STOP` states before unsafe writes;
6. warn/audit state changes;
7. recover with hysteresis after sufficient space returns.

### STORE-011 Non-owner biometric minimization
ServerSentinel shall not create a separate persistent library of non-owner face crops/templates by default. Ordinary recordings may still contain people as part of the configured video evidence.

## 10. Notifications and Slack requirements

### NOTIFY-001 Slack optional
Slack integration is optional and OFF until configured.

### NOTIFY-002 Immediate notifications
Immediate Slack alerts shall remain intentionally sparse. Initial candidates:
- confirmed server movement;
- confirmed camera tamper.

Ordinary person/motion/anonymous-entry events shall not create individual main-channel alerts by default.

### NOTIFY-003 Daily summary
Default daily summary time: 23:00 local time, configurable.

Summary shall include at minimum:
- monitored duration;
- active/available camera count;
- per-source health/degraded states;
- person/general-motion counts;
- entrance/exit observations;
- server movement/camera tamper counts;
- disconnect/reconnect counts;
- recordings;
- storage state;
- critical events/errors.

### NOTIFY-004 Threaded evidence
Relevant thumbnails/event entries may be posted as thread replies under the daily summary where configured.

### NOTIFY-005 No developer relay
Slack delivery shall go directly from the user's deployment to the user's configured Slack endpoint/API.

## 11. Presence requirements

### PRES-001 Manual presence
The dashboard shall provide explicit manual presence control.

### PRES-002 Presence states
Inferred owner presence shall support uncertainty. Initial states:
- `PRESENT`;
- `PROBABLY_PRESENT`;
- `ABSENT`;
- `UNKNOWN`.

### PRES-003 Entrance-derived presence
When a source has entrance-crossing + owner-verification profiles, owner entrance/exit observations may update inferred presence.

Uncertain/low-light/ambiguous observations shall not force `ABSENT` or `PRESENT`.

### PRES-004 Suppression safety
Only explicit `PRESENT` (including manual override) suppresses ordinary person/general-motion security automation by default. `PROBABLY_PRESENT` and `UNKNOWN` do not suppress security automation unless a future explicit policy changes this behavior.

Presence never disables:
- confirmed server-movement detection;
- confirmed camera-tamper detection;
- critical-event evidence handling;
- live view;
- manual recording;
- health status.

### PRES-005 Manual override precedence
Manual override takes precedence over inferred presence and schedules until its expiry/cancellation.

### PRES-006 Schedule
Weekly/day/time schedules may provide a lower-priority presence hint/automation but must not override an active manual override.

## 12. Setup, discovery, and pairing requirements

### SETUP-001 First-run wizard
The Ubuntu web UI shall provide guided self-hosted setup.

### SETUP-002 Local UVC add flow
Local UVC cameras shall be discovered locally and explicitly enabled/configured by the deployment owner. They do not use remote Camera Node pairing.

### SETUP-003 Remote Web Camera Node pairing
Remote Web Camera Nodes shall use a short-lived owner-approved pairing/session bootstrap without a developer account.

Initial pairing token target:
- cryptographically random;
- single use;
- approximately 5-minute expiry;
- never logged in plaintext.

QR and manual code/address flows may both be supported.

### SETUP-004 Browser credential
After successful pairing, the browser node shall receive/derive a revocable deployment-scoped credential using browser-appropriate secure storage/cryptographic APIs. Do not rely on a developer cloud identity.

### SETUP-005 Source configuration
After a source is added, setup shall allow:
- name;
- role label;
- preview;
- quality/profile;
- audio state;
- assigned detection profiles;
- ROI/entrance-line calibration where applicable.

### SETUP-006 Owner enrollment
Owner face enrollment is optional and separate from basic camera setup. Enrollment must explain local biometric processing and provide delete/re-enroll controls.

### SETUP-007 Other users
No configuration may require the original developer's personal IP, hostname, Tailnet, Slack, Wi-Fi, path, phone model, webcam model, or account.

## 13. Remote access and deployment-owner authorization

### REMOTE-001 Tailscale recommended
Tailscale is the recommended remote-access method for the dashboard. Equivalent private reachability may be used.

### REMOTE-002 No public exposure by default
Documentation shall not recommend direct public Internet port exposure as the default.

### REMOTE-003 Single-owner model
MVP assumes one deployment owner.

### REMOTE-004 No developer identity
No ServerSentinel developer-operated cloud account is required.

### REMOTE-005 Deployment-owner authorization
Tailnet membership provides network reachability, not sufficient proof of deployment ownership.

Privileged operations including live media, playback/deletion, source add/remove/pair/revoke, biometric enrollment/deletion, presence/security settings, retention/storage, and Slack configuration require explicit deployment-owner authorization.

The exact self-hosted mechanism must be locked by ADR before implementation and must support recovery/revocation without a developer-operated account.

## 14. Web dashboard requirements

The dashboard shall be responsive/mobile-first and expose at minimum:
- server/service state;
- camera-source list and capabilities;
- 1–4 source live grid;
- per-source configuration/detection profiles;
- recording controls;
- events/timeline;
- thumbnails/playback;
- star/delete;
- storage/retention;
- presence/inference/manual override;
- optional owner enrollment management;
- Slack settings;
- reconnect/degraded/manual-intervention states;
- audit/log view.

## 15. Availability and failure requirements

The system shall handle gracefully:
- one or more USB cameras disconnected/reordered;
- Web Camera Node network interruption/reconnect;
- browser suspension/termination;
- backend restart;
- storage pressure/full conditions;
- Slack failure;
- AI worker failure;
- unsupported browser/camera capabilities;
- expired/invalid pairing token;
- denied camera/microphone permission;
- low-light/insufficient image quality;
- source count/profile exceeding available USB/network/compute capacity.

Failures shall be explicit. Silent capture loss is not acceptable where health monitoring can detect it.

If the Ubuntu deployment itself is fully offline, MVP does not require a developer-operated external uptime monitor.

## 16. Performance requirements

- Capture FPS and inference FPS are separate concepts.
- The implementation must not run every detector on every frame unless benchmarks justify it.
- Inference cadence shall be configurable/profile-driven per source.
- Four active sources shall be included in benchmark/manual-test scenarios.
- Resource pressure should degrade optional/high-cost analysis before losing source-health reporting or critical monitoring where practical.
- CPU-only operation shall remain a supported baseline for core functionality even if GPU acceleration is available.

## 17. Development and completion requirements

Software-side completion before real hardware means, as applicable:
- unit tests pass;
- API integration tests pass;
- web typecheck/lint/tests pass;
- Camera Source mocks cover 1–4 source topologies;
- local UVC abstraction can be tested with mocks/fixtures;
- Web Camera Node protocol/state can be tested without a real phone;
- core E2E passes with synthetic/generated media only;
- storage/retry/idempotency tests pass;
- owner-verification logic has synthetic/generated test assets and threshold tests;
- documentation is aligned;
- remaining physical/browser-specific behavior is listed in `MANUAL_TEST.md`.

## 18. Explicit non-goals / future work

Not MVP requirements:
- native iOS/App Store client;
- automatic phone torch/visible-light activation;
- guaranteed background browser capture;
- guaranteed browser-local durable critical evidence;
- named facial identity database for non-owner people;
- automatic culprit/guilt classification;
- cross-camera biometric re-identification of anonymous people;
- developer cloud/off-site evidence service;
- RTSP/IP/Raspberry Pi source support (architecture should allow it later);
- ESP32/environment-sensor integration;
- complete CPU/GPU observability platform.
