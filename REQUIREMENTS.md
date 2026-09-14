# ServerSentinel Requirements

## 1. Purpose

ServerSentinel shall provide a self-hosted security monitoring system for valuable servers/workstations using a dedicated iPhone as a camera/sensor node and an Ubuntu machine as the storage, analysis, and dashboard host.

The system is optimized for a single owner per deployment, while remaining installable by unrelated users without developer assistance.

## 2. Product priorities

Priority order:

1. **Remote live viewing**
2. **Evidence preservation for theft/tampering**
3. **Unified ServerSentinel operational status dashboard**

The product shall prioritize continuous monitoring and evidence retention over maximum video quality.

## 3. Privacy and ownership requirements

### PRIV-001 No developer cloud
The project shall not require a ServerSentinel-operated cloud service.

### PRIV-002 No developer-side user data
The developer shall not receive or retain users' video, audio, IP addresses, hostnames, Slack webhook URLs, Tailscale information, credentials, event metadata, or server configuration as part of normal operation.

### PRIV-003 No telemetry/analytics
The official application shall not include analytics, advertising SDKs, telemetry, crash-upload SDKs, or tracking SDKs by default.

### PRIV-004 Explicit diagnostic export
Diagnostics may only leave the user's environment after an explicit export/share action initiated by the user.

### PRIV-005 Self-hosted data path
Camera data shall flow directly between the user's iPhone and the user's ServerSentinel server, except for explicitly enabled third-party integrations such as Slack or Tailscale.

## 4. Distribution and licensing requirements

### DIST-001 Public App Store target
The iOS application shall be designed for normal public App Store distribution.

### DIST-002 Open-source repository
The project repository shall be suitable for public GitHub hosting.

### DIST-003 License
Project source shall be licensed under Apache-2.0.

### DIST-004 Dependency compatibility
Dependencies, models, and weights must have licenses compatible with the project distribution goals. Copyleft dependencies that could impose incompatible obligations are blocked by default unless explicitly approved and documented.

## 5. Camera Node requirements

### CAM-001 Native iOS application
The Camera Node shall be a native iOS application.

### CAM-002 Capability-based support
The app shall detect device capabilities rather than hard-code support to iPhone 14.

Full mode:
- simultaneous rear/front capture when MultiCam is supported;
- microphone;
- torch;
- accelerometer;
- gyroscope;
- battery/power state where available;
- thermal state.

Fallback mode:
- reduced camera configuration when MultiCam or other features are unavailable;
- the app shall clearly show unsupported capabilities.

### CAM-003 Rear camera role
The rear camera is the primary server-monitoring camera.

### CAM-004 Front camera role
The front camera is the anti-tamper/approach camera when simultaneous capture is supported.

### CAM-005 Audio
Audio capture shall exist but be OFF by default. Enabling audio requires explicit user action and a visible state indicator.

### CAM-006 Monitoring state UI
While monitoring:
- the screen shall use a near-black, low-distraction UI;
- monitoring/recording/microphone state shall remain visible;
- tapping the screen shall reveal normal controls;
- the app may temporarily raise display brightness and then return to the configured dim level;
- original brightness should be restored when monitoring stops where technically safe.

### CAM-007 Keep-awake
The app shall prevent normal auto-lock while actively monitoring where iOS permits.

### CAM-008 Sensor-based tamper detection
The Camera Node shall expose accelerometer/gyroscope changes to the server and/or perform lightweight local tamper detection.

### CAM-009 Local emergency evidence
For critical events (server movement or camera tamper), the iPhone shall preserve a local emergency clip so evidence may survive loss/theft of the Ubuntu server.

Initial target emergency storage:
- 500 MB maximum;
- oldest unprotected emergency data overwritten first;
- critical clips synchronized to Ubuntu when possible.

### CAM-010 Reconnection
If communication with Ubuntu fails:
- Camera Node shall retry indefinitely with bounded backoff;
- UI shall clearly show disconnection;
- recovery shall be automatic where iOS permits;
- if user interaction is required, state shall become `Manual intervention required`.

### CAM-011 Camera shutdown limitation
The system shall not claim to prevent physical iPhone shutdown. Documentation shall recommend optional physical button guards/mounting protection.

## 6. Capture and streaming requirements

### MEDIA-001 Remote live view
The owner shall be able to view live camera video remotely through the web dashboard.

Target:
- 720p;
- 15–30 fps;
- adaptive degradation is allowed to preserve continuity under network/thermal/load constraints.

### MEDIA-002 Low-latency live transport
The implementation shall prioritize low latency for live viewing. The exact transport shall be selected through a documented PoC/ADR.

### MEDIA-003 Reliable recording transport
Recording/evidence upload shall be independent from live-view transport and shall support chunking, retry, idempotency, and integrity checking.

### MEDIA-004 Manual recording
The user shall be able to start/stop recording from the dashboard.

Maximum manual session:
- 20 minutes.

### MEDIA-005 Ring buffer
Monitoring shall maintain enough buffered data to save video from before an event.

Default automatic event window:
- pre-event: 30 seconds;
- post-event: 120 seconds;
- extend while activity continues;
- maximum event duration: 20 minutes.

### MEDIA-006 Live while presence mode is active
Live viewing and manual recording shall remain available even when automatic security monitoring is paused due to presence mode.

## 7. Detection requirements

### DET-001 General motion
The system shall detect general motion.

### DET-002 Person detection
The system shall detect people from the initial release.

Heavy image inference should run on Ubuntu rather than iPhone where practical to reduce Camera Node heat.

### DET-003 Server ROI calibration
Initial setup shall allow the user to mark the monitored server region/geometry.

This ROI is for server movement/tamper analysis, not for limiting recorded pixels.

### DET-004 Server movement
The system shall detect meaningful displacement/rotation of the monitored server using calibrated scene/ROI information.

The implementation may combine:
- feature matching;
- geometric comparison;
- object detection/tracking;
- background/edge structure;
- temporal rules.

A generic person detector alone is insufficient.

### DET-005 Camera tamper
The system shall detect probable camera tampering using multiple signals where available:
- iPhone IMU movement;
- sudden global scene transform;
- camera occlusion;
- stream interruption;
- unexpected orientation change.

### DET-006 Occlusion tolerance
Temporary person occlusion of the server should not immediately be classified as server movement.

### DET-007 Torch auto mode
When monitoring is active and low light plus motion is detected:
- torch may automatically enable if supported;
- torch shall turn off 30 seconds after the last qualifying motion;
- new motion resets the timer.

Dashboard control:
- Auto
- On
- Off

Failure to control torch shall not stop monitoring.

### DET-008 No face recognition
Identity recognition/face recognition is outside scope.

## 8. Recording and storage requirements

### STORE-001 Ubuntu is primary storage
Recordings and metadata shall primarily reside on the Ubuntu ServerSentinel host.

### STORE-002 Configurable storage path
No path may be hard-coded to a specific personal HDD mount.

### STORE-003 Intended deployment
The owner's expected deployment uses an 8 TB HDD, but the product shall support arbitrary valid user-selected storage volumes.

### STORE-004 Retention
Default video retention:
- 20 days.

### STORE-005 Capacity ceiling
The user shall configure a maximum recording-storage allocation.

Deletion triggers on whichever is reached first:
- retention limit;
- capacity limit.

### STORE-006 Starred recordings
Users may star/preserve recordings.

Starred recordings:
- are excluded from automatic retention/capacity deletion;
- count toward disk use;
- trigger warnings if preserved data threatens usable capacity.

### STORE-007 Manual deletion
The owner may explicitly delete recordings through the UI.

### STORE-008 Audit retention
Audit logs:
- default 90-day retention;
- append-only through normal application APIs;
- not individually deletable from normal UI;
- automatically expire by policy.

### STORE-009 Benchmark-derived defaults
Storage-capacity recommendations and bitrate defaults shall be based on actual benchmark data rather than guessed values.

## 9. Notifications and Slack requirements

### NOTIFY-001 Slack optional
Slack integration shall be optional and OFF until configured.

### NOTIFY-002 Immediate notifications
Immediate Slack alerts shall be intentionally limited to high-value security events to avoid alert fatigue.

Initial immediate-alert candidates:
- confirmed server movement;
- confirmed camera tamper.

Ordinary person/general-motion events shall not generate individual immediate channel notifications by default.

### NOTIFY-003 Daily summary
Default daily summary time:
- 23:00 local time;
- configurable.

Summary shall include at minimum:
- monitored duration;
- camera availability;
- person detection count;
- general motion count;
- server movement count;
- camera tamper count;
- disconnect/reconnect count;
- number of recordings;
- storage usage;
- critical events;
- errors.

### NOTIFY-004 Threaded thumbnails
The daily summary shall be the parent Slack message. Relevant event thumbnails/entries shall be posted as thread replies where supported.

### NOTIFY-005 No developer relay
Slack messages shall be sent from the user's own ServerSentinel server to the user's configured Slack endpoint/API. No ServerSentinel developer relay service.

## 10. Presence requirements

### PRES-001 One-click presence
The web dashboard shall provide a one-click `Present / 在室` action.

### PRES-002 Presence effects
Presence mode pauses:
- automatic security recording;
- automatic person/general-motion security events;
- normal security notifications.

Presence mode does not disable:
- live view;
- manual recording;
- camera/server health status.

### PRES-003 Timed presence
The user shall be able to set presence until:
- common quick durations;
- a chosen clock time;
- a practical "until I leave" workflow.

### PRES-004 Schedule
Weekly/day/time schedules shall be configurable.

### PRES-005 Manual override precedence
Explicit manual presence/monitoring state overrides schedules until its expiry.

### PRES-006 Optional automation
Optional iOS Shortcuts integration may automate presence using signals such as:
- connection to a known Wi-Fi;
- arrival/departure geofence;
- user-defined shortcut.

This integration shall not be required for core functionality.

## 11. Pairing and onboarding requirements

### SETUP-001 Self-hosted first-run wizard
The Ubuntu web UI shall provide a guided first-run setup.

### SETUP-002 Camera discovery
Camera setup should support:
1. local discovery (mDNS/Bonjour) where practical;
2. QR pairing;
3. manual server address as fallback.

### SETUP-003 Secure pairing
Pairing tokens:
- single-use;
- short-lived (initial target: 5 minutes);
- cryptographically random;
- never logged in plaintext.

### SETUP-004 Mutual trust
The pairing flow shall establish a persistent device identity and server trust relationship without a developer account system.

### SETUP-005 Hardware diagnostic
iOS onboarding shall show capability status for:
- rear camera;
- front camera;
- MultiCam;
- microphone;
- torch;
- motion sensors;
- available local storage;
- charging/power status where available.

### SETUP-006 Calibration
Setup shall include:
- camera placement preview;
- server ROI calibration;
- Camera Node orientation baseline;
- tamper baseline calibration.

### SETUP-007 Other users
No configuration may require the original developer's:
- IP;
- hostname;
- Tailnet;
- Slack;
- Apple ID;
- Wi-Fi;
- filesystem path;
- hardware model.

## 12. Remote access and authentication requirements

### REMOTE-001 Tailscale recommended
Tailscale is the recommended remote-access method.

### REMOTE-002 No public port exposure by default
Documentation shall not recommend opening the ServerSentinel web/API port directly to the Internet as the default deployment.

### REMOTE-003 Single-owner model
MVP assumes one owner per deployment.

### REMOTE-004 Web login
No separate ServerSentinel cloud identity is required.

When Tailscale is used, Tailnet membership is the primary remote-access gate for MVP.

Future local multi-user authorization may be proposed separately.

## 13. Web dashboard requirements

Mobile-first responsive design.

Dashboard shall expose at minimum:
- server service status;
- camera-node status;
- live view;
- recording controls;
- current monitoring/presence state;
- current camera/audio/torch state;
- events list;
- thumbnails;
- recording playback;
- star/unstar;
- delete;
- storage usage;
- retention settings;
- schedule/presence settings;
- Slack settings;
- camera reconnect/manual-intervention state;
- audit/log view.

## 14. App Store requirements

### STOREAPP-001 Public App
Target distribution is a normal Public App Store listing.

### STOREAPP-002 Explicit consent
Camera/microphone/sensor permissions shall be explained before request.

### STOREAPP-003 Visible monitoring state
The app shall not intentionally hide that monitoring/recording is active.

### STOREAPP-004 Demo mode
An App Review-compatible Demo Mode shall exist so core UI and capabilities can be evaluated without the reviewer operating a private Ubuntu server.

Demo mode must not be an undocumented hidden feature.

### STOREAPP-005 Privacy policy
A public privacy-policy URL will be required before release. Repository `PRIVACY.md` is the source draft, not necessarily the final legal-hosting URL.

## 15. Availability and failure requirements

The system shall handle gracefully:
- LAN interruption;
- Camera Node reconnect;
- backend restart;
- storage nearing full;
- Slack failure;
- AI worker failure;
- unsupported camera features;
- expired/invalid pairing token;
- missing microphone permission;
- thermal pressure.

If Ubuntu itself is fully offline, MVP does not require a developer-operated external uptime monitor.

## 16. Thermal/performance requirements

Exact operating profiles shall be determined by real iPhone testing.

The product shall:
- monitor iOS thermal state;
- reduce front-camera FPS/resolution before sacrificing rear evidence capture;
- reduce stream quality before terminating monitoring where practical;
- surface thermal degradation clearly;
- document the actual tested limits.

## 17. Development and completion requirements

Software-side completion before real hardware means:
- unit tests pass;
- API integration tests pass;
- core E2E passes with mock Camera Node;
- synthetic video detection tests pass;
- Docker build succeeds;
- React build/type checks pass;
- iOS non-camera logic tests pass;
- hardware-dependent items are listed in `MANUAL_TEST.md` and corresponding GitHub Issues.

Real-device validation is a separate gate.
