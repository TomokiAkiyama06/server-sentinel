# ServerSentinel Requirements

## 1. Purpose

ServerSentinel shall provide a self-hosted physical-security monitoring system for valuable servers/workstations using one or more heterogeneous camera sources and an Ubuntu main host for storage, analysis, event correlation, and the web dashboard.

The system is optimized for one deployment owner who may explicitly invite additional viewers. It must remain installable by unrelated users without developer assistance.

No specific camera model, room layout, IP address, filesystem path, or exact camera count is required.

## 2. Product priorities

Priority order:

1. **Private remote multi-camera live viewing**
2. **Evidence preservation for theft/tampering while the recorder is available**
3. **Server movement and camera-tamper detection**
4. **Room/entrance/person/presence timeline correlation**
5. **Unified ServerSentinel operational status**

Continuity and truthful state reporting are more important than maximum image quality.

## 3. Privacy and ownership requirements

### PRIV-001 No developer cloud
The project shall not require a ServerSentinel-operated cloud service.

### PRIV-002 No developer-side user data
The developer shall not receive or retain users' video, biometric templates, private network information, event metadata, recordings, audit logs, or deployment configuration as part of normal operation.

### PRIV-003 No telemetry/analytics
The official project shall not include analytics, advertising SDKs, telemetry, developer-operated crash upload, or tracking SDKs by default.

### PRIV-004 Explicit diagnostic export
Diagnostics may leave the user's environment only after an explicit export/share action initiated by the deployment owner.

### PRIV-005 Self-hosted media path
Camera media shall flow only inside the user's deployment/private network path, except for explicitly enabled third-party infrastructure such as Tailscale or Slack.

### PRIV-006 Owner biometric data
Owner face verification is optional and requires explicit enrollment. The owner template/embedding is sensitive biometric data, stays deployment-local by default, is deletable/re-enrollable, and is excluded from normal diagnostics.

### PRIV-007 Non-owner identity minimization
The MVP shall not maintain a named biometric identity database for other observed people. Anonymous tracking identifiers may be used only for scoped event correlation.

### PRIV-008 Deployment responsibility
The deployment owner is responsible for applicable laws, institutional policies, notice requirements, and camera/biometric rules in the deployment environment.

### PRIV-009 Video-only MVP
Audio capture/surveillance is not required for the MVP. Camera microphones shall not be used by default and no security decision may depend on audio.

## 4. Distribution and licensing requirements

### DIST-001 Self-hosted distribution
The MVP is self-hosted server/web software plus an optional Linux capture agent. A native iOS application, App Store distribution, and Apple Developer Program membership are not required.

### DIST-002 Open-source repository
The project repository shall be suitable for public GitHub hosting.

### DIST-003 License
Project source shall be licensed under Apache-2.0.

### DIST-004 Dependency/model compatibility
Dependencies, models, and weights must have licenses compatible with the project's distribution goals. Source-code and model/weight licenses are reviewed separately. AGPL/GPL/SSPL/source-available/unclear components are blocked by default unless explicitly approved and documented.

## 5. Camera-source requirements

### CAM-001 Camera-source abstraction
All video inputs shall use a common Camera Source abstraction rather than fixed `front`/`rear` or fixed-camera schemas.

### CAM-002 MVP source types
The MVP shall support:
- `local_uvc`: UVC/V4L2-compatible camera attached to the main Ubuntu host;
- `remote_agent`: UVC/V4L2-compatible camera attached to another owner-authorized Linux host running `media-capture-agent`.

A future browser camera source such as `remote_web` may be added later without changing the core event/storage model, but it is not required for MVP completion.

### CAM-003 Source count
The MVP shall work with **one active video source** and support **up to four active video sources**. Four is a configurable MVP limit; data models/APIs shall not assume exactly two or four sources.

### CAM-004 Free composition
Any supported source types may be mixed within the active-source limit. Examples include one local webcam, two local webcams, one remote agent camera, or mixed local/remote-agent sources.

### CAM-005 Source metadata
Each source shall have a stable logical source ID, user-visible name, source type, enabled state, optional role label, capabilities, health state, capture profile, and assigned detection profiles.

### CAM-006 Role is not hardware type
Role labels such as `server_overview`, `server_rear`, `room_overview`, `entrance`, or custom values shall not be tied to source type.

### CAM-007 Configurable detection profiles
Detection behavior is configured per source/profile, including motion, person, server ROI/movement, camera tamper, entrance/zone logic, owner verification, and image-quality gating.

### CAM-008 Stable UVC identity
The system shall not use `/dev/videoN` alone as durable physical-camera identity.

Where available, identity may use `/dev/v4l/by-id`, serial numbers, USB topology/physical path, udev metadata, vendor/product information, and capabilities.

If a reconnect cannot be matched unambiguously to the previously approved physical camera—especially with multiple identical devices lacking unique serials—the system shall **not** auto-bind it. The source becomes `manual_intervention_required` until the owner explicitly re-approves the mapping.

### CAM-009 Camera unplug/replug
A disconnected physical camera becomes `offline` and generates a health/audit event. The capture service remains alive. A uniquely identifiable reconnect may return to `online` automatically. Intentional unplugging is still recorded as an offline event; immediate notification policy may be configurable.

### CAM-010 Camera health
At minimum support `online`, `degraded`, `offline`, and `manual_intervention_required` where applicable.

### CAM-011 Room-overview support
A wide room-overview camera may be located physically closer to a separate Linux machine than to the main host. The architecture shall support forwarding that camera over the private LAN through `media-capture-agent` without requiring that capture machine to join Tailscale.

## 6. `media-capture-agent` requirements

### AGENT-001 Functional identity
The Linux capture service shall use the truthful functional name `media-capture-agent` (including the intended systemd service name). It shall not impersonate unrelated system software.

### AGENT-002 Background service
The agent shall run without a desktop window/tray requirement and should run under a dedicated non-root service account during normal operation. Root/admin privileges are limited to installation and narrowly required device/service configuration.

### AGENT-003 Video-only capture
The MVP agent captures video only. Microphones are not required and should not be opened.

### AGENT-004 Outbound connection model
The agent initiates its connection toward the main ServerSentinel host. The main host does not require SSH/admin access to the capture machine merely to receive video.

### AGENT-005 Pairing
Initial agent enrollment uses an owner-approved, short-lived, single-use pairing credential/code. The agent generates or receives a unique revocable node identity. Long-lived media/control traffic shall use authenticated encryption, with mTLS as the default design target unless an ADR selects an equivalent design.

### AGENT-006 No Tailnet requirement
The capture agent shall be able to operate over the same private LAN without being enrolled in the owner's Tailnet.

### AGENT-007 Separate ingest boundary
The main host's LAN ingest endpoint for capture agents shall be separate from the dashboard/API exposure used by human viewers. The ingest endpoint shall not expose dashboard routes.

### AGENT-008 Narrow network exposure
The ingest endpoint requires node authentication regardless of LAN location. Source-address firewall restriction is additionally recommended/required where stable network addressing permits, but IP address alone is never sufficient authentication.

### AGENT-009 Health and reconnect
Agent heartbeat/health and physical camera health are separate. A healthy agent may report its camera `offline`. Reconnect and substitution handling follows CAM-008/CAM-009.

### AGENT-010 Time synchronization
The main host and capture agent shall monitor clock synchronization/offset sufficiently to keep event ordering trustworthy. Excessive offset becomes an explicit degraded condition rather than silently producing misleading timelines.

### AGENT-011 Installation lifecycle
Development may run the agent from a Git clone. Stable releases should provide a standalone versioned artifact/installer (for example GitHub Releases) and systemd unit so production operation does not depend on a mutable development checkout.

### AGENT-012 Local recovery buffer undecided
Whether `media-capture-agent` retains a short local recovery ring buffer during main-host/network outages, its duration, storage medium (RAM/tmpfs vs disk), and privacy behavior require a separate decision before implementation. No durable agent-side recording guarantee is implied yet.

## 7. Capture, encode, and streaming requirements

### MEDIA-001 Capture/record/inference/view separation
Capture quality, durable-recording quality, inference cadence, and browser-view quality shall be independently configurable/adaptive. A high-resolution room-overview source must not force every inference or remote viewer to process the full source resolution/FPS.

### MEDIA-002 Benchmark-derived source profiles
Exact source defaults are chosen from real measurements. Candidate room-overview tests may compare high-resolution 10–15 fps capture with 1080p/15 fps and lower viewer/inference profiles.

### MEDIA-003 Codec efficiency
Prefer passthrough/stream-copy when source codec/profile is suitable. Otherwise use bounded software or hardware encode/decode resources. Remote-agent hardware acceleration may be used when available but is not a correctness requirement.

### MEDIA-004 Multi-source live view
Authorized users with `live:view` shall be able to view active sources from phone/Mac/desktop browsers through the main ServerSentinel dashboard. The UI adapts for 1–4 sources.

### MEDIA-005 Demand-driven viewer processing
Viewer-only transcoding/packaging should be started or scaled only when needed. No viewer should require a direct connection to a capture agent.

### MEDIA-006 Live transport decision
Agent-to-main and main-to-browser low-latency transports must be selected through measured PoC/ADR work. Correct authentication/reconnect/backpressure semantics are more important than committing prematurely to WebRTC/SRT/QUIC/another protocol.

### MEDIA-007 Durable recording
Durable recording is main-host authoritative. Remote source handling must preserve source identity, timestamps, bounded queues/backpressure, and integrity. If chunk retry is used it must be idempotent.

### MEDIA-008 Manual recording
The owner may start/stop manual recording for selected sources. Default maximum: **20 minutes**.

### MEDIA-009 Event ring buffer
The main host maintains bounded recent compressed media for configured sources where resources permit. Default automatic event target is 30 seconds pre-event + 120 seconds post-event, extendable while qualifying activity continues, maximum 20 minutes.

Decoded frame histories shall not be retained unnecessarily when compressed media can satisfy pre-roll requirements.

### MEDIA-010 Multi-source event evidence
One event may reference media from multiple sources. Filenames/schema use source IDs rather than role-specific fixed names.

## 8. Detection requirements

### DET-001 General motion
General motion detection shall be available per configured source.

### DET-002 Person detection
Person detection shall be available per configured source. Heavy inference runs on the main Ubuntu host by default; capture agents should remain lightweight unless a future architecture decision introduces edge inference.

### DET-003 Pluggable detector
Person/face implementations remain replaceable. Code and model/weight licenses are verified separately. YOLOX is an initial person-detector evaluation candidate, not a mandated final model.

### DET-004 Server ROI/movement
One or more sources may have server ROI/polygon/reference geometry. Meaningful displacement/rotation requires temporal/scene confirmation; person presence alone is not proof of movement.

### DET-005 Camera tamper
Detect probable tamper using available signals such as global scene transform, persistent occlusion/near-black view, stream interruption, abrupt pose/exposure change, and source-health changes correlated with movement.

### DET-006 Occlusion tolerance
Temporary person occlusion of a server ROI shall not immediately become confirmed server movement.

### DET-007 Detector-specific quality gating
Each detector shall define the visual-quality prerequisites needed for a trustworthy positive **and negative** result.

If a frame/source is too dark, blurred, saturated, obstructed, too low-resolution, or otherwise inadequate for a dependent detector:
- report `degraded`/`insufficient` quality with reason/metrics;
- skip or mark that detector `unknown`/unavailable;
- **do not interpret skipped/failed person inference as `no person`**;
- do not force owner match/non-match;
- do not force presence from absent evidence;
- live/recording may continue if frames still exist.

### DET-008 Owner-only face verification
The MVP may verify whether a detected face matches one explicitly enrolled deployment owner. Enrollment is explicit/optional; result is probabilistic; low-quality/ambiguous inputs become `unknown`; template remains local and deletable/re-enrollable.

### DET-009 No named non-owner face database
The MVP shall not enroll, name, or persist facial identity profiles for other observed people.

### DET-010 Anonymous tracking
Non-owner people may receive anonymous track/session IDs within a configured scope. Cross-camera biometric re-identification is not an MVP feature.

### DET-011 Entrance/zone crossing
A room-overview/entrance source may use a line/zone and direction when geometry supports it. Owner entry/exit is emitted only when owner verification quality is sufficient; anonymous entry/exit does not name the person.

## 9. Event/presence requirements

### EVENT-001 Unified timeline
Correlate camera/server observations chronologically: person/motion, anonymous/owner entry-exit, server movement, camera health, agent health, recording/storage state, presence, configuration changes.

### EVENT-002 No culprit inference
Do not label an observed person as thief, attacker, culprit, or cause based solely on temporal/camera correlation.

### EVENT-003 Confidence/source attribution
Derived observations include source attribution and confidence/quality where applicable.

### PRES-001 Presence states
Support `PRESENT`, `PROBABLY_PRESENT`, `ABSENT`, `UNKNOWN`.

### PRES-002 Manual override
Manual owner override has precedence over inferred state/schedules until cancelled/expired.

### PRES-003 Suppression safety
Only explicit/high-confidence `PRESENT` suppresses ordinary person/general-motion automation by default. `PROBABLY_PRESENT`/`UNKNOWN` do not silently disarm monitoring. Server movement and camera tamper remain armed in every presence state.

## 10. Storage requirements

### STORE-001 Ubuntu primary storage
Recordings, thumbnails, metadata, audit logs, and owner biometric template reside primarily on the self-hosted main Ubuntu deployment.

### STORE-002 Configurable recording root
No recording path is hard-coded to a personal disk/mount.

### STORE-003 Retention
Default recording retention: **20 days**. Default audit-log retention: **90 days**.

### STORE-004 Capacity ceiling
The owner configures maximum recording allocation. Cleanup reacts to retention, configured allocation, and actual filesystem safety pressure.

### STORE-005 Starred recordings
Starred recordings are excluded from automatic deletion but count toward disk usage. They never justify intentionally filling the filesystem.

### STORE-006 Filesystem safety reserve
Preserve a hard filesystem safety reserve independent of normal recording allocation. Reclaim eligible unstarred recordings first, then suppress ordinary/manual recording under `STORAGE_PRESSURE`; bounded critical evidence may use only a safe allowance; refuse writes before crossing the hard reserve under `STORAGE_HARD_STOP`; recover with hysteresis.

## 11. Notifications

### NOTIFY-001 Slack optional
Slack is optional and disabled until configured.

### NOTIFY-002 Sparse immediate alerts
Immediate alerts default to confirmed server movement/camera tamper. Ordinary person/motion/entry and ordinary camera unplug events are summarized unless the owner configures otherwise.

### NOTIFY-003 Daily summary
Default daily summary: 23:00 local time, configurable. Include monitored duration, source/agent health, degraded/offline counts, person/motion/entry counts, critical events, recordings, storage, and errors.

### NOTIFY-004 No developer relay
Slack delivery goes directly from the user's deployment to the user's configured Slack endpoint/API.

## 12. Human remote-access requirements

### AUTH-001 Private reachability only
Public Internet port exposure is not the default. Human remote access should use Tailscale or an equivalent private network.

### AUTH-002 Tailnet membership is not authorization
Being a Tailnet member does not grant ServerSentinel access.

### AUTH-003 Network-level concealment for uninvited ordinary members
The deployment shall use restrictive Tailscale access policy/Grants so ordinary Tailnet members who are not authorized for ServerSentinel receive no network grant to the ServerSentinel main node. Where supported by Tailscale peer-map behavior, they should not normally discover the node through peer visibility/status.

This requirement does **not** claim concealment from Tailnet Owners/Admins, infrastructure administrators, or other principals that inherently manage the Tailnet/network.

### AUTH-004 Separate ServerSentinel allowlist
Even if a user can reach the node, ServerSentinel checks an owner-managed allowlist/invitation before serving any dashboard/media data. Unauthorized users receive no camera names, counts, thumbnails, recordings, or deployment metadata.

### AUTH-005 Trusted Tailscale identity path
When Tailscale Serve or an equivalent trusted proxy supplies user identity, the backend accepts those identity headers only from the trusted local proxy path. The dashboard/API should bind to loopback or another non-bypassable local boundary so arbitrary LAN clients cannot spoof proxy identity headers.

### AUTH-006 Granular invited-user permissions
At minimum support independent permissions:
- `live:view` — browser live view;
- `recordings:view` — browser recording list/playback.

Granting one does not imply the other.

### AUTH-007 Browser-only non-owner playback
Non-owner invited users do not receive an official recording download/export endpoint/button in the MVP. The product must state that browser playback cannot technically prevent screen recording or advanced client-side capture.

### AUTH-008 Owner operations
Only the owner (or a future explicitly defined privileged role) may add/revoke users, change permissions, register/revoke capture agents/cameras, enroll/delete owner biometrics, alter retention/security settings, or delete recordings.

### AUTH-009 Grant-management boundary
Automatic mutation of Tailscale Grants from ServerSentinel is **not required** for MVP because it would introduce Tailscale administrative credentials. The owner may manage the Tailnet-level permission separately. ServerSentinel must clearly show that both Tailnet permission and application invitation are required.

### AUTH-010 Immediate revocation
Application permission revocation shall invalidate active authorization promptly. Tailnet-level access revocation remains a separate network-policy action unless a future approved integration automates it.

### AUTH-011 Timeline permission unresolved
Whether invited users with only `live:view` or `recordings:view` may access historical event/timeline metadata requires a separate explicit decision. Implementations shall not implicitly expose historical timeline data through live-view authorization.

## 13. Dashboard requirements

### UI-001 Responsive live grid
Support phone/Mac/desktop browsers. One source uses a large tile, two use split layout, three/four use responsive grid where practical.

### UI-002 Source health
Show source name/type/role, camera/agent online state, negotiated capture/view profile, image-quality state, and any `manual_intervention_required` condition.

### UI-003 Access management
Owner UI shall show invited identities, independent `live:view` / `recordings:view` permissions, active/revoked state, and the fact that Tailscale network permission is separately required.

## 14. Performance and overload requirements

### PERF-001 Four-source target
Four active sources are a supported test target, not a guarantee that every camera can run maximum advertised quality simultaneously on every USB/network/host topology.

### PERF-002 Adaptive inference
Inference cadence is independent from capture FPS and may reduce under load. Critical monitoring/health and evidence integrity take precedence over expensive analysis and viewer quality.

### PERF-003 Truthful degradation
Do not silently drop a source while reporting healthy monitoring. Surface overload, dropped frames, encoder pressure, and network/backpressure where material.

## 15. Testing/repository requirements

### TEST-001 Synthetic repository media only
Repository and CI media fixtures shall be **synthetic/generated only**. Real-person, real-room, real-monitoring, or merely publicly licensed real-person media shall not be committed to the repository or attached to GitHub PRs/issues/actions artifacts.

Public or privately licensed real-person benchmark datasets, if legally/ethically appropriate for local model evaluation, may be used only outside the repository under their terms and are not repository fixtures.

### TEST-002 Real hardware stays local
Real hardware/room/owner tests are documented in `MANUAL_TEST.md`; results may record measurements and PASS/FAIL without uploading real monitoring media or biometric templates.

### TEST-003 Required source/agent tests
Cover local UVC and remote-agent discovery, ambiguous identical-device reconnect, agent pairing/revocation, clock offset, LAN outage/reconnect, source health, 1–4 mixed topology, and capture-vs-inference/view profiles.

## 16. Development/review requirements

### DEV-001 No direct main
Non-trivial work uses Issue -> branch -> PR -> CI/review -> merge.

### DEV-002 Dual automated review
Codex and Claude must both review the current PR diff. A review is valid only for the current **HEAD and base revision/diff context**. If either HEAD or relevant base changes, the review must be rerun before merge.

### DEV-003 No secrets/private deployment data
Never commit real credentials, private keys, owner biometrics, private deployment values, or real monitoring media.

## 17. Non-goals / deferred decisions

Not required for MVP unless separately approved:
- browser/iPhone used as a camera source;
- native mobile app/App Store distribution;
- audio surveillance;
- cross-camera biometric re-identification;
- named non-owner face database;
- public Internet dashboard exposure;
- automatic Tailscale admin-policy mutation;
- guaranteed DRM/prevention of viewer screen capture;
- guaranteed concealment from Tailnet/network administrators;
- independent developer cloud/off-host evidence service;
- exact agent-local recovery-buffer policy until its ADR/Issue is decided.
