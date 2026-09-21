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
The official MVP shall not include analytics, advertising SDKs, telemetry, developer-operated crash upload, or tracking SDKs, including as opt-in features. Introducing any of these requires an explicit Owner decision and ADR before changing the product scope.

### PRIV-004 Explicit diagnostic export
Diagnostics may leave the user's environment only after an explicit export/share action initiated by the deployment owner.

### PRIV-005 Self-hosted media path
Camera media shall flow only inside the user's deployment/private network path, except for explicitly enabled third-party infrastructure such as Tailscale or Slack.

### PRIV-006 Owner biometric data
Owner face verification is optional and requires explicit enrollment. Biometric processing, including face-crop analysis and comparison, and owner template/embedding storage shall remain deployment-local. Face images/crops shall not be sent to external biometric processing services. External biometric processing/storage is not an opt-in option in the MVP; PRIV-005 third-party infrastructure exceptions do not authorize it. The owner template/embedding is sensitive biometric data, is deletable/re-enrollable, and is always excluded from diagnostic exports, including explicit Owner-initiated exports.

### PRIV-007 Non-owner identity minimization
The MVP shall not enroll, name, or persist facial identity profiles or separate face-crop/template libraries for other observed people. Anonymous tracking identifiers may be used only for scoped event correlation; ordinary authorized recordings may contain people without creating a separate biometric library.

### PRIV-008 Deployment responsibility
The deployment owner is responsible for applicable laws, institutional policies, notice requirements, and camera/biometric rules in the deployment environment.

### PRIV-009 Video-only MVP
The MVP shall be video-only: neither local capture nor media-capture-agent shall open microphone/audio devices, capture monitoring audio, or store/forward audio tracks. Browser live playback and recordings shall contain no monitoring audio, and no security decision may depend on audio. The MVP shall not offer an audio-enabling option.

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

Browser/iPhone camera capture is outside the current MVP. Human phones/Macs/desktops are viewer clients.

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
The MVP agent shall capture video only. It shall not open microphone/audio devices, capture monitoring audio, or store/forward audio tracks.

### AGENT-004 Outbound connection model
The agent initiates its connection toward the main ServerSentinel host. The main host does not require SSH/admin access to the capture machine merely to receive video.

### AGENT-005 Pairing
Initial agent enrollment uses an owner-approved, short-lived, single-use pairing credential/code. Before transmitting that credential, the Agent shall authenticate the intended Main Server using trust established through an Owner-approved trusted channel and establish encrypted bootstrap communication that protects the credential and enrollment exchange. Plaintext bootstrap and bypassing Server identity verification are prohibited; failed or missing trust verification aborts pairing without sending the code. The exact bootstrap trust mechanism shall be specified by the pairing/transport ADR. The agent generates or receives a unique revocable node identity. Long-lived media/control traffic shall use authenticated encryption, with mTLS as the default design target unless an ADR selects an equivalent design.

### AGENT-006 No Tailnet requirement
The capture agent shall be able to operate over the same private LAN without being enrolled in the owner's Tailnet.

### AGENT-007 Separate ingest boundary
The main host's LAN ingest endpoint for capture agents shall be separate from the dashboard/API exposure used by human viewers. The ingest endpoint shall not expose dashboard routes.

### AGENT-008 Narrow network exposure
The ingest endpoint requires node authentication regardless of LAN location. Source-address firewall restriction is additionally recommended where stable network addressing permits, but IP address alone is never sufficient authentication.

### AGENT-009 Health and reconnect
Agent heartbeat/health and physical camera health are separate. A healthy agent may report its camera `offline`. Reconnect and substitution handling follows CAM-008/CAM-009.

### AGENT-010 Time synchronization
The main host and capture agent shall monitor clock synchronization/offset sufficiently to keep event ordering trustworthy. Excessive offset becomes an explicit degraded condition rather than silently producing misleading timelines.

### AGENT-011 Installation lifecycle
Development may run the agent from a Git clone. Stable releases should provide a standalone versioned artifact/installer (for example GitHub Releases) and systemd unit so production operation does not depend on a mutable development checkout.

### AGENT-012 Configurable disk recovery ring buffer
`media-capture-agent` shall maintain a bounded ring buffer of **compressed video on disk**, not decoded frame history.

The deployment owner selects one of two configuration modes in ServerSentinel:

- **duration mode** — configure the target rolling-buffer time; the UI shows the projected maximum/expected disk footprint from the negotiated/configured bitrate;
- **capacity mode** — configure the maximum ring-buffer disk capacity; the UI shows the estimated effective buffer duration.

The UI shall always show current ring-buffer usage, configured limit, agent-filesystem free space, protected-incident usage, and safety reserve. It shall warn before a selected value approaches an unsafe disk state and reject values that would violate the filesystem safety reserve.

Configuration admission must support the complete **10-minute pre-loss + 10-minute post-loss** incident under the bounded/negotiated media profile. Reject a selected duration/capacity/profile when it determinably cannot retain the pre-loss window or fit that pinned window and the next 10 minutes of capture simultaneously on the expected filesystem. Estimate bytes from bounded/negotiated bitrate and segment/container overhead, accounting for existing protected incidents, other filesystem use, and the hard safety reserve. Count shared segments once; reclaim only eligible ordinary data outside the required pre-loss window, never the pinned window or unexpired protected incidents. A filesystem that fits only 10 minutes plus reserve is insufficient even if the ring setting itself is valid. Runtime uncertainty or later loss of headroom/coverage shall instead surface a degraded/warning state with actual retained intervals and gaps; never claim full protection or cross the safety reserve.

Changing ring-buffer mode/value is an owner-only operation.

### AGENT-013 Main-host-loss temporary protection
When the agent loses its authenticated connection/heartbeat to the main ServerSentinel host unexpectedly, it shall automatically protect a local incident window covering:
- **10 minutes immediately before loss of communication**; and
- **10 minutes after loss of communication**.

The default protected window is therefore **20 minutes**. The pre-loss portion is pinned from the rolling disk buffer and the post-loss portion continues locally even though the main host is unavailable.

This behavior is intended to preserve room-overview evidence when the main server is moved, disconnected, powered off, or removed before it can send a preserve command.

### AGENT-014 Critical-event preservation
When the main host confirms a critical server-movement/camera-tamper event and communication remains available, it may explicitly instruct paired agents to preserve the relevant local ring-buffer interval as incident evidence. Agent-side preserved evidence is an exception for critical resilience, not a general duplicate of all main-host recordings.

### AGENT-015 Protected-evidence lifecycle
A protected agent incident is retained on the capture agent for **60 days from completion by default**, then automatically deleted from the agent. Owner-authorized manual deletion may remove it earlier.

Protected incidents are excluded from ordinary ring-buffer overwrite before their 60-day expiry. If protected incidents and the active ring buffer create disk pressure, the agent shall reclaim only eligible non-protected ring-buffer data first, warn the owner, and refuse unsafe writes before crossing the filesystem safety reserve rather than silently deleting unexpired protected evidence.

Protected evidence retention, deletion, current bytes, and expiry time shall be visible to the owner.

### AGENT-016 Configurable media root and mount fail-safe
The Agent media root shall be deployment-configured outside the repository; no personal mount/path is hard-coded. Installer/startup and runtime write admission shall verify the approved filesystem/mount/device identity, dedicated-account writability, free space, and safety reserve. If the expected mount is absent or substituted, the Agent shall report a degraded/failed state and refuse unsafe writes. It shall not silently create or use a fallback media directory on the root filesystem.

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
Agent-to-main and main-to-browser low-latency transports must be selected through measured PoC/ADR work. **Near-real-time viewing is the product goal, but stability/reconnect behavior takes priority over minimizing latency by a specific number of seconds.**

Correct authentication, reconnection, bounded buffering/backpressure, and truthful degradation are more important than committing prematurely to WebRTC/SRT/QUIC/another protocol.

For the Agent-to-Main PoC, compare stability, reconnect, accurate gap reporting, bounded buffering/backpressure, authenticated encryption, resource usage, and latency in that order. Authenticated encryption is mandatory for any selected transport; the evaluation order does not make it optional. The exact transport remains undecided until the PoC/ADR.

### MEDIA-007 Durable recording
Durable recording is main-host authoritative during normal operation. Remote source handling must preserve source identity, timestamps, bounded queues/backpressure, and integrity. Agent-side protected incident evidence defined above is a deliberate resilience exception.

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
Detect probable camera tampering using signals available to the source, including where applicable sudden global scene transform, camera occlusion, stream interruption, abrupt orientation/pose change visible in the scene, and source-health changes correlated with motion.

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

## 11. Host hardware integrity and recording-health requirements

### INTEGRITY-001 Owner-approved hardware baseline
The main ServerSentinel host shall maintain a deployment-local, owner-approved hardware baseline for the components relevant to monitoring/evidence integrity.

The baseline shall cover, where the operating system/hardware exposes usable identifiers:
- CPU model/topology/signature information;
- installed memory modules/slots, capacity, part number, and serial where available;
- NVMe/M.2 devices, including stable model/serial/WWN-style identity and capacity where available;
- HDD/other recording drives, including stable model/serial/WWN-style identity and capacity where available;
- GPU identity, including model and stable GPU UUID/serial/PCI identity where available.

The product shall not claim that replacement with an otherwise indistinguishable component can always be detected when the platform exposes no unique identifier.

### INTEGRITY-002 Startup and daily inventory check
Hardware inventory comparison shall run:
- once during ServerSentinel startup; and
- at least once per day while the service remains running.

Results shall distinguish at minimum `OK`, `CHANGED`, `MISSING`, `NEW_DEVICE`, and `UNVERIFIABLE` where applicable.

### INTEGRITY-003 No silent baseline rewrite
Detected hardware drift shall never silently replace the approved baseline. Only the Owner may approve a new baseline or accept a deliberate hardware change, and that action shall be audited.

### INTEGRITY-004 Recording-health self-test
At least once per day, ServerSentinel shall run a recording-health self-test sufficient to detect common silent recording failures, including where applicable:
- recent frame/capture freshness for enabled sources;
- recorder/encoder pipeline state;
- expected recording filesystem/mount/device identity;
- writable/free-space state and filesystem safety reserve;
- a bounded temporary write + flush/fsync + reopen/parse/decode verification on the recording path;
- storage-device health indicators available through SMART/NVMe telemetry.

Temporary self-test media shall be bounded, deployment-local, and never uploaded as telemetry. Self-test-owned temporary/partial media shall be cleaned up on success, failure, or cancellation, and interrupted-test leftovers shall be recovered for cleanup at the next startup before another test segment is written. Cleanup shall target only identified self-test artifacts on the expected filesystem, never ordinary recordings or protected incidents. If cleanup cannot complete, report a recording-health failure, include remaining artifacts in storage admission/safety-reserve accounting, and block further self-test media writes until safe cleanup succeeds; do not silently accumulate daily leftovers or use a fallback mount.

### INTEGRITY-005 Recording-path fail-safe
If the intended recording filesystem is missing/unmounted or resolves to an unexpected device, ServerSentinel shall refuse recording and self-test media writes to that target and expose a degraded/failed state. It shall not create or use a fallback recording directory on the root filesystem or another unintended filesystem, even while reporting degradation.

### INTEGRITY-006 Immediate alerting
A baseline component becoming missing/changed, an unexpected storage device substitution, or a recording-health self-test failure is an immediate owner notification condition rather than waiting only for the daily summary. `UNVERIFIABLE`/probe failures shall at least generate a visible warning, and shall escalate when they prevent assurance of recording/storage integrity.

### INTEGRITY-007 Local-only inventory data
Raw hardware serials/UUIDs and detailed inventory are deployment-local operational/security metadata. Normal operational logs and general diagnostics shall redact or hash these identifiers. Raw identifiers shall not be sent to the developer, telemetry, public diagnostics, or GitHub issues/PRs. Any detailed diagnostic export requires an explicit owner-controlled action and does not authorize automatic upload.

## 12. Notifications

### NOTIFY-001 Slack optional
Slack is optional and disabled until configured.

### NOTIFY-002 Sparse immediate alerts
Immediate alerts cover confirmed server movement/camera tamper and hardware-integrity/recording-health failures defined by INTEGRITY-006. Ordinary person/motion/entry and ordinary camera unplug events are summarized unless the owner configures otherwise. Slack remains optional; disabling Slack does not suppress immediate local/UI fault reporting.

### NOTIFY-003 Daily summary
Default daily summary: 23:00 local time, configurable. Include monitored duration, source/agent health, degraded/offline counts, person/motion/entry counts, critical events, recordings, storage, and errors.

### NOTIFY-004 No developer relay
Slack delivery goes directly from the user's deployment to the user's configured Slack endpoint/API.

## 13. Human remote-access requirements

### AUTH-001 Private reachability only
Public Internet port exposure is not the default. Human remote access should use Tailscale or an equivalent private network.

### AUTH-002 Tailnet membership is not authorization
Being a Tailnet member does not grant ServerSentinel application access.

### AUTH-003 No mandatory Tailnet policy modification
ServerSentinel shall **not modify or manage Tailscale ACLs/Grants** and shall not store Tailscale administrative credentials. Existing Tailnet policy may remain unchanged; any policy administration is performed by the Owner outside ServerSentinel.

Because of this choice, ServerSentinel does **not** guarantee that an uninvited Tailnet member cannot discover that the main Tailscale node exists. Hiding the node itself requires an external Tailscale policy/architecture choice outside the application authorization layer.

### AUTH-004 ServerSentinel invitation/allowlist is authoritative for application data
ServerSentinel checks an owner-managed invitation/allowlist before serving dashboard/media data. A Tailnet user who is not invited receives no camera names, counts, thumbnails, recordings, timeline data, or ServerSentinel deployment metadata from the application.

### AUTH-005 Trusted Tailscale identity path
When Tailscale Serve or an equivalent trusted proxy supplies user identity, the backend accepts those identity headers only from the trusted local proxy path. The dashboard/API should bind to loopback or another non-bypassable local boundary so arbitrary LAN clients cannot spoof proxy identity headers.

A verified proxy identity header states which Tailscale login the request arrived under. Per AUTH-011 it does not by itself state which person is making the request, so it shall not be the sole basis for application authorization.

### AUTH-006 Granular invited-user permissions
At minimum support independent permissions:
- `live:view` — browser live view and current source health needed for live viewing;
- `recordings:view` — browser recording list/playback **plus historical event/timeline access associated with recordings/events**.

Granting one does not imply the other. `live:view` alone shall not expose historical timeline/event data.

### AUTH-007 Browser-only non-owner playback
Non-owner invited users do not receive an official recording download/export endpoint/button in the MVP. The product must state that browser playback cannot technically prevent screen recording or advanced client-side capture.

### AUTH-008 Owner operations
Only the owner (or a future explicitly defined privileged role) may add/revoke users, change permissions, register/revoke capture agents/cameras, configure agent ring-buffer mode/value, enroll/delete owner biometrics, alter retention/security settings, or delete recordings.

These operations shall additionally require a user verification newer than a bounded freshness window, so an older or unattended session cannot perform them on its own. A step-up that fails, is cancelled, or is declined shall leave the operation unperformed, change no state, and disclose nothing beyond the generic failure.

The step-up shall be bound to the session: the challenge is issued for that session and accepts only the still-active credential the session was created with. An assertion from any other credential, including a valid credential belonging to a different person at the same workstation, shall be refused and shall not refresh the session's verification time. Otherwise a non-owner could use their own passkey to revive a stale owner session and run a privileged operation.

### AUTH-009 Immediate application revocation
Application permission revocation shall invalidate active ServerSentinel authorization promptly. Tailnet membership/policy remains separately administered outside ServerSentinel.

Revocation is available at two levels and is credential-scoped, not device-scoped: revoking one credential of a principal shall invalidate that credential and the sessions bound to it only, while revoking the principal shall invalidate all of its credentials and sessions.

A synced passkey is a single credential that may exist on several of its owner's devices, so revoking it takes effect everywhere it synced, and the product shall not present credential revocation as per-device revocation.

Whether a credential can sync is not a guess: registration reads the authenticator's backup-eligibility and backup-state flags and records them with the credential, and the owner UI shows the resulting state. A deployment that requires device-scoped control shall be able to refuse a backup-eligible registration on that signal, with a refusal the person can act on; a deployment that does not require it shall still record the flags rather than imply that every credential is device-bound.

Backup state shall be refreshed from every successfully verified assertion, because a credential registered before its first sync becomes backed up later and a value kept only from registration would leave the owner UI permanently stale.

Backup eligibility shall not change after registration. An assertion reporting a different eligibility shall not be accepted silently: that credential shall be refused and marked inconsistent, and the Owner shall be notified as for a signature-counter regression. The effect shall be bounded so it cannot strand a person: only that credential is refused, the principal's other credentials keep working, the owner UI shall state which credential was refused and why, and a person left with none shall be re-invited through AUTH-012 — an Owner left with none recovers through the local bootstrap path rather than being locked out of the deployment.

### AUTH-010 Application fingerprint minimization for uninvited users
When an ordinary Tailnet user is not invited in ServerSentinel, the application shall minimize disclosure that ServerSentinel is running. Unauthorized responses should be generic/non-branding (for example not-found style), and shall not expose ServerSentinel product/version strings, camera/source counts, API schemas, health details, thumbnails, recordings, timeline data, or other deployment metadata.

This is application-level non-disclosure only. With unchanged Tailscale policy, the existence/reachability of the underlying Tailscale node or listening service cannot be guaranteed hidden.

### AUTH-011 Shared Tailnet account deployments
The target deployment shares a single Tailscale account across the research room to reduce Tailscale cost. Several people sign in to the Tailnet with the same Tailscale login, and any of them can enroll additional devices.

Consequences for this product:

- Tailscale login identity shall **not** be the authoritative application principal, because it cannot distinguish invited people from uninvited people in this deployment;
- ServerSentinel shall issue and verify its own per-person credential, created from an owner invitation and individually revocable. WebAuthn/passkey is the mechanism proposed in ADR-0004 and is the default design target until the Owner accepts or replaces that record;
- the credential shall be bound to a person rather than to a workstation. Registration and every authentication shall require authenticator user verification (local PIN, device unlock, or on-device biometric), and the authenticator shall be one the invited person controls. Where a lab machine's OS account or device unlock is shared, a platform authenticator stored in that shared account is a shared credential and does not satisfy this requirement; such a deployment shall use a per-person OS account or a portable authenticator the invited person carries;
- a session shall be a server-side record bound to one principal and to the credential that created it, and, where the deployment supplies a verified proxy identity, to the identity it was created under, so that a later request on the same session carrying a different verified identity is refused. Sign-out, expiry and revocation shall invalidate that server-side record, so a retained cookie/token authorizes nothing afterwards, and every human/media route shall re-check it server-side rather than trusting a client-side state. Sessions shall end after a bounded idle lifetime and a bounded absolute lifetime that the server enforces (ADR-0003 proposes 30 minutes idle and 12 hours absolute; a different value is recorded there before implementation, not chosen ad hoc), the UI shall offer an explicit sign-out for shared machines, and the owner operations of AUTH-008 shall require a fresh user-verification step rather than an old session alone;
- authenticator user verification runs on the viewer's own device and reaches the server only as the authenticator's user-verification flag. ServerSentinel shall verify the transient protocol data a registration or assertion requires — its own challenge, client data, authenticator data, the attestation or assertion signature, the signature counter, the user-verification flag, and the relying-party id and origin — and shall persist only public credential material (credential id and public key), the last accepted signature counter, the authenticator's backup-eligibility and backup-state flags, and owner-visible metadata (label, created/last-used/revoked timestamps), discarding the rest once verified. The counter and the backup flags are retained deliberately: without the counter the clone check has nothing to compare against, and without the flags AUTH-009 cannot show whether a credential syncs or refuse a backup-eligible registration;
- no viewer fingerprint or face template shall be received, persisted or exportable: it never leaves the authenticator. Credential records are an access-control list; they are unrelated to the optional owner face verification of DET-008 and shall not become a non-owner identity or biometric database;
- relying-party verification depends on ServerSentinel owning its browser origin; the dashboard is served from an origin reserved for it, with no other application sharing it. Reserving that origin is a deployment obligation — a dedicated host, VM or namespace, or an OS/service policy that prevents another process from binding the name — because the application cannot stop a co-located process from taking it;
- ServerSentinel shall check the reservation at startup and at least daily by enumerating the host's actual listeners and every proxy route that reaches them, across all schemes and ports, and shall close human access and notify the Owner when anything other than ServerSentinel answers on the reserved name. This bounds the exposure window rather than preventing the bind: a process that binds between two checks can receive credentials and cookies for that origin until the next check, and the documentation shall say so rather than presenting the check as a barrier. ADR-0003 states the reservation in full, including why another port of the same name is not acceptable;
- the origin shall be a secure context: HTTPS, or `http://localhost` for a strictly local browser. Browsers do not expose WebAuthn otherwise, so an ordinary-HTTP origin on a non-loopback host leaves the owner and every invitee unable to register or authenticate. A private-network path that terminates plain HTTP on a non-loopback host therefore does not carry human access under this requirement, even though AUTH-001 permits an equivalent private network;
- verified Tailscale login/device information may be used only as a supplementary signal (for example logging or an additional restriction), never as the only check;
- where that signal is retained, its lifecycle shall be defined and disclosed: the principal keeps at most the value last observed at authentication, overwritten on each authentication, visible to the owner only, cleared when the principal is revoked or deleted, and excluded from diagnostic exports. Any per-authentication history belongs to the audit log under the default 90-day audit retention rather than to the principal record, and `PRIVACY.md` shall list it so operators are not told that only WebAuthn material and metadata persist;
- device-scoped approval may be offered in addition, but the product shall not claim that approving a device identifies a person; a shared or borrowed device is used by whoever holds it;
- network reachability is not a boundary in this deployment: anyone holding the shared account can reach the node, so every human route depends on the application credential;
- an authenticated session shall remain bound to one principal, and revoking a principal or one of its credentials shall take effect promptly per AUTH-009;
- before authentication succeeds the application responds per AUTH-010, and an uninvited person and a revoked person receive the same response.

Both gates of AUTH-001/AUTH-004 remain mandatory and unchanged. What the shared account changes is that the network gate no longer distinguishes individuals, so it shall not be presented as the barrier that keeps an uninvited person out.

Limits that shall be documented rather than claimed away: ServerSentinel cannot detect a credential whose holder deliberately lends it, a session left unlocked on an unattended machine, or an authenticator that the deployment registered inside a shared profile against this requirement. The product shall not claim that the application separates two people who share a workstation and a device unlock.

### AUTH-012 Bootstrap and enrollment before a credential exists
AUTH-011 cannot apply to the requests that create the first credential. Exactly two HTTP routes may therefore run without one, and the pair is closed:

- invitation redemption accepts only a valid, unexpired, unredeemed enrollment code, is single-use and rate-limited, and registers exactly one credential for the named principal. Single use shall be enforced atomically rather than by a check followed by a write, so that concurrent redemptions of one code produce exactly one credential, the losing request gets the generic response, no partial state remains, and a retried redemption is idempotent;
- the authentication/assertion route itself.

Initial owner bootstrap adds no third route. It is a privileged local administrative action on the Main Server that issues a single-use, short-lived enrollment authorization shown only on the local console; the first owner then redeems it through the same redemption route, from a browser at the reserved origin. There is no owner-specific route and no remote first-visitor setup path.

Every other human/media route requires a verified credential and an active session per AUTH-011.

An enrollment code and a bootstrap authorization are bearer authorizations: whoever presents one claims the named principal, and in this deployment everyone holding the shared Tailscale account can reach the redemption path. They shall therefore be generated by a cryptographically secure random generator with at least 128 bits of entropy, drawn from the full generated value rather than from a shortened display form, and compared in constant time against a stored hash. A human-friendly encoding may be used, but it shall not reduce the entropy below that floor; a short or guessable code does not satisfy this requirement even with a lifetime limit, single use and rate limiting in place. Redemption attempts shall be rate-limited per code and per source, and the code shall expire after a short deployment-configured lifetime.

These pre-authentication routes shall return no camera names or counts, recordings, timeline data, product/version strings, API schema, or other deployment metadata, and enrollment shall grant no application data by itself; the invited person authenticates afterwards like anyone else. A request with an absent, unknown, expired or already-redeemed code shall receive the same generic AUTH-010 response as an uninvited person, and logs shall record the attempt without the raw code.

## 14. Dashboard requirements

### UI-001 Responsive live grid
Support phone/Mac/desktop browsers. One source uses a large tile, two use split layout, three/four use responsive grid where practical.

### UI-002 Source health
Show source name/type/role, camera/agent online state, negotiated capture/view profile, image-quality state, and any `manual_intervention_required` condition.

### UI-003 Access management
Owner UI shall show invited identities, independent `live:view` / `recordings:view` permissions, active/revoked state, and clearly state that Tailnet membership by itself does not grant application access.

### UI-004 Agent evidence/buffer settings
Owner UI shall expose:
- ring-buffer configuration mode: **duration** or **disk capacity**;
- configured value and estimated equivalent value in the other unit;
- projected maximum/expected ring-buffer disk footprint;
- current ring-buffer bytes;
- protected-incident bytes and expiry dates;
- agent filesystem free space and safety reserve;
- clear warning/degraded/error states when the requested 10-minute pre-loss window, headroom for the following 10 minutes, or disk safety cannot be maintained.

## 15. Performance and overload requirements

### PERF-001 Four-source target
Four active sources are a supported test target, not a guarantee that every camera can run maximum advertised quality simultaneously on every USB/network/host topology.

### PERF-002 Adaptive inference
Inference cadence is independent from capture FPS and may reduce under load. Critical monitoring/health and evidence integrity take precedence over expensive analysis and viewer quality.

### PERF-003 Truthful degradation
Do not silently drop a source while reporting healthy monitoring. Surface overload, dropped frames, encoder pressure, and network/backpressure where material.

## 16. Testing/repository requirements

### TEST-001 Synthetic repository media only
Repository and CI media fixtures shall be **synthetic/generated only**. Real-person, real-room, real-monitoring, or merely publicly licensed real-person media shall not be committed to the repository or attached to GitHub PRs/issues/actions artifacts.

Public or privately licensed real-person benchmark datasets, if legally/ethically appropriate for local model evaluation, may be used only outside the repository under their terms and are not repository fixtures.

### TEST-002 Real hardware stays local
Real hardware/room/owner tests are documented in `MANUAL_TEST.md`; results may record measurements and PASS/FAIL without uploading real monitoring media or biometric templates.

### TEST-003 Required source/agent tests
Cover local UVC and remote-agent discovery, ambiguous identical-device reconnect, agent pairing/revocation, clock offset, LAN outage/reconnect, source health, 1–4 mixed topology, capture-vs-inference/view profiles, bounded disk ring-buffer behavior, 10-minute pre-loss pinning, 10-minute post-loss continuation, and protected-evidence capacity handling.

## 17. Development/review requirements

### DEV-001 No direct main
Non-trivial work uses Issue -> branch -> PR -> CI/review -> merge.

### DEV-002 Dual automated review
Codex and Claude must both review the current PR diff. A review is valid only for the current **HEAD and base revision/diff context**. If either HEAD or relevant base changes, the review must be rerun before merge.

### DEV-003 No secrets/private deployment data
Never commit real credentials, private keys, owner biometrics, private deployment values, or real monitoring media.

## 18. Non-goals / deferred decisions

Not required for MVP unless separately approved:
- browser/iPhone used as a camera source;
- native mobile app/App Store distribution;
- audio surveillance;
- cross-camera biometric re-identification;
- named non-owner face database;
- public Internet dashboard exposure;
- ServerSentinel-managed Tailscale admin-policy mutation;
- guaranteed network-level concealment from ordinary Tailnet members when Tailnet policy is left unchanged;
- guaranteed DRM/prevention of viewer screen capture;
- guaranteed concealment from Tailnet/network administrators;
- independent general-purpose off-host recording replication;
- final camera/codec/FPS defaults before real-hardware measurement.
