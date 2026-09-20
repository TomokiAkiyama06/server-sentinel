# ServerSentinel Manual / Real-Hardware Test Plan

This document contains checks that cannot be truthfully completed using software mocks alone.

Do not mark an item PASS without performing it on the stated hardware/network/browser environment. Do not commit or attach real monitoring footage, real-person images/video/audio, owner biometric templates, or private deployment values to GitHub.

Issue #7's backend foundation uses temporary SQLite and in-process ASGI tests;
it does not mark any check here PASS. Before opening human routes under #10,
verify the documented launcher binds only to the intended loopback boundary,
the proxy cannot be bypassed, and generic denial also covers schema/version,
static assets and errors. No unauthenticated HTTP health exception is provided.

## Test metadata

```text
Date:
ServerSentinel version / Git commit:
Main Ubuntu version / hardware:
Capture-node Ubuntu version / hardware:
Camera source(s) / model(s):
USB topology:
LAN topology/speed:
Tailscale/private-access path:
Phone/Mac/desktop browser used for viewing:
Recording volume:
Tester:
```

## A. Local UVC / USB camera

Issue #11 implementation status (2026-09-20): synthetic discovery, driver-ioctl,
identity, restart-persistence and registry integration tests passed. No physical
camera was opened and no actual preview, audio-device trace or arm64 execution
was verified. All hardware checkboxes below remain unverified.

After the Owner-authorized management and worker/preview wiring are available,
run the following on the intended Main Ubuntu host under its dedicated account:

1. Record model, supported profile, device permission and stable evidence in a
   private local test record; publish only pass/fail and non-sensitive counts.
2. Enable one source with an explicit profile and select its current physical
   candidate. Verify negotiated dimensions/FPS/FourCC and first-frame transition
   from degraded to online. Repeat with up to four sources.
3. Observe the service's opened descriptors locally while the camera's integrated
   microphone is present; only the selected video device may be opened, never
   ALSA/OSS microphone devices. Do not publish trace paths or captured media.
4. Unplug one camera. Verify its offline audit event, continuing service process,
   and uninterrupted second source. Reconnect a unique serial camera with changed
   video-node numbering and verify the same source UUID returns online only after
   a new frame. Disable it and verify its video descriptor is closed.
5. Reorder identical non-serial devices, including the case where only one is
   reattached. Verify manual intervention; restart the backend and verify the
   latch still holds. Explicitly reapprove the current candidate and confirm video
   resumes. Duplicate-serial evidence must also require manual intervention.
6. Check unsupported profile/permission, driver timeout and corrupted-frame paths
   are visibly unavailable, never healthy; restore the supported configuration.
7. Using a disposable database, inject a failed ambiguity-latch write and stop the
   worker without clean shutdown. Restart with one formerly duplicated serial
   device remaining: it must require Owner reapproval. Repeat with no capture
   profile; the manual-intervention state must remain visible. A normal clean
   shutdown/restart of an unambiguous serial device may reconnect automatically.

Results: **NOT RUN — hardware, authorized management and viewer integration
remain pending. Issue #11 is not closed by synthetic tests.**

For each tested camera:

- [ ] exact manufacturer/model and advertised UVC resolution/FPS/pixel-format/codec capabilities are recorded locally;
- [ ] device is discovered;
- [ ] stable identity evidence is shown where available;
- [ ] owner can enable/disable source;
- [ ] preview works;
- [ ] negotiated resolution/FPS/format is reported;
- [ ] unplug creates `offline` event/state;
- [ ] reconnect works when identity is unambiguous;
- [ ] reboot/re-enumeration does not silently bind a different device through `/dev/videoN` reuse;
- [ ] no unnecessary privileged container is required.

### Ambiguous identical-device test

Where possible use two identical UVC devices without a usable unique serial, or a controlled mock reproducing that identity ambiguity.

- [ ] disconnect/reorder devices;
- [ ] system does **not** arbitrarily choose one as the old source;
- [ ] source enters `manual_intervention_required`;
- [ ] owner can explicitly re-approve a physical mapping;
- [ ] healthy monitoring resumes only after approval.

## B. Remote Linux capture node / `media-capture-agent`

Use the intended secondary Ubuntu machine and room-overview camera.

Installation/service:

- [ ] development checkout can run the agent during development;
- [ ] `media-capture-agent.service` installs/starts cleanly when installer exists;
- [ ] normal process runs as a dedicated non-root account;
- [ ] no GUI/tray is required;
- [ ] service name/process is `media-capture-agent` and does not impersonate unrelated software;
- [ ] microphone/audio device is not opened;
- [ ] media root is deployment-configured outside the checkout;
- [ ] ring-buffer and incident writes use the approved dedicated media filesystem when configured;
- [ ] installer/startup and runtime admission verify expected mount/filesystem/device, dedicated-account writability, free space, and safety reserve;
- [ ] using a disposable test volume, expected media-mount loss or substitution produces a visible degraded/failed state and refuses unsafe writes;
- [ ] that failure never creates or uses a fallback media directory on the root filesystem.

Use a disposable volume or controlled mount-identity mocks for failure checks; do not unmount or alter production storage for this test.

Pairing/security:

- [ ] owner creates a short-lived one-time pairing code;
- [ ] initial pairing is encrypted and authenticates the intended Main Server using Owner-approved bootstrap trust before sending the code;
- [ ] missing/mismatched Server trust and plaintext bootstrap attempts fail without exposing the code;
- [ ] expired code is rejected;
- [ ] reused code is rejected;
- [ ] agent identity is unique/revocable;
- [ ] post-pairing traffic is mutually authenticated/encrypted;
- [ ] revoked agent cannot reconnect;
- [ ] an unpaired LAN host cannot submit media;
- [ ] capture-node credential cannot access dashboard/admin APIs.

Connectivity:

- [ ] agent works over the same private LAN without joining Tailscale;
- [ ] agent initiates connection toward the main host;
- [ ] main host does not require SSH/admin access to the capture machine;
- [ ] ingest listener exposes no dashboard/settings/recording-browser routes;
- [ ] firewall/interface restrictions are documented and do not replace mTLS.

Health:

- [ ] agent-online / camera-online shown separately;
- [ ] camera USB unplug leaves agent online and camera offline;
- [ ] reconnect returns online only after safe identity match;
- [ ] agent stop/crash becomes node offline;
- [ ] main-host restart/reconnect is reported truthfully;
- [ ] heartbeat does not falsely imply that video frames are arriving.

Apply the exact-model, UVC-capability, stable-identity, and reconnect checks in section A to capture-node cameras as well as Main Server cameras.

## C. Room-overview camera placement

For the intended wide room view:

- [ ] full room/important area is visible;
- [ ] entrance/zone is visible if entrance logic is desired;
- [ ] server area is visible if the overview source is expected to contribute evidence;
- [ ] normal people/movement do not permanently occlude important regions;
- [ ] mount is stable;
- [ ] lighting variation is measured;
- [ ] person-detection feasibility is measured at the actual room-wide placement and entrance;
- [ ] optional owner-verification feasibility is measured at that placement, with insufficient face size/quality reported as unavailable rather than assumed reliable;
- [ ] camera placement complies with institutional/local rules.

Do not upload room geometry or imagery to GitHub.

### Capture-profile benchmark

Compare at minimum where camera capabilities allow:

- [ ] 4K candidate and highest useful resolution at approximately 10–15 fps; record unsupported modes explicitly when the camera lacks them;
- [ ] 1080p/15 fps;
- [ ] actual resolution, FPS, codec, and bitrate are recorded for each candidate;
- [ ] camera-native compressed format vs re-encode path;
- [ ] hardware-accelerated encode path where available;
- [ ] LAN throughput;
- [ ] capture-node CPU/GPU/VRAM;
- [ ] main-host CPU/GPU/VRAM;
- [ ] dropped frames;
- [ ] recording quality;
- [ ] person/entrance detection quality.

Choose defaults from measurements, not assumptions.

The synthetic profile core tests do not satisfy the following integration checks:

- [ ] run the selected real decoder on all compressed reference packets; verify independent inference cadence and actual resized image dimensions, including B-frame reordering and stream restart;
- [ ] compare durable recording codec/profile/quality before, during, and after changing viewer quality; record any discontinuities explicitly;
- [ ] count viewer-only codec processes, handles and memory before the first subscriber, with subscribers, and after the last leaves; confirm cleanup and bounded failure recovery;
- [ ] apply recording and viewer queue pressure separately; verify bounded memory, visible loss, and keyframe recovery without claiming continuous evidence;
- [ ] verify copy eligibility against actual codec configuration, container, timestamps and color metadata; unsupported copy/transcode paths remain unavailable;
- [ ] record only sanitized aggregate resource measurements; no deployment identifiers, room imagery, media payloads, or exact private network values enter GitHub.

## D. Source registry / mixed topology

Validate:

- [ ] 1 active source;
- [ ] 2 active sources;
- [ ] 3 active sources;
- [ ] 4 active sources;
- [ ] fifth activation rejected under default limit;
- [ ] mixed `local_uvc` + `remote_agent` works;
- [ ] source rename/role change works;
- [ ] detection profiles remain independent of source type;
- [ ] each local/remote source's admitted capture/recording/inference/viewer set
  comes from that source's inspected capabilities; a profile supported only by
  another camera/node is rejected without replacing the active configuration;
- [ ] removing one source does not corrupt recordings/events for others.

## E. Server ROI / movement

Per configured server source:

- [ ] ROI/polygon placement works;
- [ ] reference/calibration saves and can be replaced;
- [ ] small lighting changes do not trigger movement;
- [ ] person standing in front of server does not immediately become movement;
- [ ] partial occlusion clears without false critical event;
- [ ] controlled displacement/rotation triggers event;
- [ ] camera movement is distinguished from server-only movement where practical;
- [ ] one event can link evidence from other active sources.

## F. Camera tamper and source health

- [ ] move/rotate camera mount;
- [ ] cover/obstruct lens;
- [ ] disconnect USB;
- [ ] reconnect USB;
- [ ] interrupt agent process/network for remote source;
- [ ] meaningful health/tamper changes are visible/audited;
- [ ] trivial vibration does not flood critical alerts;
- [ ] known loss is never shown as healthy.

## G. Network interruption / backpressure and agent evidence protection

Remote-agent scenarios:

- [ ] LAN off ~10 seconds;
- [ ] LAN off ~2 minutes;
- [ ] switch/AP/network restart if safe;
- [ ] main ServerSentinel service restart;
- [ ] capture-node restart;
- [ ] bandwidth throttling/backpressure test in a controlled environment.

Ring-buffer configuration:

- [ ] owner can select **duration mode** and UI shows projected/actual disk usage;
- [ ] owner can select **capacity mode** and UI shows estimated effective duration;
- [ ] non-owner cannot change buffer mode/value;
- [ ] current bytes, protected-incident bytes, filesystem free space, and safety reserve are visible;
- [ ] unsafe values produce warning and are rejected before violating safety reserve;
- [ ] duration/capacity/profile admission verifies space for pinned T-10 plus T+10 capture simultaneously, estimated from bounded/negotiated bitrate and segment/container overhead with existing protected incidents, other filesystem use, and hard reserve; shared segments count once and only eligible ordinary data outside required pre-loss is reclaimable;
- [ ] a disposable filesystem/quota that fits only 10 minutes plus reserve causes configuration rejection; repeat with existing protected incidents and unrelated filesystem consumption removing post-loss headroom, without deleting unexpired evidence;
- [ ] a sufficient bounded-profile budget admits the setting and supports the complete window without crossing reserve; no new numeric reserve threshold is inferred from the test;
- [ ] runtime uncertainty or later loss of effective pre-loss coverage/post-loss headroom becomes degraded/warning with actual coverage/gaps rather than silently healthy.

Unexpected Main Server communication loss:

- [ ] agent pins the 10 minutes immediately before loss when available;
- [ ] agent continues local recording for 10 minutes after loss;
- [ ] resulting protected incident targets 20 minutes total;
- [ ] reconnect does not erase the protected incident;
- [ ] segment gaps/shortened protection are reported truthfully;
- [ ] protected incident has a 60-day agent-side expiry;
- [ ] expiry cleanup removes it automatically after 60 days (use test clock/accelerated retention harness rather than waiting 60 real days where available);
- [ ] ordinary ring-buffer pressure does not delete an unexpired protected incident;
- [ ] disk pressure produces explicit warning/hard-stop behavior before unsafe writes.

Critical preservation and lifecycle:

- [ ] an authenticated Main Server critical preserve request pins the requested available interval and reports partial coverage/gaps accurately;
- [ ] the Owner can inspect protected-incident bytes, coverage, and expiry timestamps;
- [ ] an explicit Owner manual delete can remove a protected incident before expiry and an unauthorized identity cannot delete it;
- [ ] eligible ordinary ring-buffer data is reclaimed before unexpired protected evidence, and safety reserve still blocks unsafe writes;
- [ ] configured dedicated-media mount loss/substitution refuses ring-buffer/incident writes with no root-filesystem fallback, including during post-loss capture.

Record:

- state transition;
- reconnect time;
- recording gaps;
- duplicate/missing media;
- queue/memory growth;
- agent buffer bytes;
- protected incident bytes/expiry;
- audit event;
- manual-intervention requirement if automatic recovery is unsafe.

## H. Clock synchronization

- [ ] main/capture node normally synchronize through NTP/chrony or equivalent;
- [ ] measured offset is visible/diagnosable;
- [ ] controlled excessive skew causes degraded state/warning;
- [ ] timeline does not silently present unreliable remote timestamps as exact;
- [ ] recovery clears degraded state appropriately.

## I. Live view from phone, Mac, and desktop

Local/private path:

- [ ] phone browser can open live dashboard when authorized;
- [ ] Mac browser can open live dashboard when authorized;
- [ ] desktop browser can open live dashboard when authorized;
- [ ] browser viewers obtain media only from the Main Server and never connect directly to `media-capture-agent`;
- [ ] a live URL copied to an unauthorized identity cannot retrieve or play media;
- [ ] 1-source layout usable;
- [ ] 2-source layout usable;
- [ ] 3–4 source grid usable where applicable;
- [ ] source/node health visible;
- [ ] selected camera expands cleanly;
- [ ] live start time measured;
- [ ] latency measured;
- [ ] near-real-time quality is evaluated with stability/reconnect prioritized over absolute minimum latency;
- [ ] reconnect works;
- [ ] adaptive quality works;
- [ ] one bad source does not hide health of others.

Demand-driven processing:

- [ ] no-viewer state does not perform unnecessary viewer-only transcoding;
- [ ] first viewer starts needed packaging/transcoding;
- [ ] multiple viewers remain bounded;
- [ ] viewer disconnect returns resources toward idle state.

## J. Tailscale / invitation visibility and authorization

Use test identities/accounts appropriate for the deployment. ServerSentinel does **not** modify Tailscale ACLs/Grants or store Tailscale administrative credentials; any policy administration remains outside the application and existing policy may remain unchanged.

### Uninvited ordinary Tailnet member

- [ ] if existing Tailnet policy makes the Main Server node visible/reachable, document that fact rather than claiming node invisibility;
- [ ] ServerSentinel invitation is still required before application data is served;
- [ ] unauthorized response is generic/non-branding where practical;
- [ ] no ServerSentinel product/version, API schema, health detail, camera names/counts, thumbnails, recording data, timeline data, or deployment metadata leaks through errors/alternate endpoints;
- [ ] LAN path cannot spoof trusted Tailscale identity headers.

### Invited user with `live:view` only

- [ ] can view current live streams;
- [ ] can view only current source health needed for live viewing;
- [ ] cannot list/play recordings;
- [ ] cannot access historical timeline/events;
- [ ] cannot access privileged settings.

### Invited user with `recordings:view` only

- [ ] can list/play recordings in browser when application authorization passes;
- [ ] can access historical timeline/events;
- [ ] does not gain live view unless separately granted;
- [ ] no official recording download/export control is present;
- [ ] playback URL copied to an unauthorized identity does not work.

### User with both

- [ ] live, browser playback, and historical timeline all work;
- [ ] cannot manage cameras/users/settings unless owner.

### Revocation

- [ ] app permission revoke blocks subsequent requests promptly;
- [ ] Tailnet membership alone remains insufficient for ServerSentinel application data;
- [ ] no Tailscale policy mutation is performed by ServerSentinel.

Do **not** claim invisibility from Tailnet Owners/Admins or infrastructure administrators, or node invisibility when existing Tailnet policy exposes the node.

## K. Manual/event recording

- [ ] manual recording start/stop;
- [ ] 20-minute maximum enforced;
- [ ] event recording includes configured 30 s pre / 120 s post when resource conditions permit;
- [ ] one event can contain multiple source recordings;
- [ ] manifests use source IDs, not fixed role filenames;
- [ ] playback source labels are correct;
- [ ] compressed pre-roll strategy remains bounded;
- [ ] no unnecessary long decoded-frame RAM history.

## L. Low light / detector-specific quality gating

Progressively degrade lighting/blur/visibility.

- [ ] quality transitions `sufficient -> degraded -> insufficient` appropriately;
- [ ] live/recording may continue when frames still exist;
- [ ] owner verification becomes `unknown/unavailable` before unreliable identity result;
- [ ] **person detection also becomes unknown/unavailable when its own quality prerequisites fail**;
- [ ] insufficient person quality is never displayed/stored as trustworthy `no person`;
- [ ] entrance/presence logic does not infer absence from skipped person inference;
- [ ] recovery uses suitable hysteresis;
- [ ] no automatic torch/light behavior exists.

## M. Video-only behavior

- [ ] the local capture path does not open microphone/audio devices or capture monitoring audio; MVP has no audio-enabling option;
- [ ] `media-capture-agent` does not request/open microphone devices;
- [ ] browser live playback contains no audio track in MVP;
- [ ] recordings contain no monitoring audio in MVP.

## N. Owner-only face verification

Use only the deployment owner's own enrollment during manual testing. Never upload enrollment/reference images or real-person result clips to GitHub.

- [ ] explicit biometric explanation;
- [ ] owner enroll/delete/re-enroll;
- [ ] poor enrollment image rejected/retried;
- [ ] template remains local and absent from logs/normal diagnostics;
- [ ] normal frontal/angle/distance variations tested;
- [ ] low-light/blur/partial occlusion tested;
- [ ] result includes quality/confidence;
- [ ] ambiguous input becomes `unknown`;
- [ ] no non-owner enrollment feature exists;
- [ ] verification and anonymous tracking do not create or retain persistent non-owner face-crop/template/embedding/profile libraries, whether named or anonymous; ordinary authorized recordings remain subject to recording retention and must not be used to build such libraries.

## O. Entrance / anonymous tracking / presence

Where room geometry supports entrance logic:

- [ ] owner entry/exit;
- [ ] anonymous person entry/exit;
- [ ] multiple people close together;
- [ ] partial occlusion;
- [ ] reversal/loiter near line does not spam events;
- [ ] unknown people receive no real names;
- [ ] no cross-camera biometric re-identification claim;

Presence safety applies even when entrance inference is unavailable:

- [ ] manual presence override wins;
- [ ] ambiguous/low-quality owner observation does not force presence;
- [ ] only `PRESENT` suppresses ordinary occupancy automation by default;
- [ ] repeat controlled server-movement and camera-tamper scenarios in each of `PRESENT`, `PROBABLY_PRESENT`, `ABSENT`, and `UNKNOWN`, including Owner manual overrides;
- [ ] in every case, verify the actual critical detection event, preserved recording/Agent incident evidence where configured, and configured immediate critical notifications; an armed indicator alone does not satisfy acceptance;
- [ ] `PRESENT` and manual overrides do not suppress any of those three outcomes; configured Slack receives the immediate notification, and dashboard/audit faults remain when Slack is disabled or delivery fails.

## P. Unified security timeline

Create a controlled scenario such as:

```text
Owner exits
Anonymous person enters
Server movement occurs
Camera disconnects
Anonymous person exits
```

- [ ] timestamps ordered correctly across local/remote sources;
- [ ] source attribution correct;
- [ ] linked recordings correct;
- [ ] confidence/quality shown where applicable;
- [ ] offline/gap states visible;
- [ ] system never labels the person culprit/thief/attacker.

## Q. Storage pressure / hard stop

Use a disposable/test volume.

Issue #21 unit/container scenarios cover temporary synthetic files, reserved
constructor recovery, starvation/cleanup/star races, audit failure, retention,
mock Slack and DST/rollback scheduling. They do not establish deployed volume,
real codec, configured Slack, browser playback or human authorization acceptance.
Keep the following deployment checks open; do not use production data for fills.

- [ ] metadata database and media use the expected filesystem, and configured
      journal/temp overhead safely covers recovery, cleanup and migrations;
- [ ] configured Slack receives one safe immediate critical alert and one daily
      aggregate; a failed/unconfigured channel leaves local/UI faults visible;
- [ ] slow/unavailable Slack does not block recording; full queues, pending
      shutdown/crash delivery and failed completion persistence remain visible;
- [ ] after deployment restart/DST change, summary sends at the configured local
      time without duplicate dispatch, and uncertain `pending` delivery is visible.

- [ ] retention deletes expired unstarred data;
- [ ] allocation/free-space pressure reclaims oldest eligible unstarred data;
- [ ] unrelated filesystem consumption affects admission;
- [ ] starred data not auto-deleted;
- [ ] `STORAGE_PRESSURE` suppresses specified ordinary/manual admission;
- [ ] bounded critical allowance never crosses hard reserve;
- [ ] `STORAGE_HARD_STOP` occurs before unsafe write;
- [ ] warnings/audit visible;
- [ ] recovery uses hysteresis.

Never intentionally fill a production filesystem to zero free bytes.

## R. Long-duration / performance

Run at least:

- [ ] 1 hour;
- [ ] 8 hours;
- [ ] 24 hours.

Record:

- source types/count;
- capture/record/view resolution/FPS/bitrate;
- detector inference cadence;
- main CPU/GPU/VRAM/memory;
- capture-node CPU/GPU/VRAM/memory;
- disk write rate;
- USB topology/bandwidth;
- LAN throughput;
- live-view latency;
- disconnect/reconnect count;
- dropped frames;
- service crashes;
- false health states.

Record separate performance results for 1, 2, 3, and 4 active sources, including a long-duration mixed-source run. If required hardware is unavailable, mark the affected acceptance cases unperformed rather than PASS. Final defaults come from these measurements.


## S. Main-host hardware integrity / recording-health self-test

### Hardware baseline and startup/daily comparison

Establish an Owner-approved baseline, then validate both startup and scheduled daily checks.

- [ ] CPU model/topology/signature data is captured where available;
- [ ] RAM slot/capacity/part/serial data is captured where available;
- [ ] NVMe/M.2 device model/serial/WWN-style identity/capacity is captured where available;
- [ ] HDD/recording-drive model/serial/WWN-style identity/capacity is captured where available;
- [ ] GPU model/GPU UUID/serial/PCI identity is captured where available;
- [ ] ServerSentinel startup triggers an integrity comparison;
- [ ] a running service performs the comparison at least once every 24 hours;
- [ ] results distinguish `OK`, `CHANGED`, `MISSING`, `NEW_DEVICE`, and `UNVERIFIABLE`;
- [ ] a missing/changed approved component does not silently update the baseline;
- [ ] only the Owner can approve a replacement/new baseline;
- [ ] Owner approval is audited;
- [ ] same-model replacement with no exposed stable unique identifier is reported as an identification limitation rather than falsely guaranteed;
- [ ] serials/UUIDs are redacted or hashed in normal operational logs and general diagnostics; raw identifiers remain absent from telemetry/public diagnostics/GitHub artifacts.

Use controlled inventory mocks for destructive/expensive substitution cases where physical replacement is impractical. Real hardware swaps are optional and must not damage production equipment.

### Recording-health daily self-test

- [ ] enabled sources have fresh frames or an explicit truthful offline/degraded state;
- [ ] recorder/encoder state is checked;
- [ ] configured recording root resolves to the expected filesystem/device;
- [ ] on a disposable test volume, missing/unmounted or substituted recording filesystems refuse recording and self-test media writes; no fallback directory is created or used on the root filesystem or another unintended filesystem, even while reporting degradation;
- [ ] writability, current free space, and safety reserve are checked;
- [ ] a bounded temporary media segment is written through the recording path;
- [ ] the segment is flushed/fsynced;
- [ ] the segment is reopened and container/duration/size/decode readability is validated as appropriate;
- [ ] self-test-owned temporary/partial media is deleted locally after success, write/read/decode failure, and cancellation;
- [ ] process interruption and reboot leave only bounded self-test artifacts, which are reconciled/cleaned at next startup before new self-test media is written;
- [ ] cleanup verifies the expected filesystem and self-test ownership and never deletes ordinary recordings or protected incidents;
- [ ] simulated missing/read-only storage or cleanup failure reports failure and blocks further self-test media writes until safe cleanup succeeds;
- [ ] leftover bytes count against storage admission/safety reserve, with no root-filesystem fallback or retained/uploaded diagnostic media;
- [ ] available SMART/NVMe health data is read and surfaced without unsupported lifetime prediction;
- [ ] a failed write/reopen/decode test creates a recording-health failure state;
- [ ] the self-test runs at least once every 24 hours.

### Immediate owner alerting

For each condition below, verify the system does not wait only for the 23:00 daily summary:

- [ ] approved CPU/RAM/NVMe/HDD/GPU becomes `CHANGED` or `MISSING`;
- [ ] expected recording device/mount is substituted or missing;
- [ ] recording-health write/reopen/decode fails;
- [ ] available SMART/NVMe health reports a material critical warning;
- [ ] `NEW_DEVICE`/`UNVERIFIABLE` creates at least a visible warning and escalates when recording integrity cannot be assured;
- [ ] Slack receives the immediate alert when Slack is configured;
- [ ] when Slack is disabled, dashboard/audit fault state remains visible.

Do not upload hardware serials, local mount identifiers, real temporary test media, or private infrastructure details to GitHub.


## T. No telemetry / developer reporting

- [ ] inspect Main/Agent/Web dependency inventories, installed packages, and dashboard bundles for analytics, advertising/tracking SDKs, telemetry, and developer-operated crash upload; the prohibition includes opt-in features;
- [ ] inspect controlled startup, ordinary operation, error handling, and configuration paths using browser request inspection/local network observation; no prohibited reporting occurs;
- [ ] explicitly configured product integrations are checked separately and never excuse unrelated reporting; no telemetry feature is introduced without a new explicit Owner decision and ADR changing PRIV-003;
- [ ] traces and deployment identifiers remain local; publish only sanitized pass/fail results, never raw monitoring data, secrets, or private network logs.

### Issue #12 foundation acceptance (pending physical execution)

The synthetic CI tests do not complete these checks. On an isolated Capture Node:

- [ ] Build/verify the versioned Agent artifact and run `--check` as the dedicated
  non-root account; runtime/media directories are outside source/install trees.
- [ ] Inspect the generated `media-capture-agent.service`, its dedicated UID,
  explicit video-node allowlist and empty capabilities; account/device permissions
  remain narrowly configured. Verify process command line and unit name (Linux
  kernel `comm` truncates names longer than 15 visible bytes).
- [ ] Confirm `--check` succeeds both outside and inside the generated systemd
  mount namespace when the media root is a subdirectory of an approved mount.
  A bind of another backing directory on the same device must be rejected.
- [ ] Record the Owner-approved filesystem UUID only in the private deployment
  configuration. On a disposable volume, replace the filesystem while reusing
  the mount path and device name, restart the Agent, and verify `--check` and
  new writes refuse the replacement rather than treating it as the approved
  storage.
- [ ] Start/stop through systemd after #11/#13/#14 integration; verify no GUI/tray,
  no microphone opens, no audio setting and no inbound listener/SSH dependency.
- [ ] Unplug an approved UVC camera: source becomes offline while node heartbeat
  continues. Reconnect obeys stable identity and ambiguous-device approval.
- [ ] Inject excessive clock offset, uncertainty and wall-clock steps using mocks
  or an isolated test process; timing degradation remains visible and is not
  interpreted as reliable event ordering.
- [ ] Use an isolated test filesystem to exercise mount disappearance, replacement,
  read-only state and reserve pressure at startup and runtime. Check descriptor
  pinning and no fallback-directory creation without altering production mounts.
- [ ] Restart at storage hard stop: inventory and authorized cleanup remain
  possible; new allocations and installer `--check` fail until reserve is restored.
- [ ] Confirm network observation after authenticated transport integration shows
  only Owner-configured Main communication, including error/reconnect paths.

Publish only pass/fail summaries; keep configs, mount identity, host identifiers,
credentials and captured media private.

## U. Privacy-safe diagnostic export / support bundle

Run this only on the intended Main Server using synthetic, non-production diagnostic inputs. Do not upload, commit, attach, or paste the generated bundle, its manifest, private deployment data, raw identifiers, monitoring media, credentials, or biometric material into GitHub.

- [ ] an Owner initiates a diagnostic export from the deployed application; no background, scheduled, or error path creates or transfers a bundle without that explicit action;
- [ ] an uninvited client, invited non-Owner identity, and capture-node credential each fail to create, list, retrieve, or select media for an export through every browser and direct API/copied-URL path; the response reveals no bundle metadata or media;
- [ ] before export, the bundle remains deployment-local; observe the controlled export operation locally and verify that it does not automatically upload/share to a developer or third-party endpoint;
- [ ] use harmless synthetic sentinel inputs to verify credentials, pairing secrets, private keys, and sensitive headers are excluded;
- [ ] verify Owner biometric templates/embeddings are excluded even from an explicitly initiated export, and no selected export authorizes external biometric processing/storage;
- [ ] verify raw hardware serials/UUIDs are absent or redacted/hashed, while the manifest reports only safe categories and exclusion reasons;
- [ ] verify raw monitoring media is absent by default and can be included only after an additional explicit Owner selection; do not use real monitoring media for this check;
- [ ] record only sanitized PASS/FAIL and aggregate results locally; do not retain the test bundle after the local verification policy permits deletion.

## V. Deployed Main Server install / update / rollback lifecycle

Issue #47 remains open. The synthetic CI tests do not complete these checks: they require an actual deployed Main Ubuntu Server installed from a versioned artifact or the documented Docker Compose path, kept separate from any development checkout. Use a disposable host and disposable storage; never run the destructive cases against a production deployment. This section covers Main Server lifecycle data only: capture-agent protected incidents belong to Issue #16 and no capture node is part of this section's environment, so record them as not applicable here and verify their survival in the Issue #28 full-deployment acceptance. Do not commit, attach, or paste release artifacts, private deployment paths, hostnames/IPs, listener addresses, configuration values, credentials, mount/device identities, hardware identifiers, audit contents, or recorded media into GitHub.

- [ ] install the versioned artifact / documented Compose path on a clean Main Ubuntu host without relying on a mutable development checkout; the service runs under its intended dedicated non-root runtime identity;
- [ ] configuration and credentials resolve outside the release checkout, remain admin-managed and runtime-readable but not writable; state/database, recordings, and audit logs use their documented separate mutable locations and are writable only by the intended runtime account;
- [ ] the human listener stays private-by-default behind the intended trusted-proxy boundary after install; it is not exposed to the public Internet and the proxy cannot be bypassed from an ordinary LAN client;
- [ ] before updating, seed a non-vacuous baseline: at least one ordinary recording, one starred recording, one registered camera source, several audit records, and synthetic Owner/invitation records with independent `live:view` / `recordings:view` grants plus a revoked test invitation, so that the comparisons below cannot pass on empty inventories;
- [ ] record a pre-update inventory (version/commit, recording count and sizes, starred recordings, audit record count with oldest/newest timestamps, camera source registrations, Owner presence, and nonidentifying invitation logical IDs with their permission/revocation state, plus Owner-approved hardware baseline) in local sanitized notes only; never record principal identity values, credentials, invitation values, or permission-bearing URLs, and mark each inventory that is empty or not applicable as such instead of counting it as preserved;
- [ ] counts, sizes and boundary timestamps alone cannot detect replaced content, so also record content evidence for the same baseline: each seeded recording's stable logical ID with its locally computed file digest, container duration and a decodable playback sample, and the audit rows' per-row digests or an equivalent chained digest over the whole retained set, not only the first and last rows; keep the digests and logical IDs deployment-local;
- [ ] update to a newer version through the documented lifecycle; the reported version changes and every item of the pre-update inventory survives except for intended, documented migrations;
- [ ] after the update, re-verify the content evidence, not just the counts: the same recording logical IDs are present with unchanged digests, durations and decodable playback, and the audit digests match row for row apart from rows the update itself legitimately appended, each of which is accounted for; a documented migration that intentionally rewrites stored bytes states in advance which logical IDs it rewrites and how the new content is re-verified, and any other digest change is a failure;
- [ ] when the previous version can safely read the retained state, roll back through the documented lifecycle; the service starts and the same inventory is still intact — no recording, starred recording, or audit record is deleted, truncated, or silently rewritten, proven by the same logical IDs, digests, durations, decodable playback samples and audit row digests rather than by matching counts and boundary timestamps;
- [ ] when rolled-back code cannot safely read forward-migrated state, startup refuses and reports the incompatibility truthfully instead of destructively downgrading or discarding data; follow and record the documented recovery path, then compare the same recorded inventory after it restores a startable version/state;
- [ ] repeat update and rollback with an in-progress recording and with storage near the safety reserve; no partial media is left counted as healthy, and the reserve is still honored afterwards;
- [ ] on a disposable volume, safely simulate a missing/unmounted or substituted runtime mount and restart: install, update, and rollback refuse unsafe writes, report an explicit failed/degraded result, and never create or use a silent root-filesystem fallback directory;
- [ ] start with missing or unreadable deployment configuration: the service fails closed with an actionable error and does not invent defaults for storage roots, listener boundary, or secrets;
- [ ] after update and after every rollback that starts successfully, the startup hardware-integrity comparison and the recording-health self-test run again; after a safe rollback refusal, run them only after the documented recovery restores a startable version/state. A changed approved component still requires Owner approval and still produces the immediate Owner notification of section S;
- [ ] record only sanitized PASS/FAIL results and version identifiers locally; keep deployment paths, host identity, configuration, audit contents, recording and audit digests, logical IDs, and media private.

## W. First-run setup wizard / initial configuration

Issue #48 remains open. The synthetic CI and browser integration tests do not complete these checks: they require a freshly installed deployed Main Server with no prior state, reached from a real browser over the intended private access path. Use a disposable deployment and synthetic test identities. Do not publish deployment URLs/hostnames, invitation values, secrets, raw hardware identifiers, biometric material, or monitoring media.

- [ ] on a deployment with no existing state, the first-run wizard is reachable only through the intended private listener/trusted-proxy boundary; an unauthenticated or uninvited ordinary network client cannot read or complete wizard steps and learns nothing about the deployment beyond a generic denial;
- [ ] Owner bootstrap creates exactly one Owner: with two browsers/tabs submitting the bootstrap step concurrently, and with a resubmitted/replayed bootstrap request, exactly one Owner exists afterwards and later attempts are refused rather than creating a second Owner or overwriting the first;
- [ ] after Owner creation, re-opening the wizard does not re-run bootstrap, reset the deployment, or let an unauthenticated visitor claim ownership;
- [ ] as the deployment Owner, run the wizard through Welcome, owner bootstrap, storage, hardware baseline / recorder self-check, locale/time, sources, profiles, optional verification/Slack, and private human-access steps;
- [ ] interrupt the wizard at each step (close the browser, restart the service, reboot the host); it resumes at the same step, previously completed steps are preserved, and no step silently repeats Owner creation;
- [ ] the storage step verifies the configured recording root's mount, write permission, free space, and safety reserve; on a disposable volume, a missing/unmounted or substituted filesystem is refused with a truthful error and no root-filesystem fallback is created;
- [ ] the hardware-baseline / recorder self-check step records the Owner-approved baseline, reports unavailable identifiers as `UNVERIFIABLE` rather than as a guarantee, and audits the Owner approval;
- [ ] the locale/time step records time configuration, and excessive clock offset/uncertainty stays visible instead of being presented as reliable event ordering;
- [ ] the source and profile steps complete with zero sources and with 1–4 configured sources; no step assumes a fixed two-camera topology, and absent capture hardware yields a truthful pending/unavailable state rather than a false ready state;
- [ ] skip the optional Owner face verification and Slack steps; skipping leaves them disabled, unavailable dependent features remain explicitly pending rather than appearing complete, and completing them never enrolls a non-owner identity or enables audio capture;
- [ ] the private-access step presents network-level private/Tailscale reachability and ServerSentinel invitation/permission as two independent approvals; Tailnet membership alone never becomes an application invitation, and the wizard neither requests Tailscale administrative credentials nor offers to modify ACLs/Grants;
- [ ] invitations created in the wizard grant `live:view` and `recordings:view` independently, and a `live:view`-only test identity still cannot reach recordings or the historical timeline after the wizard finishes;
- [ ] wizard screens, summaries, generated diagnostics, and service logs expose no settings secrets, pairing values, raw hardware serials/UUIDs, or biometric data;
- [ ] the wizard shell stays usable while unfinished areas remain pending, and completing it leaves the deployment in the documented post-setup state;
- [ ] record only sanitized PASS/FAIL results locally; keep deployment identifiers, invitation values, and any captured frames private.

## X. Security / admin audit log and 90-day retention

Issue #50 remains open. The synthetic CI tests do not complete these checks: they require the deployment-local audit store of a running Main Server, real service restarts, and a clock advanced across the retention boundary. Use a disposable Main Server database, synthetic test actors, synthetic logical target IDs, and synthetic sentinel values; drive retention with an accelerated/test clock or back-dated synthetic audit rows, and never back-date or delete production audit data. Seed the audit fixtures independently of the other subsystems, so that these checks run on the Issue #50 audit store together with whatever recording and retention data the deployment already has. Items naming the unified factual timeline (#26) or capture-agent protected incidents (#16) apply only where those capabilities are already deployed; where they are not, record them as not applicable — never PASS — and repeat the full comparison during the Issue #28 full-deployment acceptance. Do not enter or publish real secrets, biometric material, hardware serials/UUIDs, private network values, audit contents, actor identities, or monitoring media.

- [ ] approve a hardware baseline as the deployment Owner and verify one fixed-action success record with a logical target ID;
- [ ] change a security/admin setting and revoke one test camera, source, or capture node; each record carries actor category, fixed action, target kind, logical target ID, UTC time, and outcome, and nothing more identifying than that;
- [ ] invitation, permission grant/change/revocation, and authorization denials are recorded with their outcome; attempt an Owner-only operation as an invited non-owner principal and verify the mutation does not run while the denied audit outcome is retained;
- [ ] induce a safe synthetic mutation failure and verify a failed audit outcome is recorded without submitted values or exception text;
- [ ] using synthetic sentinel inputs, verify records contain no credentials, pairing secrets, private keys, sensitive headers, raw biometric templates/embeddings, raw hardware serials/UUIDs, or raw media;
- [ ] inspect deployed database permissions and confirm the audit store stays deployment-local with no upload/reporting path; any inclusion in a diagnostic export follows the explicit-Owner-action and redaction rules of section U;
- [ ] audit entries state observed actions and outcomes without asserting culprit, guilt, or causality; where the unified factual timeline is deployed, the audit log stays separate from it and the timeline gains no admin/security detail through it;
- [ ] server-side authorization restricts audit reading to Owner-level access: a non-owner identity with `live:view`, `recordings:view`, or both cannot read, alter, or delete audit records, including through copied URLs, and a capture-node credential cannot reach the audit routes at all;
- [ ] confirm the configured audit retention default is 90 days and is independent of the 20-day recording retention: changing one does not change the other;
- [ ] run retention with a test clock just past 90 days: only expired audit rows are removed while boundary and newer rows remain; run cleanup twice and confirm the second run is idempotent;
- [ ] with the deployment near its storage pressure/hard-stop thresholds, confirm audit writes and retention cleanup are admitted by the same storage reservation: a refused admission fails visibly and records no row instead of spending the hard filesystem reserve;
- [ ] immediately before and after cleanup, compare every non-audit lifecycle inventory the deployment actually has — recording inventory, starred recordings, protected incidents, and their retention/expiry times, plus factual timeline events and capture-agent protected incidents wherever those capabilities are deployed: cleanup applies only to expired audit rows and changes no recording or protected-incident lifecycle; list every inventory that was not yet available instead of reporting it as unchanged;
- [ ] interrupt cleanup (stop the service mid-run, simulate a read-only or full audit volume): the store stays consistent, the failure is reported as a visible fault instead of a silent success, and the next run completes without losing unexpired rows;
- [ ] audit writes survive service restart and are not lost by an unclean shutdown; a security-sensitive mutation and its durable audit record commit together, so a failed audit write fails or rolls back the mutation and surfaces a visible fault rather than silently dropping history;
- [ ] record only sanitized PASS/FAIL counts and timings locally; keep audit exports, actor identities, and deployment values private.

## Y. GitHub review-gate enforcement

Issue #4 remains open. The offline tests do not complete these checks. Follow
`docs/REVIEW_GATE_SETUP.md` after Owner App registration and trusted publisher
implementation. Use harmless synthetic documentation PRs against an isolated
test branch and an equivalent strict rule before activating protection on `main`.
The candidate generator targets `main` only; review any test-branch adaptation
explicitly. Do not alter production protection to make a negative test pass.

- [ ] record the App ID/slug/installation, immutable trusted publisher revision, applied rules, and both required check names with expected App sources;
- [ ] missing either review blocks merge; pending, failed, cancelled, unavailable, skipped and neutral reviewer outcomes each produce a blocking/pending App check (never a skipped/neutral check conclusion, which GitHub accepts);
- [ ] both trusted reviews of the exact current repository/PR/HEAD/base/merge-base/diff allow merge only after independent CI and thread gates pass;
- [ ] push a new PR HEAD and confirm old reviews cannot permit merge;
- [ ] advance the base without changing the PR HEAD and attempt merge immediately, including before the publisher handles the base update; strict protection blocks it;
- [ ] repeat base advancement with a new base already in the PR HEAD's ancestry: checks only on the old test-merge SHA cannot satisfy the new merge context, and no same-name success exists on PR HEAD;
- [ ] check targets are the current GitHub test-merge commit with the pinned base/head parents; missing/stale merge refs block publication;
- [ ] incorporate the new base into the PR, rerun both reviewers, and confirm only the new current context becomes eligible;
- [ ] a same-repository test workflow publishes the identical check names with its ordinary `GITHUB_TOKEN`; even a success from GitHub Actions cannot satisfy the dedicated-App requirement;
- [ ] a same-name commit status and a check from a different synthetic test App cannot satisfy the requirement;
- [ ] copied successful receipt JSON, a forged `Reviewed commit` comment, and a wrong PR/repository/base/diff receipt fail;
- [ ] a newer pending/failed authoritative attempt cannot be hidden by an older successful check; out-of-order completion cannot re-enable stale evidence;
- [ ] fork review completes through the trusted path; fork/same-repository PR code never receives reviewer credentials, the App key or publisher token;
- [ ] a PR retarget, base change during either review, missing API page, provider/API error, malformed receipt and unavailable publisher each fail closed;
- [ ] inspect the App's selected-repository grant and verify the publisher cannot alter source, workflows, branch protection, collaborators or repository administration;
- [ ] demonstrate recovery from a stopped publisher without disabling protection, changing expected issuers or adding bypass actors;
- [ ] record public test PR/run/check IDs, non-secret context digests, rule snapshots and observed GitHub merge refusals, then re-read the production rule after activation.

Never use a real secret as a fixture or publish an App key/token, reviewer token,
raw private API response, or monitoring data. Cleanup only the identified
synthetic test branches/PRs; no production data or unrelated rule deletion.

## Issue #20 — Target Main detector acceptance (pending)

- On the target Main Server, run the generated motion workload for 1–4 sources; measure CPU, resident memory, cadence, drops, evaluation latency and sustained health/recording continuity. Record approved per-source budgets without exporting host identifiers.
- Before any person model is loaded, verify exact implementation/runtime/weights licenses, immutable versions, local artifact SHA-256 and the complete dependency notices. Confirm no runtime downloads, alternative-model fallback, reporting or unapproved outbound attempts on normal and failure paths.
- Benchmark the accepted person backend on CPU; GPU is optional and separately measured. External benchmark media stays local under its terms and is never committed or attached to GitHub/CI. No real-model accuracy or target-host performance was verified by synthetic unit tests.
- Stop/delay inference, inject quality loss, stale frames and a wedged plugin in the isolated worker: result must become unknown, loss/throttling remain visible, and capture/recording/health/storage-safety work must continue. Verify the production watchdog/resource limits separately; the primitive cannot forcibly interrupt a native call.
