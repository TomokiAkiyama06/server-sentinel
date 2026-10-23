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
├── presence/
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

Stable Main Server releases use a checksummed versioned archive containing the
reviewed application, lockfile, license material, and offline wheelhouse. The
native installer stages immutable per-version environments, validates private
deployment configuration and its existing pinned runtime filesystem as the
dedicated non-root account, then atomically switches `current`/`previous` release
pointers. Failed service activation restores the prior pointer and attempts to
restart it. Configuration, state, recordings, and audit data remain outside both
the checkout and install tree. The systemd launcher keeps the human listener on
loopback and grants write access only to the configured state, recording and
audit directories, not to the runtime root itself. A
`Type=notify` unit does not complete activation until database migration,
application lifespan startup, and listener creation succeed. Runtime
subdirectories are resolved and must remain contained on the approved runtime
filesystem, which is pinned by its Owner-approved filesystem UUID; Linux
major/minor device numbers only corroborate that identity because a replaced or
reformatted disk can reuse them and a reboot can renumber the same disk. While
the UUID resolves to the device of the runtime root and of the mounted mount
point (not the root filesystem's), a recorded pair with the same major and
another minor is reported as stale (value-free launcher warning, Owner notice
`recording_device_numbers_changed`), not refused, when it rests only on
hardware disks (a partition judged by its parent disk, a dm/md device by its
sysfs `slaves/`, recursively, every leaf disk with a sysfs `device` link to
its bus device); a changed major, a loop/nbd/ublk/zram/ram disk or a mapping
on one, or a device without a readable sysfs entry is still refused, and a
device-mapper device only passes when the recorded one was device-mapper too
(Issue #321). Deployment configuration is administrator-owned
and runtime-readable but not runtime-writable, and is refused inside the
installation tree, inside the runtime-writable data tree, or under any
directory path component the administrator does not control. Both release pointers and the service unit move
inside one guarded transaction under a service-global lock, and each recovery
step is attempted independently. Root-only environment construction uses an
isolated, root-controlled Python interpreter from a fixed working directory and
sanitized environment. The native lifecycle is the only implemented Main Server
deployment path (ADR-0005, `REQUIREMENTS.md` DIST-005/DIST-006). Exact commands
and limitations are in `server/docs/DEPLOYMENT.md`.

No Docker Compose path is currently implemented or advertised. A future Compose
path must provide the same versioned update/rollback, external runtime mount,
dedicated identity, missing-mount refusal, and private-listener guarantees.
`media-capture-agent` is intended to run natively as a systemd service so
UVC/udev/hotplug handling does not require a privileged container.

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
A negotiated profile that differs from the requested one (driver-adjusted
size, FourCC or frame rate) is recorded and reported `degraded`, never `online`.
One physical camera is approved for at most one enabled local source (cameras
that concurrently share one serial are told apart by exact live-instance
evidence, so each twin can be mapped to its own source); a
conflicting approval is refused, and a pre-existing duplicate makes every
conflicting source `manual_intervention_required` rather than letting startup
order decide.
Until the Owner Web UI exists, `local_uvc` sources are created and cameras
approved with the local command `python -m app.cameras.uvc.admin_cli
sources|candidates|create-source|approve --config <deployment.json>` (Owner
decision D3, 2026-10-16): the `bootstrap_cli` trust model (service account,
never root, the pinned existing database of exactly the current schema, no
WebAuthn step-up), one confirmation word read from `/dev/tty` per audited
`OwnerAdministration.create_source` / `approve_uvc` operation (actor `owner`,
the source's logical UUID only), and refusal (`service_running`) while any
other process of the service account holds the application database open; the
change applies when the service starts. Cameras are listed only by a hashed
live-instance label, USB vendor:product ids, serial `present`/`absent`/`shared`
and formats, never a serial or path. An offline approval is refused for a
camera without a serial or whose serial is not unique, because stored
evidence could not identify it after the restart.
Unsupported multi-planar capture or codec/bitrate controls fail explicitly.
An open capture that delivers no frame for the configured stall window
(`frame_stall_seconds`, never shorter than 10 negotiated frame intervals) is
reported `degraded` with the fixed reason `video_frame_stalled`, never
`online`; only a delivered frame returns it to `online`. The descriptor stays
open during that window (a transient stall neither re-enumerates the device nor
ends a live weak binding); a stall lasting `frame_stall_reopen_seconds` closes
the capture (`offline`) and reopens it through the normal identity path. The
same stall check also runs from a supervisor watchdog thread, so a worker
blocked inside a kernel or storage call cannot keep a stalled source `online`,
and past `frame_stall_reopen_seconds` it reports `offline`
(`video_capture_failed`) with a reopen request; the watchdog never opens,
closes or rebinds a device itself, and the worker closes and reopens through
the identity path when it returns (a frame it returns with is discarded). The
stall age is re-checked under the transition lock, so a frame delivered after
the watchdog's snapshot is never overwritten. The watchdog keeps checking a
worker whose stop or supervisor shutdown timed out until that worker's thread
exits, so a worker still blocked after a failed runtime stop is not left
`online`. A transient stall keeps the
recorded negotiated profile. Health writes are coalesced per source and run
outside the transition lock; while a newer state is not yet durable the source
is reported unpersisted.
A stall is capture health, not scene evidence, and is never reported as an
empty scene. While a capture is live the full device scan runs at most every
`presence_scan_seconds`, counted from the previous scan's completion so a slow
scan does not trigger another after every frame (an unplug surfaces through
the open descriptor); a
scan with probe failures that no longer lists the bound device is treated as
inconclusive, not as an unplug. A closed capture always rescans before binding
and the post-open identity re-verification is unchanged.
Source workers, Owner management and the preview frame sink are internal
interfaces and no unauthenticated preview route is added. The backend lifespan
starts one worker per deployment-configured `local_uvc` source (`local_uvc`
deployment object, 1 to 4 registry UUIDs, no physical evidence) after storage
migration/admission and stops them, with bounded joins, before the monitoring
runtime stops. The workers stop in parallel under one total join bound,
`join_timeout_seconds` (default 10 s, configurable 0.1–60 s), which covers a
worker's device teardown (up to 5.5 s observed on a real C960 after an unplug)
plus `HEALTH_SETTLE_SECONDS` (1 s) for its offline health write; a worker
still alive at the bound stays watched, is never reported `online`, and the
stop is `stop_failed`. After the workers are joined the supervisor joins the
frame-progress watchdog with at least 1 s of its own, even when the worker
joins used up the shared bound; a watchdog still inside a check after that
join makes the close fail, so the stop is `stop_failed` and the adapter is not
closed under that check. A successful close leaves no worker or watchdog
thread that could still call into the adapter. A `stop_failed` runtime retries
on a later stop: once no worker or watchdog is left it closes the adapter
(a watchdog-only failure then ends `stopped`; a worker cleanup failure stays
`stop_failed` on every retry, even when that exited worker was already removed
while another one was still hung, because the supervisor keeps that failure
sticky). `join_timeout_seconds` may not be shorter than
`frame_stall_seconds`, so the watchdog can make a blocked worker's lowered
health durable before the stop releases the pinned database. Because a slow
profile widens the effective stall window beyond that bound, a stop whose
workers outlived the join also lowers each such source to `offline`
(`capture_service_stopping`) itself and waits at most 1 s for that row to be
durable before it releases the pin; the row is fenced `offline` even when the
source's transition lock cannot be taken within that bound, no later `online`
can override it, such a worker never reports `online` again, a write that does
not finish leaves the source reported unpersisted, and an incomplete fence is
counted (`health_fence_incomplete`) and logged (the stop is `stop_failed`
either way). While a fenced source's health writer is still busy at that
bound (an earlier `online` write may still commit), the stop keeps the
database pin (`health_fence_pin_held`) instead of refusing the fenced
`offline` queued behind it, and the writer releases the pin as soon as no
fenced write is in flight; the stop itself does not wait longer. The same
applies to a source whose worker was joined: a handed-off health write (for
example a watchdog `degraded`) still stalled when the stop releases the pin
keeps it, so the closing `offline` staged behind that write is not refused. A write that
never finishes before process exit can leave the row `online` until the next
start, which writes it `offline` before any capture opens. Camera-health
transitions reach the optional health sink only through a bounded, coalescing
queue drained by one delivery thread, never on a capture worker or the
watchdog; a sink call stalled past 5 s is reported (`health_sink_stalled`) and
degrades the capture service state. A worker's stop waits (inside its join
bound) until its close transition has been handed to that queue, so the stop's
final sink settle cannot miss it. If the delivery thread cannot be started the
events stay queued, are reported as `health_sink_undeliverable`, degrade the
service and are retried on the next event, status read or stop; the same holds
for a source controller's own handoff thread, whose queued events a stop hands
over itself when that thread still cannot start. Missing configuration is the explicit `unconfigured` state;
configuration without admitted storage, including a monitoring runtime whose
startup storage open failed or an admission refused while pinning the database at start, is `storage_unadmitted` (retryable, nothing opened) and never captures until
storage is admitted again. The application capture-service snapshot follows the live runtime status, so a later worker or storage fault is never left reported as `running`. Every later capture-driven registry/approval write is admitted by the Main storage policy like an audit write; a refused admission stops that capture visibly and retries, never writes past the hard reserve; the camera transition is still recorded in memory and the capture service reports `degraded` while health cannot be persisted. The runtime opens only the database file pinned under that admission (a held descriptor, so inode reuse by a replacement cannot pass the identity check) and never creates one, so a lost or replaced filesystem after startup cannot yield a fallback database; a registry read failure while a camera is live is reported as capture loss and degrades the service until polling succeeds. A cancelled or failed lifespan startup stops started workers; a cancelled shutdown invalidates the preview and still completes the bounded capture stop and remaining cleanup before re-raising. Capture-service state is reported separately from each source's
registry camera health, so an unplugged camera is `offline` while the service
keeps running. Frames feed a bounded latest-frame preview hub that retains
nothing without live viewer demand and drops its retained frame on any non-online camera transition; reading it requires a
`LiveViewerSessions` session bound to the caller's human access session, whose
validator re-checks on every open and read that the human session is still
valid (not invalidated, expired or on a revoked credential) and that the
principal still holds `live:view` at the bound revision. See `server/app/cameras/uvc/README.md`.

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

### 5.3.1 Agent UVC capture adapter

`agent/media_capture_agent/uvc_capture.py` implements the Agent `Capture`
interface for 1–4 approved local UVC sources. Identity/discovery rules are a
standalone port of the Main local adapter (§4): only a unique serial reconnects
automatically, duplicate serials and every non-serial model match require Owner
re-approval, and a durable approval/ambiguity latch plus active-session marker
under the private `runtime_root` makes an unclean exit require re-approval.
Discovery with any unreadable video node never binds a camera
(`discovery_failed`). Two sources resolving to one device both require Owner
re-approval.

Capture runs one bounded subprocess pipeline per bound source behind an
injectable launcher. The production launcher executes an operator-installed,
root-controlled `gst-launch-1.0` restricted to `v4l2src ! image/jpeg,<explicit
profile> ! fdsink fd=1`; the V4L2 descriptor opened and identity-rechecked by the
Agent is passed to the child (`device=/proc/self/fd/N`) instead of a
`/dev/videoN` path. Because GStreamer's `video4linux2` plugin opens every
`/dev/video*` node read-write while it initializes (a device probe no option
disables), the child is started through an unprivileged Landlock helper
(`uvc_sandbox.py`) that denies all filesystem access except read/execute of
system libraries, the executable and the two plugin files, and read/write/ioctl
of the one approved device inode (plus TCP bind/connect where the kernel's
Landlock ABI supports it); every other video node, `/dev`, `/sys`, `/run`, home
and runtime directories are unreachable. Only `coreelements` and `video4linux2`
are loaded (`--gst-plugin-load`, empty plugin search paths, registry cache
disabled, no `gst-plugin-scanner`), so no audio plugin is ever loaded. Without
Landlock the launcher refuses to run (fail closed). The helper file and the
Python interpreter that runs it are checked like the executable and plugins
(root-owned, not group/world writable, including parent directories) at every
start, and the resolved interpreter path is executed. From the installed zipapp
release the helper is the root-installed artifact file itself (its entry point
dispatches a fixed `--uvc-sandbox` argument to the stdlib-only helper before any
other agent module is imported), because a path inside the archive can be
neither trust-checked nor executed. Residual limits: on
Landlock ABI 4 ioctls on already reachable files are not restricted (ABI 5+
limits device ioctls to the approved inode), abstract UNIX socket and signal
scoping needs ABI 6+, and Landlock does not control UDP or connecting to a
pathname UNIX socket; plugin selection is enforced by the fixed argv and
environment, not by the kernel, because `/usr` stays readable. The child gets a minimal
environment, its own process group, no stdin, discarded stderr, and is
terminated with SIGTERM then SIGKILL of the whole group before reaping. MJPEG output is split structurally into complete
JPEG frames with a per-frame byte bound and queued in a bounded drop-oldest queue.
Because `fdsink` does not keep V4L2 buffer boundaries, bytes after an EOI that
precede the next SOI are skipped as padding up to the negotiated profile's raw
buffer size (`width * height * 2`, clamped to 4 KiB–32 MiB; Issue #305: some
cameras hand over a full-size buffer whose JPEG is followed by non-JPEG padding).
Skipped bytes are discarded as they are read, so the bound does not grow the
parser's memory. A gap beyond the bound without an SOI, and any structural
error after an SOI (including an SOI found inside padding), is a malformed stream:
the pipeline is torn down and relaunched with backoff, and no guessed frame is
emitted.
Before starting a pipeline the Agent checks the explicit profile against the MJPEG
frame sizes and intervals the opened approved node advertises (read-only
`VIDIOC_ENUM_FMT`/`ENUM_FRAMESIZES`/`ENUM_FRAMEINTERVALS` on that descriptor only,
discrete/stepwise/continuous; an offered rate within 1 % satisfies the requested
fps and is then requested exactly, e.g. 30000/1001 for 30). A profile not offered
is a stable `capture_unsupported` with no pipeline and no backoff relaunch until
the device evidence changes (e.g. replug) or the Owner re-approves. While that
verdict holds, the approved binding is kept only as long as discovery returns the
identical evidence (same kernel device instance), so a serial-less camera stays
`capture_unsupported` instead of becoming an ambiguous reconnect; it never
authorizes a launch, and a replug follows the normal identity rules (a serial-less
camera then needs Owner re-approval). A driver that
does not implement the enumeration, or advertises a mode it then refuses, is still
caught by pipeline negotiation (`capture_failed`). The check is not identity
evidence.

Per-source health: `manual_intervention_required` (`owner_approval_required`,
`identity_ambiguous`, `approval_state_unavailable`); `offline` (`camera_missing`,
`capture_failed`, `capture_unsupported`, `capture_cleanup_failed`,
`discovery_failed`); `degraded` (`capture_starting`, `capture_overloaded`);
`online` (`video_ready`) only while frames actually arrive without recent drops.
Startup/stall timeouts, malformed streams and pipeline exits retry with bounded
exponential backoff; a pipeline that cannot be reaped blocks relaunch and keeps
the recovery marker armed, and later polls retry reaping without waiting the full
stop bound so heartbeats are not delayed; teardowns within one poll share one
stop bound. The process-table check that proves the group gone is itself bounded
by that stop bound (it runs off the tick thread, so a stalled `/proc` listing or
read cannot overrun it; at most one check per pipeline is outstanding, and a
retry-only poll only polls an outstanding check instead of waiting for it); a check
that cannot finish in time counts as not reaped. Discovery scans and the capture-node
open/close run off the tick thread and share one `device_timeout` per poll, so
the heartbeat is delayed by at most `device_timeout + stop_timeout` regardless
of how many sources hang; a hung driver call yields
`discovery_failed`/`capture_failed` instead of stopping the heartbeat, starts no
additional worker while still blocked, and a late descriptor is closed unused.
If no close worker can start, the descriptor is retained for a bounded retry and
the source reports `capture_cleanup_failed` instead of the failure escaping; a
close that started but exceeded the bound also reports `capture_cleanup_failed`
(relaunch and re-approval blocked) until the worker returns. Shutdown grants a
still-blocked open/close one more `device_timeout` and otherwise fails, keeping
the recovery marker armed.
Queue drops are latched until one `capture_overloaded` snapshot has reported
them, even when polls are slower than the stall window.
Node health is unaffected by any source failure.
Wiring into the production CLI, the Owner approval route (#13/#14), ring
storage (#16) and transport (#15) is separate work.

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

ADR-0006 selects the bootstrap trust mechanism: the Owner transfers a deployment-local CA public trust bundle through an independently trusted channel; the local Main approval binds a 128-bit, five-minute, one-use code to the Agent public-key digest; and TLS 1.3 authenticates the intended Main before the code is sent. Fingerprint pinning is not the selected profile. The bootstrap/ingest adapters remain separately staged and disabled until their implementation and negative validation are complete. Post-pairing mTLS does not retroactively protect an insecure initial code exchange.

Implemented enrollment contract (Issue #13; ADR-0006 follow-up notes): for the MVP the dashboard step in the diagram above is the local Main CLI `serversentinel-pairing approve` (the installed wrapper for `python -m app.cameras.remote_agent.pairing_cli approve`), and the Agent side is `python -m media_capture_agent.enroll request|pair`. The Agent creates its key and a public request file before approval; the Main binds the approval to that key digest. The bootstrap listener is TLS 1.3 with ALPN `serversentinel-capture-enroll/1` and no client certificate. Each connection carries one frame each way, a 4-byte big-endian length followed by JSON. The request has exactly `version` (1), `deployment_id`, `code` (26 Base32 characters) and `csr` (PEM, at most 16 KiB; request frame at most 20 KiB). The response is `{"status":"issued","certificate":PEM}` or `{"status":"refused"}` (at most 32 KiB), and the refusal never carries a reason. The Agent first completes one fully verified connection without sending anything, then prompts, then reconnects with the same verification and sends.

CA key separation (Issue #109 PR1, Owner decision 2026-10-07, "Plan B"). No network-facing or database-owning process loads the deployment CA private key. Three local accounts take part: `root` only starts `sudo serversentinel-pairing init|rotate-listener|approve|revoke` (`python -m app.cameras.remote_agent.pairing_cli`; `serversentinel-pairing` is the `root:root` `0755` wrapper `/usr/local/sbin/serversentinel-pairing` that the installer places on install and update (Issue #180): each run reads the installation's `current` pointer once and runs that release's `venv/bin/python -I` under `env -i` with that release directory first on `sys.path`, so no caller variable, user site or working directory selects the interpreter or the code; it names no release, so update and rollback never rewrite it, and the installer replaces only a wrapper it generated and refuses, before any change, any other file at that path); the static system account `serversentinel-ca` owns the CA directory (0700: `ca-key.pem`, `ca-certificate.pem` and the CA-only issuance log `issuance-log.jsonl`, all 0600); the service account owns the application database and the Main listener directory (0700: listener key and certificate and the public CA copy `deployment-ca-certificate.pem`, all 0600). Before any thread exists the command forks a CA child, which starts a new session, keeps only its two pipe ends (stdin/stdout/stderr become `/dev/null`, so it holds no terminal or database descriptor), drops with `setgroups([])`, `setresgid`, `setresuid` to `serversentinel-ca`, sets `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0` and a parent-death signal, and verifies that every uid/gid is the CA account with no capability. The command then drops the same way to the service account and verifies `CapEff==0`, `CapPrm==0` and `euid!=0`; any failure aborts before the request file or the database is opened, and it also aborts if the dropped process can still open the CA directory (`ca_directory_exposed`). No file of the listener directory is opened before the drop: `approve` loads the enrollment TLS material after it, as the service account, from `O_NOFOLLOW` descriptors (`/proc/self/fd/N`), never by a path that a swapped symlink could redirect to the CA key. The fork also requires the kernel's `Threads: 1`. `approve` then validates the request, pins the database (exact schema), runs the `key_revoked`/`bound_node` prechecks, asks for `APPROVE` and calls `PairingLedger.approve`. It sends `{node_id, csr}` to the CA child, which refuses a node revoked in its issuance log and a key the log binds to another (or a revoked) node, signs exactly one fixed-profile clientAuth leaf (397 days, never beyond the CA), appends it to the issuance log with fsync before answering, and exits. The command verifies the leaf against the public CA certificate (direct issuer, exactly the node and deployment URIs, the approved key, `CA=false`, digitalSignature only, EKU clientAuth only, currently valid), waits for the child's clean exit, and only then shows the code and serves the bootstrap listener, with no process holding the CA key alive. On redemption the listener checks the CSR's proof of possession of the approved key and activates exactly the pre-signed certificate digest; it holds only `DeploymentTrust` (public) and refuses the signing class. A pre-signed certificate is inert until that activation (ingest admission requires the ledger's active record), so an unredeemed one admits nothing. Any issuer failure (refusal, crash, malformed answer, non-zero exit, verification failure, wrong ownership of the CA directory) refuses `issuer_unavailable` with the issuer's fixed word as `issuer_detail=` and never shows the code; an unwritable issuance log means nothing is signed (`issuance_log_unavailable`). `init` and `rotate-listener` generate the listener key on the service-account side and the CA child only signs its subject-free, extension-free CSR with the fixed serverAuth profile, so no file changes owner; `init` keeps the new CA provisional until the listener side has written its files and removes it otherwise. `export-bundle` and `list` run as the service account with public material only. `revoke` revokes in the ledger first and then records `node_revocation` in the issuance log; if that record cannot be written the ledger revocation stands, the command reports `ca_revocation_unrecorded` and exits 1, and a rerun records it. The deployment configuration must contain `capture_ca_directory` (a path, or `null` when the host keeps no capture CA; Owner decision 2026-10-07); a configuration without it is refused with that reason (releases declare `CAPTURE_CA_DIRECTORY_SETTING`, and the installer checks the configuration against the release it switches to: the key is required for those and refused for earlier ones, before any change), and the launcher refuses to start (also with `--check`) when a configured directory can be opened by the service account or does not exist. Both the launcher and the pairing CLI's post-drop check (`ca_directory_exposed`) treat as exposed a CA directory the service account can open, or one it controls even while access is currently denied: the directory, a path component or a CA file owned by it, a directory, CA file or non-sticky path component writable by it, or a symbolic-link component. Only `revoke` treats a missing directory as not exposed, so it still revokes in the ledger when the CA directory is lost. The CA child holds the CA directory lock from `hello` until it exits, so log checks and appends are serialized across commands (a concurrent one is refused `issuer_material_busy`). `init` writes the listener files and the CA pair under staged names and installs them with the key last; the new CA is committed before the final listener key is installed, so a final listener key implies a committed CA; an interrupted listener write (no final key) is removed and redone by the next `init`, a partial CA is removed only when the issuance log holds no record (otherwise `issuer_material_incomplete`), and a complete credential or CA is never removed. Write access, and read/search access to the CA directory and files, is decided by `access(2)` with the effective ids, so POSIX ACLs count; where that is unsupported the path counts as exposed. A torn final issuance-log line (an append interrupted before its reply) is ignored and dropped by the next append. `init` is idempotent: with an existing CA it keeps the CA and only issues a listener leaf into an empty listener directory (same server name as the CA log records), or changes nothing when that CA's complete listener credential is present; CA material is never removed. A public CA copy is written only after the listener certificate verified against that CA. The issuance log carries no hash chain (deferred, Owner decision 2026-10-07); only the CA account or root can modify it. Renewal (Issue #13) keeps its in-process signing primitive behind `renewal.RenewalIssuer` as an interim path: nothing in the application calls it and no listener carries renewal yet; the renewal-only signer that replaces it is Issue #109 PR2.

### 5.5 Long-lived trust

After pairing, use mutually authenticated encryption. mTLS with a deployment-local CA/issuer is the default target unless an ADR selects an equivalent mechanism.

Certificate profile implemented by the Issue #13 adapters (not yet wired to a running listener): an EC P-256 deployment CA (`pathlen=0`); a Main ingest leaf with EKU `serverAuth` and the bundle's DNS server name; node leaves signed only for an Owner-approved key, after the approval and before redemption, and valid only after the ledger activates them on redemption (Issue #109), with `CA=false`, EKU `clientAuth` only and exactly two SAN URIs, `urn:serversentinel:capture-node:<node UUID>` and `urn:serversentinel:deployment:<deployment UUID>`. The node's CSR proves key possession only; its requested subject/extensions are ignored. The ledger key digest is SHA-256 of the DER SubjectPublicKeyInfo and the credential digest is SHA-256 of the DER certificate. Ingest requires TLS 1.3, a client certificate chaining to the deployment CA only, and the ledger's current active record on every connection and before committing queued work; a valid certificate alone never admits a node. Node leaf validity defaults to 397 days (the maximum; never beyond the CA) and renews automatically (Owner decision 2026-09-30). The Agent starts 30 days before expiry and retries with exponential backoff from 1 hour up to 24 hours, reusing one fresh renewal key (kept 0600 in `pending-renewal/` across retries) and an empty-subject, extension-free CSR sent over its current admitted mTLS session. The Main renews only the presenting node's own identity, and only while that exact credential is the ledger's active, unexpired one. It stages the result; the first admission of the renewed certificate atomically promotes it and supersedes the old one, and until then the old certificate stays admitted. A connection that loses a concurrent promotion of the same staged renewal is admitted only if its exact key and certificate are then the active credential (Issue #121). A retry with the currently staged key is certificate-idempotent: the staged row keeps the issued certificate's public PEM, bound to its digest, and the retry is answered with that first certificate, re-verified as this CA's leaf for the same node and key, rather than a newly signed one (Issue #123); it is looked up before anything is signed, so such a retry is not refused for CA validity the staged certificate already satisfied (Issue #148). Revoked, expired or superseded credentials must re-pair. A node public key is bound to one node for good, across all credential states (Owner decision 2026-09-30). Approval, activation, renewal staging and promotion each refuse, in the same transaction, a key already bound to or staged for another node; a revoked key is never reused, even by its own node. The Main raises the local Owner-visible `capture_credential_warning` notification when an active credential is within 14 days of expiry, expired, or a renewal is refused; a warning whose notification is not confirmed as recorded (the hook raises, or returns `failed` because the local write was refused with the retry buffer full) is retried with the same event ID rather than marked reported. A leaf is never issued beyond the CA's own expiry: a renewal refused for that reason reports `renewal_ca_validity_insufficient` (distinct from `renewal_request_invalid`) and raises the deployment-wide local `capture_trust_warning` instead of the per-node warning; given the CA and Main listener expiry, the monitor also raises `capture_trust_warning` 30 days before the CA stops covering a 397-day node leaf and 30 days before the listener certificate expires (Issue #127); until a scheduler runs the monitor, the local pairing CLI (`init`, `rotate-listener`, `export-bundle`, `approve`) prints the CA expiry and the same warning words on stderr. The Main listener leaf (397 days by default) is rotated by the Owner with `pairing_cli rotate-listener`, which keeps the CA and server name so Agent bundles stay valid, replaces the pair under an exclusive directory lock with staged files and per-file atomic renames, refuses a listener certificate not issued by the selected CA, and completes an interrupted run on the next invocation before checking the new leaf's validity against the CA (Issue #148); readers refuse a mismatched key/certificate pair. Listener material belongs to the service account and is written by the CLI after it dropped to that account, so no ownership change is needed (Issue #109; the earlier `--listener-owner` option and its `CAP_CHOWN` + `CAP_DAC_OVERRIDE` requirement are gone). Concurrent `init` runs are serialized by directory locks and roll back only their own entries; the bootstrap listener sets `SO_REUSEADDR` but never `SO_REUSEPORT` (Issues #124/#125), and so does the ingest listener (`open_ingest_listener`, set before bind), so a restarted Main rebinds at once while the previous process's capture connections are in TIME_WAIT; on Linux `SO_REUSEADDR` never lets a second socket bind a port that is already listening (Issue #223). The human upstream needs no change: in production systemd's `server-sentinel-upstream.socket` holds it across service restarts, and in the unactivated path uvicorn binds through asyncio `create_server`, whose `reuse_address` already defaults to true on Linux. `export-bundle` and `approve` refuse a listener certificate not issued by the deployment CA (`listener_authority_mismatch`; `export-bundle` checks it against the public CA copy in the listener directory and refuses `deployment_ca_certificate_missing` without one), and `approve`/`list`/`revoke` open only the application's existing database file (canonical path, regular file, one link, owned by the service account the command runs as, not group/other-writable), never creating one. The bootstrap bind also refuses Tailscale addresses, IPv4 `100.64.0.0/10` (CGNAT) and IPv6 `fd7a:115c:a1e0::/48` (a ULA), including IPv4-mapped spellings, and the ingest listener configuration refuses the same ranges (Issue #150): enrollment and ingest are private-LAN only and need no Tailscale. The same ranges are refused as a Main endpoint (Owner decision 2026-10-07): `export-bundle --endpoint` refuses an IP literal in them (`trust_bundle_endpoint_tailscale_address_refused`) and writes no bundle, and the Agent refuses `main_endpoint_tailscale_address_refused` for an IP literal in them, before any traffic, as the bundle endpoint (when the bundle is parsed, so a `pair --endpoint` override does not rescue a bundle whose stored endpoint is a Tailscale IP literal; a stored DNS name is not resolved at parse time, so such a bundle is accepted and its connection is refused after the TCP connect unless a LAN `pair --endpoint` override replaces it) or as a `pair --endpoint` override, and for a DNS name whose connected peer address falls in them after the TCP connect (a TCP handshake with that peer has already happened) but before the TLS handshake and before any secret is sent. `connect_to_main` uses `socket.create_connection`, which settles on the first resolved address that connects and does not try the others after the refusal, so a name that resolves to both LAN and Tailscale addresses may be refused depending on resolution order; capture endpoint names must resolve only to LAN addresses. The check covers configured and connected destination addresses only; it does not inspect routing, so a subnet route or exit node on a capture host that optionally runs Tailscale can still carry LAN-addressed traffic over `tailscale0`. It is a configuration check, not authentication or network isolation. Classification is by address range only, so a non-Tailscale private network (another CGNAT or ULA deployment) that uses these ranges is refused too and must expose the Main on another private address.

Re-pairing contract (Owner decisions 2026-10-01/05; Issues #116/#117; ADR-0006 follow-up notes 2026-10-07). Re-pairing never bypasses the bootstrap above: it uses the same trust bundle, verified TLS 1.3, one-use code and typed local Owner approval, and stays inside the installed deployment (a different CA is a fresh install).

- *Expired, not revoked:* `enroll request|pair --repair expired` proves the installed key again, only once the installed certificate has expired (an unexpired one renews automatically). The Main re-approves the key for its same node after the Owner types `APPROVE`; the Agent accepts only a certificate for the same node and deployment that outlives the expired one and rotates it in atomically. Node UUID and camera sources are unchanged.
- *Revoked:* `--repair revoked` uses one fresh key (0600 in `pending-repair/`, re-exported on retries) and must receive a certificate for a different node of the same deployment, swapped in atomically. The Main refuses every key ever held by a revoked node (`public_key_revoked`) before the Owner prompt and again inside the approval transaction. No camera source is carried over; the Owner approves the new node's sources again. The old node's ledger rows stay `revoked` and its recordings stay attributed to it until normal retention.
- *Serialization:* every `request`, `pair` and renewal step holds one non-blocking runtime-wide lock (`flock` on `<runtime_root>/node-enrollment.lock`); `pair` holds it from the installed-identity check through install and pending-key cleanup, and `request` through writing its request file. A second run is refused at once with `enrollment_in_progress`, before any network traffic or code prompt.
- *Configuration and fail-closed start:* after a revoked re-pair the Owner updates `node_id` in the protected Agent configuration by hand (the CLI prints the exact change). Service start and `--check` refuse with `node_identity_mismatch` while the configured `node_id` differs from the installed credential's node, and with `node_credential_unavailable` when the installed credential is damaged or unreadable, including a lost commit marker once `node-identity-installed` records that an identity was committed. Only a store without that evidence (fresh, or a first install interrupted before its commit) reads as unpaired. Every validation of a committed credential (start, `--check`, pairing) durably backfills missing evidence (identities paired by an earlier release, or a stop between the commit and the evidence write) and refuses the credential if it cannot be written. The evidence is not written before the commit, so an interrupted first install stays retryable; the residual case is a commit lost after such a stop and before any validation. The old generation's files are deleted only after the swap commits; the Agent's ring buffer and protected incidents are untouched.

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
- FIFO overwrite keeps ordinary ring-buffer data within the selected capacity, and within the capacity's duration horizon at the configured expected bitrate so segment metadata stays bounded; that horizon is never shorter than the 10-minute pre-loss window.

In both modes the UI displays selected mode/value, estimated equivalent duration/capacity, current ring-buffer bytes, protected-incident bytes, filesystem free space, and safety reserve.

Configuration admission for the selected duration/capacity/profile checks both the **10-minute pre-loss window** and headroom for the **next 10 minutes while that window remains pinned**. Use bounded/negotiated bitrate and segment/container overhead to estimate the complete simultaneous 20-minute footprint on the expected filesystem, including existing protected-incident bytes, other filesystem use, and hard safety reserve. Count shared segments once; only eligible ordinary segments outside the required pre-loss window may be reclaimed for this check. The pinned pre-loss window and unexpired protected incidents are not reclaimable. Reject a determinably insufficient configuration before applying it: fitting 10 minutes plus reserve alone does not satisfy admission. The ordinary ring-buffer byte limit remains distinct from protected-incident usage; this check does not require changing duration/capacity mode or define a new numeric reserve.

Runtime uncertainty or later growth of protected/other filesystem usage may reduce post-loss headroom or pre-loss coverage. Reevaluate available headroom during storage admission and report degraded protection with actual coverage/gaps when it becomes insufficient; never claim a complete incident or permit writes across the safety reserve.

Normal unprotected segments are FIFO. Protected incident segments are not part of ordinary ring-buffer eviction.

The implemented core is `agent/media_capture_agent/ring.py`, with a private
transactional SQLite ledger and #12's descriptor-pinned media store. Admission
uses physical allocated bytes, unique shared references, explicit per-source
bitrate/cadence/overhead bounds, and verified free space after any eligible
reclamation. Its DTOs expose intervals/gaps, completion/expiry, pressure and
deletion state. The concrete contract and incomplete production/UI integration
are documented in [`agent/docs/RING_BUFFER.md`](agent/docs/RING_BUFFER.md).

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
- stop/refuse unsafe writes before crossing the filesystem safety reserve. Status predicts refusal from the sources' next appends, charged at the sources' recent real segment allocations (the mean of the simulated appends' total plus two standard deviations of that total, the deviations of all appends added as if perfectly correlated, or, for synchronized sources with enough aligned history, a prediction bound measured from their recent batch history; never above every append at its source's recent maximum; `agent/docs/RING_BUFFER.md`), with same-instant appends evaluated as one batch: while they cannot be admitted without crossing the reserve at the recent real bitrate, report `STORAGE_HARD_STOP / segment_write_refused_at_reserve` (not pressure or healthy) until space returns. If they would be refused only were every segment to reach its maximum bound, report `STORAGE_PRESSURE / segment_write_at_risk_at_maximum_bitrate` (or an earlier pressure reason), never healthy. Segment cadence is at least one second; shorter profiles are refused (`segment_duration_below_supported_cadence`);
- if the full 10-minute pre-loss target or 10-minute post-loss continuation cannot be maintained, report the exact degraded/gap state rather than claiming complete protection.

### 5.15 Media-root mount safety

The Agent media root is a deployment-configured path outside the source tree that may live on a dedicated mounted filesystem. Public code/configuration must not embed an actual deployment path.

At install/startup/runtime admission, the Agent shall verify:
- the configured media root exists or can be created only by the intended installer/owner workflow;
- it resolves to the expected filesystem/mount/device and backing-filesystem-root identity; a narrow systemd namespace bind must map to the approved parent root plus the configured relative media path;
- the approved filesystem UUID resolves to the device the mount and pinned media directory are on. Recorded major/minor only corroborate it (Issue #324, as Main's Issue #321): a difference is accepted only for an unchanged major on a hardware-backed device in sysfs that is not the root filesystem's (approved mount point not `/`), and then as degraded with the value-free `device_numbers_stale` (`--check` warning; heartbeat `storage.state = degraded`, `storage.reason = device_numbers_stale`, node reason `storage_device_numbers_stale`). A changed major, loop/nbd/zram/ram or a mapping on one, or missing sysfs evidence refuses with `mount_device_mismatch`. A differing mount `source` is accepted only together with such a renumbering, when both sources are single kernel block-device names under `/dev` and the current one's `st_rdev` is the mounted device (sd renames `/dev/sdb1` to `/dev/sda1` with `8:16` to `8:0`); otherwise `mount_source_mismatch`. Owner decision 2026-10-23: keep recording as degraded, as on Main (#323);
- sufficient free space and safety reserve remain;
- it is writable by the dedicated Agent service account;
- loss/unmount/substitution of the expected media filesystem does **not** silently redirect ring-buffer or incident writes into a directory on the root filesystem.

If the expected media filesystem is unavailable or resolves unexpectedly, Agent recording/buffering becomes explicit degraded/failed state and unsafe writes are refused until the Owner resolves or re-approves the target.

The Issue #16 ring core requires an explicit SQLite ledger size bound in addition
to media-profile/reserve inputs. It guards runtime-filesystem metadata growth
before schema creation, hot-journal recovery and transactions, and reserves
conservative completion headroom in shared-filesystem media admission. The cap
must also cover cadence-derived segment/index/protection rows for the selected
ring and the next complete pre/post incident, including existing retained
metadata. Failed reconfiguration retains the active ring's selected coverage;
only trusted clock observations advance the durable rollback watermark.
Untrusted capture discontinuities are refused without advancing per-source trusted
chronology. Capacity changes must fit incompatible legacy pre-roll throughout
profile rollover, not merely fit the filesystem or one immediate new segment. Unexpected
authentication loss is an effective Main loss even while the raw socket remains
connected; known protected-evidence damage stays degraded outside current pre-roll.
See `agent/docs/RING_BUFFER.md` for the implemented budget and integration limits.

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

Adapter selection (`server/app/media/profiles/adapters.py`) takes an explicit
acceleration policy. With `prefer_hardware`, a missing or failing accelerator
falls back to a listed software adapter and the selection records
`hardware_unavailable` + `software_fallback`; with `require_hardware`, or when no
software adapter exists, the path is `adapter_unavailable` (or
`adapter_start_failed`). Fallback is never silent and never reports the
accelerated path as active: the selection is recorded per started adapter/path
(`PathStatus.adapter_state`), not as one selector-wide latest result, so a path
still on software fallback stays visible after another path starts on
recovered hardware.

### 6.3 Room-overview benchmark

For wide room coverage, real-hardware tests should compare at minimum:

- highest useful camera resolution at ~10–15 fps;
- 1080p/15 fps;
- resulting person/entrance detection accuracy;
- main/agent CPU, GPU, VRAM, LAN throughput, dropped frames;
- browser live latency/quality;
- ring-buffer disk throughput/capacity at candidate capture profiles.

Final defaults are measured, not guessed.

The high-resolution room-overview capture is an explicit per-source allowlist
option (`CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION`) with explicit minimum
capture dimensions. Its sets must downscale inference and viewer output below
the capture resolution without raising FPS; the option is never inferred from a
role label or source type, and admission requires requesting it explicitly.
`python -m app.media.profiles.measure` is a synthetic scheduler-overhead
harness (CPU, RSS, queue depth) that prints no private values; it does not
replace the real-hardware benchmark above.

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

Transport-independent continuity contract (ADR-0007, Proposed; protocol still
unselected). Every media unit carries `(source_id, capture_epoch, sequence,
capture_time_ns)`: `capture_epoch` is a strictly increasing Agent capture-process
epoch, `sequence` counts units per source within an epoch and survives transport
reconnects, and `capture_time_ns` is the Agent monotonic capture clock within
the epoch. The Main Server assigns a new session generation on every
authenticated session open; a superseded session is rejected. Generations are
never reissued, including after node removal and re-enrollment of the same
identity, and a grant is bound to one Main process lifetime. A unit is
committed only after the bounded ingest queue accepts it: backpressure or rate
refusal does not advance continuity and the Agent retries the same sequence,
a retry of a committed unit is an idempotent `duplicate`, every media attempt
of an authorized node (including a duplicate or an early refusal that is never
enqueued) consumes its per-node ingest rate budget, a unit refused for
a reason no retry can satisfy (oversize) is recorded as loss, and any other
ingest refusal leaves continuity unchanged and the flow `degraded`. A sequence skip reports the exact missing
count, a new capture epoch reports a gap of unknown extent (also when the
source's earlier-epoch unit was attempted but never committed; an epoch lower
than one already attempted is refused as stale; a restart is recorded when a
refused unit first shows it, so it reaches the durable consumer even if that
unit is never retried, and its retry does not report it again), and an in-epoch
capture clock regression is reported. After a Main Server restart, a source's
continuity resumes from the durable recording layer's committed watermark
`(node, capture_epoch, sequence, capture_time_ns)` before its first unit is
checked, so units already recorded by the earlier process are `duplicate`
rather than leading loss and units lost after that watermark are an exact
skip; a failed watermark lookup refuses the unit transiently rather than
reporting loss or healthy flow, and until a lookup succeeds the source is kept
as a bounded, slot-limited entry reported `degraded` without advancing
continuity. The full envelope travels with each
admitted unit in the ingest queue, and the ingest boundary refuses a media
unit with a missing or partial envelope. Known loss or backpressure keeps the
source flow `degraded`, including pressure or a transient refusal on a
source's first unit before anything is committed; an observed refused attempt refreshes source activity without advancing continuity, so sustained pressure stays `degraded` rather than `interrupted`. A closed or stale session makes it `interrupted`, and node authorization failing at any check (heartbeat, media, or the ingest queue's own recheck) invalidates the session grant, while a source-only refusal does not. These authorization checks run while the tracker/queue lock guarding the affected state is held, so a revocation that lands while a session open, heartbeat, or media attempt waits for the lock is always observed (no fresh grant, liveness refresh, `duplicate` acknowledgement, enqueue, or rate window after revocation). A durable node revocation or source deactivation commits inside the tracker/queue `authorization_change` block, which holds those locks for the commit, so no check can pass before the commit and act after it; before the block releases the tracker lock, a revoked node is forgotten with its sources (so a grant issued just before the commit is unusable) and its rate window is discarded, and a deactivated source releases its active-source slot, with undrained gaps handed back to the caller for persistence; a failed commit changes nothing. Gap
events are bounded per source and coalesce into an unknown-extent event rather
than being dropped. Flow continuity is not camera health or node health (§5.8).
Tracked sources are bounded by the active-source limit (§3.4); tracked node
sessions are hard-bounded separately, so live source-less node sessions never
consume the active-source allowance. The active-source limit counts active sources, so durable deactivation or replacement of one
source releases its slot (returning its undrained gap events to the caller)
without discarding the node's other flows. A released source's continuity
(committed position, highest attempted epoch, and loss already recorded from a
refused unit) is kept outside the slot limit, also when the ingest queue holds
none of its units, so after reactivation a retry is a `duplicate` and never
enqueued twice, a lower epoch than one already attempted stays stale, and the
same loss is never handed to the durable consumer twice. Leaving the ingest
queue is not durability: that entry is dropped only after the durable
recording layer acknowledges persisting a watermark at or past its committed
position (and it carries no noted loss or uncommitted attempt), after which
the durable watermark applies. These entries are hard-bounded (deployment
setting); when full, the oldest entry's durable committed watermark is looked
up once and, if it already covers that entry (an acknowledgement that was lost
or never sent), the entry is dropped as reclaimed without counting an
eviction. Otherwise (nothing recorded, a watermark behind the entry or for
another node, or a failed lookup) the oldest is evicted and that source falls
back to its durable watermark on reactivation, which can repeat an envelope or
a gap report but never hides loss. An entry that no watermark can cover (it
carries noted loss, a refused attempt, or an unresolved lookup) is evicted
without that lookup. Revoking or forgetting a node drops its released entries
without durable confirmation: re-enrolling the same node UUID then resumes
from the durable watermark, which can repeat a drained but not yet persisted
envelope (a duplicate, never loss); a node re-paired under another UUID is
refused by the watermark's node identity instead. Each such eviction, and each ignored durable
acknowledgement (watermark for another node, or an unknown source), is never
silent: it is counted in value-free operator diagnostics (the tracker's
`diagnostics()` counters, intended for a health/status surface but not yet
wired to one; that exposure comes with the listener/route integration of
#14/#15) and logged rate-limited without node/source identity (the first
occurrence, every doubling, and at least once per 60 s while it keeps
recurring; every qualifying occurrence keeps its own record). A unit behind loss already recorded (below the first
refused unit that showed a skip or restart) is acknowledged as `duplicate`
and never admitted, so media never contradicts the recorded gap. An in-epoch
capture clock regression is measured against the committed unit and the
latest capture time observed on a refused unit of that epoch, so it is
reported also before anything of the epoch commits; the epoch of a unit
refused because the watermark lookup failed is kept when the lookup later
succeeds, even when nothing durable exists. The capture times of those
refused units are kept as well, each associated with its sequence, except
that a resolved watermark of the same epoch supersedes (as a commit would)
every refused unit at or before its sequence and every one not later than its
capture time: the baseline is then the latest capture time among the refused
units past the watermark only, so a time observed on a covered unit never
reports a spurious regression, and when none remains the watermark alone is
the baseline, so a duplicate retry leaves the source durably covered. This
association is hard-bounded per source; when the bound is reached, the oldest
entries are merged conservatively (the later capture time is kept), which can
report a spurious regression but never hides one. Activity time is re-sampled
after the lookup and after admission so a slow durable lookup cannot make a
just-accepted flow read `interrupted`. A node that owns no tracked source
and whose session is closed, invalidated or stale does not keep a slot.
Liveness time is sampled while the tracker state is locked and never moves
backwards, so a delayed or regressed clock sample cannot make an active flow
look stale or retire a live session (the new session is refused instead); a
source first seen under a regressed clock is seeded from its node's liveness
watermark rather than the older sample.
`server/app/cameras/remote_agent/continuity.py` implements this without a
listener, protocol, or cryptography.

### 6.5 Main-to-browser live transport

Phone/Mac/desktop users view live video **through the main host**, never directly from `media-capture-agent`.

The product goal is near-real-time viewing, but **stability, recovery, and continuous truthful state take priority over chasing the lowest possible latency**. No fixed sub-second target is required before PoC.

If an already encoded source can be safely relayed in a browser-compatible form, avoid unnecessary transcoding. Otherwise transcode/packetize on demand.

Viewer-only processing should scale down or stop when subscriber count is zero.

Interim (Owner decision D10, Issue #10 S7, pending #19): local UVC live video is
served as an authorized MJPEG frame pull of native camera JPEG frames, without
transcoding, through the human surface (§11.9, "S7 interim live"). Its viewer
demand ends without polls, so with no viewer nothing is retained.

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

The Issue #20 foundation in `server/app/detection/foundation` uses transient grayscale frames, one bounded pending frame per source, independent Main-monotonic inference cadence, and an explicit worker entry point. Quality failure, missing models, stale observations, dropped frames, and evaluation failure produce `unknown`; known loss/throttling remains visible in health snapshots. No model is implicitly downloaded or enabled. The CPU motion baseline detects image change only. An optional RT-DETRv2 CPU adapter loads only a separately licensed, locally supplied, digest-pinned ONNX artifact on the audited Linux x86_64/CPython 3.12 runtime; no runtime model download or cloud/provider fallback is exposed. See `server/docs/DETECTOR_FOUNDATION.md` for limits and `server/docs/DETECTOR_MODEL_AUDIT.md` for separate code/weight evidence. Inference runs in a spawned, rlimit-bounded worker process per source binding under a wall-clock watchdog; a hang, crash, start failure or protocol violation yields `unknown` with a worker reason (`detector_timeout` / `detector_crashed` / `detector_worker_unavailable` / `detector_failure`), never `absent`. `InferenceFeed` feeds pipeline inference samples to the scheduler and invalidates on discontinuities, and its `poll()` invalidates at the moment the pipeline closes, loses admission or requires renegotiation even when no further frame arrives; any current-stream frame of non-sufficient quality invalidates to `unknown` whether or not it is sampled, and closing the inference runtime invalidates every binding. The deployment `detection` object must name every detector parameter, cadence and worker limit explicitly; without it no inference runtime starts. Target-host performance and verification of the worker limits remain acceptance work.

### 7.3 Server movement

Per source/profile calibration stores server ROI/polygon, reference descriptors, background context, thresholds, and calibration version/time.

Runtime may combine global transform compensation, edges/contours, ROI similarity, temporal persistence, and person/occlusion masks.

### 7.4 Camera tamper

Candidate signals include global optical transform, persistent occlusion/near-black view, abrupt focus/exposure/scene-pose change, and disconnect closely following scene movement.

The internal `server/app/detection/roi/` core operates only on transient,
bounded grayscale frames for one immutable source/profile calibration. It stores
source type, profile, polygon, reference geometry (stream, sample, width,
height), policy, luma reader, version, and timestamp in a private append-only
calibration history after the application's ROI calibration migration. That
history is metadata only: no frame pixels, crop, thumbnail or other decoded
monitoring media is persisted, and no value computed from the frame (digest,
histogram, statistic) either (Owner decision 2026-10-22, Issue #205), so it
cannot become still-image storage outside recording authorization and
retention. A stored record therefore cannot reproduce or re-admit a reference
image; resuming detection binds the in-memory `Calibration` that produced the
record (`CalibrationRecord.bind`), whose whole non-frame provenance must equal
the record. A bare frame is never bound to a stored version; a frame read from
the camera becomes a reference only through a new calibration version. A
`reference.sha256` in a record written before #205 is ignored when read and
removed at every Main start once the migrations ran and the audit storage
admission is bound (`scrub_legacy_reference_digests`: in one write
transaction with `secure_delete` on, the table is rebuilt (every row deleted
and inserted again, re-serialized exactly as a new version), so stale copies
a legacy write left in its pages' free space are zeroed too; retried before
the restart re-acquisition and at the next start when refused; the event
`scene_reference_digests_scrubbed` carries only the row count). This removes
the value inside the database file only and is not a claim of forensic
erasure: copies outside the file (rollback-journal blocks the filesystem
freed, SSDs, snapshots or backups) may remain. The lifecycle inventory
digests the ROI metadata without that key, so the scrub is the one approved
rewrite of this append-only history and a scrubbed version verifies as
preserved against a baseline recorded by this release's tool; against a
baseline an earlier release's tool recorded it is reported `changed`. The core does not supply production thresholds, start capture, expose an
API, retain decoded media, make a presence decision, or issue a notification.

A calibration policy whose bounded search window cannot reach its own movement
or camera-shift threshold is refused: such a configuration cannot express the
displacement it asks to detect and would report a matching geometry instead. A
calibration is refused as well when its own support leaves no translating pure
translation at or beyond a threshold above the coverage minimum in every axis
direction, since a quarter turn does not register a pixel shift even when it
carries a translation and one direction does not stand for its opposite, or when
its reference already meets the obscured-scene threshold, since every unchanged
sample would then confirm a tamper that never happened.

It first estimates a bounded global translation/quarter-turn transform from
background support, then compares the ROI relative to that transform. A
confirmed ROI movement requires the policy's multiple samples and elapsed time.
An explicit ROI-occlusion signal, insufficient movement quality, sampling gap,
stream restart, regression, incompatible frame, or inadequate calibration
returns `unknown` and resets confirmation; none is converted into a trustworthy
no-movement result. A refused sample, such as a frame from another source, ends
the episode as well, so no later confirmation spans it, and the observed stream,
sequence and clock advance before any such result so that a buffered frame from
a superseded geometry cannot re-enter confirmation. An identified sample whose
metadata alone is unusable, and a refused source-loss report carrying a valid
outage clock, advance that progression too. Every replaced stream is retained
for the detector's lifetime, so a delayed frame from a stream the source has
already left is refused as stale imagery instead of becoming current again, and
no number of later replacements restores an old identity. The number of admitted
stream transitions is bounded instead, and a detector that reaches that bound
latches: every later sample and source-loss report stays unknown until a fresh
detector is bound. Temporal confirmation also begins at the reference sample, so
imagery the source captured before the calibration existed cannot contribute to
it. Because such an interruption ends the episode, a condition confirmed again
afterwards is emitted again instead of being suppressed as a duplicate, so no
confirmed critical observation is silently lost. Person presence is not an input
to this conclusion.

Camera tamper has an independent quality input and confirmation state. The core
can report a persistent near-dark scene, a global scene shift, or a scene that
stops registering while differing measurably from the calibrated background,
which covers a covered or redirected camera. That difference is a bounded
scene-change scalar and never an identity or a culprit attribution. A
registration whose best transform is acceptable but ambiguous, as on a
repetitive scene, remains `unknown` and confirms neither tamper nor its absence,
because its untransformed difference is large even when the registered transform
is small. Trusted source loss becomes critical only when it occurs within the
configured interval after a recorded global scene shift, and at most once per
tracked shift episode; uncorrelated or untrusted loss stays `unknown`. One
confirmed sample may carry both a server movement and a camera tamper, so local
critical staging always admits a whole batch rather than refusing evidence a
caller could never resubmit. A later runtime must durably handle a confirmed
critical observation for evidence preservation and configured notifications in
every presence state.

The Issue #205 `SceneMonitoringRuntime` (`server/app/detection/roi/runtime.py`)
wires this core into the Main application: capture callbacks hand it at most one
pending sample per source at a bounded sample interval (default 1 sample/s), and
a single worker runs the per-source `server_roi` and `camera_tamper` quality
gates and the detector, with per-source failure isolation. Confirmed
observations go through bounded in-memory critical staging to an injected
durable recorder (`CriticalTimelineRecorder`); without it no detector runs. The
recorder is called only on a dedicated delivery thread, never on the scene
worker, so a stalled recorder (for example on stalled storage) never blocks
sampling or detection: staging fills and further confirmations become explicit
`critical_backpressure`, and a recorder call in flight longer than the stall
bound reports the runtime `degraded` (`recorder_stalled`). Without a stored
calibration whose reference frame can be re-bound, a source stays inactive and
`unknown`; no baseline is taken from live frames except on an explicit Owner
calibration or the restart re-acquisition below.

Local capture is read as uncompressed `GREY`/`YUYV` or, since Issue #217 (Owner
decision 2026-10-11), as `MJPG` through the reviewed simplejpeg decoder: a
structural pre-check in the Main process (flat byte buffer, SOI, one baseline
scan ending in a single EOI, bounded padding, SOF dimensions equal to the
negotiated format within a pixel budget, a payload of at most 2 bytes per
negotiated pixel plus 256 KiB, entropy data checked with C-level byte operations
so its cost is linear in that bound) runs on the scene worker before any native
code sees the bytes, and the strict decode itself runs only in a separate,
per-source, resident decode child process (Owner decision 2026-10-11 on PR
#225), never in the Main process. The child is started by fork+exec of the
service interpreter (`python -I -B`) from that source's own long-lived
supervisor thread (child start and reap never run on the shared scene worker;
frames are refused as `unknown` until the child is ready) with a minimal
environment and only a private `AF_UNIX` socketpair inherited; before importing
the decoder it sets `no_new_privs`, a parent-death `SIGKILL`, non-dumpable, a
lower CPU priority and equal soft/hard rlimits (address space, descriptors, no
new process, no core, no file writes), and it runs as the same unprivileged
service account. After importing the decoder and decoding one generated warm-up
frame, and before it reports ready, the child confines itself irreversibly
(Issue #269, Owner decision 2026-10-16 on #233 (B)): a Landlock ruleset that
handles every filesystem right of the kernel's ABI and grants none (no path can
be opened, created, executed or listed; TCP bind/connect denied at ABI >= 4;
abstract UNIX socket and signal scoping at ABI >= 6), then a seccomp allowlist
built without dependencies (x86-64 and aarch64; socket I/O on the inherited
socket, memory management without `PROT_EXEC`, futex, signal return and exit
only). Any other system call, and any call through another architecture or
numbering (i386, AArch32, x32), kills the child with `SIGSYS`, which is a child
crash (`unknown`). The sandbox is fail closed: where either layer cannot be
applied (no Landlock, no seccomp filter mode or kill-process action, another
architecture, a multi-threaded child), the child reports a fixed refusal code
instead of ready and exits without decoding; the decoder then reports
`failing` at once and the source is `degraded` with
`frame_decoder_sandbox_unavailable` (logged once, value-free), every frame
`unknown`, never a negative. No setting runs the decoder unconfined. Every
exchange has a hard per-frame deadline that covers the
transfer. Any pre-check refusal, strict decode error, decoded-shape mismatch or
mid-grey undecoded band, and any child crash, kill (including OOM), exit,
timeout (the child is killed) or malformed reply is `unknown`
(`frame_undecodable`, counted per fixed reason in `undecodable_reasons`); a
replacement child starts only after a bounded exponential backoff during which
frames are refused without waiting (the supervisor starts it when the backoff
ends, without waiting for a frame), and repeated child failures lower the source
(and the runtime) to `degraded` (`frame_decoder_failing`, logged value-free).
The restart never gives up: a child that can never start (address-space cap,
import failure) is respawned at most once per 30 s per source for as long as the
source is bound, while the source stays `degraded`. A missing or differently
versioned decoder keeps the source inactive (`frame_decoder_unavailable`).
`stop()` kills and reaps every decode child within the scene stop bounds. Decode
success does not prove frame integrity. `capture_luma_layout()` must be given
the driver-negotiated profile. Other compressed formats stay `unknown`.

Poor quality, undecodable frames, backpressure, camera loss and stale
conclusions are `unknown`, never a negative. A camera loss that arrives while
staging has no room is held as backpressure and processed after staging drains,
never dropped as a per-source failure; a loss still queued at shutdown is
processed by the final worker pass. Every loss or observation that remains
undelivered is counted in the runtime status and logged (staging is in memory
only): staged observations in `critical_pending`, losses still without staging
room in `losses_held`, losses lost to a per-source fault (while running or in
the shutdown drain) in `losses_failed`, and a loss left in a capture slot, or
taken from it and not yet handed to its detector, by a worker that outlived its
stop bound in `losses_cleared`. Their total, and separately each batch refused
after `stop()` fenced the count, is handed to an injected count-only durable
sink (Owner decision 2026-10-14, #224), so each refusal is counted once; a count
may be overstated, never hidden. A missing or failing sink is reported
(`undelivered_recorded`, `scene_undelivered_unrecorded`).

When the embedder passes `scene_timeline` (a `SceneTimelineConfiguration` with
an explicit source latency bound and main-host clock port, no default),
`create_app()` owns the presence timeline for this evidence
(`app.presence.runtime.SceneTimeline`, Issue #205): a `PresenceService` over the
application database pinned under the storage admission, a `TimelineOutbox`
and a `CriticalTimelineRecorder`, which is the scene runtime's durable recorder;
its `record_undelivered` is the `undelivered` sink, an in-memory count that never
blocks and does no I/O. An embedder-supplied recorder or sink is then refused.
The lifespan opens the outbox session before it starts scene monitoring; while
the open is refused (for example storage not yet admitted) scene monitoring is
not started, the application reports it `unavailable`, every conclusion stays
`unknown`, and the open is retried until it succeeds. While running, counted
loss is written to the durable gap marker at the flush interval. At shutdown
scene `stop()` returns first; the outbox is then flushed (so a count handed over
at stop reaches the marker even when the session stays open) and closed
cleanly only when `stop()` returned `stopped` and `undelivered_recorded` is not
false. After `stop_failed`, an `unavailable` runtime, a stop that raised or an
unrecorded count, `close()` is never called: the session row stays, the next
start records an interrupted gap and Owner status reports `timeline_gap` until
the Owner clears it. A count handed over after the outbox closed or before it
opened would be refused and only logged; this ordering prevents both. Presence
reports `critical_detection` armed only while the scene runtime is `running`.
With the monitoring runtime configured, a confirmed server movement or camera
tamper notifies the Owner through the monitoring runtime's
`NotificationService` (Issue #26): the same durable `notification_events` row,
keyed by the observation identity, and the same optional immediate Slack
message (`ServerSentinel critical alert: server_movement` / `camera_tamper`,
fixed category only, no image, source, person or cause) as a hardware-integrity
or recording-health failure, in every presence state. A `CriticalDispatcher`
runs `dispatch_pending()` on the monitoring worker every 5 s (Owner decision 2026-10-22; at once again
after a batch in which every row made progress; a failing step backs off
exponentially up to 60 s and is logged value-free); unclaimed work stays
`pending`, and a full or closed notification queue (or, without Slack, a full
local-retry buffer) leaves the row `unavailable` with nothing submitted, retried
by a later step, and ends that action's batch. A step never pins the database
(the outbox open does), so it cannot deadlock the monitoring worker. While
storage is refused a confirmed observation cannot be recorded and waits only
within the scene runtime's bounded critical staging, but its Slack alert is
still attempted like a recording-health alert (Owner decision 2026-10-22,
Issue #318, accepting the duplicate risk): the recorder hands the event ID
and fixed kind to a bounded in-memory queue without blocking (64, overflow
counted and logged value-free; in practice bounded by the 32-observation
critical staging). Once recorded, an observation leaves that queue (its
notification belongs to the dispatcher), and one whose notification row is
still unclaimed is watched, registered inside the record transaction before
its commit (at most 64; an idempotent replay of one already claimed or
resolved is not watched), until a dispatch step claims it,
escalating it when a dispatch step fails (a record just before the disk is
removed, or a row left `unavailable` for queue space). The dispatcher submits these on the monitoring worker at every 5 s
interval, independently of the failing dispatch step's backoff, through the
same `NotificationService` under the observation identity, holding at most
half of its queue (at least one slot; at most 8 attempts per hard stop with
the default 16) so they cannot monopolise it. Owner status reports
value-free `unrecorded_critical_alerts` counts. After recovery the recorded
observation's notification claim joins that delivery or takes its stored
outcome instead of sending again (only an Owner requeue resends); a process
that ends between the attempt and its outcome row may notify a recovered
observation once more, the accepted duplicate. A claimed submission is never retried automatically: `failed`
or `uncertain` outcomes, and claims an earlier process left `submitting` or
`queued` whose `notification_events` row is still `pending` (or absent), stay
unresolved for an audited Owner requeue; a final `sent`/`failed`/`disabled` row
completes such a claim at the next start. Shutdown runs one last step after
scene `stop()`, then drains these alerts once more (a last step refused by
storage escalates the watched records to it), and waits up to 12 s (above the 10 s Slack timeout; configurable to at most 30 s, so that with the other stop steps shutdown stays within `TimeoutStopSec=90`) for submitted deliveries before the
notification service closes. With Slack unconfigured the local row is
`disabled` and `critical_notifications` stays `unavailable`. No
evidence-preservation port exists yet (a separate recording decision), so
`critical_evidence` stays `unavailable` in Owner status, and the production
launcher does not build scene monitoring yet (the deployment section is a
follow-up of #205; the Owner calibration route below exists). Without
`scene_timeline` the count is only logged, as before.

**Owner calibration and restart re-acquisition (Issue #205, Owner decision
2026-10-22, option A).** With `create_app(scene_calibration=...)`
(`SceneCalibrationConfiguration`; it requires scene monitoring with a durable
critical recorder (`scene_timeline` or an injected one; without it the scene
runtime never starts and nothing could be re-acquired) and the
storage-configured monitoring runtime whose `NotificationService` delivers the
Owner notices, otherwise `create_app` refuses the composition, since a notice
could only be logged and dropped) the application owns the scene runtime's
calibration provider: the stored provenance (`roi_calibration_history`, read
only) plus the reference frames this process holds in memory
(`TransientReferences`). Nothing derived from an image is written to disk;
no digest, histogram or statistic of the frame either. The history keeps the
reference geometry, polygon, policy and, since #205, the luma reader (`reader`: the capture layout and decoder pins, such as
`packed:yuyv:1920x1080` or `mjpg:simplejpeg=1.9.0:numpy=2.3.5:1920x1080`;
`decoded:remote_agent` for a decoded-sample producer). A reference is taken
from live frames only by `SceneMonitoringRuntime.acquire_reference()`: the
worker reads the next samples captured after the request through the source's
own luma reader at the reference size, assesses them with fresh `server_roi`
and `camera_tamper` quality gates and takes the first frame both report
`sufficient` (their `recovery_frames` consecutive good samples of one stream);
a camera loss or an unreadable sample restarts that count. The acquisition
fails with a fixed reason (`no_frame`, `quality_insufficient`, `busy`,
`geometry_unsupported`, `unavailable`, `cancelled`) at its deadline, at stop or
when cancelled. A reference the detector refuses (an already obscured scene,
too little support) is `scene_unsuitable`. Normal detection of the source
continues during an acquisition.

- *Owner calibration.* `POST /api/scene/sources/<id>/calibration`
  (`OWNER_OP`, CSRF, step-up; body exactly `{"normal_position_confirmed":
  true}`, the Owner's statement that the camera and the server are in their
  normal position) acquires a reference with the deployment's
  `CalibrationTemplate` of that source (reference size, Owner-selected ROI
  polygon and policy; the template is part of the deployment configuration,
  so a source without one is `template_unconfigured`) within
  `acquisition_timeout_seconds` (default 10 s, at most 30 s) and commits the
  next version's provenance with a `calibrate_scene_source` audit record
  (target `scene_calibration`, the source's logical UUID) in one transaction
  inside `admit` of the authorization's epoch, re-checking the Owner session
  and its freshness there. The acquisition runs after the authorization,
  outside the gate and the transaction; its refusal is a `failed` record and
  `200 {"outcome":"refused","reason"}`. A refusal before the attempt starts
  (`busy`, `template_unconfigured`, a closed service's `unavailable`) reads no
  frame, changes nothing and is the same `200` refusal without an audit
  record. A session that ended, or whose verification went stale, while the
  frame was read commits nothing: the generic denial with a `failed` record
  (the next request of a stale session is the ordinary `403
  step_up_required` before any frame is read). Success is `200
  {"outcome":"calibrated","version","calibrated_at"}`, after which the worker
  re-binds the source. `GET /api/scene/calibration` (`OWNER_READ`) returns per
  configured source `source_id`, `origin` (`none` / `owner` /
  `restart_reacquired`), `version`, `calibrated_at`, `phase` (`idle` /
  `acquiring` / `reacquire_pending`), `failure`, `owner_calibration_available`,
  and the scene runtime's `detection` state and `detection_reason`; never a
  pixel, frame, digest, polygon or policy value. A source with a stored
  calibration reports `reacquire_pending` from the start of Main, also while
  scene monitoring still waits for a deferred start (a timeline outbox open
  that storage has not admitted yet): Main reads the history early to mark
  it, but nothing is re-acquired, refused or notified before the runtime
  runs or has ended (a status that cannot be read counts as ended) (Issue
  #341). A history that cannot be read at that time is reported as
  `reacquire_pending` with `failure` `history_unavailable` (whether a
  calibration is stored is unknown, and the Web says so); the start reads
  the history again, which clears that failure or withdraws the mark when no
  calibration is stored.
- *Restart re-acquisition.* After every Main start, once scene monitoring
  runs, each source with a stored calibration has its reference taken again,
  every source independently and concurrently (at most four), so a camera
  that gives no frame delays neither another source's detection nor its
  notice,
  with the stored geometry, polygon and policy, but only through the same luma
  reader (otherwise `reader_changed`, also for a record written before readers
  were recorded), within `reacquire_timeout_seconds` (default 60 s), committed
  as the next version with a `reacquire_scene_reference` record of actor
  `system` (a failed commit leaves a `failed` record), and the Owner is
  notified at once, right after that source's attempt, through the
  monitoring runtime's `NotificationService`
  (`scene_reference_reacquired`, an immediate kind: the same durable
  `notification_events` row and optional Slack text `ServerSentinel critical
  alert: scene_reference_reacquired`; no source, image or reason). Such a
  reference was not confirmed by the Owner: a camera or server moved while
  Main was down is not detected against it, so the status keeps
  `restart_reacquired` until the Owner calibrates. Detection nevertheless
  starts at once on that reference (Owner decision 2026-10-23: shown and
  notified as not confirmed). A failed attempt leaves the
  source inactive and `unknown`, is retried every `reacquire_retry_seconds`
  (default 60 s), and notifies `scene_calibration_required` once per process
  (not for a runtime that has not started yet, nor at shutdown, when the
  service is closed first; a runtime that started and then stopped or failed,
  or whose start itself ended `unavailable` (it cannot be restarted), so
  that every retry is refused `unavailable`, is notified); an acquisition
  refusal of the
  system path is not an audited change. An Owner calibration ends a pending
  re-acquisition without a notice. A source never calibrated is left alone.
  An unexpected failure of one source's attempt is logged value-free
  (`scene_reacquisition_failed`) and ends neither the other sources' attempts
  nor the retries; a notice whose submission was cancelled or failed is put
  back for the next pass.
  Shutdown cancels an acquisition in flight, then submits a notice an attempt
  queued just before (while the monitoring runtime still runs) and waits up
  to 12 s for a submitted notice; a notice that could not be submitted is in
  memory only
  and logged (`scene_calibration_notice_undelivered`), and the next start
  re-acquires and notifies again.

A camera loss (`offline`, `manual_intervention_required` or `degraded`, that is
every non-`online` state) lowers the source to `degraded` until a new evaluated
sample establishes recovery. A source with no sample evaluated within the
calibration's `maximum_gap_ns` (including a bound source that never received
one) is likewise `degraded` (`observation_stale`) with `unknown` conclusions
until a fresh evaluated sample recovers it. A decoded-sample producer stream
that has been replaced is refused as stale imagery on the capture side
(`stale_rejected`) and never re-admitted under a new runtime identity; the
transition is recorded even when the replacement stream's first frame is sampled
out. Every new producer stream id uses up the retired-stream history (for a
remote agent, every capture restart), while a local UVC loss or reopen does not.
When the bounded retired-stream history (1024 ids per source) is full, further
replacement streams are refused (`stream_history_exhausted`, logged once) rather
than forgetting one; from then on no sample of that source is admitted until
restart and its conclusions are `unknown`, and a camera loss timestamped at or
after exhaustion is untrusted, so it never confirms
`source_loss_after_scene_shift` (a loss timestamped before exhaustion may still
correlate; Owner decision 2026-10-11). A sample still pending when its producer
stream is replaced is discarded as stale (`stale_rejected`). A calibration
refresh waits until a held or just-dequeued camera loss has been handed to the
current detector (reported as `refresh_pending`, which sustained losses can
prolong), and then discards a pending sample captured at or before the refresh
request (`refresh_discarded`). An explicit refresh request still waiting after
`calibration_refresh_defer_ns` (default 60 s, the calibration retry interval,
measured from the first waiting request) sets `refresh_deferred`, lowers the
source to `degraded` (`calibration_refresh_deferred`) with `unknown` movement
and tamper conclusions, and is logged once (Owner decision 2026-10-14); a source
already `degraded` for another reason (such as `critical_backpressure`,
`source_unavailable`, `frame_decoder_failing`,
`frame_decoder_sandbox_unavailable`, `scene_evaluation_failed` or
`observation_stale`) or inactive keeps that reason, with `refresh_deferred`
alongside and `unknown` conclusions. The refresh
still waits for the loss, and the state clears when it runs.

The runtime reports `degraded` while staging holds undelivered evidence, a loss
is held, a recorder call is stalled, or any source is `degraded`; since every
staged observation counts until the recorder accepts it, normal delivery of a
confirmation also shows `degraded` briefly. The runtime status reports
`unavailable` when its worker or delivery thread is no longer running (outside
shutdown), with every source `inactive` and `unknown`, and logs it once; a
worker thread that cannot be started rolls back the delivery thread within a
bounded wait. Shutdown is bounded (worker and delivery each by the stop timeout,
so up to about 10 s by default): a worker or recorder call still running after
its bound is reported as `stop_failed` (with `critical_in_flight`), and the
delivery thread then starts no further recorder call; a call that exceeded the
stall bound is logged as stalled, one merely in flight separately. A delivery
thread that had already died before stop has no call in flight, so the runtime
ends `stopped` with what it left staged counted in `critical_pending` and logged
as undelivered. After stop, staging refuses observations from a worker that
outlived its bound (counted in `critical_refused` and logged) and no conclusion
is republished. After a worker failure the final pass still stages evidence for
queued losses but every source stays withdrawn (`worker_failed`). The
application scene state follows the runtime status while running, so these
conditions report `degraded`, and a failed or dead worker or delivery thread, or
an unreadable status, `unavailable`.

Synthetic tests do not establish physical-camera, lighting, pose, or
source-health behavior.

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

The Issue #25 internal implementation uses a separate private singleton SQLite template store with Owner-only, revision-checked enrollment/replacement/deletion and atomic audit. Generation changes invalidate old/in-flight verification. `OwnerVerificationService.assess` runs the actual immutable candidate crop through its detector-specific gate and binds an opaque assessment to that candidate; source/stream/sequence alone cannot bind distinct face crops. Match receipts require the same issued object, current template generation and current quality assessment. Verifier/model absence, invalid quality or failed comparison is `unknown`. No production face model, weights, threshold, human route or external processing is supplied. See `server/app/detection/owner/README.md` for private-file, local-adapter and export contracts.

### 7.7 Anonymous tracking and entrance

Non-owner observations may use ephemeral anonymous track IDs. Same-camera temporal tracking is allowed. Cross-camera biometric re-identification is not MVP.

Entrance/zone profile may emit anonymous/owner entry-exit observations only when direction/quality conditions are met.

The internal tracker associates geometry only within one camera stream/session, with explicit resource/gap/distance limits. Ambiguity, quality failure, unmatched observations and session discontinuities discard continuity; a finite directed line plus hysteresis requires observed crossing evidence and cancels reversals inside the deadband. Owner crossing additionally needs a current same-candidate/frame verification receipt; otherwise it remains anonymous. Public crossing DTOs omit ephemeral track/session IDs and biometrics. These primitives do not enable presence automation or timeline routes; see `server/app/detection/tracking/README.md`.

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

The Issue #26 internal implementation keeps Owner-control time in a marker separate from source observation time, so one skewed receipt timestamp can neither lock out Owner control nor withhold the suppression an accepted override asks for. Critical movement/tamper work is durably queued, dispatched outside the write transaction, and never retried automatically; every critical path is reported as armed, unavailable or unknown from configured ports, observed storage admission and injected detection health, and any delivery that has not completed keeps its path degraded. Stranded critical work returns to the queue only through an audited Owner-approved resubmission. Timeline pages use main-host receipt order as their single key. Reviewed producer adapters (`server/app/presence/adapters.py`) feed Owner/anonymous entrance crossings, confirmed critical ROI observations, and source/node/storage/recording health states into that timeline as neutral facts; anonymous crossings never affect presence, an unconfirmed Owner crossing makes the Owner observation `UNKNOWN`, and the Owner presence validity and source-latency bound have no default. Each change of an entrance source's gate quality is recorded as a neutral, main-host dated `entrance_gate` fact (`ready` while sufficient, `unknown` with the reported quality otherwise, and `unknown` when the runtime reports that the tracker stopped delivering updates), so a low-light or otherwise undeterminable entrance period stays distinguishable in the `recordings:view` history from a period without crossings; it never asserts absence or names a person. Known or possible timeline loss is reported to the Owner as a durable `timeline_gap`, while facts still staged behind a transient storage, database or clock failure are reported separately as `timeline_pending` / `timeline_pending_count`: they degrade Owner status until written but are not counted as loss. A staged fact whose observation construction fails with a programming error is quarantined rather than blocking every later fact, counted in `timeline_quarantined_count` and `timeline_gap`, logged by event name only, and recorded as lost at a clean close; consecutive transient flush failures are reported as `timeline_flush_failures` and logged when a streak starts, doubles and recovers. Owner status read through another presence service over the same database in the same process sees the outbox backlog; an outbox owned by another process makes the backlog unknown (`timeline_backlog_visible=false`, reported as pending and as a gap) and refuses the Owner gap clear there. Status and history reads take no storage reservation, except any read of a WAL database, which runs under the reservation (and fails closed without it) because SQLite may create or resize the `-wal`/`-shm` sidecars at open even when they were present just before; the application database itself uses a rollback journal, whose reads create no file. The status projection performs no authorization check, and no human timeline, override or audit route may be registered until the Issue #10 boundary lands. See `server/app/presence/README.md` for the port, retention and status contracts.

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

Documented exception: an observation for a confirmed server-movement or camera-tamper event whose critical action (evidence preservation or Owner notification) has not completed is retained past the recording-retention period, including its identity and metadata payload, so unresolved critical work is never discarded as if it had succeeded. No other observation, recording or thumbnail is held back by this exception. It returns to ordinary retention as soon as that action completes or the Owner clears the event through an audited action; clearing releases its payload and delivery rows, preserves action-only degradation markers, and adds an identity-sized tombstone so a replay cannot recreate the cleared work. The exception is bounded by the deployment's shared audit-retention period so unresolved work cannot accumulate without limit. A delivery the deployment durably disabled is the one action that does not hold its observation back: disabling is a configuration decision rather than pending work, so the observation expires on the ordinary schedule while its per-action degradation marker keeps reporting that the action never happened. After expiry an event keeps only an identity-sized tombstone plus, when its action never completed, a per-action degradation marker that keeps the critical path reported as unavailable.

Agent disk-buffer safety is tracked separately from Main Server storage because the two filesystems may be different machines.

The Issue #50 security/admin audit subsystem in `server/app/audit/` is separate
from factual timeline events and owns only its own rows. Every audit write —
success, failure, denial and retention cleanup — passes the deployment storage
admission; the subsystem consumes that reserve and defines no numeric reserve of
its own, and until a deployment binds its storage policy the application refuses
audit writes rather than admitting them against an unverified reserve. Owner-facing
mutations reach the registry, the UVC approval store, the hardware-integrity
baseline and the recording store only through that audited boundary: the registry refuses its own privileged
write wrappers outside explicitly non-runtime fixture use, the recording
browser refuses Owner star/delete without it, hardware baseline approval commits
its new baseline and its audit record in one transaction on the integrity
store's connection, and no unaudited camera approval entry point is exposed.
Human-access invitation, invitation issue, `live:view` / `recordings:view`
grant change and principal/credential revocation run only through the audited
`AccessAdministration` boundary, each committed inside the human composition's
serving gate (`admit(epoch)` of the epoch its `OWNER_OP` authorization was
made under; Owner decision D6, 2026-10-11; Issue #10 S4a); invitation redemption and capture-node
pairing approval, redemption, activation and revocation append their record on
the same transaction as the state change. Non-Owner attempts at Owner-only
operations are recorded as `denied` and do not run; redemption attempts that
match no pending invitation/enrollment record nothing. Retention
computes one cutoff per run and deletes expired rows oldest first in bounded
admitted transactions, so an interrupted run stays consistent, the next run
resumes, and a repeated run deletes nothing more; it never touches recording,
starred, protected-incident or timeline lifecycles. Cleanup runs at startup and
daily; a failed run is visible as degraded retention health and is retried on a
shorter interval instead of stopping monitoring. Audit reading is Owner-only and
records nothing. See `server/app/audit/README.md`.

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
no image/media, source identity or arbitrary probe details (a camera offline
notification, Issue #301, names no source either). Both immediate and
daily notifications enqueue on a bounded delivery worker; the recorder worker
never waits for network IO. Local pending/result events share an ID and are
persisted only on the owning worker. Full queues and failed persistence remain
visible; completion-persistence retry never resends a message. The persisted daily
scheduler defaults to 23:00 configured local time and claims one dispatch per
local date across restart/DST/clock rollback; missed dates are not replayed.
An uncertain crash remains `pending`, failed delivery is visible, and no implicit
retry floods the channel. Human authorization and recording playback remain
separate integration work.

Runtime wiring (`server/app/monitoring/`, Issues #21/#23). The application
lifespan starts a monitoring runtime only when the deployment configuration's
`monitoring` object supplies all of `storage_limits`, `recording_limits` and
`recording_filesystem`. Because the startup/daily hardware integrity check and
daily recording self-test are mandatory, the production launcher (`--check`
and service start) and `python -m app` refuse to run without them, failing
closed and visibly instead of running with those checks absent. An embedded
`create_app()` without them reports the explicit `unconfigured` fault (logged
at error): storage admission stays unbound, audit and other metadata writes are
refused and no worker runs; a partial or invalid object is refused at
deployment validation. When configured, one dedicated worker thread
owns the SQLite connection, `MainStoragePolicy`, the recorder store (bound as
the policy's inventory/reclaimer), the storage state-transition audit
(`storage_state_audit`, 90-day cleanup), notifications, the daily scheduler,
hardware integrity and recording health. Audit writes from other threads (for
example 90-day audit retention) are admitted by parking that worker while it
holds the policy's control reservation through the caller's commit. Each tick
(default 60 s) polls notification completions, re-verifies the recording
filesystem, samples storage state (including other-process consumption), expires
recordings/state audit/fault history, runs the integrity and recording-health
coordinators and the daily summary. A failed step sets a visible degraded flag
and retries after 15 minutes; it never stops the other steps. No production
codec validator exists yet, so the runtime recorder refuses every segment and no
recording pipeline or human route is started. The daily summary marks monitored
duration, source, agent and observation counts `unavailable` while no capture
pipeline reports (service uptime is labeled separately), never presenting zero
observations or process uptime as verified monitoring coverage.

Camera offline notification (Issue #301 item 2, Owner decision 2026-10-22,
`server/app/monitoring/cameras.py`). A configured camera source that stays
not online (`offline`, `degraded` or `manual_intervention_required`) for
`monitoring.camera_offline_notification.after_seconds` (default 300 s, 60 s to
one day) notifies the Owner once per offline episode as the confirmed
`camera_offline` kind through the same `NotificationService`, durable
`notification_events` row and optional Slack delivery as a hardware-integrity
failure. Only `online` ends an episode; a source the Owner disabled
(`disabled`) or whose capture is stopping (`capture_service_stopping`) starts
none, so a service stop never notifies. Every configured source starts not
online, so a camera that never comes up after a start is notified too. The
monitor is fed on the local UVC runtime's health-sink delivery thread (never a
capture worker) and by the application capture watcher's status poll (a worker
that is no longer running is not online, a running worker's latest camera
state starts or ends an episode, so a health event that never reached the
sink cannot hide an outage; a status older than a received event never
overrides it), and is drained on the monitoring worker each tick (default
60 s), also while monitoring is `failed`, so the notification follows the
threshold within one tick. An episode that reached the threshold and recovered
before the drain is still notified once. If it goes offline again while that
notification is still owed, a recovery shorter than `after_seconds` is folded
into the owed episode (notified on the next drain, the count is not
restarted); after a longer recovery the new outage is its own episode with its
own time and ID and the owed one keeps its own (at most one owed episode per
source, an older unsent one is dropped and logged), so a queue that refused
the first alert for a long time never sends a later outage under the old
time. A recovery is recorded in the episode and is not notified. At most `hourly_limit` (default 4, 1 to 60) such
notifications go out per rolling hour for all sources together, re-seeded
after a restart from the confirmed `camera_offline` rows accepted in the last
hour (a `pending` one included: its uncertain delivery holds that slot; an
unconfirmed local observation never counts). The cap is absolute (Owner
decision, PR #339): a restart never sends more than `hourly_limit` in a
rolling hour, also when it resends uncertain deliveries. An episode held back by the
cap is logged once (`camera_offline_notification_rate_limited`) and notified
when the hour allows if the source is still not online, and one that recovered
meanwhile is dropped (`camera_offline_notification_dropped`). An episode in
progress is named after the source and its registry `last_seen_at` (the last
frame time), so a restart during the same outage finds the row and does not
notify again. Only a final row (`sent`, `failed` or `disabled`) counts as
notified (Issue #336): a `pending` row is a delivery whose Slack outcome the
stopped process never stored, which is not confirmed delivery. On the first
running tick the confirmed `camera_offline` rows still `pending` whose event
time is less than 24 hours old are taken, newest event first, at most
`hourly_limit` (the event time never moves when a row is written again, so a
restart loop cannot keep a row eligible; a row whose time cannot be read
counts when it was accepted within 24 hours). Each is submitted again under its
stored event ID and time, whether or not the outage is still in progress, as
an episode that reached the threshold is notified once even if it recovered
before the drain (the row does not name its source, so it opens no alerted
period and is never dropped as recovered). A resend takes a slot like any
notification: one whose uncertain delivery still holds a slot of the restored
hour waits until that slot has expired, so a resend can be up to about an hour
late, and live alerts (outages and ratio alerts of this process) are sent
before resends, which follow in stored-time order. An episode or ratio alert
whose durable name is such a row is covered by it as soon as it is named,
before the cap is consulted, and sends nothing twice. Only the outage in
progress since the service started (each source's first episode) and a ratio
alert (whose name holds only within its window) can be covered: a later
outage of the same process that reuses a restored name (its online
last-frame write was refused), before or after the resend went out, is a new
outage and is notified under a per-process ID (Codex PR #339). A `pending` row found
only by name is submitted again under that name and time, under the same cap.
So when a pending row of the hour still holds its slot and the same outage is
still in progress, the notification of that outage itself waits for the slot
too and can be up to about an hour late, even when the hour has room for
other alerts. Pending rows beyond `hourly_limit` are not restored (counted as
`unrestored` and logged once as `camera_offline_notification_unrestored`);
one of them is resent only when an outage in progress or a ratio alert maps to
it by name, and one whose outage has already recovered is not sent again. For
a restored row, or one found by name, if the earlier POST did reach Slack the
Owner receives the alert twice, never not at all. A pending
row whose event is more than 24 hours old is not sent again (the outage is
named anew after a day). A row of that name accepted more than 24 hours earlier no longer
counts as this outage (Owner decision 2026-10-22, PR #320): the next name of a
deterministic chain (`…:repeat:1`, `…:repeat:2`, …) is used and the outage is
notified again, under the hourly cap; a restart within 24 hours of that
notification still finds it. So when the last-frame time could not be written
during a short online period (for example storage refused it), a later outage
that a restarted process maps to the earlier name is notified once the earlier
notification is more than a day old; within that day it is not (within one
process such a reused ID gets a per-process ID instead). The same rule notifies
again an outage that has continued for more than a day when the service
restarts. Without storage, or for an episode that already recovered, the ID is
per process (at worst one repeat after a restart).

Intermittent outages (Owner decision 2026-10-22, Refs #301: short outages that
repeat must notify too). A source that was not online for
`flapping_offline_seconds` (default 300 s) in total within the last
`flapping_window_seconds` (default 900 s), over at least two separate
not-online periods, is notified as the same confirmed `camera_offline` kind,
fixed text and hourly cap. Only not-online time inside the window counts;
inactive time (`disabled`, `capture_service_stopping`) never counts; a single
outage is left to the continuous rule, so a total below `after_seconds` never
shortens it. Durations use the monotonic clock. The total must be at least
one 60 s tick below the window (two periods always have online time between
them). The interaction rule (Owner decision 2026-10-23, PR #335: one
flapping period yields at most two notifications, the ratio alert and one
continuous notification):

- Every `camera_offline` of a source that was sent (either rule), or that an
  earlier process already stored, opens that source's *alerted period*. One
  dropped under the cap opens none (the Owner was never told). The period
  closes only once the source has stayed online (or inactive) for a whole
  `flapping_window_seconds`; a shorter online keeps it open.
- While the period is open the ratio rule does not notify that source.
- In a period a ratio alert opened, the flapping belongs to that alert. Its
  *flapping episodes* are the outage in progress at the alert and every
  outage that begins after an online shorter than `after_seconds` (the same
  bound as folding a recovery into an owed episode). The first flapping
  episode that stays offline for `after_seconds` is notified once by the
  continuous rule; the episode in progress at the alert counts that time from
  the alert, not from its own start. Later flapping episodes of the period
  are not notified. An outage that begins after an online of at least
  `after_seconds` is an ordinary episode, notified once it lasts
  `after_seconds` as before, however long the period stays open.
- In a period a continuous notification opened, the continuous rule is
  unchanged (one notification per episode); only the ratio rule waits for
  the period to close.
- While a continuous episode of the source has reached `after_seconds` and is
  not yet notified (owed, held by the cap or refused by the queue), the ratio
  rule does not evaluate that source; the continuous notification reports it.
- A ratio alert held back by the cap is sent when the hour allows if its
  period is still open, and dropped (`camera_offline_notification_dropped`)
  once the period has closed; one refused by the queue is retried with the
  same time and ID.

`MonitoringStatus.camera_offline_degraded` is also set while a ratio-opened
period is open. Per source the not-online seconds are kept in at most 130
time bins of window/128; the oldest bin may straddle the window start and is
counted whole, so the total can exceed the true one by at most that bin's
not-online seconds and never falls short of it; the end times of the last two
not-online periods decide the "at least two" condition. Memory is therefore
bounded for any number of configured sources. A backwards monotonic clock
restarts the count for that source (the continuous rule is unaffected). A
ratio alert is named
`uuid5(EVENT_NAMESPACE, "camera-offline-flapping:<source>:<window>:<bucket>")`
with `bucket = floor(trigger wall time / window)`; a restarted process that
triggers again for the source finds a stored alert in the current or previous
bucket whose event time is less than one window old (a future time counts as
recent, an unreadable one as old) and sends nothing, opening the period as if
it had. A new flapping period can only trigger more than a window after the
previous alert of the source (its period first has to close after a whole
quiet window), so this lookup never hides a new period. Known limits after a
restart (the in-memory period does not survive it): a source that keeps
flapping more than a window after its last ratio alert, or after a continuous
alert, may get one more ratio alert; and after a restart that follows a
ratio alert, a flapping episode that stays offline for `after_seconds` is
notified by the continuous rule even when the stopped process already sent
that period's continuous notification (its name follows the last-frame
time, not the flapping alert). One restart can therefore add up to two
notifications: a restart more than a window after the last ratio alert of a
source that is still flapping can send a new ratio alert and then that new
period's continuous notification. All of them stay under the hourly cap. The Slack text is the fixed `ServerSentinel critical alert:
camera_offline`: no source name, role, UUID, device path, serial, reason or
image; the Owner identifies the source in the Web UI. `MonitoringStatus`
reports `camera_offline_degraded` (counted as degraded in the daily summary)
and `camera_offline_notifications`, false without a configured Slack endpoint
(the local row is then `disabled`). Shutdown stops the monitor first and, when
no scene critical dispatcher settles them, waits at most 12 s for a submitted
notification before the monitoring runtime stops. Only `local_uvc` sources are
wired: `remote_agent` sources have no Main runtime yet; `observe()` is the
source-type-neutral entry point for one. The daily summary still reports
source and agent counts as unavailable.

## 10. Host hardware integrity and recording self-check

### 10.1 Hardware baseline

Implementation foundation: `server/app/integrity/` provides explicit read-only
Linux probes, a revision-checked Owner-authorized local baseline, sanitized fault
outbox and startup/24-hour worker coordinator. `server/app/media/health/` provides
bounded recorder-worker temporary I/O and recovery. With configured monitoring
storage (§9), the lifespan runtime runs `IntegrityService.startup()` and the
24-hour tick with the read-only `LinuxProbe`, and `RecordingHealthService`
startup and daily self-tests. Integrity outbox events reach the durable
`notification_events` store through a bridge keyed by a deterministic ID per
outbox row, so redelivery is deduplicated; the outbox row is acknowledged only
after the local row exists. `CHANGED`/`MISSING`/storage-`UNVERIFIABLE` map to
the immediate `hardware_integrity_failure`, other warnings to the local-only
`hardware_integrity_warning`. Recording-health verdicts persist in
`recording_health_status`; `FAILED` is the immediate `recording_health_failure`
and `UNAVAILABLE` the local-only `recording_health_warning`. Human-access faults
(Issue #232 item 4, Owner decision 2026-10-16) use the same immediate path: a
failing `HostnameReservationCheck` or human-access composition is
`human_access_fault` on entering the fault and on a reason not yet reported in
the episode, a passing check while serving is `human_access_recovered`, and a
committed credential finding is `credential_finding`, one immediate
notification per finding up to four per rolling hour, the ones over that cap
batched into one notification once the hour allows (its own budget, outside
the access budget; Owner decision 2026-10-16); at most four `human_access_fault` /
`human_access_recovered` notifications per rolling hour, with a held-back
episode reported later. Both rolling hours continue across a restart: the first running tick re-seeds them from the accepted (non-`pending`) notification rows of the last hour by the wall-clock time since their acceptance (`notification_events.accepted_at`, the row's latest local write, migration 25; a row written before it counts from its event time), filtering the hour before taking the newest rows and ignoring a row stamped in the future, so a restored row counts for at most an hour after the restart (Issue #281 item 2, Issue #287). A notification retried long after its event therefore counts from the retry. When the process started with monitoring `failed` and notified before storage recovered, the stored rows are merged into its window by event ID, so its own rows are not counted twice and the earlier process's rows are not skipped (Issue #287). They set `human_access_degraded` /
`credential_finding_degraded` (the latter for one day after the latest
finding) and carry only the fixed kind. A finding committed before a restart
whose notification had not been sent yet is recovered on the first running
monitoring tick from its audit record: each `credential_finding` event ID
names the immutable id of the newest (highest-rowid) finding audit record it
covers; the newest retained finding
restores the one-day hold and is notified once unless that event row
exists with a final delivery state (rowid order, not wall-clock order).
Several findings committed after the last tick and lost to a crash before
the drain are therefore recovered as one notification, not one each; every
finding stays in the audit log (Issue #281 item 4, Owner decision 2026-10-16
in Issue #287). A notification whose local row was refused and that had not
reached Slack before a crash is not recovered; a persisting fault is detected
again after the restart (Issue #281 item 3, same decision; the critical
notification contract still attempts Slack while local storage refuses). A fault
episode whose newest access notification row is `human_access_fault` continues
after a restart, so its recovery is still announced. Without an actual
capture-pipeline adapter the self-test is an explicit `UNAVAILABLE`, not
healthy. Independently of that adapter, the runtime re-verifies the declared
recording filesystem (UUID → device, mounted mount point, pinned
root device/inode, private metadata file) on every storage sample; a mismatch
is `STORAGE_HARD_STOP`, refuses writes without creating a fallback and raises one
immediate `recording_health_failure` per episode. The recorded major/minor
numbers (`recording_filesystem.device`, `runtime_device`) only corroborate the
UUID: when they no longer name the verified device, storage is admitted,
`recording_device_numbers_stale` is set (diagnostics
`recording_filesystem.state` `degraded`, one degraded item in the daily
summary) and the immediate value-free `recording_device_numbers_changed`
attention notice is sent once per boot and device numbers (event ID from the
kernel boot ID and the numbers; a restart in the same boot finds the row and
sends nothing; without a readable boot ID once per process start). A changed
major, a loop device or a device without a sysfs entry is
`STORAGE_HARD_STOP` at every storage (re)open (Issue #321) and, while the
recorded numbers differ, on every storage sample: the sysfs topology
(hardware-only backing) is walked again each time, so a live dm table reload
or md member replacement onto loop/virtual backing that keeps the device
number and mount refuses the next admission and raises the per-episode
`recording_health_failure`; the refusal is not latched and a return to
hardware-only backing admits again (Issue #340). A refusal seen only by an
admission is kept as one value-free flag that the next tick consumes, so the
episode alerts once even when restored before that tick; `recording_health`
stays `failed` until the next daily self-test. Current numbers read no
sysfs. A mismatch at startup leaves
the runtime `failed`, refuses writes and still attempts the immediate Slack
alert; the open is retried every 15 minutes against the same declared identity
(never another directory), without repeating the alert, and a successful retry
resumes the startup integrity/health checks and admission. The baseline is never written by the runtime; approval remains the
Owner-only audited boundary, and without an approved baseline every check
reports storage `UNVERIFIABLE` (immediate). Slack is optional; local rows and
runtime status persist whether Slack is disabled or fails. Module READMEs
document contracts; #23 physical acceptance remains open.

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

A diagnostic export is optional convenience data, not monitoring evidence. Reserving space for one must not run retention or delete recordings to make room; a deployment without free space refuses the export with its explicit storage state instead. Export size is bounded twice: the implementation caps one selected media item at 512 MiB and a whole bundle at 1 GiB as a defensive upper bound, while the deployment-configured storage maximum request size remains authoritative and refuses anything larger. Selected media is copied in bounded chunks so an export never buffers a whole clip. Only reviewed fixed reason codes, never local values, reach an export caller.

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
- external_identity (optional, supplementary: the verified Tailscale
  login/device last observed at authentication, overwritten each time and never
  an authorization input; not authoritative, see §11.8. Stored but never
  returned or shown, not even to the Owner (Owner decision D14: the shared
  account does not tell people apart), cleared when the principal is revoked
  or deleted, and excluded from diagnostic exports. Per-authentication history belongs to the audit log under
  its own retention, not to this field)

principal_credential
- id
- handle (random UUID naming the credential in the Owner's inventory and in a
  credential revocation, migration 24; it is the only credential name in a URL,
  the path id of `POST /api/admin/principals/<id>/credentials/<handle>/revoke`
  (§11.5), and reveals nothing about the credential; the WebAuthn
  credential_id never reaches a URL, log or audit record)
- principal_id
- kind (WebAuthn/passkey, as accepted in ADR-0004)
- credential_id
- public_key (public material only; never a biometric template)
- user_verification: required (asserted at registration, verified again at
  every authentication)
- sign_count (last accepted signature counter; 0 when the authenticator keeps
  none)
- backup_eligible (the authenticator's BE flag, fixed at registration; a
  backup-eligible credential can sync to the person's other devices)
- backup_state (the authenticator's BS flag as of the last verified ceremony;
  refreshed on every accepted assertion, because a credential can be backed up
  after it was registered)
- status: active/revoked/inconsistent
- inconsistency_reason (owner-visible fixed reason code; currently
  `backup_eligibility_changed`, null unless status is inconsistent)
- inconsistent_at
- label (owner-visible hint, not proof of a device)
- created_at
- last_used_at
- revoked_at

principal_enrollment
- id
- principal_id
- code_hash (of a CSPRNG value with at least 128 bits of entropy; the raw
  enrollment code is never stored or logged, and comparison is constant-time)
- expires_at
- redeemed_at (single use)
- attempt_count (bounded; redemption is rate-limited per code and per source)

principal_session
- id
- principal_id
- credential_id (the credential that created the session)
- external_identity_binding (optional HMAC-SHA-256 of the canonical verified
  proxy identity, using a deployment-local secret stored outside the database;
  the raw identity is not copied into the session. A later request is compared
  in constant time against a freshly computed binding)
- created_at
- last_seen_at
- idle_expires_at / absolute_expires_at (server-enforced)
- last_user_verification_at (freshness source for owner step-up), with the
  kernel boot id and CLOCK_BOOTTIME read in the same transaction (migration 23)
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
that created it. Where the deployment supplies a verified proxy identity, the
session stores only the keyed binding described above. Each later request
canonicalizes the newly verified identity, recomputes the binding and compares
it in constant time; a mismatch is refused. The deployment-local HMAC secret is
kept outside the database and is unrelated to Tailscale administrative
credentials. The refusal applies to that request only: the session is not
revoked or moved to step-up on a mismatch, since under the shared account a
mismatch cannot identify anyone. The mismatch is audited without any identity
or binding value, at most once per session per ten minutes with the remainder
counted on the session, and an audit failure still denies (Owner decision,
2026-09-30; details in `server/app/auth/README.md`). Invitations carry no proxy
identity, and `external_identity` is neither unique nor compared with the
supplied identity: the enrollment code selects the invitation and the
credential selects the principal, so several people behind one shared login
each register and sign in with their own passkey. Sign-out, idle/absolute expiry and revocation clear the binding and
invalidate the record, so a retained cookie or token authorizes nothing
afterwards; the binding is never shown in the UI or included in diagnostics or
exports. §11.5
authorization re-checks it on every human/media route and never relies on
client-side state. Idle and absolute lifetimes are server-enforced, with the
values proposed in ADR-0003 (30 minutes idle, 12 hours absolute) and any change
recorded there before implementation; an explicit sign-out is available for shared machines, and
owner-only routes require a fresh user-verification step rather than an older
session.

User verification runs on the viewer's own device, and its result reaches the
server only as the authenticator's user-verification flag. The WebAuthn protocol
data needed to check a registration or assertion — the server-issued challenge,
client data, authenticator data, the signature counter and the user-verification
flag — is received and verified, including the relying-party id and origin.

Signatures are checked where the ceremony carries one. An assertion always does,
and its signature is verified against the stored public key. A registration
carries an attestation statement only sometimes: the common privacy-preserving
`none` format has none, and such a registration is accepted — the challenge,
origin and relying-party id, authenticator data, credential public key and
user-verification flag are still verified. Where an attestation statement is
present its format is verified; a present but invalid statement fails
registration. That data is transient: the pending
challenge is held server-side only for the bounded lifetime of one ceremony, is
single-use and is dropped when the ceremony ends or expires; of the rest, only
the fields of `principal_credential` and `principal_session` persist and
everything else is discarded once verified.

The signature counter is the one verification output that persists, as
`principal_credential.sign_count`. The comparison applies whenever either the
stored counter or the received one is non-zero: the received value must then be
strictly greater than the stored one. Anything else is a regression — including
a received 0 after a stored non-zero, which is a reset or cloned authenticator,
not an exemption — and a regression refuses the assertion and notifies the Owner
as a possible cloned authenticator. The stored value advances only on an
accepted assertion.

The single exempt case is an authenticator that keeps no counter at all: stored
and received both 0. Many passkey authenticators behave this way, and it is not
evidence of cloning.

None of this material belongs in logs, diagnostics or exports: challenges,
client and authenticator data, signatures, and enrollment codes are excluded
alongside the other sensitive values of §13, and a failed verification is logged
as a typed outcome without the payload that failed.

What never reaches ServerSentinel is biometric material. No fingerprint or face
template leaves the authenticator, so none is received, persisted or exportable
here. `principal_credential` is an access-control record, unrelated to the
optional owner face verification of §7.6 and never a non-owner identity or
biometric database (see `PRIVACY.md`).

Relying-party verification depends on ServerSentinel owning its browser origin.
Per AUTH-012 the dashboard is served from an origin reserved for it, with no
other application sharing it; a co-hosted application on that origin would put
the credential within its reach.

The reservation itself is a deployment obligation, stated in full in §11.9 and
ADR-0003: the name serves ServerSentinel alone on every scheme and port. The
application verifies it at startup and at least daily by enumerating the host's
real listeners and every proxy route for that name, re-resolving the name on
each check, and closes human access and notifies the Owner on any other answer
it can see,
a resolved address set that differs from the recorded one, or a check that
cannot be completed. Reopening after an exposure reason (another listener or
route, a changed address set, a listener/route enumeration failure) first
revokes every human session; a hostname resolution failure alone keeps access
closed and reopens without revocation once the name resolves to the recorded
set again (Owner decision, 2026-10-01; details in `server/app/auth/README.md`).
An Owner listener exception covers a wildcard system listener only by port
plus creating systemd unit (`.service` or `.socket`) and uid, verified on every
check through an unprivileged `NETLINK_SOCK_DIAG` `inet_diag` dump of the
socket's creating cgroup (`INET_DIAG_CGROUP_ID`, matched to
`/sys/fs/cgroup/system.slice/<unit>`) and uid; a socket created by another unit
or uid is an exposure reason (`UNEXPECTED_LISTENER`) once an immediate second
dump in the same check confirms it, and stored port-only or executable-path
exceptions fail closed (`LISTENER_EXCEPTIONS_OUTDATED`) until re-entered (Owner
decisions, 2026-10-01 and 2026-10-07). The only exception that covers a bind
directly on a reserved address is a `reserved_address` exception for
`tailscaled.service` with uid 0 over TCP on one recorded port other than the
dashboard, upstream and proxy ports (its plain-HTTP peerAPI; Owner decision
D1, 2026-10-16, ADR-0003); it covers only the configured reserved addresses,
at most one such exception covers each family (Issue #278), and it is
verified the same way. The Owner records the set with the local command
`python -m app.auth.reservation_cli show|set --config <deployment.json>` (Owner
decision D3, 2026-10-16): run as the service account with the same checks as
`bootstrap_cli` (no root, the configuration's service uid, a controlling
terminal, the pinned existing database of exactly the current schema), it
validates the set against the reservation the deployment's `human_access`
section states (`HumanAccessDeployment.reservation_config()`, the one the
service's check uses), reads the word
`CHANGE` from the terminal and commits the set with its
`change_security_setting` audit record (actor `owner`, the fixed
listener-exceptions id) in one transaction; the running service applies it
only after a restart. Each recorded proxy socket requires a
recorded proxy identity (`proxy_owner`: systemd unit and uid) and must be
present and created by it: a missing recorded socket keeps access closed
without revocation, and another creator is an exposure (Owner decision,
2026-10-01). Ownership that cannot be verified
(`LISTENER_OWNER_UNVERIFIED`: no socket-owner resolver, a sock_diag or cgroup
lookup that is unavailable, times out or fails its self-check, a socket in
`/proc/net` but not in the dump, a creating cgroup that cannot be resolved —
deleted, the root cgroup or `/init.scope` — while the socket's uid is one of the
expected identities' uids, `/init.scope` with uid 0, a mismatch the second dump
does not confirm, another upstream holder not seen in all three scans of the
same check (about 100 ms apart; a child between `fork` and `exec`, Issue #160), a kernel-owned socket (inode 0), an upstream port at or above `ip_unprivileged_port_start`, or an
unreadable own or unit descriptor table) is not an exposure reason: it keeps
access closed without revocation and access reopens once ownership verifies
again (Owner decisions, 2026-10-05 and 2026-10-07, superseding the 2026-10-01
wording that treated an unverifiable owner or holder as an exposure). The
socket-owner resolver (`app.auth.sock_diag.SockDiagOwners` in production) is
mandatory; a check without one never opens access. A human upstream created
in `/init.scope` by uid 0 (systemd listening from PID 1 on a host without
cgroup-BPF support) closes access with its own reason,
`UPSTREAM_CREATED_IN_INIT_SCOPE`, also without revocation (Issue #157).
sock_diag reports the
creator, not the current holder (residual risk accepted by the Owner,
2026-10-07). An unresolved creating cgroup with a uid none of the expected
identities has counts as another creator (`UNEXPECTED_LISTENER` once the second
dump confirms it; Owner decision, 2026-10-07). A unit matches a socket created
in `/system.slice/<unit>` or below nested system slices
(`/system.slice/system-cups.slice/cups.service`).
The check sees only sockets in `/proc/net` and Serve status. Traffic the kernel redirects before it reaches a listening socket on the reserved address — nftables/iptables DNAT or REDIRECT (for example Docker with `userland-proxy=false`), TPROXY, eBPF `sk_lookup` or IPVS — is not visible to it, so it cannot claim that nothing else answers; the deployment isolation must exclude such forwarding, and the Owner verifies it manually.
The loopback human upstream is created by systemd socket activation
(`server-sentinel-upstream.socket`, `ListenStream=` a loopback port below 1024,
`ReusePort=no`) and passed to the unprivileged backend (`LISTEN_FDS` /
`LISTEN_PID`). It passes only as a socket in the ServerSentinel process's own
`/proc/self/fd`, created in that socket unit's cgroup by uid 0, on a port below
`ip_unprivileged_port_start`, and held by no other process of the
ServerSentinel unit's cgroups (a same-uid `/proc/<pid>/fd` scan); a single
replacement bound by any other process, a confirmed other creator, or the
socket shared with another process is an exposure. A check without a durable
session revoker never opens access.
That bounds the exposure window rather
than preventing the bind: a process that binds between two checks receives
credentials and cookies for that origin until the next check.

The origin is the reserved `https` origin, which viewer devices outside the
Main Server reach by URL — for example the Main Server's tailnet hostname
served through Tailscale Serve to Tailscale-joined viewer devices. It must be a
secure context because browsers expose WebAuthn only there; plain HTTP on a
non-loopback host leaves every human route unreachable in practice, since
nobody can register or authenticate. `http://localhost` is not a human
dashboard origin: the human composition accepts only the reserved `https`
origin, and there is no `http://localhost` Owner route (Owner decisions,
2026-10-11 and 2026-10-16, see `SECURITY.md`). Reaching the URL is a network
precondition, not identification; the invitation and per-person WebAuthn
credential are still required.

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

"Fresh" means a user verification newer than a bounded freshness window — ADR-0003
proposes five minutes — so an older or unattended owner session cannot perform an
AUTH-008 operation by itself. Freshness is evaluated server-side from
`principal_session.last_user_verification_at`; a client cannot assert it.

The main-to-Web contract for the step-up is explicit, because the dashboard has
to know when to prompt:

```text
owner route, session fresh      -> the operation runs
owner route, session stale      -> distinct step_up_required response, no other data
step-up challenge               -> issued for the session, allowing only
                                   principal_session.credential_id
assertion by that credential    -> last_user_verification_at updates; client retries
assertion by any other credential-> refused; freshness unchanged
retry                           -> permission and freshness re-checked server-side
step-up cancelled/failed        -> generic failure; nothing executed, nothing changed
```

The step-up is bound to the session, not merely to the deployment. The challenge
is issued for that `principal_session`, its allowed credential list contains only
`principal_session.credential_id`, and the assertion is accepted only when it
comes from that still-active credential of that same principal. An assertion
from any other registered credential — including a valid one belonging to
someone else who is standing at the same workstation — is refused and leaves
`last_user_verification_at` untouched, so a second person cannot refresh a stale
owner session with their own passkey. If the session's credential has been
revoked, the session is invalid and no step-up can revive it.

The `step_up_required` signal is returned only to an already authenticated
session that holds the required permission. Anything unauthenticated, uninvited
or revoked still receives the generic response below and learns nothing about
owner routes. Repeated failed step-ups are rate-limited and logged without
credential material, and a stale session never partially applies an operation.

Implementation (Issue #10 phase 2 S3, Owner decision D3): `POST
/api/auth/step-up/options` (empty body or `{}`) returns only `challenge`,
`rpId`, `timeout`, `userVerification: "required"` and `allowCredentials`
holding exactly the session's credential; `POST /api/auth/step-up` (the JSON
assertion) answers `204` with no body. Both require an Owner session
(`OWNER_READ`, fresh or stale; Owner decision 2026-10-12), the exact `Origin`
and `X-CSRF-Token`, are charged before the body is read to their own
per-source limiter (Owner decision 2026-10-12: keyed by the verified proxy
identity, burst 5, one per 12 seconds, no global bucket, never the sign-in or
redemption limiter object), and commit under the
epoch their authorization took; a non-Owner or anyone without a valid session
gets the generic `404`. Neither step-up route extends the session: their
authorization makes every session check (idle and absolute expiry, identity
binding, CSRF, Owner role) but commits no idle touch, and only a successful
step-up moves `last_seen` and the idle expiry, in the transaction that
refreshes the verification time (PR #236 review). Repeated options requests
or failed finishes therefore cannot keep an unattended Owner session alive
past its 30-minute idle limit. A new options request replaces the session's pending
step-up challenge. "Fresh" is exactly five minutes from the verification time
read inside the commit transaction (sign-in or step-up), on the wall clock and
on `CLOCK_BOOTTIME` of the same boot, with the wall clock lagging the
monotonic clock by at most one second: a wall clock stepped back after the
verification, a reboot, a session without a recorded pair (established
before migration 23) and an unreadable boot clock are stale (fail closed,
Owner decision 2026-10-12), and a step-up is refused while the boot
clock cannot be read. A finish refused by the session gate (stop, failed
check tick or close/reopen during verification) is a no-op that leaves the
challenge pending, a credential finding (BE change, counter regression)
included; every other refusal after the client data parsed spends the
challenge, but only one bound to the refused request's own current session
(Issue #238 item 4: another session of the same Owner cannot spend it, and a
request without a current session spends nothing). A successful step-up deletes the challenge in the SQLite transaction
that refreshes the session (a refused commit rolls the deletion back and the
refusal then spends it on its own). A credential finding commits inside one
gate admission and one SQLite transaction that first deletes this session's
pending step-up challenge and writes the finding and its audit record only if
that DELETE removed the unexpired row; the Owner is notified only after that
commit, so one challenge yields at most one finding and notification. If the
DELETE removes nothing (a concurrent finish of the same answer spent it first
and may have advanced the counter, or a new options request replaced it), nothing is recorded or
notified and the finish is refused. If the transaction fails, the deletion
rolls back with the finding, and the challenge is spent on its own under a new
gate admission: it stays single use, and the unchanged stored credential lets
the next assertion detect the finding again; such a failed finding write (at
step-up or sign-in) is counted value-free (`credential_finding_unrecorded`
logged on the first and each doubling, Issue #238 item 5). A changed backup
eligibility that another session's step-up or a sign-in already marked spends
the challenge but records and notifies nothing more, so the Owner is notified
once (Issue #238 item 2). Refused finishes are counted value-free
(`owner_step_up_refused` logged on the first and each doubling). The first
mounted `OWNER_OP` routes are the S4b administration routes below.

Owner access administration (Issue #10 phase 2 S4, Owner decisions S4-1 ..
S4-8, 2026-10-13; S4a implements the store and administration, S4b the
routes, S4c the local `list` / `revoke-principal` / `revoke-credential`
commands, S6 the Web screen):

```text
invite / re-issue code / change permission /
revoke principal / revoke credential      -> OWNER_OP (owner + fresh user verification)
list principals, grants, codes, credentials -> OWNER_READ
step_up_required answer                    -> no idle touch (the session is not extended)
Owner principal as the target             -> refused (only the local recover changes it)
grant change that changes nothing         -> no revision bump, no session ends; one
                                             succeeded record ("requested, no change")
real grant change                         -> that principal's sessions end; its pending code stays valid
re-issue                                  -> other unused codes revoked, one new code (invited or active)
more than 64 non-revoked principals,
or a second pending code                  -> refused with the generic denial
```

Each mutation commits inside `admit(epoch)` of the epoch its `OWNER_OP`
authorization was made under, and re-reads the Owner session inside its own
SQLite transaction (the local recover and revocation commands commit outside
the gate): a session ended, a credential revoked, a recovery, an expired
lifetime or a verification no longer fresh since the authorization makes it
a failed operation that changes nothing. An invitation commits the
principal, its grants and its single code together, with the
`invite_principal` and `issue_principal_invitation` records; its expiry is
the in-transaction time plus the deployment's `invitation_lifetime_hours`,
and the application refuses a composition whose store has another lifetime.
The inventory returns per principal its id, display name, role, status,
times, permissions, a pending-code summary (pending, expires_at) and per
credential its handle, label, status, inconsistency reason, backup flags and
created / last-used / revoked times; never the last observed proxy identity
(D14), a credential id, public key, counter, digest or session data.
"Pending" there and in the one-pending-code limit is one definition: exactly
the conditions a redemption checks (unredeemed, unrevoked, a lookup key,
fewer than five attempts, the principal not revoked, its current
authorization revision, the current deployment generation, and the
invitation clock check on both clocks with a recorded boot pair; Issue #240).
A code failing any of them is not pending and does not block a new one, and
issuing a code marks every other unused code of that principal revoked in
the same transaction, so at most one code can ever become redeemable. The
attempt bound limits starting a redemption, not finishing one: the challenge
issued by the fifth attempt stays usable until it expires, so that attempt can
still complete the enrollment although the code is no longer shown as pending.
This is safe: the challenge is single use and bound to that invitation, the
finish re-checks every other condition, and no further challenge can be
obtained for the code. A grant
change that changes nothing still writes one `change_principal_permissions`
record with outcome `succeeded`, meaning "requested, no change"; the audit
vocabulary has no separate outcome for it.

Routes (S4b; `<id>` and `<handle>` match only the canonical lower-case UUID
form, the raw path must equal the decoded one, and the handle is a random
administration name, never the WebAuthn credential id):

```text
GET  /api/admin/principals                                   OWNER_READ
       -> 200 {"principals": [inventory entries]}
POST /api/admin/principals                                   OWNER_OP
       {"display_name": 1-64 chars, "permissions": [distinct live:view / recordings:view]}
       -> 200 {"principal_id", "code", "expires_at"}   (the only time the code is shown)
POST /api/admin/principals/<id>/invitation                   OWNER_OP  {}
       -> 200 {"code", "expires_at"}                   (other unused codes revoked)
POST /api/admin/principals/<id>/permissions                  OWNER_OP
       {"permission": "live:view" | "recordings:view", "granted": true | false}
       -> 204                                          (a delta)
POST /api/admin/principals/<id>/revoke                       OWNER_OP  {} -> 204
POST /api/admin/principals/<id>/credentials/<handle>/revoke  OWNER_OP  {} -> 204
       (credential-scoped: on all synced devices that hold the passkey)
```

Each change needs the exact `Origin` and `X-CSRF-Token`; its body
(`application/json`, bounded, one object with no duplicate or extra member) is
validated before the authorization, which runs inside `admit(epoch)`, and the
change commits through the administration inside `admit` of the same epoch.
The inventory read runs inside `admit` of its authorization's epoch and
re-checks the Owner session in its own read transaction before reading
(without the freshness requirement and without an idle touch), so a local
recover or revocation after the authorization returns nothing. Every
response is `no-store`. Every refusal is the generic `404` — anyone but a
current Owner session, a missing or wrong CSRF token or `Origin`, another
proxy identity, a closed or stopped surface, a bad path id, an unknown,
revoked or Owner target, another principal's handle, a malformed body, a
limit, or a change refused at the commit — except `403 step_up_required` for
an otherwise valid but stale Owner session on a change, decided by the
authorization with no state change and no idle touch. The changes A2-A6
are charged to their own per-session rate limiter (Owner decision
2026-10-13: a burst of 20, one more every 3 seconds, no global bucket, a
bounded table of 256 sessions), keyed server-side on a digest of the session
token after the read-only session pre-check and before the gate or any
SQLite or audit work; over the limit the change is the generic `404` and
writes nothing, no audit record included. For A2-A6 that pre-check also
requires the session's principal to be the active Owner (PR #242 review), so
a non-Owner session is the generic `404` before it is charged and can never
take a limiter slot or lock the Owner out; the role is still decided
authoritatively inside the gate. A stale Owner's `403 step_up_required`
consumes one token. The inventory read is not charged.

Exactly two HTTP routes run before a credential exists, and the pair is closed.
Owner bootstrap is not a third one: it is a local action on the host that feeds
the same redemption route.

```text
invitation redemption      -> valid, unexpired, unredeemed enrollment code only,
                              including the owner's bootstrap authorization
credential authentication  -> the assertion route itself

local owner bootstrap      -> not a route: a privileged local action on the main
                              host that issues an enrollment authorization shown
                              only on the console
```

Owner bootstrap is a privileged local administrative action on the Main Server
that issues a single-use, short-lived enrollment authorization displayed only on
the local console; the first owner redeems it once from a browser at the
reserved origin through the redemption path, so no owner-specific route and no
remote first-visitor setup exist. Invitation redemption is single-use and
rate-limited and registers exactly one `principal_credential` for the named
principal.

Single use is enforced atomically, not by a check followed by a write. Marking
`principal_enrollment.redeemed_at` and inserting the credential happen in one
transaction whose update is conditional on the row still being unredeemed and
unexpired, so of two concurrent redemptions of the same code exactly one
succeeds and the other receives the same generic response as an unknown code,
with no second credential and no partially applied state. A retry after a lost
response is idempotent in the same way: either the ceremony completed and the
code is spent, or nothing happened and the code is still redeemable until it
expires. `attempt_count` is incremented in the same conditional update so
concurrent guesses cannot slip past the rate limit.

Both the invitation code and the bootstrap authorization are bearer
authorizations on a path every holder of the shared account can reach, so both
come from a cryptographically secure random generator with at least 128 bits of
entropy. A friendlier encoding may be used for reading a code aloud or typing it,
but the entropy floor applies to the value actually checked, not to a shortened
display form, and the comparison is constant-time against `code_hash`. Lifetime,
single use and rate limiting bound how long and how often a guess may be tried;
they are not a substitute for the entropy. It returns no camera, recording, timeline or deployment data and
grants no application access by itself: the invited person then authenticates
like anyone else. An absent, unknown, expired or already-redeemed code receives
the same generic response as an uninvited person, and logs record the attempt
without the raw code. Every other human/media route requires a verified
credential and an active session.

Implementation (Issue #10 phase 2 S2, Owner decisions D4/D5 of 2026-10-11):
`POST /api/auth/registration/options` (body `{"code"}`) and `POST
/api/auth/registration` (body `{"code", "credential", "label"?}`, `204` with no
body and no cookie). A code is 160 CSPRNG bits shown as 32 Crockford base32
characters in eight groups of four (`XXXX-XXXX-…`), checked by the SHA-256 of
all 160 bits (found by a separate non-secret lookup key, the digest compared
with `hmac.compare_digest`) and single use; the server accepts only the exact
canonical form. Its lifetime is the deployment key `invitation_lifetime_hours`
(integer 1-168, default 24; Owner decision 2026-10-11). Each invitation also
records the kernel boot id and `CLOCK_BOOTTIME` at issuance: on the same boot
it is refused once the monotonic elapsed time reaches the lifetime, when that
elapsed time is negative, and when the wall clock lags it by more than 30
seconds (a rollback); after a reboot the wall-clock window decides, and the
generated Main unit is ordered after `time-sync.target`, so with an enabled
wait service this is a synchronized clock unless the host fails to
synchronize within that service's start limit (chrony-wait: 180 s), after
which the service starts unsynchronized as before (Issue #235 item 4, Owner
decision 2026-10-14; `server/docs/DEPLOYMENT.md`); a row or
host without the pair is refused (fail closed). Redemption has its own
per-source limiter keyed by the verified proxy identity (burst 5, one per 12
seconds) and no global bucket (Owner decision 2026-10-11), charged before the
body is parsed or any lock is taken, on top of the per-code bound of 5
attempts. A refusal after the limiter is counted value-free
(`invitation_redemption_refused` logged on the first and each doubling).
Every refusal is the generic `404`; the only other answer is the fixed `409
{"detail":"device_bound_credential_required"}`, decided inside the
redemption transaction only after the invitation proved valid and bound to
the consumed challenge, under a device-bound deployment policy. The local
bootstrap/recovery command is `python -m app.auth.bootstrap_cli
bootstrap|recover --config <deployment.json>` (`server/app/auth/README.md`,
`server/docs/DEPLOYMENT.md`).

Unauthorized users get no ServerSentinel deployment metadata, camera names/counts, thumbnails, event details, or recordings. For an uninvited identity, prefer a generic/non-branding denial such as a not-found-style response and do not expose product/version headers, API schema, health details, or other ServerSentinel fingerprints. This does not claim that the underlying Tailscale node/service is network-invisible when Tailnet policy is unchanged.

### 11.6 Browser-only recording access

No official non-owner recording download/export route/button in MVP. Playback manifests/segments remain authorization-protected and short-lived/session-bound as practical; a copied URL does not become public.

This is not DRM. A user who can view video may still screen-record or use advanced client tooling, and the UI/docs must not claim otherwise.

### 11.7 Revocation

ServerSentinel permission revocation invalidates application access promptly. Tailnet membership/policy remains a separate Tailscale administrative concern.

Revocation is credential-scoped, not device-scoped. Revoking a single `principal_credential` invalidates that credential and the sessions bound to it; revoking the `access_principal` invalidates all of its credentials and active sessions.

A synced passkey is one credential that can exist on several of its owner's devices, so revoking it disables it everywhere it synced, and losing one device does not by itself isolate a credential to revoke. The UI and documentation therefore describe revocation as credential-scoped and treat the label as a hint.

Emergency revocation while human access is closed (Owner decisions D6 and S4-6, Issue #10 phase 2 S4c) is local: `python -m app.auth.bootstrap_cli list|revoke-principal|revoke-credential --config <deployment.json>`, run over SSH as the service account with the same checks as `bootstrap`/`recover` (no root, the configuration's service uid, a controlling terminal, the pinned existing database of exactly the current schema). `list` prints principal logical UUID, role, status, grants and display name and credential handle, status and label, never the proxy identity (D14), credential ids, keys, counters, digests, sessions or codes. Each revocation reads the word `REVOKE` from the terminal and commits the same store mutation as the Web route with its `revoke_principal` / `revoke_principal_credential` audit record (actor `owner`, the principal's logical UUID only) in one transaction, outside the gate (it only reduces access; the serving process re-reads principal, credential and session inside each request's transaction, so the next request is denied). The Owner is never a target (S4-3, `recover` only). The procedure is in `server/docs/DEPLOYMENT.md` and `server/app/auth/README.md`.

Registration reads the authenticator's backup-eligibility and backup-state flags
and stores them as `principal_credential.backup_eligible` / `.backup_state`, so
the owner UI can show whether a credential can sync instead of guessing. A
deployment that needs device-scoped control refuses a backup-eligible
registration on that signal and tells the person why, which is a deployment
setting rather than a promise the product makes by default. The Web client
surfaces that refusal as an actionable message, not as a generic failure.

The two flags age differently. Eligibility is a property of the credential and
does not change, so a later assertion reporting a different BE is an
inconsistency: in the same transaction the assertion is refused, the credential
is marked `inconsistent` with reason `backup_eligibility_changed` and timestamp,
and every session bound to it is revoked. The Owner is notified and the UI shows
the reason and recovery action. An inconsistent credential never authenticates
or performs step-up again; the Owner revokes/replaces it, and a non-owner left
with no usable credential is re-invited. If the Owner has no other usable
credential, recovery uses ADR-0003's privileged local bootstrap path rather than
leaving the deployment inaccessible. Automated tests cover the transaction,
session invalidation and both recovery branches. Backup state does change — a credential
registered before its first sync becomes backed up afterwards — so every
accepted assertion refreshes `backup_state` from the verified authenticator
data. Recording it only at registration would leave the owner UI saying
"not backed up" for a credential that has since synced.

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

### 11.9 Owner bootstrap and session decision status

[ADR-0003](docs/ADR/0003-owner-authentication-and-trusted-proxy.md) records the
Owner-approved human-access design for Issue #6. Its 30-minute idle and 12-hour
absolute session lifetimes are product defaults; sessions fail closed when time
regresses before establishment or the last accepted activity. Until Issue #10
implements the full boundary,
the backend shell denies human requests, including application assets,
health/version/schema, and SPA/error fallbacks. Issue #8's static shell remains
a development/mock artifact until integrated with this protected delivery path.
The ADR's synthetic design model proves only policy composition, not deployed
proxy, session, cryptographic, or browser behavior.

The proposal also reserves a whole hostname: that name serves ServerSentinel
alone on every scheme and port. Path-based co-hosting shares one browser origin,
and another port of the same name still shares the cookie scope because cookies
are not port-scoped, so neither is supported. Holding the name is a deployment
obligation (a dedicated network identity, or a single-purpose node enforced
outside the application), because a directly bound listener never appears in
proxy configuration; the application's startup and daily listener/route checks
close access when another answer is found, which bounds the exposure window
instead of preventing the bind. Owner bootstrap also provisions the Owner's
first per-person credential through the local administrative boundary, since no
session exists without one. A verified trusted-proxy identity stays a supplementary check
there; the authoritative per-person application credential is decided separately
for Issue #6, by §11.8 and ADR-0004: a per-person WebAuthn credential, which is
the credential that local bootstrap provisions and that a session is bound to.

Issue #10 phase 1 (human route foundation) and phase 2 S1 (gated
authorization, CSRF, sign-out) define the first main-to-Web contract, opened
only by an explicitly enabled composition behind a fully configured
reservation check (the production launcher builds one only from an enabled
`human_access` deployment section):

```text
POST /api/auth/authentication/options -> pre-credential, rate-limited;
                                         discoverable-credential request options
POST /api/auth/authentication         -> pre-credential, rate-limited; 204 and
                                         __Host-session cookie, no data
GET  /api/session                     -> credential-backed session; the caller's
                                         own {"csrf", "role", "permissions"} only
POST /api/auth/sign-out               -> session + exact Origin + X-CSRF-Token;
                                         204, the cookie cleared (Max-Age=0),
                                         audited as sign_out_principal
anything else                         -> generic not-found denial
```

Routes come from one table: an exact method, a strict path (no re-encoded
spelling), a strict per-route query allowlist (no S1 route accepts a
parameter) and a server-side requirement (`SESSION`, `LIVE`, `RECORDINGS`,
`OWNER_READ`, `OWNER_OP`, or `PRE_CREDENTIAL` for the two ceremony routes).
Every request first needs the reserved `Host`/`Origin` (absent `Origin` only
for `GET /api/session`; every mutating route requires it), a loopback
transport peer and local address, exactly one canonical trusted-proxy login,
an open reservation verdict and a serving composition. A session route then
takes the gate epoch and commits its authorization (and the request's later
writes) inside `admit(epoch)`, so a close, or the composition stopping, after
the epoch refuses it before anything is written. A mutating session route
requires `X-CSRF-Token` equal to the session's token,
`HMAC-SHA-256` under a subkey derived from the session-binding key with its
own domain label (Owner decision D2), compared in constant time. Every
refusal is the same generic denial, except the fixed
`403 {"detail":"step_up_required"}` for an otherwise valid but stale Owner
session on an `OWNER_OP` route (Owner decision D3). Sign-out invalidates the
server-side session and its binding with a `sign_out_principal` audit record
holding only the principal's logical UUID (D7); it ends that session, not the
credential, and is refused while human access is closed. Invitation
redemption (S2), the Owner step-up (S3) and the Owner access administration
(S4b, §11.5 above) are mounted, and so are the S7 interim live routes
below; all recording/timeline routes and the other admin routes are later
phases. Details: `server/app/auth/README.md`.

Issue #10 phase 2 S5b serves the Web build through the same surface (Owner
decisions D1 and S5-1 .. S5-5; the reservation check accepts exactly one Serve
proxy route, to the backend, so there is no static host):

```text
GET /, /s.js, /s.css        -> pre-credential sign-in shell; only the route,
                               Host/Origin, loopback-peer, one-identity,
                               reservation and serving gates; no cookie,
                               session, SQLite, lock or rate limiter; the same
                               bytes for every caller who passes them
GET /app/, /app/<name>      -> any active session (SESSION, no permission,
                               authorized inside admit(epoch), touch=False:
                               never extends the idle expiry); <name> fully
                               matches [A-Za-z0-9][A-Za-z0-9.-]{0,63}, selects an
                               in-memory entry, a miss is the generic denial
```

The bytes come from `WebAssets.load(Settings.web_assets_dir)` at composition:
`manifest.json` lists exactly `shell/index.html`, `shell/s.js`,
`shell/s.css`, `app/index.html` and any further flat `app/` files, each with
its SHA-256, size and media type (`html`, `js`, `css`, `svg`, `txt` only);
an extra, missing, modified, oversized, symlinked or non-regular file, a
group- or world-writable entry and a file with a second hard link refuse the
whole composition (fail closed), and the verified bytes are frozen in
memory, so a later disk change is never served. This guards against an
accidental or partial deployment. Protection against the service account
is the root-owned, read-only placement (S5c: files `0444`, directories
`0755`, no hard link) that it cannot write. The installer also compares the
build with the unsigned release manifest copy kept in the same root-owned
release tree at install and before a rollback; that detects accidental or
partial changes and changed owners or modes, not a change by root, and it
is not repeated at every start.
`Settings.web_assets_dir` comes from the optional deployment key
`web_assets_directory` (`<installation>/current/web`, resolved against the
running release's own `web/`); without it no human composition can be
mounted, and with it the release's `--check` refuses to start unless the
build loads. The optional deployment key `human_access` (Issue #10,
`app.auth.access_config`; `server/docs/DEPLOYMENT.md`) states the
reservation (hostname, port, every reserved address, isolation
`dedicated_network_identity` / `single_purpose_node` / `null`, any visible
proxy socket and its creator, the absolute Tailscale CLI path and the
device-bound policy); when enabled it requires `web_assets_directory`, and
the launcher builds the production composition (`app.auth.composition`)
with `/proc/net`, a bounded read-only `tailscale serve status --json`
runner (fixed arguments, empty environment, 5-second timeout, 1 MiB output
cap; any failure is an enumeration failure), `getaddrinfo` and sock_diag.
A section that fails validation refuses startup with a value-free reason; a
valid section whose Tailscale CLI fails the launcher's executable check at
start does not (Issue #283): `--check` passes with a value-free
`reason=executable` warning on stderr and the start is handled like a
composition that cannot be built. Such a composition, including one
`create_app` refuses with `HumanAccessCompositionRefused` (any other
exception propagates), logs `human_access_composition_failed`, keeps
every human path closed while recording and the integrity and
recording-health checks keep running, and notifies the Owner immediately
(`human_access_fault`, monitoring health degraded until a restart composes
access). Without the key every human path stays closed. Every asset response has a
fixed header list: its `Content-Type` (the manifest's, from the S5a
build policy `web/scripts/policy.mjs`), `Content-Length`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Resource-Policy: same-origin`,
`Permissions-Policy: camera=(), microphone=(), geolocation=()` and a
`Content-Security-Policy` (`default-src 'none'`, `'self'` scripts, styles and
connections, no images or fonts and Trusted Types with no policy for the
shell, `base-uri 'none'`, `form-action 'none'`, `frame-ancestors 'none'`;
the exact strings are those of `web/scripts/policy.mjs`); never `ETag`, `Last-Modified`,
`Set-Cookie`, `304`, ranges or a content coding. `HEAD`, other methods, query
parameters and re-encoded spellings get the generic denial. Because every
document is `no-referrer`, each mutating `fetch` of the shell and the
application sets `referrer: ''` and `referrerPolicy: 'same-origin'`, so the
`POST` carries the exact `Origin` the mutating routes require (not `null`). The shell's bytes
identify the software to anyone on the shared account (accepted, S5-5), so it
carries no version marker.

S7 interim live (Owner decision D10, D5 defaults; pending #19, mock verified
only). Mounted when the composition has a `LiveFrameService`
(`HumanAccess.attach_live`; `create_app` attaches one over its local preview
hub), otherwise the generic denial:

```text
GET  /api/live/sources                      -> LIVE: {"sources": [{"id", "name",
                                               "health"}]} of configured, enabled
                                               local sources configured and
                                               negotiated as MJPG (others are
                                               neither listed nor opened; not
                                               "online" without a negotiated
                                               MJPG); nothing else
POST /api/live/sessions  {"source_id"}      -> LIVE + CSRF: {"session_id",
                                               "source_id", "lease_seconds": 15.0,
                                               "frame_interval_ms": 200}
GET  /api/live/sessions/<sid>/frame?after=n -> LIVE, the opening human session
                                               only: 200 image/jpeg with
                                               X-Frame-Sequence, or 204 (none
                                               newer, camera not online, paced)
POST /api/live/sessions/<sid>/close         -> SESSION + CSRF, own sessions: 204
```

`live:view` (or the Owner) is checked server-side on every request;
`recordings:view` alone reaches none of these. A live session is bound to the
human access session that opened it: each poll is admitted in memory (a held
id, a per-(human session, live session) budget), then inside `admit(epoch)`
the read-only session lookup must be that human session (a copied id is
refused) and the read re-runs the `live:view` validator. If the opening
human session is no longer current for the presented cookie and proxy
identity (ended, or a binding mismatch), the live session ends with that poll.
Nothing is written per frame (a binding mismatch is recorded once, coalesced,
and ends the live session), and the idle expiry is extended at most once per
60 s per live session. `lease_seconds` is a JSON number of seconds
(`frame_interval_ms` an integer). `health` is always present; an open always answers `200`, and the Web
paces its polls with `frame_interval_ms` plus some slack; a close needs no body
or `Content-Type` and is not rate-limited, while opens are charged per session
(a burst of 20, one more every 3 s; only a session of the Owner or a
`live:view` holder takes a limiter slot) and a refused open leaves no demand.
Limits: 4 sessions in total, 2 per source, 2 per person, 5 served
frames per second per session, 8 MiB and a JPEG SOI marker per frame; at most
32 live request jobs pending on the server, at most 8 of them per human
session (Issue #279 item 1, Owner decision 2026-10-16), so one session cannot
fill the shared queue; over a limit the generic denial, overload included,
with no distinct overload response (pacing: `204`). Demand ends after 15 s without an
authorized poll, on close and sign-out, at once after an Owner grant or
revocation change, and for every session while access is closed or the
composition stopped; a poll queued before the service stopped is refused.
Responses are `no-store`, `nosniff`,
`Cross-Origin-Resource-Policy: same-origin` and never an attachment, `ETag`,
range or cookie; there is no download or export.

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

Issue #10 phase 2 S5b is that integration on the server side (§11.9): only
the neutral sign-in shell (`/`, `/s.js`, `/s.css`, Owner decision D1) is
served before a credential exists; the application (`/app/`, `/app/<name>`)
needs an active session. No other asset path (source maps, workers,
`/index.html`, configuration) is served.

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

A viewer's WebAuthn user verification is not ServerSentinel biometric processing: the fingerprint/face check happens on the viewer's own device, and what reaches the server is the ceremony's verification data plus the public credential material that persists (§11.4). It creates no template, no biometric enrollment and no identity database here.

### 13.4 Human credential material

Enrollment codes and WebAuthn ceremony material — challenges, client and authenticator data, attestation and assertion signatures — are sensitive secret-adjacent data. They are excluded from logs, general APIs, diagnostics and exports, are held only for the bounded lifetime of the ceremony they belong to, and a failed verification is recorded as a typed outcome without the payload.

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
