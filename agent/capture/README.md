# Agent Capture

Owns local UVC/V4L2 discovery, identity reconciliation, video capture and
hotplug/reconnect for sources attached to the capture node. Implemented in
`../media_capture_agent/`:

| Module | Responsibility |
| --- | --- |
| `uvc_identity.py` | `DeviceEvidence`, `match_reconnect`, per-source `ReconnectController` (port of `server/app/cameras/uvc/identity.py`) |
| `uvc_discovery.py` | sysfs/`/dev/v4l/by-id` evidence and V4L2 `QUERYCAP`/`ENUM_FMT` probe (port of the Main discovery) |
| `uvc_approvals.py` | Private durable approval evidence, ambiguity latch and active-session marker in `runtime_root` |
| `uvc_pipeline.py` | `MjpegProfile`, bounded `MjpegFrameParser`, `FrameQueue`, subprocess pipeline/launcher, GStreamer argv |
| `uvc_capture.py` | `UvcCapture`: the runtime `Capture` for 1–4 sources, supervision, health and teardown |

## Identity

`/dev/videoN` alone is never identity. Evidence combines vendor/product,
serial, interface index, `/dev/v4l/by-id` aliases, USB topology, device number
and a sysfs instance token. Only a unique serial reconnects automatically.
Duplicate serials and every non-serial model match enter
`manual_intervention_required` until an Owner re-approves an exact current
candidate. A non-serial camera keeps its approval only while its capture
descriptor stays open: a crash, unplug or restart requires re-approval. A
never-approved source starts in `owner_approval_required`. If any video node
cannot be probed, discovery is incomplete and no new binding is made
(`discovery_failed`), because the unreadable node might be the camera or a
duplicate. Two sources resolving to the same device both require re-approval.

`UvcCapture.approve()` and `candidates()` are internal Owner-boundary methods.
The authenticated/audited Owner route that calls them belongs to #13/#14.

## Capture pipeline

Each bound source runs one subprocess pipeline behind the injectable
`PipelineLauncher` interface. The production `GStreamerLauncher` executes an
operator-installed `gst-launch-1.0` (absolute path, root-owned, not group/world
writable, re-checked at every start, never PATH-searched) as:

```text
python3 -I -S -B uvc_sandbox.py --device-fd <N> --read /usr --read /lib --read /lib64 \
  --read /etc/ld.so.cache --read <gst-launch-1.0> --read <plugin>... -- \
gst-launch-1.0 -q --gst-plugin-load=<dir>/libgstcoreelements.so,<dir>/libgstvideo4linux2.so \
  v4l2src device=/proc/self/fd/<N> do-timestamp=true \
  ! image/jpeg,width=<W>,height=<H>,framerate=<N>/<D> ! fdsink fd=1 sync=false
```

- Least device access: the `video4linux2` plugin opens every `/dev/video*` node
  `O_RDWR` during plugin initialization (M2M codec probe, observed with a warm
  registry on GStreamer 1.24 and 1.28; no variable disables it). The
  `uvc_sandbox.py` helper therefore applies a Landlock ruleset before `exec`
  (unprivileged: `no_new_privs`, no root, no user namespace): every filesystem
  right the kernel's Landlock ABI knows is denied except read/execute beneath
  the listed paths and read/write/ioctl of the approved device inode itself;
  TCP bind/connect is denied on ABI >= 4 and abstract UNIX sockets/signals are
  scoped on ABI >= 6. The probe's `/sys` and `/dev` enumeration fails with
  `EACCES`, so no other camera or metadata node is opened. Any helper failure
  exits 126 without executing GStreamer; a kernel without Landlock makes
  `GStreamerLauncher` refuse to start (fail closed).
- Restricted plugin set: only `coreelements` (`fdsink`) and `video4linux2`
  (`v4l2src`) are loaded from the root-controlled system plugin directory
  (each file re-checked at every start). `GST_PLUGIN_SYSTEM_PATH[_1_0]` and
  `GST_PLUGIN_PATH[_1_0]` are empty, `GST_REGISTRY_DISABLE=yes` and
  `GST_REGISTRY_FORK=no`, so neither `gst-launch-1.0` nor a
  `gst-plugin-scanner` loads ALSA/PulseAudio/PipeWire or any other plugin, and
  no registry cache is read or written (the sandbox also denies it).

- Video only: no audio, GUI, network or file element can be expressed.
- The Agent opens `/dev/videoN` itself (`O_NOFOLLOW`, character device, expected
  `st_rdev`), rescans evidence to confirm the same unique candidate, and passes
  that descriptor to the child. The path never appears in the command line.
- Minimal environment (`PATH`, `LC_ALL` and the fixed `GST_*` plugin/registry
  restrictions above); nothing inherited from the service environment.
- Own process group, no stdin, stderr discarded (it can contain device details
  and is never logged). Teardown sends SIGTERM to the group, then SIGKILL to the
  group while the exited leader is still unreaped, and reaps it only after no
  other live member of the group remains in `/proc` (a member stuck in
  uninterruptible sleep, or an unreadable process table, keeps the source
  `capture_cleanup_failed`). A member that leaves the group with `setsid` is
  not tracked without cgroups.
- The explicit profile requires the camera to advertise `MJPG`; otherwise the
  source reports `capture_unsupported` without starting a process. A profile the
  driver rejects makes the pipeline exit and reports `capture_failed`.

MJPEG output is split structurally into complete JPEG frames (per-frame byte
bound, bounded inter-frame padding, malformed stream = failure) and placed in a
bounded drop-oldest per-source `FrameQueue`. Memory is bounded by
`(queue_frames + 1) * max_frame_bytes` plus one read chunk per source.

## Health

Per-source health never affects node health; `poll()` does not raise for camera
or pipeline failures.

| State | Reasons |
| --- | --- |
| `online` | `video_ready` — frames are arriving, no frame was dropped within the stall window, and every earlier drop has already been reported once as `capture_overloaded` |
| `degraded` | `capture_starting` (bound, no frame yet), `capture_overloaded` (consumer is not keeping up) |
| `offline` | `camera_missing`, `capture_failed` (exit/stall/startup timeout/malformed stream; bounded backoff), `capture_unsupported`, `capture_cleanup_failed` (process not reaped; relaunch blocked), `discovery_failed` |
| `manual_intervention_required` | `owner_approval_required`, `identity_ambiguous`, `approval_state_unavailable` |

A pipeline that cannot be reaped, or approval state that cannot be written,
keeps the active-session marker armed so the next start requires re-approval.
All teardowns within one poll share a single stop bound (several cameras
failing together cannot multiply the delay), and only the first attempt for a
pipeline waits; later polls re-signal the
stuck process group and check without waiting, so a process in uninterruptible
sleep does not delay every heartbeat. `close()` grants it one more full bound.

Discovery scans (sysfs reads and V4L2 `QUERYCAP`/`ENUM_FMT` ioctls) and the
open and close of the capture node run in workers, never on the tick thread.
Within one poll all of these calls share a single `device_timeout` (default
2 s) and all teardowns share a single `stop_timeout`, so the heartbeat after a
poll is delayed by at most their sum however many of the 1–4 cameras hang. A
call that exceeds the bound yields `discovery_failed` (scan) or
`capture_failed` (open) for the affected sources; launches left when the bound
is used up wait for the next poll. While a source's device call is still
blocked, its next open fails at once instead of starting more threads, and a
descriptor returned late is closed in the worker without being used.
If no worker can be started at all (thread/PID exhaustion), the descriptor is
kept for a bounded retry on later polls and the source reports
`capture_cleanup_failed` (relaunch and re-approval blocked); it is never closed
on the tick thread and the failure never escapes `poll()`. A close whose worker
started but exceeded the bound is likewise `capture_cleanup_failed` until the
worker returns, and `close()` gives a still-blocked open/close one more
`device_timeout`, otherwise raising `CaptureCleanupError` with the recovery
marker left armed.

## Not yet wired

The production CLI still uses `UnconfiguredCapture`: source/profile
configuration, the Owner approval route (#13/#14), ring segment writing (#16)
and transport (#15) are separate work. Until a consumer drains `FrameQueue`,
a streaming source correctly reports `capture_overloaded`. Tests use synthetic
JPEG-shaped byte streams, a fake sysfs/udev tree and fake or synthetic Python
subprocess pipelines only; physical cameras are verified via `MANUAL_TEST.md`.
