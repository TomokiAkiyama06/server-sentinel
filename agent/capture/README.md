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
gst-launch-1.0 -q v4l2src device=/proc/self/fd/<N> do-timestamp=true \
  ! image/jpeg,width=<W>,height=<H>,framerate=<N>/<D> ! fdsink fd=1 sync=false
```

- Video only: no audio, GUI, network or file element can be expressed.
- The Agent opens `/dev/videoN` itself (`O_NOFOLLOW`, character device, expected
  `st_rdev`), rescans evidence to confirm the same unique candidate, and passes
  that descriptor to the child. The path never appears in the command line.
- Minimal environment (`PATH`, `LC_ALL`, optional `GST_REGISTRY` in the private
  runtime root); nothing inherited from the service environment.
- Own process group, no stdin, stderr discarded (it can contain device details
  and is never logged). Teardown sends SIGTERM to the group, then SIGKILL to the
  group while the exited leader is still unreaped, then reaps it.
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

## Not yet wired

The production CLI still uses `UnconfiguredCapture`: source/profile
configuration, the Owner approval route (#13/#14), ring segment writing (#16)
and transport (#15) are separate work. Until a consumer drains `FrameQueue`,
a streaming source correctly reports `capture_overloaded`. Tests use synthetic
JPEG-shaped byte streams, a fake sysfs/udev tree and fake or synthetic Python
subprocess pipelines only; physical cameras are verified via `MANUAL_TEST.md`.
