# Local UVC Adapter

Owns Main Server UVC/V4L2 discovery, capability negotiation, video-only capture integration, stable physical identity, and hotplug/reconnect reporting through the Camera Source abstraction.

Do not rely on `/dev/videoN` alone. Ambiguous identical non-serial cameras require `manual_intervention_required` and explicit owner re-approval; never bind an arbitrary substitute or capture audio.

## Implemented boundary

`LinuxDiscovery.scan()` reads sysfs USB vendor/product, serial, interface index,
topology, by-id aliases and the V4L2 video node's own capture capabilities. Audio,
metadata-only and non-USB nodes are excluded. These physical facts are private
deployment data; public health events contain only the logical source UUID,
state and a fixed reason. A unique serial/vendor/product/interface match can
reconnect automatically. Port, by-id name and device number alone cannot prove
that a non-serial camera returned.

The current sysfs object's device/inode/change-time tuple is only an ephemeral
instance marker. A recreated node invalidates a pending/live weak binding even
when its path and product metadata are identical; this marker is never treated
as durable physical identity for automatic reconnect.

`ReconnectController` retains an explicitly approved non-serial binding only
while that capture session remains alive. Reconnect, re-enable or process
restart requires approval again when identity is weak. Duplicate serial evidence
also latches manual intervention. `ApprovalStore` persists approved evidence and
the ambiguity latch in the private application SQLite database (migration 3);
storage failure blocks approval rather than falling back to an empty state.
The first selected candidate is persisted as approval-required; only a
successful explicit approval write can promote it to an approved binding.

Before any reconciliation, a durable active-session marker is written. If the
process dies or a later latch write fails, the next session requires Owner
approval instead of trusting the earlier approval value. A clean shutdown closes
capture before releasing this marker, preserving any existing ambiguity latch.
Session-token checks prevent an old controller's shutdown from clearing a newer
session. This means an unclean restart conservatively requires reapproval even
for serial-backed devices. Known duplicated serials are persisted as ambiguous.
Owner selection permits that exact current binding; it does not make the same
serial trustworthy for a later reconnect. A different uniquely observed serial
can establish new approved identity. A clean session with no known serial ambiguity
can still reconnect its unique serial device automatically.

`MmapCapture` implements single-planar streaming on Linux LP64 x86_64/aarch64.
It opens only a selected `/dev/videoN` with no symlink following, checks the
character-device number and rescans identity after open, then uses V4L2
`G/S_FMT`, `G/S_PARM`, `REQBUFS`, `QUERYBUF`, `Q/DQBUF` and `STREAMON/OFF`.
The driver-adjusted profile is reported separately from the requested profile.
V4L2 drivers adjust an unsupported request instead of failing, so the session
compares the negotiated width, height and FourCC exactly and the frame rate
within 1% (`profile_satisfies()`). On a mismatch it records the negotiated
profile, closes the descriptor and reports `degraded` with the fixed reason
`capture_profile_unavailable`, never `online`; the same device instance is not
reopened on every poll, only after the profile, enablement or device instance
changes. A camera without a serial is bound only while its descriptor is open,
so after `capture_profile_unavailable` a profile change cannot rebind it: the
source reports `identity_not_unique` and requires Owner reapproval.
`CaptureSession` also watches frame progress. A read that times out raises
`FrameTimeout` (a `CaptureError` subclass); instead of tearing down, the
session reports `degraded` (`video_frame_stalled`) once no frame has arrived
for the stall window, keeps the descriptor (and any live weak binding) open,
and returns to `online` only on the next delivered frame. The window is
`frame_stall_seconds` but never less than 10 negotiated frame intervals (the
reopen bound scales by the same factor), because a dark scene or slow profile
legitimately lowers the delivered rate; on the real C960s the covered-lens rate
dropped to about 16–17 fps, far inside a 1 s window. Each read waits at most the
stall window. A read that only times out keeps the worker reading at once, without the
supervisor's retry backoff, so a short `poll_timeout_seconds` or a dark scene
whose frame interval exceeds it cannot leave the stall window elapsing with no
read in flight (which would flap `video_frame_stalled` and `online`). A stall lasting `frame_stall_reopen_seconds` closes the capture
(`offline`, `video_capture_failed`) and the next poll reopens it through the
identity path, so a weak binding then needs the Owner again. The same check runs
from `LocalUvcSupervisor`'s single watchdog thread through
`LocalUvcAdapter.check_frame_progress()`: a worker blocked inside a kernel or
SQLite call cannot run its own read timeout, so the watchdog lowers that
source's `online` claim, and past the reopen bound reports `offline`
(`video_capture_failed`) with a reopen request that the worker performs (close,
then reopen through the identity path) as soon as it returns, and re-checks
after presence discovery before starting another read; a frame it returns with
is discarded. The watchdog never opens, closes or rebinds a device
itself. A requested stop does not end its checks: a worker still blocked after
a timed-out stop (for example when a reapproval is refused because the worker
could not stop, or a runtime stop whose supervisor `close()` timed out) stays
checked until its thread actually exits; `close()` stops the watchdog only
after every worker has been joined, and otherwise leaves it running until
those workers exit. It takes the controller's transition lock non-blockingly and re-checks
the frame age under it, so a frame delivered after its snapshot wins. That lock
covers in-memory work only: transitions, the negotiated profile and
`last_seen_at` stage their values in transition order, and the runtime records
each transition in memory under it; a per-source writer persists the merged
latest values after the lock is released, one write at a time, and logging and
the health sink receive the events (in order) after that, also outside the
lock. The source is marked unpersisted from the start of a write until every
staged value is durable, so a hung write never reads as persisted. A watchdog
report never writes the registry itself: it marks the source unpersisted and
hands the write to at most one background writer thread per source, so a hung
SQLite or storage write cannot stop the watchdog from enforcing reopen
deadlines or checking other sources. A
transient stall keeps the recorded negotiated profile. Closing a capture lowers the source to `offline`
(`video_capture_closed`) in memory before the potentially blocking
`STREAMOFF`/unmap/close, so a hung kernel teardown never leaves it `online`;
the registry write and health notification (live-preview invalidation) are
handed to background threads at that point, before the teardown, so neither
waits for a hanging close, the source is reported unpersisted until the
offline row is durable, and hung storage or a hung health sink never keeps
the descriptor open. Stopping a source then waits at most
`HEALTH_SETTLE_SECONDS` (1 s, inside the supervisor join bound) for that
write, so a clean shutdown normally leaves the row durable; a write still
hung leaves the source reported unpersisted.

While a capture is open, `LinuxDiscovery.scan()` (which opens every video node)
runs at most every `presence_scan_seconds` instead of on every frame; the
interval counts from the previous scan's completion, so a scan slowed by USB
re-enumeration does not cause a full scan after every frame. An unplug
surfaces as a descriptor error. A scan with probe failures that no longer lists
the bound device is inconclusive and keeps the live descriptor. A duplicate
serial that appears while capturing is still detected at the next due scan.
`MmapCapture` requests 4 MMAP buffers (`REQBUFS` count 4, accepting 1 to
`MAX_BUFFERS` = 8 from the driver), so the driver can fill a buffer while one
frame is copied.
The caller supplies width, height, FPS and FourCC; there are no hardware profile
defaults. Codec/bitrate controls and multi-planar-only capture are unsupported
and fail explicitly. Camera drivers without a reportable frame rate also fail.
The adapter bounds allocations to eight buffers of at most 64 MiB each and
returns one frame at a time without a decoded-frame history, disk recording,
network connection or audio operation. Driver-corrupt/empty frames are rejected.

`LocalUvcAdapter` connects these parts to the generic registry. An Owner
approval reaches it only through the audited boundary
`OwnerAdministration.approve_uvc()`, which validates the exact current
selection before its transaction and commits the approval with its
`approve_camera` audit record; the adapter exposes no unaudited public
approval, and no HTTP management or preview route. One physical camera (same
serial-backed identity, or the exact weak evidence) is approved for at most one
enabled source. When several connected cameras share one serial, that serial
cannot tell them apart, so each such (serial-ambiguous, exact live-instance)
selection is compared by its exact evidence instead and every twin can be
mapped to its own source. The check applies both sides' comparison modes, so a
source approved by serial before a twin appeared keeps its camera: approving
the twin elsewhere is refused until the Owner reapproves the holder while both
are connected. Approving a camera another enabled source holds an active
approval for is refused with the generic reason and audited as failed, checked
before and again inside the audited transaction. A disabled source or one that
requires approval holds nothing. A duplicate that predates this check (or an
older duplicate re-enabled later) makes every conflicting source
`manual_intervention_required` (`approval_conflict`) without changing either
approval, so capture never depends on startup order; the Owner disables or
reapproves one of them. A supervisor drives
`poll_source()` in each source's worker and serializes operations on that source.
The injected frame callback can feed an authorized preview or later media
pipeline; actual browser viewing remains a downstream task. Discovery and
negotiation remain `degraded` until the first video frame arrives. Unplug emits
`offline`; another source's worker can continue. Enable/disable comes from the
registry, and quality remains `unknown` until a detector evaluates it.
Graceful shutdown closes capture without claiming a physical unplug, and it
preserves any outstanding manual-intervention state.

`LocalUvcSupervisor` supplies that worker boundary. It runs one synchronous,
serialized thread per logical local source, contains and counts ordinary
adapter failures without retaining exception text, and lets other source
workers continue independently. Stop joins are bounded and failed cleanup is
reported to the lifecycle owner; the supervisor never closes a session from a
second thread while its capture poll may still be running. A source must be
stopped before the audited Owner reapproval ceremony.

`LocalUvcRuntime` (`runtime.py`) is the backend lifecycle owner. The deployment
`local_uvc` object (`config.py`, standard library only so the installer can
validate it) lists 1 to 4 logical registry source UUIDs; physical evidence is
never configuration. `create_app()` starts the runtime inside the lifespan after
schema migration/storage admission and stops it before the monitoring runtime.
Missing configuration is the explicit `unconfigured` state and configuration
without admitted storage is `storage_unadmitted` (no worker, no scan). That
includes a monitoring runtime whose startup open failed, and a storage
admission refused while the runtime pins the database at start (nothing is
opened yet, so the runtime stays startable); capture then starts once storage
is admitted again. The application's `local_uvc_state` snapshot is refreshed
from `LocalUvcRuntime.status()` every `retry_delay_seconds`, so a later worker
or storage fault shows as `degraded`/`failed` instead of a frozen `running`.
After startup every
capture-driven write (source health, negotiated profile, last-seen timestamp,
approval session marker) is admitted by the same Main storage policy as audit
writes, so a hard stop or a missing/replaced filesystem refuses it: capture
then fails visibly and retries instead of writing past the reserve. The
in-memory camera transition is still delivered (`recent_health_events()`,
per-source `camera_state`), `health_persisted` becomes false and the service
reports `degraded`, because the durable row may still show an earlier state.
Reads are covered too: the runtime's registry and approval store use a
`PinnedDatabase` that is pinned under a storage admission at start by holding
a read-only descriptor to the admitted file (so an unlinked-and-recreated
replacement can never reuse its device + inode pair), opens with SQLite
`mode=rw` (never creates a file) and refuses an unlinked, missing or replaced
file, so a lost mount never yields a fallback database. `stop()` releases the
pin.
A registry read failure while a camera is live closes that capture and
delivers the offline transition; any poll that raised marks the worker
`polling_failed` and the service `degraded` until a poll completes.
A lifespan startup that fails or is cancelled while the runtime starts still
stops every worker. A shutdown that is cancelled (ASGI shutdown timeout,
embedder) first invalidates the preview, then still waits for the bounded stop
and every remaining cleanup step before re-raising the cancellation. A UUID
that is not a `local_uvc` source is `rejected`, never silently skipped; a worker
that fails to start is `worker_failed` and its camera is written `offline`.
Service state (`running` / `degraded` / `failed` / `stopped` / `stop_failed`)
is separate from each camera's registry health. Workers stop in parallel under
one total join bound, `join_timeout_seconds` (default 10 s, configurable
0.1–60 s). It must cover a worker's `STREAMOFF`/unmap/close (up to 5.5 s
observed on a real C960 after an unplug, MANUAL_TEST P-7) plus
`HEALTH_SETTLE_SECONDS` (1 s); a bound below that can turn a clean shutdown of
a camera mid-teardown into `stop_failed`. After the workers are joined,
`close()` joins the watchdog for at least
`LocalUvcSupervisor.WATCHDOG_JOIN_MINIMUM_SECONDS` (1 s) even when the shared
bound is used up. A watchdog still inside a frame-progress check after that
join makes `close()` fail: the stop is `stop_failed` and the runtime leaves the
adapter open rather than closing it under that check (a later supervisor
`close()` joins the watchdog again). A successful close therefore returns with
no worker or watchdog thread left that could call into the adapter.
A worker that does not stop
within the join bound makes the stop `stop_failed`; the adapter is then left to
that worker's own cleanup rather than closed from a second thread, and the
durable session marker conservatively requires reapproval at next start.
`stop_failed` is not terminal for the runtime (Issue #173): a later
`LocalUvcRuntime.stop()` retries the supervisor join and, once no worker or
watchdog is left, closes the adapter (and retries a failed database release).
A watchdog-only failure then ends `stopped`; a worker whose own cleanup failed
(for example its session-marker release refused after the pin was released)
keeps the stop `stop_failed`, also on a retry after the supervisor already
removed that exited worker while another one was still hung.
`join_timeout_seconds` may not be shorter than `frame_stall_seconds`: the stop releases the database pin right after the
join, and the watchdog must have made a blocked worker's lowered state durable
before then. A slow profile's stall window (10 frame intervals) can still
exceed the join, so for every worker still alive after it the stop calls
`LocalUvcAdapter.fence_stopping()` before releasing the pin: the live session
is lowered to `offline` (`capture_service_stopping`) in memory, a source
without a session has `offline` staged directly, and the stop waits at most
`HEALTH_FENCE_SECONDS` (1 s) for those writes and notifications. A fenced
controller refuses `capture_ready`, so a late frame from that worker never
reports `online` again, and the adapter opens no capture for a fenced source;
the worker still closes its descriptor and releases its session when it
returns.
`LocalUvcRuntime.reapprove()` stops the one source's worker, runs the audited
`OwnerAdministration.approve_uvc()`, and restarts the worker whether the
ceremony committed or was refused. Health transitions go to a bounded
in-memory buffer, an optional injected sink, and a rate-limited value-free log
event (`local_uvc_source_health_changed`); durable timeline/audit ingestion of
these camera-health events is a follow-up. The optional sink never runs on a
capture worker or the watchdog: events wait in a bounded queue
(`HEALTH_SINK_MAX_PENDING`, 64) drained in order by one delivery thread. On
overflow an older event of a source that has a newer pending event is
coalesced away, so each source's latest transition is always delivered. A sink
call running longer than `HEALTH_SINK_STALL_SECONDS` (5 s) is reported as
`health_sink_stalled` and makes the service `degraded`; the status also
reports `health_sink_pending` and `health_sink_coalesced`. If the delivery
thread cannot be started, the events stay queued and are reported as
`health_sink_undeliverable` (the service is `degraded`, never `running` with
a silently lost notification); the start is retried on the next event, on
every `status()` and on `stop()`. A source stop waits, inside its join bound,
until the controller's background delivery thread has handed the close
transition to that queue, and `stop()` then waits at most
`HEALTH_SINK_SETTLE_SECONDS` (1 s) for pending deliveries. The adapter refreshes `last_seen_at`
at most once per second and does not rewrite an unchanged offline state for an
unapproved source, so polling does not become a steady SQLite write load.
Frames go to `app.media.live.local_preview.LocalPreviewHub`.

No physical webcam, actual preview/browser path, Ubuntu permission setup or
arm64 host was tested for this change. Synthetic ioctl, persistence, unplug, restart, registry
and independent-source tests run with the server suite. Issue #11 remains open
until the real-hardware procedure in `MANUAL_TEST.md` is performed.

## ABI and upstream references

The bindings are an independent implementation using Python's standard library.
The ioctl values and LP64 structure offsets were checked against
`linux/videodev2.h` using `sizeof`/`offsetof` on the development x86_64 host.
No kernel source or third-party capture package is distributed here.

- [Format negotiation](https://docs.kernel.org/userspace-api/media/v4l/vidioc-g-fmt.html)
- [Frame interval negotiation](https://docs.kernel.org/userspace-api/media/v4l/vidioc-g-parm.html)
- [Buffer allocation](https://docs.kernel.org/userspace-api/media/v4l/vidioc-reqbufs.html)
- [MMAP access](https://docs.kernel.org/userspace-api/media/v4l/func-mmap.html)
- [Queue/dequeue and corrupt-buffer handling](https://docs.kernel.org/userspace-api/media/v4l/vidioc-qbuf.html)
