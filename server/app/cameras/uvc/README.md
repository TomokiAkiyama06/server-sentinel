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
approval, and no HTTP management or preview route. A supervisor drives
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
includes a monitoring runtime whose startup open failed; capture then starts
once, when a later monitoring retry reaches `running`. After startup every
capture-driven write (source health, negotiated profile, last-seen timestamp,
approval session marker) is admitted by the same Main storage policy as audit
writes, so a hard stop or a missing/replaced filesystem refuses it: capture
then fails visibly and retries instead of writing past the reserve. The
in-memory camera transition is still delivered (`recent_health_events()`,
per-source `camera_state`), `health_persisted` becomes false and the service
reports `degraded`, because the durable row may still show an earlier state.
A lifespan startup that fails or is cancelled while the runtime starts still
stops every worker. A UUID
that is not a `local_uvc` source is `rejected`, never silently skipped; a worker
that fails to start is `worker_failed` and its camera is written `offline`.
Service state (`running` / `degraded` / `failed` / `stopped` / `stop_failed`)
is separate from each camera's registry health. A worker that does not stop
within the join bound makes the stop `stop_failed`; the adapter is then left to
that worker's own cleanup rather than closed from a second thread, and the
durable session marker conservatively requires reapproval at next start.
`LocalUvcRuntime.reapprove()` stops the one source's worker, runs the audited
`OwnerAdministration.approve_uvc()`, and restarts the worker whether the
ceremony committed or was refused. Health transitions go to a bounded
in-memory buffer, an optional injected sink, and a rate-limited value-free log
event (`local_uvc_source_health_changed`); durable timeline/audit ingestion of
these camera-health events is a follow-up. The adapter refreshes `last_seen_at`
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
