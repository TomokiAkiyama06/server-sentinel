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

`LocalUvcAdapter` connects these parts to the generic registry. An authenticated
Owner boundary must call `approve_source()` with an exact current selection;
the adapter exposes no HTTP management or preview route. A supervisor drives
`poll_source()` in each source's worker and serializes operations on that source.
The injected frame callback can feed an authorized preview or later media
pipeline; actual browser viewing remains a downstream task. Discovery and
negotiation remain `degraded` until the first video frame arrives. Unplug emits
`offline`; another source's worker can continue. Enable/disable comes from the
registry, and quality remains `unknown` until a detector evaluates it.

The backend launcher does not start physical capture automatically. No physical
webcam, actual preview/browser path, Ubuntu permission setup or arm64 host was
tested for this change. Synthetic ioctl, persistence, unplug, restart, registry
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
