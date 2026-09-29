# Independent media profiles

Issue [#17](https://github.com/TomokiAkiyama06/server-sentinel/issues/17) implements
the transport-independent core here. It does not install a capture device, codec,
decoder, encoder, muxer, human route, or live transport. The Issue stays open for
transport integration and Main Server / Capture Node / UVC measurements.

`SourceProfiles` holds immutable capture, recording, inference, and viewer
settings. All rates, dimensions, bitrate bounds, timestamp gap thresholds, and
queue limits are explicit. The numbers in synthetic tests are not deployment
defaults. `replace_viewer_profile()` and `replace_inference_profile()` do not
mutate capture or durable-recording settings. Capture/recording renegotiation
requires closing a stream generation and constructing a new pipeline.

`SourceProfileCapabilities` is an exact per-source allowlist produced after an
adapter inspects that source. `SourceProfileAdmissions` atomically checks all
four requested profiles against that allowlist and an explicitly configured
active-source limit. A rejected replacement leaves the previous admitted set
unchanged. It does not infer modes from a source role/type or provide benchmark
defaults. The Camera Source registry remains authoritative for persisted
configuration; this is the scheduler-side boundary before pipeline construction.
Successful admission returns a generation-bound lease. An admission-bound
pipeline atomically claims that lease only when its initial profiles equal the
manager's selected set. The resulting opaque ownership claim stays private to
that pipeline, so a lease holder cannot release or transition another pipeline
and a second concurrent pipeline cannot reuse it. Viewer and inference adaptation
is accepted only when the resulting complete set is in the lease's allowlist.
The same manager transition publishes the selected complete set, so admission
state stays aligned with the sole pipeline owner.
Teardown releases only the matching generation, so a delayed old teardown cannot
remove a replacement reservation. Released or superseded leases fail closed.

### Room-overview capture option

`SourceProfileCapabilities.room_overview_sets` explicitly marks the subset of an
allowlist that forms the high-resolution room-overview option
(`CaptureOption.ROOM_OVERVIEW_HIGH_RESOLUTION`). Listing it requires explicit
`RoomOverviewCriteria` (minimum capture width/height from the measured camera
capabilities; no built-in value). Each listed set must keep the capture at or
above that minimum, give inference and viewers strictly fewer pixels than the
capture and no higher FPS, and keep recording within capture size/FPS
(`room_overview_violations()` returns sanitized reason codes). The option is
never inferred from a `room_overview` role label, source type or resolution.
`SourceProfileAdmissions.admit()` defaults to `CaptureOption.STANDARD`; selecting
an overview set requires the explicit option, and a mismatch is rejected as
`capture_option_mismatch` (`capture_option_unavailable` when the source lists no
set for that option). The lease allowlist contains only the selected option's
sets, so viewer/inference adaptation cannot silently move a generation between
options.

### Adapter selection without hardware acceleration

`AdapterSelector` is an `AdapterFactory` over explicit `AdapterCandidate`s
(`hardware` / `software`, each with an integration-supplied bounded probe and
factory) and an explicit `AccelerationPolicy`:

- `prefer_hardware`: a missing, unsupported, failed-probe or failed-start
  accelerator falls back to a listed software adapter; `last_selection` records
  `hardware_unavailable` plus `software_fallback` (state `software_fallback`).
- `require_hardware`: software is never substituted; no accelerator yields
  `AdapterUnavailable` (pipeline `adapter_unavailable`), and a start failure
  yields `AdapterStartFailed` (pipeline `adapter_start_failed`).
- `software_only`: accelerators are not probed.

Nothing installed is always `unavailable`. Reason codes are fixed strings; backend
exception text and device paths are discarded. Selection reruns on every adapter
start, so a recovered accelerator is used again. The selector does not probe a
real device itself and no accelerator adapter is included.

### Synthetic resource harness

```sh
python -m app.media.profiles.measure --sources 2 --packets 3000 \
    --packet-bytes 4096 --keyframe-interval 30 --viewers 1 \
    --queue-packets 64 --queue-bytes 1048576 --pump-every 1 \
    --pump-budget 4 --acceleration prefer_hardware
```

It runs 1–4 generated packet streams through `SourcePipeline` with discard-only
software adapters and prints JSON: process CPU seconds, sampled RSS (`null` with
`rss_observable: false` when unreadable, never `0`), per-path maximum/final
queue depth, drops, discontinuities, delivered packets, synthetic inference
sample count and the adapter selection. It prints no hostname, user, path,
environment value, source identity or media, and always reports
`deployment_acceptance: false`. Exit status is `3` when any source is
unavailable. All arguments are required and bounded; there are no defaults.
It measures only scheduler overhead, not codecs, cameras, GPUs or LAN.

`plan_encoding()` permits copy only when complete verified descriptors match:
video-only content, codec/profile, codec initialization digest, container,
dimensions, frame rate, time base, pixel format, color space and bitrate bound.
This deliberately excludes potentially safe remuxes until a specific adapter can
prove their compatibility. A codec initialization digest identifies parser
configuration; it does not verify a payload by itself. A trusted ingest/parser
adapter must validate the descriptor and packet metadata before admission.

The `EncodePlan` passed to each adapter factory includes the exact source and
target descriptors. The factory must validate supported codec/container modes.
Unknown details or a changed profile produce `transcode_required`; a missing or
unsupported adapter exposes `adapter_unavailable`, never successful output.
Hardware acceleration can be implemented by an adapter but is not required by
the planner. No new codec binary or package is included.

`SourcePipeline` accepts immutable compressed packets with source UUID, stream
generation UUID, sequence number, PTS/DTS, time base and keyframe information.
Recording and viewer queues each have packet and byte limits. `pump()` performs
a caller-bounded amount of work, processing the recording path first. Every
method runs on one owning scheduler thread; adapters must do bounded,
nonblocking work. These queues do not supervise an external codec process or
enforce a wall-clock deadline on a blocking adapter. Real adapters require that
separate supervision before runtime integration.

Packets from other sources/generations and duplicate/stale sequences are rejected
without touching the active stream. A time-base mismatch requires a new stream
generation. Sequence gaps, backwards DTS, forward DTS gaps exceeding the explicit
capture profile tolerance, overflow and oversized packets reset
the affected adapter and require a keyframe. PTS reordering alone is allowed for
compressed interframes. Loss and discontinuity counters remain visible after
recovery; healthy is never reported for that generation after a known gap.
An initial wait for a keyframe is counted separately from actual loss.

The viewer adapter is created on the first internal subscription and closed when
the last subscription leaves. Pending viewer packets are released at that point.
Viewer profile changes replace only that path. Failed adapter cleanup remains
visible and prevents another viewer adapter starting until cleanup succeeds;
call `remove_viewer()` or `close()` again to retry. Subscription IDs carry no
authorization: a future human route must enforce the established access gates
before invoking this internal API.

Viewer loss counters belong to the stream generation and survive profile
replacement and zero-subscriber restart. A recovered adapter can produce video
while status still exposes `prior_viewer_loss`; a fresh keyframe does not erase
earlier drops or gaps. Only a new `SourcePipeline` generation starts new counters.

`SourcePipeline.status` combines capture discontinuities with the mandatory
recording path and, only while subscribed, the viewer path. It reports
`unavailable` for a missing/failed recording adapter, capture renegotiation, or
a closed pipeline; known loss/backpressure remains `degraded` after delivery
recovers. An idle viewer path is excluded, so old viewer-only loss does not imply
that durable recording is unhealthy.

`InferenceSampler` accepts presentation-ordered **decoded frame** timestamps and
returns whether to emit a frame at the configured inference dimensions. It uses
exact rational deadlines and constant state, skips missed deadlines without a
catch-up loop, rejects old generations, and reports timestamp resets/gaps. It
does not decode or resize images. All compressed reference packets must reach a
decoder before frame sampling; skipping compressed interframes here would break
dependent frames. A decoder/resizer adapter is still required for actual images.

Run synthetic tests from `server/`:

```sh
python -m unittest discover -s tests -p 'test_media_profile*.py' -v
```

The tests exercise cadence, profile adaptation, 1–4 isolated sources, reference
frame recovery, resource close/retry, unsupported adapters and queue pressure.
Synthetic byte packets are deliberately not represented as playable video.
Actual codec support, scaling quality, process resource ceilings, browser
playback and hardware measurements remain unverified.
