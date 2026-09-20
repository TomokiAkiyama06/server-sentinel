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

`InferenceSampler` accepts presentation-ordered **decoded frame** timestamps and
returns whether to emit a frame at the configured inference dimensions. It uses
exact rational deadlines and constant state, skips missed deadlines without a
catch-up loop, rejects old generations, and reports timestamp resets/gaps. It
does not decode or resize images. All compressed reference packets must reach a
decoder before frame sampling; skipping compressed interframes here would break
dependent frames. A decoder/resizer adapter is still required for actual images.

Run synthetic tests from `server/`:

```sh
python -m unittest discover -s tests -p 'test_media_profiles.py' -v
```

The tests exercise cadence, profile adaptation, 1–4 isolated sources, reference
frame recovery, resource close/retry, unsupported adapters and queue pressure.
Synthetic byte packets are deliberately not represented as playable video.
Actual codec support, scaling quality, process resource ceilings, browser
playback and hardware measurements remain unverified.
