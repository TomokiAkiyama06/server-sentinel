# Detector foundation (Issue #20)

`app.detection.foundation` provides transient, local-only CPU inference primitives, a digest-pinned RT-DETRv2 person adapter, and evaluation-only digest-pinned YOLOX person adapters (see below).
Importing it starts no listener, capture stream, process or thread; only an
explicit `IsolatedDetector.maintain()` call starts a detector worker process.
The current application remains closed to human API access until #6/#10.
Profile sampling (#17) is bridged by `InferenceFeed` (below); wiring the feed,
schedulers and workers into the Main runtime, recording (#18) and quality
metrics (#22) remains explicit work.

## Frame, plugin and quality contracts

`GrayFrame` and `RgbFrame` have source and stream UUIDs, a nonnegative sequence, dimensions, and
one or three immutable channel bytes per pixel respectively. Upstream validates stream provenance;
a new stream UUID resets temporal state. Sequence ordering is per stream.
The scheduler retains the four most recent retired stream UUIDs per source. A delayed frame from
that bounded history, or a non-increasing sequence, is rejected without invalidating a newer
pending or in-progress evaluation. An identifier outside the retained history begins a new stream.
Pixels never appear in frame repr, diagnostics, files, or network messages.
This is an inference frame, not a recording or pre-roll representation.

A reviewed `Detector` instance belongs to one source and has a kind,
implementation/version, `reset()`, and `evaluate(frame)`. The Python protocol
is not an untrusted-code sandbox. A scheduler manages one detector binding per
source; multiple detector profiles require separately budgeted schedulers.
No dynamic plugin discovery, model download, package installation, or model switch
is implemented by runtime code. See [the model audit](DETECTOR_MODEL_AUDIT.md) before selecting
any learned model or runtime.

Every frame admission includes a detector-specific `Quality` assessment. Until
#22 can establish prerequisites, callers must use `unknown`. Unknown, degraded,
and insufficient quality invalidate a previous positive/negative immediately,
even between inference ticks; the plugin is not run for those frames. A lack of
an approved person model returns `unknown/model_unavailable`, never `absent`.
The included `UnavailablePersonDetector` is explicitly not a working person
model. Generic motion is never translated into a person or server-movement
observation.

`MotionBaseline` compares grayscale pixels against the previous sampled frame
on the CPU. It reports the fraction whose absolute change reaches the explicit
`pixel_delta`, and compares that fraction to the explicit `changed_fraction`.
These are required evaluation parameters, not chosen deployment defaults.
Startup, reset, stream/shape change, and non-increasing sequences produce
`unknown`. This baseline does not compensate camera motion, model occlusion,
or prove physical server movement. Those contracts belong to #24.

## Cadence, resource limits and health

The caller supplies each source's cadence, maximum throttled cadence, maximum
queue age, evaluation budget, observation lifetime, and frame-pixel cap.
Inference scheduling uses Main's local monotonic clock; it does not compare
unrelated Capture Node monotonic clocks. Capture FPS remains independent.

`offer()` performs bounded admission and never calls a detector. Inputs before
the next admission time are intentionally sampled out, counted separately from
lost accepted samples. Each source has one pending frame; a later due frame
replaces an unprocessed frame and records an inference drop. A worker calls
`run_one()` independently of capture, recording, health, and storage-safety
work. Round-robin selection covers up to four active sources. The fifth is
explicitly rejected; existing sources stay registered.

The scheduler retains at most four pending frames and one in-progress frame.
The motion plugins additionally retain at most one previous frame per source.
Frames have at most three channels; the policy pixel cap bounds their byte count accordingly.
No long decoded history or media persistence is used. All frame sizes are
bounded by the registered policies.

Dropped/stale/oversized frames and over-budget evaluations produce `unknown`,
and overload doubles cadence up to the explicit ceiling. Snapshots expose
health, observation/reason, implementation/version, source/sequence, pending
state, active cadence, intentional samples, drops and processed counts. A later
successful inference remains `degraded` after known loss until the control
plane explicitly acknowledges recovery; throttling remains visible until
`restore_cadence()` is called. Neither operation erases an unavailable result.
`invalidate(source_id, reason=...)` is the explicit control-plane operation for
a detector stop, failure or unusable quality that arrives without a frame: it
drops the pending frame and replaces the published observation with `unknown`
immediately, instead of waiting for `maximum_observation_age_ns`. It publishes
no conclusion, rejects `evaluated`/`warmup` reasons, and ignores an unregistered
source, which exposes no snapshot at all. Observations also expire to `unknown`
when a feed stops. Plugin exceptions are
reduced to a fixed reason; exception messages are not logged or returned.

An evaluation budget is checked **after** a plugin returns; the scheduler
alone cannot preempt a wedged native extension. `IsolatedDetector` provides
that preemption (next section).

## Isolated worker process and watchdog

`foundation.isolation.IsolatedDetector` implements the `Detector` protocol for
the scheduler, but constructs and evaluates the reviewed detector in one
`spawn`ed child process per source binding (never `fork` of the threaded
server). The child, before calling the detector factory (so before any model
or native runtime loads):

- sets `PR_SET_NO_NEW_PRIVS` and a parent-death `SIGKILL`, and exits if the
  parent is already gone;
- applies equal soft/hard `RLIMIT_AS` and `RLIMIT_NOFILE` from explicit
  `WorkerLimits`, and zero `RLIMIT_CORE`/`RLIMIT_FSIZE`;
- redirects stdio to `/dev/null`, so plugin diagnostics cannot carry paths or
  runtime details into service logs.

The parent sends frames as fixed binary headers plus pixels, bounded by
`maximum_frame_bytes`, and reads at most 512-byte JSON replies; it never
unpickles child output. A reply is accepted only with the request id, valid
enum values, a finite fraction and a valid `Detection` combination. The start
handshake must report exactly the configured kind/implementation/version.

A wall-clock watchdog covers every request, including the frame transfer.
Outcomes, all `unknown` and never `absent`:

| Event | Result reason | Worker action |
| --- | --- | --- |
| no reply within `evaluation_timeout_ns` | `detector_timeout` | SIGKILL + reap |
| child exit / broken pipe | `detector_crashed` | reap |
| malformed/oversized reply, reset failure | `detector_failure` | SIGKILL + reap |
| plugin exception inside the child | `detector_failure` | child kept |
| no worker running (start failure, backoff, latched, closed) | `detector_worker_unavailable` | none |
| frame over `maximum_frame_bytes` | `frame_resource_limit` | not sent |

`evaluate()` never starts a process, so start/model-load latency is not
charged to an inference budget. The long-lived inference worker thread calls
`maintain()` (or `InferenceRuntime.maintain()`) between evaluations: it reaps a
child that died while idle, restarts after `restart_backoff_ns`, and after
`maximum_consecutive_failures` latches the binding unavailable until the
control plane calls `recover()`. A `maintain()` call that finds its child dead
never starts the replacement in the same call, even if the backoff has already
elapsed. `InferenceRuntime.maintain()` also invalidates the scheduler at once
for any binding without a running worker, or whose worker start count changed
since its previous call, so an idle crash cannot leave an older conclusion
published until it ages out. At
most one child exists per binding; a child that cannot be reaped blocks any
replacement and is reported as `reap_failed`. `WorkerStatus` exposes state and
start/crash/timeout/protocol counters without exception text.

Linux delivers the parent-death signal when the starting *thread* exits, so
`maintain()` belongs on the long-lived worker thread. The latch is in memory; a
service restart begins again from the deployment configuration. This is fault
isolation, not an untrusted-code sandbox: the child keeps the service
account's filesystem view and network namespace, so filesystem/network
confinement remains the systemd unit's job and every plugin still needs review.

## Sampling bridge

`foundation.feed.InferenceFeed` connects one `SourcePipeline`'s
`InferenceSampler` to one scheduler. The decoder calls `offer_decoded()` for
every presentation-ordered decoded frame with the per-frame detector quality
(`unknown` until #22 supplies one) and a `render(width, height)` callback. Only
sampled frames are rendered, at the sampled profile dimensions, and offered;
the feed assigns strictly increasing per-stream sequences. A frame of the
current stream whose quality is not `sufficient` invalidates the published
observation to `unknown/quality` whether or not it is an inference sample; it
is never rendered or evaluated. A timestamp
gap/reset, inference-profile change, new stream generation (`bind()`), closed
or renegotiating pipeline, invalid input or render failure invalidates the
published observation to `unknown` immediately. Because a pipeline can close,
lose its admission lease or require renegotiation while no further frame is
decoded, the pipeline's owning thread also calls `poll()` after every
lifecycle action and on its periodic tick; `poll()` invalidates once at that
transition (an unreadable pipeline status counts as unavailable) rather than
leaving an earlier conclusion published until its observation age expires.
Re-delivered frames are rejected by the sampler as duplicate timestamps.

## Deployment schema

`foundation.config.parse_detection` validates the deployment's optional
`detection` object (see `server/docs/DEPLOYMENT.md`). Every detector parameter,
cadence/policy value and worker limit is required; nothing is defaulted. Only
the reviewed `server-sentinel-gray-difference` v1 motion baseline and the
digest-pinned RT-DETRv2 adapter (with its exact revision and artifact SHA-256
restated) can be named. `build_inference()` refuses without a configuration,
so no inference runtime can start with implicit settings; until then every
source's detector observation is `unknown`, never `absent`.
`InferenceRuntime.close()` invalidates every binding to
`unknown/detector_worker_unavailable` before and after stopping its worker, so
a stopped runtime never leaves a conclusion published.

## Verification and remaining acceptance

The unit suite uses in-memory generated uniform grayscale frames, controlled
clocks and detector doubles. It checks actual frame differencing, quality and
model unavailability, expiration, sampling versus overload, capacity limits,
source isolation/fairness, concurrency and redacted failures. A blocked test
worker proves capture admission and health snapshots do not wait on its plugin.
Socket interception covers normal motion and quality-error paths. These tests
do not establish the behavior of a future third-party model or native runtime.

Local CPU benchmark command (no model/data/network download):

```sh
cd server
python -m app.detection.foundation.benchmark --width 320 --height 180 --frames 101
```

One development-container run on 2026-09-20, CPython 3.14.4, generated alternating
320×180 grayscale frames: 100 measured frames, median evaluation 1,375,839 ns,
maximum 1,590,304 ns. This is a reproducible workload with an illustrative local
measurement, not target Main Server acceptance, a real scene accuracy result,
a person-detector benchmark, or an inference-FPS recommendation. GPU performance
was not measured.

Issue #20 remains open for Main runtime/recording integration, target-host
verification of the worker limits, target Main CPU/optional GPU measurement,
and final per-source settings. No real-person or real-room benchmark media is
committed, uploaded or attached to CI artifacts.

## Optional RT-DETRv2 CPU person adapter

`foundation.person.RtDetrPersonDetector` loads one explicitly provided local
ONNX artifact. Its exact revision, SHA-256 and size are fixed in code; a wrong,
missing, symlinked, or non-regular artifact is unavailable. The same verified
bytes are passed to the runtime, avoiding a verify-then-reopen race. No URL,
model identifier, downloader, exported cloud provider or fallback-model option
is accepted. Model initialization errors use a fixed message without paths.

The optional runtime is deliberately limited to Linux x86_64 / CPython 3.12.
Install `requirements.lock` and `requirements-detector.lock` with `--require-hashes
--only-binary=:all:` in that environment. Base backend support for other audited
Python/platform combinations does not imply support for this optional adapter.
The CI interpreter is Linux x86_64 Python 3.12 and includes this lock through
`requirements-ci.lock`; model files are never downloaded by CI.

The adapter accepts only already-bilinearly-resized 640×640 RGB frames, applies
the pinned preprocessing `/255` CHW float32, and uses the official focal-loss
postprocessing's top 300 query/class scores. Class zero is person. The score
threshold and intra-op thread count are required caller inputs, not chosen
product defaults. Source-specific quality gating remains mandatory before a
negative can be considered evidence. Non-finite/wrong-shape outputs, grayscale
or wrong-size input, exceptions and missing models yield `unknown`.

Only `CPUExecutionProvider` is enabled, runtime provider fallback is disabled,
and the enabled provider list is checked. The wheel advertises an Azure provider;
the adapter never selects/exposes it, and the pinned graph has only standard
ONNX domains. No GPU provider is adopted by this change. The exact Linux
runtime version is pinned because later versions add reporting facilities;
see [the runtime audit](RTDETR_RUNTIME_AUDIT.md), including license obligations
for redistributing native binaries/images.

On 2026-09-20 the verified real ONNX graph was loaded in a read-only, non-root,
network-isolated CPython 3.12 container capped at one CPU and 2 GiB. A generated
uniform RGB frame completed CPU inference in 227,131,833 ns after a
241,411,158 ns load. Invalid grayscale input returned `unknown`. Python socket,
DNS and process-launch audit hooks observed zero attempts. The result was an
`absent` model observation with score 0.07831832021474838 for that synthetic
stimulus, **not** a negative observation about a real scene or an accuracy test.
This does not measure deployment Main performance or native syscall attempts;
Linux runtime reporting behavior is additionally grounded in the audited source.

Repeat only with the separately obtained, licensed, digest-matching local model:

```sh
cd server
python -m tests.detector_model_smoke /absolute/operator/model.onnx
```

The same approved local artifact can be measured repeatedly with generated
uniform pixels. Every policy value is required explicitly; the command does
not choose a deployment threshold, cadence, CPU budget, or source count:

```sh
cd server
python -m app.detection.foundation.person_benchmark \
  [--adapter rtdetr-v2-r18vd-onnx-cpu|yolox-s-onnx-cpu|yolox-tiny-onnx-cpu] \
  --artifact /absolute/operator/model.onnx \
  --score-threshold <evaluated-threshold> \
  --intra-op-threads <evaluated-thread-count> \
  --sources <1-to-4> \
  --warmup-cycles <count> \
  --measured-cycles <count> \
  --capture-interval-ns <interval> \
  --cadence-ns <initial-cadence> \
  --maximum-cadence-ns <throttled-ceiling> \
  --evaluation-budget-ns <budget> \
  --maximum-queue-age-ns <queue-age> \
  --maximum-observation-age-ns <observation-age>
```

Schema version 1 reports aggregate and per-source nearest-rank `p50`, `p95`,
and maximum evaluation latency in nanoseconds. It also replays the measured
latencies serially through the existing one-to-four-source scheduler and
reports active cadence, processed/sampled/dropped counts, pending state,
health, and the last reason. Capture ticks crossed during one inference are
admitted before the next simulated worker selection so overload is visible.
The replay is deterministic performance modelling, not a runtime/hardware
verification. Output contains the approved digest but never the artifact path
or frame bytes, and always states `deployment_acceptance: false`.

The weights are not repository fixtures, and neither weights nor real media
are uploaded as CI artifacts. CI tests use generated arrays and session doubles
to verify preprocessing, class filtering, finite results, provider restrictions,
artifact validation, errors and unsupported-platform behavior.

## Evaluation-only YOLOX CPU person adapters

Owner decision 2026-09-30 ([record](../../docs/decisions/2026-09-30-yolox-person-evaluation.md))
approves **evaluating** YOLOX; RT-DETRv2 remains the comparison. Provenance,
exact artifacts and the unresolved weights license are in
[YOLOX_EVALUATION_AUDIT.md](YOLOX_EVALUATION_AUDIT.md).

`foundation.yolox.YoloxSPersonDetector` (`yolox-s-onnx-cpu`, 640) and
`YoloxTinyPersonDetector` (`yolox-tiny-onnx-cpu`, 416) load one explicitly
provided local ONNX file whose size and SHA-256 are fixed in code, through the
same verify-then-use bytes, reviewed runtime check and CPU-only session helper
as the RT-DETRv2 adapter (no new dependency; no URL/downloader/fallback). They
accept only RGB frames already resized with preserved aspect ratio so the longer
side equals the model input, pad bottom/right with 114, convert to BGR float
0–255 without normalization, and report the maximum objectness × person-class
score. Grayscale or other sizes are `unknown/quality_unavailable`; wrong output
shape, non-finite values, scores outside [0,1] and exceptions are
`unknown/detector_failure`; never `absent`. The per-frame quality gate before
the adapter remains mandatory (#22): the adapter does not judge darkness, blur
or occlusion, and on generated uniform frames it returns `absent` with a tiny
score, which is not evidence about a real scene.

`foundation.yolox.create_yolox_person` is an importable worker factory, so an
explicitly constructed `IsolatedDetector` runs the adapter in the
watchdog-supervised spawned worker. The deployment schema
(`config.parse_detection`) deliberately **rejects** YOLOX bindings: evaluation
approval is not deployment approval.

CI never downloads weights. `tests/test_detector_yolox.py` uses session doubles
for the contract and, on the reviewed Linux/CPython 3.12 runtime, a YOLOX-shaped
ONNX graph **generated in memory** by `tests/generated_onnx.py` (no learned
parameters: anchor-0 objectness is the mean pixel value / 255) to exercise the
real ONNX Runtime, pixel layout, letterbox padding, digest rejection and the
isolated worker. Smoke with a separately obtained artifact:

```sh
cd server
python -m tests.detector_model_smoke --adapter yolox-s-onnx-cpu /absolute/operator/yolox_s.onnx
```

### Host measurement, 2026-09-30 (this development host, not target acceptance)

Host: 32 logical CPUs, NVIDIA RTX PRO 6000 Blackwell (unused for this table), CPython 3.12.14, ONNX Runtime 1.28.0 `CPUExecutionProvider`,
generated all-zero S×S RGB frames, 10 warm-up + 200 measured cycles per source,
sources evaluated serially in one process (one session per source). The host was
shared with other workloads (1-minute load average ≈ 4–7 during the reported
runs; an RT-DETRv2 run overlapped a load spike ≈ 20–32 and was repeated; the
repeated run is reported). Replay policy (evaluation inputs, **not** defaults):
capture every 66,666,667 ns (15 fps), cadence 500 ms, ceiling 4 s, budget
250 ms, queue age 1 s, observation age 5 s, threshold 0.5.

Latency, ms (aggregate nearest-rank over all sources):

| Adapter | threads | sources | p50 | p95 | max | replay |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| YOLOX-Tiny 416 | 1 | 1 / 2 / 3 / 4 | 23.6 / 24.0 / 23.8 / 23.7 | 24.3 / 25.4 / 24.4 / 25.6 | 25.1 / 27.2 / 26.1 / 28.1 | all healthy, 500 ms, 0 drops |
| YOLOX-Tiny 416 | 4 | 1 / 2 / 3 / 4 | 8.4 / 8.5 / 11.3 / 11.7 | 12.0 / 11.6 / 12.6 / 13.9 | 12.9 / 13.3 / 15.5 / 16.3 | all healthy, 500 ms, 0 drops |
| YOLOX-S 640 | 1 | 1 / 2 / 3 / 4 | 89.9 / 90.3 / 90.8 / 90.2 | 91.4 / 92.3 / 92.6 / 92.0 | 93.1 / 97.7 / 96.6 / 98.8 | all healthy, 500 ms, 0 drops |
| YOLOX-S 640 | 4 | 1 / 2 / 3 / 4 | 26.8 / 29.2 / 32.9 / 32.1 | 34.0 / 35.9 / 35.8 / 35.8 | 35.2 / 55.4 / 40.1 / 44.4 | all healthy, 500 ms, 0 drops |
| RT-DETRv2 640 | 1 | 1 / 2 / 3 / 4 | 219.9 / 221.8 / 225.7 / 220.8 | 322.8 / 227.3 / 233.8 / 224.8 | 450.9 / 238.6 / 249.1 / 237.6 | 1–2 healthy; 3 sources: two throttled to 1 s, degraded, drops; 4 sources: throttled to 1–2 s, degraded, drops |
| RT-DETRv2 640 | 4 | 1 / 2 / 3 / 4 | 71.1 / 76.4 / 77.0 / 78.7 | 79.2 / 83.5 / 85.6 / 84.0 | 82.2 / 87.9 / 89.9 / 89.8 | all healthy, 500 ms, 0 drops |

The replay is deterministic serial modelling of the measured latencies, not a
runtime verification; with a 500 ms cadence per source a single serial worker
saturates once sources × latency approaches 500 ms (RT-DETRv2 at one thread).
Generated frames make these latency-only numbers: **detection accuracy on real
room footage, low light, occlusion and the target camera angles was not
evaluated**. Cross-process contention between several isolated workers, and
the target Main Server, were not measured.

### Evaluation-only GPU measurement, 2026-09-30 (this host; production stays CPU-only)

The Owner approved `onnxruntime-gpu` **for evaluation only**. It ran from an
uncommitted scratch venv (`onnxruntime-gpu==1.28.0` with NVIDIA CUDA 13.4 /
cuDNN 9.27 wheels under NVIDIA proprietary terms; none of it is in a repository
lock or the license allowlist). The adapters and harness were unchanged except
for a CUDA-only session factory with fallback disabled; see
[YOLOX_EVALUATION_AUDIT.md](YOLOX_EVALUATION_AUDIT.md#gpu-evaluation-runtime-evaluation-only-2026-09-30)
for versions, NVIDIA license findings and node-placement evidence (YOLOX: all
203 kernel nodes on CUDA with CPU fallback forbidden; RT-DETRv2: 895 on CUDA and
134 shape-computation nodes on CPU). GPU: NVIDIA RTX PRO 6000 Blackwell
Workstation Edition, driver 595.91.07. Same generated frames and replay policy
as the CPU table, one intra-op thread, 200 measured cycles per source. The host
CPU was heavily loaded by other workloads (1-minute load ≈ 24–28), which affects
host-side preprocessing and RT-DETRv2's CPU shape nodes.

| Adapter (CUDA) | sources | p50 ms | p95 ms | max ms | replay |
| --- | --- | --- | --- | --- | --- |
| YOLOX-Tiny 416 | 1 / 2 / 3 / 4 | 1.35 / 1.37 / 1.40 / 1.47 | 1.39 / 1.41 / 1.45 / 1.51 | 1.47 / 1.70 / 1.92 / 2.04 | all healthy, 500 ms, 0 drops |
| YOLOX-S 640 | 1 / 2 / 3 / 4 | 2.10 / 2.25 / 2.31 / 2.35 | 2.26 / 2.36 / 2.39 / 2.52 | 2.92 / 2.68 / 2.99 / 3.44 | all healthy, 500 ms, 0 drops |
| RT-DETRv2 640 | 1 / 2 / 3 / 4 | 3.50 / 3.69 / 3.60 / 6.23 | 4.28 / 4.26 / 4.25 / 14.85 | 5.16 / 5.22 / 5.16 / 133.99 | all healthy, 500 ms, 0 drops |

Latency includes host-side preprocessing and host↔device copies per call. The
RT-DETRv2 four-source tail coincided with the host CPU load and was not re-run.
These are evaluation-only numbers: no production GPU path exists, and the same
accuracy caveat applies (real room footage was not evaluated).
