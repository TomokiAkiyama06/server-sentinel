# Detector foundation (Issue #20)

`app.detection.foundation` provides transient, local-only CPU inference primitives and a digest-pinned RT-DETRv2 person adapter.
It does not start a listener, capture stream, process, or thread. The current
application remains closed to human API access until #6/#10. Integration with
profile sampling (#17), recording (#18), quality metrics (#22), and the Main
runtime remains explicit work; importing this module does not enable detection.

## Frame, plugin and quality contracts

`GrayFrame` and `RgbFrame` have source and stream UUIDs, a nonnegative sequence, dimensions, and
one or three immutable channel bytes per pixel respectively. Upstream validates stream provenance;
a new stream UUID resets temporal state. Sequence ordering is per stream.
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
Observations expire to `unknown` when a feed stops. Plugin exceptions are
reduced to a fixed reason; exception messages are not logged or returned.

An evaluation budget is checked **after** a plugin returns. This primitive
cannot preempt a wedged native extension. Runtime integration must place
inference in a separately resource-limited worker/process with a watchdog so
that hard hangs cannot consume evidence/health/storage work. No production
process isolation or runtime recovery is claimed by the unit tests.

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

Issue #20 remains open for profile/recording/runtime integration, production
worker isolation, target Main CPU/optional GPU measurement,
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

The weights are not repository fixtures, and neither weights nor real media
are uploaded as CI artifacts. CI tests use generated arrays and session doubles
to verify preprocessing, class filtering, finite results, provider restrictions,
artifact validation, errors and unsupported-platform behavior.
