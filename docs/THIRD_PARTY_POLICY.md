# Third-Party Dependency and Model Policy

## Goal

Keep ServerSentinel distributable under Apache-2.0 without unintentionally introducing incompatible obligations, hidden network behavior, or developer data collection.

## Software dependency checklist

Before adding a dependency:

1. Record upstream URL.
2. Record exact version/commit.
3. Record license.
4. Check material transitive dependencies.
5. Check network/telemetry behavior.
6. Check maintenance/security state.
7. Explain why it is needed.
8. Add notices/attribution when required.

## Preferred license families

Generally acceptable after normal review:
- Apache-2.0
- MIT
- BSD-2-Clause
- BSD-3-Clause

Other licenses require explicit evaluation.

## Blocked-by-default families

Do not introduce without owner approval and a written compatibility review/ADR where appropriate:
- AGPL
- GPL where obligations may affect the combined distributed work
- SSPL
- BSL/source-available licenses
- custom non-commercial restrictions
- unknown/no-license components

## AI model rule

A model/inference stack can have multiple independent legal/provenance questions:
1. implementation/runtime code license;
2. pretrained weights/model artifact license;
3. redistribution/download terms;
4. dataset provenance/usage constraints where relevant;
5. model's network/telemetry/download behavior.

Do not assume a permissively licensed repository makes every downloadable pretrained weight safe to bundle.

## Person-detection baseline

The initial person-detector evaluation candidate is **YOLOX** because its source implementation is Apache-2.0.

This approves evaluation of the source implementation only. Before bundling/distributing pretrained weights, verify and document the exact artifact license/terms.

The detector interface remains replaceable.

## Owner face-verification models

Owner-only 1:1 face verification is optional MVP functionality and requires an independent model decision.

Before adding a face detector/embedding/verifier:
- verify code license;
- verify all weights/model artifact licenses;
- document expected accuracy/threshold evaluation method;
- document CPU/GPU requirements;
- check whether the package/model contacts external services or downloads artifacts at runtime;
- confirm biometric processing and owner templates/embeddings remain deployment-local; external biometric processing/storage is not an opt-in option in the MVP;
- confirm the implementation does not require a named multi-person identity database;
- keep the verification backend replaceable.

No face-verification model is pre-approved by this policy merely because the product requirement exists.

## Ultralytics and other copyleft/unclear detectors

Ultralytics packages/models are not a default dependency for this Apache-2.0 project because current community licensing can introduce AGPL obligations.

If an agent wants Ultralytics or another AGPL/GPL/unclear-licensed detector/model:
- stop;
- create a proposal/Issue;
- document exact obligations/artifacts;
- do not merge until explicitly approved.

The same rule applies to person detection, face verification, tracking/re-identification, and any future vision model.

## Runtime downloads

Avoid opaque auto-download behavior in production.

Where models must be downloaded:
- pin/check expected version/checksum where practical;
- document source/terms;
- avoid sending deployment/user data during download;
- make failures explicit;
- do not silently switch to a differently licensed model.

## Attribution

Maintain a third-party notices file once implementation starts.

Recommended:
- `THIRD_PARTY_NOTICES.md`;
- machine-generated license report in CI artifacts where practical;
- separate model/weight inventory with provenance/license/checksum.

## Enforced release inventory

[`license/components.json`](../license/components.json) is the release allowlist.
CI runs `python scripts/ci/license_gate.py` and fails when a reviewed dependency
input, exact locked dependency, or committed model artifact is absent or differs.
The inventory keeps exact upstream and license evidence, material transitive
evidence, notices, and redistribution obligations for each component.
Immutable pin evidence is stored in the same record: Python lock SHA256 values,
npm resolved artifacts with their SRI values, model weight digests and container
base image digests. Changing only a digest, a resolved URL, or an image digest is
therefore a gate failure even when the exact version string is unchanged, and a
location without pin evidence is never treated as license-reviewed. CI also
compares the pins pip and npm actually resolved during the build against the same
records.

Model implementation code and weights use distinct `model_code` and
`model_weight` records. Weight records bind the artifact path and SHA256; all
files under reserved model artifact directories are inspected without relying
on a suffix allowlist. A code license record never covers weights. Scopes with no
selected third-party transport/model component have an evidence-backed
`reviewed-empty` record so
their absence is explicit rather than assumed.
Committed model weights must live under `models/`, `weights/`, `checkpoints/`,
or `model-artifacts/` at any repository depth. Inventory records outside those
reserved directories are invalid, including opaque archives.
Runtime-style `assets/ml/` and `assets/ai/` paths are detection-only model-like
locations. Every file under them is checked, including opaque archives and
extensionless files, but approved weights must move to a reserved directory.

Container base images are tracked in a separate `container_images` inventory
because an unmodified Docker Official Image is an operating-system aggregate
rather than one SPDX identifier. Every tracked `Dockerfile*` is a reviewed input,
every `FROM` and `COPY --from` image must pin repository, tag and `sha256`
digest, and each reviewed image keeps its license summary, license and transitive
evidence, notices and redistribution obligations. Only the reviewed CI-only,
non-republished use is accepted; declaring an image as redistributed, using a
floating tag or variable, adding an unregistered image, or substituting a digest
blocks until the Owner records a new decision. Container builds must install
Python packages from a reviewed requirements input with `--require-hashes` and
must use `npm ci`.

Blocked-by-default licenses require an exact record in
[`license/owner-approvals.json`](../license/owner-approvals.json), including the
component name, version, kind, license, upstream, date, `repository-owner`
approver, and a committed Owner decision under `docs/decisions/`. A component id
must be the dependency coordinate itself, so an approval cannot be inherited by a
different package behind the same id. CI rejects stale, missing, mismatched,
or unused approval records.

Requirements `-r` and `-c` includes are recursively covered: each target must be
a separate reviewed repository input, paths may not escape or use a remote URL,
and cycles fail. Each Python project dependency must correspond by PEP 503 canonical
name, exact version, and scope to a reviewed requirements lock entry whose
hashes match the pin stored in the same reviewed record. Dynamic dependency
fields, setuptools dynamic dependency sources, `setup.py`, `setup.cfg`, `Pipfile`
and other unparsed manifests fail closed until a reviewed parser covers them.
`npm-shrinkwrap.json` is audited with the npm lock parser and may not sit beside
a `package-lock.json`, because npm would silently prefer it. Version strings must
be exact: PEP 440 wildcards, environment markers, extras and npm ranges or
wildcard tags are rejected as non-pins.
The permissive license set is explicit; unknown free-form,
proprietary, Elastic, Commons Clause, source-available, and other unlisted terms
need exact Owner approval rather than being accepted because they do not match a
known copyleft name. Committed `build/` and `dist/` archives, extensionless
artifacts, and unknown opaque output types remain in the artifact scan and
require independent weight evidence and checksum review. Common serialized model
formats such as `.pkl`, `.joblib`, `.npz`, `.gguf` and `.safetensors` are
detected anywhere in the repository, and any other opaque non-text file outside
the reviewed media and Web asset formats is treated as a model artifact until it
has its own record, so renaming a model does not bypass weight review. Recognized Web/static
asset suffixes, including `.wasm`, are not classified as model artifacts merely
because they are in a build output directory.
