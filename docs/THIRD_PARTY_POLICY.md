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
