# Third-Party Dependency and Model Policy

## Goal

Keep ServerSentinel distributable under Apache-2.0 without unintentionally introducing incompatible obligations or developer data collection.

## Software dependency checklist

Before adding a dependency:

1. Record upstream URL.
2. Record exact version.
3. Record license.
4. Check transitive dependencies.
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

Do not introduce without owner approval and a written ADR/legal compatibility review:
- AGPL
- GPL where obligations may affect the combined distributed work
- SSPL
- BSL/source-available licenses
- custom non-commercial restrictions
- unknown/no-license components

## AI model rule

A model has at least two license questions:
1. code/runtime license;
2. weights/model license.

Both must be acceptable.

Dataset provenance may also matter if the project later trains/distributes weights.

## Person-detection baseline

The initial evaluation candidate is **YOLOX**. Its source implementation is Apache-2.0, which fits the repository's default licensing direction.

This approval applies to evaluating the source implementation only. Before bundling/distributing any pretrained model, agents MUST separately verify and document the exact model-weight license and redistribution terms.

The detector interface must remain replaceable so another permissively licensed detector can be selected after benchmark or licensing review.

## Ultralytics and other copyleft/unclear detectors

Ultralytics packages/models are not a default dependency for this Apache-2.0 project because current Ultralytics community licensing uses AGPL-3.0.

If an agent wants Ultralytics or another AGPL/GPL/unclear-licensed detector:
- stop;
- create a proposal/Issue;
- document exact obligations;
- do not merge until explicitly approved.

## Attribution

Maintain a third-party notices file once implementation starts.

Recommended:
- `THIRD_PARTY_NOTICES.md`
- machine-generated license report in CI artifacts where practical.
