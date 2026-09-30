# 2026-09-30: evaluate YOLOX as the Issue #20 person detector

- Decision owner: repository-owner
- Date: 2026-09-30
- Scope: **evaluation only**. Not production adoption, not deployment enablement,
  not approval to commit, bundle, redistribute or auto-download weights.
- Related: Issue #20, `docs/THIRD_PARTY_POLICY.md`, `server/docs/YOLOX_EVALUATION_AUDIT.md`

## Decision

The repository owner decided in the 2026-09-30 working session (relayed to the
implementing agent in that session; confirmation on the PR that introduces this
file is the durable record) that YOLOX is to be **evaluated** as the person
detector for Issue #20, following `docs/THIRD_PARTY_POLICY.md`.

- RT-DETRv2 (the existing digest-pinned adapter) remains a comparison candidate.
- Owner face verification (#25) stays disabled for the MVP and is not affected.

## What this permits

- A digest-pinned, local-artifact YOLOX ONNX adapter in `app.detection.foundation`,
  usable by the benchmark harness, the explicit smoke command and an explicitly
  constructed isolated worker.
- Operators/developers obtaining the official Megvii `0.1.1rc0` ONNX release
  assets **outside the repository** for local measurement.

## What this does not permit

- The official pretrained weights have **no explicit license grant** (see the
  audit). This decision does not resolve that and does not declare the weights
  Apache-2.0. Adoption for deployment requires a separate Owner decision after
  the weights' terms are clarified or an alternative artifact with explicit terms
  is chosen.
- The deployment schema (`config.parse_detection`) keeps rejecting YOLOX.
- No `license/owner-approvals.json` entry is recorded: the license gate only
  accepts approvals for components present in `license/components.json`, and a
  `model_weight` component requires a committed artifact. No YOLOX weight is
  committed, so an approval record would fail the gate as referencing an absent
  component. If a weight is ever committed or distributed, it needs its own
  `model_weight` record and, because its license is unclear, an exact approval
  entry referencing a new Owner decision.
