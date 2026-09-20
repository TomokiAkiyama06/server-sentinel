# Dependency and model license inventory

`components.json` is the release allowlist for every reviewed Python/npm lock
entry and committed model artifact. Each record keeps the exact version, upstream,
license evidence, material transitive evidence, redistribution obligations, notice
files, and the independent kind (`source`, `model_code`, or `model_weight`).

Run `python3 scripts/ci/license_gate.py` before a release. The gate fails closed
when a lock input, locked package, or model artifact is absent from the inventory.
`pins.json` separately records the exact approved Python SHA256 and npm SRI for
each lock entry; changing a digest while retaining name/version/upstream fails.

Model files require a SHA256-bound `model_weight` record; model implementation
packages use a separate `model_code` record, so evidence cannot be shared by
implication. Every file below a reserved `models/`, `weights/`, `checkpoints/`,
or `model-artifacts/` directory is treated as a model artifact regardless of its
extension; common model suffixes elsewhere are also detected. Reviewed-empty
records document scopes that currently have no third-party component.
Every committed model weight must be stored below one of those reserved
directories; a `model_weight` record pointing elsewhere is rejected.
Files below an `assets/ml/` or `assets/ai/` path are also detected as model-like
regardless of extension, but these paths are detection-only: move a reviewed
weight into a reserved model directory before registering it.

Only licenses in the gate's explicit permissive SPDX allowlist pass directly.
AGPL, GPL, SSPL, BSL/source-available, proprietary, Elastic, Commons Clause,
custom, unknown, and unclear terms require an exact entry in
`owner-approvals.json`. An approval is valid only for the recorded component
version and license and must point to a committed Owner decision under
`docs/decisions/`. Updating a self-asserted license field is not approval.

The gate is offline. URLs are durable evidence references reviewed in the commit;
the gate does not claim to re-fetch or independently reinterpret legal terms.
Python `-r`/`-c` includes must resolve inside the repository to another reviewed
requirements input. Every included file is audited and include cycles fail.
Every Python project dependency must match a reviewed, hash-pinned requirements
entry by normalized name, exact version, and scope.
Dynamic `dependencies` and `optional-dependencies`, including setuptools file
indirection, fail closed until the gate has a reviewed parser for their source.
Tracked `build/` and `dist/` trees are scanned for model artifacts like any other
repository path. Recognized Web/static output suffixes, including `.wasm`,
remain allowed, while
archives, extensionless files, and unknown opaque output suffixes require model
inventory review; generated-output directory names do not waive review.
