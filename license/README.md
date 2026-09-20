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

AGPL, GPL, SSPL, BSL/source-available, unknown, and unclear licenses require an
exact entry in `owner-approvals.json`. An approval is valid only for the recorded
component version and license and must point to a committed Owner decision under
`docs/decisions/`. Updating a self-asserted license field is not approval.

The gate is offline. URLs are durable evidence references reviewed in the commit;
the gate does not claim to re-fetch or independently reinterpret legal terms.
