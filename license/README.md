# Dependency and model license inventory

`components.json` is the release allowlist for every reviewed Python/npm lock
entry and committed model artifact. Each record keeps the exact version, upstream,
license evidence, material transitive evidence, redistribution obligations, notice
files, and the independent kind (`source`, `model_code`, or `model_weight`).

Run `python3 scripts/ci/license_gate.py` before a release. The gate fails closed
when a lock input, locked package, container base image, or model artifact is
absent from the inventory.

Immutable pin evidence lives in the same record as the license evidence. Every
component location carries a `pin`: Python lock entries record their exact
SHA256 digests, npm lock entries record the resolved artifact URL and its SRI
digests, project manifests record the reviewed lock they correspond to, model
weights record the artifact digest, and `container_images` records the base
image digest. A component therefore cannot be license-reviewed without a pin,
and a digest, resolved URL or image digest that changes while the name and exact
version string stay the same fails the gate. `--resolved-python` and
`--resolved-npm` compare the pins an installer actually resolved during a build
against the same records.

Model files require a SHA256-bound `model_weight` record; model implementation
packages use a separate `model_code` record, so evidence cannot be shared by
implication. Every file below a reserved `models/`, `weights/`, `checkpoints/`,
or `model-artifacts/` directory is treated as a model artifact regardless of its
extension; common serialized model suffixes elsewhere, including `.pkl`,
`.joblib`, `.npz`, `.gguf` and `.safetensors`, are also detected, and any other
opaque non-text file outside the reviewed media and Web asset formats is treated
as a model artifact until it has its own record. The whole file is decoded, so a
readable prefix followed by artifact bytes is still opaque, and a file larger
than the bounded text scan is opaque rather than trusted unread. Tracked files are scanned even inside `node_modules` or `.venv`, so a
force-added weight cannot hide in a dependency cache; only untracked cache
content and nested checkouts are skipped. Skipping a cache requires knowing its
tracked files, so the gate fails closed when that list is unavailable. `model_scan_exemptions` records
the reviewed source packages that only share a reserved directory name, such as
`tests/models`; the exemption covers text-only Python sources, an opaque or
model-suffixed file below the path still needs weight review, and an exemption
that matches nothing fails as stale. A recognized media or Web asset suffix
exempts a file only when its header matches that format, so renaming a weight to
`.png` or `.wasm` does not make it a reviewed asset. Reviewed-empty
records document scopes that currently have no third-party component.
Every committed model weight must be stored below one of those reserved
directories; a `model_weight` record pointing elsewhere is rejected.
Files below an `assets/ml/` or `assets/ai/` path are also detected as model-like
regardless of extension, but these paths are detection-only: move a reviewed
weight into a reserved model directory before registering it.

Container base images are tracked separately in `container_images`, because a
Docker Official Image is an unmodified operating-system aggregate rather than a
single SPDX identifier. Each record keeps the repository, tag, immutable digest,
license summary, license and transitive evidence, notices and redistribution
obligations, and the Dockerfiles that use it. Only the reviewed CI-only,
non-republished distribution is accepted; any other distribution intent, a
floating tag, a variable reference, an unregistered image or a later digest
substitution fails the gate and needs a new Owner decision. Container build
commands are allowlisted rather than pattern-matched. A pip invocation must be
`install`, carry `--require-hashes`, use only reviewed options, and name reviewed
requirement or constraint files, including the attached `-rfile` and
`--requirement=file` forms. npm must use a `ci`-family command with reviewed options only, so `npm install`
and every documented alias, a path-changing option such as `--prefix` before or
after the command, a positional argument, and `npx`/`pnpm`/`yarn` fail closed.
`npm ci` must also pass `--ignore-scripts`. An executable or option token in a
build command must be a plain literal, so escaping, quoting-based obfuscation and
variable expansion cannot hide an installer; a positional argument may use a path
glob, but a requirement file value may not. A build that runs `npm run` needs a
reviewed `package.json` beside its Dockerfile, and every package script in a
reviewed manifest is audited with the same rules, so moving an install into a
script body does not bypass the gate.

Only licenses in the gate's explicit permissive SPDX allowlist pass directly.
AGPL, GPL, SSPL, BSL/source-available, proprietary, Elastic, Commons Clause,
custom, unknown, and unclear terms require an exact entry in
`owner-approvals.json`. A component id must be the dependency coordinate
(`pypi:`, `npm:` or `model:` with the exact canonical name and version), and an
approval is valid only when its name, version, kind, license and upstream all
match that component and it points to a committed Owner decision under
`docs/decisions/`. Replacing the package behind an approved id therefore loses
the approval. Updating a self-asserted license field is not approval.

The gate is offline. URLs are durable evidence references reviewed in the commit;
the gate does not claim to re-fetch or independently reinterpret legal terms.
Python `-r`/`-c` includes must resolve inside the repository to another reviewed
requirements input. Every included file is audited and include cycles fail.
Every Python project dependency must match a reviewed, hash-pinned requirements
entry by PEP 503 canonical name, exact version, and scope, and its pin must name
that lock. npm project dependencies match their reviewed lock the same way.
Versions must be exact: PEP 440 wildcards such as `1.*`, environment markers,
extras, npm ranges and npm wildcard tags are not pins. `npm-shrinkwrap.json` is
audited like `package-lock.json` and may not sit beside one, and `setup.py`,
`setup.cfg`, `Pipfile` and other unparsed manifests fail closed.
Dynamic `dependencies` and `optional-dependencies`, including setuptools file
indirection, fail closed until the gate has a reviewed parser for their source.
Tracked `build/` and `dist/` trees are scanned for model artifacts like any other
repository path. Recognized Web/static output suffixes, including `.wasm`,
remain allowed, while
archives, extensionless files, and unknown opaque output suffixes require model
inventory review; generated-output directory names do not waive review.
