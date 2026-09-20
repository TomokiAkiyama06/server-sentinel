# Continuous integration

Issue [#5](https://github.com/TomokiAkiyama06/server-sentinel/issues/5) provides
the `CI` GitHub Actions workflow. It runs for every pull request, pushes to
`main`, and manual dispatch. The final check is named **CI**; repository,
component, and Dashboard browser smoke jobs must all succeed. A failed,
cancelled, or skipped prerequisite
cannot produce a successful final check. Review provenance enforcement remains
in Issue #4; the workflow itself does not change repository protection settings.

The Owner-authorized [baseline ruleset](https://github.com/TomokiAkiyama06/server-sentinel/rules/23728669)
requires PRs, resolved review threads and the `CI` check from the GitHub Actions
App on an up-to-date branch before merging to `main`. It blocks force pushes and
deletion and has no bypass actors. That shared issuer does not distinguish a
malicious same-repository workflow from trusted CI; same-repository writers
remain trusted until #4's dedicated review gate is deployed and accepted.

Issue #4's offline review-receipt policy tests run in the repository test job.
The [deployment proposal](REVIEW_GATE_SETUP.md) and disabled ruleset generator
are preparatory tooling; their successful tests do not establish a deployed
trusted issuer or required Codex/Claude enforcement.

## Current coverage

The Main Server foundation has configured lint, synthetic tests and isolated
normal/error ASGI smoke. Its smoke additionally observes Python outbound and
process-spawn attempts; see `server/docs/FOUNDATION.md` for the precise limits.

The `web/` React foundation is implemented and activates locked dependency
installation, TypeScript/JavaScript checks, Node tests, production bundling,
Docker validation and isolated normal/error preview smoke. The additional
Dashboard browser smoke job executes the built UI in runner-installed Chrome
with synthetic viewport/session fixtures and intercepted page requests.
Other components activate checks through their manifests; README-only skeletons
continue to report **not implemented**. This coverage does not establish physical
hardware, phone/Mac device, private network, authentication deployment or live
media acceptance.

The repository job always runs:

- tracked-file secret and sensitive-path checks;
- synthetic media provenance checks;
- known prohibited SDK/reporting signature checks in component inventories,
  lockfiles, source/configuration, and available generated output;
- Pyflakes and pycodestyle lint checks for Python tooling/tests;
- synthetic positive/negative unit tests for the guards and component runner;
- whitespace checks on the checked-out change.

Negative test inputs are constructed in temporary directories. No real secret,
person, room, hardware identifier, deployment value, or monitoring media is used.

## Running locally

Use Python 3.12 or later, Git, and an isolated development environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r .ci/requirements.txt
python scripts/ci/repository_guard.py
python -m pyflakes scripts tests
python -m pycodestyle --select=E4,E7,E9 scripts tests
python -m unittest discover -s tests/unit -p 'test_*.py' -v
python scripts/ci/component_checks.py
```

The tracked-file guard checks the working copies of files in the Git index;
stage newly added files before running it. It also inspects available component
build outputs. Scan findings report fixed categories and file ordinals/line
numbers, never the matched content. Locate a tracked file locally using the
ordered Git file inventory; do not paste sensitive content into an Issue or log.

## Component onboarding

The supported component roots are `server/`, `agent/`, and `web/`. Adding source
or a manifest activates validation; incomplete lint/test/lock configuration
fails. Existing README-only placeholders remain explicitly unimplemented.

Python components require `pyproject.toml`, a hash-pinned
`requirements-ci.lock`, and a `ci.toml` containing argv arrays:

```toml
version = 1

[checks]
lint = ["python", "-m", "pyflakes", "."]
test = ["python", "-m", "pytest"]

[smoke]
dockerfile = "Dockerfile.ci"
normal = ["python", "-m", "tests.smoke", "normal"]
error = ["python", "-m", "tests.smoke", "error"]
```

These are onboarding examples, not dependencies or runtime modules already
implemented by this repository. Python dependencies install into a temporary
virtual environment with pip hash verification. Declare every required tool
and dependency in that component's reviewed lockfile.

Node components require `package.json`, `package-lock.json`, and nonempty `lint`
and `test` scripts. CI runs `npm ci --ignore-scripts --no-audit --no-fund`,
`npm run lint`, and `npm run test`. Their `ci.toml` requires the same version and
`[smoke]` section. Dependency install lifecycle scripts are not implicitly run.
CI provides Node 24. Different package managers need an explicit CI extension.

The implemented `web/` component also requires the Dashboard browser smoke job
in the aggregate CI gate. It uses installed runner Chrome and Node's built-in
CDP transport, with no browser-automation package or browser download. Synthetic
viewports exercise React rendering, permissions, errors and hostile opt-in
settings. Every page request is intercepted; an aborted external positive
control verifies observation. Browser/OS background traffic is outside this
scope. No media, trace, screenshot, or test-report artifact is uploaded.

Smoke commands must validate synthetic normal and error scenarios and exit zero
only when their assertions pass. Their image uses the component as build context.
Containers run without a network, host mounts, published ports, inherited
deployment environment, root privileges, or writable root filesystem. Resource
limits, a bounded temporary filesystem, timeouts, and container cleanup apply.
The image and all its dependencies require the usual license and pinning review.

Network isolation prevents external delivery during these smoke commands. It
does not prove that software never attempts reporting or that a future deployed
application has no telemetry. Add component-specific traffic observation as
runnable components arrive; full runtime acceptance remains in #27/#28.

Existing Dockerfiles receive BuildKit `docker build --check` validation. Existing
Compose configurations receive `docker compose --env-file /dev/null ... config
--quiet` validation. No services are deployed or published. Docker/Compose must
be available when these configurations or smoke images exist; absence fails
the check. Configurations use synthetic CI values, never real deployment `.env`
files. Each discovered Compose file must be independently valid.

## Guard limits and maintenance

Secret scanning recognizes documented credential formats and sensitive paths;
it is not a complete entropy scanner and does not scan Git history. A passing
result cannot certify that arbitrary new credential formats or private values
are absent. Never commit a real secret to test the detector.

Prohibited SDK/reporting checks recognize known signatures. They reject matched
dependencies/configuration even when disabled or opt-in. Unknown, renamed,
encoded, or dynamically loaded reporting requires dependency/code review and
runtime observation. A passing static check does not authorize a PRIV-003
exception. Policy changes still require explicit Owner approval and an ADR.

Media fixture provenance is verified by reproducing the built-in
`checkerboard-8x8-v1` recipe listed in `tests/fixtures/synthetic/manifest.json`
and comparing bytes. A filename, a hash of arbitrary media,
or a `synthetic=true` declaration alone is insufficient. Add new recipes through
review when another fixture format is needed. UI images outside fixture paths
remain permitted by the existing policy; these checks cannot classify their
visual contents or prove that an image depicts no real person or room.

The guard fails closed above 32 MiB per file, 256 MiB total, or 20,000 paths.
Symlinks, submodules, and opaque runtime archives are rejected. Larger fixtures,
additional formats, synthetic inventory exports, or packaged build outputs need
an explicit reviewed extension instead of a silent skip.

GitHub-hosted runners execute PR code with read-only repository permissions,
without deployment secrets or persisted checkout credentials. This workflow
does not upload test media, traces, reports, or other artifacts. Dependency setup
contacts official package registries and GitHub; test data remains synthetic.
CI tooling pins, licenses, and obligations are recorded in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
