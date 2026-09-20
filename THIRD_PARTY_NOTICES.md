# CI tooling inventory

Main Server runtime additions and the CI-only base image are reviewed separately
in [`server/docs/DEPENDENCIES.md`](server/docs/DEPENDENCIES.md). That inventory
includes all pinned Python wheels, Pydantic Core's Rust closure, image digests
and notice/source obligations. Preserve the bundled
[`server/docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md`](server/docs/BACKEND_THIRD_PARTY_LICENSE_TEXTS.md)
with application deployments and redistributions.

The #8 dashboard dependency inventory and static asset attribution obligations
are in [web/THIRD_PARTY_NOTICES.md](web/THIRD_PARTY_NOTICES.md).

Reviewed on 2026-09-20 for Issue #5. These tools are development/CI dependencies,
not ServerSentinel runtime dependencies or vendored release contents. No model
or weights are introduced. Install versions/hashes are in `.ci/requirements.txt`;
Action commits are pinned in `.github/workflows/ci.yml`.

| Tool | Exact version / commit | License | Purpose |
|---|---|---|---|
| [Pyflakes](https://github.com/PyCQA/pyflakes) | 3.4.0 | MIT | Python syntax, imports and undefined-name checks |
| [pycodestyle](https://github.com/PyCQA/pycodestyle) | 2.14.0 | MIT (Expat) | Selected Python structural/style checks |
| [actions/checkout](https://github.com/actions/checkout) | `d23441a48e516b6c34aea4fa41551a30e30af803` | MIT | Read-only checkout with credentials not persisted |
| [actions/setup-python](https://github.com/actions/setup-python) | `ece7cb06caefa5fff74198d8649806c4678c61a1` | MIT | Python 3.12 CI environment |
| [actions/setup-node](https://github.com/actions/setup-node) | `249970729cb0ef3589644e2896645e5dc5ba9c38` | MIT | Node 24 for conditional TypeScript checks |

## Python tools

The official [Pyflakes 3.4.0 metadata](https://pypi.org/pypi/pyflakes/3.4.0/json)
and [pycodestyle 2.14.0 metadata](https://pypi.org/pypi/pycodestyle/2.14.0/json),
their universal wheels, LICENSE files and imports were checked. Both use their
own code and the Python standard library, declare no `Requires-Dist`, and have
no vendored third-party packages or network client. The selected wheels are
SHA256-pinned; source builds and unpinned transitive installation are disallowed.
The linter commands perform local analysis. Dependency installation contacts
PyPI; it does not send source or deployment data to a lint service.

## GitHub Actions

Root licenses and production lockfile dependencies were reviewed at the exact
commits above. Missing checkout lockfile license fields were resolved using
official npm metadata for the exact package versions. Every production entry
has an integrity hash.

| Action | Production lock entries | License families in that inventory |
|---|---:|---|
| checkout | 32 | MIT, ISC, Apache-2.0 |
| setup-python | 56 | MIT, ISC, 0BSD, Apache-2.0, Apache-2.0 AND BSD-3-Clause |
| setup-node | 76 | MIT, ISC, 0BSD, Apache-2.0, Apache-2.0 AND BSD-3-Clause |

These are conservative production lock inventories, not counts of packages
remaining after bundling/tree shaking. No unknown, non-OSI, or GPL/AGPL-only
license was found in those entries. Evidence can be reproduced from each pinned
upstream `LICENSE` and `package-lock.json`:

- [checkout](https://github.com/actions/checkout/tree/d23441a48e516b6c34aea4fa41551a30e30af803)
- [setup-python](https://github.com/actions/setup-python/tree/ece7cb06caefa5fff74198d8649806c4678c61a1)
- [setup-node](https://github.com/actions/setup-node/tree/249970729cb0ef3589644e2896645e5dc5ba9c38)

Setup Actions download language runtimes from their documented upstream sources
when needed. No cache or artifact upload is configured here; Node's automatic
package-manager cache is explicitly disabled. The GitHub-hosted Ubuntu runner,
Python/Node runtimes and Docker/Compose are execution tools, not redistributed
ServerSentinel components. Future runtime packages/images require their own
license, pinning, and network review under `docs/THIRD_PARTY_POLICY.md`.

If distributing any tool source or binary, retain its upstream copyright and
license text and all applicable bundled notices, including Apache notices.
This inventory does not replace those redistribution obligations. Existing
Claude review automation remains documented in `docs/CLAUDE_REVIEW_SETUP.md`.
