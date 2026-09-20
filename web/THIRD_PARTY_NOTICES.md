# Dashboard dependency inventory

Reviewed for #8 on 2026-09-20 against exact official npm metadata,
integrity-checked tarballs, LICENSE/NOTICE files and material bundled notices.
Direct versions are exact in package.json; package-lock.json fixes all transitive
and optional platform packages with integrity. No model or weights are added.

| Package | Exact version | License | Purpose |
|---|---|---|---|
| [React](https://registry.npmjs.org/react/19.3.0) | 19.3.0 | MIT | Browser runtime |
| [React DOM](https://registry.npmjs.org/react-dom/19.3.0) | 19.3.0 | MIT | Browser renderer |
| [Scheduler](https://registry.npmjs.org/scheduler/0.28.0) | 0.28.0 | MIT | Runtime transitive |
| [React types](https://registry.npmjs.org/@types%2freact/19.3.0) | 19.3.0 | MIT | Development declarations |
| [React DOM types](https://registry.npmjs.org/@types%2freact-dom/19.3.0) | 19.3.0 | MIT | Development declarations |
| [csstype](https://registry.npmjs.org/csstype/3.2.3) | 3.2.3 | MIT | Type-only transitive |
| [TypeScript](https://registry.npmjs.org/typescript/6.0.3) | 6.0.3 | Apache-2.0 | Type checker; no npm dependencies |
| [esbuild](https://registry.npmjs.org/esbuild/0.28.2) | 0.28.2 | MIT | Local bundler; optional platform binaries |

React/React DOM/Scheduler are the only permitted third-party inputs in the
browser bundle. scripts/build.mjs checks its build input inventory and copies
their complete MIT license files beside the generated assets. Legal comments
are retained in sidecars. Include these license files when distributing assets.
Development tools and declarations never enter the browser bundle.

TypeScript's ThirdPartyNoticeText.txt retains Unicode, W3C, WHATWG attribution
and Khronos declaration-data notices. These declarations supply compile-time
types and emit no JavaScript; they are not all Apache-2.0. Preserve upstream
LICENSE and ThirdPartyNoticeText if redistributing the development tool.
A future distributable tool image requires a complete notice inventory.

All 26 optional esbuild platform manifests at 0.28.2 declare MIT and no further
npm dependencies. The compiled tool also carries Go BSD/patent obligations.
Install lifecycle scripts, including postinstall fallback downloads, are
disabled. The matching optional package supplies the executable. Preserve
Go/esbuild notices if redistributing the tool.

These are maintained releases. TypeScript 6.0.3 deliberately retains the
established JavaScript checker without the new native compiler dependencies.
This is not a guarantee of no security defects; updates need renewed exact
license/transitive review. Runtime code has no reporting/network client.
Dependency installation contacts npm; npm audit/funding and lifecycle scripts
are disabled during installation.

Browser tests use Node built-in modules and the [Chrome DevTools
Protocol](https://chromedevtools.github.io/devtools-protocol/).
The [GitHub Ubuntu 24.04 runner](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
supplies its installed Chrome as an execution tool. Tests print the executed
browser version, download no browser, and distribute none with ServerSentinel.
Page interception does not prove machine-wide zero egress.

The CI-only smoke execution image is pinned to
`node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6`.
[Node 24.21.0](https://github.com/nodejs/node/blob/v24.21.0/LICENSE) is MIT with
bundled notices; Debian system tools have their own licenses, including separate
GPL-family utilities. They are unmodified execution tools, not linked into the
dashboard or published as a ServerSentinel image. A future image distribution
must preserve notices and fulfill applicable source-availability obligations.
