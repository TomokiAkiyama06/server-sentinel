# Development and Deployment Tooling

Owns repeatable development checks and future install/update/uninstall helpers, coordinating packaging in `infra/` and application configuration contracts.

`ci/repository_guard.py`, `ci/license_gate.py`, and `ci/component_checks.py`
provide the hardware-free CI checks. The license gate reconciles reviewed exact
dependency/model evidence against lockfiles and committed model artifacts before
release. See [`docs/CI.md`](../docs/CI.md) for coverage, local commands, and
component onboarding.

Installer workflows receive configurable runtime paths and validate the expected media mount/filesystem/device, service-account writability, free space, and safety reserve before creating or admitting media storage. Never silently fall back to the root filesystem, hard-code private deployment values, commit secrets, change Tailscale policy, or delete evidence without explicit owner authorization.
