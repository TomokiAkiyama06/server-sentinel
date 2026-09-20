# ADR-0003: Native versioned Main Server release lifecycle

Status: Accepted

## Context

`REQUIREMENTS.md` DIST-001 requires a self-hosted Main Server, and Issue #47
(Plan 22) requires a stable install / update / rollback lifecycle that is
clearly separated from a mutable development checkout. Earlier documents
advertised "Docker Compose where appropriate" as an alternative Main Server
deployment path without defining what that path had to guarantee.

The lifecycle has to satisfy several existing invariants at once:

- runtime configuration, state/database, recordings and audit logs live outside
  both the checkout and the installation tree (AGENTS.md §12, REQUIREMENTS.md
  DIST-001);
- an expected runtime mount that is missing or substituted refuses unsafe writes
  and never silently falls back to the root filesystem (AGENTS.md §12);
- the service runs as a dedicated non-root account with narrow privileges;
- the human listener stays private by default behind the trusted-proxy boundary
  (AGENTS.md §9);
- install, update and rollback never delete, truncate or rewrite recordings,
  starred recordings, protected incidents or audit records, and never perform a
  destructive downgrade (AGENTS.md §14, Issue #47 acceptance criteria).

Maintaining two deployment paths that each had to prove all of the above, while
only one of them was implemented and tested, would have left the documented
Compose path as an unverified claim.

## Decision

1. The only implemented and documented Main Server deployment path is a native
   versioned release lifecycle: a checksummed version archive, a standalone
   installer zipapp, per-version immutable release trees under an installation
   root, atomically switched `current` / `previous` pointers, and a generated
   `server-sentinel.service` systemd unit.
2. No Docker Compose path for the Main Server is implemented or advertised.
   `infra/docker/` remains a future integration boundary. A future Compose path
   must provide the same external runtime mount, mount-loss refusal, dedicated
   non-root identity, private listener boundary, versioned update and
   state-compatible rollback guarantees before it is documented as available.
   This does not restrict container use for other components.
3. The installer is executed deliberately by an administrator with root
   privileges. It is not a service, is never invoked by the application, and
   performs no network access: the release archive, its SHA-256 and the offline
   wheelhouse are supplied by the administrator.
4. Trust in a release comes from content hashes, not from a transport: the
   installer verifies the published outer archive SHA-256, the manifest version,
   and every member digest before any release code is executed, and installs
   dependencies offline with `--require-hashes --only-binary=:all: --no-index`.
5. Deployment configuration is administrator-owned and runtime-readable but not
   runtime-writable. Only state/database, recordings and audit directories are
   writable by the dedicated account, on an Owner-approved runtime filesystem
   pinned by its filesystem UUID.

## Alternatives

- **Keep Compose as a parallel documented path.** Rejected for now: it would
  have to re-establish every guarantee above (external runtime mount identity,
  non-root identity, private listener, rollback) and none of that is implemented
  or tested. Documenting it would advertise unverified behavior.
- **Distribution packages (`.deb`) instead of an archive plus installer.**
  Deferred. It adds a signing/repository trust chain and archive-format
  obligations that the project is not ready to own, and it does not by itself
  provide the version pointer, rollback and runtime-mount validation this
  lifecycle needs.
- **Unprivileged, user-level systemd service.** Rejected: the lifecycle has to
  create root-owned release trees and a system unit that a compromised runtime
  account cannot modify.
- **Pin the runtime filesystem by Linux major/minor device numbers only.**
  Rejected as the primary identity: a replaced or reformatted disk can reuse the
  same device numbers and the same mount path, so the major/minor pair can only
  corroborate the filesystem UUID.

## Consequences

- One deployment path is implemented, documented and covered by synthetic tests;
  `README.md`, `docs/SETUP.md`, `SPECIFICATION.md` and `infra/*/README.md` state
  that no Compose path is currently available.
- Running the installer requires deliberate root execution. Its privileges are
  bounded: it refuses a non-canonical unit path, refuses installation ancestors
  that are symlinked, non-root-owned or group/world-writable, refuses a non-root
  service account, drops to the dedicated account for preflight, and holds a
  service-global lock for the whole transaction.
- A compromised or malicious release archive is only as trusted as the
  administrator-supplied SHA-256. That supply-chain assumption is explicit in
  `SECURITY.md` rather than implied.
- Releases accumulate under the installation root until an administrator prunes
  them deliberately; the lifecycle never deletes release trees other than a
  staged release whose own installation failed.
- Adding a Compose path later requires a new ADR and the same acceptance
  evidence.

## Validation

Synthetic, hardware-free coverage in `server/tests/test_release.py` and
`server/tests/test_systemd.py`: install / update / rollback preserving external
runtime markers, failed activation restoring the prior release and its unit,
failed release-pointer writes restoring both pointers, artifact and manifest
digest verification, archive-shape bounds, unit rendering, service unit creation
modes, release-operation locking, restrictive and permissive administrator
umasks, root-filesystem and root-device refusal, approved filesystem UUID
mismatch and replacement refusal, runtime-subdirectory symlink escape refusal,
and administrator-owned configuration requirements.

This is synthetic verification only. No deployed Main Ubuntu Server, systemd
activation, real filesystem replacement, or trusted-proxy boundary was
exercised. Those remain the `MANUAL_TEST.md` section V acceptance checks for
Issue #47.

## Follow-up

- `MANUAL_TEST.md` section V — deployed install / update / rollback acceptance,
  including the recording/audit content-evidence comparison.
- Issue #48 — first-run setup wizard on top of a deployed installation.
- A future Compose path, if proposed, needs its own ADR and acceptance evidence.
