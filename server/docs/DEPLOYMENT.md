# Main Server release lifecycle

Development commands in `FOUNDATION.md` run from a mutable checkout. A stable
deployment instead uses the versioned archive and installer described here. Do
not point a production service at a Git clone.

## Release artifact

Use a supported CPython and download the exact reviewed wheels from
`requirements.lock` into an otherwise empty wheelhouse. Build from a tagged
release checkout:

```sh
cd server
python3 -m pip download --require-hashes --only-binary=:all: --no-deps \
  --dest /tmp/server-sentinel-wheelhouse -r requirements.lock
python3 build_artifact.py --version 1.0.0 \
  --wheelhouse /tmp/server-sentinel-wheelhouse \
  --output /tmp/server-sentinel-main-1.0.0.tar.gz
python3 build_installer.py \
  --output /tmp/server-sentinel-installer-1.0.0.pyz
```

The archive contains only the Main Server package, reviewed lock and license
material, and supplied wheelhouse. It contains no checkout history, tests,
deployment configuration, credentials, or runtime data. Publish its reported
SHA-256 separately with the versioned release. The installer verifies that
outer digest, the manifest version, every member digest, and the bounded
regular-file archive shape before executing release code. Publish the reported
installer SHA-256 as well; the installer zipapp contains only standard-library
installer/configuration code plus project license material and runs without a
repository checkout.

## One-time deployment preparation

Create a dedicated non-root account and an Owner-selected runtime filesystem.
Create `state`, `recordings`, and `audit` directories on it; all four
directories must be private and owned by the service account, and must keep
owner read, write and execute permission (mode `0700`). A directory that is
owned by the service account but not writable by it — `0500`, for example — is
refused, because readiness would otherwise be announced for a runtime tree that
later recording or audit writes cannot use. The installer
never creates these paths and never substitutes the checkout, installation tree,
or a directory left on the root filesystem by a missing mount.

The configuration file itself is administrator-managed, not runtime data. Place
it in an administrator-controlled directory outside the installation tree and
outside the runtime root, owned by `root`, in a directory whose every path
component is root-owned and not writable by others unless it is sticky. Give it group read for the service account's group
and nothing more, for example `root:server-sentinel` with mode `0640`. The
runtime account must be able to read it and must never be able to rewrite it; a
world-readable, group-writable, service-owned, or runtime-root-resident
configuration is refused.

Keep the installation destination, the configuration, and the runtime root out
of `/tmp`, `/var/tmp`, `/home`, `/root` and `/run/user`. The unit sets
`PrivateTmp=true` and `ProtectHome=true`, so the running service sees empty or
inaccessible trees there and could not enter the release directory or reopen
the configured data. The installer refuses those locations before staging, and
refuses installation, configuration, or unit paths containing `..`.

The JSON configuration has this shape (values are examples, not deployment
defaults):

```json
{
  "runtime_root": "/srv/example-filesystem/server-sentinel",
  "runtime_mount_point": "/srv/example-filesystem",
  "runtime_device": [8, 1],
  "runtime_filesystem_uuid": "00000000-1111-2222-3333-444444444444",
  "service_uid": 991,
  "human_host": "127.0.0.1",
  "human_port": 8000,
  "log_level": "INFO"
}
```

`runtime_filesystem_uuid` is the Owner-approved filesystem UUID, resolved
through `/dev/disk/by-uuid`. It is the stable runtime-filesystem identity:
reformatting or swapping the disk changes it even when the mount path, the
directory layout and the Linux device numbers are reused, so the replacement is
refused instead of written to. Read it with `lsblk -no UUID <device>` or
`blkid`, and record it only in this private configuration.

`runtime_mount_point` must be an absolute path. A relative value would resolve
against whichever directory the caller happens to be in, which differs between
the administrator running the installer and the service resolving it from the
release tree, so it is refused.

`runtime_device` records the decimal Linux major/minor numbers of the same
filesystem. It corroborates the UUID and catches a missing mount that leaves a
directory behind, but it can never replace the UUID because a replacement disk
can reuse the same numbers. The mount point must contain the runtime root and
resolve to that same device, and the runtime filesystem must not be the
operating-system root filesystem or backed by its device.

Keep actual paths, filesystem identity and UID private. A loopback literal is
mandatory for the human listener; expose it through the separately configured
trusted private proxy after application authorization is available.

### Monitoring section (required to run the service)

The `monitoring` object configures the Main Server monitoring runtime
(storage admission, retention, daily summary, hardware integrity and recording
health). Values below are internally consistent examples for a filesystem
of roughly 1 TB, not defaults; size them for the actual deployment:

```json
"monitoring": {
  "time_zone": "Asia/Tokyo",
  "daily_summary_time": "23:00",
  "slack_webhook_url": "<private incoming webhook, optional>",
  "storage_limits": {
    "recording_limit_bytes": 500000000000, "critical_allowance_bytes": 10000000000,
    "hard_reserve_bytes": 20000000000, "pressure_free_bytes": 40000000000,
    "recovery_free_bytes": 60000000000, "recovery_allocation_bytes": 450000000000,
    "write_overhead_bytes": 1048576, "max_request_bytes": 16777216,
    "cleanup_batch_size": 100
  },
  "recording_limits": {
    "pre_roll_bytes": 67108864, "max_segment_bytes": 8388608, "max_segment_ms": 10000,
    "max_active_recordings": 4, "max_spool_segments": 64,
    "max_segments_per_recording": 8640
  },
  "recording_filesystem": {
    "filesystem_uuid": "00000000-1111-2222-3333-444444444444",
    "device": [8, 1],
    "mount_point": "/srv/example-filesystem"
  }
}
```

`time_zone` is an IANA name and is required when the object is present;
`daily_summary_time` defaults to 23:00. Slack stays disabled without
`slack_webhook_url`; keep that value only in this private file. Every storage
and recording limit must be sized for the deployment (all positive integers,
`hard_reserve_bytes < pressure_free_bytes < recovery_free_bytes`,
`recovery_allocation_bytes < recording_limit_bytes`, `cleanup_batch_size` at
most 1000, `max_segment_bytes` at most `max_request_bytes`); ServerSentinel does
not guess them. `recording_filesystem` must describe the filesystem that holds
`<runtime_root>/recordings`: the UUID must resolve to its device, `device` must
equal its major/minor numbers, and `mount_point` must be a mounted ancestor on
the same device other than the operating-system root. The runtime re-checks this
identity on every storage sample and refuses writes, without a fallback, when
it no longer holds.

The service must run the startup/daily hardware integrity check and the daily
recording self-test, which need all three of `storage_limits`,
`recording_limits` and `recording_filesystem`. Without the object, or without
those sections, `--check` (the unit's `ExecStartPre`) and the launcher fail
with the value-free validation message, and `python -m app` logs
`monitoring_storage_unconfigured` and exits non-zero, so the service never runs
with the mandatory checks silently absent. Supplying only some of them, or any
invalid value, also fails `--check`.

### Local UVC section (optional)

The optional `local_uvc` object names the logical Camera Registry sources
(1 to 4) whose USB/UVC cameras the Main Server backend supervises:

```json
"local_uvc": {
  "source_ids": ["00000000-0000-4000-8000-000000000001"],
  "poll_timeout_seconds": 1.0,
  "retry_delay_seconds": 1.0,
  "join_timeout_seconds": 3.0
}
```

`source_ids` are canonical lowercase registry source UUIDs, never device paths,
`/dev/videoN` numbers, serials or other physical evidence; the physical camera
for each source is selected only by the audited Owner approval and stays in the
private approval store. A listed source without that approval stays `offline`
and never opens a device. The timing keys are optional (bounded; invalid values
fail `--check`). A UUID that is not a `local_uvc` registry source is rejected at
startup and reported, never silently skipped. Without the object the backend
logs `local_uvc_unconfigured` and keeps an explicit `unconfigured` local capture
state; remote-agent-only deployments need no `local_uvc` object.

### Detection section (optional; inference stays unavailable without it)

The optional `detection` object binds reviewed detectors to sources. Values
below are placeholders showing the shape, not defaults or recommendations;
thresholds, cadence and limits must come from the target-host measurements in
`MANUAL_TEST.md` (Issue #20):

```json
"detection": {
  "bindings": [
    {
      "source_id": "00000000-0000-0000-0000-000000000001",
      "detector": {
        "kind": "motion", "implementation": "server-sentinel-gray-difference",
        "version": "1", "pixel_delta": "<evaluated>", "changed_fraction": "<evaluated>"
      },
      "cadence": {
        "cadence_ns": "<ns>", "maximum_cadence_ns": "<ns>",
        "maximum_queue_age_ns": "<ns>", "maximum_evaluation_ns": "<ns>",
        "maximum_observation_age_ns": "<ns>", "maximum_pixels": "<pixels>"
      },
      "worker": {
        "evaluation_timeout_ns": "<ns>", "start_timeout_ns": "<ns>",
        "restart_backoff_ns": "<ns>", "maximum_consecutive_failures": "<count>",
        "address_space_bytes": "<bytes>", "open_files": "<count>"
      }
    }
  ]
}
```

Every key is required and numeric values are JSON integers (fractions are
numbers in (0, 1]); unknown keys are refused. A person binding instead uses
`"kind": "person"`, `"implementation": "rtdetr-v2-r18vd-onnx-cpu"`, the pinned
model revision as `version`, an absolute `artifact` path, `artifact_sha256`
equal to the pinned digest, `score_threshold` in (0, 1) and
`intra_op_threads` from 1 to 64; see `DETECTOR_FOUNDATION.md`. Any other
implementation, version or digest is refused rather than substituted. At most
four distinct sources may be bound, each at most once per detector kind.
`evaluation_timeout_ns` must be at least `maximum_evaluation_ns`; the worker's
frame limit is derived as three bytes per `maximum_pixels`. Watchdog timeouts
must be representable by the poll(2) wait (at most `(2**31 - 1) * 1_000_000`
ns) and `address_space_bytes` / `open_files` below `2**63`, so an oversized
value is refused at `--check` instead of failing after a worker is spawned or
being read as an unlimited rlimit. These are representability ceilings, not
recommended values.

Without the object, no inference runtime can be constructed and every source's
detector observation remains `unknown`, never `absent`. An invalid object fails
`--check` with the value-free validation message. Keep the artifact path in
this private file only.

### Host SSH and the reserved-hostname listener exception

The hostname reservation check (ADR-0003, `server/app/auth/README.md`) excepts
a wildcard system listener only by port plus owning process. On the Main
Server, run `sshd` as `ssh.service` itself rather than socket-activated
through `ssh.socket` (Owner decision, 2026-10-01): with socket activation PID 1
holds the listening socket, which no exception identifies narrowly, so access
would stay closed. The Owner exception is then `tcp/22` owned by
`/usr/sbin/sshd`. These are host administration steps for the Owner; keep a
console or second session open while changing SSH:

```sh
sudo systemctl disable --now ssh.socket
sudo systemctl enable --now ssh.service
systemctl is-enabled ssh.socket ssh.service   # expect: disabled / enabled
sudo ss -ltnp 'sport = :22'                   # expect: users:(("sshd",pid=N,...))
sudo readlink /proc/N/exe                     # expect: /usr/sbin/sshd
```

Repeat the `ss`/`readlink` check after each `openssh-server` upgrade and restart
`ssh.service` once upgraded: until then the running executable shows as
`(deleted)` and the check keeps access closed.

Until the privileged socket-owner helper of Issue #126 lands, the non-root
ServerSentinel service cannot read a root-owned `sshd`'s `/proc/<pid>/fd` and
`exe`, so an excepted `sshd` stays `LISTENER_OWNER_UNVERIFIED` and human
access stays closed. ServerSentinel itself is never given root for this.

### Capture-node CA and Main listener certificate

The local pairing CLI (`python -m app.cameras.remote_agent.pairing_cli`, see
`server/app/cameras/remote_agent/README.md`) keeps the deployment CA key and the
Main capture listener credential in two different owner-only directories
(0700, files 0600), both outside the checkout and media trees. The application
does not start the ingest listener yet (#14/#15); these steps prepare it.

**Separate accounts (Issue #124).** The CA directory belongs to the account
that runs the CLI. The listener directory may belong to a different,
non-root ingest service account that must never be able to read the CA key.
Pass `--listener-owner <account or UID>` to `init`, `rotate-listener`,
`export-bundle` and `approve`. The CLI then creates the listener directory and
files already owned by that account (`fchown` happens before any key byte is
written), so no manual `chown` is needed and the ingest service reads them as
its own. Required privileges for that CLI run:

- writing (`init`, `rotate-listener`): effective `CAP_CHOWN` and
  `CAP_DAC_OVERRIDE`;
- reading (`export-bundle`, `approve`): `CAP_DAC_OVERRIDE` or
  `CAP_DAC_READ_SEARCH`.

Root has both, so the simplest form is running the CLI as root with a
root-owned CA directory. A non-root CA account can instead be given exactly
these effective capabilities for that one administrative command (for example
through systemd ambient capabilities); no service is given them. That variant
is not yet verified on a real host (`MANUAL_TEST.md`). Without them
the command refuses with `listener_owner_requires_privilege` before writing
anything. Without `--listener-owner`, the listener files belong to the
account running the CLI, and an ingest service under another account refuses
to load them (fail closed). `approve` still opens the CA key, the listener
credential and the application database in one process (separating the CA key
from the enrollment listener is #109), so the account running it needs the CA
directory as its own, the read privilege above for the listener directory, and
the database as its own; `list` and `revoke` need only the database.
`approve`, `list` and `revoke` never create a database: `--database` must name
the application's existing database file (canonical path, regular file with
one link, owned by the account running the command, not group- or
other-writable), otherwise they refuse `database_not_found`,
`database_path_rejected` or `database_rejected`. They never migrate either:
the database must already carry exactly this release's schema history,
otherwise they refuse `database_schema_outdated` (start the application once
so its startup migration runs) or `database_schema_unsupported`. The validated
file stays pinned for the whole command: if it is renamed, replaced or removed
afterwards (for example while `approve`/`revoke` waits for the typed
confirmation), every later ledger access and commit refuses
`database_rejected`, nothing is written to whatever is now at the path and no
file is recreated. Each connection is also checked against the inode SQLite
actually opened (the process's descriptors in `/proc/self/fd`), so a path
switched to another file only for the moment of the open is refused too. `export-bundle` and `approve`
refuse `listener_authority_mismatch` when the listener certificate was not
issued by the selected CA directory.

**Rotating the Main listener certificate (Issue #125).** The listener leaf
defaults to 397 days and is not renewed automatically. Rotate it before it
expires, as the account (and with the privileges) used for `init`:

```sh
python -m app.cameras.remote_agent.pairing_cli rotate-listener \
  --authority-dir <ca_dir> --listener-dir <listener_dir> [--listener-owner <account>]
# prints: listener rotated: not_after=<UTC time>
```

then restart the process that serves the capture listener so it loads the new
pair (a running listener keeps the pair it loaded at start). The CA and the
server name do not change, so Agents keep their trust bundle and need no
action; `export-bundle` output is unchanged. Rotation refuses
`listener_authority_mismatch` when the listener certificate was not issued by
the selected CA directory (for example two deployments' directories mixed up),
and `issuer_material_busy` while another `init`/`rotate-listener` holds the
directory. The old key is removed by the rename; nothing is kept beside it.
If a rotation is interrupted between replacing the key and the certificate,
loading the listener refuses `listener_material_inconsistent`; rerun
`rotate-listener`, which completes the interrupted rotation (`listener
rotation completed (interrupted run)`) instead of issuing another one. The
same applies when the key rename took effect but the directory fsync after it
failed (`issuer_material_replacement_unconfirmed`): the staged certificate is
kept, and the rerun completes the pair.

**CA validity.** A leaf is never issued beyond the deployment CA's own
expiry. When the CA has less than the requested validity left, `init`,
`rotate-listener` and `approve` refuse `deployment_ca_validity_insufficient`
(a shorter `--server-validity-days` still rotates the listener), and node
renewals are refused `renewal_ca_validity_insufficient` and raise the local
Owner warning `capture_trust_warning` (not the per-node renewal warning).
`CaptureCredentialMonitor` can also raise it ahead of time from the CA and
listener expiry (30 days before the CA stops covering a 397-day node leaf, and
30 days before the listener certificate expires); no scheduler runs the
monitor yet (#14/#15), so until then track the printed `not_after` yourself.
Replacing an expiring CA means a new `init` and re-pairing every Agent; plan
it before the CA has 397 days left.

### Capture-node re-pairing (expired or revoked node)

A `remote_agent` capture node whose credential expired, or that the Owner
revoked, is re-paired with the Main's local pairing CLI and the Agent's
`media_capture_agent.enroll --repair` mode (#116, Owner policy 2026-10-01);
nothing is deleted from the Main database. Run
`python -m app.cameras.remote_agent.pairing_cli list --database <data_dir>/state.sqlite3`
first to see whether the node is `credential=revoked`:

- not revoked, certificate expired: the Agent runs `request --repair expired`
  (its same key); `approve` shows `existing capture node: <uuid>` and the Owner
  types `APPROVE`; the Agent runs `pair --repair expired`. The node UUID and its
  camera sources stay the same.
- revoked: the Agent runs `request --repair revoked` (a fresh key). `approve`
  refuses the old key (`public_key_revoked`) and shows `new capture node` for
  the new one. After `pair --repair revoked` the Agent holds a new node UUID
  and prints the exact change (`config_update_required: set "node_id": "<new
  uuid>" ...`). Make that edit in the Agent's protected configuration by hand:
  until then the Agent refuses to start (`node_identity_mismatch`, also from
  `--check`), with no capture or ingest. Then approve that node's camera
  sources again. The revoked node stays listed as revoked, and
  its recordings stay under it until normal retention removes them.
  `--repair revoked` does not revoke anything on the Main: if it was used for a
  node that was not revoked (for example one that had only expired), the
  replaced node stays active on the Main until the Owner runs `pairing_cli
  revoke` for it, which the Owner must then do. Each further `request --repair
  revoked` after a completed swap prepares yet another new node, so do not
  repeat it once `pair --repair revoked` has succeeded.

If the Agent refuses with `node_credential_unavailable` because its installed
credential's commit was lost (`credential_commit_missing`: the
`node-identity-installed` evidence is present but `node-credentials/current.json`
or the directory is missing), there is no in-place repair. The Owner revokes
the old node on the Main (`pairing_cli revoke`); until then it stays active
there. The operator, as the Agent service account with the service stopped,
moves aside (does not delete until no longer needed for diagnosis)
`<runtime_root>/node-credentials/`, `<runtime_root>/node-identity-installed` and
any `pending-*` directories, then pairs again from scratch (`request`, `approve`,
`pair`) as a new node, sets the printed `node_id` in the configuration and has
the Owner approve its camera sources again.

Stop the Agent's `media-capture-agent` service before re-pairing and start it
afterwards. The full Agent-side procedure and its refusal words are in
[`agent/pairing/README.md`](../../agent/pairing/README.md); the real-LAN
checks are MANUAL_TEST §B step 15 (not yet executed on real hosts).

## Install, update, and rollback

Run the separately downloaded installer only after verifying its published
SHA-256. Global arguments precede the operation:

```sh
sudo /tmp/server-sentinel-installer-1.0.0.pyz \
  --destination /opt/server-sentinel-main \
  --config /etc/server-sentinel/deployment.json \
  --unit /etc/systemd/system/server-sentinel.service \
  install --version 1.0.0 \
  --artifact /tmp/server-sentinel-main-1.0.0.tar.gz --sha256 <published-sha256>

sudo /tmp/server-sentinel-installer-1.1.0.pyz \
  --destination /opt/server-sentinel-main \
  --config /etc/server-sentinel/deployment.json \
  --unit /etc/systemd/system/server-sentinel.service \
  update --version 1.1.0 \
  --artifact /tmp/server-sentinel-main-1.1.0.tar.gz --sha256 <published-sha256>

sudo /tmp/server-sentinel-installer-1.1.0.pyz \
  --destination /opt/server-sentinel-main \
  --config /etc/server-sentinel/deployment.json \
  --unit /etc/systemd/system/server-sentinel.service rollback
```

`--unit` accepts exactly `/etc/systemd/system/server-sentinel.service`. Using one
canonical administrator unit prevents another systemd search path from selecting
a different definition when the installer restarts the logical service.

`--destination` is created when it does not exist. An existing directory is
adopted only when it is empty or is already a ServerSentinel installation root,
and its mode is never widened otherwise, so a mistyped destination is reported
instead of being relaxed.

Each release gets its own virtual environment under `releases/<version>`.
Dependencies install offline from the artifact with hashes and binary-only
enforcement. Root-only environment construction accepts only an absolute,
root-controlled interpreter and runs Python isolated from the invoking directory
and inherited `PYTHON*` environment. Preflight runs as the dedicated account.
`current` and `previous`
are atomically replaced relative symlinks; a failed update restart restores and
restarts the prior release. Rollback defaults to `previous`, or accepts an
already installed `--version`. Both release pointers and the service unit move
inside one guarded transaction: a failure at any point restores both pointers and
the previous unit and restarts the release that was running before the attempt.
One service-global lock covers each whole install, update, and rollback, so
overlapping administrator invocations are serialized rather than interleaved.

Releases and runtime data are never deleted by these operations; only a staged
release whose own installation failed is removed. Database migrations are
forward-only, so an older application may reject a newer database; that failed
rollback restores the release that was running before the attempt.

Release trees therefore accumulate under the installation root. Keep the
installation filesystem separate from the runtime filesystem so release growth
cannot consume recording space, watch its free space, and prune an old release
directory only as a deliberate administrator action, never the release named by
`current` or `previous`. Pruning touches the installation filesystem only and
never state, recordings, or audit data.

The generated systemd unit runs without capabilities as the dedicated account,
gives write access only to the `state`, `recordings` and `audit` directories —
not to the runtime root itself, so the service cannot replace or remove them —
checks mount/config before every
start, and invokes the loopback-enforcing launcher. It uses `Type=notify`; the
launcher sends readiness only after ASGI lifespan/database migration and Uvicorn
listener startup both succeed. `systemctl restart` therefore remains pending or
fails rather than accepting a merely spawned process. Enabling the unit at boot
remains an explicit administrator action. Install the Ubuntu package providing
`venv` for the selected Python before the first release operation; the installer
fails closed if it cannot create the per-release environment.

## Preservation inventory across update and rollback

Counts, sizes and first/last timestamps cannot detect a same-size byte
replacement or a rewritten middle audit row. Before every update and rollback,
and again after each one, compare a content inventory taken with the installed
release's own tool. Run `verify` only after the updated or rolled-back release
has started: the guarded restart reports success only after systemd readiness,
which follows the release's database migration, so the applied migration
history must then equal that release's full migration list. It opens the state database read-only (SQLite `mode=ro`
with `query_only`), never creates or migrates it, and only reads segment files:

```sh
sudo /opt/server-sentinel-main/current/venv/bin/python -I -m app.lifecycle_inventory \
  record --runtime-root <runtime_root> --output <private-notes-dir>/before-update.json

sudo /opt/server-sentinel-main/current/venv/bin/python -I -m app.lifecycle_inventory \
  verify --runtime-root <runtime_root> --baseline <private-notes-dir>/before-update.json \
  --report <private-notes-dir>/after-update.json
```

When the deployment configures the separate private Owner-template store, add
`--owner-template-root <owner-template-root>` to both commands. A baseline
recorded with it fails a verification run without it (and the reverse), and
the store database appearing or disappearing is a change. The tool accepts the
store only under the layout the store itself enforces (every path component
unsubstitutable and searchable by the service account, a root of mode exactly
`0700` (so SQLite can write its journal there) and a single-link regular
database of mode exactly `0600` (so `0400`, `0200` or `0000`, which a root
inspector could still read but the service cannot open read-write, are
refused too), never a symlink (the search-permission check reads the classic
owner / group / other bits only and ignores POSIX ACLs, so do not rely on
ACLs to grant the service account access), both owned by the service account that owns
the state database); any other layout is recorded as `unsafe`, is not read and
always fails verification. Likewise a camera source whose stored UVC approval
evidence the service could not load always fails as
`unreadable_approval_evidence`.

When the rolled-back release predates this tool, run the same commands with
the newer release's interpreter under `releases/<version>/venv/bin/python`;
both only read the runtime tree.

`record` stores, keyed by stable logical ID: each recording's source, status,
starred flag, catalog start, target end and ended boundaries (recorded
separately, since playback is clipped to the target end), critical flag, event
link (`event_id`, which groups an event's recordings) and explicit
`recording_discontinuities` markers, and
for every linked segment, whatever its state (a link to a segment that is not
`ready` is never preserved), its source, catalog bounds, the catalog fields that
control integrity, playback or retention (`byte_length`, `stream_id` /
`sequence`, `codec`, `container`, capture node and critical flag) and the
SHA-256, size and hard-link count of its file as read from disk (the recording
store treats a file with more than one link as corrupt); a per-row and a chained SHA-256 over every
retained `security_admin_audit_records`, `integrity_audit`, `presence_audit`
and `storage_state_audit` row; the open presence timeline gap, if any (its
start, latest time and loss counts; it is cleared only by an audited Owner
action, so verification fails if it disappears or shrinks); the durable
presence state whose loss would replay, duplicate or hide critical work, each
allowed only the transitions the presence service performs: completed-event
tombstones and expired-unresolved markers (kept; a new tombstone and every
added marker event must come from an Owner release below),
retained observations as keyed digests (never their content) with their
delivery jobs and source-fact digests (Main does not run timeline expiry, so
an observation may leave only through the Owner's audited release of
unresolved critical work, which needs a recorded job neither delivered nor
disabled and appends one `critical_event_cleared` audit row naming it (no
state, the actor an Owner principal, keyed) at the same time as its
tombstone and advances the control clock to that time (which must not be
behind it now); each release is listed under the presence section's
`released` and counted in the console summary, never silently; the
observation leaves only together with its completed tombstone, and its jobs
only with one expired-unresolved event per job neither delivered nor
disabled, judged by the recorded job states (a job of a released
observation that was delivered inside the window before the release leaves
one event fewer and fails closed); an observation created after the record
and released inside the window is accepted on the same audit row, tombstone
and clock evidence, its events bounded to at least one per such release and
at most one per action (evidence, notification), since its jobs were never
recorded; any other removal, however old the observation, is `missing`,
a job or source fact left behind for a released observation is `retained`,
and a job or source fact whose observation is gone is `orphaned`);
a job's state, attempts and generation may only move forward: a claim, a
recorded outcome, or the audited Owner requeue back to pending, and a
delivered job stays delivered; attempts rise only with a claim, which also
advances the generation, so they never rise more than the generation, and a
generation rising more than the attempts requires the requeue mark), the high-water clocks (may only advance), open
outbox session rows (a row a live outbox held at record time may end in its
clean close; a stale one only in an interrupted gap) and the Owner override
(dropped only once the control clock has reached its expiry);
`presence_inputs` (live inputs with their own validity windows) and
`presence_delivery_fairness` (a round-robin cursor) replay nothing and hide no
failure, so they are not inventoried; the Owner-approved hardware baseline as
its revision and a keyed digest of its inventory (never the hardware
identifiers); pending hardware-integrity notifications (outbox rows as keyed
digests, overflow slots by category and state): a pending row may leave only
once its notification event (`uuid5(EVENT_NAMESPACE, "integrity-outbox:<id>")`)
is durably recorded with the row's own failure / warning kind (from its
immediate flag) and time, and each overflow slot only by its own promotion: a
distinct new outbox row, still pending, with the slot's time and single
category / state. Once that row is delivered it is deleted and only its
notification event (time and failure / warning kind, no category or state)
remains, which an unrelated row could match as well, so such a slot is
reported `unverifiable` (a failure), never preserved: when overflow slots
exist at record time, verify before the service delivers their promotions
(e.g. while it is still stopped for the update), or after an `unverifiable`
result check the Owner's hardware-integrity notifications for that window by
hand and re-record the baseline; one-way security state: capture nodes once
revoked stay revoked; the capture-node pairing ledger (keyed digests of keys
and credential serials only) is checked against the operations
`PairingLedger` performs (approve, redeem / expiry, activate, stage renewal,
promotion, revoke). Every current state must satisfy the ledger's
invariants: every credential's node has an activated enrollment; a revoked
credential's node has every binding revoked, no pending or consumed
enrollment and no staged renewal; an activated enrollment's node has a
credential and a revoked enrollment's node no active one; every binding's
node has an enrollment; an active credential's key, a staged renewal's key
(which differs from the credential's and belongs to an active credential)
and an open enrollment's key are each bound to that node by a live,
unrevoked binding,
every enrollment's key (any state) is bound to its node, a revoked
enrollment's binding is revoked, and a staged renewal's
key is never the key of any enrollment, recorded or current, in any state
(stage renewal binds keys no enrollment names). From record to
verify, each node may only change by a composition of those operations,
and each accepted operation must be matched by the security/admin audit row
the ledger writes in the same transaction, appended since the record
(approval, redemption or its expiry, activation or promotion, revocation;
staging a renewal writes none), otherwise `unaudited`; a row counts only if
it loads through the audit store's own record validation and carries the
actor category the ledger uses for that action, a `capture_node` target and
that node's ID (the audit table has no hash chain or MAC of its own: the
inventory's chain covers the rows present at record time, and rows appended
since are judged by these field checks only):
every enrollment recorded (any state) stays with the same node and key and
only moves forward: pending to consumed, expired, activated or revoked,
consumed to activated or revoked, the other states final (a vanished one is
`missing`), and each transition must come with the rest of the operation that
makes it: an enrollment activated since the record needs the node's
credential to hold the key of an activation since the record and the renewal
staged at record time to be gone; a node is treated as revoked since the
record when one of its recorded open enrollments became revoked (or one
created since is revoked), one of its
bindings became revoked, or its active credential became revoked, and then
every binding of the node (recorded or added since) must be revoked, no
enrollment of it may be pending or consumed, and its credential must stay
revoked (a revoked node is re-paired as a new node with a new key, Owner
decision 2026-10-01, which is what the approve command does); every
accepted credential change since the record on such a node (each
activation, and the promotion of the renewal staged at record time) must,
by the activate audit rows the ledger writes in the same transactions,
precede its first revocation in the window (an activation after it re-opened the node on its
own ID, `reopened`, even if a later revocation closed it again; ordering
relies on the audit clock, so a clock stepped backwards in between can
mis-order them); because revoke() refuses a node with nothing to
revoke, the node must also have had an active credential or an open
enrollment for it to revoke; a revoked credential stays revoked with the
same material; an active one stays, becomes the renewal staged at record
time (promotion) or the identity a fresh pairing installed (an enrollment
pending or consumed at record time with the same node and key, or a new one
whose key was neither bound nor activated at record time, or, as the Owner's
retry of an interrupted, expired or unacknowledged enrollment through the
approve command does, a new one whose key was already bound live to the same
node at record time and still is, or was revoked since only by a complete
revocation of that node); a binding is
never deleted, rebound or un-revoked; a
staged renewal stays, is retried with its own key while the credential is
unchanged, is replaced by a key newly bound since the record, or leaves by
promotion, revocation or a fresh pairing; a credential first seen now needs a
fresh pairing of its key; every binding added since the record, live or
revoked, must be explained by its own key: an enrollment of that node and
key, the node's staged renewal, its current credential key, or, for a
revoked one only, a key staged before the revocation of a node completely
revoked in the window that had an active credential in it (`unexplained`
otherwise); and no node holds more bindings than the ledger's staging cap
plus one per enrollment (`over_capacity`). Four ledger-reachable
cases fail closed: a renewal both staged and promoted inside the window (its
material cannot be shown), a key staged inside the window and then
superseded by another staging or by an activation that drops its renewal
(its binding stays live with nothing left showing it was staged; a later
revocation of the node clears this),
re-pairing or approving anything on a node already revoked, at record time
(reported as a reversed revocation) or inside the window (an incomplete
revocation), on the same node ID instead of a new one, and the Owner approving (including retrying through
the approve command) a key that was staged as a renewal at record time or is
staged now (a key both staged and approved inside the window leaves no
evidence and is not detected); verify before the next automatic renewal, or
investigate and re-record. An invalidated human session never becomes
valid again, and the authorization generation never decreases; for each
registered camera source its type, keyed digests of
its Owner-entered name and role label, a digest of its capabilities, its
`enabled` flag, capture node, a digest of its desired capture profile and of
its detection bindings, and a keyed digest of its durable UVC approval (the
identity `same_physical_camera()` compares: vendor / product / serial /
interface for a unique serial, plus device node, topology, device number and
instance marker for a camera without a serial or with an ambiguous one, so a
swap to another same-model camera is a change; and the `requires_approval` /
`serial_ambiguous` latches); the camera registry's
`max_active_video_sources`; for a configured Owner-template store, whether its
database exists, the enrollment generation and enrolled flag, keyed digests of
the template and its model provenance, and per-row / chained evidence over
`owner_template_audit`; and Owner presence plus each principal's independent
`live:view` / `recordings:view` grants, authorization revision and, for every
credential that is neither revoked nor marked inconsistent, a keyed digest of
its credential ID, public key, algorithm and backup eligibility together with
its signature counter, which may only stay or rise (a lower counter rolls back
the clone-detection floor and is a change; backup state is excluded), and each
invitation's redemption and revocation state, principal revision and
deployment generation bindings (and whether that generation is still
current), issue and expiry times, redemption attempt count and a keyed digest
of its secret digest (so a replaced enrollment binding is a change). Keyed digests
are HMAC-SHA-256 under a random salt drawn for each baseline and stored in it,
so the raw values are never written and a digest cannot be matched across
baselines; whoever holds a baseline can still test a guessed value, so keep it
deployment-local and private. It never writes principal external identities or display names,
credential IDs, public keys or labels, invitation or session secret/token
digests, session identity bindings, permission-bearing URLs, media bytes,
camera serials, device paths, topology or instance markers, Owner template
bytes, embeddings or model provenance, or audit row contents.

The database is read in one short read transaction; segment files are hashed
only after it ends, so the running service's writers are not blocked (a file
changed meanwhile shows as a change). Durable tables not yet inventoried are
listed as `not_inventoried (#132)` in the record and verify output:
`recording_source_discontinuities`, `recording_source_cursors`,
`roi_calibration_history`, `notification_events`, `uvc_approvals.session_token`,
`integrity_status` and `recording_health_status`; do not read a pass as
covering them.

`record` writes a baseline only if verifying that very state, unchanged,
would pass: it runs every current-state check `verify` runs (schema,
values, times, pairing and presence invariants, segment integrity, a usable
Owner and so on) and otherwise exits 1 without writing anything, naming
only the failing categories and their counts.

`verify` reads the baseline only if it is still a private `0600` regular file
(not a symlink) owned by the invoking user or root, and refuses otherwise.
It recomputes the same inventory and compares it. Every table, index and
trigger that the applied migrations create must exist with the definition
they give it, whether or not the tool inventories its rows: the tool replays
the applied part of its own migration catalog into an in-memory database and
compares (a future migration using `ALTER TABLE ... RENAME`, or other DDL
whose stored text depends on the SQLite version or `legacy_alter_table`,
must re-validate this comparison). At `record` a missing or different object (or a history that is
not a prefix of the catalog) refuses to write a baseline (exit 2); at
`verify` it is `table_missing` or `schema_changed` in the `tables` section.
Every Main table the inventory reads that existed at record time must still
exist, even if it was empty then, and
the applied migration history (`schema_migrations` version, name and
checksum, which startup re-checks row by row) must keep every recorded row
unchanged, and the whole history must be exactly this release's own
migration list, in order, as the startup `migrate()` check that has just run
requires: a gap, reordered, duplicated or foreign row is `history_rejected`,
and a shorter history (applied rows removed, so the next start would re-run
their schema changes) is `not_migrated`. Migrations are forward-only: a
rollback succeeds only when the older release accepts the history, so when a
release that predates this tool is verified with a newer release's
interpreter (below) and that newer release defines further migrations, the
result is `not_migrated` and must be investigated rather than accepted. Session or derived tables (WebAuthn challenges, schedule and fairness
cursors, live presence inputs, the self-test artifact pointer, setup wizard
progress) are deliberately not inventoried. A missing or changed
recording, audit row, source, principal or invitation is `failed` (exit 1);
rows and recordings that exist only now are listed as `appended` and are never
counted as preserved. Every time used as evidence (presence clocks, override
expiry, timeline gap, Owner-release audit time, tombstone, integrity and
Owner-template audit times) must be written exactly in the UTC format the
owning service writes and is compared as an instant; a time at another
offset, or otherwise formatted, is never accepted as evidence. The same holds
for every such time present now, recorded or new (presence clocks,
tombstones, unresolved markers, the override, the timeline gap, pending
integrity rows and overflow slots), since the service compares them again
(`invalid_time`), and none of them, nor any audit or pairing audit time,
may lie more than 5 minutes (the clock-skew allowance) beyond the verify
time (`future_time`): a far-future control clock would refuse every later
Owner control operation. A time that does not parse (wrong type, malformed,
negative or out of range) is `invalid_time`, never skipped, and never stops
`verify` from writing its report. Values the services parse again that no
schema CHECK constraint limits (the schema comparison keeps those
constraints in place) are validated on every current row as the owning
service writes them (`invalid_value`): audit rows through the audit store's
record validation, integrity audit actors and revisions, storage-state audit
states, Owner-template audit operations and generations, presence audit
actions and actors, job states and counters, marker counts, the override
state and actor, observation payloads, recording identities, statuses and
boundaries, discontinuity bounds, integrity outbox findings and flag, the
approved hardware baseline, camera-source and detection-binding JSON, and
pairing node and enrollment identities; the segments of a recording that
appeared since the record must also be ones the store would link. Where a
service rebuilds a model from a row, each stored column must be what it
writes from that model: an observation's id, kind, source and receipt time
match its payload; a recording's end matches its status (none while active,
its target when complete or gapped, the recovery boundary when
interrupted); an integrity outbox row's flag matches its findings; the
hardware baseline must build the whole inventory (unique kind / location,
at most 1024 components), and `record` refuses (exit 2) a baseline the
service could not read. Every current row a service rebuilds is passed through that service's own builder, plus the validator it applies when writing: camera sources (`CameraRegistry._source` and its config validator, so capabilities must be a JSON object), capture nodes (`CameraRegistry._node`), access principals and credentials (`AccessStore._principal` / `_credential`) and recording segment identities (`RecordingStore._name`). Rows with no builder are checked field by field as their service writes them: invitations (UUIDs, a 32-byte secret digest, revision / generation no later than the current ones, at most five attempts, issued before expiry, redeemed only before expiry and never both redeemed and revoked; a revocation time is not ordered against the issue time, because revocation takes the caller's clock with no floor), sessions (UUIDs, a 32-byte token digest, a credential of the same principal, last seen and any user verification or mismatch audit no earlier than establishment, the idle expiry the store derives, and no binding once invalidated; an invalidation time is not ordered against establishment, for the same reason), grants, and every pairing row (UUIDs, lowercase SHA-256 hex digests, states, positive expiries). Every recording segment row, linked or only in the pre-roll spool, passes `Segment.validate()` bounds, a lowercase SHA-256 digest, a positive length and the store's state / spool / integrity values, and a ready segment ends at or before its source's publish cursor (its sequence is not bounded: after a change to another stream the store checks none, so a resumed stream may restart below rows it already wrote). A discontinuity marker may be zero-length (a stream change with no time gap). No enum value used by an earlier release has been
retired, so older rows are not rejected by these checks. An override's expiry is legitimately in the future
and the presence service sets no longest duration, so it is not bounded. Presence jobs
and unresolved markers may name only the service's actions (`evidence`,
`notification`). The one exception for missing rows is the service's own
automatic retention, which runs at every startup (so the update restart itself
triggers it) and on its schedule: judged against the verify time with the
service's built-in periods (not deployment-configurable), a security/admin
audit row older than 90 days, an `integrity_audit` row older than 90 days, a
`storage_state_audit` row older than 90 days, and an unstarred `complete`,
`gapped` or `interrupted` recording that ended at least 20 days earlier
(critical recordings included, exactly as `RetentionService.expired()`
selects them) may be gone; each is listed under `retention_expired`, never
counted as preserved. `integrity_audit`, `storage_state_audit` and
`owner_template_audit` reuse the highest row id once retention removed it, so
a recorded row due for removal whose id now holds a row written after the
record is listed as `retention_expired` with the new row `appended`, exactly
as SQLite's row-id allocator reuses ids: every row above the highest
recorded id still present must have been due, and the rows now above it must
be numbered consecutively from it, written after the record, with times
rising with the id. Any other reuse (a rewritten row below a retained one, a
gap, out-of-order times, a recorded row not yet due, or a new row predating
the record) stays `changed`. Retention deletes rows, never a table: if the audit
table or a recording catalog table is gone or unreadable, nothing in it counts
as retention-expired and the section fails as `table_missing`. Anything one
second short of those periods, starred,
still active, or removed by capacity-pressure deletion of the oldest
recordings (`RetentionService.oldest()`) before it reached that age, stays
`missing`. The judgement uses only the row's own time and the verify time,
so a recording that capacity pressure deleted shortly before its 20 days
were up, or that the Owner deleted after them, reads as `retention_expired`
once verify runs past that age; run `verify` promptly after the update, and
if storage pressure or an Owner deletion happened during the window,
investigate and re-record.
Owner-template audit rows older than the store's own 90-day audit retention
may likewise be gone (listed under the section's `retention_expired`), since
the store's cleanup runs at startup when it is registered for audit
retention. Presence audit rows have no automatic retention in Main and must
all remain. A finished recording must be identical, including its
target and ended boundaries (a segment's retention `spool` flag and its cached
`integrity` label, which playback recomputes from the file, are not compared),
and every recorded and current segment of any accepted recording must come
from the recording's own source, overlap its target window and pass the
store's `Segment.validate()` (`invalid_segment` otherwise), and be readable
and match its catalog digest and byte length with a single hard link even if
it was already broken at record time (reported as `catalog_mismatch`). This gate applies to every accepted change,
including a recording active at record time whose broken segment a later
stop drops, and a declared rewrite. A recording the store linked no segment
to (interrupted before any segment arrived, an event over a source with no
media, or one still active with nothing linked yet) never makes `record` fail
(Owner decision 2026-10-05): the inventory marks it `"evidence": "no_evidence"`,
`coverage_counts.recordings_without_evidence` counts it apart from coverage (it
never makes an ordinary or starred recording `present`), and `verify` lists it
under the recordings section's `no_evidence`, never as `preserved`. Only its row
is verified: it must survive (a deleted row is `missing`) under the same
identity, boundary, status and star rules as any other recording, and nothing
about media is claimed for it. A recording linked to a segment that is not
readable, ready evidence still fails as `no_readable_segment_evidence`. A
recording active at record time
may gain segments (one recorded with nothing linked stays under `no_evidence`,
and its first new segment may bring one marker from an earlier, uninventoried
cursor end to that segment's start), move its target end earlier but never later, and stay
`active` with no end or become `complete` or `gapped` ending exactly at its
(possibly earlier) target, or `interrupted` ending exactly at the earlier of
its target and its latest linked segment end, or at its start when none is
linked (startup recovery); its source,
event link, start, starred and critical flags must not change, every recorded
discontinuity marker that still overlaps its target window must remain (a stop
drops only those wholly outside the new boundary), new markers must be
exactly the `stream_discontinuity` markers the store adds when it links a
newly published segment that does not continue the previous linked segment's
stream and sequence (from that segment's end to the new segment's start, one
per such publication, none missing), every newly linked segment must pass the
store's timeline guard (start no earlier than the previous segment's end, no
repeated or rewound sequence on the same stream) and the store's own
`Segment.validate()` (UUID source / stream / capture node, a positive
duration within the 20-minute segment ceiling, valid codec and container
names, a non-negative sequence and a non-empty file; the deployment's
stricter configured limits are not read), every segment it already had must be
identical except that a stop which closes the recording as `complete` or
`gapped` at an earlier target may drop the segments starting at or after that
target, as `RecordingStore.finish()` does (never for a starred or critical
recording, which then fails closed), and every current segment must
come from the recording's own source, overlap its target window, be readable
and match its catalog digest and byte length with a single hard link; anything
else is `changed`. Starring or unstarring
any recording between `record` and `verify` is also `changed` and stays a
failure (Owner decision 2026-09-30): do not change stars during the lifecycle
window; if one changed, investigate it and take a new baseline before the next
operation rather than accepting the result. If a
documented migration intentionally rewrites stored bytes, name each affected
recording in advance with `--declared-rewrite <logical ID>`; those recordings
are reported separately and must be re-verified manually, and any other digest
change is still a failure. The declaration exempts only the media bytes: each
file's digest and size and the catalog byte length. The rewritten files must
match their updated catalog digest and byte length with a single link, and
every other recorded field (star and critical flags, boundaries, event link,
discontinuities, segment set and the remaining segment catalog fields) must be
unchanged; otherwise the declared recording is still `changed`. The comparison is `empty` (exit 3),
never success, while the baseline lacks any of: an ordinary recording, a
starred recording, a camera source, a security/admin audit row, the Owner, a
`live:view`-only grant, a `recordings:view`-only grant, or a revoked principal
or invitation. The Owner counts only if it can still authenticate as the
passkey ceremony requires (an active, unrevoked principal with at least one
credential neither revoked nor marked inconsistent), both for `record`
coverage and for `verify`, where a recorded Owner that can no longer
authenticate is a failure; a grant counts only on a principal that is not
revoked. Capture-agent protected incidents are recorded as not applicable
here (#16 / #28).

Container duration probing and a decodable-playback sample need a codec and are
not performed by the tool; the inventory marks them `manual`, and
`MANUAL_TEST.md` section V covers them. Run `record` while no recording is being
written if possible: a recording started after `record` is only listed as
`appended`, and one in progress at `record` is held to the growth rules above.

A camera source without a unique serial (or with an ambiguous one) is held
for Owner re-approval after every service restart, because only a live
capture descriptor proves the same camera; its approval then differs from the
record, and after a host reboot its device instance marker differs as well.
Such a source is reported `reapproval_required` when nothing else changed,
and that is still a failure: the Owner confirms the camera, re-approves it in
the dashboard and takes a new baseline; an update that includes a reboot
always reports these sources this way.

Output files are created exclusively with mode `0600` and are refused inside
the runtime root, anywhere in the installation destination (every
`releases/<version>` tree and the `current` / `previous` links, not only the
running release's package and virtual environment), and inside any Git
checkout. Use an administrator-private directory outside those
trees. The console summary carries only statuses and counts; the files contain
logical IDs and digests and stay deployment-local, never in GitHub.

### Scope, threat model and limits

Owner decision 2026-10-07: the tool guards against a broken or buggy
migration or update (including a buggy rollback), not against an adversary.
A `preserved` result means that the invariants below held between `record`
and `verify`; it is not a proof that every service state is semantically
intact. The required invariants are:

- recordings: every recording row, its linked segments (catalog fields and
  the SHA-256, size and single hard link of each `.seg` file), its links and
  explicit discontinuity markers, with only the growth the recording store
  performs for a recording in progress. This includes a recording with no
  linked segment (recorded as `no_evidence`; only its row must survive), whose
  markers present at record time must stay, and whose first newly linked
  segment must carry the marker the store adds when that segment does not
  continue the source cursor recorded at record time (or a publication still
  catalogued since that did not overlap the recording). For every recording
  active at record time, changed or not, every still-catalogued segment of
  its source published since the record that overlaps its current (after a
  stop, final) window, the rule `RecordingStore._publish()` links by, must
  be linked to it when it was certainly published while the recording was
  active: the recording is still active, was stopped early, or has a later
  linked segment. Such a segment never explains a cursor advance. The
  publications since the record are every `ready` catalog row of the source
  starting at or after the source cursor recorded at record time, whatever
  its `spool` flag (`release_source()` clears it on linked segments too); a
  publication whose catalog row was removed together with its link is not
  visible to this rule and is caught only through the stream / sequence
  markers of the segments around it. Every ready pre-roll spool segment (`state='ready'`,
  `spool=1`), which a later recording links without re-checking it, must have
  a file matching its catalog digest, byte length and single link
  (`spool_file_mismatch` otherwise);
- the starred flag, which no update may change, and automatic retention only
  of recordings the retention rules make eligible;
- the audit tables, append-only except for rows the service retention removes;
- the Owner and the per-principal grant separation (`live:view` and
  `recordings:view` independently);
- revocation is never undone: revoked principals, invitations, pairing
  credentials, key bindings, capture nodes and invalidated sessions stay
  revoked or invalidated, and the authorization generation never decreases;
- the schema and the applied migration history;
- the session-revocation exposure marker (#134): the
  `application_metadata` row `auth.reservation.session_revocation_pending`
  holds only `1`; when it existed at record time and is gone afterwards,
  verification requires the revocation that alone removes it (a new system
  `invalidate_human_sessions` audit row, an advanced authorization generation
  and every recorded session still present invalidated), otherwise it fails as
  `cleared_without_revocation`;
- the staged renewal certificate of migration 21:
  `pairing_node_renewals.certificate_pem` is either NULL (a row staged before
  the migration) or exactly one PEM certificate whose DER SHA-256 is the
  staged serial digest, the same check the pairing ledger applies, and a
  certificate staged at record time stays with its row while the row and its
  key are kept.

Out of scope, and not claimed by a passing verification:

- detecting deliberate tampering by anyone with write access to the state
  database or the runtime tree (for example replacing a live session's token
  digest while keeping its row shape valid, or rewriting rows and their digests
  consistently); the baseline is an administrator-private file, not a
  signature;
- full re-verification of every service's state-transition semantics. The
  pairing ledger, presence delivery jobs and clocks, and similar service state
  are checked only as far as the rules above describe; the tables listed as
  `not_inventoried` are not compared at all.

Not judged: for a recording that closed at its own deadline or was
interrupted by a restart, a lost link to a segment published after its
latest linked segment, because a lagging source may legitimately publish an
overlapping segment after that close, which the store does not link. Its
link is required only if a later linked segment shows it was published
while the recording was active. A recording stopped early and then closed by
its deadline before the source caught up is held to the stricter rule and may
fail closed.

Known fail-closed side effects (verification fails although the service did
nothing wrong; investigate, then take a new baseline):

- a session revocation inside the window advances the authorization
  generation, which ends every recorded invitation, so those invitations are
  reported `changed`;
- for a recording with no linked segment at record time, when the first
  segment that is later linked continues a pre-roll publication that the
  spool has since evicted, and does not continue the recorded cursor, the
  marker the tool expects from the recorded cursor is missing and the
  recording is reported `changed`.

Deployed acceptance of this lifecycle — systemd activation, the trusted-proxy
boundary, real mount substitution, and the recording/audit content comparison
across update and rollback — is recorded in `MANUAL_TEST.md` section V for Issue
#47. The synthetic tests in `server/tests/` do not establish it.

There is currently no implemented or documented Docker Compose deployment path.
Adding one requires the same external runtime mount, pinned mount failure,
dedicated identity, private listener, version update, and rollback contract;
`infra/docker/README.md` is only a future integration boundary.
