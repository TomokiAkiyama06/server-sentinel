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
  "human_port": 880,
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
In production `human_port` is a loopback port below 1024 that systemd creates
through `server-sentinel-upstream.socket` and passes to the service (see
"Listener owners, the upstream socket and host SSH" below).

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

### Listener owners, the upstream socket and host SSH (Issue #126)

The hostname reservation check (ADR-0003, `server/app/auth/README.md`) needs
to know which systemd unit created each socket it verifies: an excepted
wildcard system listener (for example SSH on tcp/22), a recorded proxy socket,
and the human upstream. The backend finds this out itself, without root, a
helper process or any capability (Owner decision, 2026-10-07): it asks the
kernel's socket diagnostics (`NETLINK_SOCK_DIAG`) for each socket's uid and
the cgroup it was created in, and maps that cgroup to its
`/sys/fs/cgroup/system.slice/<unit>` path. The kernel reports the socket's
creator, not its current holder; a legitimately created socket handed to
another process by a compromised creator is not detected (accepted residual
risk).

Service requirements for this lookup (the unit `server/install.py` renders
meets them; keep them in any drop-in):

- the backend runs in the host network namespace that holds the reserved
  addresses: no `PrivateNetwork=`, `NetworkNamespacePath=` or
  `JoinsNamespaceOf=` (sock_diag and `/proc/net` see only the caller's
  namespace);
- `RestrictAddressFamilies=` includes `AF_NETLINK` (the rendered unit allows
  `AF_UNIX AF_INET AF_INET6 AF_NETLINK`);
- `ProtectControlGroups=` is `true`/`yes` or unset, never `private` or
  `strict`: those give the service its own cgroup namespace and view, so
  cgroup ids no longer map to the host paths;
- the service stays in its own `server-sentinel.service` cgroup (no
  `Delegate=` sub-cgroups that hide processes from the same-uid scan).

Every lookup starts with a self-check: the backend opens a loopback probe
listener of its own and requires the dump to report it with the backend's own
cgroup and uid. If netlink is denied, the kernel lacks the cgroup attribute or
the cgroup view does not match, the self-check fails and human access stays
closed with `LISTENER_OWNER_UNVERIFIED` (no session revocation). Nothing is
widened to make it pass.

#### Human upstream through socket activation

The loopback human upstream is created by systemd, as root, through
`server-sentinel-upstream.socket`, and passed to the unprivileged backend
(`Sockets=server-sentinel-upstream.socket` in the rendered service unit). The
check requires the upstream to be created by that socket unit as uid 0 and to
use a port below `/proc/sys/net/ipv4/ip_unprivileged_port_start` (1024 by
default), so no unprivileged process can bind it. Without activation the
backend, which has no capability, cannot bind a port below 1024 and the
service fails to start; on a port at or above `ip_unprivileged_port_start` it
binds the port itself, which the check treats as a configuration error: human
access stays closed without revocation. These are host
administration steps for the Owner:

0. Update to a release that supports socket activation first (this one or
   later; `app/release_capabilities.py` declares it). An older release ignores
   the passed socket and could not start on the new port.
1. Choose a free loopback port below 1024 (the template uses `880`) and set
   `"human_port"` in the deployment configuration to it, with
   `"human_host": "127.0.0.1"`. Point the Tailscale Serve mapping at
   `http://127.0.0.1:<port>`.
2. Install `infra/systemd/server-sentinel-upstream.socket` as
   `/etc/systemd/system/server-sentinel-upstream.socket` (root-owned, mode
   `0644`) with `ListenStream=127.0.0.1:<port>` set to the same port. Keep
   `ReusePort=no`, `Accept=no` and `Service=server-sentinel.service`.
3. Enable it and restart the service through the normal release lifecycle
   (or once by hand):

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now server-sentinel-upstream.socket
sudo systemctl restart server-sentinel.service
cat /proc/sys/net/ipv4/ip_unprivileged_port_start  # expect: greater than <port>
sudo ss -ltnep 'sport = :<port>'                   # expect: one row, held by the backend
```

The backend refuses to start (`human_listener_activation_invalid`) when the
passed socket is not exactly one listening TCP socket on
`human_host:human_port`, so a port mismatch between the socket unit and the
configuration is caught at start. A port at or above
`ip_unprivileged_port_start` cannot be served by activation's guarantee;
lowering that sysctl later keeps human access closed until it is restored.

#### Host SSH and other system listeners

Socket-activated system services are allowed (Owner decision, 2026-10-07,
reverting the 2026-10-01 step that disabled `ssh.socket`). On the Main Server,
keep Ubuntu's default `ssh.socket`; systemd creates the tcp/22 sockets in the
`ssh.socket` cgroup as uid 0, so the Owner exception is `tcp/22` with unit
`ssh.socket` and uid `0`. If `ssh.socket` was disabled for the earlier
decision, it may be restored (keep a console or second session open while
changing SSH):

```sh
sudo systemctl disable ssh.service
sudo systemctl enable --now ssh.socket
sudo systemctl restart ssh.service   # the running daemon releases :22 to the socket
systemctl is-enabled ssh.socket      # expect: enabled
```

Running `sshd` as `ssh.service` alone also works: the exception is then
`tcp/22` with unit `ssh.service` and uid `0`. Other wildcard system listeners
are excepted the same way by unit and uid, for example `tailscaled` on its UDP
port as `tailscaled.service` with uid `0`. Find the unit and uid of a listener
without privilege, as the service account, with the Issue #126 procedure in
`MANUAL_TEST.md` (section "ADR-0003 follow-up: accepted human-access
boundary").

Exceptions stored before this change (an executable path such as
`/usr/sbin/sshd`, or a unit without a uid) are not migrated: the check reports
`LISTENER_EXCEPTIONS_OUTDATED` and keeps human access closed until the Owner
enters them again through the audited Owner path.

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

**Crossing the socket-activation boundary (Issue #126).** A release from before
socket activation has no `app/release_capabilities.py` declaring
`HUMAN_UPSTREAM_SOCKET_ACTIVATION`: it ignores the socket passed by
`server-sentinel-upstream.socket` and binds `human_host:human_port` itself.
It cannot start while that socket unit is active or enabled (it holds, or will
hold again at boot, the endpoint), nor on a port below
`ip_unprivileged_port_start`, which the non-root service may not bind. Before
switching an `update`, `install` or `rollback` to such a release, the
installer checks both (it only queries `systemctl is-active` / `is-enabled`
for the socket unit; an unclear answer, a timeout or a query that cannot run
counts as in use) and, if either holds, refuses before changing anything: the
running release, both pointers and the unit stay as they were, a staged release
is removed, and it prints these Owner steps, in this order, with the actual
configuration path:

```sh
# 1. edit the deployment configuration: "human_port" back to the port that
#    release used (at or above /proc/sys/net/ipv4/ip_unprivileged_port_start)
# 2. stop and mask the socket unit; masked, no unit's Sockets=/Wants= and no
#    reboot can start it again. The running service keeps its passed socket
#    until it is restarted, so the dashboard stays up until step 3
sudo systemctl disable --now server-sentinel-upstream.socket
sudo systemctl mask server-sentinel-upstream.socket
# 3. the same command again; it restarts the service on that release, which
#    binds the restored port itself (no separate restart is needed)
sudo /tmp/server-sentinel-installer-<version>.pyz --destination ... --config ... \
  --unit /etc/systemd/system/server-sentinel.service rollback
# 4. point the Tailscale Serve target at http://127.0.0.1:<that port>
# 5. verify: ss -ltn shows the service on that port and the dashboard answers
```

Mask, not only disable: a service unit with `Sockets=` also `Wants=` the
socket unit, so a disabled but present socket unit would be started again by
any start of an activation release (including the installer's own restart and
its automatic recovery). The installer renders `Sockets=` only into the unit
of a release that declares the capability, and a rollback refuses a stored
unit of a release without it that still names the socket unit.

To return to socket activation later, in this order:

```sh
# 1. update to a release that supports socket activation; the socket unit is
#    still masked, so its Sockets= does not pull it in and the release binds
#    the old, unprivileged port itself (the reservation check keeps human
#    access closed without revocation until step 4)
# 2. edit the deployment configuration: "human_port" back to the ListenStream
#    port of server-sentinel-upstream.socket (below ip_unprivileged_port_start)
# 3. bind the socket; starting it cannot hand it to the running service
sudo systemctl unmask server-sentinel-upstream.socket
sudo systemctl enable --now server-sentinel-upstream.socket
# 4. restart the service so systemd passes the socket and the new port applies
sudo systemctl restart server-sentinel.service
# 5. point the Tailscale Serve target back at http://127.0.0.1:<that port>
# 6. verify: one socket on that port whose inode is in /proc/<service pid>/fd
sudo ss -ltne 'sport = :<port>'
```

The installer never starts, stops, enables or disables the socket unit and
never rewrites the deployment configuration: both are Owner-managed, and
changing them inside the transaction would leave the human endpoint down if
the restart then failed.

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

Deployed acceptance of this lifecycle — systemd activation, the trusted-proxy
boundary, real mount substitution, and the recording/audit content comparison
across update and rollback — is recorded in `MANUAL_TEST.md` section V for Issue
#47. The synthetic tests in `server/tests/` do not establish it.

There is currently no implemented or documented Docker Compose deployment path.
Adding one requires the same external runtime mount, pinned mount failure,
dedicated identity, private listener, version update, and rollback contract;
`infra/docker/README.md` is only a future integration boundary.
