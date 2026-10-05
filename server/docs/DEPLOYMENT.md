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

The non-root ServerSentinel service cannot read a root-owned `sshd`'s
`/proc/<pid>/fd` and `exe` itself, so the socket owner is looked up by the
separate helper service below. Without it an excepted `sshd` stays
`LISTENER_OWNER_UNVERIFIED` and human access stays closed. ServerSentinel
itself is never given root or capabilities for this.

### Listener socket-owner helper (Issue #126)

`server-sentinel-socket-owner.service` (`app.auth.socket_owner`, standard
library only) answers one question for ServerSentinel: which executable and
system unit hold a listening socket, or whether ServerSentinel alone holds its
own upstream socket. It never changes anything and returns no PID, command
line, account or other process detail.

- Privilege: a transient non-root account (`DynamicUser=yes`) with exactly
  `CAP_DAC_READ_SEARCH` (list another account's `/proc/<pid>/fd`, read the
  group-only deployment configuration) and `CAP_SYS_PTRACE` (the kernel's
  `ptrace_may_access` read check on the `fd/*` and `exe` links). These are the
  minimum the kernel requires; root is not used. The ptrace-family system
  calls (`~@debug`) and `open_by_handle_at` (`~@privileged`) are filtered, so
  the helper cannot attach to or read the memory of another process. It has no
  network and a read-only file system.
- Channel: systemd creates `/run/server-sentinel-socket-owner/socket`
  `root:server-sentinel-socket-owner` mode `0660` in a root-owned `0755`
  directory (socket activation). The helper answers only a peer whose
  kernel-reported `SO_PEERCRED` UID is `service_uid` from the deployment
  configuration and whose `/proc/<pid>/status` shows that UID; any other peer
  is closed without reading its request. It answers only about sockets that
  are listening in the requesting process's own network namespace.
- Bounds and audit: one request per connection, at most 4096 bytes and 64
  socket inodes, a 2-second read limit, 20 requests in a burst refilled at one
  per 3 seconds. Every answer, failure and refusal is written to the journal
  (`journalctl -u server-sentinel-socket-owner`); refusals are coalesced per
  minute.
- Failure: a missing, stopped, slow, rate-limited or malformed helper makes
  the ServerSentinel client raise, so the reservation check reports
  `LISTENER_OWNER_UNVERIFIED` and keeps human access closed. This alone does
  not revoke sessions: access reopens once ownership verifies again (Owner
  decision, 2026-10-05). Only an observed other holder (`UNEXPECTED_LISTENER`)
  is an exposure that revokes every human session before reopening.
- Mandatory: the reservation check never opens human access without a socket
  owner resolver; production composes this helper's client.

Install from the tagged release checkout as the Owner. These are host
administration steps; nothing in the installer or the service performs them:

```sh
sudo groupadd --system server-sentinel-socket-owner
sudo usermod -aG server-sentinel-socket-owner <service-account>
sudo install -m 0644 -o root -g root \
  infra/systemd/server-sentinel-socket-owner.socket \
  infra/systemd/server-sentinel-socket-owner.service /etc/systemd/system/
# Only when the installation root or configuration path differs from
# /opt/server-sentinel-main and /etc/server-sentinel/deployment.json:
sudo systemctl edit server-sentinel-socket-owner.service   # override ExecStart=/WorkingDirectory=
sudo systemctl daemon-reload
sudo systemctl enable --now server-sentinel-socket-owner.socket
sudo systemctl restart server-sentinel.service   # picks up the new group membership
```

The hostname reservation check is not yet composed in the running service
(no human route is mounted); when it is, the composition passes
`app.auth.socket_owner.SocketOwnerHelperClient()` as its `socket_owners`.

Add only the ServerSentinel service account to the group. The service is
started on demand by the socket and is `PartOf=server-sentinel.service`, so a
release update or rollback, which restarts `server-sentinel.service`, also
restarts the helper on the new release's code. Its unit has no `[Install]`
section; enable the socket only. Check the result with the helper steps in
`MANUAL_TEST.md` (Issue #126). Until those steps pass on the Main Server the
helper's behaviour there is unverified; the repository tests run it only
against synthetic `/proc` trees.

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

Deployed acceptance of this lifecycle — systemd activation, the trusted-proxy
boundary, real mount substitution, and the recording/audit content comparison
across update and rollback — is recorded in `MANUAL_TEST.md` section V for Issue
#47. The synthetic tests in `server/tests/` do not establish it.

There is currently no implemented or documented Docker Compose deployment path.
Adding one requires the same external runtime mount, pinned mount failure,
dedicated identity, private listener, version update, and rollback contract;
`infra/docker/README.md` is only a future integration boundary.
