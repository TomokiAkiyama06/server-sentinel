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
disabled; any other removal, however old the observation, is `missing`,
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
invariants: an active credential's key, a staged renewal's key (which differs
from the credential's and belongs to an active credential) and an open
enrollment's key are each bound to that node by a live, unrevoked binding,
every enrollment's key (any state) is bound to its node, a revoked
enrollment's binding is revoked, and a staged renewal's
key is never the key of any enrollment, recorded or current, in any state
(stage renewal binds keys no enrollment names). From record to
verify, each node may only change by a composition of those operations:
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
fresh pairing of its key. Three ledger-reachable cases fail closed: a renewal
both staged and promoted inside the window (its material cannot be shown),
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

`verify` reads the baseline only if it is still a private `0600` regular file
(not a symlink) owned by the invoking user or root, and refuses otherwise.
It recomputes the same inventory and compares it. Every Main table the
inventory reads that existed at record time must still exist, even if it was
empty then (a dropped one is `table_missing` in the `tables` section), and
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
counted as preserved. The one exception for missing rows is the service's own
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
it was already broken at record time (reported as `catalog_mismatch`; `record` prints a
warning for such recordings). This gate applies to every accepted change,
including a recording active at record time whose broken segment a later
stop drops, and a declared rewrite. A recording that was still active when recorded
with no linked segment yet always fails (it has no evidence to compare); record
again once it has media. Otherwise it
may gain segments, move its target end earlier but never later, and stay
`active` with no end or become `complete` or `gapped` ending exactly at its
(possibly earlier) target, or `interrupted` ending exactly at the earlier of
its target and its latest linked segment end (startup recovery); its source,
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
or invitation. Capture-agent protected incidents are recorded as not applicable
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

Deployed acceptance of this lifecycle — systemd activation, the trusted-proxy
boundary, real mount substitution, and the recording/audit content comparison
across update and rollback — is recorded in `MANUAL_TEST.md` section V for Issue
#47. The synthetic tests in `server/tests/` do not establish it.

There is currently no implemented or documented Docker Compose deployment path.
Adding one requires the same external runtime mount, pinned mount failure,
dedicated identity, private listener, version update, and rollback contract;
`infra/docker/README.md` is only a future integration boundary.
