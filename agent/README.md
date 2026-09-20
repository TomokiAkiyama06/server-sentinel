# media-capture-agent

Issue #12 supplies a native Linux service foundation with no third-party runtime
dependencies. It has no GUI/tray, listener, microphone capture or audio setting.
The current production entry point deliberately reports `pairing_required` and
`capture_unconfigured`: authenticated transport (#13), approved physical UVC
binding (#11/#14), media transport (#15) and ring management (#16) plug into the
core before it can become an operational capture node. This is not hardware
acceptance or a claim of functional remote video delivery.

Issue #16 adds the tested disk-ring/incident core under `ring.py`, `ring_models.py`
and `ring_ledger.py`. It uses real immutable disk segments and private SQLite;
its production capture/transport/Owner-UI integration is still pending. See
[`docs/RING_BUFFER.md`](docs/RING_BUFFER.md) for bounds, safe admission, coverage,
expiry, recovery and validation limits.

Implemented runtime modules live in `media_capture_agent/`: `config.py`,
`storage.py`, `health.py`, `runtime.py`, and `cli.py`. Existing responsibility
folders describe subsequent capture/pairing/transport work. Synthetic adapters
are test-only; the production CLI does not offer a synthetic mode or silently
substitute mock capture.

## Local configuration and service

Use Python 3.12+ on Linux. Run `python3 agent/media-capture-agent --config
<protected-config-file> --check` from a checkout, or invoke the installed
`media-capture-agent` executable. `--check` validates the local account, storage
identity, permissions and reserve without opening devices, writing media or
connecting to any host. Normal service execution must use a dedicated non-root
account; configuration is a regular file with mode 0600, owned by that account.
Agent and installer reject FIFOs/special files without waiting for a writer.
Both read at most 65,537 bytes before parsing, enforce the 64 KiB configuration
limit and reject metadata changes during the read.

The deployment-local JSON configuration requires every field below. No private
path, device identity, disk reserve, segment limit or clock threshold is a public
default. Unknown keys (including audio) are rejected. Keep the actual config and
all runtime/media data outside the Git checkout and the application install:

| Field | Meaning |
| --- | --- |
| `node_id` | Stable node UUID, independent of source UUIDs |
| `runtime_root` | Existing private directory, dedicated UID, mode 0700 |
| `media_root` | Existing dedicated-UID directory on the approved filesystem; no group/world write |
| `expected_mount` | `mount_point`, `filesystem`, `source`, device `major` and `minor`, and `filesystem_root` (mountinfo field 4), approved locally |
| `service_uid` | Dedicated non-root numeric UID |
| `safety_reserve_bytes` | Positive Owner-configured hard reserve |
| `max_segment_bytes` | Positive bound for each opaque video segment |
| `heartbeat_seconds` | Positive finite interval |
| `clock_offset_limit_seconds` | Positive finite acceptable absolute clock offset |
| `clock_uncertainty_limit_seconds` | Positive finite clock-exchange uncertainty bound |
| `clock_step_limit_seconds` | Positive finite wall/monotonic elapsed-time disagreement bound |

The Owner provisions paths and approves mount identity locally. Runtime never
creates roots, follows path symlinks, repairs an unexpected mount, or substitutes
a root-filesystem directory. Device numbers can change after reboot; revalidate
and explicitly re-approve configuration instead of relaxing checks. Mount IDs are
read from pinned-directory fdinfo and compared with mountinfo, including stacked
bind mounts; a mount ID change during execution refuses writes. A systemd
`ReadWritePaths` bind at exactly `media_root` is accepted only while the approved
parent mount remains present and source/filesystem/device plus backing filesystem
root match the approved parent and relative media path. A same-device bind of
another backing directory fails. This preserves the narrow write allowlist and
`ProtectSystem=strict`; it does not approve arbitrary bind mounts.

`MediaStore` serializes admissions with a directory lock, reserves physical blocks
before writing, rechecks actual free space and fsyncs data/directory. It creates
exclusive UUID-named segments under pinned directory descriptors. No sparse-write
fallback exists when allocation is unsupported. The store can open at hard stop
for inventory/recovery/deletion, but new writes and installer checks refuse it.
Ring retention authorization belongs to #16; the foundation never automatically
deletes evidence. Inventory uses no-follow metadata; recovery verifies bounded
SHA-256 content so full-size partially written allocations are not called healthy.
Filesystem free space already accounts for all existing files. A dedicated
filesystem is preferred: unrelated external writers can consume space between
syscalls, so deployment monitoring and pressure handling remain necessary.

Heartbeat node, per-source, storage and clock status are independent. A camera
unplug leaves an otherwise healthy node online. Every tick obtains a fresh clock
exchange from the authenticated injected outbound session; absent samples remain
unknown, excessive offset/uncertainty or wall-clock jumps degrade the node.
Production currently has no paired session and initiates no network connection.
No network or application credential is accepted in this foundation.

## Versioned installation

Build with `python3 agent/build_artifact.py --output <new-artifact-path>`. The
result is an executable zipapp containing only application sources and the
Apache license. Record the printed SHA-256 through the trusted release channel;
an unauthenticated hash downloaded beside an artifact is not an authenticity
check. CI executes the artifact outside its development checkout.

After the Owner provisions a dedicated account, approved storage, protected
config, a root-controlled install directory and unit directory, an administrator
may explicitly run:

```text
python3 agent/install.py --artifact <verified-artifact> --sha256 <trusted-sha256> \
  --version <release-version> --destination <root-controlled-install-directory> \
  --config <protected-config-file> --unit <unit-directory>/media-capture-agent.service \
  --video-device /dev/video0
```

The installer reads only a non-symlink, regular artifact of at most 16 MiB,
through a nonblocking descriptor; FIFOs, devices and concurrent file changes
are rejected before execution.

The device path above is illustrative, never durable UVC identity. Repeat the
option for explicitly allowed video nodes; the default device allowlist is empty.
The generated unit uses `DevicePolicy=closed` and never allows `/dev/snd`.
Approved stable identity still must be verified by the capture layer on open and
reconnect. The installer writes a new, root-owned version directory, runs local
validation as the dedicated service UID, and emits a hardened systemd unit. It
never creates users, changes permissions/mounts/firewall, overwrites an existing
unit/version, starts a service or removes prior releases. Review the unit and
explicitly install/enable it with the host's normal administration workflow.
Config/storage paths hidden by `ProtectHome` or unavailable in the unit's mount
namespace require a deployment path change; do not disable sandboxing casually.
Dollar/control characters in unit paths are rejected; percent is escaped.

The service and executable command line retain `media-capture-agent`. Linux's
kernel `comm` field truncates names to 15 visible bytes; verify the executable
command line and systemd unit rather than claiming a longer kernel field.
Physical process/device/account/mount behavior remains a manual acceptance item.

## Validation

`python3 -m unittest discover -s tests -p 'test_*.py' -v` from `agent/` tests mount
loss/substitution, admission-to-open races, partial recovery, reserve, clock skew,
source/node separation, configuration privacy and artifact execution. CI runs
normal/error core smoke with synthetic capture and transport in an isolated
non-root Docker container. Python audit hooks count and reject all socket creation,
DNS, connect, bind, send and subprocess attempts during both core scenarios. This
verifies the implemented stdlib core; future native libraries/transports need
additional observation and actual hardware/network acceptance. See
`docs/DEPENDENCIES.md` and repository `MANUAL_TEST.md`.
