# Intended Setup Experience

This document describes target UX. Exact transport commands and packaging may change through ADR/implementation.

## Main Ubuntu setup

Development target:

```bash
git clone <repo-url>
cd server-sentinel
./install.sh
```

or the documented Docker Compose path where appropriate.

Stable releases should provide versioned release artifacts/installers rather than requiring production operation from a development checkout.

## First-run server wizard

### Step 1 — Welcome

Explain:
- self-hosted/no-developer-cloud architecture;
- video-only MVP;
- local UVC and remote Linux capture-agent source types;
- phone/Mac are supported as browser viewers;
- no native iOS/App Store camera application is required.

### Step 2 — Deployment owner

Bootstrap the deployment owner from a trusted local context. Configure recovery/revocation. Tailnet membership alone is never owner authorization.

### Step 3 — Storage

- choose recording root;
- verify write permission/free space;
- default retention 20 days;
- configure recording allocation;
- explain hard filesystem safety reserve and pressure/hard-stop states.

### Step 4 — Hardware baseline / recorder self-check

Show the Owner the detected main-host inventory and require explicit approval of the initial baseline:

- CPU;
- RAM modules/slots;
- NVMe/M.2;
- HDD/recording drives;
- GPU.

Use the strongest available stable identifiers and clearly mark fields that are unavailable/unverifiable. Explain that ServerSentinel checks the baseline at startup and at least once per day, never silently rewrites it, and immediately alerts on material missing/changed hardware.

Also run/preview the recording-health self-test: expected recording filesystem, source freshness, recorder/encoder state, free-space/safety reserve, bounded temporary write + fsync + reopen/read/decode validation, and available SMART/NVMe health.

Explain that self-test-owned temporary/partial media is deleted on success, failure, or cancellation; interrupted leftovers are cleaned at next startup before a new test writes media. Cleanup verifies the expected filesystem and does not touch ordinary recordings/protected incidents. If cleanup fails, show the failure and block additional self-test media writes until safe cleanup succeeds; remaining bytes still count against storage admission/reserve. Self-test media is never uploaded or retained for diagnostics, and missing mounts never cause root-filesystem fallback.

### Step 5 — Locale/time

- timezone;
- daily summary default 23:00;
- verify main-host time synchronization.

### Step 6 — Add Camera Sources

The product can complete setup with one source and supports up to four active sources.

```text
[ Add local USB camera ]
[ Add remote Linux capture node ]
```

No fixed front/rear slots.

### Step 7 — Detection profiles

For each source:
- name;
- optional role label;
- preview;
- desired capture profile;
- detection profiles;
- ROI/entrance/zone calibration where relevant.

Audio controls are omitted in the MVP because monitoring is video-only.

### Step 8 — Owner verification (optional)

Explain biometric processing, enroll only the deployment owner, validate quality, store template locally, and provide delete/re-enroll controls.

### Step 9 — Slack (optional)

Disabled by default; skip allowed; provide a safe test message.

### Step 10 — Human remote access

Explain that two separate approvals are required:

1. Tailscale/private-network permission to the main node;
2. a ServerSentinel invitation, redeemed once to register that person's own credential, plus the permissions the owner grants.

Public port forwarding is not the normal setup.

Where the room shares one Tailscale account, the Tailscale login does not identify the person; the ServerSentinel credential does. Register each credential on an authenticator the invited person controls and keep authenticator user verification required. On a machine whose OS account or device unlock is shared, use a per-person OS account or a portable authenticator instead of a passkey stored in the shared profile. See ADR 0003.

## Add local USB camera

```text
Camera Sources
  -> Add local USB camera
  -> discovered devices
  -> choose physical device
  -> preview
  -> name + role
  -> capture profile
  -> detection profiles
  -> Save
```

Show stable identity evidence where available, not only `/dev/video0`.

If reconnect cannot be matched unambiguously—such as multiple identical devices without unique serials—show `手動確認が必要です` and require owner re-approval.

## Add remote Linux capture node

### Main/dashboard side

```text
Capture Nodes
  -> Add Capture Node
  -> generate short-lived one-time pairing code
  -> show main-host private-LAN address/port
  -> provide public Main Server trust information through a trusted Owner channel
```

### Capture-machine side

During development the repository may be cloned locally and the agent run from that checkout. Stable releases should install only the versioned `media-capture-agent` artifact.

Before pairing, verify/configure the intended Main Server's public trust information through a trusted Owner-controlled local or out-of-band channel. The address alone is not trusted identity. The exact trust setup and encrypted bootstrap transport are selected by PoC/ADR before implementation; the command below assumes that trust setup is complete.

Target command/UX shape:

```bash
sudo ./scripts/install-agent.sh
sudo media-capture-agent pair --server <verified-private-lan-host>
```

Pairing authenticates the intended Main Server and establishes an encrypted channel before sending the code. Missing/mismatched trust or failed certificate verification stops enrollment without transmitting the code; there is no plaintext or unverified-certificate fallback.

Enter the one-time code only at the non-echoing prompt. Do not put it in command arguments, environment variables, URLs, or shell command text: these may appear in process listings, shell history, or sudo/audit logs. Installer automation must use a protected input channel rather than a literal command-line secret.

After pairing:

```text
media-capture-agent.service: active
Node: Research Room Capture Node
Camera: selected UVC device
Agent: online
Camera: online
Audio: not captured
```

Normal operation has no desktop window/tray requirement.

### Agent media-root selection

Prefer an existing dedicated data filesystem with sufficient free capacity for Agent video rather than assuming the root filesystem. The exact path is deployment-specific and must not be hard-coded into the public project.

The setup/installer records the Owner-approved media root outside the source tree and the expected filesystem/mount identity where available. Installer/startup and runtime write admission verify that the expected mount/device is present, writable by the dedicated Agent account, and has adequate free space/safety reserve. Missing or substituted mounts refuse unsafe writes and report a degraded/failed state; they never silently create or use a fallback media directory on the root filesystem.

Do not automatically format disks, edit `fstab`, or create new mounts without an explicit Owner/admin action outside the normal installer.

### Agent recovery-buffer setup

Owner-only configuration offers one of two modes:

```text
[ Duration limit ]  -> choose rolling-buffer time
[ Capacity limit ]  -> choose maximum ring-buffer disk bytes
```

The UI shows estimated reciprocal capacity/duration, actual usage, protected-incident usage, free space, and safety reserve. Before applying duration/capacity/profile settings, verify that the expected filesystem can hold the pinned 10-minute pre-loss window and the following 10 minutes simultaneously. Estimate bytes from bounded/negotiated bitrate plus segment/container overhead, account for existing protected incidents and other filesystem use, and retain hard reserve. Count shared segments once; only eligible ordinary data outside the required pre-loss window is reclaimable. Reject determinably insufficient settings, including space for just 10 minutes plus reserve. Runtime uncertainty or later loss of coverage/headroom is explicitly degraded and reports actual coverage/gaps without deleting unexpired incidents or crossing reserve.

On unexpected Main Server communication loss, the Agent protects 10 minutes before + 10 minutes after the loss boundary. Completed protected incidents are retained locally for **60 days by default** and are not overwritten by the ordinary ring buffer before expiry.

### USB unplug behavior

When a camera is unplugged:

```text
Agent: ONLINE
Camera: OFFLINE
Event: camera_offline
```

If the same physical camera later reconnects unambiguously, return online automatically. Ambiguous identity requires manual approval. Intentional unplugging is still recorded; alert severity is configurable separately.

## Room-overview camera setup

A remote-agent source can be assigned role `room_overview` or `entrance` while covering the full room.

Calibration may include:
- room/entrance geometry;
- person/zone profile;
- owner-verification feasibility;
- server area if visible;
- image-quality thresholds.

Do not assume that a wide room view provides enough pixels for reliable owner face verification. Enable biometric-dependent behavior only after real placement tests demonstrate sufficient quality.

## Live dashboard on phone/Mac

Invited users access only the main ServerSentinel host.

```text
phone / Mac
    -> Tailscale/private network
    -> trusted proxy/Tailscale Serve
    -> ServerSentinel credential verification
    -> ServerSentinel dashboard
```

The capture node is never directly exposed to viewers.

Responsive layout:

```text
1 source -> one large tile
2 sources -> two responsive tiles
3–4 sources -> responsive grid
```

Each tile shows source name/type/role, source health, capture-node health where applicable, negotiated viewer quality, image-quality state, and reconnect/manual-intervention state.

Viewer-only transcoding should not remain active unnecessarily when there are no subscribers.

## Access-management UX

Owner-only access screen:

```text
Access

User A   identity@example.com
[x] Live view
[ ] Recordings
Status: Active

User B   another@example.com
[x] Live view
[x] Recordings
Status: Active
```

Minimum permissions:

- `live:view` — current live streams;
- `recordings:view` — recording list/browser playback and historical timeline/events.

Permissions are independent. `live:view` alone cannot access historical timeline/events.

Non-owner users receive no official recording download/export control in MVP. The UI must not promise that browser playback prevents screen recording/client-side capture.

The screen must clearly state that Tailscale-level network permission is managed separately outside ServerSentinel. ServerSentinel does not modify ACLs/Grants or store Tailscale administrative credentials.

The screen also lists each person's registered credentials with their owner-visible label and last-used time, and allows revoking one credential or the whole principal. Revoking one credential (for example a lost device) leaves the person's other credentials working; revoking the principal ends all of them and their sessions promptly.

## Tailscale/private-network setup

Recommended boundary:

- dashboard/backend listener used by humans binds only to loopback or another trusted non-bypassable local proxy path;
- Tailscale Serve/equivalent exposes it privately;
- existing Tailscale ACLs/Grants may remain unchanged; ServerSentinel does not modify the policy;
- ServerSentinel still checks its own invitation/permission list for every human request;
- uninvited identities receive generic/non-branding denial and no ServerSentinel deployment/media metadata.

With unchanged Tailnet policy, do not promise that the Main Server Tailscale node or listening service is invisible to other Tailnet members, Tailnet Owners/Admins, or infrastructure administrators.

## LAN capture-ingest setup

Remote agents use a separate LAN-facing ingest endpoint.

- mTLS/revocable node credential required;
- dashboard routes unavailable on that listener;
- bind/firewall exposure narrowed to the private LAN and, where practical, known capture-node addresses;
- IP address is never sufficient authentication.

## Low-light/image-quality UX

Show detector-specific quality, for example:

```text
Person detection: Insufficient (too dark)
Owner verification: Unavailable (face too small)
Recording: Active
```

Never translate a skipped person detector into `人はいません`.

## Presence UX

```text
Presence: PRESENT / PROBABLY_PRESENT / ABSENT / UNKNOWN
Source: entrance inference / manual / schedule

[ 在室にする ] [ 不在にする ] [ 自動判定へ戻す ]
```

Server movement/camera tamper remains active regardless of presence state.

## Failure UX

Prefer explicit Japanese states:

- `カメラが切断されました`
- `Capture Nodeとの接続が切れました`
- `カメラを一意に確認できないため手動確認が必要です`
- `時刻同期のずれが大きいためイベント時刻の信頼性が低下しています`
- `映像品質不足のため人物判定は不明です`
- `処理負荷のため解析頻度を下げています`
- `ストレージ残量が少なくなっています`
- `新しい録画を保存できません`
- `承認済みハードウェア構成から変更を検出しました`
- `録画先ストレージが見つからないか別デバイスです`
- `録画自己診断に失敗しました`
- `ハードウェア識別情報を確認できません`

Avoid silent degradation.
