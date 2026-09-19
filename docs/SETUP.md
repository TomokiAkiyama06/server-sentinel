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
2. ServerSentinel invitation/permissions.

Public port forwarding is not the normal setup.

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
```

### Capture-machine side

During development the repository may be cloned locally and the agent run from that checkout. Stable releases should install only the versioned `media-capture-agent` artifact.

Target command/UX shape:

```bash
sudo ./scripts/install-agent.sh
sudo media-capture-agent pair --server <private-lan-host> --code <one-time-code>
```

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

The setup/installer records the Owner-approved media root and, where practical, the expected filesystem/mount identity. At startup it verifies the mount is present, writable by the dedicated Agent account, has adequate free space/safety reserve, and has not silently fallen back to a directory on the root filesystem.

Do not automatically format disks, edit `fstab`, or create new mounts without an explicit Owner/admin action outside the normal installer.

### Agent recovery-buffer setup

Owner-only configuration offers one of two modes:

```text
[ Duration limit ]  -> choose rolling-buffer time
[ Capacity limit ]  -> choose maximum ring-buffer disk bytes
```

The UI shows estimated reciprocal capacity/duration, actual usage, protected-incident usage, free space, and safety reserve. Settings that cannot safely preserve the required 10-minute pre-loss target are rejected or explicitly degraded.

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
- `recordings:view` — recording list/browser playback.

Permissions are independent.

Non-owner users receive no official recording download/export control in MVP. The UI must not promise that browser playback prevents screen recording/client-side capture.

The screen must clearly state that Tailscale-level network permission is managed separately unless a future approved integration automates it.

## Tailscale/private-network setup

Recommended boundary:

- dashboard/backend listener used by humans binds only to loopback or another trusted non-bypassable local proxy path;
- Tailscale Serve/equivalent exposes it privately;
- existing Tailscale ACLs/Grants may remain unchanged; ServerSentinel does not require or automate policy changes;
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
