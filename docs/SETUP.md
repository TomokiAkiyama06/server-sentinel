# Intended Setup Experience

This describes the target user experience. Exact commands/transport choices may change during implementation ADRs.

## Ubuntu setup

Target easy path:

```bash
git clone <repo-url>
cd server-sentinel
./install.sh
```

or:

```bash
docker compose up -d
```

Then open the local setup page.

## First-run server wizard

### Step 1 — Welcome

Explain:
- self-hosted/no-developer-cloud architecture;
- camera/recording privacy responsibility;
- MVP supports local USB cameras and browser-based Web Camera Nodes;
- no native iOS/App Store application is required.

### Step 2 — Deployment-owner authorization

Before privileged remote access:
- bootstrap owner authorization from a trusted local context;
- choose the mechanism accepted by ADR;
- configure recovery/revocation;
- do not treat Tailnet membership alone as owner authorization.

Until complete, remote privileged dashboard/API operations remain unavailable.

### Step 3 — Storage

- choose recording root;
- verify write permission;
- display filesystem free space;
- default retention 20 days;
- configure recording allocation;
- explain hard filesystem safety reserve.

### Step 4 — Locale/time

- timezone;
- daily summary default 23:00.

### Step 5 — Add Camera Sources

The product must allow completion with **one** camera source and up to **four active** sources.

Camera list starts empty; no fixed `front/rear` slots.

Options:

```text
[ Add local USB camera ]
[ Add Web Camera Node ]
```

### Step 6 — Detection profiles

For each source:
- name;
- optional role label;
- preview;
- desired quality;
- audio state (default OFF);
- detection profiles;
- ROI/entrance line calibration as relevant.

### Step 7 — Owner verification (optional)

If desired:
- explain biometric processing;
- enroll the deployment owner only;
- validate image quality;
- store template locally;
- provide delete/re-enroll controls.

Skipping owner verification must not prevent basic monitoring.

### Step 8 — Slack (optional)

- disabled by default;
- skip allowed;
- safe test message.

### Step 9 — Remote access guidance

- Tailscale/private networking recommended;
- no public port-forwarding default;
- remote privileged actions still require Step 2 authorization.

## Add local USB camera

Flow:

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

Show stable hardware identity information where available, not only `/dev/video0`.

If the device disappears/reappears, ServerSentinel must not silently substitute a different physical camera merely because numeric device ordering changed.

## Add Web Camera Node

### Owner/dashboard side

```text
Camera Sources
  -> Add Web Camera Node
  -> one-time QR / short code (~5 min)
```

### Camera-device side

Open the ServerSentinel Camera Node page in a supported secure browser context.

Target UX:

```text
ServerSentinel Camera Node

Camera: [Back Camera v]
Microphone: OFF
Quality: Auto / 720p ...

[Pair / Connect]
```

After pairing:

```text
● Monitoring
● Server connected
Camera: ON
Mic: OFF
Quality: 720p / 15 fps
Image quality: Good

[Stop]
```

The page must clearly show monitoring/connection state.

PWA/home-screen installation can be offered where supported, but ordinary browser use remains supported.

## Web Camera Node operational guidance

Because the MVP is browser-based:
- keep the camera page active/foreground;
- request Screen Wake Lock where supported;
- explain that screen lock/browser suspension/OS termination can stop capture;
- if capture stops, the server marks the source offline/degraded;
- reconnect automatically where browser/session state permits;
- otherwise show `手動操作が必要です`.

No Apple Developer Program/App Store setup is required.

## Secure context / HTTPS

`getUserMedia()` normally requires a secure context. Setup must provide/document a legitimate secure-origin method (for example an accepted local TLS/private-network approach selected by ADR).

Do not make `ignore the certificate warning` or disabling browser security the normal onboarding path.

## Detection-profile setup examples

### Server camera

```text
✓ Person detection
✓ Motion
✓ Server ROI movement
✓ Camera tamper
✓ Image quality
```

### Entrance camera

```text
✓ Person detection
✓ Entrance crossing
✓ Owner verification (optional)
✓ Camera tamper
✓ Image quality
```

A webcam or Web Camera Node can use either profile. Role is not tied to hardware type.

## Entrance calibration

If entrance crossing is enabled:
1. preview camera;
2. draw entrance line/zone;
3. mark `inside` and `outside` direction;
4. test entry/exit;
5. tune debounce/threshold if needed.

If owner verification is enabled, test owner entry/exit after enrollment.

## Low-light setup

Do **not** configure motion-triggered torch/light.

Show a quality diagnostic such as:
- Good;
- Degraded;
- Insufficient for owner verification.

If the environment is too dark, recommend changing camera placement/ambient lighting or using a camera intended for low-light/IR operation rather than automatically illuminating the area with the phone.

## Presence UX

Top-level display:

```text
Presence: PRESENT / PROBABLY_PRESENT / ABSENT / UNKNOWN
Source: Entrance camera / Manual / Schedule
```

Manual action remains available:

```text
[ 在室にする ]
[ 不在にする ]
[ 自動判定へ戻す ]
```

Manual override has priority until cancelled/expired.

Critical server-movement/camera-tamper monitoring remains active in all presence modes.

## Live dashboard

Adapt to 1–4 active sources:

```text
1 source -> one large tile
2 sources -> two responsive tiles
3–4 sources -> responsive grid
```

Each tile shows source name, type, health, negotiated quality, audio state, and degraded/low-light status.

## Failure UX

Prefer explicit Japanese states:
- `カメラが切断されました`
- `Web Camera Nodeを再接続中`
- `ブラウザ側で手動操作が必要です`
- `映像が暗いため人物/Owner判定を停止しています`
- `処理負荷のため解析頻度を下げています`
- `ストレージ残量が少なくなっています`
- `新しい録画を保存できません`

Avoid silent degradation.
