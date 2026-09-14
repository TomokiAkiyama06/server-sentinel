# Intended Setup Experience

This describes the target user experience, not necessarily the first implementation state.

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

## Server wizard

Step 1 — Welcome  
Explain self-hosted/no-cloud architecture.

Step 2 — Storage  
- choose recording path;
- test write permission;
- display free space;
- retention default 20 days;
- capacity allocation recommendation after benchmark logic exists.

Step 3 — Locale/time  
- timezone;
- daily summary default 23:00.

Step 4 — Slack (optional)  
- skip allowed;
- test safely.

Step 5 — Remote access guidance  
- Tailscale recommended;
- no port-forwarding default.

Step 6 — Add Camera Node  
- QR;
- local discovery;
- manual fallback.

## iOS onboarding

1. Welcome/privacy explanation.
2. Camera permission.
3. Microphone explanation; default remains OFF.
4. Local network access.
5. Motion-sensor capability.
6. Find/pair server.
7. Capability diagnostic.
8. Camera preview.
9. Server ROI setup.
10. Tamper/orientation calibration.
11. Monitoring screen.

## Pairing UX

Preferred:

```text
Ubuntu Dashboard
  Add Camera
      |
      +-- QR code (5 min)
      |
iPhone scans
      |
Ubuntu shows:
  "New Camera Node: iPhone"
  [Approve]
      |
paired
```

mDNS discovery can reduce typing but must not silently pair without confirmation.

## Presence UX

Dashboard top-level button:

```text
[ 在室にする ]
```

After tap:

```text
1 hour
2 hours
3 hours
Until 18:00
Choose time...
```

When active:

```text
在室中 — 18:00に監視再開
[今すぐ監視再開]
```

## Camera screen

Armed:

```text
ServerSentinel

● 監視中
● Server Connected
Rear: ON
Front: ON
Mic: OFF

(tap for controls)
```

Use a near-black presentation.

## Failure UX

Prefer explicit states:

- `再接続中`
- `サーバーに接続できません`
- `手動操作が必要です`
- `端末温度のため画質を下げています`
- `ストレージ残量が少なくなっています`

Avoid silent degradation.
