# Architecture

## Boundary principle

ServerSentinel has no central developer backend. A deployment consists of the owner's main Ubuntu host, explicitly approved camera/capture nodes, invited human viewers, and optional third-party services such as Tailscale or Slack.

```text
Camera / Capture Nodes  --->  Main ServerSentinel  --->  invited browser viewers
        private LAN                 self-hosted              Tailscale/private
```

## Runtime model

```text
Local UVC cameras
      │
      ├───────────────────────────────┐
      │                               │
Remote room camera                    │
      │ USB                           │
      v                               │
Linux capture machine                 │
media-capture-agent                   │
      │ private LAN + mTLS            │
      └───────────────────────────────┤
                                      v
                           Main ServerSentinel
                           ├─ source/node registry
                           ├─ media ingest/recording
                           ├─ detection
                           ├─ event/presence correlation
                           ├─ storage
                           ├─ access control
                           └─ notifications
                                      │
                                trusted local proxy
                                      │
                                Tailscale Serve
                                      │
                           invited phone / Mac / PC
```

## Camera-source abstraction

MVP source types:

- `local_uvc` — camera attached to the main host;
- `remote_agent` — camera attached to an approved Linux capture node.

Browser/iPhone camera capture is outside the current product scope. Phone/Mac/desktop browsers are viewer clients.

The deployment supports 1–4 active sources. Camera count/type/role are configuration, never topology constants.

### Node vs source

A **capture node** is a computing/trust endpoint. A **Camera Source** is one logical video input.

```text
Main host
├─ Local Camera A
└─ Local Camera B

Capture Node A
└─ Room Overview Camera
```

A node credential does not grant human dashboard/admin rights.

## `media-capture-agent` boundary

The remote Linux agent:

- runs as `media-capture-agent` under a dedicated non-root account;
- captures video through V4L2/UVC;
- does not require a GUI/tray;
- does not capture audio in MVP;
- initiates outbound/private-LAN connectivity toward the main host;
- uses owner-approved one-time pairing followed by revocable mutually authenticated encrypted identity;
- reports node health separately from camera health;
- does not need Tailscale merely to forward a camera over the same LAN.

The main host exposes a narrow LAN ingest boundary for agents, distinct from the human dashboard listener.

The agent also keeps a bounded compressed-video disk ring buffer. The Owner chooses either duration mode or capacity mode. Unexpected Main Server communication loss protects 10 minutes before + 10 minutes after the loss boundary; protected incidents remain on the agent for 60 days by default and then auto-delete.

## Human-access boundary

Human remote access has two gates:

```text
Tailscale/private-network permission
             AND
ServerSentinel owner invitation/permission
```

Tailnet membership alone grants nothing.

The recommended human path is:

```text
invited browser
    -> Tailscale
    -> Tailscale Serve / trusted proxy
    -> loopback-only ServerSentinel dashboard/API
```

ServerSentinel does not require or automatically mutate Tailscale ACLs/Grants, and it does not retain a Tailscale administrative credential. The existing Tailnet policy may therefore continue to make the Main Server node visible/reachable to ordinary Tailnet members. Node-level concealment is not guaranteed unless the deployment owner separately configures Tailscale policy.

The application independently checks an owner-managed allowlist and granular permissions such as `live:view` and `recordings:view`. An uninvited Tailnet identity receives no ServerSentinel camera/media/timeline/deployment data even when the underlying Tailscale node is reachable.

## Media architecture

Capture, recording, inference, and viewer outputs are separate profiles.

```text
high-resolution source
      ├─ durable recording
      ├─ downscaled/sampled inference
      └─ adaptive browser live profile
```

This keeps a wide room-overview camera useful without forcing full-resolution AI inference or live delivery to every phone/Mac viewer.

Viewer traffic always terminates at the main host. Human clients never connect directly to `media-capture-agent`.

## UVC identity boundary

A source's logical identity is not `/dev/videoN`.

Use the strongest available stable physical evidence. When multiple identical devices cannot be distinguished safely after reconnect, ServerSentinel fails closed to `manual_intervention_required` rather than selecting one arbitrarily.

## Detection-profile model

Hardware type and analysis behavior are independent. Profiles may include:

- motion;
- person;
- server ROI/movement;
- camera tamper;
- image-quality/low-light;
- entrance crossing;
- owner verification.

Every dependent detector has its own quality prerequisites. Insufficient quality produces `unknown`/unavailable, including for person detection negatives.

## Owner verification boundary

Owner verification is narrow 1:1 biometric verification:

```text
Observed face
    -> quality gate
    -> compare with explicitly enrolled owner template
    -> match / no-match / unknown
```

No named non-owner face database is part of MVP. Anonymous same-camera tracking may be used for timeline context. Cross-camera biometric re-identification is deferred.

## Presence architecture

States:

- `PRESENT`;
- `PROBABLY_PRESENT`;
- `ABSENT`;
- `UNKNOWN`.

Manual override has highest precedence. Ambiguous or poor-quality visual evidence stays uncertain. Server movement and camera-tamper monitoring remain armed in all states.

## Evidence and timeline

The correlator links observations and recordings but does not assert culprit/guilt/causality.

When resources are constrained:

1. keep node/source health truthful;
2. preserve critical movement/tamper evidence where safe;
3. preserve recording integrity/backpressure;
4. reduce expensive detector cadence;
5. reduce live-view quality;
6. surface explicit degraded state.

Ubuntu main storage is authoritative for normal recording. A remote `media-capture-agent` keeps a bounded compressed-video disk ring buffer and, on unexpected Main Server communication loss, protects the 10 minutes before + 10 minutes after loss as secondary incident evidence. Protected incidents remain on the agent for 60 days by default. This is resilience evidence, not a full mirror of all recordings.

## Main-host integrity architecture

ServerSentinel also monitors whether the recorder itself still matches the Owner-approved hardware baseline and can actually write usable recordings.

```text
Owner-approved baseline
  ├─ CPU
  ├─ RAM modules
  ├─ NVMe / M.2
  ├─ HDD / recording devices
  └─ GPU
        │
        ├─ compare at startup
        └─ compare at least daily
              │
              ├─ OK
              ├─ CHANGED / MISSING
              ├─ NEW_DEVICE
              └─ UNVERIFIABLE
```

Baseline drift never self-approves. The Owner explicitly approves deliberate replacements.

A separate daily recording-health self-test validates source freshness, recorder/encoder state, the expected recording filesystem/device, free-space admission, and a bounded write + fsync + reopen/read/decode path. Available SMART/NVMe health indicators are also surfaced. Missing/changed baseline hardware and recording-health failures generate immediate Owner alerts rather than waiting only for the daily summary.

Raw hardware serials/UUIDs remain deployment-local and are redacted from normal public diagnostics.

## Privacy architecture

Default operation has:

- no ServerSentinel developer account;
- no developer cloud/API;
- no analytics/telemetry;
- no audio surveillance in MVP;
- no native App Store requirement;
- no named non-owner biometric identities.

## Extensibility

Potential future additions include RTSP/IP cameras, browser camera nodes, Raspberry Pi/edge nodes, off-host evidence storage, host metrics, environment sensors, and NAS targets. They are not MVP requirements.
