# Architecture

## Boundary principle

ServerSentinel has no central developer backend. A deployment boundary is one owner's self-hosted environment plus that owner's explicitly paired camera devices and optional third-party services.

```text
Deployment A                                  Deployment B
Local/Web cameras -> Ubuntu A                 Local/Web cameras -> Ubuntu B
                       \ /                                            \ /
                      owner A                                        owner B

No shared ServerSentinel developer data plane.
```

## Runtime model

```text
                    Camera Sources
          ┌────────────────────────────┐
          │ Local UVC / USB cameras    │
          │ Remote Web Camera Nodes    │
          └─────────────┬──────────────┘
                        │
                        v
          ┌────────────────────────────┐
          │ Ubuntu ServerSentinel      │
          │ source registry            │
          │ media/recording            │
          │ detection                  │
          │ event correlation          │
          │ storage                    │
          │ notifications              │
          └─────────────┬──────────────┘
                        │
                        v
          ┌────────────────────────────┐
          │ React Web UI              │
          │ dashboard + camera node   │
          └─────────────┬──────────────┘
                        │
                        v
              owner-authorized browser
```

## Camera-source abstraction

The system is deliberately not an `iPhone front/rear camera` architecture.

MVP source types:
- `local_uvc` — host-attached UVC/V4L2 camera;
- `remote_web` — camera capture from a paired browser.

The deployment supports 1–4 active sources. Camera count/type/role are configuration, not topology constants.

### Node vs source

A node is a computing endpoint/trust identity. A source is one logical video source.

Examples:

```text
Ubuntu local node
├─ USB Camera A
└─ USB Camera B

Phone browser node
└─ Camera Source C
```

Future nodes could expose additional source types without changing event/recording semantics.

## Detection-profile model

Hardware type and analysis behavior are independent.

A Camera Source can bind profiles such as:
- motion;
- person;
- server ROI/movement;
- camera tamper;
- image-quality/low-light;
- entrance crossing;
- owner verification.

This allows one webcam to do everything in a small deployment or several cameras to divide responsibilities.

## Trust boundaries

### Local UVC device

Trusted for media only after the deployment owner explicitly enables/configures the discovered physical device.

Stable hardware identity should be used where available so `/dev/videoN` reordering cannot silently swap cameras.

### Remote Web Camera Node

Trusted only after owner-authorized pairing.

Can submit:
- heartbeat/health;
- negotiated capability state;
- media/recording chunks;
- browser lifecycle state relevant to monitoring.

A paired camera node is not automatically authorized to use privileged dashboard/admin APIs.

### Ubuntu

Primary trusted authority for:
- deployment-owner authorization;
- source registry;
- pair/revoke;
- recording/retention;
- owner biometric template;
- event/timeline generation;
- dashboard API;
- notifications;
- local settings/audit.

### Remote owner browser

Tailscale/private networking provides reachability, not ownership proof.

Privileged dashboard/API access also passes the deployment-owner authorization boundary defined by `REQUIREMENTS.md` / `SECURITY.md`.

### Slack

Optional external sink explicitly configured by the owner.

## Owner verification boundary

Owner verification is a narrow 1:1 biometric feature:

```text
Observed face
    -> quality gate
    -> compare to explicitly enrolled owner template
    -> match / no-match / unknown
```

The architecture intentionally omits a named non-owner face database.

Anonymous people may receive temporary track IDs for timeline correlation, but cross-camera biometric re-identification is not part of MVP.

## Presence architecture

Presence is a derived state, not a direct face-detector output.

Potential inputs:
- owner-verified entrance crossing;
- direction (`entered` / `exited`);
- manual override;
- schedule hints;
- recency/quality.

States:
- `PRESENT`;
- `PROBABLY_PRESENT`;
- `ABSENT`;
- `UNKNOWN`.

Manual override has highest precedence. Ambiguous visual evidence becomes uncertain rather than silently disarming monitoring.

## Security-event interpretation

Separate observations from conclusions.

Example:

```text
Observations:
- Owner last observed exiting at 17:20
- Anonymous person entered at 17:43
- Server ROI shifted at 17:55
- Rear camera disconnected at 17:56

Correlator:
- build a chronological event context
- link relevant media/observations
- do NOT assert culprit/guilt
```

## Evidence priority

When resources are constrained:

1. Keep source health and failure state truthful.
2. Preserve configured critical server-movement/camera-tamper evidence where storage safety allows.
3. Preserve recording integrity and bounded queues.
4. Reduce expensive detector cadence.
5. Reduce live preview quality/FPS.
6. Prefer explicit degraded state over silent loss.

Browser Camera Nodes do not provide guaranteed independent durable storage in MVP; Ubuntu is primary evidence storage.

## Low-light architecture

No automatic phone torch/light is used in MVP.

Low light is handled by:
- frame-quality metrics;
- detector-specific gating;
- `degraded` / `insufficient` state;
- `unknown` identity/presence results where appropriate.

A future IR/night-vision camera can be added as another source rather than forcing visible illumination from a phone.

## Privacy architecture

All default features remain useful without:
- ServerSentinel developer account;
- developer cloud/API;
- analytics/telemetry;
- native App Store application.

Owner biometric material remains deployment-local. Non-owner named biometric identities are not part of MVP.

## Extensibility

Possible future components:
- RTSP/IP camera source;
- Raspberry Pi/remote edge node;
- independent/off-host evidence storage;
- native mobile client if later justified;
- host CPU/GPU metrics;
- environment sensors;
- NAS target;
- local notification integrations.

These are not MVP requirements.
