# Architecture

## Boundary principle

ServerSentinel has no central developer backend.

A deployment boundary is one owner's environment.

```text
Deployment A                    Deployment B
iPhone A -> Ubuntu A            iPhone B -> Ubuntu B
      \      /                        \      /
       owner A                        owner B

No shared ServerSentinel developer data plane.
```

## Trust boundaries

### Camera Node
Trusted after pairing.

Can submit:
- heartbeat;
- media;
- IMU/thermal telemetry;
- capability state.

### Ubuntu
Primary trusted authority for:
- pairing;
- retention;
- event generation;
- dashboard;
- notifications;
- local settings.

### Remote browser
Tailscale is the recommended MVP remote-access layer and provides network reachability, but Tailnet membership alone is not sufficient deployment-owner authorization.

Privileged dashboard/API access must also pass the deployment-owner authorization boundary defined by `REQUIREMENTS.md` REMOTE-005 and `SECURITY.md`. The exact self-hosted authorization mechanism is selected by ADR before implementation.

### Slack
Optional external sink chosen by user.

## Security-event interpretation

The pipeline should separate observations from conclusions.

Example:

```text
Observations:
- person present
- ROI partially occluded
- camera global transform low
- server feature geometry shifts 9 cm equivalent
- shift persists 3 seconds

Correlator:
-> server_movement, confidence 0.92
```

Do not let one detector directly make every security decision.

## Evidence priority

When resources are constrained:

1. Preserve critical event evidence.
2. Keep rear server camera alive.
3. Keep connection/session alive.
4. Maintain front anti-tamper camera.
5. Preserve smooth live preview.
6. Preserve high resolution.

## Privacy architecture

All default features must remain useful without:
- ServerSentinel account;
- developer token;
- developer API;
- analytics.

## Extensibility

Possible future components:
- host CPU/GPU metrics;
- environment sensors;
- additional camera nodes;
- NAS target;
- local notification integrations.

They are not MVP requirements.
