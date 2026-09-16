# ADR-0001: Project foundations

Status: Accepted

## Context

ServerSentinel is intended to protect a valuable self-hosted server using a spare iPhone while remaining usable by unrelated users through a public App Store app and public repository.

## Decision

- Project name: ServerSentinel
- Public GitHub repository target
- Apache-2.0
- Public App Store distribution target
- Free
- No ads
- No telemetry/analytics
- No developer cloud
- Self-hosted Ubuntu server
- Native iOS Camera Node
- FastAPI backend
- React dashboard
- SQLite metadata
- Docker Compose
- Tailscale recommended for remote dashboard access
- Slack optional
- Heavy vision inference on Ubuntu
- YOLOX-first person-detector evaluation with independent model-weight license verification
- Audio feature present but default OFF

## Consequences

Advantages:
- strong privacy story;
- no central user-data liability by architecture;
- low recurring developer infrastructure cost;
- easy OSS inspection;
- capable native camera/sensor integration.

Costs:
- user must operate Ubuntu;
- self-host setup must be excellent;
- App Store review needs Demo Mode;
- remote availability depends on user's environment;
- media/network complexity remains substantial.

## Follow-up

Create ADRs for:
- live media transport;
- codec/recording profile;
- final person detector/model/weights;
- server movement algorithm;
- Camera Node thermal policy after real-device tests.
