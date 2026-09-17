# ServerSentinel Privacy Model

ServerSentinel is designed so that the project developer does not operate infrastructure that receives normal monitoring data.

## Summary

Normal data paths:

```text
Local USB camera -> Main Ubuntu ServerSentinel -> user-selected storage

Remote room camera -> media-capture-agent -> private LAN -> Main Ubuntu ServerSentinel -> storage

Invited phone/Mac browser -> Tailscale/private network -> Main Ubuntu ServerSentinel
```

There is no required ServerSentinel developer cloud/account/data plane.

## Developer data collection

The intended official deployment does not include:
- advertising SDKs;
- analytics/telemetry;
- developer-operated crash upload;
- developer-operated account service;
- developer-operated media/biometric storage;
- developer relay for Slack.

The project developer should not receive during normal operation:
- video or audio;
- face templates/embeddings;
- person/presence events;
- server/capture-node addresses;
- Tailscale information;
- Slack credentials;
- recordings/thumbnails;
- audit logs;
- deployment configuration.

## Video-only MVP

The MVP is video-only for monitoring. Camera microphones are not required and `media-capture-agent` must not open audio devices by default.

## Camera sources

Local UVC cameras and remote-agent UVC cameras are enabled explicitly by the deployment owner.

A remote capture node is a media source identity, not a human account. Pairing it does not grant dashboard/admin rights.

## Human viewers

Invited human viewers may receive only the permissions explicitly assigned by the owner.

Initial permissions:
- `live:view` — current live video;
- `recordings:view` — recording list/browser playback.

They are independent.

Non-owner recording access is browser playback only in MVP. ServerSentinel does not offer them a download/export button or route, but this is not DRM: a person who can view video may still screen-record or use advanced client tooling.

Historical timeline access is not implicitly exposed through `live:view`; its exact invited-user permission model remains a separate decision.

## Tailscale/private remote access

Tailnet membership is not authorization.

The deployment should use restrictive Tailscale access policy so ordinary Tailnet members who are not intended ServerSentinel users receive no grant to the ServerSentinel node and, where Tailscale peer-map trimming applies, do not normally discover it through ordinary peer visibility.

This is not a guarantee of concealment from Tailnet Owners/Admins or infrastructure administrators.

Even a network-reachable identity must still pass the ServerSentinel application allowlist/permission check before receiving camera names, media, recordings, or other deployment metadata.

## Owner-only face verification

ServerSentinel may optionally verify whether a detected face matches the explicitly enrolled deployment owner.

This is biometric processing. Therefore:
- enrollment requires explicit owner action;
- owner template/embedding stays inside the deployment by default;
- template is not sent to the ServerSentinel developer;
- enrollment can be deleted/replaced;
- raw template is excluded from logs/normal diagnostics;
- verification is probabilistic;
- insufficient visual quality returns `unknown` rather than a forced match/non-match.

## Other observed people

The MVP does **not** maintain a named facial identity database for non-owner people.

Other people may receive anonymous/ephemeral track IDs for limited event correlation. Cross-camera biometric re-identification is outside MVP scope.

The system must not label a person as thief, attacker, culprit, or cause merely because they appeared near a critical event.

## Image-quality honesty

If a detector cannot operate reliably because of darkness, blur, obstruction, low target resolution, or similar quality limitations, dependent conclusions become `unknown`/unavailable.

In particular, a skipped/failed person detector must not be translated into `no person` and then used to infer absence.

## Recordings and retention

The main Ubuntu deployment stores:
- recordings;
- thumbnails;
- event/timeline metadata;
- audit logs;
- configuration;
- optional owner biometric template.

Defaults:
- recordings: 20 days;
- audit logs: 90 days.

Starred recordings may outlive normal recording retention.

Non-owner face crops/templates are not stored as a separate persistent identity library by default. People may still appear in ordinary configured video recordings.

## Capture-agent local storage

The policy for a short outage-recovery buffer on `media-capture-agent` is not yet decided. Until an explicit ADR/Issue defines duration, RAM/tmpfs vs disk, encryption/deletion, and retry semantics, the agent must not be described as a second durable evidence store.

## Slack

If the owner enables Slack, configured event information/thumbnails may be sent directly from the deployment to the owner's Slack workspace. The ServerSentinel developer does not relay the message.

## Diagnostics

Diagnostics remain local unless explicitly exported/shared.

Exports should redact/exclude credentials, pairing secrets, private keys, sensitive headers, owner biometric templates, and raw monitoring media unless the owner explicitly chooses otherwise.

## Public repository safety

Repository/CI media fixtures are synthetic/generated only. Real-person or real-environment monitoring media is not committed or attached to GitHub, including merely publicly licensed real-person media. External benchmark datasets may be used locally under their own terms and are not repository fixtures.

## Deployment responsibility

The deployment owner is responsible for camera placement and compliance with applicable law, institutional policy, notice/consent requirements, and biometric/camera rules.

## Future changes

Any feature that sends monitoring/biometric data to infrastructure operated by the ServerSentinel developer is a fundamental privacy-model change and requires explicit owner approval plus updated requirements/security/privacy documentation before implementation.
