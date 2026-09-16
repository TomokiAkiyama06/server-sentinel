# ServerSentinel Privacy Model

ServerSentinel is designed so that the project developer does not operate infrastructure that receives normal monitoring data.

## Summary

Normal data paths:

```text
Local USB camera -> User's Ubuntu ServerSentinel host -> User-selected storage

User-owned browser camera -> User's Ubuntu ServerSentinel host -> User-selected storage
```

Optional third-party paths:

```text
User's Ubuntu host -> User's Slack workspace
User's remote browser -> Tailscale/private network -> User's Ubuntu host
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
- server addresses;
- Tailscale information;
- Slack credentials;
- recordings/thumbnails;
- audit logs;
- deployment configuration.

## Camera and microphone

Local UVC cameras are enabled explicitly by the deployment owner.

Remote Web Camera Nodes use normal browser camera/microphone permission flows. Camera monitoring state must remain visible in the Camera Node UI.

Microphone capture is optional and **OFF by default**. Audio must not be enabled merely because a camera is enabled.

## Owner-only face verification

ServerSentinel may optionally verify whether a detected face matches the explicitly enrolled deployment owner.

This is biometric processing. Therefore:
- enrollment requires explicit owner action;
- the owner template/embedding stays inside the deployment by default;
- the template is not sent to the ServerSentinel developer;
- owner enrollment can be deleted/replaced;
- template data is excluded from normal diagnostics/export unless specifically and explicitly requested;
- logs/audit records may state that enrollment/verification occurred but must not contain the raw template.

Face verification is probabilistic. Low-quality/low-light observations may be reported as `unknown` rather than match/non-match.

## Other observed people

The MVP does **not** maintain a named facial identity database for non-owner people.

Other people may be represented by anonymous, non-name identifiers such as `Person #A` / ephemeral track UUIDs for limited event correlation. The system must not present an anonymous observation as a real-world identity.

Cross-camera biometric re-identification of anonymous people is outside MVP scope and requires a separate privacy/architecture decision.

The system must not label a person as a thief, attacker, or culprit merely because they appeared near a critical event. The dashboard presents observations and timing for human review.

## Recordings and retention

Ubuntu stores:
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

## Web Camera Node local storage

Browser/PWA local storage is not treated as guaranteed durable evidence storage in the MVP. Browser implementations may use bounded best-effort buffering for reconnect behavior, but browser eviction/lifecycle rules prevent ServerSentinel from promising that evidence survives device/browser shutdown or loss of the Ubuntu recorder.

## Low light and illumination

ServerSentinel does not automatically turn on a phone torch/screen light in response to motion or low light in the MVP. If visual quality is insufficient, affected computer-vision results become degraded/unknown.

## Slack

If the owner enables Slack:
- configured event information/thumbnails may be sent to the owner's Slack workspace;
- Slack is a user-selected third-party destination;
- the ServerSentinel developer does not relay the message.

## Tailscale / private remote access

If the owner uses Tailscale or another private-access provider, network metadata/traffic are subject to that provider and the user's configuration.

Tailnet membership is not by itself deployment-owner authorization.

## Diagnostics

Diagnostics remain local unless explicitly exported/shared.

Diagnostic export should redact or exclude:
- credentials/tokens;
- pairing secrets;
- private keys;
- sensitive headers;
- owner biometric templates;
- raw monitoring media unless the owner explicitly chooses to include it.

## Public repository safety

Repository examples and tests use synthetic/generated media only. Real-person or real-environment monitoring media is not committed or attached to PRs even with consent.

## Deployment responsibility

ServerSentinel is a tool. The deployment owner is responsible for deciding where cameras are placed and for complying with applicable law, institutional policy, notice/consent requirements, and biometric/camera rules.

## Future changes

Any feature that sends monitoring or biometric data to infrastructure operated by the ServerSentinel developer is a fundamental privacy-model change and requires explicit owner approval, updated requirements/security/privacy documentation, and user-visible disclosure before implementation.
