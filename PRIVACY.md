# ServerSentinel Privacy Model

> Draft project privacy document. A final App Store privacy policy should be reviewed before publication and hosted at a stable public URL.

## Summary

ServerSentinel is designed so that the project developer does not operate a backend that receives users' monitoring data.

Normal data path:

```text
User's iPhone -> User's Ubuntu Server -> User's storage
```

Optional:

```text
User's Ubuntu Server -> User's Slack workspace
User's remote device -> Tailscale -> User's Ubuntu Server
```

## Developer data collection

The intended official build does not include:
- advertising SDKs;
- analytics SDKs;
- telemetry;
- developer-operated crash upload;
- developer-operated account service;
- developer-operated video/audio storage.

The project developer should not receive, in normal operation:
- video;
- audio;
- motion events;
- server addresses;
- Tailscale information;
- Slack credentials;
- recordings;
- audit logs.

## Camera and microphone

Camera access is required for monitoring.

Microphone access is optional and OFF by default.

The app must clearly indicate monitoring/recording state and must request permissions using understandable explanations.

## Local storage

The iPhone may temporarily store critical evidence for server-movement/camera-tamper events.

Ubuntu stores:
- recordings;
- thumbnails;
- metadata;
- audit logs;
- configuration.

Retention is controlled by the deployment owner.

Defaults:
- recordings: 20 days;
- audit logs: 90 days.

Starred recordings can outlive the normal recording retention period.

## Slack

If the user enables Slack:
- event information and thumbnails may be sent to the user's configured Slack workspace;
- this is a user-configured third-party data destination;
- ServerSentinel's developer does not relay the message.

## Tailscale

If the user enables Tailscale, network metadata and traffic handling are subject to Tailscale's service and the user's Tailnet configuration.

ServerSentinel does not require the developer to receive Tailnet credentials.

## Diagnostics

Diagnostics stay local unless the user explicitly exports/shares them.

Diagnostic export should redact:
- credentials;
- pairing tokens;
- Slack secrets;
- private keys;
- sensitive headers.

## Public repository safety

Examples must not contain real deployment values.

See `AGENTS.md` and `SECURITY.md`.

## Future changes

Any future feature that would cause data to be sent to infrastructure operated by the ServerSentinel developer is a fundamental privacy-model change and requires:
- explicit product decision;
- updated requirements;
- updated privacy policy;
- App Store privacy disclosure review;
- user-visible disclosure.
