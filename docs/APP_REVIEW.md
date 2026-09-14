# App Store Review Preparation

Target: normal Public App Store distribution.

## Review principles

ServerSentinel Camera must present itself honestly as a self-hosted security camera node.

Do not:
- hide camera/microphone use;
- create reviewer-only secret behavior;
- market it as covert spying;
- imply the developer stores video if it does not;
- require the reviewer to join a private production Tailnet.

## Required product behaviors

- permission rationale before requests;
- visible monitoring/recording state;
- microphone default OFF;
- privacy-policy link;
- capability fallback;
- Demo Mode;
- clean failure state when no ServerSentinel server is paired.

## Demo Mode

Purpose:
Allow App Review to evaluate the product without operating a private Ubuntu environment.

Demo Mode may provide:
- synthetic server status;
- synthetic event history;
- synthetic storage status;
- setup/calibration UI;
- real local camera preview after permission where appropriate.

Demo Mode must label synthetic content clearly.

It should be accessible normally, e.g.:
`Settings -> Demo Mode`.

## Reviewer notes draft topics

Explain:
- app is a client for a self-hosted server;
- developer does not operate the user's backend;
- normal pairing uses LAN/QR;
- Demo Mode path;
- camera/microphone purpose;
- microphone default;
- no account required;
- no paid features/ads.

## Privacy declaration review

Before each App Store release:
- compare actual network requests with privacy declarations;
- re-check every third-party SDK;
- re-check crash/analytics behavior;
- verify no unexpected developer endpoint.

Do not assume an old privacy declaration stays correct after dependency changes.
