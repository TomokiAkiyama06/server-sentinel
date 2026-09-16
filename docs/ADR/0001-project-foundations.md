# ADR-0001: Project foundations

Status: Accepted

## Context

ServerSentinel protects valuable self-hosted servers/workstations through camera monitoring, recording, computer vision, and event correlation.

The initial concept used one dedicated native iOS Camera Node with front/rear MultiCam, CoreMotion, torch control, local emergency evidence, and Public App Store distribution. During requirements refinement, the product goal became clearer: camera hardware should be freely composable, inexpensive USB webcams should be first-class, and a phone should be usable as an entrance camera without requiring Apple Developer/App Store distribution.

The architecture also gained an optional owner-only face-verification/presence feature. That creates additional privacy/security obligations and must not become a general named face database.

## Decision

Project foundations:
- project name: ServerSentinel;
- public GitHub repository;
- Apache-2.0;
- free, no ads/payment;
- no telemetry/analytics;
- no developer-operated user-data cloud;
- self-hosted Ubuntu host;
- FastAPI backend;
- React/TypeScript web UI;
- SQLite metadata;
- Docker Compose;
- Tailscale recommended for remote dashboard reachability;
- deployment-owner authorization remains separate from Tailnet membership;
- Slack optional;
- heavy computer-vision inference runs on Ubuntu by default;
- dependencies/model code/weights require license review;
- audio supported where useful but OFF by default.

Camera architecture:
- common Camera Source abstraction;
- MVP source types: local UVC/V4L2 and remote browser-based Web Camera Node;
- MVP supports 1–4 active video sources in arbitrary supported composition;
- camera type, user-visible role, and detection profiles are separate concepts;
- iPhone/Android/PC may act as a Web Camera Node through a secure browser context;
- no native iOS application, Apple Developer Program, or App Store distribution is required by MVP;
- simultaneous phone front/rear capture is not required;
- automatic motion/low-light torch or visible-light activation is not part of MVP;
- browser background capture and browser-local storage are not treated as guaranteed durable evidence.

Detection/privacy architecture:
- general motion/person detection;
- per-source server ROI/movement and camera-tamper profiles;
- low-light/image-quality gating;
- optional entrance crossing;
- optional **owner-only 1:1 face verification**;
- non-owner people remain anonymous observations/tracks;
- named non-owner face database and cross-camera biometric re-identification are not MVP features;
- event timeline correlates observations but does not determine guilt/culpability.

## Alternatives considered

### Native iOS-first Camera Node

Advantages:
- AVFoundation/CoreMotion access;
- stronger control of capture lifecycle;
- possible native local evidence store;
- richer device-specific telemetry.

Rejected for MVP because:
- forces Apple signing/developer/App Store work;
- over-specializes the product around one device class;
- duplicates capabilities cheaply available from UVC webcams;
- increases thermal/mobile lifecycle complexity;
- the revised phone role (e.g. entrance camera) can be served by a browser for MVP.

A native mobile node may be reconsidered later if strong independent local/off-host evidence becomes a product requirement.

### Fixed two-webcam layout

Rejected because users may reasonably deploy one, two, three, or four cameras and may mix USB/browser sources. Fixed `server_side/server_rear` columns would create unnecessary topology lock-in.

### Automatic phone torch in low light

Rejected because visible illumination may be undesirable and browser/device support is inconsistent. Low-light insufficiency is represented explicitly and may be solved by placement/ambient/IR-capable hardware instead.

### General face identification

Rejected for MVP because owner presence only needs 1:1 owner verification and a named multi-person biometric database creates significantly larger privacy/security scope.

## Consequences

Advantages:
- cheap one-webcam deployments are valid;
- multi-camera deployments scale to four active sources;
- USB webcams and phone browsers share one logical event/storage system;
- no Apple Developer/App Store dependency;
- Android/laptop cameras can participate;
- source roles/detectors can evolve independently of hardware;
- privacy scope of biometric processing stays narrow.

Costs/limitations:
- browser Camera Node reliability is subject to browser/OS foreground rules;
- HTTPS/secure-origin setup must be solved cleanly;
- browser-local evidence cannot be promised as durable;
- independent evidence after physical loss of Ubuntu remains future work;
- UVC stable-device mapping and USB bandwidth require careful handling;
- owner verification needs model/license/threshold/privacy validation;
- four maximum-quality streams are not guaranteed on every USB/compute topology and require adaptive profiles.

## Validation

Before calling the architecture production-ready:
- test 1–4 active sources;
- test multiple UVC devices/reordering/reconnect;
- test Web Camera Node on iPhone Safari and at least one other browser/device where available;
- verify secure-origin onboarding;
- benchmark media/AI load;
- test low-light degraded behavior with no auto-light;
- test owner verification/entrance presence manually without publishing real-person media;
- test unified timeline and neutral observation language;
- verify storage pressure/failure behavior.

## Follow-up ADRs

Create ADRs before implementation where needed for:
- deployment-owner authorization;
- browser secure-origin/local HTTPS setup;
- live media transport;
- codec/recording profile;
- final person detector/model/weights;
- final owner face-verification model/weights/threshold method;
- server-movement algorithm;
- strong independent/off-host evidence storage if later required;
- any future native mobile client.
