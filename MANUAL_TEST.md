# ServerSentinel Manual / Real-Hardware Test Plan

This document contains checks that cannot be truthfully completed using software mocks alone.

Do not mark an item PASS without performing it on the stated hardware/browser/environment. Do not commit or attach real monitoring footage, real-person images/video/audio, owner biometric templates, or private deployment values to GitHub.

## Test metadata template

```text
Date:
ServerSentinel version:
Git commit:
Ubuntu version:
Server hardware:
Camera source(s):
Webcam model(s):
Web Camera device/browser/OS:
Network:
Recording disk:
Tester:
```

## A. Local UVC / USB camera

For each tested webcam:
- [ ] device is discovered;
- [ ] stable identity information is shown where available;
- [ ] owner can enable/disable source;
- [ ] preview works;
- [ ] negotiated resolution/FPS is reported;
- [ ] reconnect works after unplug/replug;
- [ ] offline/online events are generated;
- [ ] reboot does not silently attach a different physical camera because `/dev/videoN` ordering changed;
- [ ] container/service does not require unnecessary privileged mode.

Multi-camera checks:
- [ ] one UVC camera works;
- [ ] two UVC cameras work simultaneously;
- [ ] three/four active UVC or mixed sources are tested where hardware/USB topology permits;
- [ ] insufficient USB/controller bandwidth becomes explicit degraded state rather than silent loss.

Record USB controller/topology when investigating bandwidth limits.

## B. Web Camera Node

Test at minimum on the intended phone/browser. iPhone Safari is an important real deployment target but not the only valid client.

- [ ] Camera Node page loads over a valid secure context;
- [ ] camera permission flow is understandable;
- [ ] microphone remains OFF on first use;
- [ ] microphone denial does not prevent video-only monitoring;
- [ ] front/back camera selector works where browser exposes multiple cameras;
- [ ] only the selected camera is required; simultaneous front/rear capture is not assumed;
- [ ] monitoring state is visible;
- [ ] connection state is visible;
- [ ] Screen Wake Lock is requested/handled where supported;
- [ ] unsupported Wake Lock fails gracefully;
- [ ] browser reload reconnects appropriately;
- [ ] network interruption reconnects appropriately;
- [ ] permission revocation is reported;
- [ ] media track end/mute is reported;
- [ ] screen lock/background/browser suspension behavior is measured and documented;
- [ ] the UI never claims uninterrupted background capture when it stopped;
- [ ] no Apple Developer Program/App Store/native install is required.

If available, repeat core checks on at least one non-iPhone browser/device.

## C. Source registry / mixed topology

Validate configurations:
- [ ] 1 active source;
- [ ] 2 active sources;
- [ ] 3 active sources;
- [ ] 4 active sources;
- [ ] fifth activation is rejected cleanly under default limit;
- [ ] mixture of UVC + Web Camera sources works;
- [ ] source rename works;
- [ ] role label change works;
- [ ] detection profiles are independent of source type;
- [ ] removing one source does not corrupt recordings/events for the others.

## D. Physical installation / field of view

Server-monitoring camera(s):
- [ ] server body/ROI visible;
- [ ] sufficient background/context exists for camera-global-transform detection;
- [ ] rear/cable view is usable if configured;
- [ ] normal movement around the area does not constantly occlude the target;
- [ ] mounts are stable.

Entrance camera if used:
- [ ] entrance line/zone visible;
- [ ] incoming/outgoing direction can be distinguished;
- [ ] normal doorway occlusion is manageable;
- [ ] owner face is sometimes visible at sufficient size/angle when entering/exiting;
- [ ] camera placement complies with local/institutional rules.

Document geometry privately; do not upload real room imagery to GitHub.

## E. Server ROI calibration and movement

Per configured server source:
- [ ] ROI/polygon placement works;
- [ ] reference frame saved;
- [ ] recalibration works;
- [ ] small lighting changes do not trigger movement;
- [ ] person standing in front of server does not immediately trigger server movement;
- [ ] partial occlusion clears without false critical event;
- [ ] server moved several centimeters triggers event;
- [ ] server rotation triggers event;
- [ ] camera itself moved is distinguished from server-only movement where practical;
- [ ] event can link evidence from additional active sources.

Record thresholds/quality metrics without publishing real media.

## F. Camera tamper and source health

For local webcam(s):
- [ ] gently move mount;
- [ ] rotate/reposition camera;
- [ ] cover lens;
- [ ] disconnect USB;
- [ ] reconnect USB;
- [ ] confirm scene shift/occlusion/disconnect signals are represented correctly.

For Web Camera Node:
- [ ] cover lens;
- [ ] move device/stand enough to change scene;
- [ ] close/reload camera page;
- [ ] disable Wi-Fi briefly;
- [ ] revoke camera permission;
- [ ] lock/suspend browser where OS allows testing.

Expected:
- meaningful tamper/health changes are visible/audited;
- trivial scene vibration does not flood critical alerts;
- browser/UVC limitations are not hidden.

## G. Network interruption

Remote Web Camera Node scenarios:
- [ ] network off 10 seconds;
- [ ] network off 2 minutes;
- [ ] AP restart;
- [ ] server service restart;
- [ ] Ubuntu reboot;
- [ ] Tailscale/private remote-path interruption where applicable.

Check:
- state transition;
- reconnect time;
- recording gaps;
- duplicated chunks;
- missing media;
- audit event;
- manual-intervention state if automatic recovery fails.

## H. Live multi-camera view

Local network:
- [ ] 1 source usable;
- [ ] 2-source layout usable;
- [ ] 3–4 source layout usable;
- [ ] per-source health/quality visible;
- [ ] selected camera can be expanded;
- [ ] audio plays only when explicitly enabled.

Remote/private-network path:
- [ ] live start time measured;
- [ ] latency measured;
- [ ] reconnect works;
- [ ] adaptive quality degradation works;
- [ ] one degraded source does not hide healthy-source state.

## I. Manual and event recording

- [ ] start selected-source manual recording;
- [ ] stop manually;
- [ ] 20-minute maximum enforced;
- [ ] forgetting to stop does not record indefinitely;
- [ ] event recording includes configured pre-roll/post-roll;
- [ ] one event can contain multiple source recordings;
- [ ] recording manifest uses source IDs, not fixed front/rear names;
- [ ] audio follows per-source setting;
- [ ] playback/source labels are correct.

## J. Low light / image-quality gating

Test entrance and server sources under progressively darker conditions.

- [ ] quality state transitions `sufficient -> degraded -> insufficient` appropriately;
- [ ] live/recording remains available when the camera still produces frames;
- [ ] owner verification becomes `unknown/unavailable` before quality is too poor for reliable identity judgement;
- [ ] person detection degradation is visible where applicable;
- [ ] recovery after lighting returns is automatic/hysteretic;
- [ ] **no phone torch/flash/screen-light auto-activation occurs**;
- [ ] motion does not trigger visible illumination.

Document whether the deployment requires a low-light/IR-capable camera rather than forcing phone illumination.

## K. Audio

Audio default must be OFF.

- [ ] first-use default OFF;
- [ ] explicit enable required;
- [ ] enabled state visible;
- [ ] live audio works where supported;
- [ ] recorded audio works where supported;
- [ ] disabling takes effect promptly;
- [ ] permission denial handled cleanly;
- [ ] enabling audio on one source does not implicitly enable others.

## L. Owner-only face verification

Use only the deployment owner's own enrollment during manual testing. Do not upload enrollment/reference images or resulting real-person clips to GitHub.

Enrollment:
- [ ] explicit biometric explanation shown;
- [ ] owner can enroll;
- [ ] poor enrollment image rejected/asks for retry;
- [ ] owner template remains local;
- [ ] delete/re-enroll works;
- [ ] raw template does not appear in logs/normal diagnostics.

Verification conditions:
- [ ] normal frontal view;
- [ ] side angle;
- [ ] different distance;
- [ ] glasses/appearance variation where relevant;
- [ ] mask/partial occlusion;
- [ ] low light;
- [ ] deliberately poor/blurred frame;
- [ ] another consenting test person or synthetic display test is not incorrectly asserted as owner within the documented test setup.

Expected:
- [ ] result includes confidence/quality;
- [ ] ambiguous/poor-quality result becomes `unknown`;
- [ ] UI never describes verification as certainty;
- [ ] no named enrollment feature exists for other people.

## M. Entrance crossing and anonymous tracking

Test with owner and consenting participants without retaining/sharing test media externally.

- [ ] owner enters alone;
- [ ] owner exits alone;
- [ ] anonymous person enters/exits;
- [ ] two people enter close together;
- [ ] owner + another person enter together;
- [ ] one person partially occludes another;
- [ ] person reverses direction at doorway;
- [ ] loitering near line does not generate repeated entry/exit spam;
- [ ] same-camera anonymous track behavior is understandable;
- [ ] unknown people are not assigned real names;
- [ ] no cross-camera biometric re-identification is claimed.

## N. Presence inference

- [ ] high-confidence owner entry can reach `PRESENT`;
- [ ] high-confidence owner exit can reach `ABSENT` when context supports it;
- [ ] ambiguous observation becomes `PROBABLY_PRESENT`/`UNKNOWN` rather than forced state;
- [ ] low-light owner verification does not force state;
- [ ] manual override wins over inference;
- [ ] schedule does not override active manual override;
- [ ] returning to automatic inference works;
- [ ] only `PRESENT` suppresses ordinary person/general-motion automation by default;
- [ ] `PROBABLY_PRESENT` and `UNKNOWN` do not silently disarm ordinary security automation;
- [ ] server movement remains armed during presence;
- [ ] camera tamper remains armed during presence;
- [ ] live/manual recording remain available.

## O. Unified security timeline

Create a controlled synthetic/manual scenario such as:

```text
Owner exits
Anonymous person enters
Server movement occurs
One camera disconnects
Anonymous person exits
```

Check:
- [ ] timestamps are ordered correctly;
- [ ] source attribution correct;
- [ ] linked recordings/thumbnails correct;
- [ ] relevant-window view shows useful context;
- [ ] confidence/quality is shown where applicable;
- [ ] the system does not label the person as culprit/thief/attacker;
- [ ] missing/offline-source gaps are visible rather than inferred away.

## P. Storage pressure / hard stop

Use a disposable/test recording volume or controlled fixture environment.

- [ ] retention deletes expired unstarred data;
- [ ] allocation pressure reclaims oldest eligible unstarred data;
- [ ] unrelated filesystem consumption also triggers admission pressure;
- [ ] starred data is not auto-deleted;
- [ ] `STORAGE_PRESSURE` suppresses non-critical/manual admission as specified;
- [ ] bounded critical allowance does not cross hard reserve;
- [ ] `STORAGE_HARD_STOP` occurs before unsafe write;
- [ ] warnings/audit events visible;
- [ ] recovery uses hysteresis.

Never intentionally fill the production filesystem to 0 bytes free.

## Q. Long-duration / performance

Run at least:
- [ ] 1 hour;
- [ ] 8 hours;
- [ ] 24 hours.

Record:
- number/type of active sources;
- per-source resolution/FPS/bitrate;
- inference cadence per profile;
- CPU/GPU utilization;
- memory;
- disk write rate;
- USB controller topology/bandwidth where relevant;
- network throughput;
- browser/device temperature subjectively or with safe independent measurement if available;
- disconnects/reconnects;
- dropped frames;
- service/browser crashes;
- false source-health states.

Include a four-active-source run where available. Final defaults must be based on measurements rather than assumptions.
