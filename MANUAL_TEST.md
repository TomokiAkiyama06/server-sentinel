# ServerSentinel Manual / Real-Device Test Plan

This document contains tests that cannot be truthfully completed with software mocks alone.

Do not mark an item PASS without performing it on the stated hardware/environment.

## Test metadata template

```text
Date:
ServerSentinel version:
Git commit:
iPhone model:
iOS version:
Ubuntu version:
Server hardware:
Network:
Recording disk:
Tester:
```

## A. iPhone capability

- [ ] App launches on target iPhone.
- [ ] Rear camera permission flow works.
- [ ] Front camera permission flow works.
- [ ] Microphone permission flow works.
- [ ] Motion sensor permission/availability handled.
- [ ] MultiCam support reported correctly.
- [ ] Rear + front simultaneous capture works on iPhone 14.
- [ ] Unsupported-capability fallback is understandable.
- [ ] Torch capability is detected correctly.
- [ ] Charging state shown correctly where available.
- [ ] Thermal state shown correctly.

## B. Long-duration thermal test

Run at least:

- [ ] 1 hour
- [ ] 8 hours
- [ ] 24 hours

Record:
- ambient temperature;
- case/no-case;
- charger type;
- rear resolution/FPS;
- front resolution/FPS;
- bitrate;
- device thermal-state transitions;
- app crashes;
- dropped frames;
- reconnects;
- battery percentage trend while plugged in;
- phone surface temperature if independently measurable.

Acceptance target:
- monitoring remains operational;
- thermal degradation is graceful;
- no uncontrolled restart loop;
- no silent capture stop.

Final capture defaults MUST be based on these measurements.

## C. Physical installation / field of view

Target installation:
- dedicated iPhone mounted under desk near cable opening using MagSafe-style mount;
- floor-mounted server;
- camera positioned approximately toward the server's left-rear side relative to a seated user, adjusted to actual room geometry.

Validate:
- [ ] server is visible with surrounding floor/context;
- [ ] rear camera sees enough server geometry for movement detection;
- [ ] person interacting with server is captured as well as desk geometry permits;
- [ ] desk underside does not make monitoring useless;
- [ ] front camera sees likely approach/tamper area;
- [ ] mount does not obstruct camera lenses;
- [ ] phone can be charged continuously;
- [ ] phone cannot be trivially bumped by normal chair/leg movement.

Document actual angle and screenshots.

## D. Server ROI calibration

- [ ] Setup UI allows ROI placement.
- [ ] Reference frame saved.
- [ ] Recalibration works.
- [ ] Small lighting changes do not trigger movement.
- [ ] Person standing in front of server does not immediately trigger server movement.
- [ ] Partial occlusion clears without false critical alert.
- [ ] Server moved several centimeters triggers event.
- [ ] Server rotation triggers event.
- [ ] Server returned to original location produces sensible state.

Threshold values must be recorded.

## E. Camera tamper

Test:
- [ ] gently touch mount;
- [ ] rotate phone;
- [ ] remove from MagSafe;
- [ ] cover rear lens;
- [ ] cover front lens;
- [ ] unplug charging cable;
- [ ] move entire stand;
- [ ] attempt to reach side/power button with minimal phone movement.

Expected:
- meaningful tamper actions generate an event;
- trivial vibration does not flood alerts;
- critical local evidence is preserved where possible.

Physical power-button guard remains a separate hardware consideration.

## F. Local emergency evidence

- [ ] Critical event creates local clip.
- [ ] Local data survives Ubuntu network disconnect.
- [ ] Data syncs after Ubuntu returns.
- [ ] Duplicate sync is idempotent.
- [ ] 500 MB limit/ring behavior works.
- [ ] Old unprotected local data is evicted first.
- [ ] Critical unsynced data is not silently lost before policy requires it.

## G. Network interruption

Scenarios:
- [ ] Wi-Fi off 10 seconds;
- [ ] Wi-Fi off 2 minutes;
- [ ] AP restart;
- [ ] Ubuntu service restart;
- [ ] Ubuntu full reboot;
- [ ] Tailscale remote path interruption.

Check:
- UI state;
- local buffering;
- reconnect time;
- duplicated chunks;
- missing media;
- audit event;
- manual-intervention state if recovery fails.

## H. Live view

From local network:
- [ ] 720p-class target view usable.
- [ ] 15–30 fps target behavior measured.
- [ ] audio when enabled.
- [ ] rear/front selection where supported.

From outside network over Tailscale:
- [ ] mobile data connection works;
- [ ] live start time measured;
- [ ] latency measured;
- [ ] reconnect works;
- [ ] adaptive degradation works.

## I. Manual recording

- [ ] Start remotely.
- [ ] Stop remotely.
- [ ] Audio follows configured state.
- [ ] Recording appears in event/history UI.
- [ ] 20-minute maximum enforced.
- [ ] Forgetting to stop does not record indefinitely.
- [ ] Ring-buffer pre-roll is included if designed for manual start.

## J. Low light / torch

- [ ] Low-light detection works reasonably.
- [ ] Motion in low light triggers torch in Auto mode.
- [ ] Torch turns off 30 seconds after last qualifying motion.
- [ ] New motion resets timer.
- [ ] Manual On works.
- [ ] Manual Off works.
- [ ] Unsupported torch fails gracefully.
- [ ] Torch behavior does not crash MultiCam session.

## K. Audio

Audio default must be OFF.

- [ ] First-run default is OFF.
- [ ] Explicit enable is required.
- [ ] UI clearly shows enabled state.
- [ ] Live audio works.
- [ ] Recorded audio works.
- [ ] Disabling takes effect promptly.
- [ ] Permission denial handled cleanly.

## L. Presence

- [ ] One-tap presence works on mobile dashboard.
- [ ] Quick-duration selection works.
- [ ] "Until time" works.
- [ ] Presence expiry automatically restores monitoring.
- [ ] Presence pauses ordinary person/general-motion automatic security recordings/events.
- [ ] Confirmed server movement remains armed during presence, preserves evidence, and can still send its critical alert.
- [ ] Confirmed camera tamper remains armed during presence, preserves evidence, and can still send its critical alert.
- [ ] Live view still works.
- [ ] Manual recording still works.
- [ ] Weekly schedule works.
- [ ] Manual override wins over schedule until expiry.

Optional Shortcuts:
- [ ] check-in endpoint works;
- [ ] check-out endpoint works;
- [ ] Tailscale/local conditions documented.

## M. Slack

- [ ] Slack setup validates credentials/webhook safely.
- [ ] Server movement immediate message.
- [ ] Camera tamper immediate message.
- [ ] Ordinary person/motion does not spam channel.
- [ ] Daily summary at default 23:00.
- [ ] Daily time configurable.
- [ ] Thread replies include thumbnails.
- [ ] Slack outage does not stop recording.
- [ ] No secret appears in log.

## N. Storage / retention

Using test allocation:
- [ ] 20-day retention logic.
- [ ] configured capacity ceiling.
- [ ] oldest unstarred removed first.
- [ ] starred item survives.
- [ ] star/unstar works.
- [ ] UI warns when starred data threatens capacity.
- [ ] manual delete works.
- [ ] no path traversal.
- [ ] disk-full safety behavior prevents uncontrolled corruption.

## O. Audit logs

- [ ] settings changes recorded;
- [ ] monitoring state changes recorded;
- [ ] pairing/revocation recorded;
- [ ] critical events recorded;
- [ ] logs not individually deletable via normal UI;
- [ ] 90-day expiry logic testable with accelerated clock/test environment;
- [ ] secrets are redacted.

## P. Screen/brightness behavior

- [ ] Monitoring screen is near-black but status remains visible.
- [ ] Tap reveals controls.
- [ ] temporary brighter interaction state works.
- [ ] app returns to dim state.
- [ ] original brightness restoration behaves acceptably.
- [ ] auto-lock prevention works while monitoring.
- [ ] leaving/stopping app does not leave device in surprising brightness state.

## Q. App Store review readiness

On a clean device/account:
- [ ] onboarding understandable;
- [ ] all permission rationales clear;
- [ ] privacy policy accessible;
- [ ] monitoring state visible;
- [ ] audio default OFF;
- [ ] Demo Mode works without Ubuntu;
- [ ] Demo Mode clearly labels synthetic/demo data;
- [ ] no reviewer-only hidden behavior;
- [ ] no developer private hostname/IP appears.

## R. 24-hour acceptance run

Final real-device acceptance:

1. Pair clean installation.
2. Calibrate.
3. Monitor for 24 hours.
4. View remotely at least three times.
5. Trigger person event.
6. Trigger general motion.
7. Trigger server movement.
8. Trigger camera tamper.
9. Disconnect network.
10. Recover.
11. Trigger manual recording.
12. Verify Slack daily summary.
13. Verify recordings/playback.
14. Verify audit log.
15. Verify storage accounting.

Record all defects as GitHub Issues.
