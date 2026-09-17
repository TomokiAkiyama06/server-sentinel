# ServerSentinel Manual / Real-Hardware Test Plan

This document contains checks that cannot be truthfully completed using software mocks alone.

Do not mark an item PASS without performing it on the stated hardware/network/browser environment. Do not commit or attach real monitoring footage, real-person images/video/audio, owner biometric templates, or private deployment values to GitHub.

## Test metadata

```text
Date:
ServerSentinel version / Git commit:
Main Ubuntu version / hardware:
Capture-node Ubuntu version / hardware:
Camera source(s) / model(s):
USB topology:
LAN topology/speed:
Tailscale/private-access path:
Phone/Mac/browser used for viewing:
Recording volume:
Tester:
```

## A. Local UVC / USB camera

For each tested camera:

- [ ] device is discovered;
- [ ] stable identity evidence is shown where available;
- [ ] owner can enable/disable source;
- [ ] preview works;
- [ ] negotiated resolution/FPS/format is reported;
- [ ] unplug creates `offline` event/state;
- [ ] reconnect works when identity is unambiguous;
- [ ] reboot/re-enumeration does not silently bind a different device through `/dev/videoN` reuse;
- [ ] no unnecessary privileged container is required.

### Ambiguous identical-device test

Where possible use two identical UVC devices without a usable unique serial, or a controlled mock reproducing that identity ambiguity.

- [ ] disconnect/reorder devices;
- [ ] system does **not** arbitrarily choose one as the old source;
- [ ] source enters `manual_intervention_required`;
- [ ] owner can explicitly re-approve a physical mapping;
- [ ] healthy monitoring resumes only after approval.

## B. Remote Linux capture node / `media-capture-agent`

Use the intended secondary Ubuntu machine and room-overview camera.

Installation/service:

- [ ] development checkout can run the agent during development;
- [ ] `media-capture-agent.service` installs/starts cleanly when installer exists;
- [ ] normal process runs as a dedicated non-root account;
- [ ] no GUI/tray is required;
- [ ] service name/process is `media-capture-agent` and does not impersonate unrelated software;
- [ ] microphone/audio device is not opened.

Pairing/security:

- [ ] owner creates a short-lived one-time pairing code;
- [ ] expired code is rejected;
- [ ] reused code is rejected;
- [ ] agent identity is unique/revocable;
- [ ] post-pairing traffic is mutually authenticated/encrypted;
- [ ] revoked agent cannot reconnect;
- [ ] an unpaired LAN host cannot submit media;
- [ ] capture-node credential cannot access dashboard/admin APIs.

Connectivity:

- [ ] agent works over the same private LAN without joining Tailscale;
- [ ] agent initiates connection toward the main host;
- [ ] main host does not require SSH/admin access to the capture machine;
- [ ] ingest listener exposes no dashboard/settings/recording-browser routes;
- [ ] firewall/interface restrictions are documented and do not replace mTLS.

Health:

- [ ] agent-online / camera-online shown separately;
- [ ] camera USB unplug leaves agent online and camera offline;
- [ ] reconnect returns online only after safe identity match;
- [ ] agent stop/crash becomes node offline;
- [ ] main-host restart/reconnect is reported truthfully;
- [ ] heartbeat does not falsely imply that video frames are arriving.

## C. Room-overview camera placement

For the intended wide room view:

- [ ] full room/important area is visible;
- [ ] entrance/zone is visible if entrance logic is desired;
- [ ] server area is visible if the overview source is expected to contribute evidence;
- [ ] normal people/movement do not permanently occlude important regions;
- [ ] mount is stable;
- [ ] lighting variation is measured;
- [ ] camera placement complies with institutional/local rules.

Do not upload room geometry or imagery to GitHub.

### Capture-profile benchmark

Compare at minimum where camera capabilities allow:

- [ ] highest useful resolution at approximately 10–15 fps;
- [ ] 1080p/15 fps;
- [ ] camera-native compressed format vs re-encode path;
- [ ] hardware-accelerated encode path where available;
- [ ] LAN throughput;
- [ ] capture-node CPU/GPU/VRAM;
- [ ] main-host CPU/GPU/VRAM;
- [ ] dropped frames;
- [ ] recording quality;
- [ ] person/entrance detection quality.

Choose defaults from measurements, not assumptions.

## D. Source registry / mixed topology

Validate:

- [ ] 1 active source;
- [ ] 2 active sources;
- [ ] 3 active sources;
- [ ] 4 active sources;
- [ ] fifth activation rejected under default limit;
- [ ] mixed `local_uvc` + `remote_agent` works;
- [ ] source rename/role change works;
- [ ] detection profiles remain independent of source type;
- [ ] removing one source does not corrupt recordings/events for others.

## E. Server ROI / movement

Per configured server source:

- [ ] ROI/polygon placement works;
- [ ] reference/calibration saves and can be replaced;
- [ ] small lighting changes do not trigger movement;
- [ ] person standing in front of server does not immediately become movement;
- [ ] partial occlusion clears without false critical event;
- [ ] controlled displacement/rotation triggers event;
- [ ] camera movement is distinguished from server-only movement where practical;
- [ ] one event can link evidence from other active sources.

## F. Camera tamper and source health

- [ ] move/rotate camera mount;
- [ ] cover/obstruct lens;
- [ ] disconnect USB;
- [ ] reconnect USB;
- [ ] interrupt agent process/network for remote source;
- [ ] meaningful health/tamper changes are visible/audited;
- [ ] trivial vibration does not flood critical alerts;
- [ ] known loss is never shown as healthy.

## G. Network interruption / backpressure

Remote-agent scenarios:

- [ ] LAN off ~10 seconds;
- [ ] LAN off ~2 minutes;
- [ ] switch/AP/network restart if safe;
- [ ] main ServerSentinel service restart;
- [ ] capture-node restart;
- [ ] bandwidth throttling/backpressure test in a controlled environment.

Record:

- state transition;
- reconnect time;
- recording gaps;
- duplicate/missing media;
- queue/memory growth;
- audit event;
- manual-intervention requirement if automatic recovery is unsafe.

Agent-local outage buffer behavior remains pending until that feature is explicitly designed; do not claim gap recovery that has not been implemented.

## H. Clock synchronization

- [ ] main/capture node normally synchronize through NTP/chrony or equivalent;
- [ ] measured offset is visible/diagnosable;
- [ ] controlled excessive skew causes degraded state/warning;
- [ ] timeline does not silently present unreliable remote timestamps as exact;
- [ ] recovery clears degraded state appropriately.

## I. Live view from phone and Mac

Local/private path:

- [ ] phone browser can open live dashboard when authorized;
- [ ] Mac browser can open live dashboard when authorized;
- [ ] 1-source layout usable;
- [ ] 2-source layout usable;
- [ ] 3–4 source grid usable where applicable;
- [ ] source/node health visible;
- [ ] selected camera expands cleanly;
- [ ] live start time measured;
- [ ] latency measured;
- [ ] reconnect works;
- [ ] adaptive quality works;
- [ ] one bad source does not hide health of others.

Demand-driven processing:

- [ ] no-viewer state does not perform unnecessary viewer-only transcoding;
- [ ] first viewer starts needed packaging/transcoding;
- [ ] multiple viewers remain bounded;
- [ ] viewer disconnect returns resources toward idle state.

## J. Tailscale / invitation visibility and authorization

Use test identities/accounts appropriate for the deployment.

### Uninvited ordinary Tailnet member

- [ ] no Tailscale Grant to the ServerSentinel node;
- [ ] cannot establish dashboard connection;
- [ ] where Tailscale peer-map trimming applies, ServerSentinel node is not normally visible in ordinary peer/status view;
- [ ] no camera names/counts/metadata leak through errors or alternate endpoints.

Do **not** claim invisibility from Tailnet Owners/Admins or infrastructure administrators.

### Invited user with `live:view` only

- [ ] can view current live streams;
- [ ] cannot list/play recordings;
- [ ] cannot access privileged settings;
- [ ] historical timeline is not exposed implicitly while timeline permission policy remains undecided.

### Invited user with `recordings:view` only

- [ ] can list/play recordings in browser if network/application authorization passes;
- [ ] does not gain live view unless separately granted;
- [ ] no official recording download/export control is present;
- [ ] playback URL copied to an unauthorized identity does not work.

### User with both

- [ ] live and browser playback both work;
- [ ] cannot manage cameras/users/settings unless owner.

### Revocation

- [ ] app permission revoke blocks subsequent requests promptly;
- [ ] Tailnet Grant removal blocks network path independently;
- [ ] app invitation without Tailnet permission is insufficient;
- [ ] Tailnet permission without app invitation is insufficient.

## K. Manual/event recording

- [ ] manual recording start/stop;
- [ ] 20-minute maximum enforced;
- [ ] event recording includes configured 30 s pre / 120 s post when resource conditions permit;
- [ ] one event can contain multiple source recordings;
- [ ] manifests use source IDs, not fixed role filenames;
- [ ] playback source labels are correct;
- [ ] compressed pre-roll strategy remains bounded;
- [ ] no unnecessary long decoded-frame RAM history.

## L. Low light / detector-specific quality gating

Progressively degrade lighting/blur/visibility.

- [ ] quality transitions `sufficient -> degraded -> insufficient` appropriately;
- [ ] live/recording may continue when frames still exist;
- [ ] owner verification becomes `unknown/unavailable` before unreliable identity result;
- [ ] **person detection also becomes unknown/unavailable when its own quality prerequisites fail**;
- [ ] insufficient person quality is never displayed/stored as trustworthy `no person`;
- [ ] entrance/presence logic does not infer absence from skipped person inference;
- [ ] recovery uses suitable hysteresis;
- [ ] no automatic torch/light behavior exists.

## M. Video-only behavior

- [ ] camera microphone is not opened by local path unless a future approved feature changes requirements;
- [ ] `media-capture-agent` does not request/open microphone devices;
- [ ] browser live playback contains no audio track in MVP;
- [ ] recordings contain no monitoring audio in MVP.

## N. Owner-only face verification

Use only the deployment owner's own enrollment during manual testing. Never upload enrollment/reference images or real-person result clips to GitHub.

- [ ] explicit biometric explanation;
- [ ] owner enroll/delete/re-enroll;
- [ ] poor enrollment image rejected/retried;
- [ ] template remains local and absent from logs/normal diagnostics;
- [ ] normal frontal/angle/distance variations tested;
- [ ] low-light/blur/partial occlusion tested;
- [ ] result includes quality/confidence;
- [ ] ambiguous input becomes `unknown`;
- [ ] no named non-owner enrollment feature exists.

## O. Entrance / anonymous tracking / presence

Where room geometry supports entrance logic:

- [ ] owner entry/exit;
- [ ] anonymous person entry/exit;
- [ ] multiple people close together;
- [ ] partial occlusion;
- [ ] reversal/loiter near line does not spam events;
- [ ] unknown people receive no real names;
- [ ] no cross-camera biometric re-identification claim;
- [ ] manual presence override wins;
- [ ] ambiguous/low-quality owner observation does not force presence;
- [ ] only `PRESENT` suppresses ordinary occupancy automation by default;
- [ ] server movement/camera tamper remain armed.

## P. Unified security timeline

Create a controlled scenario such as:

```text
Owner exits
Anonymous person enters
Server movement occurs
Camera disconnects
Anonymous person exits
```

- [ ] timestamps ordered correctly across local/remote sources;
- [ ] source attribution correct;
- [ ] linked recordings correct;
- [ ] confidence/quality shown where applicable;
- [ ] offline/gap states visible;
- [ ] system never labels the person culprit/thief/attacker.

## Q. Storage pressure / hard stop

Use a disposable/test volume.

- [ ] retention deletes expired unstarred data;
- [ ] allocation/free-space pressure reclaims oldest eligible unstarred data;
- [ ] unrelated filesystem consumption affects admission;
- [ ] starred data not auto-deleted;
- [ ] `STORAGE_PRESSURE` suppresses specified ordinary/manual admission;
- [ ] bounded critical allowance never crosses hard reserve;
- [ ] `STORAGE_HARD_STOP` occurs before unsafe write;
- [ ] warnings/audit visible;
- [ ] recovery uses hysteresis.

Never intentionally fill a production filesystem to zero free bytes.

## R. Long-duration / performance

Run at least:

- [ ] 1 hour;
- [ ] 8 hours;
- [ ] 24 hours.

Record:

- source types/count;
- capture/record/view resolution/FPS/bitrate;
- detector inference cadence;
- main CPU/GPU/VRAM/memory;
- capture-node CPU/GPU/VRAM/memory;
- disk write rate;
- USB topology/bandwidth;
- LAN throughput;
- live-view latency;
- disconnect/reconnect count;
- dropped frames;
- service crashes;
- false health states.

Include a four-active-source run where hardware permits. Final defaults come from these measurements.
