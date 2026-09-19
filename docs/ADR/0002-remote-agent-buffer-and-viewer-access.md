# ADR 0002: Remote Capture Buffer / Viewer Access Decisions

Status: Accepted
Date: 2026-09-18

## Context

ServerSentinel MVP uses `local_uvc` camera sources on the main Ubuntu host and `remote_agent` camera sources provided by a separate Linux capture machine running `media-capture-agent` over the same private LAN. Human clients use the main ServerSentinel web UI from phone/Mac/desktop browsers.

The exact media transport and camera profile cannot be finalized until the real deployment is moved into the lab and the room-overview camera model/capabilities are measured. This ADR fixes the product behavior that does not depend on those measurements.

## Decisions

### 1. Live viewing favors stability while remaining real-time

The browser live view is intended to feel real-time, but transport selection MUST prioritize stable playback, reconnect behavior, bounded buffering, and truthful degraded-state reporting over chasing the minimum possible latency.

No fixed sub-second latency promise is made before the transport PoC. The target latency is measured after the real LAN/camera environment is available.

### 2. `media-capture-agent` uses a configurable disk recovery ring buffer

The agent keeps compressed media in a bounded disk-backed ring buffer. It MUST NOT retain a long history of decoded RGB frames for this purpose.

The owner chooses one of two ring-buffer configuration modes from ServerSentinel:

- **duration mode** — set the target retained time and show projected/actual disk use;
- **capacity mode** — set the maximum ring-buffer disk capacity and show estimated effective duration.

Both modes remain subject to filesystem safety reserve. The UI shows current use, configured limit, free space, protected-incident usage, and warnings. Reject configurations determinably unable to preserve the 10-minute pre-loss target under the bounded/negotiated media profile. If runtime uncertainty or later deterioration shortens the effective window, report degraded protection and actual coverage rather than claiming a complete window.

The buffer is recovery/incident storage, not the authoritative long-term recording store. Main ServerSentinel remains authoritative for ordinary durable recordings.

### 3. Critical incident preservation window

When the main host confirms a critical server-movement/camera-tamper incident and connectivity still exists, it requests the relevant capture agent to pin an incident clip from its ring buffer.

For a sudden loss of main-host communication, the capture agent also performs autonomous temporary preservation. The default incident window is:

- **10 minutes immediately before communication loss**; and
- **10 minutes after communication loss**.

This produces a default 20-minute evidence window around the connectivity-loss boundary. The pre-loss portion is taken from the existing ring buffer. The post-loss portion continues locally even though the main host is unreachable.

A protected incident MUST be excluded from ordinary ring overwrite and is retained on the capture agent for **60 days from completion by default**, then automatically deleted. Owner-authorized manual deletion may remove it earlier. If disk pressure occurs before expiry, reclaim ordinary ring-buffer data first and surface explicit storage pressure rather than silently deleting unexpired protected evidence.

### 4. Human-access authorization does not require changing Tailscale Grants

ServerSentinel MVP MUST NOT require automatic or routine mutation of the owner's Tailscale Grants/ACL policy.

Tailscale provides private-network reachability. ServerSentinel performs its own owner-managed invitation/allowlist and application authorization before returning dashboard or media information.

At minimum, invited-user permissions remain independent:

- `live:view` — current live video and current source/health state;
- `recordings:view` — recording list/playback **and historical event/timeline access**.

Non-owner recording access is browser playback only in the official MVP UI/API; no official download/export route is provided. This is not DRM and does not claim to prevent screen recording or advanced client-side capture.

Because Tailscale policy is not required to be narrowed, ServerSentinel MUST NOT promise that uninvited Tailnet members cannot discover the underlying Tailscale machine or detect that a network service exists. It MUST, however, fail closed at the application boundary and use generic/non-branding denial where practical, disclosing no ServerSentinel product/version, API schema, deployment metadata, camera names/counts, thumbnails, live media, recordings, or timeline data to an uninvited identity.

Deployments that require network-level peer concealment may optionally tighten Tailscale Grants/ACLs outside ServerSentinel; that is an optional hardening step, not an MVP prerequisite.

### 5. Timeline permission follows recording permission

A separate `timeline:view` permission is not introduced for MVP. Historical timeline/event metadata is included with `recordings:view`. A principal with only `live:view` receives current live/source state but not historical recordings or historical timeline/event metadata.

### 6. Browser/iPhone camera source removed from current product scope

Browser/iPhone camera capture is outside the current ServerSentinel product scope. Phone/Mac/desktop browsers are human viewing clients. Any future reintroduction would be a new explicit product decision/ADR, not a deferred MVP obligation.

### 7. Off-host evidence is incident-focused, not full replication

ServerSentinel does not require continuous replication of all main-host recordings to another machine.

The remote capture machine's disk ring buffer and critical/sudden-disconnect incident preservation are the MVP off-host evidence mechanism. This is intended to preserve useful room-overview evidence if the main server is moved, disconnected, or taken offline while the capture machine remains available.

## Deferred until real hardware/LAN is available

The following remain measurement-driven decisions:

- exact `media-capture-agent` -> main-host transport and reconnect protocol;
- exact main-host -> browser live transport and measured target latency;
- room-overview camera model/capabilities;
- capture/record/inference/view resolution, FPS, codec, and bitrate defaults;
- final owner face-verification model, weights, licensing, threshold, and measured quality.

## Security and privacy notes

`media-capture-agent` continues to run as a truthful background service name, uses video only in MVP, and does not acquire human dashboard/admin rights. Agent-to-main traffic requires authenticated encryption. The local incident buffer is bounded and contains monitoring media, so its filesystem permissions and cleanup behavior must be treated as security-sensitive.