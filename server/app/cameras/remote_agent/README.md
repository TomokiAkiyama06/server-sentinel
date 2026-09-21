# Remote Agent Adapter

Owns the Main Server side of capture-node registration, owner-approved pairing/revocation, authenticated LAN ingest, source/session validation, and separate node/camera health reporting.

Accept only narrow agent actions with bounded input. Agent credentials grant no human/admin API rights; the ingest listener exposes no dashboard routes. Do not require SSH access to capture nodes, change Tailscale policy, or route browser viewers directly to agents.

## Transport-neutral bounded ingest core

`ingest.py` is the in-process admission boundary used after a future dedicated
LAN listener has authenticated an Agent session. It exposes only typed
`heartbeat` and opaque `media` actions, requires injected node/source checks,
and defaults to rejection. Explicit deployment limits bound every queued
message, total queued bytes, and per-node message rate. Refusals report
`unauthorized`, size, rate, clock, or queue pressure without evicting accepted
messages or claiming camera/node health.

It opens no listener, parses no media/container, selects no transport, and
implements neither pairing nor mTLS. The eventual listener must independently
limit bytes before constructing an `AgentMessage`, remain separate from human
routes, and provide the revocable authenticated session required by Issue #13.
