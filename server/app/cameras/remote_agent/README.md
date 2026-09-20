# Remote Agent Adapter

Owns the Main Server side of capture-node registration, owner-approved pairing/revocation, authenticated LAN ingest, source/session validation, and separate node/camera health reporting.

Accept only narrow agent actions with bounded input. Agent credentials grant no human/admin API rights; the ingest listener exposes no dashboard routes. Do not require SSH access to capture nodes, change Tailscale policy, or route browser viewers directly to agents.
