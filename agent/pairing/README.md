# Agent Pairing

Owns short-lived, one-time owner-approved pairing and the agent's revocable mutually authenticated encrypted identity lifecycle, with mTLS as the design target.

Keep credentials deployment-local and out of logs/source control. Node identity grants only capture protocol actions, never human/admin rights. Do not require or retain Tailscale administrative credentials.

The stdlib-only foundation in `media_capture_agent.pairing` provides the
non-echoing controlling-terminal code boundary and atomic, write-once private
credential storage required by ADR-0006. It does not generate keys, parse or
sign certificates, open a listener, or send enrollment traffic. Those adapters
remain disabled until their dependency/license and authorization boundaries are
implemented and tested.
