# Dashboard and Live View

Owns responsive 1–4-source live layouts and authorized current source/capture-node, quality, and degraded-health displays from the Main Server.

`live.tsx` / `live_loop.ts` implement the interim frame-pull live screen (#205 CP-5, see `web/README.md`).

Keep type and role independent; never hard-code front/rear cameras, connect to agents directly, expose historical timeline data to `live:view` alone, or represent unavailable person inference as `no person`.
