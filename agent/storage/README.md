# Agent Ring Buffer and Protected Incidents

Owns compressed-video disk segments, owner-selected duration/capacity limits, FIFO eviction of unprotected segments, and protected-incident metadata/lifecycle.

- Unexpected Main Server connection/heartbeat loss protects T-10 minutes and continues local capture through T+10 minutes; critical preserve commands complement this autonomous protection.
- Protected incidents expire 60 days after completion by default. Only explicit owner deletion may remove them earlier; reconnect or ordinary buffer pressure never silently deletes unexpired evidence.
- Reject configurations known to miss the 10-minute pre-loss target. Report actual gaps/degraded protection when runtime conditions prevent a complete window.
- At install/startup/runtime admission, validate the configurable media root, expected mount/filesystem/device, service-account writability, free space, and hard safety reserve. Reclaim eligible unprotected data first and refuse unsafe writes.
- Never silently create/use a root-filesystem fallback after media mount loss. Runtime `buffer/` and `incidents/` live outside the checkout; no deployment paths, real media, or credentials belong here.
