# Camera Sources

Owns the shared Camera Source abstraction: `registry/` holds logical sources/nodes, `uvc/` adapts Main Server local UVC, and `remote_agent/` adapts approved remote capture nodes.

Supports 1–4 active sources with independent type, role, and detection profiles. Do not encode fixed front/rear slots, require browser/iPhone capture, or conflate capture-node health with camera health.
