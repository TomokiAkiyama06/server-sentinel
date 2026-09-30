# Manual hardware-test helpers

Helpers for `MANUAL_TEST.md` steps that need a person at real hardware. They are
not part of the product, CI or any release artifact, and must never be pointed at
a production runtime root.

- `uvc_watch.py` — prints per-second health/fps/descriptor counts for two local
  UVC sources while cameras are unplugged, moved between ports or covered
  (`MANUAL_TEST.md` section A). Frames are counted and discarded; state lives in
  a throwaway directory outside the repository.
