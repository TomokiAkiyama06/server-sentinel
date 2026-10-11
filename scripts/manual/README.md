# Manual hardware-test helpers

Helpers for `MANUAL_TEST.md` steps that need a person at real hardware. They are
not part of the product, CI or any release artifact, and must never be pointed at
a production runtime root.

- `uvc_watch.py` — prints per-second health/fps/negotiated-profile/descriptor
  counts for two local UVC sources while cameras are unplugged, moved between ports or covered
  (`MANUAL_TEST.md` section A). Frames are counted and discarded; state lives in
  a throwaway directory outside the repository. Every health transition is printed
  through the runtime health sink, so none is lost when the bounded
  recent-event buffer evicts entries during a long flapping run.
  The negotiated profile (`profile=WIDTHxHEIGHT@FPS/PIXEL_FORMAT`, `none` when the
  registry holds none, `?` for a field the driver did not report) comes from the
  registry row already read each second; it opens no extra device and never
  touches `/dev/snd` (`MANUAL_TEST.md` P-5, Issue #193).
- `transport_poc/` — Issue #15 Agent–Main media transport PoC measurement
  harness (`MANUAL_TEST.md` section G): disposable mTLS materials, a Main-side
  receiver on the product ingest admission/continuity/queue code, a
  capture-side sender, a loopback impairment proxy, a camera holder and a
  G1–G6 summarizer. Payloads are hashed and discarded; measurement output is
  numeric JSONL only. Runbook (Japanese): `transport_poc/README.md`.
