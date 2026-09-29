# End-to-End Tests

Owns mock/virtual-source workflows across Main Server, capture agent, and browser UI: setup, invitations, 1–4 sources, viewing, recording/timeline permissions, interruption, protected incidents, and visible integrity/storage failures.

Use synthetic/generated inputs and isolated runtime state. Do not claim real UVC, LAN, GPU, or phone/Mac acceptance from mock E2E; those checks belong in `MANUAL_TEST.md`. No real media or deployment credentials may enter CI artifacts.

`harness.py` owns deterministic wall/monotonic clocks, a bounded 1–4 source
mixed topology, and finite named faults. `test_mock_core_harness.py` uses those
ports to drive the production ring-buffer, hardware-integrity,
recording-health, and presence/timeline cores. Run the focused suite from the
repository root with:

```bash
PYTHONPATH=server:agent:. python3 -m unittest tests.e2e.test_mock_core_harness
```

Scenario modules added for Issue #27 reuse the same ports plus a synthetic
filesystem quota (`SyntheticQuota`) and an outbound network guard
(`NetworkGuard`) that refuses and records every socket connect/send and name
lookup from any thread:

- `test_agent_ring_scenarios.py` — duration and capacity ring modes, T-10 pin
  and autonomous T+10 continuation across reconnect/restart, partial/gap
  reporting, critical preserve, Owner delete, 60-day expiry, and simultaneous
  T-10/T+10 budget admission (exact boundaries, including existing protected
  usage that is never credited as reclaimable, and concurrent preserve
  requests) without double counting shared segments;
- `test_agent_storage_scenarios.py` — media-root mount loss, mount/device
  identity substitution and directory/symlink replacement never fall back to
  another directory, ordinary data is reclaimed before any protected incident,
  the required T-10 pre-loss window is never reclaimed under pressure (duration
  and capacity modes), and writes stop before the hard reserve;
- `test_retention_scenarios.py` — Main 20-day recordings, 90-day audit and Agent
  60-day incidents on independent clocks, starred recordings never reclaimed,
  and `STORAGE_PRESSURE` / `STORAGE_HARD_STOP`;
- `test_notification_fault_scenarios.py` — Slack unset or failing keeps the
  local Dashboard/Audit fault and never reports delivery;
- `test_no_telemetry_scenarios.py` — normal and error paths make no outbound
  connection; only an explicitly configured Slack endpoint is ever attempted.

These pass with generated placeholder bytes and synthetic mounts/quotas only;
they are not hardware, real-filesystem-substitution or network acceptance.

```bash
PYTHONPATH=server:agent:. python3 -m unittest \
  tests.e2e.test_agent_ring_scenarios tests.e2e.test_agent_storage_scenarios \
  tests.e2e.test_retention_scenarios tests.e2e.test_notification_fault_scenarios \
  tests.e2e.test_no_telemetry_scenarios
```
