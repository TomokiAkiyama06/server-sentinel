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
lookup (`getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`,
`getnameinfo` in both `socket` and `_socket`) from any thread. A process-wide
`sys.addaudithook` backstop refuses the CPython `socket.connect` / `sendto` /
`sendmsg` / resolver audit events, so direct `_socket.socket` use or a resolver
alias captured before the guard started is refused and recorded too. Because
`send`/`sendall` raise no audit event, entering the guard fails closed (recorded
as `preconnected`) when a non-AF_UNIX socket is already connected. Module-scope
imports run before any guard exists, so `test_no_telemetry_scenarios.py` also
replays every scenario module (and the production modules they load) in a fresh
interpreter whose first statement installs a refusing, recording audit hook;
an import-time connect that already closed is caught there. The same replay
imports the Agent CLI/runtime and Main launcher and runs their startup
validation and error paths (`media_capture_agent.cli.main`,
`app.deployment.main`); the report is written from an exit callback registered
before any import, so import-registered shutdown flushes run under the hook
first. The protected synthetic Agent configuration must pass `--check`
(exit 0) with only the `/dev/disk/by-uuid` stable-device lookup made synthetic
(the ephemeral filesystem has no Owner-approved UUID); the same configuration
with the real lookup, and the missing-configuration calls, must fail closed
(exit 1). The Main
web entry points (`app.main`, `app.__main__`) need FastAPI: the required CI job
installs the hash-pinned `server/requirements.lock`, verifies the resolved pins
with `license_gate.py`, and sets `E2E_REQUIRE_FULL_COVERAGE=1`, so there
they are checked fully (including the `app.__main__.main` startup error path)
and a missing web stack or a root (UID 0) run fails instead of being skipped.
Local runs without those dependencies check the web entry points only up to the
missing dependency. Because the Agent refuses UID 0 by design, every Agent
fixture (`agent_configuration()` / `agent_settings()`) skips a local root run
with an explicit reason and fails it where `E2E_REQUIRE_FULL_COVERAGE=1`. In-process services are closed while the guard is
still active, so shutdown flushes in `close()` are covered. Egress from
child processes or native code that bypasses CPython's `_socket` is outside
this in-process guard:

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
