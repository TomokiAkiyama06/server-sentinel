"""Required CI wiring regressions."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CIWorkflowTests(unittest.TestCase):
    def test_mock_e2e_suite_runs_in_required_repository_job(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        repository, separator, _remaining = workflow.partition("\n  components:\n")
        self.assertTrue(separator, "components job boundary is missing")
        self.assertIn("PYTHONPATH: server:agent:.", repository)
        self.assertIn(
            "run: python -m unittest tests.e2e.test_mock_core_harness -v",
            repository,
        )
        for module in (
            "tests.e2e.test_agent_ring_scenarios",
            "tests.e2e.test_agent_storage_scenarios",
            "tests.e2e.test_retention_scenarios",
            "tests.e2e.test_notification_fault_scenarios",
            "tests.e2e.test_access_matrix_scenarios",
            "tests.e2e.test_pairing_scenarios",
            "tests.e2e.test_detection_isolation_scenarios",
            "tests.e2e.test_no_telemetry_scenarios",
            "tests.e2e.test_capture_mtls_scenarios",
            "tests.e2e.test_capture_enrollment_scenarios",
        ):
            self.assertIn(f"\n          {module}\n", repository)
            self.assertTrue((ROOT / (module.replace(".", "/") + ".py")).is_file(), module)

    def test_guarded_entry_points_run_with_main_runtime_in_required_job(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        repository, separator, _remaining = workflow.partition("\n  components:\n")
        self.assertTrue(separator, "components job boundary is missing")
        install = repository.find(
            "python -m pip install --require-hashes --only-binary=:all: --no-cache-dir \\\n"
            "            --report \"${RUNNER_TEMP}/server-runtime-report.json\""
            " -r server/requirements.lock\n")
        verify = repository.find(
            "--resolved-python \"${RUNNER_TEMP}/server-runtime-report.json\" \\\n"
            "            --input server/requirements.lock\n")
        telemetry = repository.find("\n          tests.e2e.test_no_telemetry_scenarios\n")
        self.assertNotEqual(-1, install, "server runtime lock is not installed")
        self.assertNotEqual(-1, verify, "server runtime pins are not verified")
        self.assertNotEqual(-1, telemetry)
        self.assertLess(install, verify)
        self.assertLess(verify, telemetry)
        # Both E2E steps must forbid skipping any scenario path (missing web
        # stack, root run) and run after the runtime install.
        core = repository.find("run: python -m unittest tests.e2e.test_mock_core_harness -v")
        self.assertLess(verify, core)
        for anchor in (core, telemetry):
            step = repository[repository.rfind("\n      - name:", 0, anchor):anchor]
            self.assertIn("\n          E2E_REQUIRE_FULL_COVERAGE: '1'\n", step)
        harness = (ROOT / "tests/e2e/harness.py").read_text(encoding="utf-8")
        self.assertIn('REQUIRE_FULL_COVERAGE = "E2E_REQUIRE_FULL_COVERAGE"\n', harness)

    def test_two_account_separation_runs_as_root_and_cannot_skip(self):
        # Issue #109: the real account drops are only exercised as root.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        repository, separator, _remaining = workflow.partition("\n  components:\n")
        self.assertTrue(separator, "components job boundary is missing")
        runtime = repository.find("--input server/requirements.lock\n")
        step = repository.find("- name: Two-account CA key separation as root (Issue #109)")
        self.assertNotEqual(-1, runtime)
        self.assertNotEqual(-1, step)
        self.assertLess(runtime, step)
        body = repository[step:repository.find("\n      - name:", step + 1)]
        self.assertIn("sudo -n env PYTHONDONTWRITEBYTECODE=1 CA_SEPARATION_REQUIRE_ROOT=1", body)
        self.assertIn("-m unittest -v tests.test_ca_privilege_separation_root", body)
        test = (ROOT / "server/tests/test_ca_privilege_separation_root.py").read_text(
            encoding="utf-8")
        self.assertIn('REQUIRE_ROOT = "CA_SEPARATION_REQUIRE_ROOT"', test)

    def test_agent_ring_ledger_runs_against_debian_12_sqlite(self):
        # Issue #191: SQLite 3.40.x is covered by the pinned Debian 12 image,
        # and the job fails rather than silently testing another version.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        start = workflow.find("\n  agent-ring-sqlite-340:\n")
        self.assertNotEqual(-1, start, "Debian 12 SQLite job is missing")
        end = workflow.find("\n  web-browser:\n", start)
        self.assertNotEqual(-1, end)
        job = workflow[start:end]
        self.assertIn("docker build --file agent/Dockerfile.ci --tag agent-sqlite-340 agent", job)
        self.assertIn('sqlite3.sqlite_version.startswith("3.40.")', job)
        self.assertIn("--network=none agent-sqlite-340", job)
        self.assertIn("python -m unittest -v tests.test_ring\n", job)
        dockerfile = (ROOT / "agent/Dockerfile.ci").read_text(encoding="utf-8")
        self.assertRegex(dockerfile, r"^FROM python:[0-9.]+-slim-bookworm@sha256:[0-9a-f]{64}\n")

    def test_aggregate_ci_gate_requires_every_other_job_to_succeed(self):
        # The ruleset requires only the terminal `CI` check, so every other job
        # must be in its `needs` and asserted as `success`; otherwise a failing
        # job could not block the merge (PR #202 review).
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        _head, separator, jobs_text = workflow.partition("\njobs:\n")
        self.assertTrue(separator, "jobs section is missing")
        headers = list(re.finditer(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs_text, re.MULTILINE))
        jobs = {}
        for index, header in enumerate(headers):
            end = headers[index + 1].start() if index + 1 < len(headers) else len(jobs_text)
            self.assertNotIn(header.group(1), jobs, f"duplicate job {header.group(1)}")
            jobs[header.group(1)] = jobs_text[header.start():end]
        self.assertIn("ci", jobs, "aggregate ci job is missing")
        gate = jobs.pop("ci")
        self.assertGreaterEqual(len(jobs), 4, f"job parsing looks wrong: {sorted(jobs)}")
        self.assertIn("\n    name: CI\n", gate)
        self.assertIn("\n    if: ${{ always() }}\n", gate)
        needs = re.search(r"^    needs: \[([^\]]*)\]$", gate, re.MULTILINE)
        self.assertIsNotNone(needs, "aggregate ci job must list needs inline")
        needed = [item.strip() for item in needs.group(1).split(",") if item.strip()]
        self.assertEqual(sorted(jobs), sorted(needed))
        self.assertEqual(len(needed), len(set(needed)))
        results = dict(
            (match.group(2), match.group(1))
            for match in re.finditer(
                r"^          ([A-Z0-9_]+): \$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}$",
                gate, re.MULTILINE))
        self.assertEqual(sorted(jobs), sorted(results))
        asserted = re.findall(r'^          test "\$([A-Z0-9_]+)" = success$', gate, re.MULTILINE)
        self.assertEqual(sorted(results.values()), sorted(asserted))
        # No other comparison (e.g. accepting `skipped`) may weaken the gate.
        self.assertEqual(len(asserted), gate.count("\n          test "))
        self.assertNotIn("skipped", gate)
        self.assertNotIn("continue-on-error", workflow)


if __name__ == "__main__":
    unittest.main()
