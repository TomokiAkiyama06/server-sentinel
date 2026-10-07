"""Required CI wiring regressions."""

from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
