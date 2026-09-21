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


if __name__ == "__main__":
    unittest.main()
