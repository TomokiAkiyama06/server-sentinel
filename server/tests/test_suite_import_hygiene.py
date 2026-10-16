"""Issue #284: importing a test module leaves ``sys.path`` as it found it.

Discovery imports every test module before the first test runs, so a module
that changes ``sys.path`` at import time changes it for every test in the
process, including the processes those tests spawn: the isolated detector
worker receives the parent's ``sys.path`` and imports its factory by module
name. With the agent tree (which has its own ``tests`` package) first on the
path, a ``tests.*`` factory could not be imported and every worker start
failed under ``discover -t .``. A module that needs an extra path adds it in
``setUpModule`` and removes it in a module cleanup.
"""

import json
from pathlib import Path
import subprocess
import sys
import unittest

SERVER = Path(__file__).resolve().parents[1]

_SCRIPT = r"""
import importlib, json, pathlib, sys
server = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(server))
before = list(sys.path)
changed = []
for name in sorted(path.stem for path in (server / "tests").glob("test_*.py")):
    importlib.import_module("tests." + name)
    if sys.path != before:
        changed.append([name, [entry for entry in sys.path if entry not in before]])
        sys.path[:] = before
print(json.dumps(changed))
"""


class TestModuleImportHygieneTests(unittest.TestCase):
    def test_importing_test_modules_does_not_change_sys_path(self):
        # A fresh interpreter: this process's path already reflects discovery.
        result = subprocess.run([sys.executable, "-c", _SCRIPT, str(SERVER)],
                                cwd=SERVER, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1]), [])


if __name__ == "__main__":
    unittest.main()
