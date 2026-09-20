"""Run reviewed local-only lint tools using the CI interpreter."""

import subprocess
import sys


for arguments in (("pyflakes", "app", "tests"),
                  ("pycodestyle", "--select=E4,E7,E9", "app", "tests")):
    subprocess.run([sys.executable, "-m", *arguments], check=True)
