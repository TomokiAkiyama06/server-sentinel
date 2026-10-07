"""The Main and the Agent refuse the same Tailscale ranges (Issue #150).

The Agent is a separate stdlib-only package and cannot import the server, so
both carry a copy of ``TAILSCALE_NETWORKS``. Each module is loaded from its
file (stdlib ``ipaddress`` only), without importing either package.
"""

import importlib.util
import ipaddress
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / "server" / "app" / "cameras" / "remote_agent" / "addresses.py"
AGENT = ROOT / "agent" / "media_capture_agent" / "addresses.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TailscaleRangeParityTests(unittest.TestCase):
    def test_main_and_agent_ranges_are_identical_and_documented(self):
        main = load(MAIN, "_main_addresses")
        agent = load(AGENT, "_agent_addresses")
        expected = (ipaddress.ip_network("100.64.0.0/10"),
                    ipaddress.ip_network("fd7a:115c:a1e0::/48"))
        self.assertEqual(expected, tuple(main.TAILSCALE_NETWORKS))
        self.assertEqual(expected, tuple(agent.TAILSCALE_NETWORKS))
        for value in ("100.64.0.0", "100.127.255.255", "fd7a:115c:a1e0::1",
                      "::ffff:100.100.100.100", "100.63.255.255", "fd7a:115c:a1e1::",
                      "192.168.1.10"):
            address = ipaddress.ip_address(value)
            with self.subTest(value):
                self.assertEqual(main.is_tailscale_address(address),
                                 agent.is_tailscale_address(address))


if __name__ == "__main__":
    unittest.main()
