"""Static checks of the Issue #126 socket-owner helper systemd units.

These only read the shipped unit files; whether systemd accepts them and the
helper works under them on the Main Server is a MANUAL_TEST.md step.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "infra" / "systemd"
CLIENT = ROOT / "server" / "app" / "auth" / "socket_owner.py"


def directives(path: Path) -> dict:
    values: dict[str, list[str]] = {}
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        if not separator or section is None:
            raise AssertionError(f"unparsed unit line in {path.name}")
        values.setdefault(f"{section}.{key}", []).append(value)
    return values


class SocketOwnerUnitTests(unittest.TestCase):
    def setUp(self):
        self.service = directives(SYSTEMD / "server-sentinel-socket-owner.service")
        self.socket = directives(SYSTEMD / "server-sentinel-socket-owner.socket")

    def one(self, values, key):
        self.assertIn(key, values)
        self.assertEqual(len(values[key]), 1, key)
        return values[key][0]

    def test_socket_is_root_owned_group_restricted_and_matches_the_client(self):
        path = self.one(self.socket, "Socket.ListenStream")
        default = re.search(r'^DEFAULT_SOCKET = "([^"]+)"$', CLIENT.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(default)
        self.assertEqual(path, default.group(1))
        self.assertEqual(self.one(self.socket, "Socket.SocketUser"), "root")
        self.assertEqual(self.one(self.socket, "Socket.SocketGroup"), "server-sentinel-socket-owner")
        self.assertEqual(self.one(self.socket, "Socket.SocketMode"), "0660")
        self.assertEqual(self.one(self.socket, "Socket.DirectoryMode"), "0755")
        self.assertEqual(self.one(self.socket, "Socket.Accept"), "no")

    def test_service_holds_only_the_two_capabilities_without_root(self):
        self.assertEqual(self.one(self.service, "Service.DynamicUser"), "yes")
        for key in ("Service.CapabilityBoundingSet", "Service.AmbientCapabilities"):
            self.assertEqual(set(self.one(self.service, key).split()), {"CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"})
        self.assertNotIn("Service.User", self.service)
        self.assertEqual(self.one(self.service, "Service.NoNewPrivileges"), "yes")
        self.assertEqual(self.one(self.service, "Service.ProtectSystem"), "strict")
        self.assertEqual(self.one(self.service, "Service.PrivateNetwork"), "yes")
        self.assertEqual(self.one(self.service, "Service.RestrictAddressFamilies"), "AF_UNIX")

    def test_ptrace_and_handle_open_system_calls_are_filtered(self):
        filters = " ".join(self.service["Service.SystemCallFilter"])
        denied = [entry for value in self.service["Service.SystemCallFilter"] if value.startswith("~")
                  for entry in value[1:].split()]
        self.assertIn("@debug", denied)  # ptrace, process_vm_readv/writev
        self.assertIn("@privileged", denied)  # open_by_handle_at
        self.assertIn("@system-service", filters)

    def test_nothing_hides_or_namespaces_host_processes(self):
        # Hidden processes make every scan incomplete; a user namespace voids the capabilities.
        self.assertNotIn("Service.PrivateUsers", self.service)
        self.assertNotIn("Service.PrivatePIDs", self.service)
        self.assertNotEqual(self.service.get("Service.ProtectProc", ["default"]), ["invisible"])
        self.assertNotEqual(self.service.get("Service.ProtectProc", ["default"]), ["noaccess"])

    def test_helper_runs_the_current_release_and_follows_its_restarts(self):
        command = self.one(self.service, "Service.ExecStart").split()
        self.assertEqual(command[1:6], ["-E", "-s", "-B", "-m", "app.auth.socket_owner"])
        self.assertIn("--config", command)
        self.assertEqual(self.one(self.service, "Unit.PartOf"), "server-sentinel.service")
        self.assertEqual(self.one(self.service, "Unit.Requires"), "server-sentinel-socket-owner.socket")
        # Started by socket activation only.
        self.assertFalse(any(key.startswith("Install.") for key in self.service))


if __name__ == "__main__":
    unittest.main()
