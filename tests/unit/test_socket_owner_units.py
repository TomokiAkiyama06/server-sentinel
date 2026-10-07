"""Static checks of the Issue #126 socket-owner helper systemd units.

These only read the shipped unit files; whether systemd accepts them and the
helper works under them on the Main Server is a MANUAL_TEST.md step.
"""

from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "infra" / "systemd"
CLIENT = ROOT / "server" / "app" / "auth" / "socket_owner.py"
# System calls that turn CAP_SYS_PTRACE (or CAP_DAC_READ_SEARCH) into access to
# another process's memory or descriptors, or to an arbitrary inode. They must
# be denied by name: process_vm_readv/writev and process_madvise sit in @ipc
# and kcmp in @system-service itself, not in @debug.
CROSS_PROCESS_SYSCALLS = frozenset({
    "ptrace", "pidfd_getfd", "process_vm_readv", "process_vm_writev", "process_madvise", "kcmp",
    "open_by_handle_at",
})
# Trees that may hold data and are replaced by an empty read-only tmpfs.
MASKED_TREES = frozenset({"/etc", "/var", "/srv", "/mnt", "/media", "/opt", "/run"})


def expand_syscall_group(name: str, cache: dict) -> set:
    """System calls of a systemd group, expanded by the local systemd-analyze."""
    if not name.startswith("@"):
        return {name}
    if name not in cache:
        cache[name] = set()  # guards against a self-reference
        output = subprocess.run(["systemd-analyze", "--no-pager", "syscall-filter", name],
                                check=True, capture_output=True, text=True, timeout=30).stdout
        result = set()
        for line in output.splitlines()[1:]:
            line = line.strip()
            if line and not line.startswith("#"):
                result |= expand_syscall_group(line.split()[0], cache)
        cache[name] = result
    return cache[name]


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
        self.assertIn("@debug", denied)  # ptrace, pidfd_getfd (not process_vm_*: see below)
        self.assertIn("@privileged", denied)  # open_by_handle_at
        self.assertIn("@system-service", filters)

    def test_cross_process_system_calls_are_denied_by_name(self):
        denied = {entry for value in self.service["Service.SystemCallFilter"] if value.startswith("~")
                  for entry in value[1:].split()}
        self.assertEqual(CROSS_PROCESS_SYSCALLS - denied, set())

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not available")
    def test_effective_system_call_set_excludes_cross_process_calls(self):
        # systemd semantics: the first allow-list sets the base and every later
        # "~" line removes its expanded entries.
        cache: dict = {}
        allowed: set = set()
        for value in self.service["Service.SystemCallFilter"]:
            deny = value.startswith("~")
            entries = set()
            for entry in (value[1:] if deny else value).split():
                entries |= expand_syscall_group(entry, cache)
            allowed = allowed - entries if deny else allowed | entries
        self.assertIn("read", allowed)  # the group expansion worked
        self.assertIn("openat", allowed)
        self.assertEqual(CROSS_PROCESS_SYSCALLS & allowed, set())

    def test_file_system_is_masked_except_what_the_helper_reads(self):
        temporary = {}
        for value in self.service.get("Service.TemporaryFileSystem", []):
            for entry in value.split():
                path, _, options = entry.partition(":")
                temporary[path] = options
        self.assertEqual(MASKED_TREES - set(temporary), set())
        for path in MASKED_TREES:
            self.assertEqual(temporary[path], "ro", path)
        self.assertEqual(self.one(self.service, "Service.ProtectHome"), "yes")
        inaccessible = {entry.lstrip("-") for value in self.service.get("Service.InaccessiblePaths", [])
                        for entry in value.split()}
        self.assertLessEqual({"/boot", "/efi"}, inaccessible)
        # Nothing is bound back writable; exactly the installation root, the
        # deployment configuration file and the linker cache come back read-only.
        self.assertNotIn("Service.BindPaths", self.service)
        bound = [entry for value in self.service.get("Service.BindReadOnlyPaths", []) for entry in value.split()]
        command = self.one(self.service, "Service.ExecStart").split()
        configuration = command[command.index("--config") + 1]
        working = self.one(self.service, "Service.WorkingDirectory")
        install_root = str(Path(working).parent)
        self.assertEqual(sorted(bound), sorted([install_root, configuration, "-/etc/ld.so.cache"]))
        self.assertTrue(command[0].startswith(install_root + "/"))
        # The deployment configuration directory is not exposed whole.
        self.assertNotIn(str(Path(configuration).parent), bound)

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


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


class UnverifiedOwnershipContractTests(unittest.TestCase):
    """REQUIREMENTS.md and SPECIFICATION.md follow the 2026-10-05 Owner decision:
    unverifiable ownership keeps access closed without revocation; only an
    observed other holder is an exposure."""

    STALE = (
        "another or unverifiable owner closes access as an exposure",
        "another or unverifiable owner is an exposure",
        "another or unverifiable holder is an exposure",
        "cannot be checked keeps access closed as an exposure",
        "unreadable own fd table keeps access closed as an exposure",
    )

    def test_contracts_drop_the_superseded_wording(self):
        for name in ("REQUIREMENTS.md", "SPECIFICATION.md"):
            text = normalized(ROOT / name)
            for phrase in self.STALE:
                self.assertFalse(phrase in text, f"{name}: {phrase}")

    REQUIRED = {
        "REQUIREMENTS.md": (
            "Ownership that cannot be verified",
            "is not an exposure: it keeps access closed without revocation",
            "seen holding the socket but whose executable or unit cannot be read",
            "The socket-owner resolver is mandatory",
        ),
        "SPECIFICATION.md": (
            "(`LISTENER_OWNER_UNVERIFIED`: no socket-owner resolver",
            "is not an exposure reason: it keeps access closed without revocation",
            "counts as another owner or holder",
            "a check without one never opens access",
        ),
    }

    def test_contracts_state_closed_without_revocation_and_a_mandatory_resolver(self):
        for name, phrases in self.REQUIRED.items():
            text = normalized(ROOT / name)
            for phrase in phrases:
                self.assertTrue(phrase in text, f"{name}: {phrase}")


if __name__ == "__main__":
    unittest.main()
