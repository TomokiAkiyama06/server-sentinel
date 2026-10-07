"""Static checks of the Issue #126 listener-owner design (Owner decision, 2026-10-07).

They read shipped files only: the upstream socket unit, the authoritative
contracts and the deployment notes. Whether systemd accepts the unit and the
lookup works on the Main Server is a MANUAL_TEST.md step.
"""

import ipaddress
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOCKET_UNIT = ROOT / "infra" / "systemd" / "server-sentinel-upstream.socket"


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def directives(path: Path) -> dict:
    values: dict[str, list[str]] = {}
    section = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
            continue
        key, _, value = line.partition("=")
        values.setdefault(f"{section}{key.strip()}", []).append(value.strip())
    return values


class UpstreamSocketUnitTests(unittest.TestCase):
    def test_single_loopback_listener_on_a_privileged_port(self):
        values = directives(SOCKET_UNIT)
        listen = values.get("[Socket]ListenStream", [])
        self.assertEqual(len(listen), 1)
        host, _, port = listen[0].rpartition(":")
        self.assertTrue(ipaddress.ip_address(host.strip("[]")).is_loopback)
        # Below the default ip_unprivileged_port_start: no unprivileged bind.
        self.assertTrue(re.fullmatch(r"[0-9]+", port) and 0 < int(port) < 1024)

    def test_no_shared_port_and_passed_to_the_backend(self):
        values = directives(SOCKET_UNIT)
        self.assertEqual(values.get("[Socket]ReusePort"), ["no"])
        self.assertEqual(values.get("[Socket]Accept"), ["no"])
        self.assertEqual(values.get("[Socket]FreeBind"), ["no"])
        self.assertEqual(values.get("[Socket]Service"), ["server-sentinel.service"])
        self.assertEqual(values.get("[Install]WantedBy"), ["sockets.target"])
        for key in ("ListenDatagram", "ListenSequentialPacket", "ListenFIFO", "BindToDevice",
                    "SocketUser", "SocketGroup", "Transparent", "ExecStartPre", "ExecStartPost"):
            self.assertNotIn(f"[Socket]{key}", values)

    def test_the_privileged_helper_design_is_not_shipped(self):
        # Owner decision 2026-10-07: no helper, no CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH.
        self.assertFalse((ROOT / "server" / "app" / "auth" / "socket_owner.py").exists())
        self.assertEqual(list((ROOT / "infra" / "systemd").glob("server-sentinel-socket-owner.*")), [])
        installer = (ROOT / "server" / "install.py").read_text(encoding="utf-8")
        start = installer.index('return f"""[Unit]')
        template = installer[start:installer.index('"""', start + len('return f"""'))].splitlines()
        for line in ("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
                     "Sockets=server-sentinel-upstream.socket", "CapabilityBoundingSet=",
                     "AmbientCapabilities=", "ProtectControlGroups=true"):
            self.assertIn(line, template)
        for line in template:
            self.assertFalse(line.startswith(("PrivateNetwork=", "NetworkNamespacePath=", "Delegate=",
                                              "JoinsNamespaceOf=")), line)
            self.assertNotIn("CAP_", line)


class UnverifiedOwnershipContractTests(unittest.TestCase):
    """REQUIREMENTS.md and SPECIFICATION.md follow the Owner decisions of
    2026-10-05 (unverifiable ownership closes without revocation; the resolver
    is mandatory) and 2026-10-07 (creating unit and uid through sock_diag)."""

    STALE = (
        "another or unverifiable owner closes access as an exposure",
        "another or unverifiable owner is an exposure",
        "another or unverifiable holder is an exposure",
        "cannot be checked keeps access closed as an exposure",
        "unreadable own fd table keeps access closed as an exposure",
        "owning executable or systemd unit",
        "verifies the socket's owning process",
    )

    def test_contracts_drop_the_superseded_wording(self):
        for name in ("REQUIREMENTS.md", "SPECIFICATION.md"):
            text = normalized(ROOT / name)
            for phrase in self.STALE:
                self.assertFalse(phrase in text, f"{name}: {phrase}")

    REQUIRED = {
        "REQUIREMENTS.md": (
            "creating systemd unit (and uid)",
            "Ownership that cannot be verified",
            "is not an exposure: it keeps access closed without revocation",
            "The socket-owner resolver is mandatory",
            "only when an immediate second lookup in the same check reports the same creator",
            "`server-sentinel-upstream.socket`",
            "residual risk the Owner accepted on 2026-10-07",
        ),
        "SPECIFICATION.md": (
            "(`LISTENER_OWNER_UNVERIFIED`: no socket-owner resolver",
            "is not an exposure reason: it keeps access closed without revocation",
            "a check without one never opens access",
            "`NETLINK_SOCK_DIAG`",
            "`INET_DIAG_CGROUP_ID`",
            "`ip_unprivileged_port_start`",
        ),
    }

    def test_contracts_state_the_creator_check_and_closed_without_revocation(self):
        for name, phrases in self.REQUIRED.items():
            text = normalized(ROOT / name)
            for phrase in phrases:
                self.assertTrue(phrase in text, f"{name}: {phrase}")


class DeploymentRequirementTests(unittest.TestCase):
    def test_deployment_states_the_service_requirements_and_ssh_socket(self):
        text = normalized(ROOT / "server" / "docs" / "DEPLOYMENT.md")
        for phrase in ("`AF_NETLINK`", "no `PrivateNetwork=`", "never `private` or `strict`",
                       "keep Ubuntu's default `ssh.socket`", "`server-sentinel-upstream.socket`",
                       "`ip_unprivileged_port_start`", "`LISTENER_EXCEPTIONS_OUTDATED`"):
            self.assertTrue(phrase in text, phrase)
        # The 2026-10-01 "ssh.service only" step is reverted.
        self.assertFalse("sudo systemctl disable --now ssh.socket" in text)
        self.assertFalse("Until the privileged socket-owner helper of Issue #126 lands" in text)


if __name__ == "__main__":
    unittest.main()
