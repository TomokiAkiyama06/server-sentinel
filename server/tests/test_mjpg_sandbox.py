"""MJPG decode-child sandbox: Landlock + seccomp, fail closed (Issue #269).

The filter program is checked for both supported architectures with a small
classic-BPF interpreter (no kernel needed). On this kernel the real sandbox
code (`mjpg_child.sandbox` and its layers) is applied in a probe process
(`mjpg_sandbox_probe.py`), which then attempts one operation, so each denied
operation is shown to actually fail after confinement. Where the kernel (or a
container profile) offers no Landlock or seccomp, those tests are skipped with
the reason; with ``MJPG_SANDBOX_REQUIRED=1`` (set by ``server/ci.toml`` in CI)
they fail instead.
"""

import ctypes
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from app.detection.roi import mjpg_child, mjpg_worker


CHILD = Path(mjpg_child.__file__)
PROBE = Path(__file__).with_name("mjpg_sandbox_probe.py")
SIGSYS = -signal.SIGSYS
REQUIRED = os.environ.get("MJPG_SANDBOX_REQUIRED") == "1"

# Denied system calls by architecture (none of them is in the allowlist).
DENIED = {
    "x86_64": {
        "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "ioctl": 16, "socket": 41,
        "connect": 42, "accept": 43, "bind": 49, "listen": 50, "socketpair": 53, "clone": 56,
        "fork": 57, "vfork": 58, "execve": 59, "kill": 62, "rename": 82, "mkdir": 83,
        "creat": 85, "link": 86, "unlink": 87, "symlink": 88, "chmod": 90, "ptrace": 101,
        "getppid": 110, "mknod": 133, "prctl": 157, "mount": 165, "openat": 257,
        "unlinkat": 263, "memfd_create": 319, "seccomp": 317, "execveat": 322,
        "pkey_mprotect": 329, "io_uring_setup": 425, "clone3": 435, "openat2": 437,
        "landlock_create_ruleset": 444, "landlock_restrict_self": 446,
    },
    "aarch64": {
        "ioctl": 29, "mknodat": 33, "mkdirat": 34, "unlinkat": 35, "symlinkat": 36,
        "linkat": 37, "mount": 40, "openat": 56, "close": 57, "read": 63, "write": 64,
        "kill": 129, "prctl": 167, "getppid": 173, "socket": 198, "socketpair": 199,
        "bind": 200, "listen": 201, "accept": 202, "connect": 203, "clone": 220,
        "execve": 221, "renameat2": 276, "seccomp": 277, "memfd_create": 279,
        "execveat": 281, "pkey_mprotect": 288, "ptrace": 117, "io_uring_setup": 425,
        "clone3": 435, "openat2": 437, "landlock_create_ruleset": 444,
        "landlock_restrict_self": 446,
    },
}


def run_bpf(program, nr, arch, args=(0,) * 6):
    """Evaluate a classic BPF seccomp program on one `struct seccomp_data`."""
    data = struct.pack("=iIQ6Q", nr, arch, 0, *args)
    accumulator, pc = 0, 0
    while True:
        code, jt, jf, k = program[pc]
        if code == mjpg_child.BPF_LD_W_ABS:
            accumulator = struct.unpack_from("=I", data, k)[0]
            pc += 1
        elif code == mjpg_child.BPF_JEQ_K:
            pc += 1 + (jt if accumulator == k else jf)
        elif code == mjpg_child.BPF_JSET_K:
            pc += 1 + (jt if accumulator & k else jf)
        elif code == mjpg_child.BPF_RET_K:
            return k
        else:
            raise AssertionError(f"unexpected instruction {code:#x}")


def probe(stage, attempt, argument=None, timeout=60):
    command = [sys.executable, "-I", "-B", str(PROBE), str(CHILD), stage, attempt]
    if argument is not None:
        command.append(str(argument))
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=timeout, env={"LC_ALL": "C"}, cwd="/")
    return result.returncode, result.stdout.decode("ascii", "replace").strip()


_AVAILABILITY = {}


def unavailable(stage="full"):
    """Why `stage` cannot be applied on this kernel, or None when it can."""
    if stage not in _AVAILABILITY:
        if not sys.platform.startswith("linux"):
            _AVAILABILITY[stage] = "not Linux"
        else:
            code, output = probe(stage, "nothing")
            _AVAILABILITY[stage] = (None if code == 0
                                    else f"sandbox stage {stage!r} refused: {output or code}")
    return _AVAILABILITY[stage]


def require_sandbox(case, stage="full"):
    """Skip `case` when the sandbox is unavailable here; fail in CI."""
    reason = unavailable(stage)
    if reason is not None:
        if REQUIRED:
            case.fail(f"MJPG_SANDBOX_REQUIRED=1 but {reason}")
        case.skipTest(reason)


class SeccompProgramTests(unittest.TestCase):
    """The allowlist itself, per architecture, without a kernel."""

    def test_only_the_allowlist_passes_on_each_architecture(self):
        for machine, (audit_arch, _seccomp, numbers) in mjpg_child.ARCHITECTURES.items():
            program = mjpg_child.seccomp_program(audit_arch, numbers)
            self.assertLessEqual(len(program), 4096)  # BPF_MAXINSNS
            with self.subTest(machine=machine):
                self.assertEqual(set(mjpg_child.ALLOWED_SYSCALLS), set(numbers))
                for name in mjpg_child.ALLOWED_SYSCALLS:
                    self.assertEqual(mjpg_child.SECCOMP_RET_ALLOW,
                                     run_bpf(program, numbers[name], audit_arch), name)
                for name, number in DENIED[machine].items():
                    self.assertNotIn(number, numbers.values(), name)
                    self.assertEqual(mjpg_child.SECCOMP_RET_KILL_PROCESS,
                                     run_bpf(program, number, audit_arch), name)
                # Every number up to 1024 that is not allowed is killed.
                allowed = set(numbers.values())
                for number in range(1024):
                    expected = (mjpg_child.SECCOMP_RET_ALLOW if number in allowed
                                else mjpg_child.SECCOMP_RET_KILL_PROCESS)
                    self.assertEqual(expected, run_bpf(program, number, audit_arch), number)

    def test_executable_mappings_are_killed(self):
        for machine, (audit_arch, _seccomp, numbers) in mjpg_child.ARCHITECTURES.items():
            program = mjpg_child.seccomp_program(audit_arch, numbers)
            for name in mjpg_child.NO_EXEC_SYSCALLS:
                with self.subTest(machine=machine, syscall=name):
                    for prot, expected in ((0, mjpg_child.SECCOMP_RET_ALLOW),
                                           (0x3, mjpg_child.SECCOMP_RET_ALLOW),
                                           (0x4, mjpg_child.SECCOMP_RET_KILL_PROCESS),
                                           (0x7, mjpg_child.SECCOMP_RET_KILL_PROCESS)):
                        self.assertEqual(expected, run_bpf(program, numbers[name], audit_arch,
                                                           (0, 4096, prot, 0x22, 0, 0)))

    def test_other_architectures_and_x32_numbers_are_killed(self):
        x86_arch, _seccomp, x86 = mjpg_child.ARCHITECTURES["x86_64"]
        arm_arch, _seccomp, arm = mjpg_child.ARCHITECTURES["aarch64"]
        program = mjpg_child.seccomp_program(x86_arch, x86)
        kill = mjpg_child.SECCOMP_RET_KILL_PROCESS
        # i386 (int 0x80) and an aarch64 number on an x86-64 filter.
        for arch in (0x40000003, arm_arch, 0):
            self.assertEqual(kill, run_bpf(program, x86["recvfrom"], arch))
        # x32 aliases (bit 30) of allowed numbers.
        for name in ("recvfrom", "mmap", "exit_group"):
            self.assertEqual(kill, run_bpf(program, x86[name] | 0x40000000, x86_arch))
        program = mjpg_child.seccomp_program(arm_arch, arm)
        # AArch32 compat entry (AUDIT_ARCH_ARM) and an x86-64 caller.
        for arch in (0x40000028, x86_arch):
            self.assertEqual(kill, run_bpf(program, arm["recvfrom"], arch))

    def test_landlock_rights_by_abi(self):
        everything = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1, 4: (1 << 15) - 1}
        for abi in range(1, 10):
            fs, net, scoped = mjpg_child.landlock_rights(abi)
            self.assertEqual(everything.get(abi, (1 << 16) - 1), fs)
            self.assertEqual(3 if abi >= 4 else 0, net)
            self.assertEqual(3 if abi >= 6 else 0, scoped)

    def test_refusal_codes_match_the_parent(self):
        self.assertEqual(mjpg_child.SANDBOX_REFUSALS, mjpg_worker.SANDBOX_REFUSALS)


class FakeLibc:
    """Answers the sandbox's calls without touching the kernel."""

    def __init__(self, abi=8, ruleset=0, restrict=0, action=0, seccomp=0, prctl=0):
        self.abi, self.ruleset, self.restrict = abi, ruleset, restrict
        self.action, self.seccomp, self.prctl_result = action, seccomp, prctl
        self.calls = []

    def prctl(self, *args):
        self.calls.append(("prctl", args[0]))
        return self.prctl_result

    def syscall(self, number, *args):
        number = number.value
        self.calls.append(("syscall", number))
        if number == 444:
            if args[0] is None:
                return self.abi
            if self.ruleset < 0:
                return self.ruleset
            return os.open(os.devnull, os.O_RDONLY)  # closed by the sandbox
        if number == 446:
            return self.restrict
        if number in (317, 277):
            return self.action if args[0].value == 2 else self.seccomp
        raise AssertionError(number)


class SandboxRefusalTests(unittest.TestCase):
    """Fail closed: every layer that cannot be applied is a refusal."""

    def refusal(self, libc, *, machine=None, maxsize=None, threads=("1",)):
        uname = os.uname()
        with mock.patch.object(mjpg_child.os, "listdir", return_value=list(threads)), \
                mock.patch.object(mjpg_child.os, "uname",
                                  return_value=mock.Mock(machine=machine or uname.machine)), \
                mock.patch.object(mjpg_child.sys, "maxsize", maxsize or sys.maxsize):
            with self.assertRaises(mjpg_child.SandboxUnavailable) as caught:
                mjpg_child.sandbox(libc)
        return mjpg_child.SANDBOX_REFUSALS[caught.exception.code]

    def setUp(self):
        if os.uname().machine not in mjpg_child.ARCHITECTURES:
            self.skipTest("unsupported architecture for the fake syscall numbers")

    def test_each_unavailable_layer_is_refused(self):
        self.assertEqual("landlock_unavailable", self.refusal(FakeLibc(abi=0)))
        self.assertEqual("landlock_unavailable", self.refusal(FakeLibc(abi=-1)))
        self.assertEqual("landlock_unavailable", self.refusal(FakeLibc(ruleset=-1)))
        self.assertEqual("sandbox_not_applied", self.refusal(FakeLibc(restrict=-1)))
        self.assertEqual("seccomp_unavailable", self.refusal(FakeLibc(action=-1)))
        self.assertEqual("seccomp_unavailable", self.refusal(FakeLibc(seccomp=-1)))
        self.assertEqual("sandbox_not_applied", self.refusal(FakeLibc(prctl=-1)))
        self.assertEqual("sandbox_not_applied", self.refusal(FakeLibc(), threads=("1", "2")))
        self.assertEqual("unsupported_architecture", self.refusal(FakeLibc(), machine="riscv64"))
        self.assertEqual("unsupported_architecture",
                         self.refusal(FakeLibc(), maxsize=(1 << 31) - 1))

    def test_landlock_is_applied_before_seccomp(self):
        libc = FakeLibc()
        with mock.patch.object(mjpg_child.os, "listdir", return_value=["1"]):
            self.assertEqual(8, mjpg_child.sandbox(libc))
        numbers = [number for kind, number in libc.calls if kind == "syscall"]
        seccomp = mjpg_child.ARCHITECTURES[os.uname().machine][1]
        self.assertEqual([444, 444, 446, seccomp, seccomp], numbers)
        self.assertEqual(("prctl", 38), libc.calls[0])

    def test_no_landlock_means_no_seccomp_attempt_either(self):
        libc = FakeLibc(abi=0)
        self.refusal(libc)
        self.assertNotIn(mjpg_child.ARCHITECTURES[os.uname().machine][1],
                         [number for kind, number in libc.calls if kind == "syscall"])


class KernelSandboxTests(unittest.TestCase):
    """The real sandbox on this kernel: denied operations actually fail."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        os.chmod(self.directory.name, 0o700)

    def assertPermitted(self, stage, attempt, argument=None):
        self.assertEqual((0, ""), probe(stage, attempt, argument), (stage, attempt))

    def test_unconfined_probe_can_do_everything(self):
        # The baseline: without the sandbox each attempt succeeds here, so a
        # failure below is the sandbox's doing.
        for attempt, argument in (("open_read", PROBE), ("list_directory", "/"),
                                  ("create", self.directory.name), ("socket_inet", None),
                                  ("socket_unix", None), ("fork", None), ("spawn", None),
                                  ("thread", None), ("execve", None), ("mmap_exec", None),
                                  ("mprotect_exec", None)):
            with self.subTest(attempt=attempt):
                self.assertPermitted("none", attempt, argument)
        os.unlink(os.path.join(self.directory.name, "created"))

    def test_landlock_denies_every_filesystem_access(self):
        require_sandbox(self, "landlock")
        for attempt, argument in (("open_read", PROBE), ("open_read", "/proc/self/status"),
                                  ("list_directory", "/"), ("create", self.directory.name),
                                  ("execve", None)):
            with self.subTest(attempt=attempt, argument=argument):
                self.assertEqual((1, ""), probe("landlock", attempt, argument))
        self.assertEqual([], os.listdir(self.directory.name))
        # Landlock does not restrict creating a socket; seccomp does.
        self.assertPermitted("landlock", "socket_unix")

    def test_landlock_denies_tcp_connect_where_the_abi_supports_it(self):
        require_sandbox(self, "landlock")
        abi = mjpg_child.landlock_abi(ctypes.CDLL(None, use_errno=True))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        try:
            listener.bind(("127.0.0.1", 0))
        except OSError:
            self.skipTest("no loopback interface")
        listener.listen(1)
        port = listener.getsockname()[1]
        self.assertPermitted("none", "connect_tcp", port)
        if abi < 4:
            self.skipTest(f"Landlock ABI {abi} has no network rights")
        self.assertEqual((1, ""), probe("landlock", "connect_tcp", port))

    def test_seccomp_kills_file_network_and_process_creation(self):
        require_sandbox(self, "seccomp")
        for attempt, argument in (("open_read", PROBE), ("create", self.directory.name),
                                  ("list_directory", "/"), ("socket_inet", None),
                                  ("socket_unix", None), ("fork", None), ("spawn", None),
                                  ("thread", None), ("execve", None), ("mmap_exec", None),
                                  ("mprotect_exec", None)):
            with self.subTest(attempt=attempt):
                self.assertEqual((SIGSYS, ""), probe("seccomp", attempt, argument))
        self.assertEqual([], os.listdir(self.directory.name))

    def test_full_sandbox_denies_and_keeps_what_decoding_needs(self):
        require_sandbox(self)
        for attempt, argument in (("open_read", PROBE), ("create", self.directory.name),
                                  ("socket_inet", None), ("connect_tcp", 9), ("fork", None),
                                  ("spawn", None), ("thread", None), ("execve", None),
                                  ("mmap_exec", None), ("mprotect_exec", None)):
            with self.subTest(attempt=attempt):
                self.assertEqual((SIGSYS, ""), probe("full", attempt, argument))
        self.assertEqual([], os.listdir(self.directory.name))
        # Anonymous memory (heap growth, numpy buffers) and exit still work.
        self.assertPermitted("full", "mmap_anonymous")
        self.assertPermitted("full", "nothing")


if __name__ == "__main__":
    unittest.main()
