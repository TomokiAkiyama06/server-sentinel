"""Applies the real decode-child sandbox, then attempts one operation (Issue #269).

Run as ``python -I -B mjpg_sandbox_probe.py <mjpg_child.py> <stage> <attempt> [argument]``
by `test_mjpg_sandbox.py` only. Standard library only; no decoder, no image
data. The sandbox code is the child's own (`mjpg_child.sandbox` and its
layers), loaded from the given path exactly as the child runs it. Every module
the attempts need is imported before the sandbox is applied, as in the child.

Stages: ``none`` (no sandbox), ``landlock`` (Landlock only), ``seccomp``
(seccomp only) and ``full`` (the child's `sandbox()`).

Exit status: 0 the attempt succeeded, 1 it failed with `PermissionError`,
2 it failed with another `OSError`, 3 the sandbox could not be applied (the
refusal code is printed first), 4 invalid use. A seccomp kill ends the probe
with `SIGSYS` instead.
"""

import ctypes
import importlib.util
import mmap
import os
import socket
import sys
import threading


def load(path):
    spec = importlib.util.spec_from_file_location("mjpg_child_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def attempt(name, argument, libc):
    if name == "nothing":
        return
    if name == "open_read":
        os.close(os.open(argument, os.O_RDONLY))
    elif name == "create":
        os.close(os.open(os.path.join(argument, "created"),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    elif name == "list_directory":
        os.listdir(argument)
    elif name == "socket_inet":
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
    elif name == "socket_unix":
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
    elif name == "connect_tcp":
        # The socket is created before the sandbox (see `prepare`).
        PREPARED.connect(("127.0.0.1", int(argument)))
    elif name == "fork":
        if os.fork() == 0:
            os._exit(0)
    elif name == "spawn":
        os.posix_spawn("/bin/true", ["true"], {})
    elif name == "thread":
        threading.Thread(target=lambda: None).start()
    elif name == "execve":
        os.execv("/bin/true", ["true"])
    elif name == "mmap_anonymous":
        region = mmap.mmap(-1, 1 << 20)
        region[0] = 1
    elif name == "mmap_exec":
        mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC)
    elif name == "mprotect_exec":
        address = ctypes.addressof(ctypes.c_char.from_buffer(PREPARED))
        if libc.mprotect(ctypes.c_void_p(address), ctypes.c_size_t(4096),
                         ctypes.c_int(mmap.PROT_READ | mmap.PROT_EXEC)) != 0:
            raise OSError(ctypes.get_errno(), "mprotect")
    else:
        os._exit(4)


PREPARED = None


def prepare(name):
    """Resources an attempt needs that the sandbox would itself refuse."""
    global PREPARED
    if name == "connect_tcp":
        PREPARED = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif name == "mprotect_exec":
        PREPARED = mmap.mmap(-1, 4096)


def main(argv):
    if len(argv) not in (4, 5):
        os._exit(4)
    child, stage, name = argv[1:4]
    argument = argv[4] if len(argv) == 5 else None
    module = load(child)
    libc = ctypes.CDLL(None, use_errno=True)
    prepare(name)
    try:
        if stage == "landlock":
            if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
                raise module.SandboxUnavailable(4)
            module.restrict_filesystem(libc)
        elif stage == "seccomp":
            arch = module.architecture()
            if libc.prctl(38, 1, 0, 0, 0) != 0:
                raise module.SandboxUnavailable(4)
            module.restrict_syscalls(libc, arch)
        elif stage == "full":
            module.sandbox(libc)
        elif stage != "none":
            os._exit(4)
    except module.SandboxUnavailable as refused:
        sys.stdout.write(module.SANDBOX_REFUSALS[refused.code] + "\n")
        sys.stdout.flush()
        os._exit(3)
    try:
        attempt(name, argument, libc)
    except PermissionError:
        os._exit(1)
    except OSError:
        os._exit(2)
    os._exit(0)


if __name__ == "__main__":
    main(sys.argv)
