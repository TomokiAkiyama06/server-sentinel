"""Unprivileged Landlock confinement for the video capture pipeline child.

GStreamer's ``video4linux2`` plugin probes every ``/dev/video*`` node read-write
when it is loaded (to register memory-to-memory codec elements), before
``v4l2src`` touches the descriptor the Agent verified. No environment variable
disables that probe, so the child is confined by the kernel instead: this
helper runs between ``fork`` and the pipeline ``exec`` and applies a Landlock
ruleset (unprivileged, no root, no user namespace) that

- denies every filesystem access not listed below, including ``/sys``, ``/run``
  and ``/dev`` (enumerating or opening another camera fails with ``EACCES``);
- allows read/execute only beneath the given read-only paths;
- allows read/write/ioctl on exactly the one approved device inode (the
  descriptor inherited from the Agent), so ``/proc/self/fd/N`` can be reopened;
- denies TCP bind/connect (Landlock ABI >= 4) and abstract UNIX socket
  connections and signals outside the sandbox (ABI >= 6) where supported.

Any failure exits before ``exec``: the pipeline never runs unconfined. The
module is stdlib-only and runnable as a script::

    python3 -I -S uvc_sandbox.py --device-fd N [--read PATH]... -- EXECUTABLE [ARG]...
"""

import ctypes
import os
import stat
import struct
import sys


_SYS_CREATE_RULESET, _SYS_ADD_RULE, _SYS_RESTRICT_SELF = 444, 445, 446
_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_TRUNCATE = 1 << 14
FS_IOCTL_DEV = 1 << 15
NET_BIND_TCP = 1 << 0
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
SCOPE_SIGNAL = 1 << 1

# Filesystem rights known per Landlock ABI (ABI 1: bits 0-12, 2: REFER,
# 3: TRUNCATE, 5: IOCTL_DEV). All of them are handled, i.e. denied by default.
_FS_BY_ABI = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1,
              4: (1 << 15) - 1, 5: (1 << 16) - 1}
_FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV
EXIT_REFUSED = 126
# The only paths a pipeline child may read; plugin loading itself is restricted
# separately by the launcher's environment and ``--gst-plugin-load``.
DEFAULT_READ_PATHS = ("/usr", "/lib", "/lib64", "/etc/ld.so.cache")


class SandboxError(RuntimeError):
    """Fixed safe failure text; never includes paths or kernel details."""


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def abi_version(libc=None):
    """Supported Landlock ABI, or 0 when Landlock is unavailable/disabled."""
    try:
        libc = libc or _libc()
        version = libc.syscall(ctypes.c_long(_SYS_CREATE_RULESET), None, ctypes.c_size_t(0),
                               ctypes.c_uint32(_CREATE_RULESET_VERSION))
    except (OSError, AttributeError):
        return 0
    return version if version > 0 else 0


def handled_rights(abi):
    """``(fs, net, scoped)`` rights the ruleset denies unless a rule allows them."""
    if type(abi) is not int or abi < 1:
        raise SandboxError("video pipeline sandbox is unavailable")
    fs = _FS_BY_ABI.get(abi, _FS_BY_ABI[5])
    net = NET_BIND_TCP | NET_CONNECT_TCP if abi >= 4 else 0
    scoped = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL if abi >= 6 else 0
    return fs, net, scoped


def device_rights(abi):
    fs = handled_rights(abi)[0]
    return (FS_READ_FILE | FS_WRITE_FILE | FS_IOCTL_DEV) & fs


def _check(result, libc):
    if result < 0:
        raise SandboxError("video pipeline sandbox could not be applied")
    return result


def restrict(device_fd, read_paths=DEFAULT_READ_PATHS, *, libc=None):
    """Confine the calling (single-threaded) process; irreversible."""
    libc = libc or _libc()
    abi = abi_version(libc)
    fs, net, scoped = handled_rights(abi)
    try:
        info = os.fstat(device_fd)
    except (OSError, TypeError):
        raise SandboxError("video pipeline sandbox could not be applied") from None
    if not stat.S_ISCHR(info.st_mode):
        raise SandboxError("video pipeline sandbox could not be applied")
    attr = ctypes.create_string_buffer(struct.pack("=QQQ", fs, net, scoped))
    ruleset = _check(libc.syscall(ctypes.c_long(_SYS_CREATE_RULESET), attr,
                                  ctypes.c_size_t(len(attr.raw)), ctypes.c_uint32(0)), libc)
    try:
        def allow(fd, rights):
            rule = ctypes.create_string_buffer(struct.pack("=Qi", rights, fd))
            _check(libc.syscall(ctypes.c_long(_SYS_ADD_RULE), ctypes.c_int(ruleset),
                                ctypes.c_int(_RULE_PATH_BENEATH), rule, ctypes.c_uint32(0)),
                   libc)

        for path in read_paths:
            if not isinstance(path, str) or not os.path.isabs(path):
                raise SandboxError("video pipeline sandbox could not be applied")
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except FileNotFoundError:
                continue  # e.g. no /lib64 on this architecture.
            except OSError:
                raise SandboxError("video pipeline sandbox could not be applied") from None
            try:
                directory = stat.S_ISDIR(os.fstat(fd).st_mode)
                rights = FS_EXECUTE | FS_READ_FILE | (FS_READ_DIR if directory else 0)
                allow(fd, rights & fs)
            finally:
                os.close(fd)
        allow(device_fd, device_rights(abi))
        _check(libc.prctl(ctypes.c_int(_PR_SET_NO_NEW_PRIVS), ctypes.c_ulong(1),
                          ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)), libc)
        _check(libc.syscall(ctypes.c_long(_SYS_RESTRICT_SELF), ctypes.c_int(ruleset),
                            ctypes.c_uint32(0)), libc)
    finally:
        os.close(ruleset)
    return abi


def parse(argv):
    """``--device-fd N [--read PATH]... -- EXECUTABLE [ARG]...``"""
    try:
        split = argv.index("--")
    except ValueError:
        raise SandboxError("invalid sandbox command") from None
    options, command = argv[:split], argv[split + 1:]
    device_fd, read_paths = None, []
    index = 0
    while index < len(options):
        flag = options[index]
        if index + 1 >= len(options):
            raise SandboxError("invalid sandbox command")
        value = options[index + 1]
        if flag == "--device-fd" and device_fd is None and value.isdigit():
            device_fd = int(value)
        elif flag == "--read" and os.path.isabs(value):
            read_paths.append(value)
        else:
            raise SandboxError("invalid sandbox command")
        index += 2
    if device_fd is None or device_fd < 3 or not command or not os.path.isabs(command[0]):
        raise SandboxError("invalid sandbox command")
    return device_fd, tuple(read_paths) or DEFAULT_READ_PATHS, command


def main(argv=None):
    try:
        device_fd, read_paths, command = parse(sys.argv[1:] if argv is None else argv)
        restrict(device_fd, read_paths)
        os.execv(command[0], command)
    except BaseException:  # Never exec, and never report details (stderr is discarded).
        pass
    os._exit(EXIT_REFUSED)


if __name__ == "__main__":
    main()
