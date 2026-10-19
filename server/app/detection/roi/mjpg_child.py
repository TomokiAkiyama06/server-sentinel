"""Resident MJPG decode child (Issue #217, Owner decision 2026-10-11).

Run only by `mjpg_worker.MjpgDecoderProcess`, as a separate program
(`python -I -B mjpg_child.py ...`) with an explicit minimal environment, never
imported by the Main process. It is self-contained: before hardening it imports
only the standard library, and the only third-party code it loads is the
reviewed simplejpeg / numpy pair. It decodes camera-supplied MJPG bytes that
the Main process has already structurally validated, so a libjpeg-turbo crash,
hang or allocation failure ends this process, never the Main process.

Hardening, in this order and before simplejpeg / numpy are imported:
`PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG(SIGKILL)` (then a parent-pid check),
`PR_SET_DUMPABLE(0)`, a lower CPU priority, equal soft/hard `RLIMIT_AS`,
`RLIMIT_NOFILE`, `RLIMIT_NPROC` (no further process or thread),
`RLIMIT_CORE=0` and `RLIMIT_FSIZE=0`, and every inherited descriptor except
stdio (``/dev/null``) and the one private socket is closed.

Sandbox (Issue #269, Owner decision 2026-10-16 on #233 (B)). After the
reviewed pair is imported and one generated warm-up frame has been decoded (so
every lazy initialisation of the interpreter, numpy and libjpeg-turbo has
happened), and before the ready message, the child confines itself for good:

* Landlock (unprivileged LSM): a ruleset that handles every filesystem right
  the kernel's ABI knows and grants none, so no path can be opened, created,
  executed, listed, renamed or removed; TCP bind/connect are denied (ABI >= 4)
  and abstract UNIX sockets and signals outside the sandbox are scoped
  (ABI >= 6);
* seccomp: a classic BPF allowlist, built here without any dependency, of
  the system calls the decode loop makes (I/O on the inherited socket, memory
  management, futex, signal return, exit). `mmap` / `mprotect` asking for
  `PROT_EXEC` are refused, and every other call (any file open or creation,
  `socket` / `connect` / `bind`, `fork` / `clone` / `execve`, `ptrace`,
  `prctl`, ...) and every call entering through another architecture (i386,
  AArch32) or numbering (x32) kills the process with `SIGSYS`.

The sandbox is fail closed: where either layer cannot be applied (no
Landlock, no seccomp filter mode, another architecture), the child sends
``b"S"`` + one fixed refusal code instead of the ready message and exits, so
nothing is ever decoded unconfined. The parent then reports the source as
degraded (`frame_decoder_sandbox_unavailable`) and every frame as `unknown`.
Address-family and read-only-system confinement stays with the systemd unit.

Wire format on the private `AF_UNIX` stream socket: each message is a 4-byte
big-endian length and a body.

* ready (child -> parent): ``b"R" + b"<simplejpeg version> <numpy version>"``,
  sent only once the sandbox is in force;
* sandbox refusal (child -> parent, instead of ready): ``b"S"`` + one
  `SANDBOX_REFUSALS` code; the child then exits with status 5;
* request (parent -> child): ``b"D"``, request id (8), DCT-scaled width and
  height (2 + 2), output width and height (2 + 2), scaled MCU width and
  height (1 + 1), band length in MCUs (4), then the JPEG bytes;
* reply: ``b"K"`` + id + exactly output width x height luma bytes, or
  ``b"F"`` + id + one refusal code (1 decode failed, 2 decoded shape
  mismatch, 3 undecoded band).

A request the child cannot parse ends it (exit status 4); the parent then
reports that frame as `unknown`.
"""

import os
import sys

_PR_SET_PDEATHSIG = 1
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_REQUEST_HEADER = 1 + 8 + 2 + 2 + 2 + 2 + 1 + 1 + 4
UNDECODED_LUMA = 128
DECODE_FAILED, SHAPE_MISMATCH, UNDECODED_BAND = 1, 2, 3
# Sandbox refusal codes of the ``b"S"`` message (fixed, value-free).
SANDBOX_REFUSALS = {1: "unsupported_architecture", 2: "landlock_unavailable",
                    3: "seccomp_unavailable", 4: "sandbox_not_applied"}
EXIT_SANDBOX_REFUSED = 5

# Landlock (include/uapi/linux/landlock.h); the numbers are the same on x86-64
# and aarch64.
_LANDLOCK_CREATE_RULESET, _LANDLOCK_RESTRICT_SELF = 444, 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
# Filesystem rights known per ABI (1: bits 0-12, 2: REFER, 3: TRUNCATE,
# 5: IOCTL_DEV); every known right is handled, and none is granted.
_LANDLOCK_FS = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1, 4: (1 << 15) - 1}
_LANDLOCK_FS_LATEST = (1 << 16) - 1
_LANDLOCK_NET_TCP = (1 << 0) | (1 << 1)  # bind, connect (ABI >= 4)
_LANDLOCK_SCOPES = (1 << 0) | (1 << 1)  # abstract UNIX socket, signal (ABI >= 6)

# seccomp (include/uapi/linux/seccomp.h, filter.h, bpf_common.h, audit.h).
_SECCOMP_SET_MODE_FILTER, _SECCOMP_GET_ACTION_AVAIL = 1, 2
_SECCOMP_FILTER_FLAG_TSYNC = 1
SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ALLOW = 0x80000000, 0x7FFF0000
BPF_LD_W_ABS, BPF_JEQ_K, BPF_JSET_K, BPF_RET_K = 0x20, 0x15, 0x45, 0x06
# `struct seccomp_data`: nr (0), arch (4), instruction pointer (8), args at
# 16 + 8 * i (low 32 bits first on these little-endian architectures).
SECCOMP_DATA_NR, SECCOMP_DATA_ARCH = 0, 4
SECCOMP_DATA_PROT = 16 + 8 * 2
PROT_EXEC = 0x4
# The system calls the decode loop may make once the sandbox is in force.
# Traced with strace on CPython 3.12 and 3.14 (numpy 2.3.5, simplejpeg 1.9.0,
# 640x480 to 3840x2160 frames, valid and truncated): only `recvfrom` /
# `sendto` (`recv_into` / `sendall` on the inherited blocking socket) and
# `brk` / `mmap` / `munmap`. The rest is allocator and interpreter
# housekeeping that a larger frame or a freed arena may need (`mremap`,
# `mprotect` and `mmap` only without `PROT_EXEC`, `madvise`, `futex`), signal
# return and exit. None of them opens, creates or names a resource.
ALLOWED_SYSCALLS = ("recvfrom", "sendto", "mmap", "munmap", "mremap", "mprotect", "brk",
                    "madvise", "futex", "rt_sigreturn", "rt_sigprocmask", "restart_syscall",
                    "exit", "exit_group")
NO_EXEC_SYSCALLS = ("mmap", "mprotect")
# Per architecture: the AUDIT_ARCH value, the `seccomp` syscall number and the
# numbers of `ALLOWED_SYSCALLS` (arch/x86/entry/syscalls/syscall_64.tbl;
# include/uapi/asm-generic/unistd.h for aarch64).
ARCHITECTURES = {
    "x86_64": (0xC000003E, 317, {
        "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
        "rt_sigprocmask": 14, "rt_sigreturn": 15, "mremap": 25, "madvise": 28,
        "sendto": 44, "recvfrom": 45, "exit": 60, "futex": 202, "restart_syscall": 219,
        "exit_group": 231}),
    "aarch64": (0xC00000B7, 277, {
        "exit": 93, "exit_group": 94, "futex": 98,
        "restart_syscall": 128, "rt_sigprocmask": 135, "rt_sigreturn": 139,
        "sendto": 206, "recvfrom": 207, "brk": 214, "munmap": 215, "mremap": 216,
        "mmap": 222, "mprotect": 226, "madvise": 233}),
}


def _harden(parent_pid, address_space, open_files, niceness, keep):
    import ctypes
    import resource
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError("no_new_privs unavailable")
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError("parent-death signal unavailable")
    if os.getppid() != parent_pid:
        # The parent died before the death signal was armed.
        raise OSError("parent is gone")
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError("dumpable flag unavailable")
    os.nice(niceness)
    _soft, descriptors = resource.getrlimit(resource.RLIMIT_NOFILE)
    if descriptors == resource.RLIM_INFINITY or descriptors > 1 << 20:
        descriptors = 1 << 20
    # Popen already closed everything but stdio and the socket; this also
    # covers a descriptor a future caller might leak.
    os.closerange(3, keep)
    os.closerange(keep + 1, descriptors)
    for limit, value in ((resource.RLIMIT_AS, address_space),
                         (resource.RLIMIT_NOFILE, open_files),
                         (resource.RLIMIT_NPROC, 0),
                         (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        _soft, hard = resource.getrlimit(limit)
        if hard != resource.RLIM_INFINITY and value > hard:
            raise OSError("requested limit exceeds the service limit")
        # Equal soft/hard limits: the decoder cannot raise them again.
        resource.setrlimit(limit, (value, value))


class SandboxUnavailable(Exception):
    """The sandbox cannot be applied; `code` is a `SANDBOX_REFUSALS` key."""

    def __init__(self, code):
        super().__init__(SANDBOX_REFUSALS[code])
        self.code = code


def architecture():
    """``(audit arch, seccomp number, syscall numbers)`` for this process."""
    if sys.maxsize <= 1 << 32:
        # A 32-bit interpreter would enter through the compat syscall table.
        raise SandboxUnavailable(1)
    try:
        return ARCHITECTURES[os.uname().machine]
    except KeyError:
        raise SandboxUnavailable(1) from None


def seccomp_program(audit_arch, numbers):
    """The allowlist as classic BPF ``(code, jt, jf, k)`` instructions."""
    program = [(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH),
               # Another architecture's entry point (i386, AArch32) is killed
               # before its number is read.
               (BPF_JEQ_K, 1, 0, audit_arch),
               (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
               (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR)]
    for name in ALLOWED_SYSCALLS:
        number = numbers[name]
        if name in NO_EXEC_SYSCALLS:
            # Matched: load `prot` (third argument); PROT_EXEC is killed.
            program += [(BPF_JEQ_K, 0, 4, number),
                        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_PROT),
                        (BPF_JSET_K, 0, 1, PROT_EXEC),
                        (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
                        (BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)]
        else:
            program += [(BPF_JEQ_K, 0, 1, number), (BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)]
    # Every other number, including x32 (bit 30) aliases of allowed calls.
    program.append((BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS))
    return program


def landlock_abi(libc):
    """The kernel's Landlock ABI version, or 0 when Landlock is unavailable."""
    import ctypes

    version = libc.syscall(ctypes.c_long(_LANDLOCK_CREATE_RULESET), None, ctypes.c_size_t(0),
                           ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION))
    return version if version > 0 else 0


def landlock_rights(abi):
    """``(fs, net, scoped)`` rights the ruleset handles, i.e. denies."""
    fs = _LANDLOCK_FS.get(abi, _LANDLOCK_FS_LATEST)
    return fs, _LANDLOCK_NET_TCP if abi >= 4 else 0, _LANDLOCK_SCOPES if abi >= 6 else 0


def restrict_filesystem(libc):
    """Landlock ruleset without any rule: no filesystem access at all."""
    import ctypes
    import struct

    abi = landlock_abi(libc)
    if abi < 1:
        raise SandboxUnavailable(2)
    attr = ctypes.create_string_buffer(struct.pack("=QQQ", *landlock_rights(abi)))
    ruleset = libc.syscall(ctypes.c_long(_LANDLOCK_CREATE_RULESET), attr,
                           ctypes.c_size_t(len(attr.raw)), ctypes.c_uint32(0))
    if ruleset < 0:
        raise SandboxUnavailable(2)
    try:
        if libc.syscall(ctypes.c_long(_LANDLOCK_RESTRICT_SELF), ctypes.c_int(ruleset),
                        ctypes.c_uint32(0)) != 0:
            raise SandboxUnavailable(4)
    finally:
        os.close(ruleset)
    return abi


def restrict_syscalls(libc, arch):
    """Install the seccomp allowlist (all threads; irreversible)."""
    import ctypes
    import struct

    audit_arch, seccomp_number, numbers = arch
    action = ctypes.c_uint32(SECCOMP_RET_KILL_PROCESS)
    if libc.syscall(ctypes.c_long(seccomp_number), ctypes.c_uint(_SECCOMP_GET_ACTION_AVAIL),
                    ctypes.c_uint(0), ctypes.byref(action)) != 0:
        # No seccomp filter mode, or no kill-process action (Linux < 4.14).
        raise SandboxUnavailable(3)
    program = seccomp_program(audit_arch, numbers)
    filters = ctypes.create_string_buffer(
        b"".join(struct.pack("=HBBI", *instruction) for instruction in program))
    # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    fprog = ctypes.create_string_buffer(
        struct.pack("=H6xQ", len(program), ctypes.addressof(filters)))
    if libc.syscall(ctypes.c_long(seccomp_number), ctypes.c_uint(_SECCOMP_SET_MODE_FILTER),
                    ctypes.c_uint(_SECCOMP_FILTER_FLAG_TSYNC), fprog) != 0:
        raise SandboxUnavailable(3)


def sandbox(libc=None):
    """Confine this single-threaded process for good: Landlock, then seccomp.

    Raises `SandboxUnavailable` when either layer cannot be applied; the
    process may then be partly confined and must exit without decoding.
    Returns the Landlock ABI in force.
    """
    import ctypes

    arch = architecture()
    libc = libc or ctypes.CDLL(None, use_errno=True)
    try:
        threads = len(os.listdir("/proc/self/task"))
    except OSError:
        raise SandboxUnavailable(4) from None
    if threads != 1:
        # Landlock confines only the calling thread.
        raise SandboxUnavailable(4)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SandboxUnavailable(4)
    abi = restrict_filesystem(libc)
    # Last: the filter allows neither the Landlock nor the seccomp calls.
    restrict_syscalls(libc, arch)
    return abi


def _warm_up(simplejpeg, numpy):
    """Decode one generated 32 x 32 frame at DCT scale 1/2, as a real request
    would, so libjpeg-turbo's SIMD detection and numpy's first-use paths run
    before the sandbox. True when the decoder answered as expected."""
    image = (numpy.arange(32 * 32, dtype=numpy.uint32) % 251).astype(numpy.uint8)
    data = simplejpeg.encode_jpeg(numpy.ascontiguousarray(image.reshape(32, 32, 1)),
                                  quality=90, colorspace="GRAY")
    request = bytearray(b"D" + bytes(8) + (16).to_bytes(2, "big") * 2
                        + (8).to_bytes(2, "big") * 2 + bytes((4, 4)) + (1).to_bytes(4, "big"))
    pixels, refusal = _decode(simplejpeg, numpy, request + data)
    return refusal == 0 and len(pixels) == 8 * 8


def _read_exact(connection, size):
    buffer = bytearray(size)
    view, received = memoryview(buffer), 0
    while received < size:
        count = connection.recv_into(view[received:], size - received)
        if count == 0:
            raise EOFError
        received += count
    return buffer


def _send(connection, body):
    connection.sendall(len(body).to_bytes(4, "big") + body)


def _undecoded_band(numpy, image, mcu_width, mcu_height, minimum):
    """True when the last `minimum` MCUs in scan order are all exactly 128."""
    rows, columns = image.shape
    across, down = -(-columns // mcu_width), -(-rows // mcu_height)
    padded = numpy.full((down * mcu_height, across * mcu_width), UNDECODED_LUMA,
                        dtype=numpy.uint8)
    padded[:rows, :columns] = image
    uniform = (padded.reshape(down, mcu_height, across, mcu_width)
               == UNDECODED_LUMA).all(axis=(1, 3))
    flat = uniform.reshape(-1)
    minimum = min(minimum, flat.size)
    return bool(flat[-minimum:].all())


def _decode(simplejpeg, numpy, request):
    scaled_width = int.from_bytes(request[9:11], "big")
    scaled_height = int.from_bytes(request[11:13], "big")
    width = int.from_bytes(request[13:15], "big")
    height = int.from_bytes(request[15:17], "big")
    mcu_width, mcu_height = request[17], request[18]
    band = int.from_bytes(request[19:23], "big")
    if (min(scaled_width, scaled_height, width, height, mcu_width, mcu_height, band) == 0
            or scaled_width % width or scaled_height % height):
        raise ValueError("invalid request")
    try:
        decoded = simplejpeg.decode_jpeg(
            memoryview(request)[_REQUEST_HEADER:], colorspace="GRAY", fastdct=False,
            fastupsample=False, min_width=scaled_width, min_height=scaled_height,
            strict=True)
    except Exception:
        # Includes libjpeg warnings promoted to errors by strict mode, and an
        # allocation refused by the address-space limit.
        return None, DECODE_FAILED
    if (not isinstance(decoded, numpy.ndarray) or decoded.dtype != numpy.uint8
            or decoded.shape != (scaled_height, scaled_width, 1)):
        return None, SHAPE_MISMATCH
    image = decoded[:, :, 0]
    if _undecoded_band(numpy, image, mcu_width, mcu_height, band):
        return None, UNDECODED_BAND
    step_x, step_y = scaled_width // width, scaled_height // height
    pixels = numpy.ascontiguousarray(image[::step_y, ::step_x]).tobytes()
    if len(pixels) != width * height:
        return None, SHAPE_MISMATCH
    return pixels, 0


def main(argv):
    import socket

    descriptor, parent_pid, address_space, open_files, niceness, maximum = (
        int(value) for value in argv[1:7])
    expected = argv[7], argv[8]
    _harden(parent_pid, address_space, open_files, niceness, descriptor)
    connection = socket.socket(fileno=descriptor)
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
        os._exit(3)
    try:
        import numpy
        import simplejpeg
        versions = (str(getattr(simplejpeg, "__version__", "")),
                    str(getattr(numpy, "__version__", "")))
    except BaseException:
        os._exit(3)
    if versions != expected:
        os._exit(3)
    try:
        warm = _warm_up(simplejpeg, numpy)
    except BaseException:
        warm = False
    if not warm:
        os._exit(3)
    try:
        sandbox()
    except SandboxUnavailable as refused:
        _send(connection, b"S" + bytes((refused.code,)))
        os._exit(EXIT_SANDBOX_REFUSED)
    _send(connection, b"R" + " ".join(versions).encode("ascii"))
    limit = _REQUEST_HEADER + maximum
    while True:
        try:
            size = int.from_bytes(_read_exact(connection, 4), "big")
            if not _REQUEST_HEADER < size <= limit:
                os._exit(4)
            request = _read_exact(connection, size)
        except (EOFError, OSError):
            os._exit(0)
        if request[:1] != b"D":
            os._exit(4)
        identifier = bytes(request[1:9])
        try:
            pixels, refusal = _decode(simplejpeg, numpy, request)
        except MemoryError:
            pixels, refusal = None, DECODE_FAILED
        except Exception:
            os._exit(4)
        request = None
        if pixels is None:
            _send(connection, b"F" + identifier + bytes((refusal,)))
        else:
            _send(connection, b"K" + identifier + pixels)
        pixels = None


if __name__ == "__main__":
    try:
        main(sys.argv)
    except BaseException:
        os._exit(3)
    os._exit(0)
