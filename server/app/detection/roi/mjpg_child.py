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
stdio (``/dev/null``) and the one private socket is closed. It opens no
network socket and no file after start; confinement beyond that (filesystem,
address families, seccomp) belongs to the systemd unit, as for the isolated
inference worker.

Wire format on the private `AF_UNIX` stream socket: each message is a 4-byte
big-endian length and a body.

* ready (child -> parent): ``b"R" + b"<simplejpeg version> <numpy version>"``;
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
