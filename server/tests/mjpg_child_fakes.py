"""Synthetic stand-ins for `mjpg_child.py` (Issue #217 tests only).

Run as ``python -I -B mjpg_child_fakes.py <behaviour> <child arguments...>``.
Standard library only; no decoder and no image data. Each behaviour breaks
the decode-child contract in one way, so the parent's failure handling can be
exercised without a real libjpeg fault. ``sandbox_refused_<code>`` sends the
child's sandbox refusal (Issue #269); ``real_without_landlock`` runs the real
child as on a kernel that reports no Landlock.
"""

import os
import signal
import socket
import sys
import time


def _read_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            os._exit(0)
        data += chunk
    return data


def _send(connection, body):
    connection.sendall(len(body).to_bytes(4, "big") + body)


def real_child_without_landlock(argv):
    """The real child on a kernel that reports no Landlock (Issue #269)."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "app" / "detection" / "roi" / "mjpg_child.py"
    spec = importlib.util.spec_from_file_location("mjpg_child_without_landlock", path)
    child = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(child)
    child.landlock_abi = lambda libc: 0
    try:
        child.main([str(path)] + argv[2:])
    except BaseException:
        os._exit(3)
    os._exit(0)


def main(argv):
    import ctypes
    if argv[1] == "real_without_landlock":
        real_child_without_landlock(argv)
    # Like the real child: never outlive the test process.
    ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)
    behaviour = argv[1]
    descriptor = int(argv[2])
    expected = " ".join(argv[8:10]).encode("ascii")
    connection = socket.socket(fileno=descriptor)
    if behaviour == "exit_at_start":
        os._exit(3)
    if behaviour == "hang_at_start":
        time.sleep(3600)
    if behaviour == "wrong_ready":
        _send(connection, b"R0.0 0.0")
        time.sleep(3600)
    if behaviour.startswith("sandbox_refused_"):
        # The child's sandbox refusal message, then its exit status.
        _send(connection, b"S" + bytes((int(behaviour[16:]),)))
        os._exit(5)
    _send(connection, b"R" + expected)
    count = 0
    while True:
        size = int.from_bytes(_read_exact(connection, 4), "big")
        request = _read_exact(connection, size)
        count += 1
        identifier = request[1:9]
        width = int.from_bytes(request[13:15], "big")
        height = int.from_bytes(request[15:17], "big")
        if behaviour == "flat" or (behaviour == "exit_second" and count == 1):
            _send(connection, b"K" + identifier + bytes([90]) * (width * height))
        elif behaviour == "inspect":
            import json
            report = json.dumps({"environment": dict(os.environ),
                                 "descriptors": sorted(int(item) for item in os.listdir("/proc/self/fd")),
                                 "socket": descriptor}).encode("ascii")
            _send(connection, b"K" + identifier + report.ljust(width * height, b" "))
        elif behaviour in ("exit", "exit_second"):
            os._exit(1)
        elif behaviour == "sigkill":
            os.kill(os.getpid(), signal.SIGKILL)
        elif behaviour == "hang":
            time.sleep(3600)
        elif behaviour == "short":
            _send(connection, b"K" + identifier + bytes(width * height - 1))
        elif behaviour == "wrong_id":
            other = (int.from_bytes(identifier, "big") + 1).to_bytes(8, "big")
            _send(connection, b"K" + other + bytes(width * height))
        elif behaviour == "wrong_kind":
            _send(connection, b"X" + identifier + bytes(width * height))
        elif behaviour == "bad_refusal":
            _send(connection, b"F" + identifier + bytes((9,)))
        elif behaviour == "oversized":
            connection.sendall((1 << 31).to_bytes(4, "big") + b"K" + identifier)
            time.sleep(3600)
        elif behaviour == "partial":
            connection.sendall((9 + width * height).to_bytes(4, "big") + b"K" + identifier)
            time.sleep(3600)
        elif behaviour == "refuse":
            # A healthy child refusing every frame (strict decode error).
            _send(connection, b"F" + identifier + bytes((1,)))
        elif behaviour == "drip":
            # A correct reply, one byte every 50 ms.
            connection.sendall((9 + width * height).to_bytes(4, "big") + b"K" + identifier)
            for _ in range(width * height):
                time.sleep(0.05)
                connection.sendall(b"\x00")
            time.sleep(3600)
        elif behaviour.startswith("size_"):
            # Announces a reply of this size, then sends nothing more.
            size = int(behaviour[5:])
            connection.sendall(size.to_bytes(4, "big") + (b"K" + identifier)[:size])
            time.sleep(3600)
        else:
            os._exit(5)


if __name__ == "__main__":
    main(sys.argv)
