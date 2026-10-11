"""Numeric-only JSONL records and process/socket resource sampling.

Every record value is a number, a boolean, ``None`` or a token from the fixed
``TOKENS`` vocabulary (scenario, candidate, outcome and reason names). Free
text, paths, addresses, host names, UUIDs, certificate bytes and media bytes
can therefore never reach a measurement file. An unexpected reason string is
recorded as ``other`` rather than copied.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import termios
import threading
import time

RUN_ID_PATTERN = re.compile(r"r[0-9]{8}t[0-9]{6}[0-9a-f]{0,8}")
KEY_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,47}")

CANDIDATES = ("a_framed", "b_chunked", "b_segment", "srt_ffmpeg")
SCENARIOS = (
    "normal", "outage_1s", "outage_5s", "outage_120s", "rst", "bandwidth_cap",
    "slow_stop_10s", "slow_stop_60s", "slow_drain", "main_restart",
    "capture_restart", "capacity_4", "fifth_refused", "auth_unpaired",
    "auth_other_ca", "auth_revoked", "auth_revoked_live", "route_probe", "soak",
)
TOKENS = frozenset((
    *CANDIDATES, *SCENARIOS,
    # roles / kinds
    "receiver", "sender", "proxy", "orchestrator", "holder", "summary",
    "synthetic", "real", "builtin", "gst", "camera", "main", "agent", "both",
    # record kinds
    "start", "end", "sample", "event", "gap", "durable", "gate", "metric",
    "session_open", "session_close", "auth_refused", "interrupted", "revoked",
    "connect", "connect_failed", "loss_detected", "first_accept", "closed",
    "impairment_start", "impairment_end", "action", "exit", "epoch_start",
    "latency", "route_probe", "committed_gap", "rtt", "capture", "unavailable", "ready",
    "durable_duplicate", "durable_gap",
    # impairments / actions
    "good", "revoked_live", "unpaired", "other_ca",
    "blackhole", "reset", "rate_cap", "sigstop", "sigcont", "restart_receiver",
    "restart_sender", "revoke", "none",
    # ingest / continuity outcomes and reasons
    "accepted", "duplicate", "backpressured", "rate_limited", "rejected",
    "not_processed", "unauthorized", "stale_session", "source_capacity",
    "source_identity_mismatch", "watermark_unavailable", "already_committed",
    "stale_capture_epoch", "capture_clock_regression", "queue_limit",
    "rate_limit", "rate_window_capacity", "message_too_large", "clock_regression",
    "sequence_skip", "capture_restart", "ingest_refused", "coalesced",
    "receiving", "degraded", "interrupted",
    # transport / session reasons
    "peer_closed", "loss_timeout", "protocol_error", "tls_handshake_failed",
    "tls_session_failed", "capture_node_not_admitted", "capture_node_certificate_invalid",
    "capture_node_certificate_missing", "tls_version_refused", "admission_lost",
    "connection_limit", "shutdown", "send_failed", "superseded", "not_found",
    "main_unreachable", "main_handshake_failed", "main_identity_rejected",
    "main_endpoint_rejected", "refused", "timeout",
    # gate results
    "pass", "fail", "unmeasured", "not_applicable", "other",
))


def token(value):
    """Map a value to the fixed vocabulary; anything unknown becomes ``other``."""
    return value if isinstance(value, str) and value in TOKENS else "other"


def new_run_id():
    stamp = time.strftime("%Y%m%dt%H%M%S", time.gmtime())
    return "r" + stamp + os.urandom(3).hex()


def _check_value(key, value):
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite number in record")
        return
    if isinstance(value, str):
        if key == "run_id" and RUN_ID_PATTERN.fullmatch(value):
            return
        if value in TOKENS:
            return
    raise ValueError("record value is not numeric or a known token")


def validate_record(record):
    if not isinstance(record, dict) or not record:
        raise ValueError("record must be a non-empty mapping")
    for key, value in record.items():
        if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
            raise ValueError("record key is not a plain identifier")
        _check_value(key, value)
    return record


class JsonlWriter:
    """Append-only, flushed per record, private (0600) measurement file."""

    def __init__(self, path, *, run_id, role):
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError("invalid run id")
        self.path = Path(path)
        self.run_id = run_id
        self.role = token(role)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                             0o600)
        self._stream = os.fdopen(descriptor, "a", encoding="ascii")
        self._lock = threading.Lock()

    def write(self, kind, **fields):
        record = {"run_id": self.run_id, "role": self.role, "kind": token(kind),
                  "t_ns": time.monotonic_ns(), **fields}
        validate_record(record)
        line = json.dumps(record, separators=(",", ":"), allow_nan=False)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()

    def close(self):
        with self._lock:
            self._stream.close()


def read_jsonl(path):
    """Read a measurement file; every record is re-validated."""
    records = []
    with open(path, encoding="ascii") as stream:
        for line in stream:
            line = line.strip()
            if line:
                records.append(validate_record(json.loads(line)))
    return records


# -- resource sampling --------------------------------------------------------

def process_memory(pid="self"):
    """(VmRSS, VmHWM) in bytes, or (None, None) when unreadable."""
    values = {}
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as stream:
            for line in stream:
                name, _, rest = line.partition(":")
                if name in ("VmRSS", "VmHWM"):
                    values[name] = int(rest.split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return None, None
    return values.get("VmRSS"), values.get("VmHWM")


def process_cpu_seconds(pid=None):
    """User+system CPU seconds of this process (all threads) or of ``pid``."""
    if pid is None:
        times = os.times()
        return times.user + times.system
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as stream:
            fields = stream.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return None


def descendant_pids(pid=None, *, limit=256):
    """Live descendant process ids (``/proc/<pid>/task/*/children``), bounded."""
    pid = os.getpid() if pid is None else pid
    found, frontier = [], [pid]
    while frontier and len(found) < limit:
        current = frontier.pop()
        try:
            tasks = os.listdir(f"/proc/{current}/task")
        except OSError:
            continue
        for task in tasks:
            try:
                with open(f"/proc/{current}/task/{task}/children", encoding="ascii") as stream:
                    children = [int(value) for value in stream.read().split()]
            except (OSError, ValueError):
                continue
            found.extend(children)
            frontier.extend(children)
    return found[:limit]


def descendant_cpu_seconds(pid=None):
    """CPU seconds of live descendants (e.g. sandboxed GStreamer pipelines)."""
    return sum(process_cpu_seconds(child) or 0.0 for child in descendant_pids(pid))


def cgroup_cpu_quota():
    """(quota_us, period_us) of this process's cgroup v2 ``cpu.max``; None if unlimited."""
    try:
        with open("/proc/self/cgroup", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("0::"):
                    relative = line.strip()[3:]
                    break
            else:
                return None, None
        with open(Path("/sys/fs/cgroup") / relative.lstrip("/") / "cpu.max",
                  encoding="ascii") as stream:
            quota, period = stream.read().split()
        return (None if quota == "max" else int(quota)), int(period)
    except (OSError, ValueError):
        return None, None


def socket_queues(sock):
    """(unsent+unacked send-queue bytes, readable receive-queue bytes) via ioctl."""
    result = []
    for request in (termios.TIOCOUTQ, termios.FIONREAD):
        try:
            raw = fcntl.ioctl(sock.fileno(), request, struct.pack("i", 0))
            result.append(struct.unpack("i", raw)[0])
        except (OSError, ValueError):
            result.append(None)
    return tuple(result)


_SKMEM = re.compile(r"skmem:\(([^)]*)\)")


def ss_skmem(port, *, local=True):
    """Max skmem counters of this side's established TCP sockets (``ss -tmi``).

    ``local`` selects sockets whose local port is ``port`` (a listener's
    accepted connections); otherwise those whose remote port is ``port`` (a
    client's outbound connections).

    Returns None when ``ss`` is unavailable; only numbers are parsed, the
    address columns are never kept.
    """
    executable = shutil.which("ss")
    if executable is None:
        return None
    try:
        output = subprocess.run(
            [executable, "-tmiHn", "state", "established",
             f"( {'sport' if local else 'dport'} = :{int(port)} )"],
            capture_output=True, text=True, timeout=2, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    maxima = {"ss_sockets": 0}
    for match in _SKMEM.finditer(output):
        maxima["ss_sockets"] += 1
        for item in match.group(1).split(","):
            name = re.match(r"[a-z]+", item)
            number = re.search(r"[0-9]+$", item)
            if name and number:
                key = "ss_" + name.group(0)
                maxima[key] = max(maxima.get(key, 0), int(number.group(0)))
    return maxima


def percentiles(values, points=(50, 95, 99)):
    """Nearest-rank percentiles; empty input yields Nones."""
    ordered = sorted(values)
    result = {}
    for point in points:
        if not ordered:
            result[point] = None
            continue
        rank = max(1, -(-point * len(ordered) // 100))
        result[point] = ordered[min(rank, len(ordered)) - 1]
    return result


class Reservoir:
    """Bounded uniform sample for latency percentiles (memory stays fixed)."""

    def __init__(self, capacity=20000, *, seed=15):
        import random
        self.capacity = capacity
        self.values = []
        self.seen = 0
        self.maximum = None
        self._random = random.Random(seed)

    def add(self, value):
        self.seen += 1
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        if len(self.values) < self.capacity:
            self.values.append(value)
        else:
            index = self._random.randrange(self.seen)
            if index < self.capacity:
                self.values[index] = value
