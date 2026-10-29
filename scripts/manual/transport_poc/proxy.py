"""User-space TCP impairment proxy on loopback (no root, no ``tc``/``netem``).

It sits between the sender and the Main listener on the capture host and
forwards raw TCP bytes (it never sees TLS plaintext). Impairments:

* ``blackhole``: stop reading from every connection for N seconds (a silent
  link loss: no FIN/RST, peers only notice through their own timeouts). A
  connection opened during the blackhole is accepted by the kernel but not
  forwarded (no upstream connect) until the blackhole ends.
* ``reset``: close every forwarded connection with RST on both sides.
* ``rate_cap``: limit agent-to-Main bytes per second for N seconds.

Each direction holds at most ``buffer_bytes`` (default and maximum 64 KiB) in
user space, so the proxy itself adds a bounded, known amount of buffering.
TCP packet loss and jitter are NOT emulated (that needs root ``netem``); the
summary reports them as ``unmeasured``.
"""
import ipaddress
import json
import select
import socket
import struct
import threading
import time

from . import records
from .wire import disable_nagle

MAX_BUFFER = 64 * 1024


def parse_endpoint(text, *, loopback_only=False):
    host, _, port = text.rpartition(":")
    address = ipaddress.ip_address(host.strip("[]"))
    if address.is_unspecified or address.is_multicast:
        raise ValueError("wildcard/multicast address refused")
    if address in ipaddress.ip_network("100.64.0.0/10") or (
            address.version == 6 and address in ipaddress.ip_network("fd7a:115c:a1e0::/48")):
        raise ValueError("Tailscale address refused")
    if loopback_only and not address.is_loopback:
        raise ValueError("the proxy listens on loopback only")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return str(address), port


def parse_schedule(text):
    """``[[offset_s, "blackhole"|"reset"|"rate_cap", duration_s, bytes_per_s], ...]``."""
    items = json.loads(text) if text else []
    schedule = []
    for item in items:
        offset, action = float(item[0]), item[1]
        if action not in ("blackhole", "reset", "rate_cap") or offset < 0:
            raise ValueError("invalid schedule item")
        duration = float(item[2]) if len(item) > 2 else 0.0
        rate = int(item[3]) if len(item) > 3 else 0
        if action == "rate_cap" and rate <= 0:
            raise ValueError("rate cap needs a positive rate")
        schedule.append((offset, action, duration, rate))
    return sorted(schedule)


class _Pair:
    def __init__(self, client):
        self.client = client
        self.upstream = None
        self.closed = threading.Event()
        self._finished = 0
        self._lock = threading.Lock()

    def half_closed(self):
        """One direction reached EOF; close normally once both have."""
        with self._lock:
            self._finished += 1
            both = self._finished >= 2
        if both:
            self.closed.set()
            for sock in (self.client, self.upstream):
                try:
                    sock.close()
                except OSError:
                    pass

    def reset(self):
        for sock in (self.client, self.upstream):
            if sock is None:
                continue
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self.closed.set()


class Proxy:
    def __init__(self, listen, upstream, writer, *, buffer_bytes=MAX_BUFFER):
        if not 1024 <= buffer_bytes <= MAX_BUFFER:
            raise ValueError("proxy buffer must be 1 KiB..64 KiB")
        self.listen, self.upstream = listen, upstream
        self.writer = writer
        self.buffer_bytes = buffer_bytes
        self.listener = socket.create_server(listen, reuse_port=False)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.unblocked = threading.Event()
        self.unblocked.set()
        self.lock = threading.Lock()
        self.pairs = set()
        self.rate = None
        self.tokens = 0.0
        self.token_time = time.monotonic()
        self.bytes_up = self.bytes_down = 0
        self.max_held = 0
        self.connections = 0
        self.resets = 0

    # -- controls --------------------------------------------------------------
    def blackhole(self, on):
        if on:
            self.unblocked.clear()
        else:
            self.unblocked.set()

    def reset_all(self):
        with self.lock:
            pairs = list(self.pairs)
            self.resets += 1
        for pair in pairs:
            pair.reset()

    def rate_cap(self, bytes_per_second):
        with self.lock:
            self.rate = bytes_per_second
            self.tokens = 0.0
            self.token_time = time.monotonic()

    # -- forwarding -------------------------------------------------------------
    def _take_tokens(self, wanted):
        """Block until up to ``wanted`` bytes may pass; returns the allowance."""
        while not self.stop.is_set():
            with self.lock:
                if self.rate is None:
                    return wanted
                now = time.monotonic()
                burst = max(1024, min(self.buffer_bytes, self.rate // 10))
                self.tokens = min(burst, self.tokens + (now - self.token_time) * self.rate)
                self.token_time = now
                if self.tokens >= 1:
                    allowed = int(min(wanted, self.tokens))
                    self.tokens -= allowed
                    return allowed
                wait = (1 - self.tokens) / self.rate
            time.sleep(min(0.05, max(0.001, wait)))
        return 0

    def _send_all(self, pair, destination, data):
        view = memoryview(data)
        while view:
            if self.stop.is_set() or pair.closed.is_set():
                return False
            _, writable, _ = select.select((), (destination,), (), 0.2)
            if not writable:
                continue
            try:
                view = view[destination.send(view):]
            except BlockingIOError:
                continue
        return True

    def _pump(self, pair, source, destination, upstream):
        """Never blocks longer than 0.2 s, so ``reset`` takes effect promptly."""
        eof = False
        try:
            while not self.stop.is_set() and not pair.closed.is_set():
                if not self.unblocked.wait(0.2):
                    continue
                size = self._take_tokens(self.buffer_bytes) if upstream else self.buffer_bytes
                if size <= 0:
                    break
                readable, _, _ = select.select((source,), (), (), 0.2)
                if not readable:
                    continue
                try:
                    data = source.recv(size)
                except BlockingIOError:
                    continue
                if not data:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    eof = True
                    break
                with self.lock:
                    self.max_held = max(self.max_held, len(data))
                while not self.unblocked.wait(0.2):  # read-stop: hold one bounded buffer
                    if self.stop.is_set() or pair.closed.is_set():
                        return
                if not self._send_all(pair, destination, data):
                    return
                with self.lock:
                    if upstream:
                        self.bytes_up += len(data)
                    else:
                        self.bytes_down += len(data)
        except (OSError, ValueError):
            pass
        finally:
            if eof:
                pair.half_closed()
            else:
                pair.reset()
            if pair.closed.is_set():
                with self.lock:
                    self.pairs.discard(pair)

    def _serve_pair(self, pair):
        while not self.unblocked.wait(0.2):
            if self.stop.is_set() or pair.closed.is_set():
                return
        try:
            pair.upstream = socket.create_connection(self.upstream, timeout=5)
        except OSError:
            pair.reset()
            return
        pair.upstream.setblocking(False)
        pair.client.setblocking(False)
        # The proxy stands in for the network path: it must not add Nagle
        # stalls of its own to either hop (#369).
        for sock in (pair.client, pair.upstream):
            disable_nagle(sock)
        for source, destination, upstream in ((pair.client, pair.upstream, True),
                                              (pair.upstream, pair.client, False)):
            threading.Thread(target=self._pump, args=(pair, source, destination, upstream),
                             daemon=True).start()

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            pair = _Pair(client)
            with self.lock:
                self.pairs.add(pair)
                self.connections += 1
            threading.Thread(target=self._serve_pair, args=(pair,), daemon=True).start()

    def close(self):
        self.stop.set()
        self.unblocked.set()
        try:
            self.listener.close()
        except OSError:
            pass
        with self.lock:
            pairs = list(self.pairs)
        for pair in pairs:
            pair.reset()

    def sample(self):
        with self.lock:
            self.writer.write("sample", bytes_up=self.bytes_up, bytes_down=self.bytes_down,
                              connections=self.connections, active=len(self.pairs),
                              max_held=self.max_held, buffer_bytes=self.buffer_bytes,
                              blackhole=not self.unblocked.is_set(),
                              rate_cap=self.rate or 0, resets=self.resets)


def run_schedule(proxy, schedule, seconds, *, started=None):
    """Execute ``schedule`` relative to ``started``; logs start/end of every impairment."""
    started = time.monotonic() if started is None else started
    events = []
    for offset, action, duration, rate in schedule:
        events.append((offset, "start", action, duration, rate))
        if action != "reset":
            events.append((offset + duration, "end", action, duration, rate))
    events.sort(key=lambda item: (item[0], item[1] == "start"))
    next_sample = started
    deadline = started + seconds
    for offset, phase, action, duration, rate in events + [(seconds, "done", None, 0, 0)]:
        at = started + offset
        while time.monotonic() < min(at, deadline) and not proxy.stop.is_set():
            if time.monotonic() >= next_sample:
                proxy.sample()
                next_sample += 1.0
            time.sleep(min(0.05, max(0.0, min(at, next_sample) - time.monotonic())))
        if phase == "done" or proxy.stop.is_set() or time.monotonic() >= deadline:
            break
        if action == "blackhole":
            proxy.blackhole(phase == "start")
        elif action == "reset":
            proxy.reset_all()
        elif action == "rate_cap":
            proxy.rate_cap(rate if phase == "start" else None)
        kind = "impairment_start" if phase == "start" else "impairment_end"
        proxy.writer.write(kind, impairment=action, duration_ns=int(duration * 1e9),
                           rate_bytes=rate)
        if action == "reset":
            proxy.writer.write("impairment_end", impairment=action, duration_ns=0, rate_bytes=0)
    proxy.sample()


def run(listen, upstream, schedule, seconds, out_path, run_id, *, buffer_bytes=MAX_BUFFER):
    import signal
    writer = records.JsonlWriter(out_path, run_id=run_id, role="proxy")
    proxy = Proxy(listen, upstream, writer, buffer_bytes=buffer_bytes)
    signal.signal(signal.SIGTERM, lambda *_: proxy.stop.set())
    writer.write("ready", port=proxy.port, tcp_nodelay=True)  # both sockets of a pair (#369)
    print("ready", flush=True)
    thread = threading.Thread(target=proxy.serve, daemon=True)
    thread.start()
    try:
        run_schedule(proxy, schedule, seconds)
    finally:
        proxy.close()
        writer.write("end", bytes_up=proxy.bytes_up, bytes_down=proxy.bytes_down)
        writer.close()
    return 0
