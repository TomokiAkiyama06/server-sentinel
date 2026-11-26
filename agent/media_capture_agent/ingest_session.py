"""The Agent's capture ingest session to the Main (Issue #14), stdlib only.

The Agent initiates one outbound TLS 1.3 mTLS connection to the Main's
dedicated capture ingest listener (SPECIFICATION §5.6/§5.7) through
``main_link.connect_to_main``, so the private-LAN-only checks (Issue #150)
apply. It never listens, never speaks HTTP and reaches no human/admin route:
the only protocol is the capture ingest wire protocol, version 1 (ADR-0007
``a_framed``, mirrored from ``server/app/cameras/remote_agent/ingest_wire.py``;
``server/tests/test_capture_ingest_session.py`` runs this client against the
real Main listener)::

    uint32 big-endian body length | uint8 frame type | body

* ``HEARTBEAT`` (Agent to Main): the Agent's schema-1 node heartbeat as JSON.
* ``HEARTBEAT_ACK`` (Main to Agent): ``{"sequence", "receive_utc",
  "send_utc"}``. With the Agent's own send and receive times it forms the
  ``ClockExchange`` of §5.9; the next heartbeat reports the clock assessed
  from it.
* ``CLOSE`` (Main to Agent): one fixed reason word before the Main closes.
* ``LIVE_FRAME`` (Agent to Main): one source's newest JPEG (``live_sender``);
  the Main sends no reply.
* ``RENEWAL_REQUEST`` (Agent to Main; Issue #109, ADR-0007 addendum
  2026-11-16): ``{"csr": <PEM>}``, the node's renewal CSR. The Main renews
  only the session's own node.
* ``RENEWAL_REPLY`` (Main to Agent): ``{"status": "issued", "certificate":
  <PEM>}`` or ``{"status": "refused", "reason": <fixed word>}``. The Main
  sends it only directly before a ``HEARTBEAT_ACK``, so it is read inside a
  heartbeat round trip, never while the Agent is idle.

Stop-and-wait: one heartbeat, then its ack, within ``REPLY_TIMEOUT_SECONDS``.
Every failure (connect, handshake, ALPN, timeout, a ``CLOSE``, a malformed or
mismatched reply) drops the connection, forgets the clock exchange and raises
``IngestSessionError`` (a ``ConnectionError``, which the runtime reports as
``main_unavailable``). Reconnects back off from ``RETRY_FIRST_SECONDS`` up to
``RETRY_MAX_SECONDS``; while waiting, a heartbeat fails at once without
traffic. A tick's network work is bounded by ``CONNECT_TIMEOUT_SECONDS`` per
TCP connect attempt (``socket.create_connection`` tries each resolved address
in turn) and for the TLS handshake, ``REPLY_TIMEOUT_SECONDS`` for the send and
its reply, and another ``REPLY_TIMEOUT_SECONDS`` when a frame the Main sent
while the Agent was idle (a ``CLOSE``) is read before reconnecting. A DNS name
adds name resolution, which has no timeout here: an IP literal endpoint is
recommended (PR #406 review).

A connection the Main closed while the Agent was idle (``_still_open``: an
idle timeout, a Main restart, or this session superseded by a newer one of
the same node) is reconnected within the same tick the first time. Issue #407
(Owner decision 2026-11-16): an idle close within ``IDLE_DROP_STREAK_SECONDS``
of the previous one continues a streak, and from the second close of a
streak the reconnect waits ``RETRY_FIRST_SECONDS`` doubling up to
``RETRY_MAX_SECONDS`` (reason ``main_closed_repeatedly``). Two Agents holding
one node credential (a cloned SD card or a restored backup) then replace each
other at most about every ``RETRY_MAX_SECONDS`` instead of on every tick,
which the Main still sees and notifies. A successful heartbeat does not end
the streak (each of those sessions acknowledges heartbeats); only a
connection that stays open for the streak window does. Two numbers are kept.

The credential is read from the installed generation at every connect
(``main_link.installed_credential``), so a pairing completed while the
service runs is picked up without a restart, and a credential naming another
node than the configured one is refused (``node_identity_mismatch``).
Certificate renewal (Issue #109): with ``renewal`` (a
``credential_renewal.CredentialRenewal``), after each acknowledged heartbeat
the session asks it whether a renewal is due and, if so, sends its CSR as a
``RENEWAL_REQUEST`` on the same connection, under the same lock as the
heartbeat and the live frames; it never opens a connection for it. At most
one request is outstanding. Its ``RENEWAL_REPLY`` comes before a later
heartbeat's ack; it is handled after that ack, so the clock exchange is not
widened. An issued certificate is installed as a new credential generation
and the session reconnects at once with it (keeping the clock exchange), which
promotes it on the Main. A refusal, a reply not received within
``RENEWAL_REPLY_TIMEOUT_SECONDS``, or a connection lost while the request is
outstanding is a failed attempt, retried per the renewal schedule's back-off;
the current credential stays in use. ``renewal_status`` is that fixed word.

Nothing here logs: reasons are fixed words, never peer bytes, addresses or
key material.
"""
from __future__ import annotations

from enum import IntEnum
import json
import math
import re
import select
import socket
import ssl
import struct
import threading
import time
from typing import Callable
from uuid import UUID

from .config import MainIngestEndpoint
from .health import ClockExchange
from .main_link import build_capture_client_context, connect_to_main, installed_credential
from .pairing import NodeCredentialStore, PairingRefused


INGEST_ALPN = "serversentinel-capture-ingest/1"
HEADER = struct.Struct(">IB")
# A heartbeat is well below this; the Main's frame limit is 16 KiB.
MAXIMUM_HEARTBEAT_BYTES = 16 * 1024
# An ack or close is a small fixed-shape object.
MAXIMUM_REPLY_BYTES = 4096
# Issue #109: the renewal request (a P-256 CSR in PEM is about 500 bytes) and
# its reply (a node certificate, about 1 KiB), as the Main bounds them.
MAXIMUM_RENEWAL_REQUEST_BYTES = 8 * 1024
MAXIMUM_RENEWAL_REPLY_BYTES = 16 * 1024
# The Main answers within its signer's timeout (30 s), before the next ack.
RENEWAL_REPLY_TIMEOUT_SECONDS = 60.0
# Bounds of one tick's network work (`config.MAXIMUM_HEARTBEAT_SECONDS`): the
# TCP connect and the TLS handshake, then the heartbeat send and its reply.
CONNECT_TIMEOUT_SECONDS = 5.0
REPLY_TIMEOUT_SECONDS = 5.0
# Issue #14 (PR #413 review): the live frames share the connection with the
# heartbeat, so at most this many not-yet-sent bytes wait in the kernel ahead
# of a heartbeat (a few ms on 1 GbE, ~10 ms on 100 Mbit/s); without it the
# autotuned send buffer (MBs) would delay the heartbeat behind the frames,
# widen its clock exchange (`clock_uncertain`) or exhaust its reply timeout.
NOT_SENT_LOW_WATER_BYTES = 131_072
# Linux's option number (include/uapi/linux/tcp.h). Some CPython builds (for
# example python-build-standalone) lack `socket.TCP_NOTSENT_LOWAT`; without
# the fallback every connect would fail with an uncaught AttributeError.
TCP_NOTSENT_LOWAT = getattr(socket, "TCP_NOTSENT_LOWAT", 25)
RETRY_FIRST_SECONDS = 1.0
RETRY_MAX_SECONDS = 30.0
# Issue #407: idle closes this close together form a streak; above
# `RETRY_MAX_SECONDS`, so a streak survives its longest back-off.
IDLE_DROP_STREAK_SECONDS = 60.0
_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ACK_KEYS = frozenset({"sequence", "receive_utc", "send_utc"})
# A PEM certificate's first line (built, so the repository's secret-format
# scan does not mistake it for a PEM).
_CERTIFICATE_PEM_START = "-" * 5 + "BEGIN CERTIFICATE" + "-" * 5


class FrameType(IntEnum):
    HEARTBEAT = 0x01
    HEARTBEAT_ACK = 0x02
    # Agent to Main (Owner decision 2026-11-12, option A): one source's
    # newest JPEG for the live view. The Main keeps it in memory only and
    # sends no reply (it never acknowledges media it does not keep).
    LIVE_FRAME = 0x10
    # Issue #109: the renewal request and its reply (before a later ack).
    RENEWAL_REQUEST = 0x20
    RENEWAL_REPLY = 0x21
    CLOSE = 0x7F


# A live frame's JPEG bound; its body is the 16-byte source UUID then the JPEG.
MAXIMUM_LIVE_FRAME_BYTES = 1_048_576


class IngestSessionError(ConnectionError):
    """A fixed-reason session failure; the message never holds peer bytes."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def encode_frame(kind: FrameType, payload: dict) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return HEADER.pack(len(body), int(kind)) + body


def _receive_exactly(connection, size: int, deadline: float,
                     clock: Callable[[], float]) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        left = deadline - clock()
        if left <= 0:
            raise IngestSessionError("main_reply_timeout")
        # Each receive gets only what is left of the reply's one deadline.
        connection.settimeout(left)
        try:
            chunk = connection.recv(min(remaining, 65536))
        except socket.timeout:
            raise IngestSessionError("main_reply_timeout") from None
        if not chunk:
            raise IngestSessionError("main_closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_reply(connection, deadline: float, *, clock: Callable[[], float] = time.monotonic,
               prefix: bytes = b"") -> tuple[FrameType, dict]:
    """Read one Main frame; its length is refused before the body is read.

    ``prefix`` is the start of the header, already read by the caller.
    """
    header = prefix + _receive_exactly(connection, HEADER.size - len(prefix), deadline, clock)
    length, kind = HEADER.unpack(header)
    try:
        frame_type = FrameType(kind)
    except ValueError:
        raise IngestSessionError("main_reply_invalid") from None
    if frame_type in (FrameType.HEARTBEAT, FrameType.LIVE_FRAME, FrameType.RENEWAL_REQUEST):
        # Agent-to-Main types never come from the Main.
        raise IngestSessionError("main_reply_invalid")
    limit = (MAXIMUM_RENEWAL_REPLY_BYTES if frame_type is FrameType.RENEWAL_REPLY
             else MAXIMUM_REPLY_BYTES)
    if not 0 < length <= limit:
        raise IngestSessionError("main_reply_invalid")
    body = _receive_exactly(connection, length, deadline, clock)
    try:
        value = json.loads(body.decode("utf-8"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise IngestSessionError("main_reply_invalid") from None
    if not isinstance(value, dict):
        raise IngestSessionError("main_reply_invalid")
    return frame_type, value


def _refuse_constant(_value):
    raise ValueError("non-finite number")


def _finite(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _close_reason(value: dict) -> str:
    reason = value.get("reason") if set(value) == {"reason"} else None
    # Only a fixed word is kept; anything else is not repeated.
    return reason if isinstance(reason, str) and _WORD.fullmatch(reason) else "other"


def _renewal_reply(value: dict) -> tuple[bytes | None, str | None]:
    """An issued certificate PEM, or a refusal word; anything else is invalid."""
    if value.get("status") == "issued" and set(value) == {"status", "certificate"}:
        certificate = value["certificate"]
        if (isinstance(certificate, str) and certificate.isascii()
                and certificate.lstrip().startswith(_CERTIFICATE_PEM_START)):
            return certificate.encode("ascii"), None
    elif value.get("status") == "refused" and set(value) == {"status", "reason"}:
        reason = value["reason"]
        if isinstance(reason, str) and _WORD.fullmatch(reason):
            return None, reason
    raise IngestSessionError("main_reply_invalid")


def _shutdown(connection) -> None:
    try:
        connection.close()
    except OSError:
        pass


class IngestSession:
    """The runtime's ``OutboundSession`` over the capture ingest protocol."""

    unavailable_reason = "pairing_required"

    def __init__(self, store: NodeCredentialStore, endpoint: MainIngestEndpoint, node_id: UUID,
                 *, connect=connect_to_main, credential=installed_credential,
                 utc: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 renewal=None):
        if (not isinstance(endpoint, MainIngestEndpoint) or not isinstance(node_id, UUID)
                or not callable(connect) or not callable(credential)
                or (renewal is not None and not all(
                    callable(getattr(renewal, name, None))
                    for name in ("due", "issued", "failed")))):
            raise ValueError("invalid ingest session dependencies")
        self._store = store
        self._endpoint = endpoint
        self._node_id = node_id
        self._connect_to_main = connect
        self._credential = credential
        self._utc = utc
        self._monotonic = monotonic
        self._connection = None
        # The heartbeat (tick thread) and the live frames (`live_sender`)
        # share the one connection; every use of it holds this lock.
        self._io = threading.RLock()
        self._exchange: ClockExchange | None = None
        # Established connections lost so far (Issue #16 ring loss trigger).
        self.connection_losses = 0
        self._failures = 0
        self._retry_at = None
        # Issue #407: the current streak of idle closes and its latest time.
        self._idle_drops = 0
        self._idle_drop_at: float | None = None
        # Issue #109: the renewal schedule and install, and the monotonic
        # deadline of the one outstanding request (None: none outstanding).
        self._renewal = renewal
        self._renewal_deadline: float | None = None
        # Fixed words for status and tests; never peer bytes.
        self.last_failure: str | None = None
        self.last_close_reason: str | None = None

    # -- OutboundSession -------------------------------------------------

    @property
    def authenticated(self) -> bool:
        """An installed node credential exists (a session may still be down)."""
        if self._connection is not None:
            return True
        try:
            return self._store.installed()
        except PairingRefused:
            # A damaged credential is not "unpaired": the connect attempt
            # refuses it and the node reports `main_unavailable`.
            return True

    def exchange_clock(self) -> ClockExchange | None:
        """The exchange of the latest ack on the current connection, if any."""
        return self._exchange

    @property
    def renewal_status(self) -> str | None:
        """The renewal's fixed status word (Issue #109), or None."""
        return None if self._renewal is None else getattr(self._renewal, "status", None)

    def send_heartbeat(self, heartbeat: dict) -> None:
        with self._io:
            self._send_heartbeat(heartbeat)

    def send_live_frame(self, source_id: UUID, jpeg: bytes) -> bool:
        """Send one live frame on the current connection; False if not sent.

        It never connects (the heartbeat owns connecting and its back-off)
        and expects no reply. A frame that is not one complete JPEG within
        ``MAXIMUM_LIVE_FRAME_BYTES`` is skipped. A send failure drops the
        connection like a heartbeat failure.
        """
        if (not isinstance(source_id, UUID) or not isinstance(jpeg, bytes)
                or not 4 <= len(jpeg) <= MAXIMUM_LIVE_FRAME_BYTES
                or not jpeg.startswith(b"\xff\xd8") or not jpeg.endswith(b"\xff\xd9")):
            return False
        with self._io:
            connection = self._connection
            if connection is None:
                return False
            frame = HEADER.pack(16 + len(jpeg), int(FrameType.LIVE_FRAME)) + source_id.bytes + jpeg
            try:
                connection.settimeout(REPLY_TIMEOUT_SECONDS)
                connection.sendall(frame)
            except (OSError, ssl.SSLError, ValueError):
                self._drop()
                self._failed("main_send_failed")
                return False
            return True

    def _send_heartbeat(self, heartbeat: dict) -> None:
        if self._connection is not None and not self._still_open():
            self._drop()
            self._idle_dropped()
        if self._connection is None:
            if self._retry_at is not None and self._monotonic() < self._retry_at:
                raise IngestSessionError("main_retry_wait")
            try:
                self._connect()
            except IngestSessionError as failure:
                self._failed(failure.reason)
                raise
        try:
            renewal_reply = self._round_trip(heartbeat)
        except IngestSessionError as failure:
            self._drop()
            self._failed(failure.reason)
            raise
        except (OSError, ssl.SSLError, ValueError):
            self._drop()
            self._failed("main_send_failed")
            raise IngestSessionError("main_send_failed") from None
        self._failures = 0
        self._retry_at = None
        self.last_failure = None
        if self._renewal is not None:
            self._renew(renewal_reply)

    def close(self) -> None:
        with self._io:
            self._drop()

    # -- internals ---------------------------------------------------------

    def _failed(self, reason: str) -> None:
        self.last_failure = reason
        self._failures += 1
        delay = min(RETRY_FIRST_SECONDS * 2 ** min(self._failures - 1, 16), RETRY_MAX_SECONDS)
        self._retry_at = self._monotonic() + delay

    def _idle_dropped(self) -> None:
        """Back off from the second idle close of a streak (Issue #407).

        The first one (a Main restart, an idle timeout, one replacement by
        a reconnect of this node) reconnects at once, as before.
        """
        now = self._monotonic()
        if (self._idle_drop_at is not None
                and 0 <= now - self._idle_drop_at < IDLE_DROP_STREAK_SECONDS):
            self._idle_drops = min(self._idle_drops + 1, 64)
        else:
            self._idle_drops = 1
        self._idle_drop_at = now
        if self._idle_drops < 2:
            return
        self.last_failure = "main_closed_repeatedly"
        delay = min(RETRY_FIRST_SECONDS * 2 ** min(self._idle_drops - 2, 16), RETRY_MAX_SECONDS)
        self._retry_at = max(self._retry_at or now, now + delay)

    def _drop(self, *, keep_exchange: bool = False) -> None:
        if (self._renewal_deadline is not None and self._connection is not None
                and self.last_close_reason is None):
            # A send that failed first (a live frame) must not hide the
            # Main's CLOSE already waiting to be read (PR #425 review).
            try:
                self._still_open()
            except Exception:
                pass
        connection, self._connection = self._connection, None
        if not keep_exchange:
            self._exchange = None
            if connection is not None:
                # Issue #16 (PR #433 review): an established session was lost,
                # even if the same heartbeat reconnects before it returns. The
                # renewal's own reconnect (``keep_exchange``) is not a loss.
                self.connection_losses += 1
        if connection is not None:
            _shutdown(connection)
        if self._renewal_deadline is not None:
            # The reply of the outstanding request can no longer arrive. A
            # Main that does not know the request type closed the session
            # with `frame_type_refused` (an older release).
            self._renewal_deadline = None
            self._renewal.failed("renewal_unsupported_by_main"
                                 if self.last_close_reason == "frame_type_refused"
                                 else "renewal_reply_lost")

    def _renew(self, reply: tuple[bytes | None, str | None] | None) -> None:
        """Handle a renewal reply, then send a due request (Issue #109).

        Runs under the IO lock right after an acknowledged heartbeat, so the
        request travels on the heartbeat's connection.
        """
        if reply is not None:
            self._renewal_deadline = None
            certificate, reason = reply
            if certificate is None:
                self._renewal.failed(reason)
            elif self._renewal.issued(certificate):
                # Present the new credential now: the Main promotes it at
                # this connection's admission. The clock exchange stays valid.
                self._drop(keep_exchange=True)
                try:
                    self._connect()
                except IngestSessionError as failure:
                    self._failed(failure.reason)
                return
        if self._connection is None:
            return
        if self._renewal_deadline is not None:
            if self._monotonic() >= self._renewal_deadline:
                self._renewal_deadline = None
                self._renewal.failed("renewal_reply_timeout")
            return
        csr = self._renewal.due()
        if csr is None:
            return
        frame = encode_frame(FrameType.RENEWAL_REQUEST, {"csr": csr.decode("ascii")})
        if len(frame) - HEADER.size > MAXIMUM_RENEWAL_REQUEST_BYTES:
            self._renewal.failed("renewal_request_too_large")
            return
        try:
            self._connection.settimeout(REPLY_TIMEOUT_SECONDS)
            self._connection.sendall(frame)
        except (OSError, ssl.SSLError, ValueError):
            self._renewal.failed("renewal_send_failed")
            self._drop()
            self._failed("main_send_failed")
            return
        self._renewal_deadline = self._monotonic() + RENEWAL_REPLY_TIMEOUT_SECONDS

    def _connect(self) -> None:
        try:
            credential = self._credential(self._store)
        except PairingRefused:
            raise IngestSessionError("node_credential_unavailable") from None
        if credential.node_id != self._node_id:
            raise IngestSessionError("node_identity_mismatch")
        try:
            context = build_capture_client_context(
                credential.ca_certificate_pem, certificate_path=credential.certificate_path,
                key_path=credential.key_path)
            context.set_alpn_protocols([INGEST_ALPN])
            connection = self._connect_to_main(
                context, server_name=credential.server_name, host=self._endpoint.host,
                port=self._endpoint.port, timeout_seconds=CONNECT_TIMEOUT_SECONDS)
        except PairingRefused as refused:
            # Fixed words from `main_link` (unreachable, identity, Tailscale).
            raise IngestSessionError(str(refused)) from None
        except (OSError, ssl.SSLError, ValueError):
            raise IngestSessionError("main_handshake_failed") from None
        try:
            if connection.selected_alpn_protocol() != INGEST_ALPN:
                raise IngestSessionError("main_alpn_refused")
            # Stop-and-wait over small frames: without this, Nagle and delayed
            # ACK add ~40 ms per heartbeat (Issue #369, ADR-0007).
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.setsockopt(socket.IPPROTO_TCP, TCP_NOTSENT_LOWAT,
                                  NOT_SENT_LOW_WATER_BYTES)
        except IngestSessionError:
            _shutdown(connection)
            raise
        except OSError:
            _shutdown(connection)
            raise IngestSessionError("main_handshake_failed") from None
        self._connection = connection
        self.last_close_reason = None

    def _still_open(self) -> bool:
        """False if the Main closed (or sent ``CLOSE``) while the Agent was idle.

        Stop-and-wait means nothing is due from the Main between ticks; a
        an end of stream or application data (a ``CLOSE``) between ticks means
        the Main ended the session.
        """
        connection = self._connection
        try:
            if not connection.pending() and not select.select([connection], [], [], 0)[0]:
                return True
            # Readable is not yet application data: TLS 1.3 post-handshake
            # records (session tickets) also wake `select`. One non-blocking
            # read tells them apart without waiting.
            connection.settimeout(0.0)
            prefix = connection.recv(HEADER.size)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
            return True
        except (OSError, ValueError):
            return False
        if not prefix:
            return False
        try:
            kind, value = read_reply(connection, self._monotonic() + REPLY_TIMEOUT_SECONDS,
                                     clock=self._monotonic, prefix=prefix)
        except (IngestSessionError, OSError, ssl.SSLError):
            return False
        if kind is FrameType.CLOSE:
            self.last_close_reason = _close_reason(value)
        return False

    def _round_trip(self, heartbeat: dict) -> tuple[bytes | None, str | None] | None:
        """One heartbeat and its ack; returns a renewal reply read before the ack."""
        connection = self._connection
        frame = encode_frame(FrameType.HEARTBEAT, heartbeat)
        if len(frame) - HEADER.size > MAXIMUM_HEARTBEAT_BYTES:
            raise IngestSessionError("heartbeat_too_large")
        deadline = self._monotonic() + REPLY_TIMEOUT_SECONDS
        send_utc, send_monotonic = self._utc(), self._monotonic()
        connection.settimeout(REPLY_TIMEOUT_SECONDS)
        try:
            connection.sendall(frame)
        except socket.timeout:
            raise IngestSessionError("main_reply_timeout") from None
        renewal = None
        kind, value = read_reply(connection, deadline, clock=self._monotonic)
        if kind is FrameType.RENEWAL_REPLY:
            # Only directly before an ack (Issue #109); it is handled after
            # the ack. A reply after `RENEWAL_REPLY_TIMEOUT_SECONDS` still
            # answers the latest request (there is only ever one).
            if self._renewal is None:
                raise IngestSessionError("main_reply_invalid")
            renewal = _renewal_reply(value)
            kind, value = read_reply(connection, deadline, clock=self._monotonic)
            if kind is FrameType.RENEWAL_REPLY:
                raise IngestSessionError("main_reply_invalid")
        receive_utc, receive_monotonic = self._utc(), self._monotonic()
        if kind is FrameType.CLOSE:
            self.last_close_reason = _close_reason(value)
            raise IngestSessionError("main_closed")
        if (set(value) != _ACK_KEYS or type(value["sequence"]) is not int
                or value["sequence"] != heartbeat.get("sequence")
                or not _finite(value["receive_utc"]) or not _finite(value["send_utc"])):
            raise IngestSessionError("main_reply_invalid")
        # `health.assess_clock` judges the exchange (negative or impossible
        # intervals are `clock_invalid`); it is only recorded here.
        self._exchange = ClockExchange(
            local_send_utc=send_utc, local_send_monotonic=send_monotonic,
            remote_receive_utc=value["receive_utc"], remote_send_utc=value["send_utc"],
            local_receive_utc=receive_utc, local_receive_monotonic=receive_monotonic)
        return renewal
