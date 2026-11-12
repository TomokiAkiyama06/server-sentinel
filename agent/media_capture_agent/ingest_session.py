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

Stop-and-wait: one heartbeat, then its ack, within ``REPLY_TIMEOUT_SECONDS``.
Every failure (connect, handshake, ALPN, timeout, a ``CLOSE``, a malformed or
mismatched reply) drops the connection, forgets the clock exchange and raises
``IngestSessionError`` (a ``ConnectionError``, which the runtime reports as
``main_unavailable``). Reconnects back off from ``RETRY_FIRST_SECONDS`` up to
``RETRY_MAX_SECONDS``; while waiting, a heartbeat fails at once without
traffic, so a tick never blocks on an unreachable Main for longer than one
bounded connect plus one bounded reply.

The credential is read from the installed generation at every connect
(``main_link.installed_credential``), so a pairing completed while the
service runs is picked up without a restart, and a credential naming another
node than the configured one is refused (``node_identity_mismatch``).
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
# Bounds of one tick's network work (`config.MAXIMUM_HEARTBEAT_SECONDS`): the
# TCP connect and the TLS handshake, then the heartbeat send and its reply.
CONNECT_TIMEOUT_SECONDS = 5.0
REPLY_TIMEOUT_SECONDS = 5.0
RETRY_FIRST_SECONDS = 1.0
RETRY_MAX_SECONDS = 30.0
_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ACK_KEYS = frozenset({"sequence", "receive_utc", "send_utc"})


class FrameType(IntEnum):
    HEARTBEAT = 0x01
    HEARTBEAT_ACK = 0x02
    CLOSE = 0x7F


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
    if not 0 < length <= MAXIMUM_REPLY_BYTES:
        raise IngestSessionError("main_reply_invalid")
    try:
        frame_type = FrameType(kind)
    except ValueError:
        raise IngestSessionError("main_reply_invalid") from None
    body = _receive_exactly(connection, length, deadline, clock)
    if frame_type is FrameType.HEARTBEAT:
        raise IngestSessionError("main_reply_invalid")
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
                 monotonic: Callable[[], float] = time.monotonic):
        if (not isinstance(endpoint, MainIngestEndpoint) or not isinstance(node_id, UUID)
                or not callable(connect) or not callable(credential)):
            raise ValueError("invalid ingest session dependencies")
        self._store = store
        self._endpoint = endpoint
        self._node_id = node_id
        self._connect_to_main = connect
        self._credential = credential
        self._utc = utc
        self._monotonic = monotonic
        self._connection = None
        self._exchange: ClockExchange | None = None
        self._failures = 0
        self._retry_at = None
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

    def send_heartbeat(self, heartbeat: dict) -> None:
        if self._connection is not None and not self._still_open():
            self._drop()
        if self._connection is None:
            if self._retry_at is not None and self._monotonic() < self._retry_at:
                raise IngestSessionError("main_retry_wait")
            try:
                self._connect()
            except IngestSessionError as failure:
                self._failed(failure.reason)
                raise
        try:
            self._round_trip(heartbeat)
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

    def close(self) -> None:
        self._drop()

    # -- internals ---------------------------------------------------------

    def _failed(self, reason: str) -> None:
        self.last_failure = reason
        self._failures += 1
        delay = min(RETRY_FIRST_SECONDS * 2 ** min(self._failures - 1, 16), RETRY_MAX_SECONDS)
        self._retry_at = self._monotonic() + delay

    def _drop(self) -> None:
        connection, self._connection = self._connection, None
        self._exchange = None
        if connection is not None:
            _shutdown(connection)

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

    def _round_trip(self, heartbeat: dict) -> None:
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
        kind, value = read_reply(connection, deadline, clock=self._monotonic)
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
