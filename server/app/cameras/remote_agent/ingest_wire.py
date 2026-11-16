"""Capture ingest wire protocol, version 1 (ADR-0007 ``a_framed``, Issue #14).

Standard library only; no socket is opened here. One connection carries the
TLS 1.3 mTLS session of one capture node (``ingest_tls``), negotiated with the
ALPN protocol ``INGEST_ALPN``. Inside it every message is a frame::

    uint32 big-endian body length | uint8 frame type | body

The length is checked against the caller's limit *before* any body byte is
read (ADR-0007 item 5: bounded pre-read limits), and a zero-length frame or an
unknown type is refused. Version 1 has four frame types:

* ``HEARTBEAT`` (Agent to Main): a UTF-8 JSON object, the Agent's node
  heartbeat (``agent/media_capture_agent/runtime.py``, schema version 1). It is
  validated strictly (``parse_heartbeat``): unknown keys, non-finite numbers,
  duplicate keys and oversized collections are refused.
* ``HEARTBEAT_ACK`` (Main to Agent): ``{"sequence", "receive_utc",
  "send_utc"}``, the Main's UTC times at receipt and reply, so the Agent can
  estimate the clock offset (SPECIFICATION §5.9) without the Main comparing
  clocks itself.
* ``CLOSE`` (Main to Agent): ``{"reason": <fixed word>}`` just before the Main
  closes the connection.
* ``LIVE_FRAME`` (Agent to Main; Issue #14, Owner decision 2026-11-12, option
  A): a live preview frame, ``source UUID (16 bytes, uuid.UUID.bytes) | one
  complete JPEG`` (``parse_live_frame``). The JPEG starts with ``FF D8``, ends
  with ``FF D9`` and is at most ``MAXIMUM_LIVE_FRAME_BYTES``; the frame's
  body limit (``MAXIMUM_LIVE_FRAME_BODY_BYTES``) is applied from the header,
  before the body is read, like every other type's. The Main sends **no**
  reply: it keeps only the newest frame per source in memory, for the live
  view, and stores nothing, so there is nothing to acknowledge.

Recording media is not part of version 1: it is accepted only once the
durable recording consumer exists (#17 / #313), so a Main never acknowledges
media it cannot keep. A frame of any other type ends the connection with
``frame_type_refused``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import json
import math
import re
import socket
import struct
import time
from typing import Callable, Mapping
from uuid import UUID


INGEST_ALPN = "serversentinel-capture-ingest/1"
HEADER = struct.Struct(">IB")
_MAXIMUM_COUNTER = 2 ** 63 - 1
# The bounded vocabulary of node reasons the Main keeps (Agent ``runtime.py``
# and ``health.py``). Any other word is kept only as ``other``: an Agent never
# makes the Main hold free text.
KNOWN_NODE_REASONS = frozenset({
    "storage_unavailable", "storage_device_numbers_stale", "capture_unconfigured",
    "pairing_required", "main_unavailable", "clock_unavailable", "clock_invalid",
    "clock_step", "clock_uncertain", "clock_offset",
})
OTHER_REASON = "other"
NODE_STATES = frozenset({"online", "degraded"})
STORAGE_STATES = frozenset({"online", "degraded", "failed"})
CLOCK_STATES = frozenset({"online", "degraded", "unknown"})
MAXIMUM_NODE_REASONS = 16
# The MVP's active-source limit (1-4 sources per deployment).
MAXIMUM_HEARTBEAT_SOURCES = 4
# LIVE_FRAME (Issue #14, Owner decision 2026-11-12): the JPEG after the
# 16-byte source UUID is at most 1 MiB.
LIVE_FRAME_SOURCE_BYTES = 16
MAXIMUM_LIVE_FRAME_BYTES = 1_048_576
MAXIMUM_LIVE_FRAME_BODY_BYTES = LIVE_FRAME_SOURCE_BYTES + MAXIMUM_LIVE_FRAME_BYTES
_JPEG_START = b"\xff\xd8"
_JPEG_END = b"\xff\xd9"
_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")
# The Agent's storage and source reasons are its refusal codes, some upper
# case (`StorageRefused("STORAGE_HARD_STOP")`, sent as `str(exc)` by
# `runtime.py`). They are validated as codes but never kept here.
_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_HEARTBEAT_KEYS = frozenset({
    "schema_version", "node_id", "sequence", "utc_seconds", "monotonic_seconds",
    "node_state", "node_reasons", "clock", "storage", "sources",
})
_CLOCK_KEYS = frozenset({"state", "reason", "offset_seconds", "uncertainty_seconds"})
_STORAGE_KEYS = frozenset({"state", "reason", "available_bytes", "safety_reserve_bytes"})
_SOURCE_KEYS = frozenset({"source_id", "state", "reason"})


class FrameType(IntEnum):
    HEARTBEAT = 0x01
    HEARTBEAT_ACK = 0x02
    LIVE_FRAME = 0x10
    CLOSE = 0x7F


class WireRefused(Exception):
    """A fixed-reason protocol refusal; the message never holds peer bytes."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class PeerClosed(Exception):
    """The peer ended the stream (cleanly, or before a whole frame arrived)."""


@dataclass(frozen=True)
class Frame:
    kind: FrameType
    body: bytes


@dataclass(frozen=True)
class NodeHeartbeat:
    """What the Main keeps from one valid heartbeat: fixed words and counts only.

    Byte counts, clock offsets and source details are validated but not kept
    here; remote camera health needs source authorization (follow-up of #14).
    """

    node_id: UUID
    sequence: int
    node_state: str
    reasons: tuple[str, ...]
    storage_state: str
    clock_state: str
    source_count: int


@dataclass(frozen=True)
class LiveFrame:
    """One live preview frame: the source it names and its JPEG bytes."""

    source_id: UUID
    jpeg: bytes

    def __repr__(self) -> str:
        # Never the media bytes.
        return "LiveFrame(<redacted>)"


def _receive_exactly(connection: socket.socket, size: int, deadline: float | None,
                     clock: Callable[[], float]) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        if deadline is not None:
            left = deadline - clock()
            if left <= 0:
                raise socket.timeout("frame deadline")
            # Every receive gets only what is left of the frame's one
            # deadline, so a peer trickling a byte per receive cannot keep a
            # frame open past it (PR #401 Codex review).
            connection.settimeout(left)
        chunk = connection.recv(min(remaining, 65536))
        if not chunk:
            raise PeerClosed()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(connection: socket.socket, maximum_body_bytes: int, *,
               deadline: float | None = None,
               clock: Callable[[], float] = time.monotonic,
               type_limits: Mapping[FrameType, int] | None = None) -> Frame:
    """Read one frame; the length is refused before its body is read.

    ``maximum_body_bytes`` bounds every type that ``type_limits`` does not
    name (and an unknown type); ``type_limits`` gives a known type its own
    bound (``LIVE_FRAME``: ``MAXIMUM_LIVE_FRAME_BODY_BYTES``). The bound of
    the header's type is applied before any body byte is read.

    With ``deadline`` (a ``clock`` value), the whole frame -- header and body
    -- must arrive before it, however the peer splits its bytes; otherwise
    ``socket.timeout`` is raised. ``socket.timeout`` and ``OSError`` propagate
    to the caller; a stream that ends between or inside frames is
    ``PeerClosed``.
    """
    limits = dict(type_limits or {})
    if (type(maximum_body_bytes) is not int or maximum_body_bytes <= 0
            or any(not isinstance(kind, FrameType) or type(limit) is not int or limit <= 0
                   for kind, limit in limits.items())):
        raise ValueError("invalid frame limit")
    length, kind = HEADER.unpack(_receive_exactly(connection, HEADER.size, deadline, clock))
    if length == 0:
        raise WireRefused("frame_empty")
    try:
        frame_type = FrameType(kind)
    except ValueError:
        frame_type = None
    if length > limits.get(frame_type, maximum_body_bytes):
        raise WireRefused("frame_too_large")
    if frame_type is None:
        raise WireRefused("frame_type_refused")
    return Frame(frame_type, _receive_exactly(connection, length, deadline, clock))


def parse_live_frame(body: bytes) -> LiveFrame:
    """Split a ``LIVE_FRAME`` body; anything but one whole JPEG is ``live_frame_invalid``.

    Only the JPEG's start and end markers are checked; the image is never
    decoded here. The bytes are passed through to the live view unchanged.
    """
    if (not isinstance(body, bytes)
            or not LIVE_FRAME_SOURCE_BYTES + len(_JPEG_START) + len(_JPEG_END)
            <= len(body) <= MAXIMUM_LIVE_FRAME_BODY_BYTES):
        raise WireRefused("live_frame_invalid")
    jpeg = body[LIVE_FRAME_SOURCE_BYTES:]
    if not jpeg.startswith(_JPEG_START) or not jpeg.endswith(_JPEG_END):
        raise WireRefused("live_frame_invalid")
    return LiveFrame(UUID(bytes=body[:LIVE_FRAME_SOURCE_BYTES]), jpeg)


def encode_live_frame(source_id: UUID, jpeg: bytes) -> bytes:
    """The Agent's ``LIVE_FRAME`` encoding (tests and the contract check)."""
    if not isinstance(source_id, UUID) or not isinstance(jpeg, bytes):
        raise ValueError("invalid live frame")
    body = source_id.bytes + jpeg
    return HEADER.pack(len(body), int(FrameType.LIVE_FRAME)) + body


def encode_frame(kind: FrameType, payload: dict) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return HEADER.pack(len(body), int(kind)) + body


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _refuse_constant(_value):
    raise ValueError("non-finite number")


def parse_json_object(body: bytes) -> dict:
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicates,
                           parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise WireRefused("frame_body_invalid") from None
    if not isinstance(value, dict):
        raise WireRefused("frame_body_invalid")
    return value


def _finite(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _word(value) -> bool:
    return isinstance(value, str) and _WORD.fullmatch(value) is not None


def _code(value) -> bool:
    return isinstance(value, str) and _CODE.fullmatch(value) is not None


def _counter(value) -> bool:
    return type(value) is int and 0 <= value <= _MAXIMUM_COUNTER


def _uuid(value) -> UUID:
    if not isinstance(value, str):
        raise ValueError
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError
    return parsed


def parse_heartbeat(body: bytes) -> NodeHeartbeat:
    """Validate a version 1 heartbeat; any deviation is ``heartbeat_invalid``."""
    value = parse_json_object(body)
    try:
        if set(value) != _HEARTBEAT_KEYS or value["schema_version"] != 1 \
                or type(value["schema_version"]) is not int:
            raise ValueError
        node = _uuid(value["node_id"])
        if not _counter(value["sequence"]) or value["sequence"] == 0:
            raise ValueError
        if not _finite(value["utc_seconds"]) or not _finite(value["monotonic_seconds"]):
            raise ValueError
        state = value["node_state"]
        reasons = value["node_reasons"]
        if (state not in NODE_STATES or not isinstance(reasons, list)
                or len(reasons) > MAXIMUM_NODE_REASONS
                or not all(_word(reason) for reason in reasons)
                or len(set(reasons)) != len(reasons)):
            raise ValueError
        # The Agent reports `online` exactly when it has no reason.
        if (state == "online") != (not reasons):
            raise ValueError
        clock = value["clock"]
        if (not isinstance(clock, dict) or not {"state", "reason"} <= set(clock) <= _CLOCK_KEYS
                or clock["state"] not in CLOCK_STATES or not _word(clock["reason"])
                or any(clock.get(name) is not None and not _finite(clock[name])
                       for name in ("offset_seconds", "uncertainty_seconds"))):
            raise ValueError
        storage = value["storage"]
        if (not isinstance(storage, dict) or not {"state"} <= set(storage) <= _STORAGE_KEYS
                or storage["state"] not in STORAGE_STATES
                or ("reason" in storage and not _code(storage["reason"]))
                or any(name in storage and not _counter(storage[name])
                       for name in ("available_bytes", "safety_reserve_bytes"))):
            raise ValueError
        sources = value["sources"]
        if not isinstance(sources, list) or len(sources) > MAXIMUM_HEARTBEAT_SOURCES:
            raise ValueError
        seen = set()
        for source in sources:
            if (not isinstance(source, dict) or set(source) != _SOURCE_KEYS
                    or not _code(source["state"]) or not _code(source["reason"])):
                raise ValueError
            identity = _uuid(source["source_id"])
            if identity in seen:
                raise ValueError
            seen.add(identity)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise WireRefused("heartbeat_invalid") from None
    kept = tuple(dict.fromkeys(reason if reason in KNOWN_NODE_REASONS else OTHER_REASON
                               for reason in reasons))
    return NodeHeartbeat(node_id=node, sequence=value["sequence"], node_state=state,
                         reasons=kept, storage_state=storage["state"],
                         clock_state=clock["state"], source_count=len(sources))
