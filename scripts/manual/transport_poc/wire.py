"""Wire formats of the PoC candidates (no network I/O here).

Candidate A (``a_framed``): TLS 1.3 mTLS stream of length-prefixed frames.
Candidate B (``b_chunked``): the same frames as HTTP/1.1 chunked request and
response bodies on one long-lived ``POST``; (``b_segment``): one ``PUT`` per
1 s segment whose body is a run of frames and whose response carries the
acknowledgements.

Every frame is ``uint32 length`` followed by ``length`` bytes starting with a
one-byte type. The media frame carries the ADR-0007 envelope
``(source_id, capture_epoch, sequence, capture_time_ns)``; the payload is
opaque compressed video that the receiver only hashes and discards.
"""
import struct
from uuid import UUID, uuid5

MEDIA, HEARTBEAT, ACK, HEARTBEAT_ACK = 1, 2, 3, 4
_LENGTH = struct.Struct(">I")
_MEDIA = struct.Struct(">B16sQQQ")
_HEARTBEAT = struct.Struct(">BQ")
_ACK = struct.Struct(">B16sQQBB")
MEDIA_HEADER_BYTES = _MEDIA.size
MAX_HEAD_BYTES = 8192
STREAM_PATH = "/poc15/v1/stream"
SEGMENT_PATH = "/poc15/v1/segment"

OUTCOMES = ("accepted", "duplicate", "backpressured", "rate_limited", "rejected",
            "not_processed")
REASONS = ("none", "unauthorized", "stale_session", "source_capacity",
           "source_identity_mismatch", "watermark_unavailable", "already_committed",
           "stale_capture_epoch", "capture_clock_regression", "queue_limit", "rate_limit",
           "rate_window_capacity", "message_too_large", "clock_regression", "other")


SOURCE_SLOTS = 5  # four active plus one that must be refused (G6)


def source_ids(node_id):
    """Deterministic synthetic source identities of one node (index 0-4)."""
    return [uuid5(node_id, f"poc15-source-{index}") for index in range(SOURCE_SLOTS)]


class ProtocolError(ValueError):
    """A peer violated framing or a pre-read bound; the connection is closed."""


def frame(body):
    return _LENGTH.pack(len(body)) + body


def media_frame(source_id, epoch, sequence, capture_ns, payload):
    return frame(_MEDIA.pack(MEDIA, source_id.bytes, epoch, sequence, capture_ns) + payload)


def heartbeat_frame(sent_ns):
    return frame(_HEARTBEAT.pack(HEARTBEAT, sent_ns))


def heartbeat_ack_frame(echo_ns):
    return frame(_HEARTBEAT.pack(HEARTBEAT_ACK, echo_ns))


def ack_frame(source_id, epoch, sequence, outcome, reason):
    outcome_code = OUTCOMES.index(outcome)
    reason_code = REASONS.index(reason if reason in REASONS else "other")
    return frame(_ACK.pack(ACK, source_id.bytes, epoch, sequence, outcome_code, reason_code))


def parse_body(body):
    """Return a tuple describing one frame body; raises ``ProtocolError``."""
    if not body:
        raise ProtocolError("empty frame")
    kind = body[0]
    if kind == MEDIA:
        if len(body) < _MEDIA.size:
            raise ProtocolError("short media frame")
        _, source, epoch, sequence, capture_ns = _MEDIA.unpack_from(body)
        return MEDIA, UUID(bytes=source), epoch, sequence, capture_ns, body[_MEDIA.size:]
    if kind in (HEARTBEAT, HEARTBEAT_ACK):
        if len(body) != _HEARTBEAT.size:
            raise ProtocolError("bad heartbeat frame")
        return kind, _HEARTBEAT.unpack(body)[1]
    if kind == ACK:
        if len(body) != _ACK.size:
            raise ProtocolError("bad ack frame")
        _, source, epoch, sequence, outcome, reason = _ACK.unpack(body)
        if outcome >= len(OUTCOMES) or reason >= len(REASONS):
            raise ProtocolError("bad ack code")
        return ACK, UUID(bytes=source), epoch, sequence, OUTCOMES[outcome], REASONS[reason]
    raise ProtocolError("unknown frame type")


def check_length(length, maximum_body):
    if not 1 <= length <= maximum_body:
        raise ProtocolError("frame length outside bound")
    return length


class FrameReader:
    """Incremental splitter with a pre-read bound on every frame body."""

    def __init__(self, maximum_body):
        self.maximum_body = maximum_body
        self._buffer = bytearray()

    def __len__(self):
        return len(self._buffer)

    def feed(self, data):
        self._buffer += data
        bodies = []
        while len(self._buffer) >= 4:
            length = check_length(_LENGTH.unpack_from(self._buffer)[0], self.maximum_body)
            if len(self._buffer) < 4 + length:
                break
            bodies.append(bytes(self._buffer[4:4 + length]))
            del self._buffer[:4 + length]
        return bodies


# -- HTTP/1.1 helpers (candidate B) -------------------------------------------

def request_head(method, path, *, content_length=None):
    lines = [f"{method} {path} HTTP/1.1", "Host: ingest", "Content-Type: application/octet-stream"]
    if content_length is None:
        lines.append("Transfer-Encoding: chunked")
    else:
        lines.append(f"Content-Length: {int(content_length)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def response_head(status, *, chunked=False, content_length=0, close=False):
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 413: "Payload Too Large"}[status]
    lines = [f"HTTP/1.1 {status} {reason}", "Content-Type: application/octet-stream"]
    lines.append("Transfer-Encoding: chunked" if chunked
                 else f"Content-Length: {int(content_length)}")
    if close:
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def parse_head(raw):
    """Parse a bounded request/response head into (start line parts, headers)."""
    if len(raw) > MAX_HEAD_BYTES:
        raise ProtocolError("head too large")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("head not ascii") from None
    lines = text.split("\r\n")
    start = lines[0].split(" ", 2)
    if len(start) < 2:
        raise ProtocolError("bad start line")
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator or not name or name != name.strip():
            raise ProtocolError("bad header line")
        name = name.lower()
        if name in headers:
            raise ProtocolError("duplicate header")
        headers[name] = value.strip()
    return start, headers


def chunk(data):
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


LAST_CHUNK = b"0\r\n\r\n"


class ChunkDecoder:
    """Bounded HTTP/1.1 chunked-body decoder; chunk extensions/trailers refused."""

    def __init__(self, maximum_chunk):
        self.maximum_chunk = maximum_chunk
        self._buffer = bytearray()
        self.finished = False

    def __len__(self):
        return len(self._buffer)

    def feed(self, data):
        self._buffer += data
        chunks = []
        while not self.finished:
            end = self._buffer.find(b"\r\n")
            if end < 0:
                if len(self._buffer) > 18:
                    raise ProtocolError("chunk size line too long")
                break
            line = bytes(self._buffer[:end])
            if not line or len(line) > 16 or not all(c in b"0123456789abcdefABCDEF" for c in line):
                raise ProtocolError("bad chunk size")
            size = int(line, 16)
            if size > self.maximum_chunk:
                raise ProtocolError("chunk exceeds bound")
            if size == 0:
                if len(self._buffer) < end + 4:
                    break
                if self._buffer[end + 2:end + 4] != b"\r\n":
                    raise ProtocolError("trailers refused")
                del self._buffer[:end + 4]
                self.finished = True
                break
            if len(self._buffer) < end + 2 + size + 2:
                break
            if self._buffer[end + 2 + size:end + 4 + size] != b"\r\n":
                raise ProtocolError("bad chunk terminator")
            chunks.append(bytes(self._buffer[end + 2:end + 2 + size]))
            del self._buffer[:end + 4 + size]
        return chunks

    def take_rest(self):
        rest = bytes(self._buffer)
        self._buffer.clear()
        return rest


# -- JPEG comment envelope (optional SRT adapter) -----------------------------

_COM_TAG = b"POC15\x00"


def embed_envelope(jpeg, source_index, epoch, sequence, capture_ns):
    """Insert the envelope as a JPEG COM segment right after SOI."""
    if not jpeg.startswith(b"\xff\xd8"):
        raise ValueError("not a JPEG frame")
    body = _COM_TAG + struct.pack(">BQQQ", source_index, epoch, sequence, capture_ns)
    segment = b"\xff\xfe" + struct.pack(">H", len(body) + 2) + body
    return jpeg[:2] + segment + jpeg[2:]


def extract_envelope(jpeg):
    """Return ((source_index, epoch, sequence, capture_ns), payload) or raise."""
    if not jpeg.startswith(b"\xff\xd8\xff\xfe"):
        raise ProtocolError("envelope segment missing")
    (length,) = struct.unpack(">H", jpeg[4:6])
    body = jpeg[6:4 + length]
    if length != len(_COM_TAG) + 25 + 2 or not body.startswith(_COM_TAG):
        raise ProtocolError("bad envelope segment")
    envelope = struct.unpack(">BQQQ", body[len(_COM_TAG):])
    return envelope, jpeg[:2] + jpeg[4 + length:]
