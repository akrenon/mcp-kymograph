"""Where HTTP/1.1 messages begin and end on one direction of one connection.

The forwarding side needs exactly this and nothing more (docs/design/http-transport.md, 2.2):
where a head ends, and where the body after it ends — by ``Content-Length``, by chunked
encoding, or by the connection closing. It needs it without ever holding a body back and
without ever losing a byte, so :class:`HttpFramer` returns **pieces** that partition its
input: joined, the ``raw`` bytes of every piece returned are exactly the bytes fed in, in
order, whatever happened. That is the guarantee the forwarder rests on, as ``_ForwardFramer``
rests on it over stdio.

Under the rules of :class:`~mcp_kymograph.framing.LineFramer`: no stream, no writer, nothing to
wait for. Bytes go in, pieces come out. Memory is bounded without reference to the body: a
head and a trailer section are held up to :data:`~mcp_kymograph.http.head.MAX_HEAD_BYTES`, a
chunk-size line up to :data:`MAX_CHUNK_LINE_BYTES`; body bytes are handed on as they arrive.

**A framing error costs observation, not the connection.** A head that does not parse, a
length that cannot be trusted, a chunk line that is not one: the framer reports
``framing_error`` once, with the reason, and from then on returns everything — what it held
included — as pass-through, until the connection ends. It does not try to resynchronise: a
framer that guesses where the next message starts is how one request is read as two.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from mcp_kymograph.http.head import (
    HEAD_TOO_LARGE,
    MAX_FIELDS,
    MAX_HEAD_BYTES,
    Head,
    HeadError,
    parse_fields,
    parse_head,
    split_lines,
)

#: The longest chunk-size line held, extensions included. A size needs 16 hex digits at most;
#: the rest is room for extensions, which nothing here reads.
MAX_CHUNK_LINE_BYTES = 4096

#: The most hex digits a chunk size may have: 16 already count past every real body.
MAX_CHUNK_SIZE_DIGITS = 16

# -- the kinds of piece ---------------------------------------------------------------------

#: A message's head, parsed (``head``). Its raw bytes are the head as sent.
HEAD = "head"
#: Body bytes as sent (``raw``) and the content they carry (``payload``): the same bytes for
#: ``Content-Length`` and close-delimited bodies, the chunk data alone for chunked ones.
BODY = "body"
#: A message ended: ``complete`` true where its framing said so (or the close delimited it),
#: false where the connection ended first. Carries ``trailers`` of a chunked message.
END = "end"
#: Empty lines between messages (RFC 9112, 2.2: a server SHOULD ignore at least one).
GAP = "gap"
#: Reported once: from here the connection is passed through (``reason``).
FRAMING_ERROR = "framing_error"
#: Bytes passed through verbatim after a framing error.
PASSTHROUGH = "passthrough"

# -- the reason words of a framing error (beside those of head.py) --------------------------

BAD_CONTENT_LENGTH = "bad_content_length"
CONFLICTING_LENGTH = "conflicting_length"
UNSUPPORTED_TRANSFER_CODING = "unsupported_transfer_coding"
BAD_CHUNK_SIZE = "bad_chunk_size"
CHUNK_LINE_TOO_LARGE = "chunk_line_too_large"
BAD_CHUNK_END = "bad_chunk_end"
TRAILER_TOO_LARGE = "trailer_too_large"
#: Not an error of the peer: after a 101 or a CONNECT the bytes are no longer HTTP/1.1.
PROTOCOL_SWITCHED = "protocol_switched"
#: The framer itself failed to advance: a bug in it, never in the traffic.
FRAMER_STALLED = "framer_stalled"


@dataclass(frozen=True, slots=True)
class Piece:
    """One stretch of the input, and what it is."""

    kind: str
    raw: bytes = b""
    payload: bytes = b""
    head: Head | None = None
    complete: bool = True
    trailers: tuple[tuple[str, str], ...] = ()
    reason: str | None = None
    detail: str | None = None


# The framer's states.
_HEAD, _LENGTH, _CLOSE, _SIZE, _DATA, _DATA_END, _TRAILER, _PASSTHROUGH = range(8)


class HttpFramer:
    """Finds message boundaries on one direction of one HTTP/1.1 connection.

    ``request=True`` for the client's direction, ``False`` for the server's. A response's body
    depends on the request it answers (a response to HEAD has none): the forwarder names each
    request's method with :meth:`expect`, in order, and the responses are matched to them in
    order (HTTP/1.1 answers in order on a connection). A response with nothing expected is
    read as one to a request such as POST.
    """

    __slots__ = (
        "_buffer",
        "_chunk_left",
        "_expected",
        "_head",
        "_left",
        "_max_chunk_line",
        "_max_fields",
        "_max_head",
        "_request",
        "_scanned",
        "_started",
        "_state",
    )

    def __init__(
        self,
        *,
        request: bool,
        max_head_bytes: int = MAX_HEAD_BYTES,
        max_fields: int = MAX_FIELDS,
        max_chunk_line_bytes: int = MAX_CHUNK_LINE_BYTES,
    ) -> None:
        if min(max_head_bytes, max_fields, max_chunk_line_bytes) < 1:
            raise ValueError("the bounds must be positive")
        self._request = request
        self._max_head = max_head_bytes
        self._max_fields = max_fields
        self._max_chunk_line = max_chunk_line_bytes
        self._expected: deque[str] = deque()
        self._state = _HEAD
        self._buffer = bytearray()
        self._scanned = 0
        self._started = False
        self._head: Head | None = None
        self._left = 0
        self._chunk_left = 0

    @property
    def passing_through(self) -> bool:
        return self._state == _PASSTHROUGH

    @property
    def buffered_bytes(self) -> int:
        """How much the framer is holding: never more than a head or a chunk-size line."""
        return len(self._buffer)

    def expect(self, method: str) -> None:
        """The method of the next request on this connection, for the response framer."""
        self._expected.append(method.upper())

    def feed(self, chunk: bytes) -> list[Piece]:
        """Consume one read; return the pieces it completes, which together hold all of it.

        Within one read, consecutive body, gap and pass-through bytes come back as one piece
        each — a chunked body's frames and data together (``raw`` all of it, ``payload`` the
        data) — so the number of pieces follows the number of messages, not of lines or chunks.
        """
        pieces = _Pieces()
        position = 0
        while position < len(chunk):
            state = self._state
            advanced = self._step(chunk, position, pieces)
            if advanced <= position and self._state == state:
                # Every step consumes a byte or changes state; one that does neither would spin
                # forever on the forwarding path. A bug — reported as a framing error, and the
                # rest passed through: observation is lost, never the connection.
                if state != _PASSTHROUGH:
                    self._fail(pieces, HeadError(FRAMER_STALLED, f"no progress in state {state}"))
                pieces.append(Piece(PASSTHROUGH, chunk[position:]))
                self._state = _PASSTHROUGH
                break
            position = advanced
        return pieces.done()

    def finish(self) -> list[Piece]:
        """The connection ended. Close out the message under way, holding nothing back."""
        held = bytes(self._buffer)
        state, head, started = self._state, self._head, self._started
        self._buffer.clear()
        self._scanned = 0
        self._started = False
        self._head = None
        if state == _PASSTHROUGH:
            return [Piece(PASSTHROUGH, held)] if held else []
        self._state = _HEAD
        if state == _HEAD and not started:
            # Between messages: at most a CR waiting for its LF, part of the gap.
            return [Piece(GAP, held)] if held else []
        if state == _CLOSE:
            return [Piece(END, head=head)]
        return [Piece(END, held, head=head, complete=False)]

    # -- one step ---------------------------------------------------------------------------

    def _step(self, data: bytes, position: int, pieces: list[Piece]) -> int:
        state = self._state
        if state == _PASSTHROUGH:
            pieces.append(Piece(PASSTHROUGH, data[position:]))
            return len(data)
        if state == _HEAD:
            return self._read_head(data, position, pieces)
        if state == _CLOSE:
            pieces.append(Piece(BODY, data[position:], data[position:]))
            return len(data)
        if state in (_LENGTH, _DATA):
            left = self._left if state == _LENGTH else self._chunk_left
            take = min(left, len(data) - position)
            body = data[position : position + take]
            pieces.append(Piece(BODY, body, body))
            if state == _LENGTH:
                self._left -= take
                if self._left == 0:
                    self._end(pieces)
            else:
                self._chunk_left -= take
                if self._chunk_left == 0:
                    self._state = _DATA_END
            return position + take
        if state == _DATA_END:
            return self._read_data_end(data, position, pieces)
        if state == _SIZE:
            return self._read_size_line(data, position, pieces)
        return self._read_section(data, position, pieces, trailer=True)

    def _read_head(self, data: bytes, position: int, pieces: list[Piece]) -> int:
        if not self._started:
            # Empty lines before a start line are the gap between messages.
            while position < len(data):
                if self._buffer == b"\r":
                    if data[position] != 0x0A:
                        break
                    self._buffer.clear()
                    pieces.append(Piece(GAP, b"\r\n"))
                    position += 1
                elif data.startswith(b"\r\n", position):
                    pieces.append(Piece(GAP, b"\r\n"))
                    position += 2
                elif data[position] == 0x0A:
                    pieces.append(Piece(GAP, b"\n"))
                    position += 1
                elif data[position] == 0x0D and position + 1 == len(data):
                    self._buffer += b"\r"
                    return position + 1
                else:
                    break
            if position == len(data):
                return position
            self._started = True
        return self._read_section(data, position, pieces, trailer=False)

    def _read_section(
        self, data: bytes, position: int, pieces: list[Piece], *, trailer: bool
    ) -> int:
        """Collect a head or a trailer section up to its empty line, at most MAX_HEAD_BYTES."""
        room = self._max_head + 1 - len(self._buffer)
        window = data[position : position + room]
        before = len(self._buffer)
        self._buffer += window
        end = _end_of_section(self._buffer, self._scanned, trailer=trailer)
        if end is None:
            self._scanned = max(0, len(self._buffer) - 2)
            if len(self._buffer) > self._max_head:
                reason = TRAILER_TOO_LARGE if trailer else HEAD_TOO_LARGE
                self._fail(pieces, HeadError(reason, f"no end within {self._max_head} bytes"))
            return position + len(window)
        section = bytes(self._buffer[:end])
        self._buffer.clear()
        self._scanned = 0
        consumed = position + end - before
        try:
            if trailer:
                if len(section) > self._max_head:
                    raise HeadError(TRAILER_TOO_LARGE, f"over {self._max_head} bytes")
                lines = [line for line in split_lines(section) if line]
                trailers = parse_fields(lines, max_fields=self._max_fields)
            else:
                head = parse_head(
                    section,
                    request=self._request,
                    max_fields=self._max_fields,
                    max_head_bytes=self._max_head,
                )
        except HeadError as error:
            self._buffer += section
            self._fail(pieces, error)
            return consumed
        if trailer:
            self._end(pieces, section, trailers)
        else:
            self._started = False
            self._begin_body(head, section, pieces)
        return consumed

    def _begin_body(self, head: Head, block: bytes, pieces: list[Piece]) -> None:
        try:
            framing = self._framing(head)
        except HeadError as error:
            self._buffer += block
            self._fail(pieces, error, head)
            return
        self._head = head
        pieces.append(Piece(HEAD, block, head=head))
        if framing == "switch":
            self._end(pieces)
            self._fail(pieces, HeadError(PROTOCOL_SWITCHED, _switched(head)), head)
        elif framing == "chunked":
            self._state = _SIZE
        elif framing == "close":
            self._state = _CLOSE
        elif framing == 0:
            self._end(pieces)
        else:
            self._left = int(framing)
            self._state = _LENGTH

    def _framing(self, head: Head) -> int | str:
        """How this message's body is delimited (RFC 9112, 6.3): a length, chunked, close.

        A ``CONNECT`` request switches this direction to pass-through at once, before its
        answer is known: a 407 that keeps the connection as HTTP then costs the observation of
        what follows on it, never a byte of it.
        """
        if head.is_request:
            if head.method == "CONNECT":
                return "switch"
        else:
            status = head.status or 0
            if status == 101:
                return "switch"
            if 100 <= status < 200:
                return 0  # an interim response: the final one to the same request follows
            method = self._expected.popleft() if self._expected else None
            if method == "CONNECT" and 200 <= status < 300:
                return "switch"
            if method == "HEAD" or status in (204, 304):
                return 0
        encodings = head.values("transfer-encoding")
        codings = [
            coding.strip().lower()
            for value in encodings
            for coding in value.split(",")
            if coding.strip()
        ]
        lengths = head.values("content-length")
        if encodings and lengths:
            # RFC 9112, 6.1: "ought to be handled as an error" — it is how requests are smuggled.
            # The field's presence counts, not what is in it: an empty one is no way around it.
            raise HeadError(CONFLICTING_LENGTH, "both Transfer-Encoding and Content-Length")
        if encodings:
            if head.version == "HTTP/1.0":
                raise HeadError(UNSUPPORTED_TRANSFER_CODING, "Transfer-Encoding in HTTP/1.0")
            if not codings:
                raise HeadError(UNSUPPORTED_TRANSFER_CODING, "no coding in Transfer-Encoding")
            if codings.count("chunked") > 1:
                raise HeadError(UNSUPPORTED_TRANSFER_CODING, "chunked more than once")
            if codings[-1] == "chunked":
                return "chunked"
            if head.is_request:
                raise HeadError(
                    UNSUPPORTED_TRANSFER_CODING, f"{len(codings)} codings, the last not chunked"
                )
            return "close"
        if lengths:
            numbers = {element.strip() for value in lengths for element in value.split(",")}
            if any(not n.isascii() or not n.isdigit() or len(n) > 19 for n in numbers):
                raise HeadError(BAD_CONTENT_LENGTH, "a Content-Length that is not a length")
            if len(numbers) != 1:
                raise HeadError(CONFLICTING_LENGTH, f"{len(numbers)} lengths that differ")
            return int(numbers.pop())
        return 0 if head.is_request else "close"

    # -- chunked ---------------------------------------------------------------------------

    def _read_size_line(self, data: bytes, position: int, pieces: list[Piece]) -> int:
        newline = data.find(b"\n", position)
        end = len(data) if newline == -1 else newline + 1
        room = self._max_chunk_line - len(self._buffer)
        if end - position > room:
            self._buffer += data[position : position + room]
            limit = f"longer than {self._max_chunk_line} bytes"
            self._fail(pieces, HeadError(CHUNK_LINE_TOO_LARGE, limit))
            return position + room
        self._buffer += data[position:end]
        if newline == -1:
            return end
        line = bytes(self._buffer)
        self._buffer.clear()
        text = line[:-2] if line.endswith(b"\r\n") else None
        size, semicolon, _ = (text or b"").partition(b";")
        if semicolon:
            size = size.rstrip(b" \t")  # BWS before an extension, nowhere else
        if (
            text is None
            or any((byte < 0x20 and byte != 0x09) or byte == 0x7F for byte in text)
            or not size
            or len(size) > MAX_CHUNK_SIZE_DIGITS
            or any(byte not in b"0123456789abcdefABCDEF" for byte in size)
        ):
            self._buffer += line
            self._fail(pieces, HeadError(BAD_CHUNK_SIZE, f"a chunk-size line of {len(line)} bytes"))
            return end
        pieces.append(Piece(BODY, line))
        if int(size, 16) == 0:
            self._state = _TRAILER
        else:
            self._chunk_left = int(size, 16)
            self._state = _DATA
        return end

    def _read_data_end(self, data: bytes, position: int, pieces: list[Piece]) -> int:
        """The CRLF after a chunk's data, possibly split over two reads."""
        while position < len(data) and len(self._buffer) < 2:
            self._buffer.append(data[position])
            position += 1
            if self._buffer not in (b"\r", b"\r\n"):
                self._fail(pieces, HeadError(BAD_CHUNK_END, "chunk data not followed by CRLF"))
                return position
        if len(self._buffer) == 2:
            pieces.append(Piece(BODY, bytes(self._buffer)))
            self._buffer.clear()
            self._state = _SIZE
        return position

    # -- endings ---------------------------------------------------------------------------

    def _end(self, pieces: list[Piece], raw: bytes = b"", trailers=()) -> None:
        pieces.append(Piece(END, raw, head=self._head, trailers=tuple(trailers)))
        self._state = _HEAD
        self._head = None

    def _fail(self, pieces: list[Piece], error: HeadError, head: Head | None = None) -> None:
        pieces.append(
            Piece(FRAMING_ERROR, head=head or self._head, reason=error.reason, detail=error.detail)
        )
        if self._buffer:
            pieces.append(Piece(PASSTHROUGH, bytes(self._buffer)))
            self._buffer.clear()
        self._state = _PASSTHROUGH
        self._head = None


class _Pieces(list):
    """The pieces of one read, with each run of body, gap or pass-through bytes joined into one
    piece as it is appended — never more than one such piece under way."""

    def __init__(self) -> None:
        super().__init__()
        self._kind: str | None = None
        self._raw: list[bytes] = []
        self._payload: list[bytes] = []

    def append(self, piece: Piece) -> None:
        if piece.kind in (BODY, GAP, PASSTHROUGH):
            if piece.kind != self._kind:
                self._flush()
                self._kind = piece.kind
            self._raw.append(piece.raw)
            self._payload.append(piece.payload)
            return
        self._flush()
        super().append(piece)

    def done(self) -> list[Piece]:
        self._flush()
        return list(self)

    def _flush(self) -> None:
        if self._kind is not None:
            raw, payload = b"".join(self._raw), b"".join(self._payload)
            super().append(Piece(self._kind, raw, payload))
        self._kind, self._raw, self._payload = None, [], []


def _end_of_section(buffer: bytearray, scanned: int, *, trailer: bool) -> int | None:
    """The offset just past the empty line that ends a head or a trailer section, or None.

    A trailer section may be nothing but that empty line; a head has its start line first.
    ``scanned`` is where an earlier look stopped, so a section fed a byte at a time is not
    searched again from its beginning on every byte.
    """
    if trailer and scanned == 0:
        if buffer.startswith(b"\r\n"):
            return 2
        if buffer.startswith(b"\n"):
            return 1
    index = scanned
    while True:
        newline = buffer.find(b"\n", index)
        if newline == -1:
            return None
        following = newline + 1
        if buffer.startswith(b"\r\n", following):
            return following + 2
        if buffer.startswith(b"\n", following):
            return following + 1
        index = following


def _switched(head: Head) -> str:
    if head.is_request:
        return "CONNECT: what follows is a tunnel"
    return f"{head.status}: what follows is not HTTP/1.1"
