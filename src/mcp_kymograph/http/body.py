"""The JSON body of one HTTP message as one frame: a message, or a batch.

Over HTTP a POST body, or a response body of type ``application/json``, is one message — or,
under 2025-03-26, one batch (docs/design/http-transport.md, 1.3, 2.3). Its end is the end of
the HTTP message, which :class:`~mcp_kymograph.http.message.HttpFramer` finds; this framer is fed
the payload of the body pieces and closed with :meth:`JsonBodyFramer.finish`.

Under the rules of :class:`~mcp_kymograph.framing.LineFramer`: it parses no JSON (the recorder
does, on the frame), holds at most ``max_message_bytes``, and a body larger than that is
counted and dropped, never clipped.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES

_WHITESPACE = b" \t\r\n"


@dataclass(frozen=True, slots=True)
class BodyFrame:
    """One body. ``data`` verbatim and empty when ``truncated``; ``size_bytes`` its true size.

    ``batch`` says the first byte that is not whitespace is ``[``: a JSON array, which in
    JSON-RPC is a batch. ``incomplete`` says the HTTP message ended before its framing did.
    """

    data: bytes
    size_bytes: int
    batch: bool = False
    truncated: bool = False
    incomplete: bool = False


class JsonBodyFramer:
    """Collects one body; a new instance per HTTP message."""

    __slots__ = ("_buffer", "_first", "_max", "_size")

    def __init__(self, max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> None:
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be positive")
        self._max = max_message_bytes
        self._buffer = bytearray()
        self._size = 0
        self._first: int | None = None

    @property
    def buffered_bytes(self) -> int:
        """How much of the body is held. Never exceeds the limit."""
        return len(self._buffer)

    def feed(self, payload: bytes) -> list[BodyFrame]:
        """Take the next part of the body. A body is complete only at its end: returns []."""
        if self._first is None:
            stripped = payload.lstrip(_WHITESPACE)
            if stripped:
                self._first = stripped[0]
        self._size += len(payload)
        if self._size > self._max:
            self._buffer.clear()
        else:
            self._buffer += payload
        return []

    def finish(self, *, complete: bool = True) -> list[BodyFrame]:
        """The HTTP message ended (``complete=False``: before its framing said so).

        A body of nothing or of whitespace alone is no message, and gives no frame.
        """
        size, first = self._size, self._first
        data = bytes(self._buffer)
        self._buffer = bytearray()
        self._size = 0
        self._first = None
        if first is None:
            return []
        batch = first == ord("[")
        if size > self._max:
            return [BodyFrame(b"", size, batch, truncated=True, incomplete=not complete)]
        return [BodyFrame(data, size, batch, incomplete=not complete)]
