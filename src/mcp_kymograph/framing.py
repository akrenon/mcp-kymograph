"""Message framing for the recording path — an observer, never a participant.

The stdio transport is newline-delimited JSON, so finding message boundaries means finding
newlines. The proxy does that on a *copy* of the bytes: the originals are already on their
way to the other side by the time this module sees them.

That separation is the property the whole tool rests on, so it is expressed in the types
rather than left to discipline. A :class:`LineFramer` holds no stream, no writer, no
recorder and no lock; it cannot await anything and has nothing to block on. Bytes go in,
frames come out. Whatever happens in here — a limit hit, a buffer dropped — cannot reach
the connection between client and server, because the connection is not reachable from
here.

Memory is bounded by construction: the buffer never grows past ``max_message_bytes``, even
if a server never sends a newline at all. Past that point the framer keeps counting but
stops keeping, and resynchronises on the next newline.
"""

from __future__ import annotations

from dataclasses import dataclass

#: One message may occupy this much of our memory before the framer stops keeping it. It
#: bounds the observer, and an oversized message is still forwarded in full. The driver reads
#: lines up to the same length, though never less than ``driver.MIN_LINE_BYTES``.
DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Frame:
    """One message boundary found in the stream.

    ``data`` is verbatim: the bytes between two newlines, with a preceding carriage return
    left in place. It is empty when ``truncated`` is set, because an oversized message is
    dropped rather than clipped — a prefix can end in the first half of a credential, which
    no pattern would then recognise as one.

    ``size_bytes`` is always the true length of the line, excluding its terminator, and
    keeps counting through a message the framer has stopped storing.
    """

    data: bytes
    size_bytes: int
    truncated: bool = False
    incomplete: bool = False


class LineFramer:
    """Splits a byte stream into message frames, one direction per instance."""

    __slots__ = ("_buffer", "_discarding", "_max", "_size")

    def __init__(self, max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> None:
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be positive")
        self._max = max_message_bytes
        self._buffer = bytearray()
        self._size = 0
        self._discarding = False

    @property
    def buffered_bytes(self) -> int:
        """How much of the current message is being held. Never exceeds the limit."""
        return len(self._buffer)

    def feed(self, chunk: bytes) -> list[Frame]:
        """Consume a copy of one read from the stream and return completed frames."""
        frames: list[Frame] = []
        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            if newline == -1:
                self._absorb(chunk, start, len(chunk))
                return frames
            self._absorb(chunk, start, newline)
            frame = self._complete()
            if frame is not None:
                frames.append(frame)
            start = newline + 1

    def finish(self) -> list[Frame]:
        """Close out the stream, reporting whatever was left mid-line.

        A remnant is not silently dropped: a message the server started and never finished
        is exactly the kind of thing a later phase wants to see. Trailing whitespace is not
        a remnant, and is skipped like any blank line.
        """
        if self._size == 0:
            return []

        size = self._size
        discarding = self._discarding
        data = bytes(self._buffer)
        self._reset()

        if discarding:
            return [Frame(data=b"", size_bytes=size, truncated=True, incomplete=True)]
        if not data.strip():
            return []
        return [Frame(data=data, size_bytes=size, incomplete=True)]

    # -- internals ------------------------------------------------------------------

    def _absorb(self, chunk: bytes, start: int, end: int) -> None:
        """Take the part of ``chunk`` belonging to the current message.

        Offsets rather than a slice, so the bytes of a message we have already given up on
        are never copied: a server flooding one endless line costs us the counter and
        nothing else.
        """
        length = end - start
        if length <= 0:
            return

        self._size += length
        if self._discarding:
            return

        if self._size > self._max:
            self._discarding = True
            self._buffer.clear()
            return

        self._buffer += chunk[start:end]

    def _complete(self) -> Frame | None:
        size = self._size
        discarding = self._discarding
        data = bytes(self._buffer)
        self._reset()

        if discarding:
            return Frame(data=b"", size_bytes=size, truncated=True)
        if not data.strip():
            # Blank lines and stray whitespace between messages are framing, not content.
            return None
        return Frame(data=data, size_bytes=size)

    def _reset(self) -> None:
        self._buffer = bytearray()
        self._size = 0
        self._discarding = False
