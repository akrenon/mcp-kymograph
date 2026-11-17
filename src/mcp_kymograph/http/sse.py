"""Server-sent events on a ``text/event-stream`` body, as frames.

One SSE event is one message: its ``data`` lines joined by newlines (docs/design/http-transport.md,
2.3). Parsed as the HTML standard's event-stream interpretation has it: lines end with CRLF,
LF or CR; a byte order mark at the very start of the stream is dropped; a line beginning with
``:`` is a comment; ``field: value`` loses one space after the colon; ``data`` appends,
``event`` names the type, ``id`` sets the last event id unless it holds NUL, ``retry`` sets the
reconnection time if it is digits only; an empty line dispatches.

What is not a message is still counted, never silently passed over: comments (keep-alives),
``retry`` fields, and **events with empty data** — 2025-11-25 has a server open a stream with
"an SSE event consisting of an event ID and an empty data field". Such an event is returned
like any other, with ``data`` empty and its id kept, and :attr:`SseEvent.is_message` false.

Under the rules of :class:`~mcp_kymograph.framing.LineFramer`: no stream, no writer, nothing to
wait for; at most ``max_message_bytes`` of an event's data and of one line held; an event whose
data is larger, or with a line longer than that, is returned truncated: counted, its data
dropped, never clipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES

BOM = b"\xef\xbb\xbf"

#: What a line may exceed the data bound by before it is no longer held: room for a field name,
#: its colon and a space. Of a longer line only this much of its start is kept.
_LINE_SLACK = 16

#: The end of a line: CRLF, CR or LF. One search per line, from where the last one ended, so a
#: read is scanned once however its lines end.
_LINE_END = re.compile(rb"\r\n|\r|\n")

#: The most digits a ``retry`` value may have to be read: ten cover more than a year in
#: milliseconds, and a longer number is not one a client can wait for.
MAX_RETRY_DIGITS = 10

#: An ``id`` was sent too long to keep: from there the stream's last event id is not known.
_LOST = object()


@dataclass(frozen=True, slots=True)
class SseEvent:
    """One dispatched event.

    ``data`` is the joined data, verbatim bytes, empty when ``truncated``; ``size_bytes`` its
    true length. ``event_id`` is the stream's last event id when the event was dispatched (it
    persists from event to event, as the standard has it), ``None`` if none was ever set —
    or, with ``id_lost``, if the last one sent was too long to keep: unknown, not unset.
    ``incomplete`` marks an event the stream ended in, before the empty line that dispatches.
    """

    data: bytes
    size_bytes: int
    event_type: str = "message"
    event_id: str | None = None
    truncated: bool = False
    incomplete: bool = False
    id_lost: bool = False

    @property
    def is_message(self) -> bool:
        """An event with data is a message; one with empty data is counted, not a message."""
        return self.size_bytes > 0


class SseFramer:
    """Splits one event stream into events; a new instance per stream."""

    __slots__ = (
        "_after_cr",
        "_comments",
        "_data",
        "_data_lines",
        "_data_size",
        "_event_type",
        "_events",
        "_id_pending",
        "_last_id",
        "_last_id_lost",
        "_line",
        "_line_size",
        "_max",
        "_pending",
        "_retries",
        "_retry",
        "_start",
        "_started",
        "_tainted",
    )

    def __init__(self, max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> None:
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be positive")
        self._max = max_message_bytes
        self._start = bytearray()  # the first bytes, until they are known not to be a BOM
        self._started = False
        self._after_cr = False
        self._line = bytearray()
        self._line_size = 0
        self._last_id: str | None = None
        self._last_id_lost = False
        self._id_pending: object = None
        self._comments = 0
        self._retries = 0
        self._retry: int | None = None
        self._events = 0
        self._reset_event()

    # -- what was counted -----------------------------------------------------------------

    @property
    def comments(self) -> int:
        """Comment lines seen: keep-alives, as the specification recommends them."""
        return self._comments

    @property
    def retries(self) -> int:
        """Valid ``retry`` fields seen."""
        return self._retries

    @property
    def retry(self) -> int | None:
        """The last valid ``retry`` value, in milliseconds."""
        return self._retry

    @property
    def events(self) -> int:
        """Events dispatched, with data or without."""
        return self._events

    @property
    def last_event_id(self) -> str | None:
        return self._last_id

    @property
    def buffered_bytes(self) -> int:
        """What is held: an event's data (at most the bound) and the line under way (at most
        the bound and :data:`_LINE_SLACK`), and up to two bytes of a BOM not yet decided on."""
        return len(self._line) + len(self._data) + len(self._start)

    # -- feeding --------------------------------------------------------------------------

    def feed(self, chunk: bytes) -> list[SseEvent]:
        events: list[SseEvent] = []
        if not self._started:
            self._start += chunk
            if len(self._start) < len(BOM) and BOM.startswith(self._start):
                return events
            chunk = bytes(self._start)
            self._start = bytearray()
            self._started = True
            if chunk.startswith(BOM):
                chunk = chunk[len(BOM) :]
        position = 0
        length = len(chunk)
        if self._after_cr and position < length:
            self._after_cr = False
            if chunk[0] == 0x0A:
                position = 1
        while position < length:
            found = _LINE_END.search(chunk, position)
            if found is None:
                self._absorb(chunk, position, length)
                break
            self._absorb(chunk, position, found.start())
            self._line_ended(events)
            if found.end() == length and found.group() == b"\r":
                self._after_cr = True  # the LF of a CRLF may begin the next read
            position = found.end()
        return events

    def finish(self) -> list[SseEvent]:
        """The stream ended. An event under way is returned as incomplete, not dropped.

        A stream that ends on a line without its end has that line read for its data only: a
        ``data`` line counts into the incomplete event, an ``id``, ``event`` or ``retry`` that
        was never finished changes nothing — the standard drops such a line.
        """
        events: list[SseEvent] = []
        if not self._started and self._start:
            # Fewer bytes than a BOM, and a prefix of one: they are the stream's content.
            remainder = bytes(self._start)
            self._start = bytearray()
            self._started = True
            self._absorb(remainder, 0, len(remainder))
        if self._line_size or self._line:
            self._line_ended(events, unfinished=True)
        if self._pending:
            events.append(self._event(incomplete=True))
        return events

    # -- lines ----------------------------------------------------------------------------

    def _absorb(self, chunk: bytes, start: int, end: int) -> None:
        if end <= start:
            return
        self._line_size += end - start
        if self._line_size > self._max + _LINE_SLACK:
            # A line longer than any data this framer keeps. Its start is kept — enough to say
            # which field it is — and the rest is counted, not held.
            if len(self._line) < _LINE_SLACK:
                self._line += chunk[start : start + _LINE_SLACK - len(self._line)]
            del self._line[_LINE_SLACK:]
            return
        self._line += chunk[start:end]

    def _line_ended(self, events: list[SseEvent], *, unfinished: bool = False) -> None:
        size = self._line_size
        line = bytes(self._line)
        self._line.clear()
        self._line_size = 0
        if unfinished and line.partition(b":")[0] != b"data":
            return
        if size > self._max + _LINE_SLACK:
            self._overlong(line, size)
            return
        if not line:
            if self._pending:
                events.append(self._event(incomplete=False))
            return
        if line[:1] == b":":
            self._comments += 1
            return
        name, colon, value = line.partition(b":")
        if colon and value[:1] == b" ":
            value = value[1:]
        if name in (b"data", b"event") or (name == b"id" and b"\0" not in value):
            # What makes an event: a block of nothing but retry, unknown or ignored fields (an
            # id holding a NUL) is none.
            self._pending = True
        if name == b"data":
            self._data_lines += 1
            self._data_size += len(value) + (1 if self._data_lines > 1 else 0)
            if self._data_size > self._max:
                self._tainted = True
                self._data.clear()
            elif not self._tainted:
                if self._data_lines > 1:
                    self._data += b"\n"
                self._data += value
        elif name == b"event":
            self._event_type = value.decode("utf-8", "replace")
        elif name == b"id":
            if b"\0" not in value:
                self._id_pending = value.decode("utf-8", "replace")
        elif (
            name == b"retry"
            and value
            and len(value) <= MAX_RETRY_DIGITS
            and value.isdigit()
            and value.isascii()
        ):
            self._retry = int(value)
            self._retries += 1

    def _overlong(self, start: bytes, size: int) -> None:
        """A line past the bound, of which only ``start`` was kept: counted for what it is.

        A comment is still a comment. A ``data`` line counts its true length into the event's
        size and makes the event truncated. An ``id`` too long to keep makes the stream's last
        event id unknown (``id_lost``) until the next one that is kept. An ``event`` too long
        to keep makes the event truncated: its type is not known. A ``retry`` that long is no
        number a client can wait for, and is passed over. A field whose name does not fit in
        what was kept is no field this framer reads (the four it reads have short names), and
        is passed over, as an unknown field is. An ``id`` with a NUL in what was kept is
        ignored, as a short one is; a NUL past what was kept cannot be seen, and that id counts
        as lost — the safe side, since the standard would keep the id before it.
        """
        if start[:1] == b":":
            self._comments += 1
            return
        name, colon, rest = start.partition(b":")
        if not colon or name not in (b"data", b"id", b"event"):
            return
        if name == b"id" and b"\0" in rest:
            return
        self._pending = True
        if name == b"data":
            value = size - len(name) - 1 - (1 if rest[:1] == b" " else 0)
            self._data_lines += 1
            self._data_size += value + (1 if self._data_lines > 1 else 0)
            self._tainted = True
            self._data.clear()
        elif name == b"id":
            self._id_pending = _LOST
        else:
            self._tainted = True

    def _event(self, *, incomplete: bool) -> SseEvent:
        if self._id_pending is _LOST:
            self._last_id, self._last_id_lost = None, True
        elif self._id_pending is not None:
            self._last_id, self._last_id_lost = self._id_pending, False
        size = self._data_size
        tainted = self._tainted
        event = SseEvent(
            data=b"" if tainted else bytes(self._data),
            size_bytes=size,
            event_type=self._event_type or "message",
            event_id=self._last_id,
            truncated=tainted,
            incomplete=incomplete,
            id_lost=self._last_id_lost,
        )
        self._events += 1
        self._reset_event()
        return event

    def _reset_event(self) -> None:
        self._data = bytearray()
        self._data_size = 0
        self._data_lines = 0
        self._event_type = ""
        self._id_pending = None
        self._pending = False
        self._tainted = False
