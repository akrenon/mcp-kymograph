"""The scope guard: a tool call is held against the engagement before it reaches the server.

The gate (:func:`mcp_kymograph.engagement.check`) refuses a *script* that calls a tool the file
does not allow, before anything starts. This module is the second wall, for what the gate cannot
see: the stdio proxy of ``run``, where a foreign client chooses its calls as it goes, and the
driver, where a call that got past the gate must still not be sent (``Driver._call``). Both ask
:func:`mcp_kymograph.engagement.tool_cause`; this module adds what only a proxy needs, which is
reading a client's message *the way the server will*.

**A message is read once, strictly, and passed on only if it is clear.** The proxy parses a copy
of each line the client sends and decides on that. Any form in which a server could read something
else than the guard did is not passed on:

* a key given twice in the message or in its ``params`` (parsers keep the first or the last, and
  the server's may not be the guard's);
* a key spelled otherwise than the JSON-RPC key it folds to (``Method``, ``METHOD``, ``paramſ``,
  ``ID``, ``JSONRPC`` at the top of a message; ``Name`` in the ``params`` of a call), and a
  ``method`` that folds to ``tools/call`` without being it (``Tools/Call``): some parsers match
  keys without regard to case (Go's ``encoding/json``, which takes the last of several), so the
  server may read a call where the guard saw none, or another tool. The names under ``tools``
  and ``deny_tools`` are compared exactly;
* a message too long or nested too deeply to read in full (:data:`events.MESSAGE_UNEXAMINED`);
* a JSON array (a batch) with one call that is not allowed: nothing of it is passed on.

``method`` is compared after the JSON is decoded, so ``"tools\\/call"`` and ``"tools\\u002fcall"``
are the call they spell. A line that is not valid JSON is not passed on either: not UTF-8
(strictly decoded), with a byte order mark, with ``NaN`` or ``Infinity``, or with anything after
the value (a comment, a second object), or with a carriage return anywhere but directly before
the line's end (a server that reads universal newlines splits the line there). It is recorded as
:data:`events.MESSAGE_UNEXAMINED` and not answered, since it has no readable ``id``. A blank line
passes, and so does every message the guard has no rule for. An allowed message is passed on
byte for byte.

**Nothing from the traffic is part of a cause or of what the client is told.** The causes are
fixed words; the tool's name is a field of its own, cut like a method name. The answer to the
client is a JSON-RPC error with the code :data:`BLOCKED_CODE` and a fixed text, to the request's
own ``id``. The answer is not recorded as a message: the server did not say it.

This module makes no connection and touches no file.
"""

from __future__ import annotations

import json
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp_kymograph import events

if TYPE_CHECKING:
    from mcp_kymograph.engagement import Engagement

#: The JSON-RPC error code of an answer to a blocked call. In the range JSON-RPC leaves to the
#: implementation (-32000 to -32099), and not one MCP uses (-32002; -32020 to -32022; the
#: standard -32600 to -32603 and -32700), nor -32000, which SDKs use for a closed connection.
BLOCKED_CODE = -32050
#: The error's text: fixed, so that nothing the client sent is in it.
BLOCKED_MESSAGE = "Not sent to the server: the engagement does not allow this call."

#: The method a call has.
CALL_METHOD = "tools/call"

#: Digits beyond which an integer is not built (CPython refuses 4300 and then reads no message).
#: Read as null instead, so that a number the server may read does not make a message "not JSON".
_MAX_INT_DIGITS = 4000

#: The bytes JSON allows between its tokens; a line of nothing else is empty.
_JSON_SPACE = b" \t\r\n"


@dataclass(frozen=True, slots=True)
class Blocked:
    """One call that was not passed on: why, which tool it named, and what the client is owed.

    ``tool`` is the name as the client wrote it, not cut (the recorder masks it, then cuts it;
    the length of the line bounds it); ``message_id`` is the request's id as
    the client wrote it, or None; ``answered`` is whether an answer is written to the client (a
    request has an id; a notification has none)."""

    cause: str
    tool: str | None = None
    message_id: Any = None
    answered: bool = False
    batch: bool = False


@dataclass(frozen=True, slots=True)
class Screening:
    """What the guard decided about one line it did not pass on: the calls it blocked and the
    bytes to answer with (a line without its newline), or None when nobody is to be answered."""

    blocked: tuple[Blocked, ...]
    reply: bytes | None


class ScopeGuard:
    """What an engagement allows a client to call, and the reading of a client's lines against it.

    Built with :meth:`of`, which returns None when the file has nothing to enforce at this level
    (neither ``tools`` nor ``deny_tools``, as in every file of the first version): such a run is
    not touched, and ``actions`` stays the gate's alone.
    """

    def __init__(self, engagement: Engagement) -> None:
        self._engagement = engagement

    @classmethod
    def of(cls, engagement: Engagement | None) -> ScopeGuard | None:
        if engagement is None or (engagement.tools is None and not engagement.deny_tools):
            return None
        return cls(engagement)

    def cause(self, tool: str | None) -> str | None:
        """Why a call of ``tool`` is not allowed, or None: :func:`engagement.tool_cause`."""
        # Here and not at the top: the engagement module reads the recorder, which the driver
        # (and so this module) is read by, through the corpus.
        from mcp_kymograph.engagement import tool_cause

        return tool_cause(self._engagement, tool)

    def screen(self, line: bytes) -> Screening | None:
        """One line the client sent, without its newline: None to pass it on, as it is, or what
        was blocked. Never raises: a line that fails to be read is blocked, not passed."""
        try:
            return self._screen(line)
        except Exception:  # noqa: BLE001 - a guard that fails must not become a way past it
            return _unexamined()

    def _screen(self, line: bytes) -> Screening | None:
        if not line.strip(_JSON_SPACE):
            return None
        # A carriage return inside a line is JSON space to the guard, but a server that reads its
        # stdin with universal newlines splits the line there and reads the parts as lines of
        # their own, where the guard saw one message without a call. Only the line's end may hold
        # one: a ``\n`` and a ``\r`` directly before it.
        if b"\r" in line.removesuffix(b"\n").removesuffix(b"\r"):
            return _unexamined()
        # Under a guard a line is valid JSON or it is not passed on: a lenient server might read
        # what a strict parser rejects (a comment, a trailing rest, NaN, bytes that are not
        # UTF-8), and the guard cannot say what that server would make of it. A byte order mark
        # is such a case: RFC 8259 says a parser must not add one, and some parsers skip it, so
        # the line is held back rather than guessed at.
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            return _unexamined()
        if text.count("[") + text.count("{") > events.MAX_READ_DEPTH:
            depth = events.nesting(text)
            if depth is None:
                return _unexamined()
            if depth > events.MAX_READ_DEPTH:
                return _unexamined()
        repeated: list[tuple[dict, dict[str, list]]] = []

        def pairs(items: list[tuple[str, Any]]) -> dict:
            made: dict = {}
            twice: dict[str, list] = {}
            for key, value in items:
                if key in made:
                    twice.setdefault(key, [made[key]]).append(value)
                made[key] = value
            if twice:
                repeated.append((made, twice))
            return made

        try:
            document = json.loads(
                text,
                object_pairs_hook=pairs,
                parse_int=lambda digits: int(digits) if len(digits) <= _MAX_INT_DIGITS else None,
                parse_constant=_no_constant,
            )
        except (RecursionError, ValueError):
            return _unexamined()
        if isinstance(document, list):
            return self._batch(document, repeated)
        found = self._one(document, repeated, batch=False)
        if found is None:
            return None
        return Screening((found,), _reply([found]))

    def _batch(self, items: list, repeated: list[tuple[dict, dict[str, list]]]) -> Screening | None:
        """A batch is passed on whole or not at all: one call that is not allowed keeps every
        request in it from the server. Each request is answered, with the cause of the first call
        that was blocked, since the others were not wrong, only not sent."""
        found = [self._one(item, repeated, batch=True) for item in items]
        blocked = tuple(item for item in found if item is not None)
        if not blocked:
            return None
        first = blocked[0].cause
        replies = []
        for item, result in zip(items, found, strict=True):
            if result is None:
                requested = _requested(item, repeated)
                if requested is not None:
                    replies.append(_error(requested[0], first))
            elif result.answered:
                replies.append(_error(result.message_id, result.cause))
        return Screening(blocked, None if not replies else _array(replies))

    def _one(
        self, message: Any, repeated: list[tuple[dict, dict[str, list]]], *, batch: bool
    ) -> Blocked | None:
        """One message of the line. Blocked if it is a call that is not allowed, or if it cannot
        be told what it is."""
        if batch and isinstance(message, list):
            # A batch in a batch is no JSON-RPC: what a server reads out of it is not the guard's
            # to say. It has no id, so nothing is answered for it. (The depth is bounded by
            # ``events.nesting`` in ``_screen``.)
            return Blocked(events.MESSAGE_UNEXAMINED, None, None, False, batch)
        if not isinstance(message, dict):
            return None
        twice = _twice(message, repeated)
        requested = _requested(message, repeated)
        identifier, answered = (None, False) if requested is None else (requested[0], True)
        if twice and "method" in message:
            # A key given twice at the top of a message that has a method: which method, which
            # params, which id is the parser's to say. Not passed on.
            return Blocked(events.MESSAGE_UNEXAMINED, None, identifier, answered, batch)
        if _respelled(message, _TOP_KEYS):
            # Not the key the guard reads, but one a case-insensitive server may read instead.
            # The id stays as `_requested` found it: under another spelling there is none.
            return Blocked(events.MESSAGE_UNEXAMINED, None, identifier, answered, batch)
        method = message.get("method")
        if isinstance(method, str) and method != CALL_METHOD and method.casefold() == CALL_METHOD:
            return Blocked(events.MESSAGE_UNEXAMINED, None, identifier, answered, batch)
        if method != CALL_METHOD:
            return None
        params = message.get("params")
        name: Any = None
        if isinstance(params, dict):
            if _respelled(params, ("name",)) or _twice(params, repeated):
                return Blocked(events.MESSAGE_UNEXAMINED, None, identifier, answered, batch)
            name = params.get("name")
        tool = name if isinstance(name, str) else None
        cause = self.cause(tool)
        if cause is None:
            if tool is None:
                # Only `deny_tools`: a call whose name cannot be read is not one the guard can
                # say is not denied, so it is not passed on.
                return Blocked(events.MESSAGE_UNEXAMINED, None, identifier, answered, batch)
            return None
        return Blocked(cause, tool, identifier, answered, batch)


#: The keys of a message the guard reads, or that decide whether it is read.
_TOP_KEYS = ("method", "params", "id", "jsonrpc")


def _respelled(mapping: dict, names: tuple[str, ...]) -> bool:
    """Whether a key of ``mapping`` folds to one of ``names`` without being written as it."""
    return any(key not in names and _fold(key) in names for key in mapping)


def _fold(key: str) -> str:
    """``key`` folded as a case-insensitive server may fold it: ``casefold``, and the two dotted
    and dotless forms of ``i`` (``ı``, and ``i`` with a combining dot, which is what ``İ`` folds
    to) read as ``i``, which ``casefold`` leaves alone."""
    return key.casefold().replace("ı", "i").replace("i̇", "i")


def _unexamined() -> Screening:
    return Screening((Blocked(events.MESSAGE_UNEXAMINED),), None)


def _no_constant(name: str) -> Any:
    """``NaN`` and ``Infinity`` are not JSON; Python's parser reads them unless told not to."""
    raise ValueError(f"not JSON: {name}")


def _twice(mapping: dict, repeated: list[tuple[dict, dict[str, list]]]) -> dict[str, list]:
    for made, keys in repeated:
        if made is mapping:
            return keys
    return {}


def _requested(message: Any, repeated: list[tuple[dict, dict[str, list]]]) -> tuple[Any] | None:
    """``(id,)`` of a request, a message with a ``method`` (a string) and an ``id``, else None.
    Only a request is answered: a client's response to a server's request has an ``id`` too, from
    the server's id space, and a notification has none. An id that is not a string or a number is
    answered as null: JSON-RPC's word for an id that could not be read.

    With a key given twice (any key, in the message or its ``params``), a server may read the
    first value or the last, so a message is a request if *any* of its ``method`` values is a
    string. It is answered only if all its ``id`` values are the same and valid, a single invalid
    ``id`` included; with conflicting or invalid ids any choice could hit another request the
    client has open, so the proxy says nothing (the message is still held back and recorded).
    Without a key given twice, an invalid ``id`` is answered as null."""
    if not isinstance(message, dict) or "id" not in message:
        return None
    twice = _twice(message, repeated)
    methods = twice.get("method") or ([message["method"]] if "method" in message else [])
    if not any(isinstance(method, str) for method in methods):
        return None
    params = message.get("params")
    if twice or (isinstance(params, dict) and _twice(params, repeated)):
        # A key given twice, whichever it is: the server may read the message in another way
        # than the guard, so an id is answered only if every value it may read is the same.
        first, *others = twice.get("id") or [message["id"]]
        same = all(type(other) is type(first) and other == first for other in others)
        return (first,) if same and _valid_id(first) else None
    value = message["id"]
    return (value,) if _valid_id(value) else (None,)


def _valid_id(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    return not isinstance(value, bool) and isinstance(value, (str, int))


def _error(identifier: Any, cause: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "error": {"code": BLOCKED_CODE, "message": BLOCKED_MESSAGE, "data": {"cause": cause}},
    }


def _dumps(value: Any) -> bytes:
    """The JSON of a reply, never with ``NaN`` or ``Infinity``. If it cannot be made anyway, the
    ids are given up and the reply is made with ``id`` null."""
    try:
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        nulled = [dict(item, id=None) for item in (value if isinstance(value, list) else [value])]
        text = json.dumps(
            nulled if isinstance(value, list) else nulled[0],
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    return text.encode("ascii")


def _array(replies: list[dict[str, Any]]) -> bytes:
    return _dumps(replies)


def _reply(blocked: list[Blocked]) -> bytes | None:
    (only,) = blocked
    if not only.answered:
        return None
    return _dumps(_error(only.message_id, only.cause))


# -- writers: the guard in the way the bytes go ----------------------------------------------

#: Called with each :class:`Blocked`, to be written to the recording.
Record = Callable[[Blocked], Awaitable[None]]


class ClientWriter:
    """The writer to the client, shared by the server's answers and the guard's.

    A server's output is forwarded in chunks that may end in the middle of a line, so an error
    the guard writes between two chunks would cut a message in two. The guard's lines wait until
    the server's last chunk has ended its line, and are written right after it. A line still
    waiting when the stream ends is not written: the server ended mid-message, and the stream is
    no longer one a client reads lines from."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._mid_line = False
        self._waiting: list[bytes] = []

    def write(self, data: bytes) -> None:
        self._inner.write(data)
        if data:
            self._mid_line = not data.endswith(b"\n")
        if not self._mid_line and self._waiting:
            waiting, self._waiting = self._waiting, []
            for line in waiting:
                self._inner.write(line)

    def answer(self, line: bytes) -> None:
        """Write one line of the guard's, now or when the server's current line is done."""
        if self._mid_line:
            self._waiting.append(line)
        else:
            self._inner.write(line)

    async def drain(self) -> None:
        await self._inner.drain()

    def close(self) -> None:
        self._inner.close()


class GuardedWriter:
    """The writer to the server, with the guard in front of it.

    Everything written to the server goes through here — what the client sent and what a rule
    put in its place — so no path past the guard is left. It holds back a line until it is whole,
    asks the guard, and writes it on unchanged or not at all. A line longer than ``limit`` is
    not passed on: it cannot be read in full, so it is blocked as unexamined. What the client is
    owed is written to ``client`` at once; what is to be recorded waits for :meth:`drain` or
    :meth:`settle`, which may wait, because a blocked call must not be lost to a full queue.
    """

    def __init__(
        self, inner: Any, client: ClientWriter, guard: ScopeGuard, *, limit: int, record: Record
    ) -> None:
        self._inner = inner
        self._client = client
        self._guard = guard
        self._limit = limit
        self._record = record
        self._held = bytearray()
        self._too_long = False
        self._pending: list[Blocked] = []

    def write(self, data: bytes) -> None:
        start = 0
        while start < len(data):
            end = data.find(b"\n", start)
            whole = end != -1
            self._take(data[start : end + 1 if whole else len(data)], whole=whole)
            start = end + 1 if whole else len(data)

    def _take(self, piece: bytes, *, whole: bool) -> None:
        if self._too_long:
            # The rest of a line already blocked: dropped up to its newline.
            self._too_long = not whole
            return
        # Counted as the LineFramer counts: the newline is not part of the message (a carriage
        # return before it is), so a line of exactly ``limit`` bytes is passed on.
        if len(self._held) + len(piece) - (1 if whole else 0) > self._limit:
            self._held.clear()
            self._pending.append(Blocked(events.MESSAGE_UNEXAMINED))
            self._too_long = not whole
            return
        self._held += piece
        if whole:
            line = bytes(self._held)
            self._held.clear()
            self._decide(line)

    def _decide(self, line: bytes) -> None:
        screening = self._guard.screen(line.rstrip(b"\n"))
        if screening is None:
            self._inner.write(line)
            return
        self._pending.extend(screening.blocked)
        if screening.reply is not None:
            self._client.answer(screening.reply + b"\n")

    async def drain(self) -> None:
        await self._flush()
        await self._inner.drain()

    async def settle(self, *, stopped: bool = False) -> None:
        """The end of the client's input: a last line without a newline is read like any other
        (the server would read it at end-of-file), and what is left to record is recorded. In a
        stopped run that line is dropped unread, since nothing more goes on to the server."""
        if self._held:
            line = bytes(self._held)
            self._held.clear()
            if not stopped:
                self._decide(line)
        await self._flush()

    async def _flush(self) -> None:
        answered = False
        while self._pending:
            blocked = self._pending.pop(0)
            answered = answered or blocked.answered
            await self._record(blocked)
        if answered:
            await self._client.drain()

    def close(self) -> None:
        self._inner.close()
